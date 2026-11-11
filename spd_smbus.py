#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Linux SPD acquisition. Passive discovery, kernel EEPROM reads, SMBus/I2C.

Reads never select SPD pages or change muxes. Raw access is restricted to
0x50-0x57 and 256-byte SDR/DDR/DDR2/DDR3 images. See docs/HARDWARE.md.
"""
import argparse
import array
import binascii
from contextlib import contextmanager
import ctypes as C
from dataclasses import dataclass
import errno
import fcntl
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import time

I2C_SLAVE = 0x0703
I2C_FUNCS = 0x0705
I2C_RDWR = 0x0707
I2C_SMBUS = 0x0720
I2C_M_RD = 1
I2C_FUNC_I2C = 1
I2C_FUNC_SMBUS_READ_BYTE_DATA = 0x00080000
I2C_SMBUS_READ = 1
I2C_SMBUS_BYTE_DATA = 2
SYS_EE = '/sys/bus/i2c/devices'
SYS_ADAPTERS = '/sys/class/i2c-adapter'
DEV_ROOT = '/dev'
TRANSIENT = {errno.EAGAIN, errno.EINTR, errno.ETIMEDOUT, errno.EREMOTEIO, errno.EIO}
SUPPORTED = {4:'SDR', 7:'DDR', 8:'DDR2', 11:'DDR3'}


class i2c_msg(C.Structure):
    _fields_ = [('addr',C.c_uint16),('flags',C.c_uint16),('len',C.c_uint16),('buf',C.c_void_p)]


class i2c_rdwr_ioctl_data(C.Structure):
    _fields_ = [('msgs',C.POINTER(i2c_msg)),('nmsgs',C.c_uint32)]


class smbus_data(C.Union):
    _fields_ = [('byte',C.c_uint8),('word',C.c_uint16),('block',C.c_uint8*34)]


class smbus_ioctl_data(C.Structure):
    _fields_ = [('read_write',C.c_uint8),('command',C.c_uint8),('size',C.c_uint32),('data',C.POINTER(smbus_data))]


def _address(addr):
    if not isinstance(addr,int) or not 0x50 <= addr <= 0x57:
        raise ValueError('SPD address must be a 7-bit address from 0x50 to 0x57')


def _range(start,end,limit=256):
    if not isinstance(start,int) or not isinstance(end,int) or not 0 <= start <= end < limit:
        raise ValueError(f'Inclusive range must satisfy 0 <= start <= end < {limit}')


def _options(chunk,retries):
    if not isinstance(chunk,int) or not 1 <= chunk <= 32:
        raise ValueError('Read chunk must be 1-32 bytes')
    if not isinstance(retries,int) or not 0 <= retries <= 5:
        raise ValueError('Retries must be 0-5')


def _retry(operation,retries=2):
    for attempt in range(retries+1):
        try:
            return operation()
        except OSError as exc:
            if exc.errno not in TRANSIENT or attempt==retries:
                raise
            time.sleep(.01*(attempt+1))


def adapter_functions(fd):
    value=array.array('L',[0])  # Linux ABI: unsigned long, including on 32-bit hosts.
    fcntl.ioctl(fd,I2C_FUNCS,value,True)
    return value[0]


def _claim(fd,addr):
    _address(addr)
    # I2C_RDWR alone bypasses the kernel's in-use-address check. Always claim
    # normally first. Never use I2C_SLAVE_FORCE or unbind an existing driver.
    fcntl.ioctl(fd,I2C_SLAVE,addr)


def _i2c_rdwr(fd,msgs):
    if not 1 <= len(msgs) <= 2:
        raise ValueError('Expected one write message or one combined address/read')
    native=(i2c_msg*len(msgs))()
    buffers=[]
    for index,(addr,flags,buf) in enumerate(msgs):
        _address(addr)
        if not 1 <= len(buf) <= 256:
            raise ValueError('Invalid I2C message length')
        if flags not in (0,I2C_M_RD) or flags and not isinstance(buf,bytearray):
            raise ValueError('Read messages require a mutable bytearray')
        backing=(C.c_uint8*len(buf)).from_buffer_copy(buf)
        buffers.append(backing)
        native[index]=i2c_msg(addr,flags,len(buf),C.cast(backing,C.c_void_p))
    request=i2c_rdwr_ioctl_data(native,len(msgs))
    completed=fcntl.ioctl(fd,I2C_RDWR,request)
    if completed != len(msgs):
        raise OSError(errno.EIO,f'Short I2C transfer: {completed}/{len(msgs)} messages')
    for index,(_,flags,buf) in enumerate(msgs):
        if flags&I2C_M_RD:buf[:]=bytes(buffers[index])


def _smbus_byte(fd,offset):
    data=smbus_data()
    request=smbus_ioctl_data(I2C_SMBUS_READ,offset,I2C_SMBUS_BYTE_DATA,C.pointer(data))
    result=fcntl.ioctl(fd,I2C_SMBUS,request)
    if result != 0:raise OSError(errno.EIO,'Unexpected SMBus ioctl result')
    return data.byte


def _transport(functions,transport):
    if transport=='auto':
        if functions&I2C_FUNC_SMBUS_READ_BYTE_DATA:return 'smbus'
        if functions&I2C_FUNC_I2C:return 'i2c'
    elif transport=='smbus' and functions&I2C_FUNC_SMBUS_READ_BYTE_DATA:return transport
    elif transport=='i2c' and functions&I2C_FUNC_I2C:return transport
    raise ValueError(f'Adapter does not support requested {transport} SPD read transport')


def spd_read(fd,addr,start=0,end=255,chunk=16,transport='auto',retries=2):
    """Exact raw read; offset-only writes are used solely for I2C random reads."""
    _address(addr);_range(start,end);_options(chunk,retries)
    method=_transport(adapter_functions(fd),transport)
    _claim(fd,addr)
    result=bytearray()
    if method=='smbus':
        for offset in range(start,end+1):
            result.append(_retry(lambda:_smbus_byte(fd,offset),retries))
    else:
        for offset in range(start,end+1,chunk):
            count=min(chunk,end-offset+1)
            def transfer():
                buffer=bytearray(count)
                _i2c_rdwr(fd,[(addr,0,bytearray([offset])),(addr,I2C_M_RD,buffer)])
                return buffer
            result.extend(_retry(transfer,retries))
    return bytes(result)


def _bus(bus):
    if not isinstance(bus,int) or bus<0:raise ValueError('Bus must be a nonnegative adapter number')


def open_bus(bus):
    _bus(bus)
    return os.open(f'{DEV_ROOT}/i2c-{bus}',os.O_RDWR|getattr(os,'O_CLOEXEC',0))


@contextmanager
def bus_session(bus):
    fd=open_bus(bus)
    try:
        # Cooperative process exclusion, in addition to the adapter driver's
        # transaction locking. This cannot arbitrate against a BMC or firmware.
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def ee1004_devpath(bus,addr):
    _bus(bus);_address(addr)
    return str(Path(SYS_EE)/f'{bus}-{addr:04x}')


def _eeprom(bus,addr):return Path(ee1004_devpath(bus,addr))/'eeprom'


def _driver(bus,addr):
    path=Path(ee1004_devpath(bus,addr))/'driver'
    return path.resolve().name if path.is_symlink() else None


def ee1004_present(bus,addr):
    # A generic at24/eeprom file must not be mistaken for a DDR4 page driver.
    path=Path(ee1004_devpath(bus,addr))
    try:name=(path/'name').read_text().strip()
    except FileNotFoundError:name=''
    return _eeprom(bus,addr).is_file() and (_driver(bus,addr)=='ee1004' or name=='ee1004')


def _read_exact_at(stream,start,length):
    stream.seek(start)
    result=bytearray()
    while len(result)<length:
        block=stream.read(length-len(result))
        if not block:raise OSError(errno.EIO,f'Short EEPROM read at offset {start+len(result)}')
        result.extend(block)
    return bytes(result)


def ee1004_read(bus,addr):
    if not ee1004_present(bus,addr):raise ValueError('An ee1004 EEPROM interface is required')
    with _eeprom(bus,addr).open('rb',buffering=0) as stream:
        return _read_exact_at(stream,0,512)


def image_diagnostics(data,start=0):
    issues=[]
    if not data:return ['Read returned no bytes']
    if start:return issues
    if len(data)>=128 and (all(b==0 for b in data) or all(b==255 for b in data)):
        return ['Read contains only erased/zero data']
    if len(data)<3:return issues
    mem=data[2]
    if mem not in (*SUPPORTED,12):return [f'Unrecognized SPD memory type 0x{mem:02X}']
    if len(data)<128:return issues
    if mem in SUPPORTED:
        from spd_integrity import integrity_info
        info=integrity_info(data)
        if info['status']!='VALID':issues.append(f"{info['variant']} mismatch over {info['coverage']}")
    elif len(data)>=256:
        for offset in (0,128):
            stored=int.from_bytes(data[offset+126:offset+128],'little')
            if stored!=binascii.crc_hqx(data[offset:offset+126],0):issues.append(f'DDR4 CRC mismatch in block at {offset}')
    return issues


@dataclass
class ReadResult:
    data: bytes
    source: str
    bus: int
    address: int
    start: int
    end: int
    snapshots: int
    diagnostics: list

    def report(self):
        import hashlib
        return dict(source=self.source,bus=self.bus,address=f'0x{self.address:02X}',start=self.start,end=self.end,
                    length=len(self.data),snapshots=self.snapshots,sha256=hashlib.sha256(self.data).hexdigest(),
                    diagnostics=self.diagnostics,
                    integrity_checked=self.start==0 and ((len(self.data)>=128 and self.data[2] in SUPPORTED) or (len(self.data)>=256 and self.data[2]==12)))


def acquire_spd(bus,addr,start=0,end=None,chunk=16,backend='auto',retries=2,snapshots=2,allow_invalid=False):
    """Return matching snapshots or fail. No page/mux/PCI configuration writes."""
    _bus(bus);_address(addr);_options(chunk,retries)
    if backend not in ('auto','sysfs','smbus','i2c'):raise ValueError('Unknown read backend')
    if not isinstance(snapshots,int) or not 2<=snapshots<=5:raise ValueError('Use 2-5 consistency snapshots')
    limit=512 if ee1004_present(bus,addr) else 256
    end=limit-1 if end is None else end
    _range(start,end,limit)
    path=_eeprom(bus,addr)
    use_sysfs=backend=='sysfs' or backend=='auto' and path.is_file()
    if backend=='sysfs' and not path.is_file():raise FileNotFoundError(f'No kernel EEPROM interface at {path}')
    previous=None
    if use_sysfs:
        # A failed kernel-owned read never falls back to bypassing its driver.
        with path.open('rb',buffering=0) as stream:
            for _ in range(snapshots):
                value=_retry(lambda:_read_exact_at(stream,start,end-start+1),retries)
                if previous is not None and previous!=value:raise OSError(errno.EIO,'EEPROM snapshots differ; image not saved')
                previous=value
        source=f'sysfs:{path}'
    else:
        if end>255:raise ValueError('Raw SPD reads cannot cross byte 255; use ee1004 sysfs for DDR4')
        if _driver(bus,addr):raise OSError(errno.EBUSY,'Device is owned by a kernel driver; use its EEPROM interface')
        with bus_session(bus) as fd:
            method=_transport(adapter_functions(fd),backend)
            header=spd_read(fd,addr,0,2,chunk,method,retries)
            if header[2] not in SUPPORTED:
                raise ValueError(f'Raw access supports SDR/DDR/DDR2/DDR3 only (type 0x{header[2]:02X}); no page selection is attempted')
            for _ in range(snapshots):
                value=spd_read(fd,addr,start,end,chunk,method,retries)
                if previous is not None and value!=previous:raise OSError(errno.EIO,'SPD snapshots differ; image not saved')
                previous=value
        source=f'{method}:{DEV_ROOT}/i2c-{bus}'
    issues=image_diagnostics(previous,start)
    if issues and not allow_invalid:raise ValueError('; '.join(issues)+'; use --allow-invalid to preserve a stable damaged image')
    return ReadResult(previous,source,bus,addr,start,end,snapshots,issues)


def list_buses():
    ids=set()
    for base,pattern in ((Path(DEV_ROOT),'i2c-*'),(Path(SYS_ADAPTERS),'i2c-*')):
        for path in base.glob(pattern):
            try:ids.add(int(path.name.split('-')[-1]))
            except ValueError:continue
    return sorted(ids)


def inventory(bus=None):
    """Passive enumeration: names, bound devices and adapter capabilities only."""
    buses=[bus] if bus is not None else list_buses()
    result=[]
    for number in buses:
        _bus(number)
        try:name=(Path(SYS_ADAPTERS)/f'i2c-{number}'/'name').read_text().strip()
        except OSError:name='Unknown adapter'
        record=dict(bus=number,name=name,devices=[])
        try:
            fd=open_bus(number)
            try:
                mask=adapter_functions(fd)
                record['functions']=f'0x{mask:X}'
                record['smbus_byte_data']=bool(mask&I2C_FUNC_SMBUS_READ_BYTE_DATA)
                record['raw_i2c']=bool(mask&I2C_FUNC_I2C)
            finally:os.close(fd)
        except OSError as exc:record['adapter_error']=str(exc)
        for addr in range(0x50,0x58):
            path=Path(ee1004_devpath(number,addr))
            if not path.exists():continue
            try:device_name=(path/'name').read_text().strip()
            except OSError:device_name='Unknown device'
            record['devices'].append(dict(address=f'0x{addr:02X}',name=device_name,driver=_driver(number,addr),
                                          eeprom=path.joinpath('eeprom').is_file(),ee1004=ee1004_present(number,addr)))
        result.append(record)
    return result


def atomic_output(path,data):
    destination=Path(path)
    if destination.exists() and not destination.is_file():
        raise ValueError('Output must be a regular file, not a device or directory')
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent,delete=False) as stream:
            temporary=stream.name;stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,destination)
    finally:
        if temporary and os.path.exists(temporary):os.unlink(temporary)


def crc16_xmodem(data):return binascii.crc_hqx(data,0)


def fix_base_crc(spd):
    from spd_integrity import repair_integrity
    spd[:]=repair_integrity(spd)


def hexdump(data,width=16,start=0):
    return '\n'.join(f'{start+off:03X}: '+data[off:off+width].hex(' ').upper() for off in range(0,len(data),width))


def quick_read_byte0(fd,addr):return spd_read(fd,addr,0,0,1)[0]


def spd_write(fd,addr,data,start=0,end=255,page_size=16,t_wr_s=.02,verify=True):
    """Explicit raw-I2C programmer. Validate fully before the first write."""
    _address(addr);_range(start,end)
    if len(data) not in (128,256) or end>=len(data):raise ValueError('Write range exceeds a 128/256-byte image')
    if data[2] not in SUPPORTED:raise ValueError('Raw programming supports SDR/DDR/DDR2/DDR3 only')
    if page_size not in (8,16,32,64):raise ValueError('Page size must be 8,16,32 or 64 bytes')
    if not math.isfinite(t_wr_s) or not .005<=t_wr_s<=1:raise ValueError('Write delay must be 0.005-1 seconds')
    if not verify:raise ValueError('Read-back verification is mandatory')
    if not adapter_functions(fd)&I2C_FUNC_I2C:raise ValueError('Page programming requires an I2C-capable adapter')
    _claim(fd,addr)
    pos=start
    while pos<=end:
        count=min(page_size-pos%page_size,end-pos+1)
        _i2c_rdwr(fd,[(addr,0,bytearray([pos])+bytearray(data[pos:pos+count]))])
        time.sleep(t_wr_s)  # Never retry an ambiguously completed programming transaction.
        pos+=count
    actual=spd_read(fd,addr,start,end,transport='i2c')
    if actual!=data[start:end+1]:raise OSError(errno.EIO,'EEPROM write verification failed')


def cmd_write(args):
    if not args.enable_write:raise ValueError('Programming requires --enable-write, --range and --backup')
    if args.ee1004:raise ValueError('ee1004 programming is not supported')
    if args.range is None or not args.backup:raise ValueError('Programming requires an explicit --range and --backup file')
    _address(args.addr);_bus(args.bus)
    image=bytearray(Path(args.infile).read_bytes())
    start,end=args.range;_range(start,end)
    if len(image) not in (128,256) or end>=len(image):raise ValueError('Input/range must fit one 128/256-byte image')
    if image[2] not in SUPPORTED:raise ValueError('Unsupported programming memory generation')
    if args.page not in (8,16,32,64) or not math.isfinite(args.delay) or not .005<=args.delay<=1:
        raise ValueError('Invalid page size or write delay')
    if args.fix_crc:fix_base_crc(image)
    if _driver(args.bus,args.addr):raise OSError(errno.EBUSY,'Kernel-owned device cannot be programmed by the raw path')
    # Hold a single session across backup, programming and verification.
    with bus_session(args.bus) as fd:
        if not adapter_functions(fd)&I2C_FUNC_I2C:raise ValueError('Programming requires a raw-I2C capable adapter')
        original=spd_read(fd,args.addr,0,len(image)-1,transport='i2c')
        repeated=spd_read(fd,args.addr,0,len(image)-1,transport='i2c')
        if original!=repeated:raise OSError(errno.EIO,'Unstable target; programming refused')
        if original[2]!=image[2]:raise ValueError('Target and input memory generations differ')
        expected=bytearray(original);expected[start:end+1]=image[start:end+1]
        issues=image_diagnostics(expected)
        if issues:raise ValueError('Result would have invalid integrity: '+'; '.join(issues))
        # Exclusive creation prevents overwriting an earlier backup (or the input).
        with open(args.backup,'xb') as stream:
            stream.write(original);stream.flush();os.fsync(stream.fileno())
        spd_write(fd,args.addr,bytes(image),start,end,args.page,args.delay,True)
        final=spd_read(fd,args.addr,0,len(image)-1,transport='i2c')
        if final!=expected:raise OSError(errno.EIO,'Full-image verification failed; retain the backup')
    print(f'Wrote and verified bytes {start}-{end}; original saved at {args.backup}')
    return 0


def cmd_doctor(args):
    platform={}
    for key in ('sys_vendor','product_name','bios_version'):
        try:platform[key]=(Path('/sys/class/dmi/id')/key).read_text().strip()
        except OSError:platform[key]='Unavailable'
    adapters=inventory(args.bus)
    print(json.dumps(dict(platform=platform,kernel=os.uname().release,adapters=adapters,
                         notes=['Adapter numbers are not DIMM slot numbers.',
                                'No mux, PCI, iLO or firmware configuration is changed.',
                                'HP Gen8 firmware may not expose every DIMM SPD through host adapters.',
                                'No accessible EEPROM does not imply an empty DIMM slot.']),indent=2))
    return 0


def cmd_list(args):
    print(json.dumps(inventory(args.bus),indent=2));return 0


def cmd_scan(args):
    if not args.probe:return cmd_list(args)
    # An explicit bus and --probe are required. No SMBus QUICK or bus-wide sweep.
    records=[]
    with bus_session(args.bus) as fd:
        for addr in range(0x50,0x58):
            if _driver(args.bus,addr):
                records.append(dict(address=f'0x{addr:02X}',status='kernel-owned; use sysfs'));continue
            try:
                header=spd_read(fd,addr,0,2,chunk=1,retries=0)
                records.append(dict(address=f'0x{addr:02X}',status='responding',memory_type=f'0x{header[2]:02X}'))
            except OSError as exc:
                records.append(dict(address=f'0x{addr:02X}',status='unavailable',errno=exc.errno,error=str(exc)))
    print(json.dumps(records,indent=2));return 0


def cmd_read(args):
    if args.out and args.report and Path(args.out).resolve()==Path(args.report).resolve():
        raise ValueError('Image output and report must be different files')
    backend='sysfs' if args.ee1004 else args.backend
    if args.ee1004 and not ee1004_present(args.bus,args.addr):raise ValueError('--ee1004 requires an ee1004-bound device')
    result=acquire_spd(args.bus,args.addr,args.start,args.end,args.chunk,backend,args.retries,args.snapshots,args.allow_invalid)
    if args.out:atomic_output(args.out,result.data)
    else:print(hexdump(result.data,start=result.start))
    report=result.report()
    print(json.dumps(report),file=sys.stderr)
    if args.report:atomic_output(args.report,(json.dumps(report,indent=2)+'\n').encode())
    return 0


def _parse_range(value):
    try:
        parts=value.split(':')
        if len(parts)==1:return (int(parts[0],0),)*2
        if len(parts)==2:return tuple(int(x,0) for x in parts)
    except ValueError:pass
    raise argparse.ArgumentTypeError('Use inclusive START:END, decimal or 0x-prefixed')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('doctor',help='Passive platform/adapter diagnostics for hardware support')
    p.add_argument('--bus',type=int);p.set_defaults(func=cmd_doctor)
    p=sub.add_parser('list',help='Passive adapter and kernel EEPROM inventory (JSON)')
    p.add_argument('--bus',type=int);p.set_defaults(func=cmd_list)
    p=sub.add_parser('scan',help='Passive inventory, or explicit SPD-only address probes')
    p.add_argument('--bus',required=True,type=int)
    p.add_argument('--probe',action='store_true',help='Actively read offsets 0-2 at 0x50-0x57 on this adapter')
    p.set_defaults(func=cmd_scan)
    p=sub.add_parser('scan-ee1004',help='Passive inventory including ee1004 interfaces')
    p.add_argument('--bus',type=int);p.set_defaults(func=cmd_list)
    for name in ('read','dump','dump-ee1004'):
        p=sub.add_parser(name,help='Consistent, exact SPD acquisition; sysfs preferred')
        p.add_argument('--bus',required=True,type=int)
        p.add_argument('--addr',required=True,type=lambda x:int(x,0))
        p.add_argument('--start',type=lambda x:int(x,0),default=0)
        p.add_argument('--end',type=lambda x:int(x,0),default=None,help='Inclusive end; default 255, or 511 for ee1004')
        p.add_argument('--chunk',type=int,default=16)
        p.add_argument('--backend',choices=('auto','sysfs','smbus','i2c'),default='auto')
        p.add_argument('--retries',type=int,default=2)
        p.add_argument('--snapshots',type=int,default=2)
        p.add_argument('--allow-invalid',action='store_true',help='Permit stable images with integrity diagnostics')
        p.add_argument('--out');p.add_argument('--report')
        p.add_argument('--auto',action='store_true',help='Compatibility alias; automatic sysfs preference is the default')
        p.add_argument('--ee1004',action='store_true',default=name=='dump-ee1004')
        p.set_defaults(func=cmd_read)
    p=sub.add_parser('write',help='Explicit raw-I2C programming with backup and mandatory verification')
    p.add_argument('--bus',required=True,type=int);p.add_argument('--addr',required=True,type=lambda x:int(x,0))
    p.add_argument('--in',dest='infile',required=True);p.add_argument('--range',type=_parse_range)
    p.add_argument('--enable-write',action='store_true');p.add_argument('--backup')
    p.add_argument('--page',type=int,default=16);p.add_argument('--delay',type=float,default=.02)
    p.add_argument('--verify',action='store_true',help='Compatibility flag; verification is always enabled')
    p.add_argument('--fix-crc',action='store_true');p.add_argument('--ee1004',action='store_true')
    p.set_defaults(func=cmd_write)
    args=parser.parse_args(argv)
    try:return args.func(args)
    except (ValueError,OSError) as exc:
        detail=''
        if isinstance(exc,PermissionError):detail=' Check access to the selected device; inventory does not require active probing.'
        elif isinstance(exc,OSError) and exc.errno==errno.EBUSY:detail=' Do not force/unbind the device; use the kernel EEPROM interface.'
        print(f'Error: {exc}.{detail}',file=sys.stderr);return 1


if __name__=='__main__':sys.exit(main())
