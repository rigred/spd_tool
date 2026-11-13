# SPDX-License-Identifier: MIT
"""Windows native SMBus acquisition/programming through official PawnIO modules."""
from contextlib import contextmanager
import json
from pathlib import Path
import sys
import time

from spd_hardware import DeviceImage,SUPPORTED,cancelled,ranked,target_length
from spd_integrity import integrity_info
from spd_pawnio import MODULES,PawnIOSession,module_directory


def address(value):
    if type(value) is not int or not 0x50<=value<=0x57:raise ValueError('SPD address must be 7-bit 0x50..0x57')


class WindowsBackend:
    def __init__(self,profile='i801',directory=None,session_factory=None):
        if profile not in MODULES:raise ValueError('Windows adapter must be i801 or piix4')
        self.profile=profile;self.directory=module_directory(directory)
        self.session_factory=session_factory or PawnIOSession;self._identity=None
        self.target=f'Windows PawnIO {profile} ({self.directory})'

    @contextmanager
    def _session(self,writing=False):
        with self.session_factory(self.profile,self.directory) as bus:
            identity=tuple((k,bus.identity[k]) for k in ('profile','type','base','vendor_id','device_id'))
            if self._identity is not None and identity!=self._identity:raise ValueError('Windows SMBus controller identity changed; discover and review the target again')
            self._identity=identity
            if writing and bus.write_protected() is True:raise ValueError('Host SPD write protection is enabled; it will not be disabled. Use an external programmer')
            yield bus

    def _read(self,bus,addr,cancel=None):
        address(addr)
        def byte(offset):
            cancelled(cancel)
            result=bus.execute('ioctl_smbus_xfer',(addr,1,offset,2,0),1)[0]
            if not 0<=result<=255:raise OSError('Invalid byte from Windows SMBus controller')
            return result
        header=bytes(byte(i) for i in range(3));length=target_length(header)
        if header[2] not in SUPPORTED:raise ValueError('Windows native acquisition supports SDR/DDR/DDR2/DDR3; SPD page switching is unavailable')
        return header+bytes(byte(i) for i in range(3,length))

    def read(self,addr,cancel=None):
        address(addr);cancelled(cancel)
        with self._session() as bus:
            data=self._read(bus,addr,cancel)
            if data!=self._read(bus,addr,cancel):raise ValueError('Windows SPD snapshots differ; unstable image was not accepted')
        info=integrity_info(data);issues=() if info['status']=='VALID' else (f'{info["variant"]} mismatch over {info["coverage"]}',)
        return DeviceImage(self.target,addr,data,'Windows PawnIO '+self.profile,issues)

    def scan(self,active=False,cancel=None,log=lambda message:None):
        if not active:raise ValueError('Enable probing SPD addresses (0x50–0x57); Windows has no passive EEPROM inventory')
        images=[];errors=[]
        for addr in range(0x50,0x58):
            cancelled(cancel);log(f'Reading Windows {self.profile} / 0x{addr:02X}')
            try:images.append(self.read(addr,cancel))
            except (OSError,ValueError) as exc:
                cancelled(cancel);errors.append(f'0x{addr:02X}: {exc}')
        return ranked(images),errors

    @contextmanager
    def programmer(self,addr):
        address(addr)
        with self._session(writing=True) as bus:
            backend=self
            class Session:
                def read(self):return backend._read(bus,addr)
                def write(self,offset,value):
                    if type(offset) is not int or not 0<=offset<self.length or type(value) is not int or not 0<=value<=255:raise ValueError('Invalid SPD byte write')
                    # One command only. An ambiguous EEPROM write is never retried.
                    bus.execute('ioctl_smbus_xfer',(addr,0,offset,2,value),0)
                    deadline=time.monotonic()+0.1
                    while True:
                        try:
                            if bus.execute('ioctl_smbus_xfer',(addr,1,offset,2,0),1)[0]==value:return
                        except OSError as exc:
                            if getattr(exc,'winerror',None) in (5,50,87):raise
                        if time.monotonic()>=deadline:raise OSError(f'EEPROM byte {offset} did not verify after the write; programming stopped')
                        time.sleep(0.005)
            session=Session();header=self._read(bus,addr);session.length=target_length(header[:3]);yield session


def inventory(directory=None,session_factory=None):
    adapters=[];errors=[]
    for profile in MODULES:
        backend=WindowsBackend(profile,directory,session_factory)
        try:
            with backend._session() as bus:
                adapters.append(dict(bus.identity,write_protected=bus.write_protected(),module_directory=str(backend.directory)))
        except (ValueError,OSError) as exc:errors.append(dict(profile=profile,error=str(exc)))
    return dict(adapters=adapters,errors=errors)


def add_parser(subparsers):
    parser=subparsers.add_parser('windows-smbus',help='Native Windows SPD read/write using the official PawnIO driver and modules')
    parser.add_argument('--module-dir',help='Override the pinned PawnIO SMBus module folder')
    parser.add_argument('--adapter',choices=tuple(MODULES),default='i801')
    operations=parser.add_subparsers(dest='operation',required=True)
    operations.add_parser('adapters',help='Identify supported controllers without probing SPD addresses')
    scan=operations.add_parser('scan');scan.add_argument('--probe',action='store_true',help='Explicitly probe SPD addresses 0x50–0x57')
    read=operations.add_parser('read');read.add_argument('--addr',required=True,type=lambda s:int(s,0));read.add_argument('--out',required=True);read.add_argument('--allow-invalid',action='store_true')
    write=operations.add_parser('write');write.add_argument('--addr',required=True,type=lambda s:int(s,0));write.add_argument('--spd',required=True);write.add_argument('--range',required=True,metavar='START:END');write.add_argument('--backup',help='Required when --enable-write is used');write.add_argument('--enable-write',action='store_true',help='Commit the reviewed range; default is preview only')
    parser.set_defaults(func=command)


def command(args):
    from spd_hardware import prepare_programming,execute_programming
    from spd_library import load_spd_file
    if sys.platform!='win32':raise ValueError('Native SMBus requires Windows; use the Linux SMBus or USB serial backend here')
    if args.operation=='adapters':
        report=inventory(args.module_dir);print(json.dumps(report,indent=2))
        if not report['adapters']:raise ValueError('No supported Windows SMBus adapter; see controller errors above and docs/WINDOWS.md')
        return
    backend=WindowsBackend(args.adapter,args.module_dir)
    if args.operation=='scan':
        images,errors=backend.scan(active=args.probe);print(json.dumps(dict(images=[d.summary() for d in images],errors=errors),indent=2));return
    if args.operation=='read':
        image=backend.read(args.addr)
        if not image.valid and not args.allow_invalid:raise ValueError('SPD integrity failed; --allow-invalid permits an unchanged, stable recovery dump')
        with Path(args.out).open('xb') as output:output.write(image.data)
        print(json.dumps(image.summary(),indent=2));return
    if args.enable_write and not args.backup:raise ValueError('--backup is required with --enable-write')
    try:start,end=(int(x,0) for x in args.range.split(':'))
    except ValueError as exc:raise ValueError('Range must be START:END, inclusive') from exc
    image=load_spd_file(args.spd).data
    plan=prepare_programming(backend,args.addr,image,start,end)
    print(json.dumps(execute_programming(backend,plan,args.backup) if args.enable_write else dict(plan.report(),preview=True),indent=2))
