#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
spd_smbus.py — Linux SMBus/I2C SPD tool (scan/read/write) for /dev/i2c-*
No external dependencies. Uses ioctl(I2C_RDWR) via ctypes.

Examples
--------
# List buses and scan for SPD EEPROMs on bus 0
python spd_smbus.py scan --bus 0

# Read full 256B SPD at 0x50 to file
python spd_smbus.py read --bus 1 --addr 0x50 --out dimm.bin

# Write bytes 176..183 (HPT tag) and verify
python spd_smbus.py write --bus 1 --addr 0x50 --in patched.bin --range 176:184 --verify

# Fix base CRC (0..116, JEDEC XMODEM) before writing whole image
python spd_smbus.py write --bus 1 --addr 0x50 --in new.bin --fix-crc --verify

# Hex dump (and quick decode of a few fields)
python spd_smbus.py dump --bus 1 --addr 0x50
"""
import argparse, ctypes as C, fcntl, glob, os, sys, time
from typing import List, Tuple

# ---- ioctl constants from linux/i2c-dev.h
I2C_RDWR  = 0x0707
I2C_M_RD  = 0x0001

# ---- i2c_msg and i2c_rdwr structs
class i2c_msg(C.Structure):
    _fields_ = [
        ("addr",  C.c_uint16),
        ("flags", C.c_uint16),
        ("len",   C.c_uint16),
        ("buf",   C.c_void_p),
    ]

class i2c_rdwr_ioctl_data(C.Structure):
    _fields_ = [
        ("msgs",  C.POINTER(i2c_msg)),
        ("nmsgs", C.c_uint32),
    ]

def _i2c_rdwr(fd, msgs: List[Tuple[int,int,bytearray]]) -> None:
    """
    msgs: list of (addr, flags, buffer) where buffer is a bytearray (writable for reads)
    """
    # Build C array of i2c_msg, keeping Python buffers alive in a side list
    c_msgs = (i2c_msg * len(msgs))()
    keepalive = []
    for i, (addr, flags, buf) in enumerate(msgs):
        if not isinstance(buf, (bytes, bytearray)):
            raise TypeError("buffer must be bytes/bytearray")
        ba = bytearray(buf) if not isinstance(buf, bytearray) else buf
        keepalive.append(ba)
        c_buf = C.create_string_buffer(len(ba))  # always alloc; copy for writes
        if not (flags & I2C_M_RD) and len(ba):
            C.memmove(c_buf, (C.c_char * len(ba)).from_buffer(ba), len(ba))
        c_msgs[i].addr  = addr
        c_msgs[i].flags = flags
        c_msgs[i].len   = len(ba)
        c_msgs[i].buf   = C.cast(c_buf, C.c_void_p)
        keepalive.append(c_buf)
    data = i2c_rdwr_ioctl_data(C.cast(c_msgs, C.POINTER(i2c_msg)), len(msgs))
    fcntl.ioctl(fd, I2C_RDWR, data)
    # copy read data back
    for i, (addr, flags, buf) in enumerate(msgs):
        if flags & I2C_M_RD:
            src = C.cast(c_msgs[i].buf, C.POINTER(C.c_ubyte))
            for j in range(c_msgs[i].len):
                buf[j] = src[j]

# ---- SPD helpers
def crc16_xmodem(data: bytes) -> int:
    """JEDEC base CRC for DDR3 SPD: poly 0x1021, init 0x0000, no reflect, xorout 0x0000"""
    reg = 0x0000
    for b in data:
        reg ^= (b << 8) & 0xFFFF
        for _ in range(8):
            if reg & 0x8000:
                reg = ((reg << 1) ^ 0x1021) & 0xFFFF
            else:
                reg = (reg << 1) & 0xFFFF
    return reg & 0xFFFF

def fix_base_crc(spd: bytearray) -> None:
    if len(spd) < 128:
        return
    crc = crc16_xmodem(bytes(spd[0:117]))  # 0..116 inclusive
    spd[126] = crc & 0xFF
    spd[127] = (crc >> 8) & 0xFF

def hexdump(b: bytes, width: int = 16) -> str:
    lines=[]
    for off in range(0, len(b), width):
        chunk = b[off:off+width]
        hexs = " ".join(f"{x:02X}" for x in chunk)
        asc  = "".join(chr(x) if 32<=x<127 else "." for x in chunk)
        lines.append(f"{off:03d}: {hexs:<{width*3}}  {asc}")
    return "\n".join(lines)

# ---- low-level SPD ops
def spd_read(fd: int, addr: int, start: int=0, end: int=255, chunk: int=16) -> bytes:
    if not (0x03 <= chunk <= 32):  # keep messages short; many EEPROMs like 16/32B
        chunk = 16
    out = bytearray()
    for ofs in range(start, end+1, chunk):
        n = min(chunk, end - ofs + 1)
        # SMBus random-read: write [offset] then repeated-start read n bytes
        wbuf = bytearray([ofs & 0xFF])
        rbuf = bytearray(n)
        _i2c_rdwr(fd, [
            (addr, 0x0000, wbuf),
            (addr, I2C_M_RD, rbuf),
        ])
        out += rbuf
    return bytes(out)

def spd_write(fd: int, addr: int, data: bytes, start: int=0, end: int=255,
              page_size: int=16, t_wr_s: float=0.02, verify: bool=True) -> None:
    """Page-write with delay and optional verify. Most DDR3 SPD EEPROMs are 16B pages."""
    if page_size not in (8, 16, 32, 64):
        page_size = 16
    start = max(0, start); end = min(255, end)
    view = memoryview(data)
    pos = start
    while pos <= end:
        page_off = pos % page_size
        room = page_size - page_off
        n = min(room, end - pos + 1)
        wbuf = bytearray(1 + n)
        wbuf[0] = pos & 0xFF
        wbuf[1:] = view[pos:pos+n]
        _i2c_rdwr(fd, [(addr, 0x0000, wbuf)])
        time.sleep(t_wr_s)  # write cycle time
        pos += n
    if verify:
        rb = spd_read(fd, addr, start, end)
        if rb != bytes(view[start:end+1]):
            # find first mismatch
            for i, (a,b) in enumerate(zip(rb, view[start:end+1])):
                if a != b:
                    off = start + i
                    raise IOError(f"verify failed at {off} (wrote {b:02X}, read {a:02X})")
    return

# ---- bus helpers
def list_buses() -> List[int]:
    ids=[]
    for p in sorted(glob.glob("/dev/i2c-*")):
        try:
            ids.append(int(p.split("-")[-1]))
        except ValueError:
            pass
    return ids

def open_bus(bus: int) -> int:
    path = f"/dev/i2c-{bus}"
    return os.open(path, os.O_RDWR)

def quick_read_byte0(fd: int, addr: int) -> int:
    """Return first byte or raise on NACK."""
    wbuf = bytearray([0x00])
    rbuf = bytearray(1)
    _i2c_rdwr(fd, [(addr, 0x0000, wbuf), (addr, I2C_M_RD, rbuf)])
    return rbuf[0]

# --------- ee1004 sysfs helpers (DDR4 path) -----------------------------------
SYS_EE = "/sys/bus/i2c/devices"

def ee1004_devpath(bus: int, addr: int) -> str:
    return f"{SYS_EE}/{bus}-{addr:04x}"

def ee1004_present(bus: int, addr: int) -> bool:
    name = os.path.join(ee1004_devpath(bus, addr), "name")
    try:
        with open(name, "r") as f:
            return "ee1004" in f.read().strip().lower()
    except FileNotFoundError:
        # some kernels still provide eeprom without a name; treat existence of file as present
        return os.path.exists(os.path.join(ee1004_devpath(bus, addr), "eeprom"))

def ee1004_read(bus: int, addr: int) -> bytes:
    path = os.path.join(ee1004_devpath(bus, addr), "eeprom")
    with open(path, "rb") as f:
        blob = f.read()
    # Most drivers expose a 512-byte eeprom. If shorter, still return what we got.
    return blob

# ---- CLI
def cmd_scan(args):
    buses = [args.bus] if args.bus is not None else list_buses()
    if not buses:
        print("No /dev/i2c-* buses found (need i2c-dev).", file=sys.stderr); sys.exit(1)
    for bus in buses:
        print(f"[Bus {bus}] scanning 0x50..0x57 (DDR3/raw i2c-dev)")
        try: fd = open_bus(bus)
        except PermissionError: print(f"  ! Permission denied opening /dev/i2c-{bus}"); continue
        found=[]
        for addr in range(0x50,0x58):
            try: b0 = quick_read_byte0(fd, addr); found.append((addr,b0))
            except OSError: pass
        os.close(fd)
        print("  (none)" if not found else "\n".join(f"  addr 0x{a:02X}: Byte0={b0:02X}" for a,b0 in found))
    return 0

def cmd_scan_ee1004(args):
    buses = [args.bus] if args.bus is not None else list_buses()
    if not buses:
        print("No i2c buses found.", file=sys.stderr); sys.exit(1)
    for bus in buses:
        print(f"[Bus {bus}] ee1004 devices (DDR4 SPD via sysfs):")
        hits=[]
        for addr in range(0x50,0x58):
            if ee1004_present(bus, addr):
                size = 0
                try:
                    size = os.path.getsize(os.path.join(ee1004_devpath(bus, addr), "eeprom"))
                except Exception:
                    pass
                hits.append((addr,size))
        if not hits: print("  (none)")
        else:
            for addr,size in hits:
                print(f"  addr 0x{addr:02X}: eeprom file present ({size} bytes)")
    return 0

def cmd_read(args):
    # AUTO: prefer ee1004 if available
    use_ee = args.ee1004 or (args.auto and ee1004_present(args.bus, args.addr))
    if use_ee:
        data = ee1004_read(args.bus, args.addr)
        # honor start/end on the 512-byte blob
        data = data[args.start:args.end+1] if (args.start or args.end != 255) else data
    else:
        fd = open_bus(args.bus)
        try:
            data = spd_read(fd, args.addr, args.start, args.end, args.chunk)
        finally:
            os.close(fd)
    if args.out:
        with open(args.out, "wb") as f:
            # for partial reads, still write a full-size container to be convenient
            full_len = 512 if use_ee else 256
            if args.start != 0 or (args.end+1) != full_len:
                full = bytearray([0xFF]*full_len)
                full[args.start:args.start+len(data)] = data
                f.write(full)
            else:
                f.write(data)
        print(f"Wrote {len(data)} bytes to {args.out}")
    else:
        print(hexdump(data))
    return 0

def _search_hpt(blob: bytes):
    i = 0; hits=[]
    while True:
        j = blob.find(b"HPT\x00", i)
        if j < 0: break
        code = blob[j+4:j+8] if j+8 <= len(blob) else b""
        hits.append((j, code))
        i = j+1
    return hits

def cmd_dump(args):
    # DDR3/raw
    fd = open_bus(args.bus)
    try:
        data = spd_read(fd, args.addr, 0, 255, args.chunk)
    finally:
        os.close(fd)
    print(hexdump(data))
    tag = data[176:180]; code = data[180:184]
    print(f"\nHPT tag: {'present' if tag==b'HPT\\x00' else 'absent'}"
          + (f', code={code.hex().upper()}' if tag==b'HPT\\x00' else ""))

def cmd_dump_ee1004(args):
    # DDR4/sysfs
    blob = ee1004_read(args.bus, args.addr)
    print(f"[Info] Read {len(blob)} bytes")
    # Pretty print by page
    p0 = blob[:256]; p1 = blob[256:512]
    print("\n-- Page 0 (0x00..0xFF) --")
    print(hexdump(p0))
    print("\n-- Page 1 (0x100..0x1FF) --")
    print(hexdump(p1))
    # Hunt for HPT markers anywhere
    hits = _search_hpt(blob)
    if hits:
        print("\nHPT-like markers found:")
        for off,code in hits:
            pretty = code.hex().upper() if len(code)==4 else "(truncated)"
            print(f"  at offset 0x{off:03X}  code={pretty}")
    else:
        print("\nNo 'HPT\\x00' marker found.")

def cmd_write(args):
    if args.ee1004:
        raise SystemExit("ee1004 path is read-only; writing via sysfs is not supported.")
    with open(args.infile, "rb") as f:
        img = bytearray(f.read())
    if len(img) < 256: raise SystemExit("Input image must be at least 256 bytes")
    if args.fix_crc: fix_base_crc(img); print("Fixed base CRC16 (0..116)")
    start,end = args.range
    fd = open_bus(args.bus)
    try:
        spd_write(fd, args.addr, img, start, end, page_size=args.page, t_wr_s=args.delay, verify=args.verify)
    finally:
        os.close(fd)
    print(f"Wrote {end-start+1} bytes to 0x{args.addr:02X} on bus {args.bus}")

def _parse_range(s: str) -> Tuple[int,int]:
    if ":" not in s:
        v = int(s, 0); return (v, v)
    a,b = s.split(":",1)
    return (int(a,0), int(b,0))

def main(argv=None):
    ap = argparse.ArgumentParser(description="Linux SMBus/I2C SPD expansion tool (DDR3 + DDR4/ee1004)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="scan 0x50..0x57 via raw i2c-dev (DDR3-style)")
    p.add_argument("--bus", type=int); p.set_defaults(func=cmd_scan)

    p = sub.add_parser("scan-ee1004", help="list ee1004 (DDR4 SPD) devices from sysfs")
    p.add_argument("--bus", type=int); p.set_defaults(func=cmd_scan_ee1004)

    p = sub.add_parser("read", help="read SPD bytes (auto: prefer ee1004 when present)")
    p.add_argument("--bus", required=True, type=int)
    p.add_argument("--addr", required=True, type=lambda x:int(x,0))
    p.add_argument("--start", type=lambda x:int(x,0), default=0)
    p.add_argument("--end",   type=lambda x:int(x,0), default=255)
    p.add_argument("--chunk", type=int, default=16)
    p.add_argument("--out")
    p.add_argument("--ee1004", action="store_true", help="force ee1004 sysfs path (DDR4)")
    p.add_argument("--auto", action="store_true", help="prefer ee1004 if available at bus/addr")
    p.set_defaults(func=cmd_read)

    p = sub.add_parser("dump", help="hexdump (DDR3/raw i2c-dev)")
    p.add_argument("--bus", required=True, type=int)
    p.add_argument("--addr", required=True, type=lambda x:int(x,0))
    p.add_argument("--chunk", type=int, default=16)
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("dump-ee1004", help="hexdump (DDR4/ee1004 sysfs), searches HPT markers")
    p.add_argument("--bus", required=True, type=int)
    p.add_argument("--addr", required=True, type=lambda x:int(x,0))
    p.set_defaults(func=cmd_dump_ee1004)

    p = sub.add_parser("write", help="write SPD bytes (i2c-dev only; NOT ee1004)")
    p.add_argument("--bus", required=True, type=int)
    p.add_argument("--addr", required=True, type=lambda x:int(x,0))
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--range", type=_parse_range, default=(0,255), help="byte range a:b (inclusive)")
    p.add_argument("--page", type=int, default=16, help="EEPROM page size (8/16/32/64)")
    p.add_argument("--delay", type=float, default=0.02, help="write cycle delay seconds (t_WR)")
    p.add_argument("--verify", action="store_true", help="read-back verify")
    p.add_argument("--fix-crc", action="store_true", help="fix base CRC16 (bytes 126..127)")
    p.add_argument("--ee1004", action="store_true", help="(guard) not supported for write")
    p.set_defaults(func=cmd_write)

    try: return ap.parse_args(argv).__dict__['func'](ap.parse_args(argv))
    except PermissionError:
        print("Permission denied. Run as root or relax udev on /dev/i2c-* and sysfs eeprom.", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())