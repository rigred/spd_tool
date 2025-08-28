#!/usr/bin/env python3
"""
Convert an SPD CSV dump into a binary .bin file (DDR3‑friendly, strict range checks).

Changes vs v2
- Index column is **decimal** by default and now supports **ranges** like
  "42 - 60" which are interpreted as **half‑open**: [start, end) — i.e. 42..59.
- For range rows, the VALUE must **exactly** fit the range length:
    • Hex run (e.g., "B9DD" or "B9 DD") → must decode to (end-start) bytes.
    • String (e.g., part number) → len(string) must equal (end-start).
  Otherwise the tool raises a clear error and exits.
- For single‑index rows, only a **single byte** value is allowed. Multi‑byte hex
  or strings require a range row; this prevents accidental overflow beyond 256.
- Enforces that no write goes past the requested output length (default 256).

Usage:
  python spd_csv_to_bin_v3.py input.csv -o spd.bin --length 256 --fix-crc

"""
from __future__ import annotations
import argparse
import csv
import re
import sys
from typing import Dict, Iterable, List, Optional, Tuple

HEX_PAIR_RE = re.compile(r"^[0-9A-Fa-f]{2}$")
ONLY_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
RANGE_RE = re.compile(r"^\s*(\d+)\s*[-–—]\s*(\d+)\s*$")  # supports -, –, —
INT_IN_TEXT_RE = re.compile(r"(-?\d+)")


def strip_comment(s: str) -> str:
    for sep in ("#", "//", ";"):
        if sep in s:
            s = s.split(sep, 1)[0]
    return s.strip()


def parse_index_or_range(token: str) -> Tuple[int, Optional[int]]:
    """Return (start, end_exclusive or None). Indices are **decimal**.
    Accepts either 'N' or 'N - M'. For ranges, uses half‑open [start, end) so the
    end index itself is not written; this matches your CSV style where '60' is
    written on its own after '42 - 60'.
    """
    if token is None:
        raise ValueError("missing index")
    s = strip_comment(token)
    if not s:
        raise ValueError("empty index cell")
    m = RANGE_RE.match(s)
    if m:
        start = int(m.group(1), 10)
        end = int(m.group(2), 10)
        if end <= start:
            raise ValueError(f"invalid range '{s}': end ({end}) must be > start ({start})")
        return start, end
    # single index; be forgiving of 'Byte 126' etc.
    m2 = INT_IN_TEXT_RE.search(s)
    if not m2:
        raise ValueError(f"cannot parse index '{token}' as decimal or range")
    start = int(m2.group(1), 10)
    if start < 0:
        raise ValueError("index must be >= 0")
    return start, None


def normalize_hex_run(s: str) -> Optional[bytes]:
    """Return bytes if s looks like a pure hex run (with or without spaces)."""
    t = strip_comment(s)
    if not t:
        return None
    t = t.replace(" ", "").replace("\t", "")
    if len(t) % 2 != 0:
        return None
    if not ONLY_HEX_RE.match(t):
        return None
    try:
        return bytes(int(t[i:i+2], 16) for i in range(0, len(t), 2))
    except Exception:
        return None


def parse_value_byte(token: str) -> Optional[int]:
    if token is None:
        return None
    s = strip_comment(token)
    if not s:
        return None
    # 0xNN
    if s.lower().startswith("0x"):
        try:
            v = int(s, 16)
            return v if 0 <= v <= 255 else None
        except Exception:
            return None
    # NNh
    if s.endswith(('h','H')) and ONLY_HEX_RE.match(s[:-1]):
        try:
            v = int(s[:-1], 16)
            return v if 0 <= v <= 255 else None
        except Exception:
            return None
    # NN (prefer hex pair)
    if HEX_PAIR_RE.match(s):
        try:
            return int(s, 16)
        except Exception:
            return None
    # decimal byte
    if s.isdigit():
        try:
            v = int(s, 10)
            return v if 0 <= v <= 255 else None
        except Exception:
            return None
    return None


def unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    return s


def read_csv_records(path: str) -> List[Tuple[str, str]]:
    with open(path, 'r', newline='', encoding='utf-8', errors='ignore') as f:
        sample = f.read(2048)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample)
        except Exception:
            dialect = csv.excel
        reader = csv.reader(f, dialect)
        try:
            header = next(reader)
        except StopIteration:
            return []
        # normalize header
        h0 = (header[0] or '').strip().lower()
        h1 = (header[1] or '').strip().lower() if len(header) > 1 else ''
        if not ("index" in h0 or "byte" in h0 or "addr" in h0):
            # no header; treat first row as data — prepend it back
            rows = [header] + list(reader)
        else:
            rows = list(reader)
    # keep only non-empty 2-column rows
    out: List[Tuple[str, str]] = []
    for r in rows:
        if not r:
            continue
        if len(r) < 2:
            # allow a 1‑col row if it's entirely blank
            if not strip_comment(r[0]):
                continue
            raise SystemExit(f"Bad row (needs 2 columns): {r}")
        idx, val = r[0], r[1]
        if strip_comment(idx) == '' and strip_comment(val) == '':
            continue
        out.append((idx, val))
    return out


def build_buffer(records: List[Tuple[str, str]], total_len: int, encoding: str) -> bytearray:
    buf = bytearray([0x00] * total_len)
    written: Dict[int, int] = {}

    for idx_str, val_str in records:
        start, end = parse_index_or_range(idx_str)
        if end is None:
            # single index — enforce single byte
            b = parse_value_byte(val_str)
            if b is None:
                # maybe the user tried to put a string or multi‑byte hex on a single index
                if normalize_hex_run(val_str):
                    raise SystemExit(
                        f"Value '{val_str}' at index {start} decodes to multiple bytes; "
                        f"use a range like '{start} - {start+len(normalize_hex_run(val_str))}' instead.")
                raise SystemExit(
                    f"Non‑byte value at index {start}: '{val_str}'. "
                    f"Strings or multi‑byte hex require a range (e.g., '{start} - {start+N}').")
            if start >= total_len:
                raise SystemExit(f"Index {start} is outside output length {total_len}")
            buf[start] = b
            written[start] = b
            continue

        # range path: half‑open [start, end)
        length = end - start
        data = normalize_hex_run(val_str)
        if data is not None:
            if len(data) != length:
                raise SystemExit(
                    f"Range {start}-{end} expects {length} bytes, but hex field decodes to {len(data)} bytes")
        else:
            # treat as string
            s = unquote(val_str)
            data = s.encode(encoding, errors='strict')
            if len(data) != length:
                raise SystemExit(
                    f"Range {start}-{end} expects {length} bytes, but string length is {len(data)}")
        # bounds check
        if end > total_len:
            raise SystemExit(
                f"Range {start}-{end} exceeds output length {total_len} (max index {total_len-1})")
        # write
        for off, byte in enumerate(data):
            i = start + off
            buf[i] = byte
            written[i] = byte
    return buf


def crc16_ccitt(data: bytes, init: int = 0x0000) -> int:
    crc = init & 0xFFFF
    for b in data:
        crc ^= (b & 0xFF) << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def main() -> None:
    ap = argparse.ArgumentParser(description="Convert SPD CSV to .bin with strict decimal index/range handling")
    ap.add_argument("csv", help="Input CSV path")
    ap.add_argument("-o", "--out", default="spd.bin", help="Output .bin path")
    ap.add_argument("--length", type=int, default=256, help="Total output bytes (default 256)")
    ap.add_argument("--encoding", default="ascii", help="Encoding for string ranges (default ascii)")
    ap.add_argument("--fix-crc", action="store_true", help="Recompute DDR3 base CRC over bytes 0..125 → bytes 126..127 (LSB,MSB)")
    args = ap.parse_args()

    records = read_csv_records(args.csv)
    buf = build_buffer(records, args.length, args.encoding)

    if args.fix_crc:
        if len(buf) < 128:
            print("[warn] Output shorter than 128 bytes; skipping CRC update")
        else:
            crc = crc16_ccitt(bytes(buf[0:126]))
            buf[126] = crc & 0xFF
            buf[127] = (crc >> 8) & 0xFF
            print(f"[info] Base CRC16 (0..125) = 0x{crc:04X} → [126]=0x{buf[126]:02X}, [127]=0x{buf[127]:02X}")

    with open(args.out, 'wb') as f:
        f.write(buf)

    last_written = max(i for i, b in enumerate(buf) if b != 0x00) if any(buf) else -1
    print(f"Wrote {len(buf)} bytes → {args.out} | highest non‑zero index: {last_written}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr)
        sys.exit(1)
