#!/usr/bin/env python3
"""
spd_text_to_bin.py — Convert text SPD hex dumps back to binary (.bin)

Accepts lines like:
  000  92 13 0B 01 04 22 00 08 0B 11 01 08 09 00 FC 02
  010  69 78 69 28 69 11 10 79 20 08 3C 3C 00 D8 83 01
…(etc)

Rules:
- Ignores the leading 3- or 4-digit offset token if present.
- Consumes any number of 2-hex-digit tokens per line (case-insensitive).
- Ignores everything else (comments, extra whitespace).
- Writes the collected bytes in the order they appear.

Usage:
  python spd_text_to_bin.py -i "Samsung*.txt" -o out_dir/
  python spd_text_to_bin.py -i "dump.txt" -o dump.bin
"""
import argparse, glob, os, re, sys
from pathlib import Path

HEX2 = re.compile(r"^[0-9A-Fa-f]{2}$")
OFFSET = re.compile(r"^[0-9A-Fa-f]{3,4}$")  # e.g. 000, 010, 0A0, 00A0

def parse_text_spd(path: Path) -> bytes:
    out = bytearray()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # Split on whitespace; skip empty lines
            parts = line.strip().split()
            if not parts:
                continue
            # If the first token looks like an address/offset, drop it
            if OFFSET.match(parts[0]):
                parts = parts[1:]
            # Collect any 2-hex-digit tokens
            for tok in parts:
                if HEX2.match(tok):
                    out.append(int(tok, 16))
                # else ignore non-hex tokens silently
    return bytes(out)

def main():
    ap = argparse.ArgumentParser(description="Convert text SPD hex dump(s) to binary")
    ap.add_argument("-i", "--input", required=True,
                    help="Input file (txt) or glob (quote it!)")
    ap.add_argument("-o", "--output", required=True,
                    help="Output file (.bin) OR existing directory for batch")
    ap.add_argument("--expect-len", type=int, default=0,
                    help="Optional expected byte length (e.g., 256). If set, will error if mismatched.")
    args = ap.parse_args()

    inputs = sorted(glob.glob(args.input))
    if not inputs:
        print(f"No inputs matched: {args.input}", file=sys.stderr)
        sys.exit(1)

    out_path = Path(args.output)
    is_dir = out_path.exists() and out_path.is_dir()
    if len(inputs) > 1 and not is_dir:
        print("When converting multiple inputs, --output must be an existing directory.", file=sys.stderr)
        sys.exit(1)

    if len(inputs) == 1 and not is_dir:
        # Single file → single output file
        data = parse_text_spd(Path(inputs[0]))
        if args.expect_len and len(data) != args.expect_len:
            print(f"[ERROR] {inputs[0]} produced {len(data)} bytes (expected {args.expect_len})", file=sys.stderr)
            sys.exit(2)
        with open(out_path, "wb") as f:
            f.write(data)
        print(f"[OK] Wrote {len(data)} bytes → {out_path}")
        return

    # Batch mode: write one .bin per input into the output directory
    out_path.mkdir(parents=True, exist_ok=True)
    for inp in inputs:
        data = parse_text_spd(Path(inp))
        if args.expect_len and len(data) != args.expect_len:
            print(f"[WARN] {inp}: got {len(data)} bytes (expected {args.expect_len}); writing anyway.")
        base = Path(inp).stem
        dst = out_path / f"{base}.bin"
        with open(dst, "wb") as f:
            f.write(data)
        print(f"[OK] {inp} → {dst}  ({len(data)} bytes)")

if __name__ == "__main__":
    main()
