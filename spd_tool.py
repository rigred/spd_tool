#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# spd_tool.py
#
# Main entry point for the modular SPD tool. This file contains the
# command-line interface (CLI) and orchestrates calls to the SPD library.
#
import argparse
import json
import sys
from spd_library import load_spd_file, hexdiff
from spd_smbus import main as smbus_main

def _json_default(o):
    # Make decoder output JSON-serializable.
    if isinstance(o, (bytes, bytearray, memoryview)):
        return bytes(o).hex()  # or list(o) if you prefer arrays of ints
    if isinstance(o, set):
        return sorted(o)
    # Add other special cases if your decoded_data can include them
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")

def cmd_dump(args: argparse.Namespace):
    """Handles the 'dump' command."""
    spd = load_spd_file(args.spd)
    decoded_data = spd.get_decoded_data()

    if args.json:
        # Support stdout when path is '-' (common CLI idiom)
        if args.json == "-":
            json.dump(decoded_data, sys.stdout, indent=2, default=_json_default)
            sys.stdout.write("\n")
        else:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(decoded_data, f, indent=2, default=_json_default)
            # if you print a status line, print it to stderr so it doesn't pollute stdout:
            print(f"[OK] Wrote decoded SPD data to {args.json}", file=sys.stderr)
        return

    # Use the decoder's pretty print method
    spd.decoder.pretty_print(decoded_data, programmer_mode=args.programmer)

def cmd_diff(args: argparse.Namespace):
    """Handles the 'diff' command."""
    spd_a = load_spd_file(args.file_a)
    spd_b = load_spd_file(args.file_b)

    print(f"[File A] {args.file_a}")
    print(f"[File B] {args.file_b}")

    for label, spd in (("File A", spd_a), ("File B", spd_b)):
        crc = spd.decoded_data['crc_info']
        print(f"[{label} CRC] Status: {crc['status']} (Coverage: {crc['coverage']}, Variant: {crc['variant']})")

    diffs = hexdiff(spd_a.data, spd_b.data)
    print(f"\n[Diff] {len(diffs)} differing bytes")

    if diffs:
        print("\n  Offset | File A Val | File B Val")
        print("  -------|------------|------------")
        diff_list = diffs[:args.limit] if args.limit else diffs
        for off, a, b in diff_list:
            print(f"  {off:03d}    |     {a:02X}     |     {b:02X}")

    if args.show_maps:
        print("\n--- File A SPD field map (raw) ---")
        print(spd_a.decoder.dump_field_map())
        print("\n--- File B SPD field map (raw) ---")
        print(spd_b.decoder.dump_field_map())

def cmd_patch(args: argparse.Namespace):
    """Handles the 'patch' command."""
    source_spd = load_spd_file(args.source)
    target_spd = load_spd_file(args.target)

    patched_data = target_spd.patch(source_spd, args)

    with open(args.out, "wb") as f:
        f.write(patched_data)
    print(f"[OK] Wrote patched SPD to {args.out}")

def main():
    """Builds and executes the command-line interface."""
    parser = argparse.ArgumentParser(description="Modular SPD Tool (SDR + DDR families).")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # Dump command
    p_dump = subparsers.add_parser("dump", help="Decode and display a single SPD file.")
    p_dump.add_argument("--spd", required=True, help="Input SPD file (.bin or text).")
    p_dump.add_argument("--json", help="Export decoded data to a JSON file.")
    p_dump.add_argument("--programmer", action="store_true", help="Show offsets, hex values, and undecoded gaps in dump output.")
    p_dump.add_argument("--quiet", action="store_true", help="suppress status messages")
    p_dump.set_defaults(func=cmd_dump)

    # Diff command
    p_diff = subparsers.add_parser("diff", help="Compare two SPD files.")
    p_diff.add_argument("--file-a", required=True, help="First SPD file for comparison.")
    p_diff.add_argument("--file-b", required=True, help="Second SPD file for comparison.")
    p_diff.add_argument("--show-maps", action="store_true", help="Show raw field maps for detailed comparison.")
    p_diff.add_argument("--limit", type=int, help="Limit diff output to first N differences.")
    p_diff.set_defaults(func=cmd_diff)

    # Patch command
    p_patch = subparsers.add_parser("patch", help="Patch a target SPD with data from a source SPD.")
    p_patch.add_argument("--source", required=True, help="Source SPD to copy data from.")
    p_patch.add_argument("--target", required=True, help="Target SPD to be patched.")
    p_patch.add_argument("--out", required=True, help="Output file for patched SPD.")
    p_patch.add_argument("--force", action="store_true", help="Force potentially unsafe operations.")
    p_patch.add_argument("--copy-vendor", action="store_true", help="Copy vendor/customer region (bytes 176-255).")
    p_patch.add_argument("--copy-hpt", action="store_true", help="Copy only the HP SmartMemory HPT block (bytes 176-183).")
    p_patch.add_argument("--set-hpt", type=lambda x: bytes.fromhex(x.replace(":", "")), help="Set a specific 4-byte HPT code (e.g., A40185E8).")
    p_patch.add_argument("--copy-mfgid", action="store_true", help="Copy JEDEC manufacturer ID (bytes 117-118).")
    p_patch.add_argument("--copy-partnum", action="store_true", help="Copy module part number (bytes 128-145).")
    p_patch.add_argument("--copy-range", action="append", help="Copy an arbitrary byte range START:END (e.g., 0x10:0x20).")
    p_patch.set_defaults(func=cmd_patch)

    p = subparsers.add_parser("smbus", help="SMBus/I2C SPD ops (scan/read/write)")
    p.add_argument("args", nargs=argparse.REMAINDER, help="pass-through to spd_smbus.py")
    def _smbus_cmd(ns):
    # forward args to the expansion tool's argparse
        sys.exit(smbus_main(ns.args))
    p.set_defaults(func=_smbus_cmd)


    args = parser.parse_args()
    try:
        args.func(args)
    except (ValueError, FileNotFoundError, SystemExit, NotImplementedError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
