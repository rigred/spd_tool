# Embedded SPD extraction

Memory-down systems may supply SPD-like initialization data from firmware
instead of an SMBus EEPROM. A removable DIMM can therefore be readable through
`smbus` while the soldered memory has no corresponding exposed device. Firmware
may contain several profiles selected by board straps, SKU or firmware logic.
Finding a profile does not identify the configuration selected at boot.

## Scan a BIOS image

Obtain the BIOS update for the exact system model from the system vendor and
unpack its download archive. The scanner accepts a binary update capsule,
BIOS region, full flash image or an already extracted binary section. It reads
files offline and requires no root privileges or hardware access.

```sh
python spd_tool.py firmware scan --input BIOS.cap --out spd-from-bios
```

The output directory must be new. Each candidate is saved as a binary file;
`report.json` records source paths, byte offsets, memory-type signatures,
integrity results, confidence, SHA-256 hashes and extraction warnings. Repeated
base blocks share a profile ID, while every occurrence retains its location.
Source firmware is never modified, and extracted bytes are never repaired.

Omit `--out` for inspection without extraction, or use `--json` for a report
on stdout:

```sh
python spd_tool.py firmware scan --input BIOS.cap --json
```

The default search requires plausible supported-layout fields and a valid
base checksum/CRC. Firmware initialization tables sometimes omit integrity
bytes. Enable heuristic candidates explicitly when investigating these:

```sh
python spd_tool.py firmware scan --input BIOS.cap \
  --include-invalid --out spd-candidates
```

`INVALID` and `UNVERIFIED` candidates require manual verification. Intel's
vendor-defined LPDDR3 type `0xF1` is always `UNVERIFIED`; it is not relabeled as
JEDEC DDR3 to obtain a successful integrity check. Heuristic matches in code
or unrelated tables remain possible.

## Compressed UEFI sections

A raw image scan cannot see SPD data inside compressed or encrypted sections.
Use [UEFIExtract](https://github.com/LongSoft/UEFITool) to unpack supported UEFI
containers, then scan its output directory recursively:

```sh
UEFIExtract BIOS.cap
python spd_tool.py firmware scan --input BIOS.cap.dump \
  --include-invalid --out spd-from-sections
```

Use the actual output directory produced by the installed UEFIExtract build.
The scanner does not invoke unpackers or execute firmware. ZIP archives and
vendor installer executables also need unpacking before scanning. Unsupported
vendor containers, encrypted data, split tables and timing values constructed
by firmware code require format-specific analysis. An empty scan is not proof
that memory configuration data is absent.

Offsets in a section scan are relative to the named section file. They are
not original capsule offsets or physical SPI flash addresses. Nested unpacker
outputs can contain both a parent body and its child sections, producing
multiple occurrences of the same profile. Symbolic links are not followed.

## Extraction extent and supported signatures

The default extraction is exactly 128 bytes, including the base integrity
field. Firmware often stores only a base block even when its header describes
a larger EEPROM. This is not a reconstruction of a complete module EEPROM.
Legacy SUM8 covers bytes 0-62; DDR3 CRC follows byte 0's declared coverage;
DDR4 and JEDEC LPDDR3/LPDDR4/LPDDR4X base CRC covers bytes 0-125. Remaining
extracted bytes are not thereby authenticated.

| Signature | Search and extraction | Core decoder/editor |
| --- | --- | --- |
| SDR, DDR, DDR2, DDR3 | Base integrity check and optional heuristic mode | Supported |
| DDR4 (`0x0C`) | Base CRC and optional heuristic mode | Not supported |
| JEDEC LPDDR3 (`0x0F`), LPDDR4 (`0x10`), LPDDR4X (`0x11`) | Base CRC and optional heuristic mode | Not supported |
| Intel LPDDR3 (`0xF1`) | Heuristic mode only; vendor-defined integrity | Not supported |

These are conservative layout filters, not exhaustive recognition of every
SPD revision or proprietary memory-down format. DDR5 and later signatures
are not searched.

For a table whose extent has been established independently, request a larger
slice explicitly:

```sh
python spd_tool.py firmware scan --input memory-table.bin \
  --length 256 --include-invalid --out extended-candidates
```

`--length` accepts 128, 256 or 512. Bytes beyond 127 are labeled adjacent
context with an unverified table boundary. The scanner does not infer their
ownership or verify extension CRCs. If the requested slice extends past EOF,
only the complete 128-byte base is extracted and the report explains the
shortfall. No zero padding is added. Adjacent profiles are retained even when
an explicit larger slice overlaps them.

A supported 128-byte SDR/DDR/DDR2/DDR3 extraction can be inspected directly:

```sh
python spd_tool.py gui --spd candidate.bin
python spd_tool.py dump --spd candidate.bin --programmer
```

## Interpreting a laptop firmware scan

On Skylake-era systems, investigate ordinary DDR3/DDR4 and LPDDR3 signatures
as appropriate for the board. An ASUS model name alone does not establish the
onboard memory technology or firmware layout. Compare candidate organization,
timings and any retained identity data with the soldered DRAM markings and
system specification. Establish profile selection separately through firmware
analysis or platform documentation.

Start with an OEM update image. Reading the running machine's SPI flash is a
separate, platform-specific acquisition task; the scanner does not enable
internal flash access, probe embedded controllers or bypass firmware locks.
An update image may differ from the installed firmware and may contain
profiles for several hardware variants. Preserve the original file and hash.

## Limits and failures

The scanner limits individual inputs to 128 MiB and total bytes scanned to
1024 MiB by default. Adjust these explicitly for larger extracted trees:

```sh
python spd_tool.py firmware scan --input BIOS.cap.dump \
  --max-file-mib 256 --max-total-mib 2048 --out larger-scan
```

At most 20,000 regular files and 10,000 candidates are accepted. Read errors
and size-limit failures are recorded in the report, and the command exits with
status 1 for an incomplete scan. No matches is a successful scan with status 0.
Output and invalid-argument errors also exit nonzero. Existing output
directories are rejected rather than overwritten.

See also [hardware acquisition](HARDWARE.md),
[image formats](FORMATS.md) and the coreboot
[SPD extraction utility description](https://doc.coreboot.org/util.html).
