# SPD Tool

Decode, compare, patch and edit **DDR2 and DDR3** SPD images with Python 3.9+
(standard library only). The existing SDR decoder and Linux SMBus utilities
are also included. DDR/DDR4/DDR5 decoding is not implemented by the core CLI;
the catalog utility has separate legacy and DDR4 recognition.

## Graphical editor

```sh
python spd_tool.py gui
python spd_tool.py gui --spd module.bin
# Equivalent standalone entry point:
python spd_editor.py module.bin
```

The Tk editor provides:

- Decoded organization, timings, manufacturing, integrity status and warnings.
- Every available byte in an editable table with decimal/hex offsets, field
  labels, saved values and highlighted changes. Double-click a row to edit.
- Multi-byte hex-range writes and dedicated part-number and serial dialogs.
- Undo/redo, file comparison, JSON export, Save and Save As.
- Checksum/CRC repair on save (enabled by default), atomic file replacement,
  and an unsaved-changes prompt when opening another image or closing.

Tk must be installed and a graphical display available. Some Linux Python
installations need the distribution's `python3-tk` package. Windows/macOS
Python installations commonly include Tk. The core CLI does not import Tk
or the Linux-only SMBus driver unless that command is invoked.

Save writes a **binary SPD image**, including when the input was hex text.
Use Save As to retain an original text dump. The editor operates on files;
it does not write to a DIMM EEPROM.

## CLI

```sh
python spd_tool.py dump --spd module.bin
python spd_tool.py dump --spd module.bin --programmer
python spd_tool.py dump --spd module.bin --json decoded.json
python spd_tool.py dump --spd module.bin --json -
python spd_tool.py diff --file-a original.bin --file-b edited.bin --show-maps
python spd_tool.py patch --source donor.bin --target target.bin --out patched.bin --copy-partnum
python spd_tool.py patch --source donor.bin --target target.bin --out patched.bin --copy-range 0x10:0x20
```

Patch ranges are **inclusive**. Manufacturer, part-number and vendor copy
options use the selected generation's offsets. DDR2 uses manufacturing
bytes 64–98; DDR3 uses 117–149. Cross-generation copies and ranges beyond
either image are rejected. A module-type mismatch requires `--force`.
Patching repairs the destination's generation-specific integrity field,
including when byte 0 changes DDR3 CRC coverage.

HP HPT operations are DDR3-specific:

```sh
python spd_tool.py patch --source hp.bin --target target.bin --out patched.bin --copy-hpt --force
```

`--force` overrides module compatibility/HP identification checks; it does
not permit cross-generation copies, truncated ranges or invalid HPT lengths.

## Supported data

| Area | DDR2 | DDR3 |
| --- | --- | --- |
| Type, revision, organization | Ranks, rows/columns, banks, device/bus/ECC widths, density, package, height | Density, ranks, addressing, widths, voltages, capacity |
| Timings | CAS operating points; special tCK fractions; tAC; tRP/tRRD/tRCD/tRAS; tWR/tWTR/tRTP; extended tRC/tRFC; setup/hold, skew, PLL | MTB/FTB with signed fine corrections; tCK/tAA/tRCD/tRP/tRAS/tRC/tRFC/tWR/tRRD/tWTR/tRTP/tFAW; cycles and supported CAS downbins |
| Manufacturing | Continuation-code manufacturer ID, part, revision, location, BCD date, serial | Module/DRAM IDs, part, revision, location, BCD date, serial |
| Integrity | Byte 63 = sum(bytes 0–62) modulo 256 | CRC-16/XMODEM, initial 0, bytes 126–127 little endian; byte 0 selects coverage 0–116 or 0–125 |
| Module details | Type bitmap, burst/refresh/configuration, raw attributes | Unbuffered mapping, mechanical fields, RDIMM registers/control words, LRDIMM buffer identification/personality bytes |
| Extensions | Vendor/customer bytes preserved and editable | Existing DDR3 XMP profile layout and HP HPT; raw extension bytes retained |

Unknown manufacturer IDs keep their bank/code; the bundled name table covers
common vendors, not all of JEP106. Reserved fields, DDR2 EPP, undocumented
vendor data, revision-specific XMP extensions and LRDIMM buffer programming
fields remain raw. Their complete bytes can be viewed, edited and round-tripped;
this is not a claim to decode every proprietary extension. XMP profiles with
invalid time bases, missing blocks or disabled flags are not presented as
active operating profiles.

Images from 128 to 256 bytes are retained at their original length. Partial
DDR3 images report missing optional data. The loader accepts binary data or
strict `HH`/`0xHH` hex tokens, commas/whitespace, optional hex offset prefixes
(`0010:`), and `#`/`;` comments. It rejects oversized images and unsupported
memory types instead of silently truncating or guessing SDR.

A valid checksum confirms data integrity, not electrical compatibility or
that an edited module will boot. Invalid encodings and inconsistent capacity
are reported in decoded warnings; the raw bytes remain available for analysis.

## Other tools

- `sort_spd.py`: scans dumps, catalogs to SQLite/HTML and organizes samples;
  DDR2 manufacturing and integrity now use the core decoder, and DDR3 CRC
  respects byte 0's coverage bit.
- `spd_smbus.py`: Linux hardware access. `--fix-crc` repairs DDR2/legacy
  checksums or DDR3 CRCs according to memory type; hardware writes remain a
  separate command.
- `utils/spd_csv_to_bin.py`: CSV conversion, with generation-aware
  `--fix-crc` integrity repair. CSV range endpoints are **exclusive** (unlike
  CLI patch endpoints).
- `hp_smartmemory_ident.py`: HP serial/HPT registry utilities.

## Tests

```sh
python -m unittest discover -v
```

Tests cover synthetic DDR2/DDR3 vectors, both CRC coverages, signed fine
offsets, ECC capacity, XMP profile flags, malformed/truncated inputs, CLI
operations, catalog/SMBus integrity functions, editor undo/redo, atomic save
failure, and every binary sample in the repository. Real Tk integration tests
run when `DISPLAY` is available (or on Windows), otherwise they are skipped.
No DIMM hardware is needed. See [REVIEW.md](REVIEW.md) for review findings and
remaining validation limits.

## References

- [JEDEC 21-C](https://www.jedec.org/standards-documents/focus/memory-module-designs-dimms)
- [i2c-tools decode-dimms](https://kernel.googlesource.com/pub/scm/utils/i2c-tools/i2c-tools/+/refs/heads/master/eeprom/decode-dimms)
  (independent cross-check of byte meanings and timing encodings; no source
  code copied into this MIT-licensed project).
- [Intel DDR3 XMP overview](https://www.intel.cn/content/dam/doc/white-paper/extreme-memory-profile-ddr3-technology-paper.pdf)

## License

Source files retain their MIT SPDX notices from the project.
