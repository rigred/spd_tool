# Command reference

Commands assume the repository root as the current directory. Input images
may be binary or hex text; output images are binary.

## Inspect and compare

```sh
python spd_tool.py dump --spd module.bin
python spd_tool.py dump --spd module.bin --programmer
python spd_tool.py dump --spd module.bin --json decoded.json
python spd_tool.py dump --spd module.bin --json -

python spd_tool.py diff --file-a original.bin --file-b modified.bin
python spd_tool.py diff --file-a original.bin --file-b modified.bin \
  --show-maps --limit 32
```

`--programmer` includes raw offsets and field maps. `--json -` writes JSON to
stdout. Diff reports length differences as well as changed bytes; absent tail
bytes are shown as `--`.

## Firmware SPD extraction

```sh
python spd_tool.py firmware scan --input BIOS.cap --out extracted-spd
python spd_tool.py firmware scan --input BIOS.cap.dump \
  --include-invalid --out candidate-spd
python spd_tool.py firmware scan --input BIOS.cap --json
```

Scan a binary firmware image or recursively scan already unpacked sections.
`--out` must name a new directory; omit it for a scan without files. Extraction
defaults to a 128-byte base block. `--length 256` or `--length 512` explicitly
includes adjacent context whose ownership is unverified. `--include-invalid`
includes plausible blocks with invalid, missing or vendor-defined integrity.
The JSON report retains every occurrence, source-file offsets and hashes.

Default limits are 128 MiB per file and 1024 MiB total; adjust with
`--max-file-mib` and `--max-total-mib`. Scan errors produce status 1 and are
recorded in the report. No matches returns status 0. See
[embedded SPD extraction](FIRMWARE.md) for compressed firmware, LPDDR signatures
and the distinction between a firmware candidate and the active RAM profile.

## Graphical editor

```sh
python spd_tool.py gui
python spd_tool.py gui --spd module.bin
python spd_editor.py module.bin
```

| View | Purpose |
| --- | --- |
| Overview | Structured identity, organization, operating points and integrity |
| Decoded JSON | Complete decoded fields and raw details |
| Byte editor | Individual bytes, hex ranges, part number and serial |
| SPD field editor | Named fields, legal encodings, locations and field notes |
| HP SmartMemory | Registry matching, HPT edits and candidate computation |
| Comparison | Byte differences between the current buffer and another image |
| Hardware / programmer | Linux or USB bridge discovery, reads and reviewed EEPROM programming |

Save and Save As write the current buffer through an atomic file replacement.
Checksum/CRC repair is enabled by default and can be disabled in the editor.
Save As is useful when retaining a text dump or an unmodified binary. Opening
another image or closing the application prompts for unsaved edits.
See the [GUI hardware workflow](GUI_HARDWARE.md) for target selection and
programming. The [USB serial bridge](EXTERNAL_BRIDGE.md) uses the same GUI
workflow with optional pySerial and compatible microcontroller firmware.

The Byte editor also opens the [XMP editor and timing planner](XMP_TIMING_PLANNER.md).

## Named edits

```sh
python spd_tool.py fields --spd rdimm.bin --expert
python spd_tool.py edit --spd rdimm.bin --out modified.bin \
  --set ca_a=1 --set ca_b=2
python spd_tool.py edit --spd lrdimm.bin --out modified.bin \
  --set delay_1.35_min=5.125 --set F15RC6=0xA
python spd_tool.py edit --spd vintage.bin --out modified.bin \
  --set registered_address=1 --set pll=1
```

`fields` emits JSON containing field keys, current values, bit locations,
units, descriptions and legal choice codes. `--expert` includes packed
control words and personality nibbles. Fields are selected by memory type,
module family and register layout.

Repeat `--set KEY=VALUE` to apply several edits. Choice fields take encoded
numeric values. Numeric fields use their documented units; exact fractions
such as `1/3` are accepted. A `0x` prefix specifies the raw encoded count.
Values outside the field or between representable steps are rejected.

Additional `edit` options:

| Option | Operation |
| --- | --- |
| `--part-number TEXT` | Set up to 18 printable ASCII characters |
| `--serial HEX` | Set four serial bytes in SPD byte order |
| `--hpt HEX` | Set the DDR3 HPT marker and four code bytes |
| `--copy-module-settings DONOR` | Copy compatible DDR3 bytes 60-116 or SDR/DDR attributes 21-22 |

`edit` repairs integrity and saves atomically. Module-settings copying retains
module manufacturing identity, serial, part number and the DDR3 customer
region. It requires a matching memory generation and module-type field.

## Donor patches

```sh
python spd_tool.py patch --source donor.bin --target module.bin \
  --out modified.bin --copy-mfgid --copy-partnum
python spd_tool.py patch --source donor.bin --target module.bin \
  --out modified.bin --copy-range 0x10:0x20
```

All patch ranges are inclusive. The patcher checks source and target bounds,
preserves the target length and repairs its integrity field. Memory generations
must match. `--force` allows a module-type mismatch and overrides the HP vendor
check for HPT operations; generation, length and range checks still apply.

| Option | SDR / DDR / DDR2 | DDR3 |
| --- | --- | --- |
| `--copy-mfgid` | Bytes 64-71 | Bytes 117-118 |
| `--copy-partnum` | Bytes 73-90 | Bytes 128-145 |
| `--copy-vendor` | Byte 99 through the shorter image's end | Bytes 176-255 |
| `--copy-hpt` | Unavailable | Bytes 176-183 |
| `--set-hpt HEX` | Unavailable | HPT marker and four code bytes |

The legacy `--copy-vendor` region includes manufacturer/customer data and may
include Intel SDR extension bytes 126-127. Select explicit ranges when only a
subset is required.

## HP family registry

```sh
python hp_smartmemory_ident.py identify \
  --serial 0x4132E061 --hpt 0xFCD7E032
python hp_smartmemory_ident.py hpt \
  --serial 0x4132E061 --part-number 712383-081
python hp_smartmemory_ident.py lookup M393B2G70EB0-CMA
```

The standalone utility defaults to `hp_families.json` in the working directory.
Set the global `--registry PATH` option before the subcommand to select another
registry. `learn` derives a family from two serial/HPT pairs and a known HP part
number; `add-equivalent` records a vendor part-number association. Both commands
write the registry. See their `--help` output for required arguments.

The editor uses the registry beside `spd_editor.py`. Its family matcher checks
the modular relationship directly. Candidate computation is explicit and capped
at 1024 results. See [HP SmartMemory](REGISTERED_MODULES.md#hp-smartmemory)
for byte order and interpretation.

## Cataloging

```sh
python sort_spd.py samples --recursive --out-root catalog \
  --db catalog.sqlite3 --html catalog/index.html --spd-tool ./spd_tool.py
```

The catalog scanner extracts SPD windows from files, organizes images by
identity and writes SQLite/HTML indexes. Its DDR4 recognition is independent
of core decoding support. `--move-single` moves an original source file when
exactly one SPD is found; the default extraction workflow retains source files.

## CSV conversion

```sh
python utils/spd_csv_to_bin.py module.csv --out module.bin \
  --length 256 --fix-crc
```

CSV indices are decimal. Ranges use an exclusive end: `60 - 76` writes bytes
60-75. Values must fit the specified byte/range exactly. `--fix-crc` repairs
the integrity field selected by the image's memory-type byte.

## Linux SMBus / I2C

```sh
python spd_smbus.py doctor
python spd_smbus.py list
python spd_smbus.py read --bus 1 --addr 0x50 \
  --out module.bin --report module-read.json
python spd_smbus.py scan --bus 1 --probe
```

Discovery is passive unless `--probe` is specified. Reads prefer a kernel
EEPROM interface and otherwise select SMBus byte-data or combined I2C according
to adapter capabilities. Two matching snapshots and valid image integrity are
required by default; `--allow-invalid` permits stable damaged images. Partial
reads are saved without padding. Programming requires `--enable-write`, an
explicit `--range`, an original-image `--backup`, and mandatory verification.

See [Hardware acquisition](HARDWARE.md) for transport options, HP Gen8 platform
constraints and programming requirements.


## Native Windows SMBus

Native Windows hardware commands use `windows-smbus`:

```powershell
python spd_tool.py windows-smbus adapters
python spd_tool.py windows-smbus --adapter i801 scan --probe
python spd_tool.py windows-smbus --adapter i801 read --addr 0x50 --out original.bin
```

See [Windows setup, preview/write commands and controller limits](WINDOWS.md).
The existing `smbus` subcommand remains the Linux transport.

## Container conversion and bulk collection import

```sh
python spd_tool.py convert --source module.thp --out module.bin
python spd_tool.py convert --source first.thp --source second.thp --out modules.spdz
python spd_tool.py convert --source collection.zip --out-dir converted
python spd_tool.py library-import --collection ./library --source SPDs.7z
python spd_tool.py library-import --collection ./library --source ./Unsorted-SPD-Dumps/Dumps
```

Conversion preserves exact payloads, including invalid SPD integrity. Use
`--format bin` or `--format spdz` to select an output explicitly. Bulk reports
include per-input errors; exit status 2 indicates partial failure.
`library-import --source` accepts directories and reports editable/read-only,
distinct-image and invalid/unknown integrity counts. A stored damaged or
unsupported-generation image is an archive entry, not a conversion failure.
The full JSON report lists each source and rejected input. Existing
output files are not overwritten. Read [THP import](THP_IMPORT.md) and the
[open bundle specification](OPEN_SPD_BUNDLE.md) for format and validation scope.
