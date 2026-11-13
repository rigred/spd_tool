# Thaiphoon THP import and lossless conversion

Supported THP files can be imported individually or in
bulk through **SPD library → Add SPD files / Import folder**, or converted from
the CLI. Imports decode the container into a normal `.bin` image under the
collection's existing manufacturer/model hierarchy. They do not modify the
source file or repair its SPD checksum/CRC.

SDR through DDR3 images can open in the editor. DDR4, DDR5 and unsupported or
damaged memory-type declarations open in the library's read-only inspector.
Those archive entries support exact binary and open-bundle export; they do not
enable timing editing or EEPROM programming for newer generations.

## Commands

```sh
# Convert a single TH20 dump into exact raw SPD bytes.
python spd_tool.py convert --source module.thp --out module.bin

# Convert multiple inputs to hash-addressed binary files in one directory.
python spd_tool.py convert --source first.thp --source second.thp --out-dir converted

# Import and convert directly into the managed SQLite collection.
python spd_tool.py library-import --collection ./collection \
  --source first.thp --source second.thp

# Recursively import a public dump collection, including extensionless THP files.
python spd_tool.py library-import --collection ./collection \
  --source ./Unsorted-SPD-Dumps/Dumps

# Import an ordinary ZIP, open SPD bundle or optional 7z collection.
python spd_tool.py library-import --collection ./collection --source SPDs.7z

# Create a portable open bundle, retaining original THP source files.
python spd_tool.py convert --source first.thp --source second.thp --out modules.spdz
```

For `.7z` support, install `python -m pip install -r requirements-archives.txt`.
THP, raw/text dumps and ZIP/open bundles use the Python standard library only.
Without the optional dependency, unpack 7z with a normal archive utility and
import the extracted folder. Archives are read into bounded memory buffers;
member paths are not extracted directly into the collection filesystem.

Bulk import separates conversion failures from invalid or unknown SPD integrity.
The GUI displays grouped results and a bounded preview; **Export → Last import
report** saves the complete JSON report. Import reports each rejected member while retaining successfully decoded
images. Identical raw images are deduplicated by SHA-256, including images
arriving through different wrappers or filenames. Ordinary `.zip` archives
may contain `.thp`, `.bin`, `.spd`, hex-text and the supported RW text dumps.
Nested archives, encrypted archives and unknown THP revisions are rejected.

## Supported container revisions

Each observed layout consists of a five-byte header (`04` followed by four
ASCII identifier bytes), the transformed payload and a one-byte opaque trailer.
The trailer is `13` in this public collection; its checksum meaning has not been
established. Exact lengths are required. Payload length comes from the header,
not from a filename or guessed RAM generation.

| Identifier | File bytes | Payload bytes | Transform |
| --- | ---: | ---: | --- |
| TH20 | 262 | 256 | XOR with `i & 255` |
| TH40 | 518 | 512 | XOR with `i & 255` |
| TH41 | 518 | 512 | Repeating ASCII mask 41; byte zero unchanged |
| TH42 | 518 | 512 | Repeating ASCII mask 42; byte zero unchanged |
| TH43 | 518 | 512 | 16-bit ciphertext-feedback transform |
| TH50 | 1030 | 1024 | Same mask as TH41; byte zero unchanged |
| TH53 | 1030 | 1024 | Same feedback transform as TH43 |

These are reversible obfuscation schemes, not cryptographic protection or
authentication. THP version names do not establish whether an SPD payload is
valid. Other revisions, including similarly named identifiers, are not assumed
to use one of these transforms.

For TH41/TH50 and TH42, the mask is the following **ASCII text**, not its hex
decoding:

```python
MASK41 = b'0A30CD6F8C7890C5DAB95F68F18A6AF7420CD3D630A4C439AB98FAD1C83C6F7A568AB26CD39D1AF1D2'
MASK42 = b'5531A7648C7390C1D8A91F34F5656A77440F93F610A57F38A442FBD8C03C328B7D8E715C317A3A'
# MASK41 has 82 bytes; MASK42 has 78.
spd[0] = payload[0]
for i in range(1, len(payload)):
    spd[i] = payload[i] ^ mask[i % len(mask)]
```

For TH43/TH53, feedback uses the original encrypted byte. Updating the state
with the decoded byte produces incorrect output:

```python
state = 471
spd = bytearray()
for encrypted in payload:
    spd.append(encrypted ^ (state >> 8))
    state = (state + encrypted + 12719) & 0xFFFF
```

The importer never changes the payload based on a failed SPD checksum. In
particular, TH50 examples in the tested collection have invalid DDR5 CRCs;
conversion retains those results instead of manufacturing a valid checksum.

## Public collection validation

Regression testing uses
[passnet-spd/Unsorted-SPD-Dumps](https://github.com/passnet-spd/Unsorted-SPD-Dumps)
at commit `a5391203743ec9a263fe922d8a9fd55ad7891c68`. All 3,741 dump files decode
and import: 597 TH20, 525 TH40, 1,826 TH41, 11 TH42, 659 TH43, 8 TH50 and
115 TH53. This includes 38 files without the usual `.thp` extension. Decoded
images deduplicate to 3,585 entries.

Of those 3,741 source images, 543 use supported editor generations and 3,198
are read-only entries. Integrity inspection flags 412 mismatches and 55 unknown
results. Unknown memory types are retained under their actual type byte, even
if a filename suggests DDR3. Import success means that the container was
decoded and its exact bytes stored; it does not qualify the SPD for hardware.

DDR4 checks cover bytes 0–125 and 128–253, against the CRCs at 126–127 and
254–255. DDR5 checks cover bytes 0–509 against the CRC at 510–511. These checks
do not validate vendor or XMP regions outside that coverage. Manufacturer,
part number, date and serial use each generation's manufacturing block;
unavailable capacity/speed/rank fields remain unknown.

The repository is not redistributed with SPD Tool. To run its optional regression
test, obtain the pinned commit and set `SPD_TEST_CORPUS` to its `Dumps` directory:

```sh
SPD_TEST_CORPUS=/path/to/Unsorted-SPD-Dumps/Dumps \
  python -m unittest tests.test_modern_thp -v
```

## Observed TH20 structure

The implemented THP layout was established from the three supplied DDR3
samples and verified against their decoded part numbers, exact bytes and base
CRC results. It is an interoperability description of that layout, not an
assertion that every Thaiphoon Burner release uses the same format.

| File offset | Length | Observed content |
| --- | --- | --- |
| 0 | 1 | `04` prefix byte |
| 1–4 | 4 | ASCII `TH20` identifier |
| 5–260 | 256 | SPD bytes XOR-transformed with their zero-based byte offsets |
| 261 | 1 | Opaque trailer; `13` in all three supplied samples |

For each SPD byte offset `i`, from 0 through 255:

```python
spd[i] = thp[5 + i] ^ i
```

The same XOR operation encodes the payload again. This is a reversible
obfuscation, not a cryptographic confidentiality mechanism. Removing the
header alone is insufficient: the payload must also be transformed.

The prefix and trailer bytes are retained in import observations and the
complete original `.thp` is stored separately. The trailer's meaning and any
independent TH20 container checksum have **not** been established. It is not
claimed to authenticate the payload or substitute for SPD integrity checks.
The importer accepts an opaque trailer byte rather than treating `13` as a
proven checksum. Unknown identifiers and unexpected lengths fail explicitly;
they are not decoded using guessed offsets or silently truncated.

An independent minimal conversion for this particular layout is:

```python
from pathlib import Path

source = Path("module.thp").read_bytes()
if len(source) != 262 or source[:5] != b"\x04TH20":
    raise ValueError("Unsupported THP layout")
raw_spd = bytes(value ^ offset for offset, value in enumerate(source[5:261]))
with open("module.bin", "xb") as output:
    output.write(raw_spd)
```

No Thaiphoon executable, Windows installation, registration or proprietary
runtime is required for this conversion.

## Findings from the supplied examples

| Sample | Decoded bytes | Base integrity | Additional finding |
| --- | --- | --- | --- |
| GeIL CL9-9-9 DDR3-1333 | 256 | Valid CRC | Decoded PN matches the file label |
| TIGO DDR3-NB-8G-1600 | 256 | Valid CRC | Decoded PN matches the file label |
| Avexir DDR3-2400 CL10 8GB | 256 | Invalid CRC | Native MTB divisor at SPD byte 11 is zero |

These results describe the exact decoded files, not verified hardware. The
Avexir conversion preserves the bad CRC and zero divisor; neither is guessed
or corrected during import. Repair is a separate explicit editing operation.

The supplied `SPDs.7z` also contains raw `.spd` files and an RW text dump. Its
`2133 c9 psc.spd` entry has memory-type byte `00`; the collection keeps it as
a read-only unknown-type image instead of labelling it DDR3 based on its filename. Duplicate
images under different names remain a single collection image. Generic binary
conversion can still preserve an unsupported raw image for inspection.

## Collection storage and original sources

Converted images use the ordinary path layout:

```text
modules/<generation>/<manufacturer>/<part-number>/<serial>--<sha256>.bin
```

Original nonbinary sources are retained separately as
`originals/<source-sha256>.thp`, `.rw` or `.txt`. The SQLite import records link
the normalized image to its source hash, source name, transformation, archive
member information and retained original. Multiple source observations can
refer to the same deduplicated image. Sources outside the collection remain
untouched.

Opening a THP/RW/container in the GUI disables automatic integrity repair on
save initially, so **Save As** can preserve the exact decoded bytes. The
repair checkbox can be enabled deliberately. Saving redirects to a binary
filename; the editor refuses to overwrite `.thp`, `.rw`, `.zip`, `.7z` or
`.spdz` files with a disguised raw image. **Export open bundle** preserves
current image bytes exactly and is separate from checksum repair.

Use the [Open SPD Bundle specification](OPEN_SPD_BUNDLE.md) for portable
archives with independently verifiable raw payloads, original-source retention
and editable UTF-8 metadata. THP export is intentionally unnecessary: the raw
binary and open bundle formats carry the same SPD data without obfuscation.
