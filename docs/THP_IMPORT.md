# Thaiphoon THP import and lossless conversion

TH20 files can be opened directly in the editor, imported individually or in
bulk through **SPD library → Add SPD files / Import folder**, or converted from
the CLI. Imports decode the container into a normal `.bin` image under the
collection's existing manufacturer/model hierarchy. They do not modify the
source file or repair its SPD checksum/CRC.

## Commands

```sh
# Convert a single TH20 dump into exact raw SPD bytes.
python spd_tool.py convert --source module.thp --out module.bin

# Convert multiple inputs to hash-addressed binary files in one directory.
python spd_tool.py convert --source first.thp --source second.thp --out-dir converted

# Import and convert directly into the managed SQLite collection.
python spd_tool.py library-import --collection ./collection \
  --source first.thp --source second.thp

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

Bulk import reports each rejected member while retaining successfully decoded
images. Identical raw images are deduplicated by SHA-256, including images
arriving through different wrappers or filenames. Ordinary `.zip` archives
may contain `.thp`, `.bin`, `.spd`, hex-text and the supported RW text dumps.
Nested archives, encrypted archives and unknown THP revisions are rejected.

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
`2133 c9 psc.spd` entry has memory-type byte `00`; the collection reports it as
unsupported instead of labelling it DDR3 based on its filename. Duplicate
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
