# Open SPD Bundle, version 1

**Status:** project-defined open interchange specification. This is not a
JEDEC container format or an industry certification standard. The specification,
schema and implementation are available under the repository's MIT license.
Implementations do not require this application's SQLite database or software.

The container is an ordinary unencrypted ZIP archive. `.spdz` is a convenient
extension; renaming it to `.zip` does not change its contents. Use the existing
`application/zip` media type. Plain `.bin` files remain first-class inputs and
outputs; the container is optional metadata and integrity packaging.

## Required layout

| Member | Content |
| --- | --- |
| `manifest.json` | UTF-8 JSON metadata and the authoritative payload list |
| `manifest.sha256` | ASCII SHA-256 of the exact manifest bytes, in the form `<64 lowercase hex digits>  manifest.json\n` |
| `images/<sha256>.bin` | Exact raw SPD bytes, one member per distinct content hash |
| `sources/...` | Optional original THP/text files, each explicitly listed and hashed |

Writers should use ZIP STORE or DEFLATE for broad interoperability. Encryption,
links and special files are not permitted. Member names are relative POSIX
paths without `..`, `.`, empty components, drive prefixes, backslashes, NULs or
control characters. Every nondirectory member must be listed by the manifest,
except the manifest and its checksum. Duplicate member names are invalid.
Readers must not silently trust an unlisted payload.

### Manifest example

The hashes and image details below are illustrative placeholders. A real writer
calculates them from the exact files:

```json
{
  "format": "open-spd-bundle",
  "version": 1,
  "images": [
    {
      "file": "images/<64-lowercase-hex-sha256>.bin",
      "length": 256,
      "sha256": "<64-lowercase-hex-sha256>",
      "memory_type": 11,
      "metadata": {
        "manufacturer": "Decoded manufacturer declaration",
        "part_number": "ACTUAL-MODULE-PN",
        "serial": "00000000",
        "spd_integrity": {"status": "VALID"},
        "oem": {"oem_name": "HP", "part_number": "123456-001"}
      },
      "sources": [
        {
          "format": "thaiphoon-th20",
          "name": "original.thp",
          "file": "sources/<source-sha256>.thp",
          "length": 262,
          "sha256": "<source-sha256>",
          "decoded_length": 256,
          "decoded_sha256": "<decoded-image-sha256>",
          "details": {
            "header_hex": "0454483230",
            "trailer_hex": "13"
          }
        }
      ]
    }
  ]
}
```

The machine-readable [manifest schema](../schemas/open-spd-bundle-v1.schema.json)
defines required field types. ZIP membership, computed hashes, declared lengths,
image-path equality, memory-type equality and size limits also require semantic
validation; JSON Schema alone cannot verify file bytes.

## Field rules

- `format` is exactly `open-spd-bundle`; `version` is integer `1`. Unknown
  versions must be rejected rather than interpreted as version 1.
- `images` is nonempty. Each image has `file`, `length`, `sha256` and
  `memory_type`. SHA-256 values use exactly 64 lowercase hexadecimal characters.
- Image paths are exactly `images/<that-image-sha256>.bin`; images with the same
  hash are represented once. Different source names belong in `sources`.
- `length` is the exact uncompressed byte length. A raw image contains 3–65536
  bytes, allowing partial/future-generation archival without promising that a
  particular editor supports it. Normal supported editor images remain 128–256
  bytes. `memory_type` is integer 0–255 and equals raw byte 2.
- Optional `metadata` is a JSON object. Manufacturer identity is a decoded
  declaration; OEM sticker details and test records are observations, not proof
  of provenance or authentication. Unknown metadata may be retained without
  assigning it a hardware meaning. Collection reexports preserve unknown
  imported metadata in a deduplicated `imported_metadata` observation list.
- Optional `metadata.provenance`, when present, is an object with boolean
  `generated` and `result_sha256` matching the actual image. Generated records
  must retain that status across collection import, export and reimport so they
  do not become independent HPT mining evidence.
- Each optional source observation contains textual `format` and `name`, source
  `length` and `sha256`. `name` is a display name, not an extraction path. A
  source `file` is optional; if supplied, it is under `sources/` and must exist,
  have the declared length and match its hash. Original sources can precede
  editing; their decoded hash need not equal a subsequently modified image.
- `decoded_sha256`, `decoded_length` and `details` describe a conversion when
  known. They are optional observations; the hash of a retained original source
  is verified independently. Readers must not infer undocumented conversions.
- Unknown nonstructural metadata does not change the interpretation of raw
  bytes. Changes to required structural semantics need a new format version.
- JSON duplicate keys, NaN and Infinity are invalid. JSON values use UTF-8
  without a byte-order mark. Hash the exact manifest bytes, not a reserialized
  or newline-normalized representation.

## Verification and integrity levels

A conforming reader checks ZIP member names and limits, verifies
`manifest.sha256`, parses the manifest, verifies each listed payload's length
and SHA-256, and checks the cross-field rules above before importing images.
Missing, duplicate, corrupted or unlisted payloads reject the bundle as a unit.
A valid bundle may still contain an invalid SPD image: transport integrity and
SPD checksum/CRC validity are different properties.

The image's original checksum/CRC is never repaired implicitly. In particular,
DDR3's base CRC generally does not protect XMP or the entire manufacturer/customer
area; the bundle SHA-256 covers every image byte. ZIP also has its own CRC32
checks, which are not a substitute for manifest-level hash verification.

The bundled manifest checksum catches accidental manifest damage. It does
**not** authenticate the manifest: someone who changes an archive can replace
both its files and its checksums. Authenticity requires a separately trusted
hash or detached signature distributed through an independent trust mechanism.
Version 1 does not pretend to provide signatures, OEM certification or proof
that a dump was read from physical hardware.

An independent payload verification requires only Python's standard library:

```python
import hashlib, json, zipfile

with zipfile.ZipFile("modules.spdz") as archive:
    raw = archive.read("manifest.json")
    expected = archive.read("manifest.sha256").split()[0].decode("ascii")
    assert hashlib.sha256(raw).hexdigest() == expected
    manifest = json.loads(raw)
    for image in manifest["images"]:
        data = archive.read(image["file"])
        assert len(data) == image["length"]
        assert hashlib.sha256(data).hexdigest() == image["sha256"]
        for source in image.get("sources", []):
            if "file" in source:
                original = archive.read(source["file"])
                assert len(original) == source["length"]
                assert hashlib.sha256(original).hexdigest() == source["sha256"]
```

This example illustrates independent hash checking. Production readers also
need the structural, path, size and provenance checks described above.

## Resource limits in this implementation

- At most 4096 ZIP members, including the manifest and checksum.
- At most 1 MiB per member and per manifest; image payloads at most 65536 bytes.
- At most 64 MiB total uncompressed data and 64 MiB compressed input.
- No nested archives, encrypted members, filesystem extraction, links or special
  files. Decompression occurs into bounded memory buffers.

These limits are part of this implementation's accepted v1 profile. A reader
may impose stricter documented limits and report a clear rejection. Output
files are published atomically and never overwrite existing files implicitly.

## Application workflows

**Byte editor → Export open bundle** exports the current image without repair.
**SPD library → Export open bundle** exports selected images, OEM details,
generated provenance and retained original sources. Use **Add SPD files** or
**Import folder** to bring bundles into a collection. Multi-image bundles open
through the library, where a particular image can then be selected for editing.
Single-image bundles may be opened directly in the editor.

The CLI `convert` command writes bundles using an `.spdz` or `.zip` output
extension, or `--format spdz`. `--out-dir` supports bulk binary conversion with
hash-addressed filenames. THP and RW sources are retained when producing a
bundle. Converted binaries are exact payloads, not newly repaired dumps.

The existing public-submission ZIP/manifest is a separate workflow/schema and
is not automatically interpreted as this format. A future public service can
adopt this documented interchange format without requiring proprietary files.

Read [THP import](THP_IMPORT.md) for the observed TH20 layout and its limits.
