# Development

## Source layout

| Module | Responsibility |
| --- | --- |
| `spd_library.py` | Image loading, memory-type dispatch and byte differences |
| `legacy_decoder.py` | Shared SDR/DDR organization, timings and manufacturing |
| `sdr_decoder.py`, `ddr_decoder.py` | Legacy generation entry points |
| `ddr2_decoder.py` | DDR2 layout and timing encodings |
| `ddr3_decoder.py`, `ddr3_xmp_decoder.py` | DDR3 base/module data and XMP |
| `spd_fields.py` | Named field masks, encodings, units and layout selection |
| `spd_integrity.py` | Checksums, CRCs and bounded donor patches |
| `spd_editor.py` | Editor document model and Tk interface |
| `spd_overview.py` | Structured module overview presentation model |
| `spd_tool.py` | Offline CLI |
| `spd_smbus.py` | Linux hardware access |
| `sort_spd.py` | Image scanning and SQLite/HTML cataloging |
| `hp_smartmemory_ident.py` | HP family registry and modular relationships |
| `tests/` | Decoder, CLI, editor-model and Tk tests |

Keep format logic in decoders and field definitions. The CLI and GUI should
use the same encoding and integrity routines. Linux hardware imports belong
in the hardware command path so offline tools remain usable on other systems.

## Running tests

```sh
python -m unittest discover -v
python -m unittest tests.test_registered -v
```

Hardware tests mock Linux ioctl/sysfs boundaries and never touch physical buses.
Tk integration tests require a graphical display and Tk. They are skipped on
headless Linux environments. Tests do not program physical EEPROMs.

The suite includes supplied images, synthetic edge cases and published
registered-SDR configurations with independently specified checksums. Preserve
coverage for partial images, malformed encodings, both DDR3 CRC coverages,
neighboring-bit preservation and failed atomic saves.

## Adding or changing a format

Document the source layout and applicable revisions. Keep unknown fields raw
until their encoding is established. Gate module-specific semantics by memory
type, module family and component type; pre-production layouts may differ.

For a named field, define its mask, valid encodings, units and description in
`spd_fields.py`. Add an independent packed-byte expectation and verify that
editing the field preserves all unrelated bits. Test save/reopen behavior
when the field falls inside an integrity-covered region. Use exact rational
arithmetic for timebase-dependent encoding.

For a decoder, implement `decode`, `pretty_print`, `dump_field_map` and the
shared patch interface, then register its memory type in `spd_library.py`.
Keep decoded output JSON-serializable and retain raw bytes for unsupported
extensions. Update the support matrix and format documentation with the
implemented scope.

## Reporting format issues

Include the command, Python version, memory type, module family, SPD revision
and affected offsets. A minimal image or byte range should include enough
context to reproduce the encoding. Redact module serial numbers and other
identifiers if required. For register/buffer issues, include the component
manufacturer/revision and the relevant specification or datasheet section.

Hardware reports should distinguish image decoding, EEPROM transport and boot
or memory-training behavior. A successful file edit or checksum check alone
does not verify the latter two.
