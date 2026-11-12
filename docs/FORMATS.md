# SPD image formats

## Input and output

The core loader accepts one SPD image containing 128-256 bytes. It retains the
exact length and dispatches by byte 2:

| Byte 2 | Decoder |
| --- | --- |
| `0x04` | SDR SDRAM |
| `0x07` | DDR SDRAM |
| `0x08` | DDR2 SDRAM |
| `0x0B` | DDR3 SDRAM |

Unsupported types and oversized images are rejected. Use the catalog scanner
to extract images from larger files. Partial DDR3 images retain their base
block; absent optional manufacturing/customer data is reported as unavailable.

Hex-text inputs support:

- Two-digit byte tokens, `HH` or `0xHH`.
- Whitespace and comma separators.
- Optional hexadecimal offset prefixes such as `0010:`.
- `#` and `;` comments.

Offsets must follow the number of bytes already parsed. Unrecognized text is
rejected. Plain hex streams without byte separators, ASCII side columns and
arbitrary hexdump headers are outside this syntax.

Image saves and patch output are binary. JSON exports contain decoded values,
raw fields and diagnostics; they are not accepted as replacement SPD images.

## Offset conventions

Offsets are zero-based. Unless a command explicitly says otherwise, displayed
byte ranges include both endpoints.

| Interface | Example | Bytes selected |
| --- | --- | --- |
| `patch --copy-range` | `0x10:0x20` | 16-32 inclusive |
| CSV converter range | `60 - 76` | 60-75; end exclusive |
| Named field location | Byte 70, bits `7:6` | Two bits within byte 70 |

Named field edits update a mask within one byte and preserve neighboring bits.
The raw editor accepts arbitrary bytes but keeps the image length and memory
generation fixed.

## Integrity fields

| Family | Stored field | Computation |
| --- | --- | --- |
| SDR / DDR / DDR2 | Byte 63 | Sum of bytes 0-62, modulo 256 |
| DDR3, byte 0 bit 7 set | Bytes 126-127, little endian | CRC-16/XMODEM over bytes 0-116 |
| DDR3, byte 0 bit 7 clear | Bytes 126-127, little endian | CRC-16/XMODEM over bytes 0-125 |

DDR3 uses polynomial `0x1021`, initial value zero, no reflection and no final
XOR. A CRC matching the alternate coverage is reported as a diagnostic; the
image remains invalid under its declared coverage. Repair uses the current
byte 0 value, including after a patch changes it.

Legacy byte 95 belongs to the serial number. The tool does not treat it as an
extension checksum. A valid checksum/CRC covers the applicable base region;
it does not authenticate vendor data or validate memory training parameters.

## Timings

Decoded timings use nanoseconds, with clock counts derived where applicable.
Named delay edits must fit the active timebase exactly.

- **SDR:** integer CAS bitmap, explicit CAS operating points, distinct
  lower-CAS timing encodings and signed setup/hold values.
- **DDR:** half-cycle CAS bitmap; quarter-ns tRP/tRRD/tRCD and tCKmax;
  generation-specific tAC, skew and refresh timings.
- **DDR2:** special tCK fraction codes, explicit lower-CAS points and extended
  fractional tRC/tRFC fields.
- **DDR3:** MTB/FTB conversion with signed fine corrections, secondary timings
  and CAS selection constrained by the advertised support bitmap.

Required timing counts round upward. Legacy downbins use advertised operating
points. Register pipeline latency is reported separately from DRAM CAS.

## Organization and manufacturing

Usable capacity excludes checking bits. Density and address geometry are
cross-checked, with inconsistent encodings reported in warnings. Legacy rank
geometry can describe asymmetric ranks. DDR's low rank-density bits encode
1/2 GiB ranks; SDR's corresponding high-density extension is selected when
address geometry corroborates it.

SDR, DDR and DDR2 manufacturer IDs use a JEP106 continuation sequence in bytes
64-71. DDR3 stores continuation count and manufacturer code in two-byte fields.
The vendor-name table is a subset of JEP106; unknown entries retain their codes.
Named register/buffer ID edits regenerate odd parity.

Serial edits take four bytes in SPD order. Legacy manufacturing dates retain
the two-digit year. DDR2/DDR3 date output uses the decoder's 2000-based year
convention. Invalid or missing BCD dates are reported as unknown.

## Extensions and layout boundaries

DDR3 RDIMM fields follow the SSTE32882 layout when that register type is
identified. Other register types expose raw nibbles. LRDIMM named settings
follow the production Annex K.4 layout; pre-production revisions retain raw
personality access. See [Registered modules](REGISTERED_MODULES.md).

XMP profiles require enabled flags, complete blocks and valid timebases.
Revision-specific XMP extensions, DDR2 EPP and undocumented vendor regions
remain raw. LRDIMM personality destinations are named, while the meanings of
the vendor-specific values remain device-dependent.

HP HPT matching uses the bundled learned-family registry. Serial/HPT integers
are interpreted big endian. Registry matches express an observed relationship,
not cryptographic authenticity.
