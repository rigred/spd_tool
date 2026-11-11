# Registered modules and HP SmartMemory

Named fields are available in the **Registers / buffers** tab and through
`spd_tool.py fields` / `edit`. The schema selects fields by memory generation,
module family and register type. Field locations, units and legal encodings
are included in `fields` JSON output.

```sh
python spd_tool.py fields --spd module.bin --expert
```

The GUI shows encoded values beside their meanings. Enable **Show raw
control/personality words** for complete control-word nibbles and runtime
register interpretations. Raw byte editing remains available for reserved
encodings and unrecognized component layouts.

## DDR3 RDIMM

Supported families are RDIMM, Mini-RDIMM and 72-bit SO-RDIMM. Named fields
cover module organization/mechanics, DRAM rows, register count, heat spreader,
register type/revision and parity-aware JEP106 register identification.

For SSTE32882, SPD bytes 69-76 contain two control-word nibbles per byte:
the even-numbered word in bits 3:0 and the odd-numbered word in bits 7:4.
`RC0` through `RC15` edit those nibbles individually.

| Settings | Field keys |
| --- | --- |
| CA A/B drive | `ca_a`, `ca_b` |
| Control A/B drive | `control_a`, `control_b` |
| Clock-pair drive | `clock_13`, `clock_02` |
| Output inversion/floating | `rc0_inversion`, `rc0_float` |
| Output disables | `rc0_disable_a`, `rc0_disable_b` |
| Individual clock disables | `rc1_disable_y0` through `rc1_disable_y3` |
| Prelaunch and output timing | `rc2_prelaunch`, `rc2_3t` |
| Input termination | `rc2_ibt`, `rc8_ibt`, `rc8_mirror_ibt` |
| Weak drive and power-down | `rc9_weak`, `rc9_pd_enable`, `rc9_pd_ibt_off` |
| Operating conditions | `rc10_speed`, `rc11_voltage`, `rc11_internal_vref` |

The `rc*` subfields use JESD82-29A.01 runtime semantics. Most corresponding
SPD locations are reserved by Annex K; firmware commonly supplies these
values itself. Their presence in an image does not imply that the memory
controller will load them. RC10 specifies the operating-speed code supplied
to the register, independently of its maximum rated speed. Optional functions
require component/revision support.

Unknown register types expose raw nibbles without SSTE32882 interpretations.
The editor changes EEPROM image contents, not live register state.

```sh
python spd_tool.py edit --spd rdimm.bin --out modified.bin \
  --set ca_a=1 --set ca_b=2
```

Choice codes are layout-specific; inspect `fields --expert` before applying
settings from a different module or register revision.

## DDR3 LRDIMM

Named fields follow the production Annex K.4 layout.

| SPD bytes | Contents |
| --- | --- |
| 60-66 | Mechanics, attributes, buffer revision and manufacturer |
| 67-71 | Global drive strengths, prelaunch and delay controls |
| 72-77 | DDR3-800/1066 termination and per-rank ODT |
| 78-83 | DDR3-1333/1600 termination and per-rank ODT |
| 84-89 | DDR3-1866/2133 termination and per-rank ODT |
| 90-95 | Minimum/maximum module delay at 1.5, 1.35 and 1.25 V |
| 96-101 | Reserved |
| 102-116 | Buffer personality words |

Global controls include rank mirroring/numbering, buffer orientation, rank
swapping, CA prelaunch, extended delay and additive delay. Extended/additive
delay values are expressed as fractions of tCK.

### Speed-dependent termination

Each operating band has independent MDQ drive/termination, read/write ODT0/ODT1
assertions for ranks 0-7, DRAM drive, RTT_NOM and RTT_WR. Field keys begin with
`800_1066.`, `1333_1600.` or `1866_2133.`. RTT_NOM applies to ranks 0/1 in this
layout; RTT_WR applies to all ranks.

```sh
python spd_tool.py edit --spd lrdimm.bin --out modified.bin \
  --set 1333_1600.mdq_odt=3 \
  --set 1333_1600.rank2.write.odt1=1 \
  --set 1333_1600.rtt_nom=3
```

Select values for the module's topology, DRAM loading and buffer revision.
These commands illustrate field syntax rather than a tuning profile.

### Module delays

Module delay fields use the current SPD MTB. With an MTB of 1/8 ns,
`delay_1.35_min=5.125` encodes 41. Exact fractions are accepted, and values
between representable steps are rejected.

```sh
python spd_tool.py edit --spd lrdimm.bin --out modified.bin \
  --set delay_1.35_min=5.125 --set delay_1.35_max=7
```

### Personality words

All 30 nibbles are named by their JEDEC destination, including the
cross-function mapping at byte 105:

| Byte | Bits 3:0 | Bits 7:4 |
| --- | --- | --- |
| 105 | `F14RC6` | `F15RC6` |

```sh
python spd_tool.py edit --spd lrdimm.bin --out modified.bin --set F15RC6=0xA
```

Personality value meanings are vendor-defined. Consult the buffer documentation
for the applicable device and revision. Pre-production LRDIMM layouts are
flagged and retain raw personality access.

## Copying module settings

```sh
python spd_tool.py edit --spd target.bin --out modified.bin \
  --copy-module-settings donor.bin
```

For DDR3 registered modules, this copies bytes 60-116, including component
identity and personality settings, while retaining module manufacturing
identity, serial, part number and customer data. Memory generation and module
type must match. SDR/DDR copies use attribute bytes 21-22.

## HP SmartMemory

The **HP SmartMemory** tab displays the serial, HPT code and matching learned
families. Direct HPT edits write the marker and code as one undoable operation.
Family-based computation displays candidate values for explicit selection.
Changing the selected family clears previously computed candidates.

| Field | Offset | Integer interpretation |
| --- | --- | --- |
| Module serial | 122-125 | Big endian |
| HPT marker | 176-179 | `48 50 54 00` (`HPT\0`) |
| HPT code | 180-183 | Big endian |

This byte order matches `hp_families.json` and the standalone HP utility.
Matching checks the family's modular relationship directly. Candidate
computation is limited to 1024 results in the editor. A family match indicates
a learned serial/HPT relationship, not cryptographic authenticity.

Serial and part-number edits do not rewrite HPT automatically. Recompute the
code explicitly when required. CLI registry operations are documented in the
[command reference](docs/CLI.md#hp-family-registry).

## SDR and DDR registered modules

Legacy byte 21 describes the module's input buffering, registration and clock
configuration. Named edits include:

| Attribute | Field key |
| --- | --- |
| Address/control buffer | `buffered_address` |
| Address/control register | `registered_address` |
| On-module PLL | `pll` |
| DQMB buffer/register | `buffered_dqmb`, `registered_dqmb` |
| Differential clock | `differential_clock` |
| Redundant addressing | `redundant_address` |

```sh
python spd_tool.py edit --spd sdr.bin --out modified.bin \
  --set registered_address=1 --set pll=1
```

Buffered and registered flags may both be set. These SPDs describe the
physical attributes without a DDR3-style register ID or control-word array.
DRAM CAS and registered command pipeline latency are reported separately.
Geometry, CAS support, refresh, voltage and basic timings have named fields;
other bytes remain accessible in the raw editor.

## References

- JEDEC Standard 21-C, Annex K, Release 21A: DDR3 SPD, registered and
  load-reduced module appendices (production layout).
  [Document mirror](https://docs.ampnuts.ru/eevblog.docs/Standards/DDR4/JEDEC_DDR3_SPD_Specification_Rev1.1_R21A.pdf)
- JEDEC JESD82-29A.01: SSTE32882 register control-word semantics.
  [TI-hosted document](https://e2e.ti.com/cfs-file/__key/communityserver-discussions-components-files/48/JESD82_2D00_29A.01.pdf)
- Texas Instruments SCAA093B: register-related DDR3 RDIMM SPD settings.
  [Application report](https://www.ti.com/lit/an/scaa093b/scaa093b.pdf)
- Infineon HYS72Vxx3xxGR PC133 registered SDRAM module datasheet,
  June 2001, SPD tables pages 13-14.
  [Manufacturer document hosted by Mouser](https://www.mouser.com/catalog/specsheets/HYS72Vxx.pdf)
- [i2c-tools decode-dimms](https://kernel.googlesource.com/pub/scm/utils/i2c-tools/i2c-tools/+/refs/heads/master/eeprom/decode-dimms)
  and [Freescale DDR1 SPD interpretation](https://android.googlesource.com/platform/external/u-boot/+/refs/heads/android-tv-s-beta3/drivers/ddr/fsl/ddr1_dimm_params.c)
  cross-check legacy timing and rank-density encodings.
