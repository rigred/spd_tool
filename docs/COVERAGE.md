# Engineering coverage

This matrix records implemented software scope. It is not a claim that every
optional SPD revision, proprietary extension or physical DIMM has been qualified.

| Capability | SDR | DDR | DDR2 | DDR3 |
| --- | --- | --- | --- | --- |
| Base decoding and manufacturer/identity data | Implemented | Implemented | Implemented | Implemented |
| Structured organization, capabilities, refresh/electrical declarations | Implemented | Implemented | Implemented | Implemented, module-family dependent |
| Registered/buffered attributes | Legacy physical wiring flags | Legacy physical wiring flags | Module type/attribute declarations | RDIMM register and LRDIMM buffer layouts |
| Native primary timing encoding and CAS | Legacy units/bitmap | Legacy fractional CAS/units | Fractional cycles, quarter-ns and extended tRC/tRFC | MTB/FTB, signed fine offsets, packed fields |
| OEM metadata, catalog annotations and comparison | Implemented | Implemented | Implemented | Implemented |
| Compatibility and multi-donor merge | Implemented | Implemented | Implemented | Implemented |
| Native timing proposals and evidence | Implemented | Implemented | Implemented | Implemented |
| EPP extension | Not defined by implemented format | Not defined by implemented format | Full/abbreviated DDR2 UDIMM format | Not defined by implemented format |
| XMP authoring | Not defined by implemented format | Not defined by implemented format | No DDR2 XMP format implemented | XMP 1.1/1.2/1.3 |
| HPT computation | Not defined by implemented format | Not defined by implemented format | Not defined by implemented format | Existing empirical HP family engine |
| Command timelines and comparisons | Known constraints + explicit missing inputs | Known constraints + explicit missing inputs | Known constraints, supplied tFAW if applicable | Known constraints, supplied operating CWL |
| Base integrity | SUM8 | SUM8 | SUM8 | Declared-coverage CRC16 |
| Automated encoding/merge/timeline tests | Yes | Yes | Yes | Yes |
| New physical programming/boot qualification | Not performed | Not performed | Not performed | Not performed |

## Boundaries

- Structured fields cover implemented standard organization, capabilities,
  manufacturing and timing declarations. Reserved bytes, unknown manufacturer
  formats and revision-specific electrical controls retain raw access. A named
  raw bitmap is an encoding aid, not a decoder for every bit's private meaning.
- Legacy access/cycle encodings and lower-CAS operating points are not DDR3
  timings. Native CAS edits invalidate stale legacy lower-CAS points rather
  than inventing new points. SDR does not gain DDR-specific timings.
- DDR2 EPP covers NVIDIA SP-02496-001 rev. 01, not EPP 2.0 or every vendor's
  customer-area format. EPP replacement can overwrite manufacturer data.
- Register control transfer requires physical equivalence review. Editing an
  SPD register declaration does not rewire or replace the component.
- Timing diagrams are minimum-constraint examples with explicit workload and
  burst assumptions, not exhaustive DRAM command/protocol compliance checks.
- PCB routing, exact chip speed grade and register IC identity often cannot
  be established from SPD alone. Manual chip/PCB/register annotations remain
  observations and do not silently change compatibility decisions.
- Proprietary OEM authenticity, private checksums, HP firmware acceptance and
  overclock stability remain outside software validation.

## Regression evidence

`tests/test_engineering.py` includes independent EPP packed-byte vectors,
generation-specific native encoders, neighboring-byte preservation, hard and
operation-scoped compatibility decisions, multi-donor conflict resolution,
recipe replay, immutable source refresh, timing dependencies, bank reuse and
settings validation. `tests/test_workbench_gui.py` exercises integrated previews,
undo/staleness, collection restoration/discovery, EPP forms and planner/timeline
navigation under a graphical display. Existing sample/CLI/hardware-simulation
regressions remain in the full suite.
