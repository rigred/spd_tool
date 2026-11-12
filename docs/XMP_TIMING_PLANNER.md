# DDR3 XMP editor and timing-bin planner

Open **Performance profiles → XMP / evidence / timing-bin planner**.
The integrated editor has a DDR3 XMP authoring page and a separate
proposal planner for the supported SDR, DDR, DDR2 and DDR3 families. Neither
page changes a running memory controller or programs hardware.

## Edit or create XMP

Select profile 1 or 2 and **Load existing** to edit a populated profile, including
a disabled one. **Seed from JEDEC** builds an initial draft from the base SPD.
New headers use XMP 1.3; existing XMP 1.1/1.2/1.3 revisions are retained. Unknown
revisions are refused rather than rewritten as a known layout. Authoring
requires a complete 256-byte DDR3 image; it does not append an invented tail to
a partial dump.

Editable fields include enable state, DIMMs per channel, voltage, CAS bitmap,
profile medium timebase and the primary/secondary/refresh timings. Timing fields
are in nanoseconds. The CAS list uses integer CL values 4-18. Expert raw fields
expose command-rate encoding, turnaround/back-to-back adjustments, ASR,
controller voltage and vendor personality. Their interpretation can depend on
revision/platform; preserve them unless their encoding is known. Unrepresented
reserved fields and the other profile's block are retained on edit.

Use **Preview encoded profile** to inspect every byte difference and the actual
quantized values. **Apply reviewed profile to editor** is a single undoable
operation and requires an unchanged buffer/options. Save As writes the result;
program it only through the separate hardware backup/write/verify workflow.

### Storage and quantization

XMP occupies bytes 176-254, with byte 255 reserved. The authoring operation
preserves bytes 0-175, including all base JEDEC timings and manufacturer identity.
It preserves byte 255 when editing an existing XMP image. Creating a new header
initializes the customer region, including its previously blank reserved byte.
The base SPD CRC does not cover this extension; no fictitious XMP CRC is added.

HP HPT and other customer formats use the same region. Creation over populated
non-XMP data requires **Permit replacing non-XMP customer data**. This is a
format replacement; XMP and HPT cannot coexist at these offsets. Retain the
original dump before saving/programming a replacement.

XMP 1.3 uses the global fine timebase at byte 184 and signed corrections at
211-215 / 246-250. Older supported revisions retain their coarse encodings.
Minimum times are rounded upward when necessary, and field overflow is an
error. The maximum refresh interval tREFI is encoded in **thousands of MTB
units** and rounded downward. With a 0.125 ns MTB, 7800 ns becomes 62 units,
or 7750 ns; it is not encoded as 62400 units. The editor now also corrects
fine-offset and refresh-unit decoding for existing profiles.

The preview reports the encoded maximum data rate rather than implying the
requested clock is exactly representable. For example, an upward-rounded
1.072 ns period corresponds to about 1865.67 MT/s. Rounded speed labels are not
proof of the actual configured clock. Firmware may select or round clock bins
differently. Existing malformed profiles can expose a CAS bitmap that does not
satisfy their encoded tAA/tCK; correct the values before authoring them.

## Generate faster timing proposals

On **Timing-bin planner**, enter target data rates in MT/s. For DDR families,
clock MHz is half the transfer rate; for SDR the two are equal. The default
model preserves absolute timing minima from SPD and recomputes cycle counts
at the target period. It does not hold the original CL/tRCD/etc. constant while
silently reducing their absolute time requirements.

The voltage and maximum refresh interval are explicit operator inputs. Voltage
is never raised automatically. The initial 7800 ns refresh value is an operator
default, not a decoded temperature rating; enter the correct chip/temperature
limit. Refresh time is not scaled upward with clock speed.

Choose **Generate proposals**, inspect the warnings/violations, and select a
row. **Use selected proposal in XMP editor** copies its draft to the selected
slot for further refinement and encoded-byte review. Non-DDR3 families produce
planning results only. The planner does not add XMP to SDR/DDR/DDR2 or rewrite
their JEDEC timing tables.

The planner uses ceil(minimum time / period) and applicable minimum-cycle
constraints. It also keeps tRC at least tRAS+tRP after quantization. A DDR3 CWL
reference table supplies an initial selector within its covered period range;
outside that range an explicit CWL is needed. A manual CWL override applies to
all requested rows. The XMP CWL time threshold is chosen to preserve the desired
CWL cycle selector at the encoded period; the preview exposes the stored value.
Platform mode-register legality still requires independent verification.

A profile that exceeds field widths, supported CAS encodings, or supplied
operating limits is not silently clamped into a supposedly valid XMP profile.
Its proposal remains available with a diagnostic. Proposed CAS values outside
the module's base CAS bitmap are flagged. No model assumes that a DRAM chip,
module PCB, register/buffer or memory controller supports a faster clock merely
because minimum times can be expressed at that clock.

## Refine from tests or chip datasheets

Use **Evidence template** to export a module-hash-bound JSON skeleton, or
**Edit evidence JSON** to enter it inside the application. **Load evidence JSON**
imports an existing file. Inputs are limited to 1 MiB and 256 test points.
The full module SHA-256 must match the current image. After changing the image,
clear the external evidence or deliberately rebind a reviewed copy to that
image; the tool does not silently change its scope.

An illustrative input structure follows. Replace the hash, identifiers, source
references and example numbers with actual evidence for the loaded module:

```json
{
  "schema": "spd-tool-timing-evidence/1",
  "module_sha256": "COPY_THE_FULL_HASH_FROM_THE_GENERATED_TEMPLATE",
  "datasheet": {
    "reference": "Exact manufacturer document, revision, page and speed grade",
    "chip_part_number": "PHYSICALLY_VERIFIED_COMPONENT_PN",
    "conditions": "Voltage, temperature, density and organization conditions",
    "max_rate_MTps": 1866,
    "voltage_min_V": 1.425,
    "voltage_max_V": 1.575,
    "tCKmin_ns": 1.07,
    "timings": {
      "tAAmin": {"min_ns": 13.5},
      "tRRDmin": {"min_ns": 6, "min_cycles": 4},
      "tFAWmin": {"min_ns": 30, "min_cycles": 16},
      "tREFI": {"max_ns": 3900}
    }
  },
  "tested_points": [
    {
      "rate_MTps": 1866,
      "voltage_V": 1.5,
      "timings_cycles": {"tAAmin": 13, "tRCDmin": 13, "tRPmin": 13},
      "reference": "Actual test log, platform, configuration and duration",
      "temperature_C": 45,
      "passed": true,
      "notes": "Example structure only; replace with real observations"
    }
  ]
}
```

Datasheets are **manually transcribed constraints**, not automatically scraped
or inferred from the module part number. Verify the chip markings, revision,
density, organization and operating conditions independently. Canonical timing
names are used throughout: `tAAmin` in `timings_cycles` represents CL, while
`tCWLmin` represents CWL. Datasheet minima accept `min_ns` and/or `min_cycles`;
refresh accepts only `max_ns`. Clock-period limits use the top-level
`tCKmin_ns`. Source and chip PN are required for active datasheet constraints.

With the normal SPD anchor, datasheet minima act as additional floors. To use
faster chip-rated timings in place of supplied SPD minima, explicitly enable
**Use transcribed datasheet timings as anchor**. Only supplied fields are
replaced; unspecified timings retain their SPD anchor. Target-speed, voltage
and clock-period limits remain enforced.

Select a user-reported test from the anchor dropdown to hold its supplied
absolute timings while proposing other clocks. The test voltage must match;
there is no voltage/frequency scaling model. Missing test timings retain the
other anchor values and applicable datasheet floors. A failed test cannot be
an anchor. A reported failure at the requested speed/voltage blocks generation
of an XMP draft at that point. Contradictory reports require review rather than
being averaged into an optimistic result.

A refined output is still an **untested proposal**, including when some inputs
came from a passed test. The new clock, other timings, quantization or platform
conditions may differ. Validate memory stability and data integrity on the
intended hardware before relying on a custom bin. Software does not run stress
tests, certify stability or turn a user report into a hardware guarantee.

## Export and provenance

Profile JSON uses `spd-tool-xmp-profile/1` and retains exact requested fields
and a module hash. Proposal exports use `spd-tool-timing-proposals/1` and include
evidence, source classifications, constraints and diagnostics. Output filenames
must be new. Applying an XMP draft records generated provenance with kind
`ddr3-xmp`, the requested/encoded profile, original/result hashes, evidence and
byte changes. Archive with **Add editor image** to retain that record in the
collection and submission manifest. Undo/redo tracks it by buffer state.

The collection uses its common generated-profile provenance mechanism
(`vendor_profile_application` in submissions). Generated timing images are
excluded from HPT mining and independent donor evidence. A binary file alone
cannot retain this metadata; preserve the report/manifest when sharing it.

## Layout references

- Intel's [DDR3 XMP technology paper](https://www.intel.com/content/dam/doc/white-paper/extreme-memory-profile-ddr3-technology-paper.pdf)
  describes the extension and firmware-selected performance profiles.
- The Intel-authored [EDK2 MRC SPD structures](https://patchew.org/EDK2/20190817001603.30632-1-michael.a.kubacki%40intel.com/20190817001603.30632-29-michael.a.kubacki%40intel.com/)
  identify the profile fields, global FTB and signed fine-offset locations.
- [pyhwinfo's original SPD parser](https://github.com/remittor/pyhwinfo/blob/master/memory.py)
  independently documents the tREFI multiplier.
- [U-Boot's DDR3 controller implementation](https://github.com/u-boot/u-boot/blob/master/drivers/ddr/fsl/ctrl_regs.c)
  provides the reference CWL period ranges used by the planner. It is not a
  substitute for the target chip/controller datasheets.


## Native conversion and interactive analysis

**Analyze proposal** opens the shared Timing Analysis page. **Preview native SPD
proposal** translates the selected proposal into the loaded generation's native
fields; illegal CAS values and unrepresentable timings are refused. The native
page's **Danger Zone** translates enabled DDR3 XMP slots into primary timing
fields with explicit tested-hardware acknowledgment, dependency adjustment,
CRC repair and a reversible preview. Voltage and several controller behaviors
cannot be transferred to native fields. See [Engineering workbench](ENGINEERING_WORKBENCH.md)
for these workflows and the timing model's assumptions.

## Live feasibility and clock-based drafts

Profile fields are validated as they are typed. Red entries cannot be encoded
or conflict with the current timing combination; amber entries show quantization
or deliberately overridden warnings. The diagnostic table lists affected fields
and explains each result without requiring repeated preview-error dialogs.

For example, at 0.833 ns tCK, a 9.113 ns tAA requires at least CL11. Selecting
only CL6 and CL10 is inconsistent. The editor highlights CAS, tAA and tCK and
shows the clock envelope for the currently selected CAS/tAA combination.

That envelope combines the actual profile timebase/field capacity and CAS-time
constraint. It is an **encoding/CAS envelope**, not an assertion that the chips,
PCB or memory controller work throughout that range. MHz is the DRAM clock;
DDR MT/s is twice that clock. Displayed rates use encoded, quantized periods.

Choose a target in MHz or MT/s, choose **Current profile** or **SPD / loaded
evidence**, then **Generate timing draft at this speed**. Current-profile mode
preserves absolute timing minima, rounds them to cycles at the requested clock,
selects a representable CAS, and accounts for actual encoding when satisfying
tRC ≥ tRAS+tRP. It retains refresh as a maximum interval and preserves expert
vendor fields. SPD mode uses the existing evidence-aware planner. Generation
updates the editable form; it does not apply or program an image. Preview the
result before applying it. Quantization may make the encoded rate slightly
lower than the requested rate.

Supplied datasheet voltage/rate/timing limits and failed-test records are shown
as additional warnings. Malformed inputs, invalid timebases and numeric overflow
remain errors. A generated draft remains untested, including when some anchor
values came from user-reported passed tests.

## Idiot override

**Idiot override** explicitly permits logically inconsistent XMP timing
combinations and bypassing supplied operating-limit warnings. Enter an override
reason or intent, review the highlighted conflicts, preview, then apply. The
confirmation identifies the override; its reason and diagnostics are stored in
provenance and the operation audit. Changing the override after preview requires
a new review, just like changing timing fields.

This permits combinations such as a CAS bitmap that cannot satisfy tAA/tCK or
tRC shorter than tRAS+tRP. It does not silently wrap overflowing integers, accept
NaN or write a nonexistent CAS bit. Values still have to fit the selected SPD
format. The byte editor remains available for deliberate raw encodings.

The native and DDR2 EPP timing pages also have explicit logical-consistency
overrides with recorded reasons. Native timing inputs flag encoding errors and
dependency conflicts while editing. Native drafts can be generated directly
from a chosen MHz or MT/s value through the common timing planner. The override
does not waive the separate physical programmer's target, backup and read-back
requirements, and does not establish successful operation.
