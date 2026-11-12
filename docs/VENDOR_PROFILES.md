# Vendor metadata and HP donor profiles

Open **SPD library → Vendor data / profiles**. This tool operates on collection
entries and the current editor buffer. Creating or applying a profile never
programs hardware directly.

## Inspect manufacturer and vendor data

**Inspect selected library image** reports its module and DRAM manufacturers,
manufacturer part number, raw manufacturer/customer regions, printable strings,
possible numeric part-number references, text hints, HPT signature and known
serial/HPT registry matches. Sticker annotations are shown separately.
**Inspect loaded editor image** examines the current buffer without requiring
it to be added to the collection first.

Manufacturer IDs are declarations decoded from SPD. An `HPT\0` marker indicates
an HP-compatible data layout; it does not authenticate the module. Text hints
and numeric part-number patterns remain explicitly unverified. For example,
a readable OEM name in an opaque region is evidence worth investigating, not
proof of the OEM's identity. An equation match can identify several candidate
families. Unknown binary fields remain raw hex with offsets rather than being
assigned invented meanings.

Vendor observations are automatically included in catalog metadata and public
submission entries. Existing catalogs receive a metadata-version backfill on
open without moving images or changing user-entered OEM annotations.

## Create a donor profile

1. Import a full donor dump from a module with the desired vendor data. Select
   that entry in the library and open **Vendor data / profiles**.
2. Use the bundled registry, or the collection's OEM labels and family mining,
   to establish a relation that validates the donor's actual serial/HPT pair.
3. Choose **Create profile from selected donor**. Select the family explicitly
   when several fit, give the profile a name, and save it.

Profiles are persisted in the collection database. An eligible donor must have
valid base integrity and an observed DDR3 HPT signature. A matching part-number
alias alone is insufficient: the selected relation must reproduce the donor's
actual HPT. Known registry entries, saved collection families and provisional
relations learned from distinct samples are available with their provenance.
A provisional relation does not become certified by being saved as a profile.

Default profiles modify only bytes 176-183: the HPT marker and four newly
computed HPT bytes. The donor's serial-bound HPT is not copied to a different
serial. The expert opaque-template option also copies bytes 150-175 and
184-255, and requires complete 256-byte donor and target images. These ranges
can contain undocumented identifiers or vendor checksums; their meanings and
portability are not established. This option must be chosen deliberately and
all changes remain visible in the preview.

## Apply to the corresponding generic module

Load the intended target dump into the editor. For the Samsung example, retain
the Samsung manufacturer's part number and the target's original serial.
Select the donor profile and choose **Find target HPT solutions**.

Eligibility checks require:

- DDR3 images containing the complete HPT block; image length is never expanded.
- The same manufacturer part number after whitespace/case normalization.
  Meaningful punctuation remains significant.
- Matching bytes 3-116, covering module layout, geometry, timing and register
  settings. A shared PN does not override a functional difference.
- Matching DRAM manufacturer IDs when both are populated.
- Valid donor and target base integrity, plus current donor-family validation.

Manufacturer IDs, serial, manufacturing date/location, part number, revisions,
and functional configuration are preserved. The tool does not fabricate an HP
sticker number or change the module's JEDEC manufacturer ID to impersonate a
supplier. Manual HP sticker family labels can establish the donor's family
scope across vendors, but do not waive the exact-PN and functional checks for
transferring a donor template to a target.

Even-coefficient families can produce multiple HPT solutions. None is selected
automatically when more than one exists. Choose a value deliberately; the
learned relation alone cannot determine which value a particular server will
accept. Unknown, inconsistent or stale donor relations stop the operation.
Zero/erased serials are flagged; the tool does not manufacture unique serials.

Choose **Preview changes** to inspect the target hash, preserved serial, chosen
HPT, donor/profile provenance and every byte difference. Existing non-HPT
customer data, potentially including XMP, requires an explicit replacement
permission. The default HPT-only mode overwrites the HPT block, not the rest of
that region; permission does not make other retained payload bytes meaningful.

**Apply reviewed changes to editor** revalidates the profile and checks that
the target buffer and chosen options still match the review. Applying is one
undoable operation. The base checksum/CRC is repaired without resizing the
image. Save As preserves a binary result. To program a DIMM, proceed separately
to **Hardware / programmer**, select the real device, and use the existing
change review, backup and full read-back verification workflow.

This can create an HPT-compatible profile for a corresponding generic module.
It does not make the module HP-certified, prove electrical qualification, or
guarantee SmartMemory recognition. Server firmware may check additional data,
use different relations, reject a revision or enforce other restrictions.
No physical server acceptance has been established by the software tests.

## Provenance and family-mining hygiene

Applying a profile records its donor, family coefficients, target hash/serial,
selected HPT, changes and result hash on the editor document. **Add editor image**
archives that provenance with the generated image. It survives reopening from
the library and is included in public submission manifests. Further edits are
marked as modified after profiling. Undo/redo restores the correct provenance
for each buffer state, so undoing a profile does not label the original buffer
as generated.

Generated entries are excluded from HPT family mining and selected-model sample
counts, and cannot become independent profile donors. This prevents fabricated
serial/HPT pairs from inflating evidence for their own generating relation.
Identical bytes share provenance in this content-addressed collection; marking
a hash as generated conservatively excludes that hash from evidence. Retain
independently acquired original dumps and their provenance.

A raw `.bin` alone cannot retain a provenance record or prove that it came from
hardware. When moving generated images between collections or publishing them,
retain their submission manifest/report and do not present generated dumps as
independently observed family evidence. Archive import of submission ZIPs is
not implemented; extracting/reimporting a binary by itself cannot reconstruct
its generation history.

See also [library management](LIBRARY.md),
[registered modules](../REGISTERED_MODULES.md), and
[GUI programming](GUI_HARDWARE.md).
