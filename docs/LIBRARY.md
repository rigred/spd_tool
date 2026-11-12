# SPD library

The **SPD library** tab integrates collection management with the editor.
Choose **Open / create collection** and select a writable folder. The collection
contains a portable `library.sqlite3` database and exact binary copies under:

```text
modules/<memory type>/<manufacturer>/<model>/<serial>--<SHA-256>.bin
```

Names are sanitized for Windows and Unix filesystems and components are kept
short. Keep the collection root short when targeting Windows installations
without long-path support. Move/copy the entire collection together; database
paths are relative. Do not edit managed copies outside the editor. Hashes are
checked when reopening them.

## Import and edit

Use **Add SPD files** for binary or supported hex-text dumps, **Import folder**
for a recursive batch, or **Add editor image** to capture the current editor
buffer, including unsaved changes. Imports never move or repair the source.
Identical bytes share one database entry while source references are retained.
Different dumps with the same serial remain distinct. Invalid checksums remain
visible for recovery work. Errors are reported per file.

Imports use the core SDR/DDR/DDR2/DDR3 decoder and its 128-256-byte limits.
Large firmware images must first be extracted with the firmware scanner. Files
larger than 1 MiB and symbolic links are rejected, and folder imports are limited
to 10,000 candidate files. Folder imports consider `.bin`, `.spd`, `.hex` and
`.txt`. An import result's accepted count includes duplicates encountered.

Select one row and **Open selected in editor**. The editor receives a snapshot;
Save As and subsequent **Add editor image** preserve a modified version without
overwriting the archived original. Search matches identity, integrity and hash.

The historical `sort_spd.py` SQLite/HTML organizer remains available. Its old
SQLite schema is not rewritten or opened as the new database. To bring an old
collection into this interface, import its organized binary folder into a new
collection. Existing JSON/HTML indexes are not needed and are left untouched.
DDR4 records in the old organizer remain there until core catalog support is
extended; the GUI reports those imports as unsupported.

## HP SmartMemory

**Analyze HPT family** examines the selected DDR3 model. **Compute HPT for editor
serial** evaluates that selected model's family for the current DDR3 editor
serial; explicitly verify the editor module belongs to the selected family.
Results are displayed as JSON, including coefficients, provenance, possible
HPT values and limitations. They do not program hardware or change an image.
Use the editor's HP SmartMemory tab to apply a deliberately chosen value.

Registered family lookup uses normalized exact part numbers and listed aliases.
For an unregistered model, local evidence is grouped by manufacturer, model and
module organization. Only integrity-valid images with a complete HPT tag count.
Repeated images or repeated serials do not count as independent evidence.
Conflicting HPT values for one serial prevent local inference.

Two distinct serial/HPT pairs define a **provisional** modular relation. Three
or more matching samples are labeled **sample-consistent** only when every
available sample satisfies it. Neither label establishes an authentic HP
family, cryptographic validity or compatibility. An inconsistent group yields
no inferred family. Degenerate relations and more than 1024 possible HPT values
are not enumerated. Multiple solutions remain visible rather than selecting
one silently. Learned relations are recomputed from the collection and never
automatically saved into the bundled family registry.

## Public submission interface

Select one or more rows and choose **Prepare public submission**. After an
explicit disclosure prompt, the tool creates a new ZIP with raw images and a
versioned `spd-tool-submission/1` manifest. Absolute source paths are omitted;
raw images retain serial numbers and vendor data. Review the archive before
publishing it. Existing output files are not replaced.

No public endpoint is configured and no network upload is performed. This
export is the integration boundary for the future service. A service adapter
must add endpoint configuration, explicit publication consent, transport and
server validation, authentication where required, and durable receipt/error
handling. Offline bundles must remain usable without an account or network.
