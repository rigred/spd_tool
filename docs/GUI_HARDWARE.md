# Hardware acquisition and programming in the editor

Open the **Hardware / programmer** tab in `python spd_tool.py gui`. Connection
discovery is explicit: starting the editor or opening an SPD file performs no
hardware transactions. The panel supports a Linux I2C/SMBus adapter or a
[USB serial SPD bridge](EXTERNAL_BRIDGE.md).

## Discover, scan and select

1. Select **Linux I2C / SMBus** or **USB serial bridge**.
2. Click **Discover adapters**, then choose the intended adapter or port.
   Adapter numbers and serial port paths may also be entered manually.
3. Click **Scan selected adapter**.
4. Select a readable device to inspect its identity, serial number, acquisition
   source, snapshot count, integrity diagnostics and SHA-256.

Linux scanning defaults to registered devices with a kernel EEPROM interface.
Enable **Probe unregistered SPD addresses** to read unregistered addresses
0x50-0x57 on that adapter. No general I2C sweep or SMBus QUICK probe is used.
The external bridge's explicit scan reads the same eight SPD addresses. Failed
addresses remain visible alongside successful reads.

Acquisition requires two matching snapshots. Stable images with damaged
integrity remain available with diagnostics, allowing recovery and inspection.
An unstable or incomplete acquisition is not accepted. Kernel EEPROM drivers
may cache data; see [Linux acquisition](HARDWARE.md) for transport details.

The list is ordered by valid integrity, editor support and image completeness.
**Select best available image** selects the first readable entry using that
ordering. This is an acquisition-quality preference: it does not optimize RAM
timings, select an electrically compatible donor or identify the physical slot.
Reported MT/s is the SPD timing limit, not a measurement of the running clock.
Confirm the selected part number and serial against the intended DIMM.

## Read and save

**Read into editor** acquires a fresh pair of matching snapshots from the
selected device and opens them on the Overview tab. Unsaved editor changes are
handled through the usual save/discard prompt. A hardware read has no file
path; use **Save As** to preserve it.

**Save selected dump** saves the exact image captured by the scan. It does not
perform another hardware read or repair integrity. Choose a new filename;
existing files are not replaced. Select the device again to inspect provenance
and its image hash.

Linux ee1004 DDR4 dumps can be acquired and saved, but cannot be opened in the
current decoder/editor or programmed. The serial bridge supports SDR, DDR,
DDR2 and DDR3 with declared 128/256-byte EEPROMs. It performs no page selection.

## Review and program

1. Load or edit the desired image in the editor.
2. Return to **Hardware / programmer** and select the target device.
3. Choose an inclusive byte range. The range must fit both the editor image and
   the target EEPROM. A 128-byte image can update the base of a 256-byte target;
   the target tail is retained.
4. Leave **Repair integrity in programming copy** enabled to compute the
   checksum/CRC for the outgoing copy. Include those checksum bytes in the range
   when changing covered data. This option does not modify the editor buffer.
5. Click **Review changes**. The programmer reads a fresh target twice and
   displays its identity, original/result hashes and every byte difference.
6. Click **Back up, program and verify**, choose a new backup filename and
   confirm the named device and change count.

Changing the editor data, target, range or repair option invalidates the
review. The commit operation reacquires the target twice under a single
transport session and compares it with the reviewed original. A changed or
unstable target aborts before writing. The target memory generation and EEPROM
capacity declaration cannot be changed.

A full target backup is exclusively created and flushed before any EEPROM
write. A neighboring `.json` file records the reviewed plan, hashes and byte
changes. Both filenames must be new. The plan file is review metadata, not a
certificate that a later programming attempt succeeded.

Only changed bytes are programmed, using single-byte writes without automatic
write retries or EEPROM page-size assumptions. Two full target read-backs
must match the reviewed result, including bytes outside the selected range.
The GUI reports completion only after verification. Scan again before further
hardware operations.

Programming requires raw I2C support on Linux. SMBus-only adapters can read
SPDs but cannot use this programming path. Kernel-owned devices are never
forcibly claimed or unbound; use a suitable external programmer for those
targets. The USB bridge additionally requires its physical write-enable jumper.
EEPROM write protection remains in force; the tool does not issue protection
unlock commands or emulate vendor authorization.

## Progress, cancellation and failures

Transport operations run outside the Tk event thread. Hardware controls are
locked during an operation; the editor stays responsive. **Cancel read / scan**
stops at the next cancellation boundary. A Linux ioctl remains governed by its
driver's timeout. Programming runs to completion or failure and cannot be
cancelled mid-sequence. Close is blocked while a hardware operation is active.
The panel has an outer scrollbar for smaller windows, plus independent result
and review scrollbars.

If programming fails after it begins, retain the backup and reacquire the
device. The EEPROM may contain a partially modified image. Automatic rollback
is not attempted over an uncertain connection. A backup can be loaded into the
editor and programmed through a new explicit review after correcting the
underlying connection or write-protection problem. A matching hash establishes
image contents, not electrical suitability or successful memory training.
