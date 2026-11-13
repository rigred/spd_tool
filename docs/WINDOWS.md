# Windows execution and native SPD access

The editor, library, conversion tools and USB serial programmer run on Windows.
Native motherboard SMBus access uses the **official signed PawnIO driver** and
hash-pinned official SMBus modules. No WinRing0/RWEverything driver, arbitrary
port-I/O interface or kernel driver installer is included.

## Setup

1. Install the official signed driver from [pawnio.eu](https://pawnio.eu/).
   Keep normal Windows signing/security policies enabled; SPD Tool does not
   install/start drivers or change those policies.
2. Windows release packages include the SMBus modules. From source, run:

   ```powershell
   python packaging/fetch_windows_modules.py
   ```

   This verifies official PawnIO.Modules **0.2.11** archive/module hashes and
   retains the license and matching source archive. It does not install a
   driver. Offline inputs use `--archive` and `--source-archive`.
3. Run hardware operations as Administrator. File editing, conversion and
   collection management do not require elevation. USB serial uses its normal
   board driver and port permissions.

Native access requires **64-bit Windows on x86-64**. It uses PawnIO's documented
device IOCTL interface directly, without a PawnIOLib DLL.

## Controllers and scope

| Adapter | Support |
| --- | --- |
| `i801` | Intel I801-compatible SMBus recognized by the official module |
| `piix4` | Supported AMD FCH PIIX4-compatible controller, current primary port 0 |
| USB serial | External DIMM programming independently of the host chipset |

These names do not imply support for every Intel/AMD controller. The official
AMD module recognizes a narrower hardware set than the historical Linux PIIX4
driver. Unsupported controllers fail explicitly. Auxiliary ports, mux changes,
CPU IMC sideband access and physical DIMM slot mapping are not implemented.

The external programmer remains available for modules the host does not expose.

Native read/write covers **128/256-byte SDR, DDR, DDR2 and DDR3 SPD**. DDR4/DDR5
remain read-only file/archive support; live EEPROM paging/programming is outside
this backend. Intel host write protection is queried and never disabled. AMD
has no equivalent query here; ignored/protected writes fail readback and stop.

## GUI

In **Hardware / programmer**, select **Windows native SMBus**, then **Discover
adapters**. Discovery identifies controllers without probing DIMM addresses.
Select an adapter, enable **Probe unregistered SPD addresses (0x50–0x57)** and
scan. Windows has no equivalent to the Linux passive kernel EEPROM inventory.

The optional **Windows PawnIO modules** folder overrides the bundled/source
location. `SPD_TOOL_PAWNIO_DIR` supplies its initial value. Overrides must contain
the same pinned module bytes; arbitrary/newer modules are not accepted silently.
Changing the connection/module folder invalidates previous scans and reviews.
Stable reads require two identical snapshots. Programming uses the existing
range review, confirmation, exclusive backup and full-image verification flow.

## CLI

```powershell
python spd_tool.py windows-smbus adapters
python spd_tool.py windows-smbus --adapter i801 scan --probe
python spd_tool.py windows-smbus --adapter i801 read --addr 0x50 --out original.bin

# Preview only: no SPD writes.
python spd_tool.py windows-smbus --adapter i801 write --addr 0x50 --spd edited.bin --range 0:255

# Commit with an original-image backup and mandatory verification.
python spd_tool.py windows-smbus --adapter i801 write --addr 0x50 --spd edited.bin --range 0:255 --backup before.bin --enable-write
```

Use 7-bit addresses (`0x50`, not `0xA0`). `--module-dir` is an optional connection
option before the subcommand. Reads require valid integrity unless
`--allow-invalid` explicitly requests an unchanged stable recovery dump.
Write ranges are inclusive. Committing requires `--enable-write` and a new
backup filename. Console-built executables expose these commands through
`SPDTool.exe --cli windows-smbus ...`.

## Transactions and failures

The shared Windows SMBus mutex is held across an acquisition or complete
programming session, including backup and verification. Busy/abandoned mutexes
fail without resetting the bus. The mutex coordinates cooperating software;
it cannot arbitrate firmware, SMM or a BMC.

Only SMBus byte-data commands to `0x50–0x57` and offsets `0–255` are exposed.
There are no page-selector, protection-clear, clock-change or general I2C-sweep
commands. Controller identity is checked across sessions. Writes issue one byte
command followed by bounded readback polling. Ambiguous writes are never retried.
Stale targets, write errors and verification failures stop with backups retained.

Driver boundaries and controllers have simulated tests. GitHub's Windows job
checks execution/packaging without accessing a physical controller. A successful
offline self-test does not qualify a DIMM or motherboard for programming.

References: [PawnIO](https://github.com/namazso/PawnIO),
[pinned modules](https://github.com/namazso/PawnIO.Modules/tree/52a7e536dff3e53c96917a28caac5e0fa6510696),
[hardware acquisition](HARDWARE.md), [desktop builds](RELEASES.md).
