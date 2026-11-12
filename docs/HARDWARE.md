# Linux SPD acquisition

The editor exposes acquisition and programming in its **Hardware / programmer**
tab. See the [GUI workflow](GUI_HARDWARE.md) for reviewed writes, or the
[external bridge guide](EXTERNAL_BRIDGE.md) for standalone DIMM fixtures.

Soldered RAM may use firmware-supplied SPD data without an exposed EEPROM.
Use [embedded SPD extraction](FIRMWARE.md) to investigate BIOS images offline.

`spd_smbus.py` provides passive adapter discovery, consistent EEPROM reads and
an explicit raw-I2C programming path. It does not configure PCI devices, select
mux channels, unbind drivers, load kernel modules or access private iLO buses.

## Discovery

```sh
python spd_smbus.py doctor
python spd_smbus.py list
python spd_smbus.py list --bus 1
```

`doctor` reports the platform vendor/model, BIOS version, kernel and available
adapters. `list` reports adapter names/capabilities and registered devices at
0x50-0x57, including bound drivers and EEPROM interfaces. Both commands are
passive: querying adapter capabilities does not issue EEPROM transactions.
Device permissions can limit the capability information without preventing
sysfs inventory.

Adapter numbers are assigned by Linux and can change between boots. Neither
an adapter number nor an SPD address identifies a physical DIMM slot. Use
platform inventory/slot labels to establish that correspondence.

`scan --bus N` is also passive. Explicit active probing is available for a
selected adapter:

```sh
python spd_smbus.py scan --bus 1 --probe
```

This reads offsets 0-2 at 0x50-0x57, skips kernel-owned devices, and reports
per-address failures. It does not use SMBus QUICK, scan other address ranges,
select pages or route muxes. Review the adapter's purpose before probing it.

## Read an image

```sh
python spd_smbus.py read --bus 1 --addr 0x50 \
  --out module.bin --report module-read.json
```

Use the permissions appropriate for the selected `/dev/i2c-N` or sysfs EEPROM
interface. The tool itself does not elevate privileges.

### Transport selection

| Backend | Behavior |
| --- | --- |
| `auto` (default) | Use an existing kernel EEPROM file; otherwise select a supported raw transport |
| `sysfs` | Require `/sys/bus/i2c/devices/N-005x/eeprom` |
| `smbus` | Require SMBus Read Byte Data; read each offset explicitly |
| `i2c` | Require `I2C_FUNC_I2C`; use combined offset/read transfers |

Raw auto-selection prefers SMBus byte-data reads. This supports SMBus-only
adapters without assuming that `I2C_RDWR` is available. Raw access first uses
normal `I2C_SLAVE` ownership checks. A bound driver is not overridden, and a
failed sysfs read never falls back to bypassing that driver.

Raw reads support SDR/DDR/DDR2/DDR3 and stop at byte 255. DDR4 full-image reads
require an ee1004 EEPROM interface, which manages page access in the kernel.
A generic EEPROM file is not assumed to be ee1004.

### Consistency and output

Two matching snapshots are required by default. `--snapshots` accepts 2-5.
Transient transfer failures have bounded retries (`--retries 0-5`, default 2).
Kernel driver transaction timeouts still govern an individual ioctl; the tool
does not change adapter-wide timeout settings. Kernel EEPROM drivers may cache
data, so matching sysfs snapshots are not a claim of two independent physical
bus measurements.

Short transfers, differing snapshots and failed integrity checks abort before
image output replacement. `--allow-invalid` permits preservation of a stable
image with diagnostics; it does not repair the EEPROM or the saved image.
Read reports identify the source, range, snapshot count, SHA-256 and diagnostics.
They do not assign a physical DIMM slot or certify hardware compatibility.

Partial reads contain exactly the requested bytes, without padding:

```sh
python spd_smbus.py read --bus 1 --addr 0x50 \
  --start 176 --end 183 --out hpt-block.bin
```

Ranges are inclusive. The default range is 0-255, or 0-511 for an ee1004
interface. Set `--end 127` when acquiring a 128-byte image. Integrity checks
apply only when the requested range includes the applicable checksum/CRC;
partial output is an extracted region, not a complete SPD container.

## HP ProLiant ML350p / DL360p Gen8

Begin with passive diagnostics:

```sh
python spd_smbus.py doctor > hardware.json
python spd_smbus.py list
```

On a host adapter exposing SPD, use a bound EEPROM interface or the supported
SMBus byte-data path. Intel's `i2c-i801` driver supports Patsburg-class adapters
and additional integrated device functions; the actual adapters and reachable
addresses must be established on the running system.

Host SMBus visibility is firmware/platform-dependent. An empty inventory does
not establish that a DIMM slot is empty. This tool does not attempt hidden-PCI
controller enablement, arbitrary mux writes, BMC arbitration bypass or forced
driver removal to reach additional slots. Its cooperative adapter lock only
coordinates other processes using the same locking convention; it cannot
exclude firmware or a management controller.

HPE advisory c04629195 documents an iLO 4 firmware 2.03 SNMP SPD retrieval
issue affecting these Gen8 models and describes RIBCL retrieval as a workaround.
That management-interface issue is separate from Linux host-bus access. The
tool has no iLO/RIBCL transport, and iLO inventory should not be treated as a
byte-exact EEPROM dump without checking the returned data.

The transport code is tested with mocked Linux ioctl/sysfs boundaries. Actual
ML350p/DL360p Gen8 reads, slot routing and EEPROM programming have not been
hardware-qualified. Preserve `doctor` output, the acquisition report, kernel
messages and the image when reporting a platform-specific failure.

## Programming

Programming is separate from discovery and reads. It requires an explicit
opt-in, range, original-image backup and a raw-I2C-capable adapter. There is no
SMBus-only page-programming fallback or ee1004 write path.

```sh
python spd_smbus.py write --bus 1 --addr 0x50 --in modified.bin \
  --range 176:183 --enable-write --backup original.bin --verify
```

The target is read twice before programming. The backup is created exclusively
and is not overwritten. The expected final image must have valid base
integrity. Writes respect EEPROM page boundaries; read-back verification is
mandatory and includes the complete image afterward. Ambiguously completed
write transactions are not retried automatically. Select the correct EEPROM
page size and write-cycle delay for the device.

`--fix-crc` updates the input image's applicable integrity field before the
range is applied. If the selected range omits a required checksum change, the
expected-image check rejects the operation. Byte ranges are never silently
clipped and oversized images are rejected. Electrical write protection and
firmware ownership remain platform constraints.

## References

- [Linux userspace I2C interface](https://docs.kernel.org/i2c/dev-interface.html)
- [Linux I2C/SMBus capabilities](https://docs.kernel.org/i2c/functionality.html)
- [Linux i2c-i801 driver](https://docs.kernel.org/i2c/busses/i2c-i801.html)
- [HPE advisory c04629195](https://support.hpe.com/hpesc/public/docDisplay?docId=c04629195&docLocale=en_US)
