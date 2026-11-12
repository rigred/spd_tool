# External USB serial SPD programmer

The external interface connects the editor to a microcontroller acting as an
I2C controller. It supports standalone SPD EEPROM acquisition and byte
programming for SDR, DDR, DDR2 and DDR3 modules with declared 128/256-byte
EEPROMs. DDR4/DDR5 page switching, protection unlocking and vendor-specific 
protocols are outside this bridge's scope.

## Host setup

Install the optional serial dependency in the environment used by the editor:

```sh
python -m pip install -r requirements-bridge.txt
python spd_tool.py gui
```

Open **Hardware / programmer**, select **USB serial bridge**, discover ports
and choose the bridge's port. A port path such as `/dev/ttyUSB0`,
`/dev/ttyACM0` or `COM4` can also be entered manually. The port is configured at
115200 baud, 8N1 without hardware flow control. Serial transfers have two-second
read/write timeouts, and POSIX ports use exclusive access. Opening a connection
allows two seconds for boards that reset on serial open; DTR/RTS are deasserted
by the host, but board/driver behavior can still cause a reset.

Discovery enumerates ports without opening them. Scan/read/review/program
operations open and close their own connection, with a versioned capability
handshake before I2C traffic. Scanning can therefore take additional time on
boards that reset at each connection. No arbitrary serial terminal protocol,
Bus Pirate mode or third-party adapter firmware is assumed.

Follow the [GUI hardware workflow](GUI_HARDWARE.md) for reading, selecting,
editing, backing up and programming.

## Reference firmware

The Arduino sketch is
[`firmware/spd_bridge/spd_bridge.ino`](../firmware/spd_bridge/spd_bridge.ino).
Build/upload it with a board package whose Wire implementation exposes
`WIRE_HAS_TIMEOUT`, `setWireTimeout`, `clearWireTimeoutFlag` and
`getWireTimeoutFlag`. The sketch deliberately fails compilation when timeout
support is absent. The board's standard `Serial` and default `Wire` pins are
used; check the selected board's pin map. No additional sketch libraries are
required.

The firmware uses a 100 kHz bus and a 25 ms Wire timeout with bus-controller
reset on timeout. Its default mode is read-only. Digital pin 4 is an
`INPUT_PULLUP` write interlock: ground it to enable programming, or leave it
open for reads only. The jumper is checked in the handshake and again before
every programming transaction. It is independent of the EEPROM's own WP pin
and software/permanent protection mechanisms.

## Bench fixture

Use an isolated DIMM socket/breakout wired for the exact module pinout. DIMM
and SO-DIMM pin numbers differ between generations; use the module's own
datasheet rather than a generic pin-number recipe.

| Signal | Connection |
| --- | --- |
| SDA | MCU Wire SDA through voltage-compatible open-drain I2C wiring |
| SCL | MCU Wire SCL through voltage-compatible open-drain I2C wiring |
| Ground | Common MCU, fixture and EEPROM supply reference |
| SPD supply | Regulated voltage specified for that module's SPD EEPROM |
| SPD address straps | Defined logic levels establishing 0x50-0x57 |
| MCU digital pin 4 | Open for read-only; grounded to permit programming |

Provide suitable SDA/SCL pull-ups to the EEPROM's I/O supply and level
translation where required. Some board libraries enable internal pull-ups to
the MCU supply; inspect and account for those too. A 5 V controller must not
drive a lower-voltage SPD bus directly. The DRAM's nominal operating voltage
is not an instruction for powering its separate SPD EEPROM. Verify the supply,
pull-up levels, socket wiring and EEPROM protection requirements before use.

Use this fixture with the module removed from the PC. Do not attach a powered
external controller to a module connected to a motherboard or another bus
controller. The sketch does not control fixture power, isolation, address
straps or the EEPROM's hardware WP pin.

## SPD1 protocol

Both directions use ASCII frames terminated by a single LF byte:

```text
SPD1 SEQUENCE COMMAND ARGUMENTS*CCCC\n
SPD1 SEQUENCE OK VALUES*CCCC\n
SPD1 SEQUENCE ERR REASON*CCCC\n
```

`CCCC` is four hexadecimal digits containing CRC-16/XMODEM of all ASCII bytes
before `*`, initial value zero, polynomial `0x1021`, without reflection or final
XOR. The LF and `*CCCC` suffix are excluded. The known vector `123456789` has
CRC `31C3`. This protects against accidental serial corruption; it is not an
authentication protocol.

Sequence numbers are decimal 1-999999999 and must be echoed exactly. The host
checks framing, sequence, CRC, status and expected payload length. A malformed,
stale, timed-out or rejected response closes the connection. No request with
an ambiguous completion is retried automatically.

| Request body after sequence | Successful reply after `OK` |
| --- | --- |
| `HELLO` | `256 16 1 ENABLED` |
| `READ ADDRESS OFFSET COUNT` | Exactly `COUNT*2` hexadecimal data characters |
| `WRITE ADDRESS OFFSET HH` | Empty payload |

All numeric arguments except `HH` are decimal. Addresses are 80-87 (0x50-0x57),
offsets 0-255, read counts 1-16, and `HH` is one byte encoded as two hex digits.
A read must remain within bytes 0-255. The handshake advertises a maximum
256-byte address space, 16-byte read payload, one-byte write payload and a
write interlock state of `0` or `1`. The host derives the actual target extent
from supported EEPROM capacity declarations and rejects unsupported layouts.

Writes require a recognized memory type, supported capacity, unchanged memory
type at byte 2 and an enabled physical jumper. One EEPROM byte is sent per I2C
transaction, followed by a 20 ms write-cycle delay and byte read-back. An ACK
alone is not accepted as successful programming. Host-side full-image matching
and backup checks remain mandatory.

Frames longer than the reference firmware's 159-character input payload are
discarded through the next LF. Incomplete input is discarded after one second
without another byte. Bad frame CRCs are discarded without I2C traffic; the
host then times out. A bridge implementation must not print debug output onto
the protocol port. Host responses are bounded below 256 bytes.

## Validation and extension

The tests compile the shipped sketch with a C++ compiler against simulated
Arduino/Wire APIs and exercise it through the Python transport, including
programming, read-back and malformed-frame rejection. They do not qualify a
specific MCU board, voltage translator, fixture or physical EEPROM. Compile
against the intended board core and validate the fixture on a recoverable
module before relying on it for production programming.

Other microcontrollers can implement the same SPD1 interface. Preserve bounded
I2C timeouts, exact transfer lengths, address restrictions, the write interlock
and failure semantics. Extend the protocol version/capability negotiation
before adding larger address spaces or multi-page SPD support.

Reference APIs: [pySerial](https://pyserial.readthedocs.io/en/latest/pyserial_api.html)
and [Arduino Wire timeouts](https://docs.arduino.cc/language-reference/en/functions/communication/wire/setWireTimeout/).
