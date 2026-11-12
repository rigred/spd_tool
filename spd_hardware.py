# SPDX-License-Identifier: MIT
"""GUI hardware service: immutable read results and reviewable programming plans."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
import sys
from pathlib import Path

from spd_integrity import integrity_info, repair_integrity

SUPPORTED = {4: 'SDR', 7: 'DDR', 8: 'DDR2', 11: 'DDR3'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def target_length(header):
    if len(header) < 3:
        raise ValueError('Short SPD header')
    if header[2] in (4, 7, 8) and header[1] in (7, 8):
        return 1 << header[1]
    if header[2] == 11 and header[0] & 0x70 == 0x10:
        return 256
    raise ValueError('Target must declare a supported 128/256-byte SPD EEPROM')


def cancelled(event):
    if event is not None and event.is_set():
        raise ValueError('Operation cancelled')


@dataclass(frozen=True)
class DeviceImage:
    target: str
    address: int
    data: bytes
    source: str
    diagnostics: tuple = ()
    snapshots: int = 2

    @property
    def editable(self):
        return len(self.data) in (128, 256) and self.data[2] in SUPPORTED

    @property
    def valid(self):
        return not self.diagnostics

    def summary(self):
        memory = SUPPORTED.get(self.data[2], 'DDR4' if self.data[2] == 12 else f'0x{self.data[2]:02X}')
        identity, capacity, manufacturer, serial, rate = '', '', '', '', ''
        if self.editable:
            from spd_library import SPD
            decoded = SPD(self.data).decoded_data
            mfg = decoded.get('manufacturing', {})
            identity = str(mfg.get('module_part_number', mfg.get('part_number', '')))
            manufacturer = str(mfg.get('module_mfg_id', ''))
            serial = str(mfg.get('serial_number', ''))
            rate = decoded.get('max_data_rate_MTps', '')
            size = decoded.get('module_size_GiB')
            if size is not None:
                capacity = f'{size:g} GiB'
            elif decoded.get('module_size_MiB') is not None:
                capacity = f'{decoded["module_size_MiB"]:g} MiB'
        return dict(target=self.target, address=f'0x{self.address:02X}', memory=memory,
                    identity=identity, capacity=capacity, length=len(self.data),
                    manufacturer=manufacturer, serial=serial, data_rate_MTps=rate,
                    integrity='VALID' if self.valid else '; '.join(self.diagnostics),
                    sha256=digest(self.data), source=self.source, snapshots=self.snapshots)


def ranked(images):
    # Preference is acquisition quality, never a judgement of electrical suitability.
    return sorted(images, key=lambda d: (d.valid, d.editable, len(d.data), -d.address), reverse=True)


class LinuxBackend:
    def __init__(self, bus):
        if not sys.platform.startswith('linux'):
            raise ValueError('The local I2C / SMBus backend requires Linux; select USB serial bridge instead')
        if not isinstance(bus, int) or bus < 0:
            raise ValueError('Select a nonnegative Linux I2C bus')
        self.bus = bus
        self.target = f'Linux i2c-{bus}'

    def read(self, address, cancel=None):
        from spd_smbus import acquire_spd
        cancelled(cancel)
        base = acquire_spd(self.bus, address, end=127, allow_invalid=True)
        result = base if base.data[2] in (4, 7, 8) and base.data[1] == 7 else acquire_spd(self.bus, address, allow_invalid=True)
        cancelled(cancel)
        return DeviceImage(self.target, address, result.data, result.source, tuple(result.diagnostics), result.snapshots)

    def scan(self, active=False, cancel=None, log=lambda message: None):
        from spd_smbus import inventory
        records = inventory(self.bus)
        addresses = range(0x50, 0x58) if active else [int(d['address'], 16) for r in records for d in r['devices'] if d['eeprom']]
        images, errors = [], []
        for address in addresses:
            cancelled(cancel)
            log(f'Reading {self.target} / 0x{address:02X}')
            try:
                images.append(self.read(address, cancel))
            except (OSError, ValueError) as exc:
                cancelled(cancel)
                errors.append(f'0x{address:02X}: {exc}')
        return ranked(images), errors

    @contextmanager
    def programmer(self, address):
        import spd_smbus as hw
        hw._address(address)
        if hw._driver(self.bus, address):
            raise ValueError('Kernel-owned EEPROM cannot be programmed through raw I2C. Use an external programmer.')
        with hw.bus_session(self.bus) as fd:
            if not hw.adapter_functions(fd) & hw.I2C_FUNC_I2C:
                raise ValueError('This adapter does not support raw I2C programming')
            class Session:
                def read(self):
                    return hw.spd_read(fd, address, 0, self.length-1, transport='i2c')

                def write(self, offset, value):
                    # Byte writes avoid assuming an EEPROM page size.
                    data = bytearray(256)
                    data[offset] = value
                    data[2] = value if offset == 2 else self.memory_type
                    hw.spd_write(fd, address, bytes(data), offset, offset, page_size=8)
            session = Session()
            header = hw.spd_read(fd, address, 0, 2, transport='i2c')
            if header[2] not in SUPPORTED:
                raise ValueError('Programming requires SDR/DDR/DDR2/DDR3; no SPD page switching is supported')
            session.memory_type = header[2]
            session.length = target_length(header)
            yield session


class ExternalBackend:
    def __init__(self, port, bridge_factory=None):
        from spd_bridge import SerialBridge
        self.port = port
        self.target = f'USB bridge {port}'
        self.bridge_factory = bridge_factory or SerialBridge

    def _read(self, bridge, address, cancel=None):
        header = bridge.read(address, 0, 3)
        if header[2] not in SUPPORTED:
            raise ValueError('External bridge supports SDR/DDR/DDR2/DDR3 only; no SPD page switching')
        length = target_length(header)
        result = bytearray()
        for offset in range(0, length, 16):
            cancelled(cancel)
            result.extend(bridge.read(address, offset, 16))
        if len(result) != length:
            raise ValueError('Short external SPD image')
        return bytes(result)

    def read(self, address, cancel=None):
        with self.bridge_factory(self.port) as bridge:
            first = self._read(bridge, address, cancel)
            if first != self._read(bridge, address, cancel):
                raise ValueError('External SPD snapshots differ')
        info = integrity_info(first)
        issues = () if info['status'] == 'VALID' else (f'{info["variant"]} mismatch over {info["coverage"]}',)
        return DeviceImage(self.target, address, first, self.target, issues)

    def scan(self, active=False, cancel=None, log=lambda message: None):
        # Explicit Scan probes only SPD addresses, never a general I2C sweep.
        images, errors = [], []
        for address in range(0x50, 0x58):
            cancelled(cancel)
            log(f'Reading {self.target} / 0x{address:02X}')
            try:
                images.append(self.read(address, cancel))
            except (OSError, ValueError) as exc:
                cancelled(cancel)
                errors.append(f'0x{address:02X}: {exc}')
        return ranked(images), errors

    @contextmanager
    def programmer(self, address):
        with self.bridge_factory(self.port) as bridge:
            if not bridge.write_enabled:
                raise ValueError('Enable the bridge hardware write jumper before preparing programming')
            backend = self
            class Session:
                def read(self):
                    return backend._read(bridge, address)

                def write(self, offset, value):
                    bridge.write_byte(address, offset, value)
            yield Session()


@dataclass(frozen=True)
class ProgrammingPlan:
    target: str
    address: int
    original: bytes
    expected: bytes
    start: int
    end: int
    editor_hash: str

    @property
    def changes(self):
        return tuple((n, a, b) for n, (a, b) in enumerate(zip(self.original, self.expected)) if a != b)

    def report(self):
        return dict(target=self.target, address=f'0x{self.address:02X}', start=self.start, end=self.end,
                    original_sha256=digest(self.original), expected_sha256=digest(self.expected),
                    editor_sha256=self.editor_hash, changes=[dict(offset=n, before=a, after=b) for n, a, b in self.changes])


def prepare_programming(backend, address, image, start, end, repair=True):
    image = bytes(image)
    if len(image) not in (128, 256) or image[2] not in SUPPORTED:
        raise ValueError('Programming requires a 128/256-byte SDR/DDR/DDR2/DDR3 editor image')
    if not 0 <= start <= end < len(image):
        raise ValueError('Programming range must fit the editor image')
    desired = repair_integrity(image) if repair else image
    with backend.programmer(address) as session:
        original = session.read()
        if original != session.read():
            raise ValueError('Target is unstable; programming refused')
    if len(original) not in (128, 256) or end >= len(original) or original[2] != image[2]:
        raise ValueError('Target size or memory generation does not match the editor image')
    expected = bytearray(original)
    expected[start:end + 1] = desired[start:end + 1]
    if target_length(original[:3]) != len(original) or target_length(expected[:3]) != len(original):
        raise ValueError('Programming cannot change the target EEPROM capacity declaration')
    if integrity_info(expected)['status'] != 'VALID':
        raise ValueError('Selected range would leave invalid integrity; include the checksum/CRC bytes')
    return ProgrammingPlan(backend.target, address, original, bytes(expected), start, end, digest(image))


def execute_programming(backend, plan, backup, log=lambda message: None):
    if backend.target != plan.target:
        raise ValueError('Programming target changed; prepare a new review')
    if not plan.changes:
        raise ValueError('No changed bytes to program')
    if (len(plan.original) not in (128, 256) or len(plan.expected) != len(plan.original)
            or plan.original[2] not in SUPPORTED or plan.original[2] != plan.expected[2]
            or not 0 <= plan.start <= plan.end < len(plan.original)
            or any(not plan.start <= n <= plan.end for n, a, b in plan.changes)
            or target_length(plan.expected[:3]) != len(plan.original)
            or integrity_info(plan.expected)['status'] != 'VALID'):
        raise ValueError('Invalid programming plan; prepare a new review')
    # The fresh target check and exclusive backup occur under one transport session.
    with backend.programmer(plan.address) as session:
        current = session.read()
        if current != plan.original or current != session.read():
            raise ValueError('Target changed since review; no bytes were written')
        # Keep a sidecar next to the binary backup. Neither file may exist already.
        sidecar = Path(str(backup) + '.json')
        with sidecar.open('x', encoding='utf-8') as handle:
            json.dump(plan.report(), handle, indent=2)
            handle.flush(); os.fsync(handle.fileno())
        with Path(backup).open('xb') as handle:
            handle.write(current)
            handle.flush(); os.fsync(handle.fileno())
        if os.name == 'posix':
            directory = os.open(Path(backup).absolute().parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        log(f'Backup saved: {backup}. Programming {len(plan.changes)} changed bytes.')
        for index, (offset, before, after) in enumerate(plan.changes, 1):
            session.write(offset, after)  # Ambiguous writes are never retried.
            log(f'Programmed {index}/{len(plan.changes)}: byte {offset}')
        final = session.read()
        if final != plan.expected or final != session.read():
            raise OSError('Full-image verification failed; retain the backup and inspect the target')
    return dict(plan.report(), backup=str(backup), verified=True)
