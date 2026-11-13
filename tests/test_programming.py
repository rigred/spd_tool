# SPDX-License-Identifier: MIT
from contextlib import contextmanager
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from spd_hardware import (DeviceImage, LinuxBackend, ExternalBackend, ranked,
                          prepare_programming, execute_programming)
from spd_integrity import repair_integrity
from tests.test_spd import ddr3


class MemoryBackend:
    target = 'test programmer'

    def __init__(self, original):
        self.memory = bytearray(original)
        self.writes = []
        self.backup = None
        self.fail_at = None
        self.corrupt = False
        self.reads = 0
        self.unstable = False

    @contextmanager
    def programmer(self, address):
        backend = self
        class Session:
            def read(self):
                backend.reads += 1
                result = bytearray(backend.memory)
                if backend.unstable and backend.reads % 2 == 0:
                    result[140] ^= 1
                return bytes(result)

            def write(self, offset, value):
                if backend.backup is not None:
                    assert backend.backup.read_bytes() == ddr3()
                if backend.fail_at == len(backend.writes):
                    raise OSError('Ambiguous write completion')
                backend.writes.append((offset, value))
                backend.memory[offset] = value
                if backend.corrupt:
                    backend.memory[255] ^= 1
        yield Session()


class ProgrammingTests(unittest.TestCase):
    def edited(self):
        data = bytearray(ddr3()); data[16] += 1
        return repair_integrity(data)

    def test_review_backup_minimal_writes_and_full_verification(self):
        backend = MemoryBackend(ddr3())
        image = self.edited()
        plan = prepare_programming(backend, 0x50, image[:128], 0, 127)
        self.assertEqual(plan.expected, image)
        self.assertEqual(backend.writes, [])
        with tempfile.TemporaryDirectory() as temp:
            backup = Path(temp) / 'backup.bin'; backend.backup = backup
            report = execute_programming(backend, plan, backup)
            self.assertEqual(backup.read_bytes(), ddr3())
            self.assertEqual(bytes(backend.memory), image)
            self.assertEqual(backend.writes, [(n, b) for n, a, b in plan.changes])
            self.assertTrue(report['verified'])
            self.assertEqual(json.loads(Path(str(backup)+'.json').read_text()), plan.report())

    def test_stale_unstable_wrong_generation_and_invalid_range_refused(self):
        backend = MemoryBackend(ddr3())
        plan = prepare_programming(backend, 0x50, self.edited(), 0, 255)
        backend.memory[145] ^= 1
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, 'changed since review'):
                execute_programming(backend, plan, Path(temp)/'backup')
            self.assertEqual(list(Path(temp).iterdir()), [])
        self.assertEqual(backend.writes, [])
        backend.unstable = True
        with self.assertRaisesRegex(ValueError, 'unstable'):
            prepare_programming(backend, 0x50, self.edited(), 0, 255)
        backend.unstable = False
        with self.assertRaisesRegex(ValueError, 'invalid integrity'):
            prepare_programming(backend, 0x50, self.edited(), 16, 16)
        with self.assertRaises(ValueError):
            prepare_programming(backend, 0x50, self.edited()[:128], 0, 255)

    def test_backup_failure_and_tampered_plan_never_write(self):
        backend = MemoryBackend(ddr3())
        plan = prepare_programming(backend, 0x50, self.edited(), 0, 255)
        with tempfile.TemporaryDirectory() as temp:
            backup = Path(temp)/'existing'; backup.write_bytes(b'keep')
            with self.assertRaises(FileExistsError):
                execute_programming(backend, plan, backup)
            self.assertEqual(backup.read_bytes(), b'keep')
            self.assertEqual(backend.writes, [])
            with self.assertRaisesRegex(ValueError, 'Invalid programming plan'):
                execute_programming(backend, replace(plan, start=200), Path(temp)/'new')

    def test_failed_writes_are_not_retried_and_final_image_is_checked(self):
        for corrupt in (False, True):
            backend = MemoryBackend(ddr3())
            plan = prepare_programming(backend, 0x50, self.edited(), 0, 255)
            backend.corrupt = corrupt
            if not corrupt:
                backend.fail_at = 1
            with tempfile.TemporaryDirectory() as temp:
                backup = Path(temp)/'backup'
                with self.assertRaises(OSError):
                    execute_programming(backend, plan, backup)
                self.assertEqual(backup.read_bytes(), ddr3())
                self.assertEqual(len(backend.writes), len(plan.changes) if corrupt else 1)

    def test_acquisition_ranking_and_summary(self):
        good = DeviceImage('test', 0x51, ddr3(), 'test')
        bad = DeviceImage('test', 0x50, ddr3(), 'test', ('CRC mismatch',))
        short = DeviceImage('test', 0x52, ddr3()[:128], 'test')
        self.assertEqual(ranked([short, bad, good]), [good, short, bad])
        self.assertEqual(good.summary()['integrity'], 'VALID')
        self.assertEqual(good.summary()['length'], 256)

    def test_vintage_128_byte_target_preserves_size(self):
        from tests.test_registered import legacy
        original = bytearray(legacy(4, length=128)); original[1] = 7
        original = repair_integrity(original)
        edited = bytearray(original); edited[27] += 1
        edited = repair_integrity(edited)
        backend = MemoryBackend(original)
        plan = prepare_programming(backend,0x50,edited,0,127)
        self.assertEqual(len(plan.original),128)
        with tempfile.TemporaryDirectory() as temp:
            backup = Path(temp)/'backup'
            self.assertTrue(execute_programming(backend,plan,backup)['verified'])
            self.assertEqual(backup.read_bytes(),original)
            self.assertEqual(bytes(backend.memory),edited)

    def test_linux_kernel_owned_programming_rejected(self):
        import sys
        if not sys.platform.startswith('linux'):self.skipTest('Linux kernel ownership test')
        from unittest.mock import patch
        with patch('spd_smbus._driver', return_value='eeprom'), patch('spd_smbus.bus_session') as session:
            with self.assertRaisesRegex(ValueError, 'Kernel-owned'):
                prepare_programming(LinuxBackend(3), 0x50, ddr3(), 0, 255)
            session.assert_not_called()


if __name__ == '__main__':
    unittest.main()
