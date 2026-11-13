# SPDX-License-Identifier: MIT
"""Compile the shipped sketch and run host/firmware protocol integration."""
from pathlib import Path
import select
import os
import shutil
import subprocess
import tempfile
import unittest

from spd_bridge import SerialBridge, frame
from spd_hardware import ExternalBackend, prepare_programming, execute_programming
from tests.test_spd import ROOT, ddr3
from spd_integrity import repair_integrity


class SimulatedSerial:
    def __init__(self, executable, image, enabled=True, **kwargs):
        self.executable, self.image, self.enabled = executable, image, enabled
        self.process = None

    def open(self):
        self.process = subprocess.Popen([str(self.executable),str(self.image),'enabled' if self.enabled else 'locked'],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def close(self):
        if self.process:
            self.process.stdin.close()
            self.process.wait(timeout=3)
            self.process.stdout.close()
            self.process = None

    def reset_input_buffer(self): pass

    def write(self, payload):
        self.process.stdin.write(payload); self.process.stdin.flush()
        return len(payload)

    def read_until(self, delimiter, size):
        if not select.select([self.process.stdout],[],[],3)[0]:
            return b''
        return self.process.stdout.readline(size)


@unittest.skipUnless(os.name=='posix' and shutil.which('g++'), 'POSIX pipes and C++ compiler required for firmware simulator')
class FirmwareBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.exe = cls.directory/'bridge'
        subprocess.run(['g++','-std=c++17','-Wall','-Wextra','-Werror','-I',str(ROOT/'tests/bridge_simulator'),
                        str(ROOT/'tests/bridge_simulator/main.cpp'),'-o',str(cls.exe)],check=True,capture_output=True)
        cls.image = cls.directory/'spd.bin'; cls.image.write_bytes(ddr3())

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def bridge(self, enabled=True):
        return SerialBridge('simulator', serial_factory=lambda **kwargs:SimulatedSerial(self.exe,self.image,enabled,**kwargs),settle=0)

    def test_real_sketch_protocol_read_write_and_rejection(self):
        with self.bridge() as bridge:
            self.assertTrue(bridge.write_enabled)
            self.assertEqual(bridge.read(0x50,0,16), ddr3()[:16])
            bridge.write_byte(0x50,145,0x55)
            self.assertEqual(bridge.read(0x50,145,1),b'\x55')
            with self.assertRaises(OSError): bridge.request('WRITE 80 2 08')
        with self.bridge(False) as bridge:
            with self.assertRaises(OSError): bridge.request('WRITE 80 140 55')
        with self.bridge() as bridge:
            with self.assertRaises(OSError): bridge.request('READ 79 0 1')
        with self.bridge() as bridge:
            with self.assertRaises(OSError): bridge.request('READ 80 255 2')

    def test_end_to_end_programmer_uses_reference_sketch(self):
        # Keep a single simulated EEPROM alive across serial reconnects by sharing
        # one connected bridge through a context wrapper; actual EEPROM is persistent.
        from contextlib import contextmanager
        with self.bridge() as bridge:
            @contextmanager
            def connected(port): yield bridge
            backend = ExternalBackend('simulator', bridge_factory=connected)
            image = backend.read(0x50)
            self.assertEqual(image.data, ddr3())
            changed = bytearray(image.data); changed[16] += 1
            changed = repair_integrity(changed)
            plan = prepare_programming(backend,0x50,changed,0,255)
            with tempfile.TemporaryDirectory() as temp:
                result = execute_programming(backend,plan,Path(temp)/'backup')
                self.assertTrue(result['verified'])
                self.assertEqual(backend.read(0x50).data, changed)

    def test_bad_crc_and_oversized_frames_never_reach_wire(self):
        good = frame('SPD1 13 READ 80 140 1')
        bad = frame('SPD1 12 WRITE 80 140 55')[:-6] + b'*0000\n'
        oversized = b'X'*300+b'\n'
        done = subprocess.run([str(self.exe),str(self.image),'enabled'], input=bad+oversized+good,capture_output=True,timeout=3)
        self.assertEqual(done.stdout, frame(f'SPD1 13 OK {ddr3()[140]:02X}'))


if __name__ == '__main__': unittest.main()
