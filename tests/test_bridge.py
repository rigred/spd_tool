# SPDX-License-Identifier: MIT
import binascii
import unittest
from spd_bridge import SerialBridge, frame


class FakeSerial:
    def __init__(self, **kwargs):
        self.options = kwargs
        self.closed = False
        self.reply = '256 16 1 1'
        self.requests = []
        self.fault = None

    def open(self): pass
    def close(self): self.closed = True
    def reset_input_buffer(self): pass

    def write(self, data):
        self.requests.append(data)
        return len(data)-1 if self.fault == 'short-write' else len(data)

    def read_until(self, delimiter, size):
        text = self.requests[-1].decode().split('*')[0].split(' ')
        response = frame(' '.join(text[:2]) + ' OK' + (' '+self.reply if self.reply else ''))
        if self.fault == 'crc': response = response[:-6] + b'*0000\n'
        if self.fault == 'sequence': response = frame('SPD1 0 OK 256 16 1 1')
        if self.fault == 'timeout': response = b''
        if self.fault == 'error': response = frame(' '.join(text[:2]) + ' ERR I2C_READ')
        return response


class BridgeTests(unittest.TestCase):
    def connect(self, stream):
        return SerialBridge('fake', serial_factory=lambda **kw:stream, settle=0)

    def test_frame_handshake_exact_read_and_write(self):
        self.assertEqual(frame('123456789'), b'123456789*31C3\n')
        stream = FakeSerial()
        with self.connect(stream) as bridge:
            self.assertTrue(bridge.write_enabled)
            stream.reply = '01020304'
            self.assertEqual(bridge.read(0x50, 3, 4), b'\x01\x02\x03\x04')
            stream.reply = ''
            bridge.write_byte(0x50, 63, 0xA7)
        self.assertTrue(stream.closed)

    def test_bad_frames_fail_closed_without_retry(self):
        for fault in ('crc','sequence','timeout','error','short-write'):
            stream = FakeSerial()
            with self.connect(stream) as bridge:
                stream.fault = fault
                with self.assertRaises((ValueError, OSError)):
                    bridge.read(0x50, 0, 1)
                self.assertTrue(stream.closed)
                self.assertIsNone(bridge.stream)
                self.assertEqual(len(stream.requests), 2)

    def test_lengths_capabilities_and_write_lock(self):
        for reply in ('512 16 1 1', '256 16 1', '256 16 16 1'):
            stream = FakeSerial(); stream.reply = reply
            with self.assertRaises(ValueError):
                with self.connect(stream): pass
            self.assertTrue(stream.closed)
        stream = FakeSerial(); stream.reply = '256 16 1 0'
        with self.connect(stream) as bridge:
            with self.assertRaisesRegex(ValueError, 'jumper'):
                bridge.write_byte(0x50, 0, 1)
            with self.assertRaises(ValueError): bridge.read(0x49, 0, 1)
            with self.assertRaises(ValueError): bridge.read(0x50, 255, 2)
            stream.reply = 'AA'
            with self.assertRaisesRegex(ValueError, 'Short'):
                bridge.read(0x50, 0, 2)
            self.assertTrue(stream.closed)


if __name__ == '__main__':
    unittest.main()
