# SPDX-License-Identifier: MIT
"""Versioned, checksummed USB serial bridge for standalone SPD programmers."""
import binascii
from contextlib import contextmanager
import os
import secrets
import time


def frame(text):
    raw = text.encode('ascii')
    return raw + f'*{binascii.crc_hqx(raw, 0):04X}\n'.encode('ascii')


class SerialBridge:
    def __init__(self, port, baudrate=115200, serial_factory=None, settle=2):
        if not port:
            raise ValueError('Select a serial port')
        self.port, self.baudrate = port, baudrate
        self.serial_factory, self.settle = serial_factory, settle
        self.stream = None
        self.sequence = secrets.randbelow(1000000000)
        self.write_enabled = False

    def __enter__(self):
        factory = self.serial_factory
        if factory is None:
            try:
                import serial
            except ImportError as exc:
                raise ValueError('External bridge requires pyserial: python -m pip install pyserial') from exc
            factory = serial.Serial
        options = dict(port=None, baudrate=self.baudrate, timeout=2, write_timeout=2)
        if os.name == 'posix':
            options['exclusive'] = True
        try:
            self.stream = factory(**options)
            self.stream.dtr = False
            self.stream.rts = False
            self.stream.port = self.port
            self.stream.open()
            time.sleep(self.settle)  # Some boards reset when a serial port opens.
            self.stream.reset_input_buffer()
            capabilities = self.request('HELLO')
            if capabilities[:3] != ['256', '16', '1'] or len(capabilities) != 4 or capabilities[3] not in ('0', '1'):
                raise ValueError('Unsupported SPD1 bridge capabilities')
            self.write_enabled = capabilities[3] == '1'
            return self
        except Exception:
            self.close()
            raise

    def close(self):
        if self.stream is not None:
            self.stream.close()
            self.stream = None

    def __exit__(self, *args):
        self.close()

    def request(self, command):
        if self.stream is None:
            raise ValueError('Bridge is not connected')
        self.sequence = self.sequence % 999999999 + 1
        prefix = f'SPD1 {self.sequence}'
        payload = frame(f'{prefix} {command}')
        try:
            if self.stream.write(payload) != len(payload):
                raise OSError('Short serial write; reconnect before continuing')
            raw = self.stream.read_until(b'\n', 256)
            if not raw.endswith(b'\n') or len(raw) >= 256:
                raise OSError('Bridge timeout or oversized response; reconnect before continuing')
            body, crc = raw[:-1].rsplit(b'*', 1)
            if len(crc) != 4 or int(crc, 16) != binascii.crc_hqx(body, 0):
                raise ValueError('Bridge response checksum mismatch')
            tokens = body.decode('ascii').split(' ')
            if tokens[:2] != prefix.split(' '):
                raise ValueError('Stale or mismatched bridge response')
            if len(tokens) < 3 or tokens[2] != 'OK':
                raise OSError('Bridge rejected request: ' + ' '.join(tokens[3:]))
            return tokens[3:]
        except Exception:
            # Never continue on a desynchronized or ambiguously completed request.
            self.close()
            raise

    def read(self, address, offset, length):
        if not 0x50 <= address <= 0x57 or not 0 <= offset < 256 or not 1 <= length <= 16 or offset + length > 256:
            raise ValueError('Bridge read outside supported SPD range')
        reply = self.request(f'READ {address} {offset} {length}')
        if len(reply) != 1 or len(reply[0]) != length * 2:
            self.close()
            raise ValueError('Short or malformed bridge read')
        try:
            data = bytes.fromhex(reply[0])
        except ValueError:
            self.close()
            raise ValueError('Malformed bridge data')
        if len(data) != length:
            self.close()
            raise ValueError('Bridge data length mismatch')
        return data

    def write_byte(self, address, offset, value):
        if not self.write_enabled:
            raise ValueError('Bridge write-enable jumper is not enabled')
        if not 0x50 <= address <= 0x57 or not 0 <= offset < 256 or not 0 <= value <= 255:
            raise ValueError('Bridge write outside supported SPD range')
        if self.request(f'WRITE {address} {offset} {value:02X}'):
            self.close()
            raise ValueError('Unexpected write acknowledgement')


def list_ports():
    try:
        from serial.tools.list_ports import comports
    except ImportError as exc:
        raise ValueError('External bridge requires pyserial: python -m pip install pyserial') from exc
    return [(p.device, p.description) for p in comports()]
