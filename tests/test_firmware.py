# SPDX-License-Identifier: MIT
import binascii
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from spd_firmware import scan_blob, scan_firmware
from spd_integrity import repair_integrity
from tests.test_spd import ddr2, ddr3, ROOT
from tests.test_registered import legacy


def modern(memory_type=12):
    d = bytearray(128)
    for offset, value in {0:0x23, 1:0x11, 2:memory_type, 3:2 if memory_type == 12 else 14,
                          4:5, 5:0x21, 12:1, 13:3, 18:10, 19:20,
                          20:0x80, 24:110, 26:110}.items():
        d[offset] = value
    d[126:128] = binascii.crc_hqx(d[:126], 0).to_bytes(2, 'little')
    return bytes(d)


class FirmwareTests(unittest.TestCase):
    def test_unaligned_adjacent_and_duplicate_bases(self):
        for raw in (ddr3()[:128], ddr3(short=True)[:128], ddr2()[:128],
                    legacy(4)[:128], legacy(7)[:128], modern(), modern(15), modern(16), modern(17)):
            image = b'capsule!' + raw + raw + b'\xff' * 31
            hits = scan_blob(image)
            self.assertEqual([h['offset'] for h in hits], [8, 136])
            self.assertEqual([h['data'] for h in hits], [raw, raw])
            self.assertTrue(all(h['integrity']['status'] == 'VALID' for h in hits))

    def test_invalid_and_intel_low_power_are_opt_in(self):
        invalid = bytearray(ddr3()[:128]); invalid[126] ^= 1
        intel = bytearray(ddr3()[:128]); intel[2] = 0xF1; intel[126:128] = b'\0\0'
        image = bytes(invalid + intel)
        self.assertEqual(scan_blob(image), [])
        hits = scan_blob(image, include_invalid=True)
        self.assertEqual([h['integrity']['status'] for h in hits], ['INVALID', 'UNVERIFIED'])
        self.assertEqual(hits[1]['memory_type'], 'LPDDR3-Intel')
        self.assertEqual(hits[1]['data'], intel)
        self.assertTrue(all(h['confidence'] == 'heuristic' for h in hits))

    def test_declared_crc_coverage_not_replaced_by_alternate(self):
        raw = bytearray(ddr3()[:128]); raw[0] ^= 0x80
        raw[126:128] = binascii.crc_hqx(raw[:126], 0).to_bytes(2, 'little')
        self.assertEqual(scan_blob(raw), [])
        self.assertEqual(scan_blob(raw, True)[0]['integrity']['status'], 'INVALID')

    def test_truncation_context_and_no_repairs(self):
        raw = ddr3()[:128]
        self.assertEqual(scan_blob(raw[:-1]), [])
        hit = scan_blob(raw, length=256)[0]
        self.assertEqual(hit['length'], 128)
        self.assertTrue(any('unavailable' in w for w in hit['warnings']))
        context = bytes(range(128))
        hit = scan_blob(raw + context, length=256)[0]
        self.assertEqual(hit['data'], raw + context)
        self.assertTrue(any('adjacent context' in w for w in hit['warnings']))
        self.assertEqual(scan_blob(raw + context)[0]['data'], raw)

    def test_false_positive_filters(self):
        rng = random.Random(919)
        self.assertEqual(scan_blob(bytes(rng.getrandbits(8) for _ in range(1024 * 1024)), True), [])
        for byte in (0, 255):
            self.assertEqual(scan_blob(bytes([byte]) * 4096, True), [])
        raw = bytearray(ddr3()[:128]); raw[3] = 0
        self.assertEqual(scan_blob(repair_integrity(raw)), [])

    def test_bundled_binary_samples(self):
        for path in (ROOT / 'samples').rglob('*.bin'):
            raw = path.read_bytes()
            if len(raw) >= 128 and raw[2] in (4, 7, 8, 11, 12):
                with self.subTest(path=path):
                    hits = scan_blob(b'BIOS!' + raw, include_invalid=True)
                    self.assertTrue(any(h['offset'] == 5 and h['data'] == raw[:128] for h in hits))

    def test_directory_provenance_exact_extraction_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / 'unpacked'; source.mkdir()
            nested = source / 'volume'; nested.mkdir()
            raw = ddr3()[:128]
            (nested / 'body.bin').write_bytes(b'12345' + raw)
            (source / 'second.bin').write_bytes(raw)
            (source / 'ignored').symlink_to(nested, target_is_directory=True)
            (source / 'ignored.bin').symlink_to(nested / 'body.bin')
            out = root / 'extracted'
            report = scan_firmware(source, out)
            self.assertEqual(report['errors'], [])
            self.assertEqual(len(report['files']), 2)
            self.assertEqual(report['unique_base_profiles'], 1)
            self.assertEqual(len(report['candidates']), 2)
            for hit in report['candidates']:
                self.assertEqual((out / hit['output']).read_bytes(), raw)
                self.assertEqual(hit['sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(hit['profile_id'], 'profile-0001')
            self.assertEqual(json.loads((out / 'report.json').read_text()), report)
            with self.assertRaisesRegex(ValueError, 'already exists'):
                scan_firmware(source, out)

    def test_limits_errors_and_non_file_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); image = root / 'large.bin'
            image.write_bytes(b'\xff' * (1024 * 1024 + 1))
            report = scan_firmware(image, max_file_mib=1)
            self.assertEqual(len(report['errors']), 1)
            self.assertEqual(report['bytes_scanned'], 0)
            image.write_bytes(ddr3()[:128])
            with patch('spd_firmware.MAX_CANDIDATES', 0):
                self.assertEqual(len(scan_firmware(image)['errors']), 1)
            with self.assertRaises(ValueError):
                scan_firmware(image, max_file_mib=0)
            with self.assertRaises(ValueError):
                scan_firmware(image, length=129)
            with self.assertRaises(ValueError):
                scan_firmware(root / 'missing')

    def test_cli_json_and_partial_failure_status(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); image = root / 'bios.cap'; image.write_bytes(b'UEFI' + ddr3()[:128])
            command = [sys.executable, str(ROOT / 'spd_tool.py'), 'firmware', 'scan', '--input', str(image), '--json']
            done = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(done.stdout)['candidates'][0]['offset'], 4)
            image.write_bytes(b'\xff' * (1024 * 1024 + 1))
            done = subprocess.run(command + ['--max-file-mib', '1'], capture_output=True, text=True)
            self.assertEqual(done.returncode, 1)
            self.assertEqual(len(json.loads(done.stdout)['errors']), 1)


if __name__ == '__main__':
    unittest.main()
