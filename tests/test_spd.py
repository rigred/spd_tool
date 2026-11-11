import binascii
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ddr2_decoder import cycle_time
from spd_library import SPD, load_spd_file, hexdiff
from spd_integrity import integrity_info, repair_integrity
from spd_editor import EditorDocument

ROOT = Path(__file__).resolve().parents[1]


def ddr2(length=256, ecc=False):
    d = bytearray(length)
    # Synthetic 1 GiB, single rank, 8 banks, 14 row / 10 column bits, x8.
    for offset, value in {0:128,1:8,2:8,3:14,4:10,5:0,6:72 if ecc else 64,
                          8:5,9:0x25,10:0x40,11:2 if ecc else 0,12:0x80,
                          13:8,14:8 if ecc else 0,16:12,17:8,18:0x70,20:4,
                          23:0x30,24:0x45,25:0x3D,26:0x50,27:60,28:30,29:60,30:45,
                          31:1,36:60,37:30,38:30,40:2,41:60,42:127,43:0x50,
                          62:0x12,64:0x2C,93:0x09,94:0x25}.items():
        d[offset] = value
    d[73:91] = b'TEST-DDR2         '
    d[95:99] = bytes.fromhex('12345678')
    return repair_integrity(d)


def ddr3(length=256, short=False):
    d = bytearray(length)
    for off, val in {0:0x92 if short else 0x12,1:0x13,2:11,3:2,4:4,5:0x21,6:2,
                     7:9,8:11,9:0x11,10:1,11:8,12:10,14:0xA0,16:110,
                     17:120,18:110,19:48,20:110,21:0x11,22:24,23:134,
                     24:0,25:5,26:60,27:60,28:1,29:0,117:0x80,118:0x2C,
                     120:0x15,121:0x30}.items():
        d[off] = val
    if length >= 150:
        d[128:146] = b'TEST-DDR3         '
    return repair_integrity(d)


class DecoderTests(unittest.TestCase):
    def test_ddr2_organization_timings_and_checksum(self):
        for ecc in (False, True):
            d = SPD(ddr2(ecc=ecc)).decoded_data
            self.assertEqual(d['module_size_MiB'], 1024)
            self.assertEqual(d['ecc_bits'], 8 if ecc else 0)
            self.assertEqual(d['timings_ns']['tRFCmin'], 127.25)
            self.assertEqual(d['timings_ns']['tRPmin'], 15)
            self.assertEqual(d['max_data_rate_MTps'], 800)
            self.assertEqual(d['derived']['profiles'][0]['CL'], 6)
            self.assertIn('Micron', d['manufacturing']['module_mfg_id'])
            self.assertEqual(d['crc_info']['status'], 'VALID')
            self.assertEqual(d['manufacturing']['serial_number'], '12345678')
            self.assertEqual(d['manufacturing']['manufacture_date'], '2009-W25')
            self.assertEqual(d['warnings'], [])

    def test_ddr2_special_cycle_encodings(self):
        for raw, expected in [(0x3A, 3.25), (0x3B, 3.33), (0x3C, 3.66), (0x3D, 3.75), (0x25, 2.5)]:
            self.assertEqual(cycle_time(raw), expected)
        self.assertIsNone(cycle_time(0x3E))

    def test_ddr3_timings_and_ecc_capacity(self):
        d = SPD(ddr3()).decoded_data
        self.assertEqual(d['module_size_GiB'], 8)
        self.assertEqual(d['addressing_module_size_GiB'], 8)
        self.assertEqual(d['bank_address_bits'], 3)
        self.assertEqual(d['timings_clocks']['CL'], 11)
        self.assertEqual(d['timings_ns']['tWRmin'], 15)
        self.assertEqual(d['timings_ns']['tFAWmin'], 32)
        self.assertEqual(d['timings_ns']['tRCmin'], 48.75)
        self.assertTrue(all(int(p['timings'].split('-')[0]) in (9, 11) for p in d['jedec_downbins']))

    def test_signed_fine_offsets(self):
        raw = bytearray(ddr3()); raw[34] = 0xFF; raw[35] = 2; raw[38] = 0x80
        d = SPD(raw).decoded_data
        self.assertEqual(d['timings_ns']['tCKmin'], 1.249)
        self.assertEqual(d['timings_ns']['tAAmin'], 13.752)
        self.assertEqual(d['timings_ns']['tRCmin'], 48.622)

    def test_crc_known_vector_and_both_coverages(self):
        self.assertEqual(binascii.crc_hqx(b'123456789', 0), 0x31C3)
        for short in (False, True):
            raw = ddr3(short=short)
            self.assertEqual(integrity_info(raw)['status'], 'VALID')
            self.assertEqual(integrity_info(raw)['coverage'], '0..116' if short else '0..125')
            changed = bytearray(raw); changed[0] ^= 128
            self.assertEqual(integrity_info(changed)['status'], 'INVALID')
            repaired = repair_integrity(changed)
            self.assertEqual(integrity_info(repaired)['status'], 'VALID')

    def test_alternate_crc_is_only_diagnostic(self):
        raw = bytearray(ddr3()); raw[126:128] = binascii.crc_hqx(raw[:117], 0).to_bytes(2, 'little')
        info = integrity_info(raw)
        self.assertEqual(info['status'], 'INVALID')
        self.assertIn('diagnostic', info)

    def test_partial_and_unsupported_images(self):
        for length in (128, 176, 256):
            raw = ddr3(length)
            self.assertEqual(SPD(raw).data, raw)
            self.assertEqual(len(SPD(ddr2(length)).data), length)
        for raw in (bytes(127), bytes(128), bytes(512)):
            with self.assertRaises((ValueError, NotImplementedError)):
                SPD(raw)

    def test_bad_encodings_report_warnings(self):
        raw = bytearray(ddr3()); raw[11] = 0; raw[9] = 0
        d = SPD(raw).decoded_data
        self.assertFalse(d['time_bases']['valid'])
        self.assertTrue(d['warnings'])
        raw = bytearray(ddr2()); raw[40] = 0xEE; raw[9] = 0xFF
        self.assertIsNone(SPD(raw).decoded_data['timings_ns']['tRCmin'])

    def test_lrdimm_offsets(self):
        raw = bytearray(ddr3()); raw[3] = 11; raw[64] = 0x25; raw[65:67] = b'\x00\x2c'
        raw[102:117] = bytes(range(15))
        d = SPD(raw).decoded_data['registered_info']
        self.assertIn('Micron', d['mfg_id'])
        self.assertEqual(d['revision'], 0x25)
        self.assertEqual(len(d['personality_bytes']), 15)

    def test_all_supplied_samples_print_and_serialize(self):
        paths = list((ROOT / 'samples').rglob('*.bin'))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path):
                spd = load_spd_file(path)
                json.dumps(spd.decoded_data)
                with contextlib.redirect_stdout(io.StringIO()):
                    spd.decoder.pretty_print(spd.decoded_data, programmer_mode=True)

    def test_xmp_enabled_profiles_and_bad_timebase(self):
        from ddr3_xmp_decoder import decode_xmp
        raw = bytearray(ddr3());raw[176:184] = bytes.fromhex('0c 4a 01 12 01 08 01 08')
        raw[185:199] = bytes.fromhex('2a 0a 6e a0 00 50 6e 6e 78 11 18 86 00 00')
        raw[221] = 10
        decoded = decode_xmp(raw)
        self.assertEqual(len(decoded['xmp_profiles']), 1)
        self.assertEqual(decoded['xmp_profiles'][0]['voltage_V'], 1.5)
        self.assertEqual(decoded['xmp_profiles'][0]['timings'].split('-')[0], '11')
        raw[181] = 0
        self.assertNotIn('xmp_profiles', decode_xmp(raw))
        self.assertIsNone(decode_xmp(raw[:128]))


class IOTests(unittest.TestCase):
    def test_text_and_binary_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'image'
            for raw in (ddr2(), ddr3(), ddr3(128)):
                for content in (raw, raw.hex(' ').encode(),
                                '\n'.join(f'{i:04x}: ' + raw[i:i+16].hex(' ') + ' # comment' for i in range(0,len(raw),16)).encode()):
                    path.write_bytes(content)
                    self.assertEqual(load_spd_file(path).data, raw)
            path.write_text('deadbeef ' * 128)
            with self.assertRaises(ValueError): load_spd_file(path)

    def test_patch_preserves_length_and_repairs_checksum(self):
        args = SimpleNamespace(copy_range=['0:0', '27:29'])
        for fixture in (ddr2, ddr3):
            target = fixture()
            source = bytearray(target); source[0] ^= 128; source[27] ^= 1
            result = SPD(target).patch(SPD(source), args)
            self.assertEqual(len(result), len(target))
            self.assertEqual(integrity_info(result)['status'], 'VALID')
            self.assertEqual(result[0], source[0])
        with self.assertRaises(ValueError):
            SPD(ddr2()).patch(SPD(ddr3()), args)
        with self.assertRaises(ValueError):
            SPD(ddr3()).patch(SPD(ddr3(128)), SimpleNamespace(copy_partnum=True))
        with self.assertRaises(ValueError):
            SPD(ddr2()).patch(SPD(ddr2()), SimpleNamespace(copy_hpt=True))
        with self.assertRaises(ValueError):
            SPD(ddr2()).patch(SPD(ddr2()), SimpleNamespace(copy_range=['-1:5']))

    def test_editor_undo_redo_save_and_reopen(self):
        for fixture in (ddr2, ddr3):
            doc = EditorDocument(fixture())
            original = doc.spd.data
            doc.set_part_number('EDITED');doc.set_serial('A1B2C3D4')
            self.assertTrue(doc.dirty)
            doc.undo();doc.undo();self.assertEqual(doc.spd.data, original)
            doc.redo();doc.redo()
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / 'output.bin'
                doc.save(path)
                self.assertFalse(doc.dirty)
                reopened = load_spd_file(path)
                self.assertEqual(reopened.decoded_data['crc_info']['status'], 'VALID')
                self.assertEqual(reopened.decoded_data['manufacturing']['module_part_number'], 'EDITED')
                self.assertEqual(reopened.decoded_data['manufacturing']['serial_number'], 'A1B2C3D4')

    def test_editor_rejects_invalid_edits_and_failed_save(self):
        doc = EditorDocument(ddr3())
        for offset, value in ((256, b'\0'), (2, b'\x08'), (-1, b'\0')):
            with self.assertRaises(ValueError): doc.edit(offset, value)
        with self.assertRaises(ValueError): doc.set_part_number('X' * 19)
        doc.edit(16, b'\x70')
        before = doc.spd.data
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'output.bin';path.write_bytes(b'original')
            with patch('spd_editor.os.replace', side_effect=OSError('test')):
                with self.assertRaises(OSError): doc.save(path)
            self.assertEqual(path.read_bytes(), b'original')
            self.assertEqual(len(list(Path(temp).iterdir())), 1)
            self.assertEqual(doc.spd.data, before)
            self.assertTrue(doc.dirty)

    def test_cli_dump_diff_patch(self):
        with tempfile.TemporaryDirectory() as temp:
            a,b,out = [Path(temp) / name for name in ('a.bin','b.bin','out.bin')]
            a.write_bytes(ddr2(128));b.write_bytes(ddr2())
            def cli(*args):
                return subprocess.run([sys.executable, str(ROOT/'spd_tool.py'), *map(str,args)], capture_output=True, text=True)
            result = cli('dump','--spd',a,'--json','-')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['general']['memory_type'], 'DDR2 SDRAM')
            result=cli('diff','--file-a',a,'--file-b',b)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('--',result.stdout)
            result=cli('patch','--source',a,'--target',b,'--out',out,'--copy-partnum')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(integrity_info(out.read_bytes())['status'],'VALID')

    def test_catalog_and_hardware_integrity(self):
        from sort_spd import parse_ddr2, ddr3_crc_pair
        from spd_smbus import fix_base_crc
        self.assertEqual(parse_ddr2(ddr2())['serial_u32'],0x12345678)
        self.assertEqual(parse_ddr2(ddr2())['crc_status'],'ok')
        for raw in (ddr2(), ddr3(), ddr3(short=True)):
            changed=bytearray(raw);changed[27] ^= 1;fix_base_crc(changed)
            self.assertEqual(integrity_info(changed)['status'],'VALID')
        self.assertEqual(ddr3_crc_pair(ddr3())[2],'ok')


if __name__ == '__main__':
    unittest.main()
