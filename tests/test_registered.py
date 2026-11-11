import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from spd_library import SPD
from spd_editor import EditorDocument
from spd_fields import module_fields, field_by_key, edit_field, registered_warnings
from spd_integrity import repair_integrity, integrity_info
from tests.test_spd import ddr3, ROOT


def registered_ddr3(lrdimm=False, short=False):
    d=bytearray(ddr3(short=short));d[3]=11 if lrdimm else 1
    d[63]=0x89 if lrdimm else 0x0A
    d[64]=0x21 if lrdimm else 0x80
    d[65:67]=bytes.fromhex('04 b3')
    d[67]=0 if lrdimm else 0x33
    d[68]=0
    if lrdimm:
        d[67:72]=bytes.fromhex('50 55 e4 a5 b6')
        d[72:90]=bytes.fromhex('15 12 34 56 78 49 23 11 22 33 44 8d 31 21 43 65 87 10')
        d[90:96]=bytes((32,48,40,56,48,64))
        d[102:117]=bytes.fromhex('10 32 54 76 98 ba dc fe 10 32 54 98 ba dc fe')
    else:
        d[70:72]=bytes.fromhex('50 55')
    return repair_integrity(d)


def legacy(mem=4,length=256,registered=True):
    d=bytearray(length)
    values={0:128,1:8,2:mem,3:13,4:10,5:2,6:72,8:1 if mem==4 else 4,
            9:0x75 if mem==4 else 0x50,10:0x54 if mem==4 else 0x60,
            11:2,12:0x80,13:8,14:8,15:1,16:0x8F,17:4,
            18:6 if mem==4 else 0x1C,19:1,20:1,21:0x16 if registered else 0,22:0x0E,
            23:0xA0 if mem==4 else 0x60,24:0x60,25:0 if mem==4 else 0x75,
            26:0 if mem==4 else 0x75,27:20 if mem==4 else 60,28:15 if mem==4 else 40,
            29:20 if mem==4 else 60,30:45 if mem==4 else 40,31:0x40,
            32:0x15,33:0x08,34:0x15,35:0x08,41:55 if mem==7 else 0,
            42:70 if mem==7 else 0,43:0x50 if mem==7 else 0,
            62:0x12,64:0x7F,65:0x98,93:0x98,94:0x42}
    for off,value in values.items():d[off]=value
    d[73:91]=b'REGISTERED-LEGACY '
    d[95:99]=bytes.fromhex('12345678')
    return repair_integrity(d)


class RegisteredTests(unittest.TestCase):
    def test_rdimm_drive_mapping_and_runtime_fields(self):
        data=registered_ddr3()
        self.assertEqual(field_by_key(data,'ca_a').raw(data),1)
        self.assertEqual(field_by_key(data,'ca_b').raw(data),1)
        changed=edit_field(data,'ca_b',2)
        self.assertEqual(changed[70],0x90)
        changed=edit_field(changed,'rc0_inversion',1)
        self.assertEqual(changed[69],1)
        changed=edit_field(changed,'rc1_disable_y3',1)
        self.assertEqual(changed[69],0x81)
        changed=edit_field(changed,'rc2_ibt',1)
        self.assertEqual(changed[70],0x94)
        changed=edit_field(changed,'rc10_speed',4)
        changed=edit_field(changed,'rc11_voltage',2)
        self.assertEqual(changed[74],0x24)
        self.assertTrue(any('RC0' in w for w in registered_warnings(changed)))
        self.assertEqual(field_by_key(data,'RC3').value(data),5)
        self.assertIn('Inphi',SPD(data).decoded_data['registered_info']['mfg_id'])

    def test_personality_byte_105_crosses_functions(self):
        data=registered_ddr3(True)
        self.assertEqual(field_by_key(data,'F14RC6').offset,105)
        self.assertEqual(field_by_key(data,'F15RC6').offset,105)
        changed=edit_field(data,'F15RC6',0xB)
        self.assertEqual(changed[105],0xB6)
        self.assertEqual(changed[104],data[104])
        self.assertEqual(changed[106],data[106])
        changed=edit_field(changed,'F15RC15',3)
        self.assertEqual(changed[116],0x3E)

    def test_lrdimm_odt_masks_all_speeds(self):
        data=registered_ddr3(True)
        for band,base in (('800_1066',72),('1333_1600',78),('1866_2133',84)):
            for rank in range(8):
                for mode,shift in (('read',0),('write',4)):
                    for line in range(2):
                        key=f'{band}.rank{rank}.{mode}.odt{line}'
                        changed=bytearray(data);changed[base+1+rank//2]=0
                        result=edit_field(changed,key,1)
                        self.assertEqual(result[base+1+rank//2],1<<(shift+2*(rank%2)+line))
            changed=edit_field(data,f'{band}.rtt_nom',5)
            self.assertEqual(changed[base+5]&0x1C,0x14)
            self.assertEqual(changed[base+5]&~0x1C,data[base+5]&~0x1C)

    def test_delays_reserved_and_exact_units(self):
        data=registered_ddr3(True)
        self.assertEqual(field_by_key(data,'ext_delay_cke').display(data),'3/128 tCK')
        changed=edit_field(data,'delay_1.35_min','5.125')
        self.assertEqual(changed[92],41)
        with self.assertRaises(ValueError):edit_field(data,'delay_1.35_min','5.13')
        with self.assertRaises(ValueError):edit_field(data,'800_1066.mdq_odt',4)
        with self.assertRaises(ValueError):edit_field(data,'F15RC6',16)
        with self.assertRaises(ValueError):edit_field(data,'F15RC6',-1)
        with self.assertRaises(ValueError):edit_field(data,'F15RC6','NaN')
        changed=bytearray(data);changed[10:12]=bytes((1,15))
        result=edit_field(changed,'delay_1.5_min','1/3')
        self.assertEqual(result[90],5)

    def test_each_legal_field_preserves_neighbors(self):
        for data in (registered_ddr3(),registered_ddr3(True),legacy(4),legacy(7)):
            for f in module_fields(data):
                values=f.choices.keys() if f.choices else (0,f.maximum)
                for value in values:
                    from fractions import Fraction
                    physical=str(Fraction(value)*Fraction(str(f.scale)))
                    result=edit_field(data,f.key,physical)
                    expected_offsets={f.offset}
                    self.assertTrue(all(a==b for i,(a,b) in enumerate(zip(data,result)) if i not in expected_offsets),f.key)
                    mask=f.maximum<<f.shift
                    if f.key not in ('device_mfg_bank','device_mfg_code'):
                        self.assertEqual(result[f.offset]&~mask,data[f.offset]&~mask,f.key)
                    self.assertEqual(f.raw(result),value,f.key)

    def test_manufacturer_parity(self):
        data=registered_ddr3()
        changed=edit_field(data,'device_mfg_bank',0)
        self.assertEqual(changed[65],0x80)
        changed=edit_field(changed,'device_mfg_code',0x17)
        self.assertEqual(changed[66],0x97)
        self.assertIn('Texas',SPD(changed).decoded_data['registered_info']['mfg_id'])

    def test_family_and_revision_gating(self):
        with self.assertRaises(ValueError):edit_field(ddr3(),'RC3',5)
        with self.assertRaises(ValueError):edit_field(registered_ddr3(),'F15RC6',5)
        unknown=bytearray(registered_ddr3());unknown[68]=1
        self.assertNotIn('RC3',{f.key for f in module_fields(unknown)})
        self.assertIn('raw70_high',{f.key for f in module_fields(unknown)})
        early=bytearray(registered_ddr3(True));early[1]=5
        self.assertNotIn('F15RC6',{f.key for f in module_fields(early)})

    def test_register_save_reopen_both_crc_coverages(self):
        for lrdimm in (False,True):
            for short in (False,True):
                doc=EditorDocument(registered_ddr3(lrdimm,short))
                key='F15RC6' if lrdimm else 'ca_a'
                doc.set_module_field(key,0)
                self.assertTrue(doc.dirty)
                doc.undo();self.assertFalse(doc.dirty)
                doc.redo()
                with tempfile.TemporaryDirectory() as temp:
                    path=Path(temp)/'edited.bin';doc.save(path)
                    raw=path.read_bytes()
                    self.assertEqual(integrity_info(raw)['status'],'VALID')
                    self.assertEqual(field_by_key(raw,key).raw(raw),0)
                    self.assertEqual(raw[176:],registered_ddr3(lrdimm,short)[176:])

    def test_copy_settings_checks_type_and_preserves_identity(self):
        doc=EditorDocument(registered_ddr3(True))
        source=bytearray(doc.spd.data);source[70]=0xA7
        before=doc.spd.data
        doc.copy_module_settings(source)
        self.assertEqual(doc.spd.data[70],0xA7)
        self.assertEqual(doc.spd.data[117:126],before[117:126])
        self.assertEqual(doc.spd.data[128:],before[128:])
        with self.assertRaises(ValueError):doc.copy_module_settings(registered_ddr3())

    def test_hp_matching_does_not_enumerate_and_uses_byte_order(self):
        doc=EditorDocument(registered_ddr3())
        doc.set_serial('00000003');doc.set_hpt('00000007')
        registry={'test':dict(A='0x00000002',B='0x00000001',K='0x0000000D',name='Test family')}
        self.assertEqual(doc.hp_info(registry)['matches'][0]['name'],'Test family')
        self.assertEqual(doc.hpt_candidates('test',registry),['00000007'])
        doc.set_serial('00000004')
        self.assertFalse(doc.hp_info(registry)['matches'])
        self.assertEqual(doc.hpt_candidates('test',registry),['00000005'])
        self.assertEqual(doc.spd.data[180:184],bytes.fromhex('00000007'))
        bad={'test':dict(A='0x1',B='0x80000000',K='0x0')}
        with self.assertRaises(ValueError):doc.hpt_candidates('test',bad)
        with self.assertRaises(ValueError):EditorDocument(legacy()).set_hpt('00000000')

    def test_cli_typed_edits(self):
        with tempfile.TemporaryDirectory() as temp:
            a=Path(temp)/'a.bin';out=Path(temp)/'out.bin';a.write_bytes(registered_ddr3(True))
            result=subprocess.run([sys.executable,str(ROOT/'spd_tool.py'),'edit','--spd',str(a),'--out',str(out),
                                   '--set','F15RC6=0xA','--set','800_1066.rtt_nom=3'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(out.read_bytes()[105]>>4,10)
            self.assertEqual(out.read_bytes()[77]&28,12)
            self.assertEqual(integrity_info(out.read_bytes())['status'],'VALID')
            result=subprocess.run([sys.executable,str(ROOT/'spd_tool.py'),'fields','--spd',str(a),'--expert'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            fields=json.loads(result.stdout)
            self.assertIn('F15RC6',{f['key'] for f in fields})


class LegacyTests(unittest.TestCase):
    def test_sdr_and_ddr_registered_decode(self):
        for mem in (4,7):
            decoded=SPD(legacy(mem)).decoded_data
            self.assertTrue(decoded['registered_info']['registered'])
            self.assertTrue(decoded['registered_info']['pll'])
            self.assertTrue(decoded['registered_info']['attributes']['registered_dqmb'])
            self.assertEqual(decoded['data_width_bits'],64)
            self.assertEqual(decoded['ecc_bits'],8)
            self.assertEqual(decoded['module_size_MiB'],512)
            self.assertIn('Kingston',decoded['manufacturing']['module_mfg_id'])
            self.assertEqual(decoded['manufacturing']['manufacture_date'],'98-W42')
            self.assertEqual(decoded['crc_info']['status'],'VALID')
            self.assertEqual(decoded['derived']['profiles'][0]['CL'],3)
            json.dumps(decoded)
            with contextlib.redirect_stdout(io.StringIO()):SPD(legacy(mem)).decoder.pretty_print(decoded,True)

    def test_ddr_half_cas_and_quarter_timings(self):
        d=SPD(legacy(7)).decoded_data
        self.assertEqual([p['CL'] for p in d['derived']['profiles']],[3,2.5,2])
        self.assertEqual(d['derived']['profiles'][1]['tCK_ns'],6)
        self.assertEqual(d['timings_ns']['tRPmin'],15)
        self.assertEqual(d['timings_ns']['tACmax'],.6)
        self.assertEqual(d['max_data_rate_MTps'],400)
        self.assertEqual(d['timings_ns']['tCKmax'],20)

    def test_sdr_no_extrapolated_cas_and_ceil_cycles(self):
        d=SPD(legacy()).decoded_data
        self.assertEqual([p['CL'] for p in d['derived']['profiles']],[3,2])
        self.assertEqual(d['derived']['profiles'][0]['tRP'],3)
        self.assertEqual(d['timings_ns']['tACmax'],5.4)
        self.assertEqual(d['max_data_rate_MTps'],133)
        raw=bytearray(legacy());raw[25:27]=bytes((60,24));raw[18]=7
        self.assertEqual(SPD(raw).decoded_data['derived']['profiles'][2]['tCK_ns'],15)

    def test_infineon_published_registered_sdr_vectors(self):
        # Manufacturer table, HYS72Vxx3xxGR, June 2001, pages 13-14.
        # Seven published configurations and stored checksums, independent of
        # repair_integrity, also cover x4 checking devices and 1 GiB rank codes.
        base=bytearray.fromhex('80 08 04 0c 0a 01 48 00 01 75 54 02 80 04 04 01 8f 04 06 01 01 1f 0e a0 60 00 00 14 0f 14 2d 20 15 08 15 08')
        variants=[(12,10,1,0x80,4,0x8F,0x20,0xC8,128),
                  (12,10,1,0x80,8,0x0F,0x20,0x50,128),
                  (12,11,1,0x80,4,0x0F,0x40,0x69,256),
                  (13,10,1,0x82,8,0x0F,0x40,0x73,256),
                  (13,11,1,0x82,4,0x0F,0x80,0xAC,512),
                  (13,11,2,0x82,4,0x0F,0x80,0xAD,1024),
                  (13,12,2,0x82,4,0x0F,0x01,0x2F,2048)]
        for row,col,ranks,refresh,device,burst,density,checksum,size in variants:
            raw=bytearray(128);raw[:36]=base
            for off,value in {3:row,4:col,5:ranks,12:refresh,13:device,14:device,16:burst,31:density,62:2,63:checksum,126:0x64,127:0x8F}.items():raw[off]=value
            decoded=SPD(raw).decoded_data
            self.assertEqual(decoded['crc_info']['status'],'VALID')
            self.assertEqual(decoded['module_size_MiB'],size)
            self.assertEqual(decoded['addressing_module_size_MiB'],size)
            self.assertTrue(decoded['registered_info']['registered'])
            self.assertTrue(decoded['registered_info']['pll'])
            self.assertEqual(decoded['ecc_bits'],8)

    def test_high_density_vintage_modules(self):
        for mem in (4,7):
            raw=bytearray(legacy(mem));raw[3]=15;raw[31]=1
            self.assertEqual(SPD(raw).decoded_data['module_size_MiB'],2048)
        raw=bytearray(legacy());raw[3]=7;raw[31]=1
        # Too-small/invalid geometry doesn't corroborate the extended density code.
        self.assertEqual(SPD(raw).decoded_data['module_size_MiB'],8)

    def test_legacy_edit_save_patch_catalog(self):
        from sort_spd import parse_sdr,parse_ddr1
        for mem in (4,7):
            doc=EditorDocument(legacy(mem,128))
            doc.set_module_field('registered_address',0)
            self.assertEqual(doc.spd.data[21],0x14)
            doc.set_part_number('VINTAGE-EDIT')
            doc.set_serial('DEADBEEF')
            doc.repair()
            self.assertEqual(doc.spd.decoded_data['manufacturing']['module_part_number'],'VINTAGE-EDIT')
            meta=(parse_sdr if mem==4 else parse_ddr1)(doc.spd.data)
            self.assertEqual(meta['crc_status'],'ok')
            self.assertIsNone(meta['stored_crc_ext'])
            self.assertEqual(meta['serial_u32'],0xDEADBEEF)
            source=bytearray(legacy(mem,128));source[73:91]=b'DONOR             '
            result=SPD(doc.spd.data).patch(SPD(source),SimpleNamespace(copy_partnum=True,force=True))
            self.assertEqual(result[73:91],source[73:91])
            self.assertEqual(integrity_info(result)['status'],'VALID')

    def test_buffered_detection_and_invalid_profiles(self):
        raw=bytearray(legacy());raw[21]=1
        self.assertTrue(SPD(raw).decoded_data['registered_info']['buffered'])
        self.assertFalse(SPD(raw).decoded_data['registered_info']['registered'])
        raw[9]=0;raw[23]=0;raw[18]=0
        self.assertEqual(SPD(raw).decoded_data['derived']['profiles'],[])
        self.assertTrue(SPD(raw).decoded_data['warnings'])


if __name__=='__main__':unittest.main()
