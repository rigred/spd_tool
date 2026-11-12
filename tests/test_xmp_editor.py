# SPDX-License-Identifier: MIT
from fractions import Fraction
import copy
import hashlib
import unittest
from spd_xmp import encode_profile,read_profile,quantize
from spd_timing_planner import plan_bins,evidence_template
from ddr3_xmp_decoder import decode_xmp
from tests.test_spd import ddr3,ddr2
from tests.test_registered import legacy


class XMPAuthoringTests(unittest.TestCase):
    def profile(self,rate=1600):return plan_bins(ddr3(),[rate])[0]['profile']

    def test_custom_fine_timebase_quantization(self):
        count,fine,actual=quantize(Fraction(1,10),Fraction(1,255),Fraction(15,1000),8)
        self.assertEqual(actual,Fraction(1,10))
        self.assertEqual(count,102);self.assertEqual(fine,-20)

    def test_generated_1600_profile_independent_byte_expectations(self):
        raw=ddr3();new=encode_profile(raw,1,self.profile())
        self.assertEqual(new[:176],raw[:176])
        self.assertEqual(new[176:185],bytes.fromhex('0c 4a 01 13 01 08 01 08 11'))
        self.assertEqual(new[185],0x2A)
        self.assertEqual(new[186],10)
        self.assertEqual(new[187],110)
        self.assertEqual(new[188:190],b'\x80\0') # CL11 only
        self.assertEqual(new[194:197],bytes([0x11,24,134])) # 280/390 MTB
        self.assertEqual(int.from_bytes(new[197:199],'little'),62)
        parsed=read_profile(new,1)
        self.assertEqual(parsed['timings_ns']['tCKmin'],1.25)
        self.assertEqual(parsed['encoded_max_rate_MTps'],1600)
        self.assertEqual(parsed['timings_ns']['tREFI'],7750)

    def test_fine_offsets_and_profiles_preserve_neighbors(self):
        raw=encode_profile(ddr3(),1,self.profile())
        raw=bytearray(raw);raw[219]=0xA5;raw[255]=0xCC
        new=encode_profile(raw,2,self.profile(1866))
        self.assertEqual(new[185:220],raw[185:220])
        self.assertEqual(new[255],0xCC)
        parsed=read_profile(new,2)
        self.assertGreaterEqual(parsed['timings_ns']['tCKmin'],2000/1866)
        self.assertLess(parsed['timings_ns']['tCKmin']-2000/1866,.0011)
        self.assertNotEqual(new[246],0)
        self.assertEqual(len(decode_xmp(new)['xmp_profiles']),2)
        edited=read_profile(new,1);edited['enabled']=False
        result=encode_profile(new,1,edited)
        self.assertEqual(result[220:255],new[220:255]);self.assertFalse(result[178]&1)

    def test_signed_fine_and_global_timebase_decode_vector(self):
        raw=bytearray(encode_profile(ddr3(),1,self.profile()))
        raw[186]=9;raw[211]=(-54)&255 # 9*125ps - 54ps = 1.071ns
        raw[212]=(-1)&255
        detail=decode_xmp(raw)['xmp_profiles_detailed'][0]
        self.assertEqual(detail['timings_ns']['tCKmin'],1.071)
        self.assertEqual(detail['timings_ns']['tAAmin'],13.749)
        raw[184]=0
        self.assertNotIn('xmp_profiles',decode_xmp(raw))

    def test_overlapping_hp_and_field_overflows_are_not_silent(self):
        raw=bytearray(ddr3());raw[176:184]=b'HPT\0abcd'
        with self.assertRaisesRegex(ValueError,'Customer'):encode_profile(raw,1,self.profile())
        new=encode_profile(raw,1,self.profile(),True)
        self.assertEqual(new[:176],raw[:176]);self.assertEqual(new[176:178],b'\x0c\x4a')
        for mutation in [dict(cas_latencies=[19]),dict(voltage_V='1.51'),dict(mtb_divisor=0)]:
            p=self.profile();p.update(mutation)
            with self.assertRaises(ValueError):encode_profile(ddr3(),1,p)
        p=self.profile();p['timings_ns']['tRFCmin']=100000
        with self.assertRaises(ValueError):encode_profile(ddr3(),1,p)
        with self.assertRaises(ValueError):encode_profile(ddr3()[:128],1,self.profile())

    def test_older_profile_revision_and_reserved_bytes_preserved(self):
        raw=bytearray(encode_profile(ddr3(),1,self.profile()));raw[179]=0x12
        raw[211]=0x82;raw[216:219]=b'XYZ';raw[203]|=0xA0
        p=read_profile(raw,1)
        result=encode_profile(raw,1,p)
        self.assertEqual(result,raw)


class TimingPlannerTests(unittest.TestCase):
    def test_forward_clock_conserves_time_not_constant_cycles(self):
        rows=plan_bins(ddr3(),[1600,1866,2133])
        self.assertEqual([r['cycles']['tAAmin'] for r in rows],[11,13,15])
        for row in rows:
            self.assertEqual(row['timings_ns']['tREFI'],7800)
            self.assertIsNotNone(row['profile'])
            self.assertTrue(row['warnings'])
        fast=plan_bins(ddr3(),[4000])[0]
        self.assertIsNone(fast['profile'])
        for raw in [ddr2(),legacy(4),legacy(7)]:
            row=plan_bins(raw,[200])[0]
            self.assertIsNone(row['profile'])
            self.assertEqual(row['clock_MHz'],200 if raw[2]==4 else 100)

    def test_datasheet_nck_floors_refresh_max_and_explicit_anchor(self):
        raw=ddr3();e=evidence_template(raw)
        e['datasheet']=dict(reference='Chip datasheet rev A p42',chip_part_number='TEST-CHIP',
                            timings={'tAAmin':{'min_ns':12},'tRRDmin':{'min_ns':5,'min_cycles':6},'tREFI':{'max_ns':3900}})
        conservative=plan_bins(raw,[1600],evidence=e)[0]
        refined=plan_bins(raw,[1600],evidence=e,datasheet_anchor=True)[0]
        self.assertEqual(conservative['cycles']['tAAmin'],11)
        self.assertEqual(refined['cycles']['tAAmin'],10)
        self.assertEqual(refined['cycles']['tRRDmin'],6)
        self.assertEqual(refined['timings_ns']['tREFI'],3900)
        e['datasheet']['max_rate_MTps']=1600
        fast=plan_bins(raw,[1866],evidence=e)[0]
        self.assertTrue(fast['violations']);self.assertIsNone(fast['profile'])

    def test_tested_anchor_failed_tests_and_evidence_scope(self):
        raw=ddr3();e=evidence_template(raw)
        e['tested_points']=[dict(rate_MTps=1866,voltage_V=1.5,timings_cycles={'tAAmin':12},reference='Memtest log',passed=True)]
        row=plan_bins(raw,[1866],evidence=e,anchor_index=0)[0]
        self.assertEqual(row['cycles']['tAAmin'],12)
        self.assertEqual(row['anchor'],'user-reported tested input')
        self.assertIn('Untested proposal',row['warnings'][0])
        with self.assertRaises(ValueError):plan_bins(raw,[1866],voltage=1.65,evidence=e,anchor_index=0)
        with self.assertRaises(ValueError):plan_bins(raw[:-1]+b'X',[1866],evidence=e)
        e['tested_points'][0]['passed']=False
        row=plan_bins(raw,[1866],evidence=e)[0];self.assertTrue(row['violations'])
        with self.assertRaises(ValueError):plan_bins(raw,[1866],evidence=e,anchor_index=0)

    def test_evidence_input_validation(self):
        raw=ddr3();e=evidence_template(raw)
        e['datasheet']['timings']={'tREFI':{'min_ns':9000}}
        with self.assertRaises(ValueError):plan_bins(raw,[1600],evidence=e)
        for invalid in ['nan',0,-1]:
            with self.assertRaises(ValueError):plan_bins(raw,[invalid])
