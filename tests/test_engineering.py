# SPDX-License-Identifier: MIT
import copy,json,tempfile,unittest
from pathlib import Path
from spd_library import SPD,hexdiff
from spd_integrity import repair_integrity,integrity_info
from spd_native import native_timings,encode_native,promote_xmp
from spd_epp import encode_epp,decode_epp,duplicate_epp
from spd_compatibility import assess
from spd_merge import merge,replay,digest
from spd_fields import module_fields,edit_field
from spd_timing_analysis import configuration,schedule
from spd_settings import load,save
from spd_catalog import Catalog
from spd_xmp import encode_profile
from spd_timing_planner import plan_bins,evidence_template
from tests.test_spd import ddr2,ddr3,ROOT
from tests.test_registered import legacy,registered_ddr3


def udimm():
    data=bytearray(ddr2());data[20]=2;return repair_integrity(data)


def epp_profile():return dict(enabled=True,voltage_V='2.1',command_rate=2,cas=5,address_drive=2,cs_drive=1,clock_drive=3,data_drive=0,dqs_drive=1,address_delay=31,address_setup=1,cs_delay=12,cs_setup=0,timings_ns=dict(tCKmin='1.875',tRCDmin=15,tRPmin=15,tRASmin=45,tWRmin=15,tRCmin=60))


class NativeTests(unittest.TestCase):
    def test_four_generation_noop_preserves_exact_bytes(self):
        for data in (legacy(4),legacy(7),ddr2(),ddr3()):
            with self.subTest(generation=data[2]):self.assertEqual(encode_native(data,native_timings(data)),data)
    def test_primary_cycles_and_neighbor_preservation(self):
        for data,value,expected in [(legacy(4),21,21),(legacy(7),'15.1',61),(ddr2(),'15.1',61)]:
            result=encode_native(data,{'tRCDmin':value});self.assertEqual(result[29],expected)
            self.assertLessEqual({i for i,_,_ in hexdiff(data,result)},{29,63})
            self.assertEqual(integrity_info(result)['status'],'VALID')
    def test_ddr3_signed_fine_and_mtb_preservation(self):
        data=ddr3();result=encode_native(data,{'tCKmin':'1.071','tRCDmin':'13.751'},[13])
        d=SPD(result).decoded_data['timings_ns'];self.assertGreaterEqual(d['tCKmin'],1.071);self.assertLess(d['tCKmin'],1.0721)
        self.assertEqual(result[9:12],data[9:12]);self.assertEqual(result[117:126],data[117:126]);self.assertEqual(result[128:],data[128:]);self.assertEqual(integrity_info(result)['status'],'VALID')
    def test_ddr2_extended_refresh_and_cycle_encodings(self):
        data=ddr2();result=encode_native(data,{'tRFCmin':'300.33','tCKmin':'2.33'})
        self.assertEqual(result[9],0x2b);self.assertEqual(result[42],44);self.assertEqual(result[40]&15,5)
        self.assertEqual(SPD(result).decoded_data['timings_ns']['tRFCmin'],300.33)
    def test_legacy_cas_remaps_and_invalidates_lower_points(self):
        for data,cas,mask in [(legacy(4),[3],4),(legacy(7),[2.5],8),(ddr2(),[5],32)]:
            result=encode_native(data,{},cas);self.assertEqual(result[18],mask);self.assertEqual(result[23:27],bytes(4))
    def test_invalid_timing_and_cas_rejected(self):
        for timing in ({'tCKmin':0},{'tCKmin':10000},{'not_a_field':1},{'tRCmin':1}):
            with self.assertRaises(ValueError):encode_native(ddr3(),timing)
        with self.assertRaises(ValueError):encode_native(legacy(7),{},[4.5])
    def test_xmp_semantic_conversion_and_acknowledgment(self):
        profile=plan_bins(ddr3(),[1600])[0]['profile'];data=encode_profile(ddr3(),1,profile)
        with self.assertRaises(ValueError):promote_xmp(data,1)
        result,report=promote_xmp(data,1,True)
        self.assertEqual(result[176:],data[176:]);self.assertEqual(result[3:12],data[3:12]);self.assertEqual(result[117:126],data[117:126])
        self.assertEqual(SPD(result).decoded_data['timings_ns']['tCKmin'],1.25);self.assertIn('voltage',report['note'])
    def test_vintage_below_100_mhz_is_not_forced_into_ddr_bins(self):
        proposal=plan_bins(legacy(4),[66],voltage='3.3')[0]
        self.assertEqual(proposal['rate_MTps'],66);self.assertAlmostEqual(proposal['tCK_ns'],1000/66)

    def test_structured_fields_for_all_generations(self):
        for data in (legacy(4),legacy(7),ddr2(),ddr3()):
            self.assertGreater(len(module_fields(data)),15)
        result=edit_field(ddr2(),'rank_count',1);self.assertEqual(result[5]&7,1);self.assertEqual(result[5]&248,ddr2()[5]&248)
    def test_bundled_images_native_decode_encode_preserves_known_fields(self):
        count=0
        for path in (ROOT/'samples').rglob('*.bin'):
            data=path.read_bytes()
            try:SPD(data)
            except (ValueError,NotImplementedError):continue
            # Not every real dump has logically valid timing fields. Invalid images
            # must fail cleanly, rather than being presented as supported hardware.
            try:result=encode_native(data,native_timings(data))
            except ValueError:continue
            self.assertEqual(result[64:117],data[64:117]);self.assertEqual(result[128:],data[128:]);count+=1
        self.assertGreater(count,0)


class EPPTests(unittest.TestCase):
    def test_published_full_layout_and_special_clock(self):
        data=udimm();result=encode_epp(data,0,epp_profile())
        self.assertEqual(result[99:104],bytes.fromhex('6d 56 4e b1 10'))
        self.assertEqual(result[104:116],bytes.fromhex('8c 36 01 3f 0c 1e 20 3c 3c 2d 3c 3c'))
        self.assertEqual(result[:99],data[:99]);self.assertEqual(result[128:],data[128:])
        p=decode_epp(result)['profiles'][0];self.assertEqual(p['timings_ns']['tCKmin'],1.875);self.assertFalse(p['errors'])
        self.assertEqual(SPD(result).decoded_data['epp']['format'],'full')
    def test_abbreviated_all_four_slots_and_optimal(self):
        data=udimm()
        for i in range(4):data=encode_epp(data,i,epp_profile(),'abbreviated',optimal=i)
        parsed=decode_epp(data);self.assertEqual(parsed['optimal'],3);self.assertTrue(all(p['enabled'] for p in parsed['profiles']))
        self.assertEqual(data[103],0xf3)
    def test_duplicate_preserves_other_profile(self):
        data=encode_epp(udimm(),0,epp_profile());result=duplicate_epp(data,0,1)
        self.assertEqual(result[104:116],data[104:116]);self.assertEqual(result[116:128],data[104:116])
    def test_reserved_bits_preserved_when_editing(self):
        data=bytearray(encode_epp(udimm(),0,epp_profile()));data[106]|=0xfc;data[107]|=0xc0
        result=encode_epp(data,0,epp_profile());self.assertEqual(result[106]&252,252);self.assertEqual(result[107]&192,192)
    def test_replacement_and_format_switch_are_explicit(self):
        data=bytearray(udimm());data[99:103]=b'OEM!'
        with self.assertRaises(ValueError):encode_epp(data,0,epp_profile())
        data=encode_epp(data,0,epp_profile(),replace=True)
        with self.assertRaises(ValueError):encode_epp(data,0,epp_profile(),'abbreviated')
    def test_scope_and_encoding_validation(self):
        for data in (ddr3(),legacy(4),ddr2()):
            with self.assertRaises(ValueError):encode_epp(data,0,epp_profile())
        for key,value in [('voltage_V',2.51),('cas',7),('command_rate',3),('address_delay',32)]:
            p=epp_profile();p[key]=value
            with self.assertRaises(ValueError):encode_epp(udimm(),0,p)
        with self.assertRaises(ValueError):encode_epp(udimm(),0,epp_profile(),optimal=1)
        p=epp_profile();p['timings_ns']['tRCmin']=50
        with self.assertRaises(ValueError):encode_epp(udimm(),0,p)
    def test_bad_voltage_and_reserved_cas_detected(self):
        data=bytearray(encode_epp(udimm(),0,epp_profile()));data[104]=127;data[110]=0x21
        self.assertGreaterEqual(len(decode_epp(data)['profiles'][0]['errors']),2)


class CompatibilityMergeTests(unittest.TestCase):
    def test_generation_geometry_and_architecture_cannot_be_overridden(self):
        for donor in (ddr2(),registered_ddr3()):
            r=assess(donor,ddr3(),overrides={'hardware_equivalence':'test'});self.assertFalse(r['allowed']);self.assertEqual(r['classification'],'Incompatible')
        donor=bytearray(ddr3());donor[7]^=8;donor=repair_integrity(donor)
        self.assertFalse(assess(donor,ddr3(),overrides={'hardware_equivalence':'test'})['allowed'])
    def test_timing_variance_metadata_allowed_timing_scoped(self):
        donor=encode_native(ddr3(),{'tRCDmin':14})
        self.assertEqual(assess(donor,ddr3())['classification'],'Hardware-equivalent')
        self.assertTrue(assess(donor,ddr3())['allowed']);self.assertFalse(assess(donor,ddr3(),'timing')['allowed'])
        self.assertTrue(assess(donor,ddr3(),'timing',{'timing':'tested at target clock'})['allowed'])
    def test_register_substitution_requires_equivalence_only_for_controls(self):
        target=registered_ddr3();donor=bytearray(target);donor[65]^=1;donor=repair_integrity(donor)
        self.assertTrue(assess(donor,target)['allowed']);self.assertFalse(assess(donor,target,'register')['allowed'])
        self.assertTrue(assess(donor,target,'register',{'register_equivalence':'same documented IC function'})['allowed'])
        donor=bytearray(target);donor[68]=1;donor=repair_integrity(donor)
        self.assertFalse(assess(donor,target,'register',{'register_equivalence':'override'})['allowed'])
    def test_part_mismatch_is_conditional(self):
        donor=bytearray(ddr3());donor[128]=ord('X')
        self.assertEqual(assess(donor,ddr3())['classification'],'Conditional match')
        self.assertTrue(assess(donor,ddr3(),overrides={'hardware_equivalence':'observed chips/PCB match'})['allowed'])
    def test_single_field_and_identity_protection_all_generations(self):
        for target in (legacy(4),legacy(7),ddr2(),ddr3()):
            off=119 if target[2]==11 else 72;donor=bytearray(target);donor[off]=5;donor=repair_integrity(donor)
            with self.assertRaises(ValueError):merge(target,[dict(data=donor,keys=['location'])])
            result=merge(target,[dict(data=donor,keys=['location'],overrides={'identity':'confirmed factory location'})])
            self.assertEqual(result['data'][off],5);self.assertEqual(result['data'][95:99],target[95:99]);self.assertFalse(result['conflicts'])
    def test_conflicting_multiple_donors_require_resolution_and_replay(self):
        target=ddr3();a=bytearray(target);b=bytearray(target);a[150]=1;b[150]=2
        selections=[dict(data=bytes(x),keys=['manufacturer_payload'],overrides={'opaque':'reviewed vendor block'}) for x in (a,b)]
        result=merge(target,selections);self.assertIsNone(result['data']);self.assertTrue(result['conflicts'])
        choices={f"{c['offset']}:{c['bit']}":digest(a) for c in result['conflicts']}
        result=merge(target,selections,choices);self.assertEqual(result['data'][150],1)
        self.assertEqual(replay(target,result['recipe'],{digest(a):bytes(a),digest(b):bytes(b)})['data'],result['data'])
        with self.assertRaises(ValueError):replay(bytes(a),result['recipe'],{})
    def test_semantic_native_transfer_and_hpt_dependency(self):
        target=ddr3();donor=encode_native(target,{'tRCDmin':14})
        with self.assertRaises(ValueError):merge(target,[dict(data=donor,keys=['native_timings'])])
        result=merge(target,[dict(data=donor,keys=['native_timings'],overrides={'timing':'tested complete timing set'})])
        self.assertEqual(SPD(result['data']).decoded_data['timings_ns']['tRCDmin'],14)
        donor=bytearray(target);donor[176:184]=b'HPT\0abcd'
        with self.assertRaisesRegex(ValueError,'Serial-bound'):merge(target,[dict(data=donor,keys=['customer_payload'],overrides={'opaque':'reviewed'})])
    def test_xmp_transfer_requires_timing_review(self):
        target=ddr3();donor=encode_profile(target,1,plan_bins(target,[1600])[0]['profile'])
        with self.assertRaisesRegex(ValueError,'timing review'):merge(target,[dict(data=donor,keys=['customer_payload'],overrides={'opaque':'reviewed'})])
    def test_catalog_recipe_and_immutable_refresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source.bin';source.write_bytes(ddr3());cat=Catalog(root/'collection');cat.import_files([source])
            target=ddr3();donor=bytearray(target);donor[150]=1
            r=merge(target,[dict(data=donor,keys=['manufacturer_payload'],overrides={'opaque':'reviewed'})]);bundle=dict(recipe=r['recipe'],sources={digest(donor):bytes(donor).hex()})
            key=cat.save_recipe('Test',bundle);self.assertEqual(Catalog(cat.root).recipes()[0]['id'],key)
            source.write_bytes(bytes(donor));cat.refresh_sources();self.assertEqual(len(cat.rows()),2)
            self.assertEqual(cat.data(digest(target)),target);cat.refresh_sources();self.assertEqual(len(cat.rows()),2)


class TimingSettingsTests(unittest.TestCase):
    def test_all_generations_and_native_cas_anchor(self):
        for data in (legacy(4),legacy(7),ddr2(),ddr3()):
            c=configuration(data);r=schedule(data[2],c['parameters']);self.assertTrue(r['events'])
            if data[2]!=11:self.assertEqual(c['parameters']['CL'],max(SPD(data).decoded_data['cas_latencies_supported']))
            for event in r['events']:self.assertAlmostEqual(event['ns'],event['cycle']*c['parameters']['tCK'])
    def test_dependencies_and_rolling_activation_window(self):
        p=dict(tCK=2,CL=5,tRCD=10,tRP=10,tRAS=30,tRC=40,tRFC=100,tRRD=4,tFAW=24,tWR=10,tRTP=4,tWTR=4,tCWL=8,tCCD=4,tREFI=7800)
        r=schedule(11,p);acts=[e for e in r['events'] if e['lane']=='ACT / bank sweep'];self.assertEqual(acts[4]['cycle'],12)
        pre=next(e for e in r['events'] if e['command']=='PRE' and e['lane']=='Write / same bank');self.assertGreaterEqual(pre['cycle'],5+4+2+5)
        p['tRC']=20;self.assertTrue(schedule(11,p)['violations'])
    def test_four_bank_activation_sweep_precharges_before_reuse(self):
        p=dict(tCK=2,CL=5,tRCD=10,tRP=10,tRAS=30,tRC=40,tRFC=100,tRRD=4,tFAW=24)
        r=schedule(8,p,bank_count=4);sweep=[e for e in r['events'] if e['lane']=='ACT / bank sweep']
        self.assertEqual(sweep[-2]['command'],'PRE B0');self.assertEqual(sweep[-1]['command'],'ACT B0')
        self.assertGreaterEqual(sweep[-1]['cycle']-sweep[-2]['cycle'],5);self.assertGreaterEqual(sweep[-1]['cycle'],20)

    def test_missing_constraints_do_not_fabricate_commands(self):
        c=configuration(legacy(4));r=schedule(4,c['parameters'])
        self.assertIn('tRFC',r['missing']);self.assertFalse(any(e['command']=='REF' for e in r['events']))
        self.assertFalse(any(w['name']=='tFAW' for w in r['windows']))
    def test_settings_roundtrip_corruption_and_invalid_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'prefs.json';self.assertEqual(load(path),{})
            save(dict(catalog_path='/missing',autoload=True,filters={'memory':'DDR2'},sort='Model'),path)
            self.assertEqual(load(path)['filters']['memory'],'DDR2')
            path.write_text('{');self.assertEqual(load(path),{})
            path.write_text(json.dumps(dict(version=1,catalog_path=[])));self.assertEqual(load(path),{})
    def test_invalid_operating_parameters(self):
        for p in (dict(tCK=0),dict(tCK=float('nan')),dict(tCK=1,tRCD=-1)):
            with self.assertRaises(ValueError):schedule(11,p)
