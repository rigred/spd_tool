# SPDX-License-Identifier: MIT
import copy,unittest
from tests.test_spd import ddr3
from tests.test_engineering import udimm,epp_profile
from spd_timing_planner import plan_bins,evidence_template
from spd_profile_validation import validate_xmp,generate_xmp_at_rate
from spd_xmp import encode_profile,read_profile
from spd_native import encode_native
from spd_epp import encode_epp


class ProfileValidationTests(unittest.TestCase):
    def profile(self):return plan_bins(ddr3(),[1600])[0]['profile']
    def test_screenshot_conflict_is_field_specific_and_has_clock_envelope(self):
        p=self.profile();p['cas_latencies']=[6,10];p['timings_ns'].update(tCKmin=.833,tAAmin=9.113)
        report=validate_xmp(ddr3(),1,p)
        self.assertFalse(report['logical_valid']);self.assertFalse(report['errors'])
        self.assertIn('Needs CL ≥ 11',report['warnings']['cas_latencies'][0]);self.assertIn('tCKmin',report['warnings']);self.assertIn('tAAmin',report['warnings'])
        envelope=report['clock_envelope'];self.assertAlmostEqual(envelope['min_tCK_ns'],.912);self.assertLess(envelope['max_rate_MTps'],2400)
    def test_quantization_and_multiple_unencodable_fields_reported_together(self):
        p=self.profile();p['timings_ns']['tCKmin']='garbage';p['timings_ns']['tRFCmin']=999999;p['voltage_V']='1.62';p['cas_latencies']=[19]
        report=validate_xmp(ddr3(),1,p)
        self.assertTrue({'tCKmin','tRFCmin','voltage_V','cas_latencies'}<=report['errors'].keys())
    def test_current_profile_generation_repairs_cas_at_chosen_speed(self):
        p=self.profile();p['cas_latencies']=[6,10];p['timings_ns'].update(tCKmin=.833,tAAmin=9.113)
        result,lineage=generate_xmp_at_rate(ddr3(),1,p,2400)
        self.assertEqual(result['cas_latencies'],[11]);encoded=encode_profile(ddr3(),1,result);actual=read_profile(encoded,1)
        self.assertLessEqual(actual['encoded_max_rate_MTps'],2400);self.assertGreater(actual['encoded_max_rate_MTps'],2390)
        self.assertEqual(lineage['classification'],'extrapolated; untested')
        self.assertGreaterEqual(actual['timings_ns']['tRCmin']+1e-6,actual['timings_ns']['tRASmin']+actual['timings_ns']['tRPmin'])
    def test_current_profile_uses_its_mtb_and_preserves_refresh(self):
        p=self.profile();p['mtb_dividend']=1;p['mtb_divisor']=10
        result,lineage=generate_xmp_at_rate(ddr3(),1,p,1866)
        self.assertEqual(result['mtb_divisor'],10);self.assertEqual(result['timings_ns']['tREFI'],p['timings_ns']['tREFI'])
    def test_spd_generation_honors_evidence_limit(self):
        evidence=evidence_template(ddr3());evidence['datasheet'].update(reference='manual input',chip_part_number='test',max_rate_MTps=1600)
        with self.assertRaisesRegex(ValueError,'datasheet'):generate_xmp_at_rate(ddr3(),1,self.profile(),2133,evidence)
    def test_spd_generation_can_explicitly_override_supplied_speed_limit(self):
        evidence=evidence_template(ddr3());evidence['datasheet'].update(reference='manual input',chip_part_number='test',max_rate_MTps=1600)
        result,lineage=generate_xmp_at_rate(ddr3(),1,self.profile(),1866,evidence,source='SPD',override=True)
        self.assertTrue(lineage['overridden_constraints']);self.assertTrue(encode_profile(ddr3(),1,result))

    def test_override_only_bypasses_logical_checks(self):
        p=self.profile();p['cas_latencies']=[4];p['timings_ns']['tRCmin']=1
        with self.assertRaises(ValueError):encode_profile(ddr3(),1,p)
        result=encode_profile(ddr3(),1,p,allow_inconsistent=True);self.assertEqual(read_profile(result,1)['cas_latencies'],[4])
        p['timings_ns']['tRFCmin']=999999
        with self.assertRaises(ValueError):encode_profile(ddr3(),1,p,allow_inconsistent=True)
        with self.assertRaises(ValueError):encode_native(ddr3(),{'tRCmin':1})
        self.assertTrue(encode_native(ddr3(),{'tRCmin':1},allow_inconsistent=True))
        p=epp_profile();p['timings_ns']['tRCmin']=1
        with self.assertRaises(ValueError):encode_epp(udimm(),0,p)
        self.assertTrue(encode_epp(udimm(),0,p,allow_inconsistent=True))
    def test_invalid_timebase_and_rates_do_not_crash_diagnostics(self):
        p=self.profile();p['mtb_divisor']='0';self.assertIn('mtb_divisor',validate_xmp(ddr3(),1,p)['errors'])
        for rate in (0,-1,10001):
            with self.assertRaises(ValueError):generate_xmp_at_rate(ddr3(),1,self.profile(),rate)

import os
from unittest.mock import patch

@unittest.skipUnless(os.environ.get('DISPLAY'),'No graphical display')
class LiveProfileTkTests(unittest.TestCase):
    def test_live_cas_flag_generation_and_override_audit(self):
        import tkinter as tk
        from spd_editor import SPDEditor,EditorDocument
        root=tk.Tk()
        try:
            app=SPDEditor(root);app.document=EditorDocument(ddr3());app.refresh();page=app.edit_xmp();page.seed()
            page.values['cas_latencies'].set('6,10');page.timings['tCKmin'].set('.833');page.timings['tAAmin'].set('9.113')
            self.assertEqual(page.field_entries['cas_latencies'].cget('style'),'Invalid.TEntry')
            self.assertEqual(str(page.preview_button.cget('state')),'disabled')
            page.target_rate.set('1200');page.clock_unit.set('MHz');page.generate_at_clock()
            self.assertEqual(page.values['cas_latencies'].get(),'11');self.assertTrue(page.live_validate()['logical_valid'])
            page.values['cas_latencies'].set('4');page.idiot_override.set(True);page.override_reason.set('Deliberate lab test of invalid CAS combination')
            page.build_preview();self.assertTrue(page.preview[2]['idiot_override'])
            with patch('tkinter.messagebox.askyesno',return_value=True):page.apply()
            self.assertTrue(app.document.vendor_profile_application['idiot_override']);app.undo();self.assertEqual(app.document.spd.data,ddr3())
            page.target_rate.set('not a number');self.assertEqual(page.target_entry.cget('style'),'Invalid.TEntry')
        finally:root.destroy()
    def test_native_speed_generation_and_override(self):
        import tkinter as tk
        from spd_editor import SPDEditor,EditorDocument
        root=tk.Tk()
        try:
            app=SPDEditor(root);app.document=EditorDocument(ddr3());app.refresh();page=app.performance
            page.native_rate.set('800');page.native_unit.set('MHz');page.generate_native();self.assertEqual(page.cas.get(),'11')
            page.native_vars['tRCmin'].set('1');self.assertTrue(page.validate_native())
            with self.assertRaises(ValueError):page.build_native()
            page.native_override.set(True);page.native_reason.set('Deliberate lab experiment');page.build_native();self.assertTrue(page.preview.proposal[2]['idiot_override'])
            page.native_vars['tRFCmin'].set('999999')
            with self.assertRaises(ValueError):page.build_native()
        finally:root.destroy()
