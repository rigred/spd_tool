# SPDX-License-Identifier: MIT
import os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from tests.test_spd import ddr2,ddr3
from tests.test_registered import legacy
from tests.test_engineering import udimm
from spd_editor import EditorDocument
from spd_catalog import Catalog
from spd_merge import digest

@unittest.skipUnless(os.environ.get('DISPLAY'),'No graphical display')
class WorkbenchTkTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        from spd_editor import SPDEditor
        self.tmp=tempfile.TemporaryDirectory();self.config=patch.dict(os.environ,{'SPD_TOOL_CONFIG_DIR':self.tmp.name});self.config.start()
        self.root=tk.Tk();self.app=SPDEditor(self.root);self.app.document=EditorDocument(ddr3());self.app.refresh();self.root.update()
    def tearDown(self):
        self.root.destroy();self.config.stop();self.tmp.cleanup()
    def test_native_preview_apply_undo_and_stale_guard(self):
        app=self.app;panel=app.performance;panel.native_vars['tRCDmin'].set('14');panel.build_native();panel.preview.apply()
        self.assertEqual(app.document.spd.decoded_data['timings_ns']['tRCDmin'],14);self.assertEqual(len(app.document.engineering_history),1)
        app.undo();self.assertEqual(app.document.spd.data,ddr3());app.redo();panel.native_vars['tRCDmin'].set('14.25');panel.build_native()
        app.document.edit(150,b'\1')
        with self.assertRaisesRegex(ValueError,'stale'):panel.preview.apply()
    def test_four_generation_forms_and_timeline(self):
        for data in (legacy(4),legacy(7),ddr2(),ddr3()):
            self.app.document=EditorDocument(data);self.app.refresh();self.assertIn('tCKmin',self.app.performance.native_vars)
            if data[2]==4:self.assertEqual(self.app.performance.xmp.voltage.get(),'3.3')
            if data[2]==7:self.assertEqual(self.app.performance.xmp.voltage.get(),'2.5')
            self.app.timing.load();self.root.update();self.assertTrue(self.app.timing.canvas.find_all())
        self.app.timing.pin();self.app.timing.params['tRCD'].set('14');self.app.timing.draw();self.assertTrue(self.app.timing.reference)
    def test_epp_create_preview_and_decode(self):
        app=self.app;app.document=EditorDocument(udimm());app.refresh();panel=app.performance;panel.seed_epp();panel.build_epp();panel.epp_preview.apply()
        self.assertEqual(app.document.spd.decoded_data['epp']['format'],'full');panel.load_epp();self.assertEqual(panel.epp_vars['voltage_V'].get(),'1.8')
        app.undo();self.assertIsNone(app.document.spd.decoded_data['epp'])
    def test_catalog_discovery_field_selection_and_composition(self):
        app=self.app;cat=Catalog(Path(self.tmp.name)/'catalog');cat.add(ddr3());donor=bytearray(ddr3());donor[150]=1;cat.add(donor)
        wrong=bytearray(ddr3());wrong[7]^=8
        from spd_integrity import repair_integrity
        cat.add(repair_integrity(wrong));app.catalog.catalog=cat
        panel=app.factory;panel.discover();self.assertEqual(len(panel.donor_tree.get_children()),2)
        panel.donor_tree.selection_set(digest(donor));panel.inspect();panel.fields.selection_set('manufacturer_payload');panel.overrides['opaque'].set('vendor data reviewed');panel.queue();panel.build()
        self.assertEqual(panel.preview.proposal[1][150],1);panel.preview.apply();self.assertEqual(app.document.spd.data[150],1)
        self.assertEqual(app.document.spd.data[122:126],ddr3()[122:126])
    def test_planner_native_preview_and_analysis_integration(self):
        panel=self.app.performance.xmp;panel.rates.set('1600');panel.generate();panel.table.selection_set('0');panel.native_plan()
        self.assertTrue(self.app.performance.preview.proposal);panel.analyze_plan();self.assertIn('extrapolated',self.app.timing.current['label'])
    def test_missing_catalog_startup_does_not_create_directory(self):
        from spd_settings import save
        missing=Path(self.tmp.name)/'absent';save(dict(catalog_path=str(missing),autoload=True))
        self.app.catalog.restore_settings();self.assertFalse(missing.exists());self.assertIn('unavailable',self.app.catalog.location.get())
    def test_catalog_preferences_restore_filters(self):
        from spd_settings import save
        cat=Catalog(Path(self.tmp.name)/'saved');cat.add(ddr3())
        save(dict(catalog_path=str(cat.root),autoload=True,filters={'memory':'DDR3'},sort='Vendor',search='',year_from='Any',year_to='Any'))
        self.app.catalog.restore_settings();deadline=time.monotonic()+5
        while self.app.hardware.busy and time.monotonic()<deadline:self.root.update();time.sleep(.01)
        self.assertFalse(self.app.hardware.busy);self.assertEqual(self.app.catalog.filters['memory'].get(),'DDR3');self.assertEqual(self.app.catalog.sort.get(),'Vendor')
        self.assertEqual(len(self.app.catalog.table.get_children()),1)
