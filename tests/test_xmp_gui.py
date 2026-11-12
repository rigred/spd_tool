# SPDX-License-Identifier: MIT
import os
import tempfile
import unittest
from unittest.mock import patch
from spd_editor import EditorDocument
from tests.test_spd import ddr3

@unittest.skipUnless(os.environ.get('DISPLAY'),'No graphical display')
class XMPTkTests(unittest.TestCase):
    def test_generate_preview_apply_undo_and_stale_review(self):
        import tkinter as tk
        from spd_editor import SPDEditor
        root=tk.Tk()
        try:
            app=SPDEditor(root);app.document=EditorDocument(ddr3());app.refresh()
            dialog=app.edit_xmp();dialog.seed();dialog.build_preview()
            self.assertTrue(dialog.preview)
            with patch('tkinter.messagebox.askyesno',return_value=True):dialog.apply()
            self.assertEqual(app.document.spd.data[176:178],b'\x0c\x4a')
            self.assertEqual(app.document.spd.data[:176],ddr3()[:176])
            self.assertEqual(app.document.vendor_profile_application['kind'],'ddr3-xmp')
            app.undo();self.assertEqual(app.document.spd.data,ddr3());self.assertIsNone(app.document.vendor_profile_application)
            app.redo();dialog.load();dialog.build_preview();dialog.values['voltage_V'].set('1.65')
            with self.assertRaisesRegex(ValueError,'changed'):dialog.apply()
            dialog.rates.set('1600,1866,2133');dialog.generate()
            self.assertEqual(len(dialog.plans),3)
            dialog.table.selection_set('1');dialog.use_plan()
            self.assertEqual(dialog.values['cas_latencies'].get(),'13')
        finally:root.destroy()

    def test_hpt_overlap_is_explicit(self):
        import tkinter as tk
        from spd_editor import SPDEditor
        root=tk.Tk()
        try:
            app=SPDEditor(root);raw=bytearray(ddr3());raw[176:184]=b'HPT\0abcd'
            app.document=EditorDocument(raw);app.refresh();dialog=app.edit_xmp();dialog.seed()
            with self.assertRaisesRegex(ValueError,'HPT'):dialog.build_preview()
            dialog.replace.set(True);dialog.build_preview()
            self.assertEqual(dialog.preview[1][:176],raw[:176])
        finally:root.destroy()
