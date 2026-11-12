# SPDX-License-Identifier: MIT
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from spd_catalog import Catalog
from spd_editor import EditorDocument
from spd_integrity import repair_integrity
from tests.test_catalog import hp


@unittest.skipUnless(os.environ.get('DISPLAY'),'No graphical display')
class VendorProfileTkTests(unittest.TestCase):
    def test_review_apply_undo_and_catalog_provenance(self):
        import tkinter as tk
        from spd_editor import SPDEditor
        with tempfile.TemporaryDirectory() as temp,patch('spd_catalog.load_registry',return_value={}):
            root=tk.Tk()
            try:
                app=SPDEditor(root);panel=app.catalog;panel.catalog=Catalog(temp)
                donor=panel.catalog.add(hp(1,101));panel.catalog.add(hp(2,102))
                family=panel.catalog.hp_analysis(donor['sha256'])['families'][0]['key']
                profile=panel.catalog.create_hp_profile(donor['sha256'],family,'Test donor')
                raw=bytearray(hp(5,0));raw[176:184]=b'\0'*8;raw=repair_integrity(raw)
                app.document=EditorDocument(raw);app.refresh()
                dialog=panel.vendor_dialog();dialog.profile.set(next(iter(dialog.records)))
                dialog.options();self.assertEqual(dialog.hpt.get(),'00000069')
                dialog.build_preview()
                with patch('tkinter.messagebox.askyesno',return_value=False):dialog.apply()
                self.assertEqual(app.document.spd.data,raw)
                with patch('tkinter.messagebox.askyesno',return_value=True):dialog.apply()
                self.assertEqual(app.document.spd.data[180:184],(105).to_bytes(4,'big'))
                self.assertEqual(app.document.spd.data[122:126],raw[122:126])
                app.undo();self.assertIsNone(app.document.vendor_profile_application)
                app.redo();self.assertTrue(app.document.vendor_profile_application['generated'])
                sha=panel.capture_editor()
                row=next(r for r in panel.catalog.rows() if r['sha256']==sha)
                self.assertTrue(row['generated_vendor_profile'])
                self.assertEqual(panel.catalog.mine_families()['groups'][0]['distinct_serials'],2)
                # Build another review, then change the editor: stale review must fail.
                app.undo();dialog.options();dialog.build_preview();app.document.edit(140,b'X')
                with self.assertRaisesRegex(ValueError,'changed'):dialog.apply()
            finally:root.destroy()
