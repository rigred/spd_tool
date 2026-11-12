# SPDX-License-Identifier: MIT
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tests.test_spd import ddr3

@unittest.skipUnless(os.environ.get('DISPLAY'),'No graphical display')
class CatalogTkTests(unittest.TestCase):
    def test_collection_add_open_search_and_public_export(self):
        import tkinter as tk
        from spd_editor import SPDEditor,EditorDocument
        with tempfile.TemporaryDirectory() as temp:
            root=tk.Tk()
            try:
                app=SPDEditor(root);panel=app.catalog
                with patch('tkinter.filedialog.askdirectory',return_value=temp):panel.choose()
                app.document=EditorDocument(ddr3());app.refresh()
                panel.add_editor();root.update()
                rows=panel.table.get_children();self.assertEqual(len(rows),1)
                panel.search.set('not a part number');self.assertFalse(panel.table.get_children())
                panel.search.set('TEST-DDR3');self.assertEqual(len(panel.table.get_children()),1)
                panel.table.selection_set(rows[0]);panel.open_selected()
                self.assertEqual(app.document.spd.data,ddr3());self.assertFalse(app.document.path)
                output=Path(temp)/'public.zip'
                with patch('tkinter.messagebox.askyesno',return_value=True),patch('tkinter.filedialog.asksaveasfilename',return_value=str(output)):
                    panel.submission()
                self.assertTrue(output.is_file())
            finally:root.destroy()

    def test_filters_mining_review_and_save(self):
        import tkinter as tk
        import time
        from tkinter import ttk
        from spd_editor import SPDEditor
        from spd_catalog import Catalog
        from tests.test_catalog import hp
        from tests.test_spd import ddr2
        with tempfile.TemporaryDirectory() as temp:
            root=tk.Tk()
            try:
                app=SPDEditor(root);panel=app.catalog;panel.catalog=Catalog(temp)
                for raw in [hp(1,101),hp(2,102),hp(3,103),ddr2()]:panel.catalog.add(raw)
                panel.refresh();root.update()
                panel.filters['memory'].set('DDR2');panel.refresh()
                self.assertEqual(len(panel.table.get_children()),1)
                panel.clear_filters();self.assertEqual(len(panel.table.get_children()),4)
                panel.year_from.set('2020');panel.year_to.set('2000');panel.refresh()
                self.assertIn('must not exceed',panel.count.get());panel.clear_filters()
                panel.mine()
                def wait():
                    deadline=time.monotonic()+5
                    while app.hardware.busy and time.monotonic()<deadline:root.update();time.sleep(.01)
                    self.assertFalse(app.hardware.busy);root.update()
                wait()
                dialog=next(w for w in root.winfo_children() if isinstance(w,tk.Toplevel))
                button=next(w for w in dialog.winfo_children() if isinstance(w,ttk.Button))
                with patch('tkinter.simpledialog.askstring',return_value='Reviewed test family'),patch('tkinter.messagebox.askyesno',return_value=True):button.invoke()
                wait()
                self.assertEqual(len(panel.catalog.saved_families()),1)
            finally:root.destroy()

    def test_loaded_editor_oem_details_and_edited_snapshot(self):
        import tkinter as tk
        from tkinter import ttk
        from spd_catalog import Catalog
        from spd_editor import SPDEditor,EditorDocument
        import hashlib
        with tempfile.TemporaryDirectory() as temp:
            root=tk.Tk()
            try:
                app=SPDEditor(root);panel=app.catalog;panel.catalog=Catalog(temp)
                raw=ddr3();app.document=EditorDocument(raw);app.refresh()
                panel.edit_oem(True);root.update()
                dialog=next(w for w in root.winfo_children() if isinstance(w,tk.Toplevel))
                fields=next(w for w in dialog.winfo_children() if isinstance(w,ttk.Frame))
                entries=[w for w in fields.winfo_children() if isinstance(w,ttk.Entry)]
                entries[0].insert(0,'HPE');entries[1].insert(0,'123456-071')
                next(w for w in dialog.winfo_children() if isinstance(w,ttk.Button)).invoke()
                sha=hashlib.sha256(raw).hexdigest()
                self.assertEqual(panel.catalog.oem_details(sha)['part_number'],'123456-071')
                self.assertEqual(app.document.spd.data,raw)
                app.document.edit(140,b'X');panel.add_editor()
                newsha=hashlib.sha256(app.document.spd.data).hexdigest()
                self.assertNotEqual(newsha,sha)
                self.assertEqual(panel.catalog.oem_details(newsha)['part_number'],'123456-071')
                self.assertEqual(panel.catalog.data(sha),raw)
            finally:root.destroy()
