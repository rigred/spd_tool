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
