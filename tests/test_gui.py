"""Real Tk integration checks; run with DISPLAY set to an X server."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tests.test_spd import ddr2, ddr3


@unittest.skipUnless(os.environ.get('DISPLAY') or os.name == 'nt', 'No graphical display')
class TkTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        from spd_editor import SPDEditor
        self.root = tk.Tk()
        self.app = SPDEditor(self.root)
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'input.bin'
        self.path.write_bytes(ddr3())
        self.app.open_path(self.path)
        self.root.update()

    def tearDown(self):
        self.root.destroy()
        self.temp.cleanup()

    def test_edit_undo_redo_save_compare_export(self):
        self.assertEqual(len(self.app.bytes_view.get_children()), 256)
        self.app.bytes_view.selection_set('16')
        with patch('tkinter.simpledialog.askstring', return_value='70'):
            self.app.edit_selected()
        self.assertEqual(self.app.document.spd.data[16], 0x70)
        self.assertIn('1 changed bytes', self.app.status.get())
        self.app.undo();self.assertFalse(self.app.document.dirty)
        self.app.redo();self.assertTrue(self.app.document.dirty)
        output = Path(self.temp.name) / 'edited.bin'
        with patch('tkinter.filedialog.asksaveasfilename', return_value=str(output)):
            self.assertTrue(self.app.save_as())
        self.assertFalse(self.app.document.dirty)
        with patch('tkinter.filedialog.askopenfilename', return_value=str(self.path)):
            self.app.compare()
        self.assertIn('differing bytes', self.app.diff.get('1.0', 'end'))
        export = Path(self.temp.name) / 'decoded.json'
        with patch('tkinter.filedialog.asksaveasfilename', return_value=str(export)):
            self.app.export()
        self.assertIn('DDR3 SDRAM', export.read_text())
        self.app.document.edit(16, b'\x72')
        with patch('tkinter.messagebox.askyesnocancel', return_value=None):
            self.assertFalse(self.app.confirm_discard())
        self.root.update()

    def test_ddr2_open_and_validation_error(self):
        self.path.write_bytes(ddr2(128))
        self.app.open_path(self.path)
        self.assertEqual(len(self.app.bytes_view.get_children()), 128)
        self.assertIn('DDR2', self.app.status.get())
        self.app.bytes_view.selection_set('2')
        with patch('tkinter.simpledialog.askstring', return_value='0B'), patch('tkinter.messagebox.showerror') as error:
            self.app.run(self.app.edit_selected)
            self.assertTrue(error.called)
        self.assertEqual(self.app.document.spd.mem_type, 8)
        self.root.update()
