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

    def test_registered_field_dialog_filter_and_hp_edit(self):
        import tkinter as tk
        from tkinter import ttk
        from tests.test_registered import registered_ddr3
        self.path.write_bytes(registered_ddr3())
        self.app.open_path(self.path)
        self.app.book.select(self.app.module_tab)
        self.app.field_search.set('CA A drive')
        self.root.update()
        self.assertEqual(self.app.module_view.get_children(),('ca_a',))
        self.app.module_view.selection_set('ca_a')
        self.app.edit_module_field()
        self.root.update()
        dialog=next(w for w in self.root.winfo_children() if isinstance(w,tk.Toplevel))
        def children(widget):
            result=[]
            for child in widget.winfo_children():
                result.append(child);result.extend(children(child))
            return result
        widgets=children(dialog)
        next(w for w in widgets if isinstance(w,ttk.Combobox)).set('2: Strong')
        next(w for w in widgets if isinstance(w,ttk.Button) and w.cget('text')=='Apply').invoke()
        self.root.update()
        self.assertEqual(self.app.document.spd.data[70],0x60)
        self.assertTrue(self.app.document.dirty)
        self.app.undo();self.assertEqual(self.app.document.spd.data[70],0x50)
        self.app.field_search.set('')
        with patch('tkinter.simpledialog.askstring',return_value='12345678'):
            self.app.edit_hpt()
        self.assertEqual(self.app.document.spd.data[176:184],bytes.fromhex('4850540012345678'))
        self.path.write_bytes(registered_ddr3(True))
        self.app.open_path(self.path)
        self.app.show_expert.set(True)
        self.app.field_search.set('F15RC6')
        self.root.update()
        self.assertEqual(self.app.module_view.get_children(),('F15RC6',))
        self.app.module_view.selection_set('F15RC6')
        self.app.edit_module_field()
        self.root.update()
        dialog=next(w for w in self.root.winfo_children() if isinstance(w,tk.Toplevel))
        widgets=children(dialog)
        entry=next(w for w in widgets if isinstance(w,ttk.Entry))
        entry.delete(0,'end');entry.insert(0,'0xA')
        next(w for w in widgets if isinstance(w,ttk.Button) and w.cget('text')=='Apply').invoke()
        self.root.update()
        self.assertEqual(self.app.document.spd.data[105],0xA6)

    def test_hp_family_candidates_are_invalidated(self):
        import tkinter as tk
        from tkinter import ttk
        from tests.test_registered import registered_ddr3
        self.path.write_bytes(registered_ddr3())
        self.app.open_path(self.path)
        self.app.document.set_serial('48BD4D77')
        self.app.compute_hpt()
        self.root.update()
        dialog=next(w for w in self.root.winfo_children() if isinstance(w,tk.Toplevel))
        widgets=dialog.winfo_children()[0].winfo_children()
        combos=[w for w in widgets if isinstance(w,ttk.Combobox)]
        buttons={w.cget('text'):w for w in widgets if isinstance(w,ttk.Button)}
        with patch('tkinter.messagebox.showerror') as error:
            buttons['Calculate candidates'].invoke()
            self.root.update()
            self.assertFalse(error.called)
            self.assertTrue(combos[1].get())
            self.assertEqual(len(combos[1]['values']),4)
            combos[0].current(1)
            self.root.update()
            self.assertEqual(combos[1].get(),'')
            self.assertFalse(combos[1]['values'])
            buttons['Calculate candidates'].invoke()
            self.root.update()
            self.assertFalse(error.called)
            expected=combos[1].get()
            buttons['Apply selected HPT'].invoke()
            self.root.update()
            self.assertEqual(self.app.document.spd.data[180:184].hex().upper(),expected)

    def test_legacy_registered_tab_and_metadata(self):
        from tests.test_registered import legacy
        for mem in (4,7):
            self.path.write_bytes(legacy(mem,128))
            self.app.field_search.set('')
            self.app.open_path(self.path)
            self.assertIn('registered_address',self.app.module_view.get_children())
            self.assertEqual(len(self.app.bytes_view.get_children()),128)
            with patch('tkinter.simpledialog.askstring',return_value='GUI-VINTAGE'):
                self.app.edit_part()
            self.assertEqual(self.app.document.spd.data[73:91],b'GUI-VINTAGE       ')
            self.root.update()

    def test_double_click_waits_for_mapping_and_uses_clicked_row(self):
        import tkinter as tk
        from types import SimpleNamespace
        from tests.test_registered import legacy
        self.path.write_bytes(legacy())
        self.app.open_path(self.path)
        self.app.book.select(self.app.module_tab)
        self.app.field_group.set('Legacy timings');self.app.refresh_module_fields()
        self.root.update()
        box=self.app.module_view.bbox('tRAS')
        self.assertTrue(box)
        x,y,width,height=box
        grabs=[]
        original=tk.Toplevel.grab_set
        def checked(dialog):
            grabs.append(dialog.winfo_viewable())
            self.assertTrue(dialog.winfo_viewable())
            # Contents must exist before the WM can make the dialog modal.
            self.assertTrue(dialog.winfo_children())
            original(dialog)
        with patch.object(tk.Toplevel,'grab_set',new=checked):
            # Dispatch the actual widget binding, through Tk's double-click detection.
            self.app.module_view.event_generate('<ButtonPress-1>',x=x+15,y=y+height//2,time=1000)
            self.app.module_view.event_generate('<ButtonRelease-1>',x=x+15,y=y+height//2,time=1010)
            self.app.module_view.event_generate('<ButtonPress-1>',x=x+15,y=y+height//2,time=1100)
            self.app.module_view.event_generate('<ButtonRelease-1>',x=x+15,y=y+height//2,time=1110)
            self.root.update()
            self.assertTrue(grabs)
            self.assertEqual(self.app._active_dialog.title(),'tRAS')
            active=self.app._active_dialog
            self.app.edit_module_field();self.root.update()
            self.assertIs(self.app._active_dialog,active)
            active.destroy();self.root.update()
            self.assertIsNone(self.app._active_dialog)
        # Empty space / heading double-clicks never edit a previous selection.
        with patch.object(self.app,'edit_module_field') as edit:
            self.app._edit_tree_row(SimpleNamespace(x=5,y=1),self.app.module_view,edit)
            self.root.update();edit.assert_not_called()

    def test_overview_updates_on_edit_and_undo(self):
        self.assertEqual(self.app.book.select(),str(self.app.overview_tab))
        self.assertEqual(self.app.overview_metrics['family'].get(),'DDR3')
        self.assertEqual(self.app.overview_metrics['capacity'].get(),'8 GiB')
        self.assertEqual(self.app.overview_metrics['integrity'].get(),'VALID')
        self.app.document.set_part_number('OVERVIEW-EDIT');self.app.refresh()
        self.assertEqual(self.app.overview_values[('Module identity','Part number')].get(),'OVERVIEW-EDIT')
        self.app.undo()
        self.assertEqual(self.app.overview_values[('Module identity','Part number')].get(),'TEST-DDR3')
        self.assertTrue(self.app.overview_trees['timings'].get_children())

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
