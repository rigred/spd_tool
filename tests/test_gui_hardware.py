# SPDX-License-Identifier: MIT
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from spd_hardware import DeviceImage
from tests.test_programming import MemoryBackend
from tests.test_spd import ddr3


class GUIBackend(MemoryBackend):
    def read(self, address, cancel=None):
        return DeviceImage(self.target, address, bytes(self.memory), 'test')

    def scan(self, active=False, cancel=None, log=lambda message:None):
        log('Test acquisition')
        return [self.read(0x50)], ['0x51: no device']


@unittest.skipUnless(os.environ.get('DISPLAY') or os.name == 'nt', 'No graphical display')
class HardwareTkTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        from spd_editor import SPDEditor
        self.root = tk.Tk(); self.app = SPDEditor(self.root)
        self.panel = self.app.hardware
        self.panel.mode.set('Linux I2C / SMBus')  # The transport factory below is simulated on every OS.
        self.temp = tempfile.TemporaryDirectory()
        self.backend = GUIBackend(ddr3())
        self.factory = patch('spd_hardware_gui.LinuxBackend',return_value=self.backend)
        self.factory.start()
        self.root.update()

    def tearDown(self):
        self.factory.stop()
        self.root.destroy(); self.temp.cleanup()

    def wait(self):
        deadline = time.monotonic()+5
        while self.panel.busy and time.monotonic()<deadline:
            self.root.update(); time.sleep(.01)
        self.assertFalse(self.panel.busy)
        self.root.update()

    def scan(self):
        self.panel.adapter.set('0 — test adapter')
        self.panel.scan(); self.wait()

    def test_scan_select_read_and_export_exact_dump(self):
        self.scan()
        self.assertEqual(len(self.panel.devices.get_children()),2)
        self.panel.devices.selection_set('error-0')
        self.panel.select_best()
        self.assertEqual(self.panel.devices.selection(),('0',))
        self.panel.load(); self.wait()
        self.assertEqual(self.app.document.spd.data, ddr3())
        self.assertEqual(self.app.document.path, '')
        self.assertEqual(self.app.book.select(),str(self.app.overview_tab))
        output=Path(self.temp.name)/'dump.bin'
        with patch('tkinter.filedialog.asksaveasfilename',return_value=str(output)):
            self.panel.save_dump()
        self.assertEqual(output.read_bytes(),ddr3())
        self.panel.adapter.set('1')
        with self.assertRaisesRegex(ValueError,'Connection changed'):
            self.panel.load()

    def test_windows_discovery_scan_and_module_folder_invalidation(self):
        self.panel.mode.set('Windows native SMBus');self.panel.windows_modules.set(self.temp.name);self.panel.active.set(True)
        report=dict(adapters=[dict(profile='i801',type='i801',vendor_id='8086',device_id='1C22')],errors=[])
        with patch('spd_hardware_gui.sys.platform','win32'),patch('spd_windows.inventory',return_value=report) as discover,patch('spd_hardware_gui.WindowsBackend',return_value=self.backend) as backend:
            self.panel.discover();self.wait();discover.assert_called_once_with(self.temp.name)
            self.assertTrue(self.panel.adapter.get().startswith('i801'))
            self.panel.scan();self.wait();backend.assert_called_once_with('i801',self.temp.name)
            self.assertEqual(len(self.panel.images),1)
            self.panel.windows_modules.set(str(Path(self.temp.name)/'changed'))
            with self.assertRaisesRegex(ValueError,'Connection changed'):self.panel.selected()

    def test_review_confirm_backup_program_and_verify(self):
        self.scan(); self.panel.load(); self.wait()
        self.app.document.edit(16,b'\x70')
        self.panel.prepare(); self.wait()
        self.assertIn('Target SHA-256', self.panel.details.get('1.0','end'))
        self.assertEqual(self.backend.writes,[])
        backup=Path(self.temp.name)/'backup.bin'
        with patch('tkinter.filedialog.asksaveasfilename',return_value=str(backup)), patch('tkinter.messagebox.askyesno',return_value=False):
            self.panel.program()
        self.assertEqual(self.backend.writes,[])
        self.assertFalse(backup.exists())
        with patch('tkinter.filedialog.asksaveasfilename',return_value=str(backup)), patch('tkinter.messagebox.askyesno',return_value=True):
            self.panel.program()
        self.wait()
        self.assertEqual(backup.read_bytes(),ddr3())
        self.assertTrue(self.backend.writes)
        self.assertIsNone(self.panel.scan_config)
        self.assertIn('Programming complete',self.panel.state.get())

    def test_review_invalidated_by_editor_or_options(self):
        self.scan(); self.panel.load(); self.wait()
        self.app.document.edit(16,b'\x70')
        self.panel.prepare(); self.wait()
        self.panel.repair.set(False)
        with self.assertRaisesRegex(ValueError,'changed'):
            self.panel.program()
        self.assertEqual(self.backend.writes,[])
        self.panel.repair.set(True)
        self.panel.prepare(); self.wait()
        self.app.document.edit(16,b'\x71')
        with self.assertRaisesRegex(ValueError,'changed'):
            self.panel.program()

    def test_background_work_freezes_controls_and_blocks_close(self):
        started=threading.Event(); finish=threading.Event()
        def work():
            started.set(); finish.wait(3); return None
        try:
            self.panel.start_job('Working',work,lambda result:None)
            self.assertTrue(started.wait(1))
            self.assertEqual(str(self.panel.adapter_box.cget('state')),'disabled')
            with self.assertRaisesRegex(ValueError,'Wait for the hardware'):
                self.app.close()
            self.panel.cancel()
            self.assertTrue(self.panel.cancel_event.is_set())
        finally:
            finish.set(); self.wait()
        self.assertEqual(str(self.panel.adapter_box.cget('state')),'normal')


if __name__ == '__main__': unittest.main()
