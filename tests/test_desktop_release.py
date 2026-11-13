# SPDX-License-Identifier: MIT
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from spd_desktop import main


class DesktopLauncherTests(unittest.TestCase):
    def test_cli_dispatch_restores_process_arguments(self):
        original=sys.argv
        def command():self.assertEqual(sys.argv[1:],['convert','--help'])
        with patch('spd_tool.main',side_effect=command):main(['--cli','convert','--help'])
        self.assertIs(sys.argv,original)

    def test_image_argument_opens_desktop(self):
        with patch('spd_editor.main') as launch:
            self.assertEqual(main(['example.spd']),0);launch.assert_called_once_with('example.spd')

    def test_gui_check_requires_self_test(self):
        with patch('sys.stderr'),self.assertRaises(SystemExit) as error:main(['--gui-check'])
        self.assertEqual(error.exception.code,2)

    def test_failure_report_and_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            report=Path(tmp)/'failure.json'
            with patch('spd_release_check.self_test',side_effect=ValueError('missing dependency')),patch('sys.stdout',None):
                self.assertEqual(main(['--self-test','--report',str(report)]),1)
            data=json.loads(report.read_text());self.assertEqual(data['status'],'FAILED');self.assertIn('missing dependency',data['error'])

    @unittest.skipUnless(importlib.util.find_spec('py7zr') and importlib.util.find_spec('serial'),'Desktop build dependencies not installed')
    def test_real_self_test_report_runs_without_hardware(self):
        with tempfile.TemporaryDirectory() as tmp:
            report=Path(tmp)/'check.json'
            with patch('sys.stdout',None):self.assertEqual(main(['--self-test','--report',str(report)]),0)
            data=json.loads(report.read_text());self.assertEqual(data['status'],'PASS');self.assertFalse(data['hardware_accessed']);self.assertGreaterEqual(len(data['checks']),7)
