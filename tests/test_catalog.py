# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from spd_catalog import Catalog, safe_name
from spd_integrity import repair_integrity
from tests.test_spd import ddr3


def hp(serial,hpt):
    d=bytearray(ddr3()); d[122:126]=serial.to_bytes(4,'big'); d[176:184]=b'HPT\0'+hpt.to_bytes(4,'big')
    return repair_integrity(d)


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.catalog=Catalog(self.root/'collection')
    def tearDown(self):self.temp.cleanup()

    def test_import_dedup_provenance_integrity_and_tampering(self):
        data=ddr3(); a=self.catalog.add(data,'one');self.catalog.add(data,'two')
        self.assertEqual(len(self.catalog.rows()),1)
        self.assertEqual(self.catalog.data(a['sha256']),data)
        self.assertIn('modules/DDR3/',a['path'])
        with self.catalog.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM sources').fetchone()[0],2)
        (self.catalog.root/a['path']).write_bytes(data[:-1]+b'X')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):self.catalog.data(a['sha256'])

    def test_invalid_input_preserves_sources_and_reports_errors(self):
        source=self.root/'source.bin';source.write_bytes(ddr3())
        bad=self.root/'bad.bin';bad.write_bytes(b'bad')
        good,errors=self.catalog.import_files([source,bad])
        self.assertEqual(len(good),1);self.assertEqual(len(errors),1);self.assertEqual(source.read_bytes(),ddr3())
        self.assertNotIn('/',safe_name('../../CON'))
        self.assertNotEqual(safe_name('CON'),'CON')

    def test_provisional_relation_and_third_sample_validation(self):
        with patch('spd_catalog.load_registry',return_value={'uncomputed':dict(equivalents=['TEST-DDR3'])}):
            first=self.catalog.add(hp(1,101));self.catalog.add(hp(2,102))
            result=self.catalog.hp_analysis(first['sha256'],4)
            self.assertEqual(result['families'][0]['origin'],'provisional-two-sample')
            self.assertEqual(result['families'][0]['candidates'],['00000068'])
            self.catalog.add(hp(3,103))
            self.assertEqual(self.catalog.hp_analysis(first['sha256'])['families'][0]['origin'],'sample-consistent')
            self.catalog.add(hp(4,999))
            self.assertEqual(self.catalog.hp_analysis(first['sha256'])['families'],[])

    def test_conflicting_serial_and_known_family(self):
        first=self.catalog.add(hp(1,101));self.catalog.add(hp(1,102))
        with patch('spd_catalog.load_registry',return_value={}):
            result=self.catalog.hp_analysis(first['sha256']);self.assertTrue(result['conflicting_samples']);self.assertFalse(result['families'])
        registry={'known':dict(A='0x1',B='0xFFFFFFFF',K='0xFFFFFF9C',equivalents=['TEST-DDR3'])}
        with patch('spd_catalog.load_registry',return_value=registry):
            result=self.catalog.hp_analysis(first['sha256'],4)
            self.assertEqual(result['families'][0]['candidates'],['00000068'])

    def test_public_bundle_no_absolute_sources_and_no_overwrite(self):
        entry=self.catalog.add(ddr3(),'/private/source/path')
        destination=self.root/'submission.zip'
        report=self.catalog.export_submission([entry['sha256']],destination)
        with zipfile.ZipFile(destination) as archive:
            self.assertEqual(archive.read(report['images'][0]['file']),ddr3())
            self.assertNotIn('/private',archive.read('manifest.json').decode())
        with self.assertRaises(FileExistsError):self.catalog.export_submission([entry['sha256']],destination)
