# SPDX-License-Identifier: MIT
import json
import unittest
from unittest.mock import patch
from spd_catalog import Catalog
from spd_integrity import repair_integrity
from tests import test_catalog as fixtures
hp=fixtures.hp
from tests.test_spd import ddr3, ddr2

class CatalogMetadataTests(unittest.TestCase):
    setUp=fixtures.CatalogTests.setUp
    tearDown=fixtures.CatalogTests.tearDown
    def test_manifest_identity_metadata_and_existing_collection_upgrade(self):
        entry=self.catalog.add(ddr3())
        with self.catalog.connect() as db:
            old={k:v for k,v in entry.items() if k in ('sha256','path','memory','manufacturer','part','serial','integrity','length')}
            db.execute('UPDATE images SET metadata=?',(json.dumps(old),))
        reopened=Catalog(self.catalog.root)
        row=reopened.rows()[0]
        self.assertEqual(row['metadata_version'],4)
        self.assertEqual(row['manufacture_year'],2015)
        self.assertEqual(row['path'],entry['path'])
        manifest=reopened.export_submission([entry['sha256']],self.root/'meta.zip')
        image=manifest['images'][0]
        self.assertEqual(manifest['schema'],'spd-tool-submission/2')
        self.assertEqual(image['part_number'],'TEST-DDR3')
        self.assertEqual(image['capacity_mib'],8192)
        self.assertEqual(image['module_type'],'UDIMM')
        self.assertEqual(image['manufacture_date'],'2015-W30')
        self.assertNotIn('path',image)

    def test_combined_facets_dates_and_numeric_sort(self):
        self.catalog.add(ddr3());self.catalog.add(ddr2())
        unknown=bytearray(ddr3());unknown[120:122]=b'\0\0';unknown[122]=1
        self.catalog.add(repair_integrity(unknown))
        self.assertEqual(len(self.catalog.rows(filters={'memory':'DDR3','ecc':'ECC'})),2)
        self.assertEqual(len(self.catalog.rows(year_from=2010,year_to=2020)),1)
        self.assertEqual(len(self.catalog.rows(filters={'manufacture_year':'Unknown'})),1)
        self.assertEqual(self.catalog.rows(sort='Capacity')[0]['memory'],'DDR2')
        self.assertIn('DDR3',self.catalog.facets()['memory'])
        with self.assertRaises(ValueError):self.catalog.rows(year_from=2020,year_to=2000)

    def test_mine_save_reuse_revalidate_and_conflicts(self):
        with patch('spd_catalog.load_registry',return_value={}):
            first=self.catalog.add(hp(1,101));self.catalog.add(hp(2,102));self.catalog.add(hp(3,103))
            report=self.catalog.mine_families();group=report['groups'][0]
            self.assertEqual(group['distinct_serials'],3)
            self.assertEqual(group['evaluation'],'sample-consistent')
            saved=self.catalog.save_family(group,'Test family')
            self.assertTrue(saved['saved'])
            self.assertEqual(len(self.catalog.saved_families()),1)
            analysis=self.catalog.hp_analysis(first['sha256'],4)
            self.assertEqual(analysis['families'][0]['candidates'],['00000068'])
            self.catalog.add(hp(4,999))
            with self.assertRaises(ValueError):self.catalog.save_family(group)
            self.assertEqual(self.catalog.mine_families()['groups'][0]['status'],'inconsistent')
            self.assertIn('conflicts',self.catalog.hp_analysis(first['sha256'])['families'][0]['error'])

    def test_duplicate_serials_and_stale_evidence(self):
        self.catalog.add(hp(1,101));self.catalog.add(hp(2,102))
        group=self.catalog.mine_families()['groups'][0]
        self.assertEqual(group['evaluation'],'provisional-two-sample')
        self.catalog.add(hp(3,103))
        with self.assertRaisesRegex(ValueError,'changed'):self.catalog.save_family(group)
        self.catalog.add(hp(1,900))
        group=self.catalog.mine_families()['groups'][0]
        self.assertEqual(group['status'],'conflicting-serial')
        with self.assertRaises(ValueError):self.catalog.save_family(group)

    def test_unreadable_matching_evidence_prevents_saving(self):
        first=self.catalog.add(hp(1,101));self.catalog.add(hp(2,102));third=self.catalog.add(hp(3,103))
        candidate=self.catalog.mine_families()['groups'][0]
        (self.catalog.root/third['path']).write_bytes(b'broken')
        report=self.catalog.mine_families()
        self.assertEqual(report['groups'][0]['status'],'unreadable-evidence')
        self.assertEqual(len(report['errors']),1)
        with self.assertRaises(ValueError):self.catalog.save_family(candidate)
