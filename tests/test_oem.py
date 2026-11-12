# SPDX-License-Identifier: MIT
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from spd_catalog import Catalog
from spd_integrity import repair_integrity
from tests.test_catalog import hp


def module(serial,code,part,vendor=0x2C):
    data=bytearray(hp(serial,code));data[128:146]=part.encode().ljust(18,b' ');data[118]=vendor
    return repair_integrity(data)


class OEMTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.catalog=Catalog(Path(self.temp.name)/'collection')
    def tearDown(self):self.temp.cleanup()

    def test_general_oem_persistence_manifest_and_clear(self):
        raw=module(1,101,'VENDOR-ONE');entry=self.catalog.add(raw)
        details=dict(oem_name='Dell',part_number='OEM-123',spare_number='SP-1',assembly_number='ASSY-2',model='Server',notes='Sticker photograph reference')
        self.catalog.set_oem_details(entry['sha256'],details)
        reopened=Catalog(self.catalog.root)
        self.assertEqual(reopened.data(entry['sha256']),raw)
        self.assertEqual(reopened.rows(filters={'oem_name':'Dell'})[0]['oem_part_number'],'OEM-123')
        image=reopened.export_submission([entry['sha256']],Path(self.temp.name)/'oem.zip')['images'][0]
        self.assertEqual(image['part_number'],'VENDOR-ONE')
        self.assertEqual(image['oem']['part_number'],'OEM-123')
        self.assertIn('user-entered',image['oem']['source'])
        reopened.set_oem_details(entry['sha256'],{})
        self.assertEqual(reopened.oem_details(entry['sha256']),{})

    def test_cross_vendor_hp_family_and_generic_oem_isolation(self):
        with patch('spd_catalog.load_registry',return_value={}):
            a=self.catalog.add(module(1,101,'VENDOR-ONE'))
            b=self.catalog.add(module(2,102,'VENDOR-TWO',0xCE))
            c=self.catalog.add(module(4,104,'VENDOR-THREE',0x98))
            for entry,name in [(a,'HP'),(b,'HPE'),(c,'Hewlett-Packard')]:
                self.catalog.set_oem_details(entry['sha256'],dict(oem_name=name,part_number='LABEL',hp_family_part_number='123456-071'))
            group=self.catalog.mine_families()['groups'][0]
            self.assertEqual(group['distinct_serials'],3)
            self.assertEqual(group['scope'],['OEM:HP','123456071','HP-PN'])
            self.assertEqual(len({m['manufacturer'] for m in group['members']}),3)
            self.catalog.save_family(group)
            result=self.catalog.hp_analysis(c['sha256'],5)
            self.assertEqual(result['families'][0]['candidates'],['00000069'])
            other=self.catalog.add(module(6,900,'DIFFERENT-VENDOR'))
            self.catalog.set_oem_details(other['sha256'],dict(oem_name='Dell',part_number='123456-071'))
            hpgroup=next(g for g in self.catalog.mine_families()['groups'] if g['hp_family_part_number'])
            self.assertEqual(hpgroup['distinct_serials'],3)
            self.catalog.set_oem_details(a['sha256'],dict(oem_name='HP',part_number='OTHER'))
            with self.assertRaises(ValueError):self.catalog.save_family(group)
            self.assertIn('assignments changed',self.catalog.hp_analysis(c['sha256'])['families'][0]['error'])

    def test_hp_pn_known_registry_lookup_and_conflicting_shared_pn(self):
        a=self.catalog.add(module(1,101,'UNLISTED-VENDOR'))
        self.catalog.set_oem_details(a['sha256'],dict(oem_name='HP',part_number='123456-071'))
        registry={'known':dict(name='123456-071',A='0x1',B='0xFFFFFFFF',K='0xFFFFFF9C')}
        with patch('spd_catalog.load_registry',return_value=registry):
            self.assertEqual(self.catalog.hp_analysis(a['sha256'],4)['families'][0]['candidates'],['00000068'])
        b=self.catalog.add(module(1,900,'OTHER-VENDOR',0xCE))
        self.catalog.set_oem_details(b['sha256'],dict(oem_name='HPE',part_number='123456071'))
        group=self.catalog.mine_families()['groups'][0]
        self.assertEqual(group['status'],'conflicting-serial')
        with self.assertRaises(ValueError):self.catalog.save_family(group)

    def test_annotations_validated_without_modifying_image(self):
        entry=self.catalog.add(module(1,101,'ONE'))
        for invalid in ({'extra':'field'},{'oem_name':123},{'part_number':'bad\nvalue'},{'notes':'x'*2001}):
            with self.assertRaises(ValueError):self.catalog.set_oem_details(entry['sha256'],invalid)
