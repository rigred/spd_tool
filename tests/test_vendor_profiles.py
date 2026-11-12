# SPDX-License-Identifier: MIT
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from spd_catalog import Catalog
from spd_editor import EditorDocument
from spd_integrity import repair_integrity
from spd_vendor import vendor_metadata
from tests.test_catalog import hp


class VendorProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.catalog=Catalog(Path(self.temp.name)/'library')
        self.registry=patch('spd_catalog.load_registry',return_value={});self.registry.start()
        self.donor=self.catalog.add(hp(1,101));self.catalog.add(hp(2,102))
        self.family=self.catalog.hp_analysis(self.donor['sha256'])['families'][0]['key']
        self.profile=self.catalog.create_hp_profile(self.donor['sha256'],self.family,'Test donor')
        target=bytearray(hp(5,0));target[176:184]=b'\0'*8
        self.target=repair_integrity(target)
    def tearDown(self):self.registry.stop();self.temp.cleanup()

    def test_profile_preserves_identity_and_electrical_settings(self):
        result,report=self.catalog.preview_hp_profile(self.profile['id'],self.target,'00000069')
        self.assertEqual(result[:176],self.target[:176])
        self.assertEqual(result[184:],self.target[184:])
        self.assertEqual(result[122:126],(5).to_bytes(4,'big'))
        self.assertEqual(result[176:184],b'HPT\0'+(105).to_bytes(4,'big'))
        self.assertEqual(report['target_serial'],'00000005')
        reopened=Catalog(self.catalog.root)
        self.assertEqual(reopened.vendor_profiles()[0]['id'],self.profile['id'])

    def test_mismatched_model_settings_crc_and_hpt_refused(self):
        for offset in (4,16,64,128):
            raw=bytearray(self.target);raw[offset]^=1;raw=repair_integrity(raw)
            with self.assertRaises(ValueError):self.catalog.hp_profile_options(self.profile['id'],raw)
        raw=bytearray(self.target);raw[126]^=1
        with self.assertRaises(ValueError):self.catalog.hp_profile_options(self.profile['id'],raw)
        with self.assertRaises(ValueError):self.catalog.preview_hp_profile(self.profile['id'],self.target,'00000000')

    def test_existing_customer_data_requires_explicit_replacement(self):
        raw=bytearray(self.target);raw[176:180]=b'XMP!'
        with self.assertRaisesRegex(ValueError,'existing customer'):
            self.catalog.preview_hp_profile(self.profile['id'],raw,'00000069')
        result,_=self.catalog.preview_hp_profile(self.profile['id'],raw,'00000069',True)
        self.assertEqual(result[176:180],b'HPT\0')

    def test_generated_images_excluded_from_learning_and_provenance_exported(self):
        result,report=self.catalog.preview_hp_profile(self.profile['id'],self.target,'00000069')
        entry=self.catalog.add(result);self.catalog.mark_profile_generated(entry['sha256'],report)
        self.assertEqual(self.catalog.mine_families()['groups'][0]['distinct_serials'],2)
        self.assertEqual(self.catalog.hp_analysis(self.donor['sha256'])['distinct_samples'],2)
        with self.assertRaises(ValueError):self.catalog.create_hp_profile(entry['sha256'],self.family,'Circular')
        manifest=self.catalog.export_submission([entry['sha256']],Path(self.temp.name)/'public.zip')
        self.assertTrue(manifest['images'][0]['vendor_profile_application']['generated'])

    def test_undo_redo_tracks_generated_provenance(self):
        result,report=self.catalog.preview_hp_profile(self.profile['id'],self.target,'00000069')
        doc=EditorDocument(self.target);doc.replace(result);doc.vendor_profile_application=report
        doc.undo();self.assertIsNone(doc.vendor_profile_application)
        doc.redo();self.assertTrue(doc.vendor_profile_application['generated'])
        doc.edit(140,b'X');self.assertTrue(doc.vendor_profile_application['modified_after_profile'])
        self.assertEqual(doc.vendor_profile_application['result_sha256'],hashlib.sha256(doc.spd.data).hexdigest())

    def test_stale_family_and_opaque_template(self):
        self.catalog.add(hp(3,999))
        with self.assertRaisesRegex(ValueError,'changed'):self.catalog.hp_profile_options(self.profile['id'],self.target)
        # A separate clean collection validates the explicit opaque copy boundaries.
        cat=Catalog(Path(self.temp.name)/'opaque')
        raw=bytearray(hp(1,101));raw[150:158]=b'VENDOR!!';raw[190:194]=b'TAIL'
        donor=cat.add(raw);cat.add(hp(2,102))
        key=cat.hp_analysis(donor['sha256'])['families'][0]['key']
        profile=cat.create_hp_profile(donor['sha256'],key,'Opaque',True)
        result,_=cat.preview_hp_profile(profile['id'],self.target,'00000069')
        self.assertEqual(result[150:176],raw[150:176]);self.assertEqual(result[184:],raw[184:])
        self.assertEqual(result[117:150],self.target[117:150])

    def test_vendor_metadata_observations_do_not_invent_sticker_identity(self):
        raw=bytearray(hp(1,101));raw[190:201]=b'DELL MODULE'
        info=vendor_metadata(raw)
        self.assertTrue(info['hpt_signature_present'])
        self.assertEqual(info['possible_oem'],'HP/HPE-compatible HPT layout')
        self.assertTrue(any(hint['vendor']=='Dell' for hint in info['text_hints']))
        self.assertNotIn('oem_part_number',info)

    def test_even_coefficient_multiple_solutions_are_retained(self):
        cat=Catalog(Path(self.temp.name)/'multiple')
        donor=cat.add(hp(102,1));cat.add(hp(104,2))
        family=cat.hp_analysis(donor['sha256'])['families'][0]['key']
        profile=cat.create_hp_profile(donor['sha256'],family,'Two solutions')
        raw=bytearray(hp(106,0));raw[176:184]=b'\0'*8
        options=cat.hp_profile_options(profile['id'],raw)
        self.assertEqual(set(options['candidates']),{'00000003','80000003'})
