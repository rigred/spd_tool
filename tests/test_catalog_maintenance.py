# SPDX-License-Identifier: MIT
import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from spd_catalog import Catalog
from tests.test_spd import ddr3
from tests.test_containers import FIXTURES


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.catalog=Catalog(self.root/'collection')
    def tearDown(self):self.temp.cleanup()
    def test_remove_restore_retains_external_source_and_metadata(self):
        source=self.root/'external.thp';source.write_bytes((FIXTURES/'geil.thp').read_bytes())
        row=self.catalog.import_files([source])[0][0];sha=row['sha256'];self.catalog.set_oem_details(sha,{'oem_name':'HP','part_number':'123456-001'})
        sources=self.catalog.import_sources(sha);plan=self.catalog.removal_plan([sha]);report=self.catalog.remove_images(plan)
        self.assertFalse(self.catalog.rows());self.assertTrue(source.exists());self.assertFalse((self.catalog.root/row['path']).exists());self.assertEqual(len(self.catalog.trash_entries()),1)
        self.catalog.restore_trash(report['trash_id']);self.assertEqual(len(self.catalog.rows()),1);self.assertEqual(self.catalog.oem_details(sha)['part_number'],'123456-001');self.assertEqual(self.catalog.import_sources(sha),sources)
        self.assertTrue((self.catalog.root/row['path']).exists());self.assertFalse(self.catalog.trash_entries())
    def test_dependent_profiles_recipes_and_families_require_explicit_inclusion(self):
        sha=self.catalog.add(ddr3())['sha256']
        with self.catalog.connect() as db:
            db.execute('INSERT INTO vendor_profiles VALUES (?,?)',('profile',json.dumps(dict(donor_sha256=sha))))
            db.execute('INSERT INTO merge_recipes VALUES (?,?,?)',('recipe','test',json.dumps(dict(sources={sha:'test'}))))
            db.execute('INSERT INTO families VALUES (?,?)',('family',json.dumps(dict(evidence_sha256=[sha]))))
        plan=self.catalog.removal_plan([sha]);self.assertTrue(all(v==1 for v in plan['dependents'].values()))
        with self.assertRaisesRegex(ValueError,'dependencies'):self.catalog.remove_images(plan)
        report=self.catalog.remove_images(plan,True);self.assertFalse(self.catalog.vendor_profiles());self.assertFalse(self.catalog.recipes());self.assertFalse(self.catalog.saved_families())
        self.catalog.restore_trash(report['trash_id']);self.assertEqual(len(self.catalog.vendor_profiles()),1);self.assertEqual(len(self.catalog.recipes()),1);self.assertEqual(len(self.catalog.saved_families()),1)
    def test_stale_review_and_changed_payload_do_not_remove_data(self):
        row=self.catalog.add(ddr3());plan=self.catalog.removal_plan([row['sha256']]);self.catalog.set_oem_details(row['sha256'],dict(notes='changed'))
        with self.assertRaisesRegex(ValueError,'changed'):self.catalog.remove_images(plan)
        self.assertEqual(len(self.catalog.rows()),1)
    def test_shared_original_is_kept_until_last_associated_image_is_removed(self):
        first=self.catalog.import_files([FIXTURES/'geil.thp'])[0][0];source=self.catalog.import_sources(first['sha256'])[0]
        second=bytearray(self.catalog.data(first['sha256']));second[150]^=1;other=self.catalog.add(second)
        with self.catalog.connect() as db:db.execute('INSERT INTO imports VALUES (?,?,?,?)',(other['sha256'],'shared','shared',json.dumps(source)))
        plan=self.catalog.removal_plan([first['sha256']]);self.assertFalse(any(f['path']==source['original_path'] for f in plan['files']))
        self.catalog.remove_images(plan);self.assertTrue((self.catalog.root/source['original_path']).exists())
    def test_filesystem_failure_rolls_back_moves_and_database(self):
        row=self.catalog.add(ddr3());plan=self.catalog.removal_plan([row['sha256']])
        with patch('spd_catalog_maintenance.os.replace',side_effect=OSError('simulated move failure')):
            with self.assertRaises(OSError):self.catalog.remove_images(plan)
        self.assertEqual(len(self.catalog.rows()),1);self.assertTrue((self.catalog.root/row['path']).exists());self.assertFalse(self.catalog.trash_entries())
    def test_restore_refuses_changed_metadata_or_payload(self):
        row=self.catalog.add(ddr3());report=self.catalog.remove_images(self.catalog.removal_plan([row['sha256']]))
        quarantined=self.catalog.root/'.trash'/report['trash_id']/'files'/row['path'];quarantined.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'verification'):self.catalog.restore_trash(report['trash_id'])
        self.assertFalse(self.catalog.rows())
    def test_empty_trash_is_explicit_and_never_touches_external_files(self):
        external=self.root/'outside.bin';external.write_bytes(ddr3());row=self.catalog.import_files([external])[0][0]
        result=self.catalog.remove_images(self.catalog.removal_plan([row['sha256']]));self.catalog.empty_trash([result['trash_id']])
        self.assertTrue(external.exists());self.assertFalse(self.catalog.trash_entries())
        with self.assertRaises(ValueError):self.catalog.restore_trash(result['trash_id'])
    def test_trash_can_be_restored_after_moving_the_collection(self):
        import shutil
        row=self.catalog.add(ddr3());report=self.catalog.remove_images(self.catalog.removal_plan([row['sha256']]))
        moved=self.root/'moved';shutil.move(str(self.catalog.root),moved);catalog=Catalog(moved)
        catalog.restore_trash(report['trash_id']);self.assertEqual(catalog.data(row['sha256']),ddr3())
    def test_restore_does_not_overwrite_reimported_annotation_changes(self):
        row=self.catalog.add(ddr3());sha=row['sha256'];self.catalog.set_oem_details(sha,dict(notes='before removal'));report=self.catalog.remove_images(self.catalog.removal_plan([sha]))
        self.catalog.add(ddr3());self.catalog.set_oem_details(sha,dict(notes='new annotation'))
        with self.assertRaisesRegex(ValueError,'overwrite'):self.catalog.restore_trash(report['trash_id'])
        self.assertEqual(self.catalog.oem_details(sha)['notes'],'new annotation')

    def test_trash_with_only_remaining_active_copy_must_be_recovered_first(self):
        row=self.catalog.add(ddr3());plan=self.catalog.removal_plan([row['sha256']]);report=self.catalog.remove_images(plan)
        # Simulate a process exit after file moves but before database commit.
        with self.catalog.connect() as db:
            original=plan['tables']['images'][0];db.execute('INSERT INTO images VALUES (?,?,?)',(original['sha'],original['path'],original['metadata']))
        with self.assertRaisesRegex(ValueError,'remaining copy'):self.catalog.empty_trash([report['trash_id']])
        self.catalog.restore_trash(report['trash_id']);self.assertEqual(self.catalog.data(row['sha256']),ddr3())

    def test_missing_external_references_cleanup_preserves_managed_images(self):
        source=self.root/'source.bin';source.write_bytes(ddr3());row=self.catalog.import_files([source])[0][0];self.catalog.add(ddr3(),'editor snapshot');source.unlink()
        review=self.catalog.missing_references();self.assertEqual(len(review['missing']),1);self.assertEqual(review['missing'][0]['source'],str(source))
        result=self.catalog.cleanup_references(review);self.assertEqual(result['references_removed'],1);self.assertEqual(result['images_removed'],0);self.assertEqual(self.catalog.data(row['sha256']),ddr3());self.assertFalse(self.catalog.missing_references()['missing'])
    def test_restored_external_reference_is_not_removed_from_stale_review(self):
        source=self.root/'source.bin';source.write_bytes(ddr3());self.catalog.import_files([source]);source.unlink();review=self.catalog.missing_references();source.write_bytes(ddr3())
        self.assertEqual(self.catalog.cleanup_references(review)['references_removed'],0)
    def test_missing_managed_snapshot_can_be_removed_without_deleting_external_source(self):
        row=self.catalog.add(ddr3());(self.catalog.root/row['path']).unlink();plan=self.catalog.removal_plan([row['sha256']]);self.assertEqual(plan['files'][0]['state']['kind'],'missing')
        self.catalog.remove_images(plan);self.assertFalse(self.catalog.rows())


@unittest.skipUnless(os.environ.get('DISPLAY'),'No graphical display')
class LibraryLayoutTkTests(unittest.TestCase):
    def test_library_has_top_level_mode_and_expanding_scrollable_list(self):
        import tkinter as tk
        from spd_editor import SPDEditor
        with tempfile.TemporaryDirectory() as tmp:
            root=tk.Tk()
            try:
                app=SPDEditor(root);app.catalog.catalog=Catalog(tmp)
                for i in range(80):
                    data=bytearray(ddr3());data[122:126]=i.to_bytes(4,'big');app.catalog.catalog.add(data)
                app.catalog.refresh();app.show_library();root.update()
                self.assertNotIn(str(app.catalog_tab),app._nav_tabs);self.assertFalse(app.navigation.winfo_ismapped());self.assertFalse(app.editor_toolbar.winfo_ismapped())
                self.assertGreater(app.catalog.table.winfo_height(),350);app.catalog.table.yview_moveto(1);root.update();self.assertGreater(app.catalog.table.yview()[0],0)
                app.show_module();root.update();self.assertTrue(app.navigation.winfo_ismapped());self.assertTrue(app.editor_toolbar.winfo_ismapped())
            finally:root.destroy()
    def test_gui_remove_review_and_cleanup(self):
        import tkinter as tk
        from tkinter import ttk
        from spd_editor import SPDEditor
        with tempfile.TemporaryDirectory() as tmp:
            root=tk.Tk()
            try:
                app=SPDEditor(root);panel=app.catalog;panel.catalog=Catalog(Path(tmp)/'collection');source=Path(tmp)/'source.bin';source.write_bytes(ddr3());row=panel.catalog.import_files([source])[0][0];panel.refresh();panel.table.selection_set(row['sha256'])
                source.unlink();dialog=panel.cleanup_missing()
                next(w for w in dialog.winfo_children() if isinstance(w,ttk.Button)).invoke();self.assertFalse(panel.catalog.missing_references()['missing'])
                dialog=panel.remove_selected();next(w for w in dialog.winfo_children() if isinstance(w,ttk.Button)).invoke();self.assertFalse(panel.catalog.rows());self.assertEqual(len(panel.catalog.trash_entries()),1)
            finally:root.destroy()
