# SPDX-License-Identifier: MIT
import binascii
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from spd_archive import archive_integrity
from spd_catalog import Catalog,describe
from spd_containers import decode_image,folder_inputs,read_inputs
from spd_conversion import convert_files
from spd_import_report import import_report,report_preview
from spd_library import SPD


def modern_image(memory=12):
    data=bytearray(512 if memory==12 else 1024);data[:4]=bytes((0x23,0x11,memory,2))
    m,d,s,p,end=(320,323,325,329,349) if memory==12 else (512,515,517,521,551)
    data[m:m+2]=b'\x80\xCE';data[d:d+2]=b'\x24\x12';data[s:s+4]=b'\x12\x34\x56\x78'
    data[p:end]=b'TEST-MODULE'.ljust(end-p,b' ')
    if memory==12:data[350:352]=b'\x80\xCE'
    for start,end in ([(0,126),(128,254)] if memory==12 else [(0,510)]):
        data[end:end+2]=binascii.crc_hqx(data[start:end],0).to_bytes(2,'little')
    return bytes(data)


class ModernTHPTests(unittest.TestCase):
    # Literal observations from the pinned public collection; no downloaded
    # container or proprietary executable is included in the test fixtures.
    def test_observed_prefix_vectors(self):
        cases=[('TH40',512,'23100e018124060f08690a080d0e0e0f','23110c02852100080060000301030000'),
               ('TH41',512,'23503f33056d364e3823373b3b334335','23110c03462900080060000302030000'),
               ('TH42',512,'23253f33c416363c3803373030334331','23100c02852100080040000309030000'),
               ('TH43',512,'222269944cda2e689284f62a5a8ebff1','23110c03852100080040000301030000'),
               ('TH50',1024,'515921b0f04764463843373839304360','51181280b30352000000000000000055'),
               ('TH53',1024,'31237795cdfc0f0292c4f729498cb8f2','30101202040020620000000012010700')]
        for version,length,cipher,plain in cases:
            with self.subTest(version=version):
                raw=b'\x04'+version.encode()+bytes.fromhex(cipher)+bytes(length-16)+b'\x13'
                record=decode_image(raw,'no-extension')
                self.assertEqual(record['data'][:16],bytes.fromhex(plain));self.assertEqual(len(record['data']),length)
                self.assertEqual(record['original'],raw)
                for bad in (raw[:-1],raw+b'x'):
                    with self.assertRaisesRegex(ValueError,'exactly'):decode_image(bad,'bad.thp')

    def test_modern_raw_hex_and_binary_conversion_have_identical_bytes(self):
        for memory in (12,18):
            with self.subTest(memory=memory),tempfile.TemporaryDirectory() as tmp:
                raw=modern_image(memory);source=Path(tmp)/'raw.bin';source.write_bytes(raw)
                text=Path(tmp)/'text.hex';text.write_text(' '.join(f'{v:02X}' for v in raw))
                self.assertEqual(read_inputs(text)[0][0]['data'],raw)
                out=Path(tmp)/'converted.bin';report=convert_files([text],out=out)
                self.assertFalse(report['errors']);self.assertEqual(out.read_bytes(),raw)
                self.assertFalse(report['outputs'][0]['metadata']['editable'])
                self.assertEqual(source.read_bytes(),raw)
                with self.assertRaises(ValueError):SPD(raw)

    def test_directory_sniffs_thp_signatures_and_skips_symlinks_and_managed_tree(self):
        from tests.test_containers import thp
        from tests.test_spd import ddr3
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'missing-extension').write_bytes(thp(ddr3()));(root/'renamed.tx').write_bytes(thp(ddr3()))
            (root/'notes.md').write_text('Documentation');(root/'link.thp').symlink_to(root/'missing-extension')
            managed=root/'collection';managed.mkdir();(managed/'old.thp').write_bytes(thp(ddr3()))
            self.assertEqual(len(folder_inputs(root,exclude=[managed])),2)
            catalog=Catalog(managed);rows,errors=catalog.import_files([root]);self.assertFalse(errors);self.assertEqual(len(rows),2);self.assertEqual(len(catalog.rows()),1)
            self.assertEqual(folder_inputs(managed,exclude=[managed]),[])
            archive=root/'mixed.zip'
            with zipfile.ZipFile(archive,'w') as z:z.writestr('no-extension',thp(ddr3()))
            self.assertEqual(read_inputs(archive)[0][0]['data'],ddr3())


class ArchivalCatalogTests(unittest.TestCase):
    def test_identity_metadata_and_integrity_scope(self):
        for memory in (12,18):
            with self.subTest(memory=memory):
                row=describe(modern_image(memory));self.assertFalse(row['editable']);self.assertEqual(row['part'],'TEST-MODULE')
                self.assertIn('Samsung',row['manufacturer']);self.assertEqual(row['serial'],'12345678')
                self.assertEqual(row['manufacture_date'],'2024-W12');self.assertEqual(row['integrity'],'VALID');self.assertIsNone(row['capacity_mib'])
                corrupt=bytearray(modern_image(memory));corrupt[10]^=1
                self.assertEqual(archive_integrity(corrupt)['status'],'INVALID')
        corrupt=bytearray(modern_image());corrupt[150]=1
        info=archive_integrity(corrupt);self.assertEqual(info['blocks'][0]['status'],'VALID');self.assertEqual(info['status'],'INVALID')
        with self.assertRaises(ValueError):archive_integrity(b'bad')

    def test_unknown_and_bad_identity_are_not_inferred_from_filenames(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'Samsung-DDR3.thp'
            from tests.test_containers import thp
            path.write_bytes(thp(bytes(256)));catalog=Catalog(Path(tmp)/'collection');rows,errors=catalog.import_files([path])
            self.assertFalse(errors);row=rows[0];self.assertEqual(row['memory'],'Unknown(0x00)');self.assertEqual(row['integrity'],'UNKNOWN');self.assertFalse(row['editable'])
            self.assertEqual(row['manufacturer'],'Unknown manufacturer')
        bad=bytearray(modern_image());bad[323:325]=b'\xFE\xFF';bad[329]=0x01
        row=describe(bad);self.assertIsNone(row['manufacture_date']);self.assertEqual(row['part'],'Unknown model');self.assertTrue(row['warnings'])

    def test_archive_bundle_and_submission_roundtrip_and_untrusted_editable_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog=Catalog(Path(tmp)/'one');rows=[catalog.add(modern_image(m)) for m in (12,18)]
            for row in rows:catalog.set_oem_details(row['sha256'],dict(oem_name='Test OEM',part_number='sticker-PN'))
            bundle=Path(tmp)/'modules.spdz';catalog.export_bundle([r['sha256'] for r in rows],bundle)
            other=Catalog(Path(tmp)/'two');imported,errors=other.import_files([bundle]);self.assertFalse(errors);self.assertEqual(len(imported),2)
            for row in imported:
                self.assertFalse(row['editable']);self.assertEqual(other.data(row['sha256']),catalog.data(row['sha256']))
                self.assertEqual(other.oem_details(row['sha256'])['part_number'],'sticker-PN')
            submission=other.export_submission([r['sha256'] for r in imported],Path(tmp)/'submission.zip')
            self.assertTrue(all(not r['editable'] and r['part_number']=='TEST-MODULE' for r in submission['images']))
            from spd_bundle import write_bundle
            spoofed=Path(tmp)/'spoofed.spdz';write_bundle([dict(data=modern_image(),metadata=dict(editable=True,support='Editable'))],spoofed)
            self.assertFalse(other.import_files([spoofed])[0][0]['editable'])

    def test_compact_report_retains_full_rejections_and_support_counts(self):
        rows=[dict(describe(modern_image()),sha256='a',source='source',import_format='binary')]
        errors=[dict(path=f'bad-{i}',error='Unsupported format') for i in range(1000)]
        report=import_report(rows,errors);preview=report_preview(report)
        self.assertEqual(report['archived'],1);self.assertEqual(report['unique_images'],1);self.assertEqual(report['error_groups'],{'Unsupported format':1000})
        self.assertEqual(len(report['errors']),1000);self.assertIn('bad-19:',preview);self.assertNotIn('bad-20:',preview);self.assertLess(len(preview),4000)


@unittest.skipUnless(os.environ.get('DISPLAY'),'No graphical display')
class ArchivalTkTests(unittest.TestCase):
    def test_readonly_inspector_and_exact_binary_export_preserve_editor_document(self):
        import tkinter as tk
        from spd_editor import SPDEditor,EditorDocument
        from tests.test_spd import ddr3
        with tempfile.TemporaryDirectory() as tmp:
            root=tk.Tk()
            try:
                app=SPDEditor(root);app.document=EditorDocument(ddr3());app.refresh();original=app.document
                panel=app.catalog;panel.catalog=Catalog(Path(tmp)/'collection');raw=modern_image();row=panel.catalog.add(raw);panel.refresh()
                panel.table.selection_set(row['sha256']);root.update()
                with patch.object(app,'confirm_discard') as confirm:
                    dialog=panel.open_selected();root.update();confirm.assert_not_called()
                self.assertIs(app.document,original);self.assertIn('read-only',dialog.title());dialog.destroy()
                out=Path(tmp)/'export.bin'
                with patch('tkinter.filedialog.asksaveasfilename',return_value=str(out)):panel.export_binary()
                self.assertEqual(out.read_bytes(),raw)
                panel.filters['support'].set('Read-only archive');panel.refresh();self.assertEqual(len(panel.table.get_children()),1)
                panel.filters['support'].set('Editable');panel.refresh();self.assertFalse(panel.table.get_children())
                panel.last_import_report=import_report([dict(row,source='test',import_format='binary')],[]);out=Path(tmp)/'report.json'
                with patch('tkinter.filedialog.asksaveasfilename',return_value=str(out)):panel.export_import_report()
                self.assertEqual(json.loads(out.read_text())['archived'],1)
            finally:root.destroy()


@unittest.skipUnless(os.environ.get('SPD_TEST_CORPUS'),'Set SPD_TEST_CORPUS to the pinned Unsorted-SPD-Dumps/Dumps directory')
class PublicCorpusTests(unittest.TestCase):
    def test_pinned_collection_counts_and_complete_decoded_hashes(self):
        from collections import Counter
        root=Path(os.environ['SPD_TEST_CORPUS']);counts=Counter()
        for path in folder_inputs(root):
            record=read_inputs(path)[0][0];counts[record['source']['format']]+=1
        self.assertEqual(counts,{'thaiphoon-th20':597,'thaiphoon-th40':525,'thaiphoon-th41':1826,'thaiphoon-th42':11,'thaiphoon-th43':659,'thaiphoon-th50':8,'thaiphoon-th53':115})
        for name,expected in [('Kingston KF3200C16D4-8GX (9).thp','1d4fd1113e9f1ee2b2b43278dc3bf4a474b3d01fdcdbb5e8e807a466faf2a7ee'),('RAmos RM4S8G46A1A-PGGWE1.thp','40d4492b449163063f510d56ddb86fffb8c8608cfc48c07444de56eee81ffce3'),('G.Skill F4-3200C16-16GTZSW (2).thp','522285dc9e27bdca41183a725dd9ea2466bbc0fad45a3985cc5330492618d8ae'),('SCY SM4S510888DHC.thp','1a2998bc85cc13a0a321e49c49551ca8ab5c34908d7e2f1a1cd85f806ecfdd4e'),('Undefined Undefined (36).thp','60d8b35759813f4975bae45c281c40be92bdef6a8cddc629585b17f5fa669e12'),('G.Skill F5-6000J3038F16G.thp','1a996e6d3dbb039b66978d4d7722f0181769826789a49e9730c58fa72d5603c3')]:
            data=read_inputs(root/name)[0][0]['data'];self.assertEqual(hashlib.sha256(data).hexdigest(),expected)
