# SPDX-License-Identifier: MIT
import copy,hashlib,io,json,os,stat,subprocess,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
from spd_containers import decode_image,read_inputs,zip_members,exclusive_output,sha256
from spd_bundle import write_bundle,decode_bundle_members
from spd_conversion import convert_files
from spd_library import load_spd_file
from spd_catalog import Catalog
from spd_editor import EditorDocument
from tests.test_spd import ddr3,ROOT

FIXTURES=Path(__file__).parent/'fixtures'/'thp'
try:
    import py7zr
except ImportError:py7zr=None


def thp(data):return b'\x04TH20'+bytes(v^i for i,v in enumerate(data))+b'\x13'


def bundle_members(record):
    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)/'test.spdz';write_bundle([record],path)
        with zipfile.ZipFile(path) as z:return {name:z.read(name) for name in z.namelist()}


def modify_manifest(members,mutate):
    members=dict(members);manifest=json.loads(members['manifest.json']);mutate(manifest)
    raw=json.dumps(manifest).encode();members['manifest.json']=raw;members['manifest.sha256']=(sha256(raw)+'  manifest.json\n').encode();return members


class THPTests(unittest.TestCase):
    def test_supplied_samples_exact_payload_hashes_and_identity(self):
        cases=[('geil','1cd560bc9f29f76a56a5c8f5d35ef680d93964bdf22bcb568f54f5cb3beeab50','CL9-9-9 DDR3-1333','VALID'),('tigo','946ac4fef4860702554399dbb7a62d6036ce11a3b816582b3959ebb827567bbc','DDR3-NB-8G-1600','VALID'),('avexir','8e993bb360da2e0617ffa448ce5028cfc9ee29fd8f2cff6a66318133699a5420','DDR3-2400 CL10 8GB','INVALID')]
        for name,digest,part,integrity in cases:
            with self.subTest(name=name):
                spd=load_spd_file(FIXTURES/(name+'.thp'));self.assertEqual(sha256(spd.data),digest);self.assertEqual(len(spd.data),256)
                self.assertEqual(spd.decoded_data['manufacturing']['module_part_number'],part);self.assertEqual(spd.decoded_data['crc_info']['status'],integrity)
        self.assertEqual(load_spd_file(FIXTURES/'avexir.thp').data[11],0)
    def test_thp_decode_is_reversible_and_does_not_repair(self):
        raw=(FIXTURES/'avexir.thp').read_bytes();record=decode_image(raw,'avexir.thp')
        self.assertEqual(thp(record['data']),raw);self.assertEqual(record['original'],raw);self.assertIn('No independently verified',record['source']['details']['container_integrity'])
    def test_signature_length_and_unknown_version_are_not_guessed(self):
        for raw in [b'\x04TH21'+bytes(257),thp(ddr3())[:-1],thp(ddr3())+b'x',ddr3()]:
            with self.assertRaises(ValueError):decode_image(raw,'bad.thp')
    def test_trailer_is_preserved_without_claiming_it_is_a_checksum(self):
        raw=thp(ddr3())[:-1]+b'\x99';record=decode_image(raw,'test.thp')
        self.assertEqual(record['data'],ddr3());self.assertEqual(record['original'],raw);self.assertEqual(record['source']['details']['trailer_hex'],'99')
    def test_magic_detection_works_without_thp_extension(self):
        self.assertEqual(decode_image(thp(ddr3()),'renamed.dat')['data'],ddr3())
    def test_rw_records_are_sequential_and_comments_are_not_spd_bytes(self):
        text='Type:DIMM SPD Address A0\\r\\nWidth:01\\r\\n'+' '.join(f'{i:02X}={v:02X}' for i,v in enumerate(ddr3()))+'\\r\\n; note: original clock assumptions\\r\\n'
        record=decode_image(text.encode(),'test.rw');self.assertEqual(record['data'],ddr3());self.assertEqual(len(record['source']['details']['comments']),1)
        for bad in [text.replace('01=','00=',1),text.replace('Width:01','Width:02'),text+'arbitrary text']:
            with self.assertRaises(ValueError):decode_image(bad.encode(),'bad.rw')
    def test_binary_conversion_preserves_invalid_crc_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'avexir.bin';report=convert_files([FIXTURES/'avexir.thp'],out=out)
            self.assertFalse(report['errors']);self.assertEqual(sha256(out.read_bytes()),'8e993bb360da2e0617ffa448ce5028cfc9ee29fd8f2cff6a66318133699a5420')
            with self.assertRaises(FileExistsError):convert_files([FIXTURES/'avexir.thp'],out=out)
            self.assertEqual(len(out.read_bytes()),256)
    def test_gui_document_cannot_overwrite_container_as_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            for extension in ('.thp','.spdz','.zip','.7z','.rw'):
                path=Path(tmp)/('output'+extension)
                with self.assertRaises(ValueError):EditorDocument(ddr3()).save(path)
                self.assertFalse(path.exists())
    def test_conversion_cli_binary_and_bundle_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'test.bin';result=subprocess.run([sys.executable,str(ROOT/'spd_tool.py'),'convert','--source',str(FIXTURES/'geil.thp'),'--out',str(out)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(len(out.read_bytes()),256)
            bundle=Path(tmp)/'test.spdz';convert_files([FIXTURES/'geil.thp'],out=bundle)
            self.assertEqual(read_inputs(bundle)[0][0]['data'],out.read_bytes())


class OpenBundleTests(unittest.TestCase):
    def test_plain_zip_manifest_and_independent_hash_verification(self):
        record=decode_image((FIXTURES/'geil.thp').read_bytes(),'geil.thp');members=bundle_members(record)
        manifest=json.loads(members['manifest.json']);entry=manifest['images'][0]
        self.assertEqual(manifest['format'],'open-spd-bundle');self.assertEqual(manifest['version'],1)
        self.assertEqual(hashlib.sha256(members[entry['file']]).hexdigest(),entry['sha256'])
        self.assertEqual(hashlib.sha256(members['manifest.json']).hexdigest().encode(),members['manifest.sha256'][:64])
        loaded=decode_bundle_members(members)[0];self.assertEqual(loaded['data'],record['data']);self.assertEqual(loaded['sources'][0]['original'],record['original'])
    def test_payload_source_and_manifest_corruption_rejected(self):
        members=bundle_members(decode_image(thp(ddr3()),'test.thp'))
        for name in ('manifest.json','manifest.sha256',*filter(lambda n:n.startswith(('images/','sources/')),members)):
            changed=dict(members);changed[name]=members[name][:-1]+bytes([members[name][-1]^1])
            with self.subTest(name=name),self.assertRaises(ValueError):decode_bundle_members(changed)
    def test_missing_unlisted_duplicates_and_invalid_versions_rejected(self):
        members=bundle_members(dict(data=ddr3(),metadata={}))
        bad=copy.copy(members);bad['unlisted.bin']=b'x'
        with self.assertRaises(ValueError):decode_bundle_members(bad)
        for change in [lambda m:m.update(version=2),lambda m:m.update(version=True),lambda m:m['images'].append(m['images'][0]),lambda m:m['images'][0].update(file='../escape.bin'),lambda m:m['images'][0].update(length=True)]:
            with self.assertRaises(ValueError):decode_bundle_members(modify_manifest(members,change))
    def test_manifest_duplicate_json_keys_and_nan_rejected(self):
        members={'manifest.json':b'{"format":"x","format":"open-spd-bundle"}'}
        with self.assertRaisesRegex(ValueError,'Duplicate JSON'):decode_bundle_members(members)
        members={'manifest.json':b'{"version": NaN}'}
        with self.assertRaisesRegex(ValueError,'Nonfinite'):decode_bundle_members(members)
    def test_metadata_and_generated_provenance_preserved(self):
        data=ddr3();provenance=dict(generated=True,result_sha256=sha256(data),kind='test fixture')
        record=dict(data=data,metadata=dict(oem=dict(oem_name='HP',part_number='123456-001'),provenance=provenance))
        loaded=decode_bundle_members(bundle_members(record))[0];self.assertEqual(loaded['metadata'],record['metadata'])
        record['metadata']['provenance']['result_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'provenance'):bundle_members(record)
    def test_partial_failure_does_not_publish_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'test.bin'
            with patch('spd_containers.os.link',side_effect=OSError('simulated publication failure')):
                with self.assertRaises(OSError):exclusive_output(path,ddr3())
            self.assertFalse(path.exists());self.assertEqual(list(Path(tmp).iterdir()),[])
    def test_future_generation_raw_images_can_be_archived_without_decoder_claims(self):
        data=bytearray(512);data[2]=12;loaded=decode_bundle_members(bundle_members(dict(data=data,metadata={})))
        self.assertEqual(loaded[0]['data'],bytes(data))
    def test_unknown_memory_type_is_archived_without_inventing_a_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw=bytearray(256);raw[2]=0;path=Path(tmp)/'unsupported.spdz';write_bundle([dict(data=raw,metadata={})],path)
            rows,errors=Catalog(Path(tmp)/'collection').import_files([path]);self.assertFalse(errors);self.assertEqual(len(rows),1)
            self.assertFalse(rows[0]['editable']);self.assertEqual(rows[0]['memory'],'Unknown(0x00)');self.assertEqual(rows[0]['integrity'],'UNKNOWN')


class CollectionContainerTests(unittest.TestCase):
    def test_bulk_thp_conversion_keeps_originals_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog=Catalog(Path(tmp)/'collection');paths=list(FIXTURES.glob('*.thp'));before={p:p.read_bytes() for p in paths}
            rows,errors=catalog.import_files(paths);self.assertEqual(len(rows),3);self.assertFalse(errors)
            catalog.import_files(paths);self.assertEqual(len(catalog.rows()),3)
            for row in rows:
                self.assertTrue(row['path'].endswith('.bin'));self.assertEqual(len(catalog.data(row['sha256'])),256)
                sources=catalog.import_sources(row['sha256']);self.assertEqual(len(sources),1);self.assertTrue((catalog.root/sources[0]['original_path']).exists())
            self.assertEqual(before,{p:p.read_bytes() for p in paths})
    def test_collection_bundle_roundtrip_retains_oem_and_generated_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog=Catalog(Path(tmp)/'one');row=catalog.add(ddr3());sha=row['sha256'];catalog.set_oem_details(sha,dict(oem_name='HP',part_number='123456-001'))
            catalog.mark_profile_generated(sha,dict(generated=True,result_sha256=sha,kind='test'))
            bundle=Path(tmp)/'collection.spdz';catalog.export_bundle([sha],bundle)
            other=Catalog(Path(tmp)/'two');rows,errors=other.import_files([bundle]);self.assertFalse(errors);self.assertEqual(other.oem_details(sha)['part_number'],'123456-001');self.assertTrue(other.rows()[0]['generated_vendor_profile'])
    def test_generic_zip_partial_failure_is_reported_and_valid_members_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'mixed.zip'
            with zipfile.ZipFile(path,'w') as z:z.writestr('good.thp',thp(ddr3()));z.writestr('bad.thp',b'bad')
            catalog=Catalog(Path(tmp)/'collection');rows,errors=catalog.import_files([path]);self.assertEqual(len(rows),1);self.assertEqual(len(errors),1)
    def test_archive_traversal_symlinks_and_duplicate_members_are_rejected(self):
        for name,link in [('../bad.thp',False),('bad\\path.thp',False),('/absolute.thp',False),('link.thp',True)]:
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w') as z:
                item=zipfile.ZipInfo(name)
                if link:item.external_attr=(stat.S_IFLNK|0o777)<<16
                z.writestr(item,thp(ddr3()))
            with self.assertRaises(ValueError):zip_members(stream.getvalue())
    def test_spdz_without_manifest_is_not_a_generic_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'bad.spdz'
            with zipfile.ZipFile(path,'w') as z:z.writestr('good.bin',ddr3())
            with self.assertRaisesRegex(ValueError,'manifest'):read_inputs(path)
    @unittest.skipUnless(py7zr,'Optional py7zr not installed')
    def test_supplied_7z_import_archives_bad_memory_type_and_decodes_rw(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog=Catalog(Path(tmp)/'collection');rows,errors=catalog.import_files([FIXTURES/'mixed-spds.7z'])
            self.assertEqual(len(rows),13);self.assertFalse(errors);self.assertEqual(len(catalog.rows()),11)
            archived=[r for r in rows if not r['editable']];self.assertEqual(len(archived),1);self.assertEqual(archived[0]['memory'],'Unknown(0x00)')
            self.assertTrue(any(row['import_format']=='rw-everything' for row in rows))

@unittest.skipUnless(os.environ.get('DISPLAY'),'No graphical display')
class ContainerTkTests(unittest.TestCase):
    def test_thp_save_as_and_open_bundle_export_preserve_original(self):
        import tkinter as tk
        from spd_editor import SPDEditor
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'source.thp';original=(FIXTURES/'avexir.thp').read_bytes();source.write_bytes(original)
            root=tk.Tk()
            try:
                app=SPDEditor(root);app.open_path(source);self.assertFalse(app.fix_on_save.get())
                out=Path(tmp)/'converted.bin'
                with patch('tkinter.filedialog.asksaveasfilename',return_value=str(out)):self.assertTrue(app.save())
                self.assertEqual(source.read_bytes(),original);self.assertEqual(sha256(out.read_bytes()),'8e993bb360da2e0617ffa448ce5028cfc9ee29fd8f2cff6a66318133699a5420')
                bundle=Path(tmp)/'editor.spdz'
                with patch('tkinter.filedialog.asksaveasfilename',return_value=str(bundle)):app.export_bundle()
                self.assertEqual(read_inputs(bundle)[0][0]['data'],out.read_bytes())
                generic=Path(tmp)/'single-raw.zip'
                with zipfile.ZipFile(generic,'w') as z:z.writestr('raw.bin',out.read_bytes())
                app.fix_on_save.set(True);app.open_path(generic);self.assertFalse(app.fix_on_save.get())
            finally:root.destroy()
    def test_gui_bulk_import_files_and_export_selection(self):
        import tkinter as tk,time
        from spd_editor import SPDEditor
        with tempfile.TemporaryDirectory() as tmp:
            root=tk.Tk()
            try:
                app=SPDEditor(root);panel=app.catalog;panel.catalog=Catalog(Path(tmp)/'collection')
                with patch('tkinter.filedialog.askopenfilenames',return_value=[str(FIXTURES/'geil.thp'),str(FIXTURES/'tigo.thp')]):panel.import_files()
                deadline=time.monotonic()+5
                while app.hardware.busy and time.monotonic()<deadline:root.update();time.sleep(.01)
                self.assertFalse(app.hardware.busy);self.assertEqual(len(panel.table.get_children()),2)
                panel.table.selection_set(panel.table.get_children());out=Path(tmp)/'selection.spdz'
                with patch('tkinter.filedialog.asksaveasfilename',return_value=str(out)):panel.export_bundle()
                self.assertEqual(len(read_inputs(out)[0]),2)
            finally:root.destroy()

class BundleMetadataRegressionTests(unittest.TestCase):
    def test_unknown_metadata_survives_collection_reexport_without_nested_growth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);bundle=root/'initial.spdz';write_bundle([dict(data=ddr3(),metadata={'custom_chip_notes':{'part':'observed-chip'}})],bundle)
            for i in range(3):
                catalog=Catalog(root/f'collection-{i}');rows,errors=catalog.import_files([bundle]);self.assertFalse(errors)
                bundle=root/f'roundtrip-{i}.spdz';catalog.export_bundle([rows[0]['sha256']],bundle)
                metadata=read_inputs(bundle)[0][0]['metadata'];self.assertEqual(metadata['imported_metadata'],[{'custom_chip_notes':{'part':'observed-chip'}}])
    def test_invalid_imported_oem_metadata_does_not_create_unlabelled_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'invalid.spdz';write_bundle([dict(data=ddr3(),metadata=dict(oem=dict(part_number=123)))],path)
            catalog=Catalog(Path(tmp)/'collection');rows,errors=catalog.import_files([path]);self.assertFalse(rows);self.assertTrue(errors);self.assertFalse(catalog.rows())
    def test_archive_member_size_limit_is_enforced_before_conversion(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('large.bin',b'\0'*(1024*1024+1))
        with self.assertRaisesRegex(ValueError,'limit'):zip_members(stream.getvalue())
