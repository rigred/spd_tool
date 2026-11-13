# SPDX-License-Identifier: MIT
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from spd_version import VERSION

ROOT=Path(__file__).resolve().parents[1]


def helper(name):
    spec=importlib.util.spec_from_file_location('spd_release_'+name,ROOT/'packaging'/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class ReleasePackagingTests(unittest.TestCase):
    def test_github_python_shell_can_import_checkout_from_temporary_script(self):
        # GitHub's shell: python writes run: into a runner-temp script. Python
        # searches that directory, not necessarily the checkout working directory.
        text=(ROOT/'.github/workflows/desktop-releases.yml').read_text()
        step=text.split('      - name: Check release tag\n',1)[1].split('      - name:',1)[0]
        code=step.split('        run: |\n',1)[1]
        code='\n'.join(line[10:] for line in code.splitlines())+'\n'
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);script=directory/'runner-temp-check.py';script.write_text(code)
            env=dict(os.environ,GITHUB_WORKSPACE=str(ROOT),RELEASE_TAG='v'+VERSION)
            result=subprocess.run([sys.executable,'-I',str(script)],cwd=ROOT,env=env,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            env['RELEASE_TAG']='v0.0.0'
            result=subprocess.run([sys.executable,'-I',str(script)],cwd=ROOT,env=env,text=True,capture_output=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('must match',result.stderr)
            env['GITHUB_WORKSPACE']=str(directory)
            result=subprocess.run([sys.executable,'-I',str(script)],cwd=ROOT,env=env,text=True,capture_output=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('missing spd_version.py',result.stderr)

    def test_windows_build_stages_only_verified_assets(self):
        build=helper('build_desktop')
        from spd_pawnio import MODULES
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'packaging').mkdir()
            for name in ('docs','schemas','firmware'):(root/name).mkdir()
            (root/'README.md').write_text('Fixture');(root/'hp_families.json').write_text('{}')
            assets=root/'official';assets.mkdir()
            expected={entry[0] for entry in MODULES.values()}|{'COPYING','SOURCE.zip','ORIGIN.json'}
            for name in expected:(assets/name).write_bytes(b'fixture')
            (assets/'PRIVATE.txt').write_text('Do not distribute unrelated files')
            def freeze(command,**kwargs):
                self.assertIn('--windowed',command);self.assertNotIn('--uac-admin',command)
                staged=root/'build/desktop/windows-modules'
                self.assertEqual({p.name for p in staged.iterdir()},expected)
                self.assertIn(str(staged)+':resources/windows/PawnIO',command)
                app=root/'output/SPDTool';app.mkdir(parents=True);(app/'SPDTool.exe').write_bytes(b'fixture')
            with patch.object(build,'__file__',str(root/'packaging/build_desktop.py')),patch.object(build.sys,'platform','win32'),patch.object(build.subprocess,'run',side_effect=freeze),patch.object(build.metadata,'version',return_value='fixture'),patch.object(build.metadata,'distributions',return_value=[]),patch.object(build.platform,'platform',return_value='Windows fixture'),patch.object(build.platform,'libc_ver',return_value=('','')),patch.object(build.sysconfig,'get_path',return_value=str(root)),patch('spd_pawnio.module_directory',return_value=assets),patch('spd_pawnio.module_bytes',return_value=b'fixture'):
                app=build.build(root/'output')
            self.assertEqual({p.name for p in (app/'documentation/third-party/PawnIO.Modules').iterdir()},expected)
            self.assertTrue((app/'SHA256SUMS').is_file())

    def test_corrupted_upstream_download_is_rejected_before_unpacking(self):
        fetch=helper('fetch_windows_modules')
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'bad.zip';path.write_bytes(b'corrupted')
            with self.assertRaisesRegex(ValueError,'SHA-256'):fetch.payload('https://example.invalid',fetch.RELEASE_SHA,path)

    def test_archive_requires_matching_runtime_verification_and_preserves_permissions(self):
        archive=helper('archive_desktop')
        with tempfile.TemporaryDirectory() as tmp,patch.object(archive.sys,'platform','linux'),patch.object(archive.platform,'machine',return_value='x86_64'):
            root=Path(tmp);app=root/'dist/SPDTool';app.mkdir(parents=True);exe=app/'SPDTool';exe.write_bytes(b'fixture');exe.chmod(0o755)
            checksum=hashlib.sha256(exe.read_bytes()).hexdigest();(app/'SHA256SUMS').write_text(checksum+'  SPDTool\n')
            validation=root/'dist/validation';validation.mkdir();report=validation/'frozen-check.json'
            report.write_text(json.dumps(dict(status='PASS',frozen=True,cli_verified=True,version=VERSION,bundle_manifest_sha256=hashlib.sha256((app/'SHA256SUMS').read_bytes()).hexdigest(),executable_sha256=checksum)))
            with patch.object(archive,'ROOT',root):
                target=archive.archive(app,root/'output')
                with tarfile.open(target) as z:
                    if os.name=='posix':self.assertEqual(z.getmember('SPDTool/SPDTool').mode&0o111,0o111)
                    else:self.assertTrue(z.getmember('SPDTool/SPDTool').isfile())
                self.assertTrue(target.with_name(target.name+'.sha256').is_file())
                exe.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError,'Build changed'):archive.archive(app,root/'different-output')
                windows=root/'windows/SPDTool';windows.mkdir(parents=True);winexe=windows/'SPDTool.exe';winexe.write_bytes(b'fixture')
                (windows/'SHA256SUMS').write_text(checksum+'  SPDTool.exe\n')
                report.write_text(json.dumps(dict(status='PASS',frozen=True,cli_verified=True,version=VERSION,bundle_manifest_sha256=hashlib.sha256((windows/'SHA256SUMS').read_bytes()).hexdigest(),executable_sha256=checksum)))
                with patch.object(archive.sys,'platform','win32'):
                    packed=archive.archive(windows,root/'windows-output')
                    with zipfile.ZipFile(packed) as z:self.assertEqual(z.read('SPDTool/SPDTool.exe'),b'fixture')
                    (windows/'unreviewed.txt').write_text('Not part of the verified build')
                    with self.assertRaisesRegex(ValueError,'Unexpected'):archive.archive(windows,root/'unsafe-output')
