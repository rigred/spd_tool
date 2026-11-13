# SPDX-License-Identifier: MIT
"""Offline frozen-runtime verification after relocation, including Unicode paths."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def verify(directory=None,gui=False):
    directory=Path(directory or ROOT/'dist/SPDTool').resolve()
    env=dict(os.environ)
    for key in ('PYTHONPATH','PYTHONHOME','TCL_LIBRARY','TK_LIBRARY'):env.pop(key,None)
    output=ROOT/'dist/validation';output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='spd-frozen-check-') as temp:
        root=Path(temp)/'Relocated SPD é';root.mkdir();app=root/'SPDTool'
        shutil.copytree(directory,app);working=root/'empty working directory';working.mkdir()
        env['SPD_TOOL_CONFIG_DIR']=str(root/'preferences')
        executable=app/('SPDTool.exe' if sys.platform=='win32' else 'SPDTool')
        report=root/'check.json';args=[str(executable),'--self-test','--report',str(report)]
        if gui:args.append('--gui-check')
        subprocess.run(args,cwd=working,env=env,check=True,timeout=120)
        result=json.loads(report.read_text(encoding='utf-8'))
        if result['status']!='PASS' or not result['frozen']:raise ValueError('Executable did not pass its frozen runtime check')
        # Windows GUI builds have no stdout; verify CLI behavior by its output file.
        from_file=root/'source.bin';to_file=root/'converted.bin';data=bytes(128);from_file.write_bytes(data)
        subprocess.run([str(executable),'--cli','convert','--source',str(from_file),'--out',str(to_file)],cwd=working,env=env,check=True,timeout=30)
        if to_file.read_bytes()!=data:raise ValueError('Frozen CLI conversion mismatch')
        result.update(bundle_manifest_sha256=hashlib.sha256((app/'SHA256SUMS').read_bytes()).hexdigest(),executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),cli_verified=True)
        (output/'frozen-check.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('Relocated frozen runtime and CLI checks passed')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory');parser.add_argument('--gui',action='store_true');args=parser.parse_args();verify(args.directory,args.gui)
