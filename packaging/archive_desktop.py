# SPDX-License-Identifier: MIT
"""Archive a verified native build, preserving Linux executable permissions."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys
import tarfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def archive(directory=None,output=None):
    sys.path.insert(0,str(ROOT))
    from spd_version import VERSION
    app=Path(directory or ROOT/'dist/SPDTool').resolve();output=Path(output or ROOT/'release-assets');output.mkdir(parents=True,exist_ok=True)
    platform_name={'win32':'windows','linux':'linux'}.get(sys.platform)
    if platform_name is None:raise ValueError('Release archiver currently targets Windows and Linux')
    if platform.machine().lower() not in ('amd64','x86_64'):raise ValueError('This release matrix targets x86-64')
    report=ROOT/'dist/validation/frozen-check.json'
    if not report.is_file():raise ValueError('Run packaging/verify_desktop.py before archiving a release')
    verified=json.loads(report.read_text(encoding='utf-8'));executable=app/('SPDTool.exe' if sys.platform=='win32' else 'SPDTool')
    if (verified.get('status')!='PASS' or not verified.get('frozen') or not verified.get('cli_verified') or verified.get('version')!=VERSION
            or verified.get('bundle_manifest_sha256')!=hashlib.sha256((app/'SHA256SUMS').read_bytes()).hexdigest()
            or verified.get('executable_sha256')!=hashlib.sha256(executable.read_bytes()).hexdigest()):raise ValueError('Build changed or frozen verification is missing; run packaging/verify_desktop.py again')
    listed=set()
    for line in (app/'SHA256SUMS').read_text(encoding='utf-8').splitlines():
        expected,name=line.split('  ',1);path=(app/name).resolve()
        if name in listed or app not in path.parents or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise ValueError('Build file failed checksum verification: '+name)
        listed.add(name)
    if listed!={p.relative_to(app).as_posix() for p in app.rglob('*') if p.is_file() and p!=app/'SHA256SUMS'}:raise ValueError('Unexpected or missing build files; rebuild and verify the application')
    target=output/(f'SPDTool-{VERSION}-{platform_name}-x86_64'+('.zip' if platform_name=='windows' else '.tar.gz'))
    if target.exists():raise ValueError('Archive already exists; choose a clean output directory')
    if platform_name=='windows':
        with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
            for path in sorted(app.rglob('*')):
                if path.is_file():z.write(path,'SPDTool/'+path.relative_to(app).as_posix())
            z.write(report,'validation/frozen-check.json')
    else:
        with tarfile.open(target,'w:gz') as tar:tar.add(app,arcname='SPDTool');tar.add(report,arcname='validation/frozen-check.json')
    checksum=hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_name(target.name+'.sha256').write_text(checksum+'  '+target.name+'\n',encoding='utf-8')
    print(target)
    return target


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory');parser.add_argument('--output');args=parser.parse_args();archive(args.directory,args.output)
