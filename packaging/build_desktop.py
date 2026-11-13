# SPDX-License-Identifier: MIT
"""Build a relocatable desktop directory on its target OS and architecture."""
import argparse
from datetime import datetime,timezone
import hashlib
import importlib.metadata as metadata
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import sysconfig


def build(output=None,console=False):
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root))
    from spd_version import VERSION
    output=Path(output or root/'dist').resolve();work=root/'build'/'desktop'
    for package in ('pyinstaller','pyserial','py7zr'):
        try:metadata.version(package)
        except metadata.PackageNotFoundError as exc:raise SystemExit('Install requirements-build.txt in this Python environment first') from exc
    # --collect-all includes dynamically loaded archive codecs. Serial's native
    # backend modules also need explicit collection for a frozen application.
    command=[sys.executable,'-m','PyInstaller','--noconfirm','--clean','--noupx',
             '--console' if console else '--windowed','--onedir','--name','SPDTool','--distpath',str(output),
             '--workpath',str(work),'--specpath',str(work),
             '--collect-all','py7zr','--collect-submodules','serial',
             '--add-data',str(root/'hp_families.json')+':.',str(root/'spd_desktop.py')]
    work.mkdir(parents=True,exist_ok=True)
    if sys.platform=='win32':
        from spd_pawnio import MODULES,module_bytes,module_directory
        # Fetching is a separate explicit build step; it never installs a driver.
        for profile in MODULES:module_bytes(profile)
        windows_assets=work/'windows-modules'
        if windows_assets.exists():shutil.rmtree(windows_assets)
        windows_assets.mkdir()
        for name in [entry[0] for entry in MODULES.values()]+['COPYING','SOURCE.zip','ORIGIN.json']:
            origin=module_directory()/name
            if not origin.is_file():raise ValueError('Run packaging/fetch_windows_modules.py to include the module license and corresponding sources')
            shutil.copy2(origin,windows_assets/name)
        command[-1:-1]=['--add-data',str(windows_assets)+':resources/windows/PawnIO']
    subprocess.run(command,cwd=root,check=True)
    # On macOS the .app is the desktop artifact; on Linux/Windows it is onedir.
    app=output/('SPDTool.app' if sys.platform=='darwin' else 'SPDTool')
    documentation=app/('Contents/Resources/documentation' if sys.platform=='darwin' else 'documentation')
    documentation.mkdir(parents=True,exist_ok=True)
    shutil.copy2(root/'README.md',documentation/'README.md')
    shutil.copytree(root/'docs',documentation/'docs',dirs_exist_ok=True)
    shutil.copytree(root/'schemas',documentation/'schemas',dirs_exist_ok=True)
    shutil.copytree(root/'firmware',documentation/'firmware',dirs_exist_ok=True)
    if sys.platform=='win32':
        shutil.copytree(windows_assets,documentation/'third-party/PawnIO.Modules',dirs_exist_ok=True)
    (app/'START_HERE.txt').write_text('SPD Tool '+VERSION+'\n\nLaunch '+('SPDTool.exe' if sys.platform=='win32' else 'SPDTool')+' to open the editor.\nKeep the complete application directory together. No Python installation is required.\nStore collections in a writable folder outside the application directory.\n7z import and USB serial support are included; board drivers remain separate.\n\nDiagnostics: SPDTool --self-test --report check.json\nGUI diagnostics: SPDTool --self-test --gui-check --report gui-check.json\nCLI: SPDTool --cli --help\n\nRead documentation/docs/RELEASES.md for platform limits and build details.\n',encoding='utf-8')
    if sys.platform=='win32':
        with (app/'START_HERE.txt').open('a',encoding='utf-8') as info:info.write('\nNative motherboard SMBus requires the separately installed official signed PawnIO driver and Administrator rights. See documentation/docs/WINDOWS.md.\n')
    packages={d.metadata['Name']:d.version for d in metadata.distributions() if d.metadata.get('Name')}
    provenance=dict(version=VERSION,built_at=datetime.now(timezone.utc).isoformat(),python=platform.python_version(),
                    platform=platform.platform(),architecture=platform.machine(),libc=platform.libc_ver(),packages=dict(sorted(packages.items())),
                    source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob('*.py'))},
                    hardware_qualification=False)
    (app/'BUILD_INFO.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
    licenses=app/'licenses';licenses.mkdir(exist_ok=True);notices=[]
    for distribution in metadata.distributions():
        name=distribution.metadata.get('Name','Unknown')
        notices.append(name+' '+distribution.version+'\n'+str(distribution.metadata.get('License-Expression') or distribution.metadata.get('License') or 'See included license files')+'\n')
        for entry in distribution.files or ():
            # Preserve actual dependency license texts, not guessed summaries.
            if any(part.lower().startswith(('license','copying','notice')) for part in entry.parts):
                origin=Path(distribution.locate_file(entry))
                if origin.is_file():
                    target=licenses/name/str(entry).replace('..','_');target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(origin,target)
    python_license=Path(sysconfig.get_path('stdlib'))/'LICENSE.txt'
    if python_license.is_file():shutil.copy2(python_license,licenses/'Python-LICENSE.txt')
    # Debian-family Linux builds keep runtime copyright/license notices here.
    # Other platforms retain the upstream Python/dependency license files above.
    if sys.platform.startswith('linux'):
        python_package=f'libpython{sys.version_info.major}.{sys.version_info.minor}'
        for package in (python_package,python_package+'-stdlib','libtcl8.6','libtk8.6','libssl3t64','libzstd1','liblzma5','libbz2-1.0','libffi8','libgcc-s1','zlib1g','libexpat1','libreadline8t64','libsqlite3-0','libuuid1'):
            notice=Path('/usr/share/doc')/package/'copyright'
            if notice.is_file():shutil.copy2(notice,licenses/(package+'-copyright.txt'))
    (app/'THIRD_PARTY_NOTICES.txt').write_text('\n'.join(sorted(notices)),encoding='utf-8')
    (app/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(app).as_posix()+'\n' for p in sorted(app.rglob('*')) if p.is_file() and p.name!='SHA256SUMS'),encoding='utf-8')
    print('Built '+str(app))
    return app


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',help='Output parent directory (default: dist)')
    parser.add_argument('--console',action='store_true',help='Keep a console for CLI use on Windows')
    args=parser.parse_args();build(args.output,args.console)
