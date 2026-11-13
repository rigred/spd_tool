# SPDX-License-Identifier: MIT
"""Packaged runtime checks using synthetic data in a temporary directory only."""
import binascii
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
from spd_version import VERSION


def self_test(gui=False):
    import py7zr
    import serial
    import serial.tools.list_ports
    from spd_catalog import Catalog
    from spd_containers import read_inputs
    from spd_conversion import convert_files
    from spd_integrity import repair_integrity
    from spd_thp import decode_thp
    registry=json.loads(Path(__file__).with_name('hp_families.json').read_text(encoding='utf-8'))
    if not registry:raise ValueError('Bundled HP family registry is empty')
    checks=['HP family registry','pyserial and platform port-discovery imports']
    if sys.platform=='win32':
        from spd_pawnio import MODULES,module_bytes
        for profile in MODULES:module_bytes(profile)
        checks.append('Pinned Windows PawnIO SMBus modules (no driver/hardware access)')
    # Synthetic DDR3 identity/timing fixture; not a hardware configuration.
    legacy=bytearray(256)
    for i,v in {0:0x12,1:0x13,2:11,3:2,4:4,5:0x21,6:2,7:9,8:11,9:0x11,10:1,11:8,12:10,14:0xA0,16:110,17:120,18:110,19:48,20:110,21:0x11,22:24,23:134,25:5,26:60,27:60,28:1,117:0x80,118:0x2C,120:0x24,121:0x12}.items():legacy[i]=v
    legacy[128:146]=b'SPD-SELF-TEST     '
    # Keep the byte length fixed even if this label changes.
    if len(legacy)!=256:raise ValueError('Self-test fixture length changed')
    legacy=repair_integrity(legacy)
    modern=bytearray(512);modern[:4]=b'\x23\x11\x0C\x02'
    modern[126:128]=binascii.crc_hqx(modern[:126],0).to_bytes(2,'little')
    state=471;cipher=bytearray()
    for value in modern:
        encrypted=value^(state>>8);cipher.append(encrypted);state=(state+encrypted+12719)&65535
    wrapper=b'\x04TH43'+cipher+b'\x13'
    if decode_thp(wrapper)[0]!=modern:raise ValueError('TH43 decode mismatch')
    checks.append('TH43 feedback container conversion')
    with tempfile.TemporaryDirectory(prefix='spd-release-check-') as temp:
        directory=Path(temp)/'SPD é collection';directory.mkdir()
        legacy_file=directory/'legacy.bin';legacy_file.write_bytes(legacy)
        modern_file=directory/'modern.thp';modern_file.write_bytes(wrapper)
        archive=directory/'sources.7z'
        with py7zr.SevenZipFile(archive,'w') as output:output.write(modern_file,arcname='modern.thp')
        decoded,errors=read_inputs(archive)
        if errors or len(decoded)!=1 or decoded[0]['data']!=modern:raise ValueError('7z codec import mismatch')
        checks.append('7z write/read and THP extraction')
        catalog=Catalog(directory/'library');rows,errors=catalog.import_files([legacy_file,archive])
        if errors or len(rows)!=2 or sum(r['editable'] for r in rows)!=1:raise ValueError('SQLite library import mismatch')
        bundle=directory/'library.spdz';catalog.export_bundle([r['sha256'] for r in rows],bundle)
        other=Catalog(directory/'relocated library');imported,errors=other.import_files([bundle])
        if errors or {other.data(r['sha256']) for r in imported}!={legacy,bytes(modern)}:raise ValueError('Open bundle roundtrip mismatch')
        exported=directory/'export.bin';result=convert_files([modern_file],out=exported)
        if result['errors'] or exported.read_bytes()!=modern:raise ValueError('Raw binary export mismatch')
        checks+=['SQLite library with editable and archival images','Unicode file paths','Open bundle, source retention and binary export']
        if gui:
            import tkinter as tk
            from spd_editor import SPDEditor
            previous=os.environ.get('SPD_TOOL_CONFIG_DIR');os.environ['SPD_TOOL_CONFIG_DIR']=str(directory/'preferences')
            root=None
            try:
                root=tk.Tk();app=SPDEditor(root);app.open_path(legacy_file);app.catalog.catalog=catalog;app.catalog.refresh();app.show_library();root.update()
                original=app.document;row=next(r for r in rows if not r['editable']);app.catalog.table.selection_set(row['sha256'])
                inspector=app.catalog.open_selected();root.update()
                if app.document is not original or not inspector.winfo_exists():raise ValueError('Read-only inspector altered the editor')
                inspector.destroy();root.update();checks.append('Tk editor, library and read-only inspector')
            finally:
                if root is not None:root.destroy()
                if previous is None:os.environ.pop('SPD_TOOL_CONFIG_DIR',None)
                else:os.environ['SPD_TOOL_CONFIG_DIR']=previous
    return dict(status='PASS',version=VERSION,frozen=bool(getattr(sys,'frozen',False)),
                python=platform.python_version(),platform=platform.platform(),architecture=platform.machine(),
                py7zr=py7zr.__version__,pyserial=serial.__version__,checks=checks,hardware_accessed=False)
