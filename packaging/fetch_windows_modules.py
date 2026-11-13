# SPDX-License-Identifier: MIT
"""Fetch hash-pinned official PawnIO SMBus modules and corresponding sources."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import sys
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]
RELEASE_URL='https://github.com/namazso/PawnIO.Modules/releases/download/0.2.11/release_0_2_11.zip'
RELEASE_SHA='43608cb89bc84247fef1368a139013f7d043e17db6d6c8dfc9b46bf0905a81f4'
SOURCE_COMMIT='52a7e536dff3e53c96917a28caac5e0fa6510696'
SOURCE_URL='https://github.com/namazso/PawnIO.Modules/archive/'+SOURCE_COMMIT+'.zip'
SOURCE_SHA='3766588abec0a353aa8824a1f138a443a4e54c62a38eec30b2d44d770c59e62a'


def payload(url,expected,local=None):
    if local:
        path=Path(local)
        if path.stat().st_size>8*1024*1024:raise ValueError('Module archive exceeds 8 MiB')
        data=path.read_bytes()
    else:
        with urllib.request.urlopen(url,timeout=30) as response:data=response.read(8*1024*1024+1)
    if len(data)>8*1024*1024 or hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Official PawnIO archive failed SHA-256 verification: '+url)
    return data


def fetch(destination=None,archive=None,source_archive=None):
    sys.path.insert(0,str(ROOT))
    from spd_containers import exclusive_output
    from spd_pawnio import MODULES,MODULE_RELEASE,module_bytes
    binary=payload(RELEASE_URL,RELEASE_SHA,archive);source=payload(SOURCE_URL,SOURCE_SHA,source_archive)
    outputs={}
    with zipfile.ZipFile(io.BytesIO(binary)) as z:
        for name,expected,_,_ in MODULES.values():
            if z.getinfo(name).file_size>1024*1024:raise ValueError('Oversized module')
            data=z.read(name)
            if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Module payload hash mismatch: '+name)
            outputs[name]=data
        outputs['COPYING']=z.read('COPYING')
    outputs['SOURCE.zip']=source
    outputs['ORIGIN.json']=(json.dumps(dict(release=MODULE_RELEASE,release_url=RELEASE_URL,release_sha256=RELEASE_SHA,source_url=SOURCE_URL,source_sha256=SOURCE_SHA,source_commit=SOURCE_COMMIT),indent=2)+'\n').encode()
    destination=Path(destination or ROOT/'resources/windows/PawnIO')
    if destination.is_symlink():raise ValueError('Module output must not be a symbolic link')
    destination.mkdir(parents=True,exist_ok=True)
    for name,data in outputs.items():
        target=destination/name
        try:exclusive_output(target,data)
        except FileExistsError:
            if target.is_symlink() or target.read_bytes()!=data:raise ValueError('Existing module file differs: '+str(target))
    for profile in MODULES:module_bytes(profile,destination)
    print('Verified official PawnIO SMBus modules and corresponding sources: '+str(destination))
    return destination


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output');parser.add_argument('--archive',help='Offline official release ZIP');parser.add_argument('--source-archive',help='Offline matching source ZIP')
    args=parser.parse_args();fetch(args.output,args.archive,args.source_archive)
