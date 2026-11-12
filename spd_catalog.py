# SPDX-License-Identifier: MIT
"""Portable, content-addressed SPD collection; never edits imported originals."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import zipfile

from spd_library import SPD, load_spd_file
from spd_integrity import integrity_info
from hp_smartmemory_ident import load_registry, learn_family_from_two, compute_hpt_solutions


def safe_name(value):
    value = re.sub(r'[^A-Za-z0-9._ -]', '_', str(value)).strip(' .')[:32]
    if not value or value.split('.')[0].upper() in {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(10)),*(f'LPT{i}' for i in range(10))}:
        value = 'Unknown-' + value
    return value


def normalized(value):
    return re.sub(r'[^A-Z0-9]', '', value.upper())


class Catalog:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS images (sha TEXT PRIMARY KEY, path TEXT UNIQUE NOT NULL, metadata TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS sources (sha TEXT NOT NULL, source TEXT NOT NULL, UNIQUE(sha,source))')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(str(self.root/'library.sqlite3'))
        db.row_factory = sqlite3.Row
        try:
            with db: yield db
        finally: db.close()

    def add(self, data, source='editor'):
        data = bytes(data)
        spd = SPD(data)
        decoded = spd.decoded_data
        mfg = decoded.get('manufacturing', {})
        vendor = mfg.get('module_mfg_id', 'Unknown manufacturer')
        part = mfg.get('module_part_number', mfg.get('part_number', '')) or 'Unknown model'
        serial = str(mfg.get('serial_number', '')) or 'No serial'
        sha = hashlib.sha256(data).hexdigest()
        relative = Path('modules')/safe_name(spd.mem_type_name)/safe_name(vendor)/safe_name(part)/(safe_name(serial)[:16]+'--'+sha+'.bin')
        metadata = dict(sha256=sha, memory=spd.mem_type_name, manufacturer=vendor, part=part, serial=serial,
                        length=len(data), integrity=integrity_info(data)['status'], path=relative.as_posix())
        destination = self.root/relative
        if self.root not in destination.resolve().parents: raise ValueError('Catalog destination escapes collection')
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open('xb') as handle: handle.write(data)
        except FileExistsError:
            if destination.read_bytes() != data: raise ValueError('Existing catalog artifact failed hash verification')
        with self.connect() as db:
            db.execute('INSERT OR IGNORE INTO images VALUES (?,?,?)', (sha,relative.as_posix(),json.dumps(metadata)))
            db.execute('INSERT OR IGNORE INTO sources VALUES (?,?)',(sha,str(source)))
        return metadata

    def import_files(self, paths):
        results, errors = [], []
        for path in paths:
            try:
                path = Path(path)
                if path.is_symlink() or path.stat().st_size > 1024*1024:
                    raise ValueError('Symbolic link or file larger than 1 MiB')
                results.append(self.add(load_spd_file(path).data, str(path)))
            except (ValueError,OSError,NotImplementedError) as exc:
                errors.append(dict(path=str(path),error=str(exc)))
        return results, errors

    def rows(self, search=''):
        with self.connect() as db:
            rows = [json.loads(row['metadata']) for row in db.execute('SELECT metadata FROM images ORDER BY path')]
        return [r for r in rows if search.casefold() in ' '.join(str(v) for v in r.values()).casefold()]

    def data(self, sha):
        with self.connect() as db:
            row = db.execute('SELECT path FROM images WHERE sha=?',(sha,)).fetchone()
        if row is None: raise ValueError('Unknown catalog image')
        path = (self.root/row['path']).resolve()
        if self.root not in path.parents: raise ValueError('Catalog path escapes collection')
        if path.stat().st_size > 256: raise ValueError('Catalog artifact exceeds supported image size')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha: raise ValueError('Catalog image hash mismatch')
        return data

    def hp_analysis(self, sha, serial=None):
        data = self.data(sha)
        if data[2] != 11 or len(data)<184: raise ValueError('HPT analysis requires DDR3 with the customer block present')
        row = next(r for r in self.rows() if r['sha256']==sha)
        registry = load_registry(str(Path(__file__).with_name('hp_families.json')))
        serial = int.from_bytes(data[122:126],'big') if serial is None else serial
        families = []
        for key, family in registry.items():
            names = [family.get('name',''), *family.get('equivalents',[])]
            if normalized(row['part']) not in [normalized(name) for name in names]: continue
            if all(k in family for k in ('A','B','K')):
                families.append(dict(key=key,origin='registry',family=family))
        samples = {}
        # Exact manufacturer/model and matching module organization, not a guessed alias.
        for other in self.rows():
            if (other['manufacturer'],normalized(other['part'])) != (row['manufacturer'],normalized(row['part'])): continue
            raw = self.data(other['sha256'])
            if len(raw)<184 or raw[2]!=11 or raw[3:9]!=data[3:9] or raw[176:180]!=b'HPT\0': continue
            if integrity_info(raw)['status']!='VALID': continue
            s,h = int.from_bytes(raw[122:126],'big'),int.from_bytes(raw[180:184],'big')
            samples.setdefault(s,set()).add(h)
        conflicting = any(len(h)!=1 for h in samples.values())
        pairs = sorted((s,next(iter(h))) for s,h in samples.items())
        if not families and len(pairs)>=2 and not conflicting and row['part'] != 'Unknown model':
            # Prefer an odd serial difference: an invertible B avoids information loss.
            even = next((p for p in pairs if not p[0]&1), None)
            odd = next((p for p in pairs if p[0]&1), None)
            pair = (even,odd) if even and odd else (pairs[0],pairs[1])
            a,b,k = learn_family_from_two(*pair[0],*pair[1])
            if a or b:
                consistent = all((a*s+b*h)&0xFFFFFFFF==k for s,h in pairs)
                if consistent:
                    families.append(dict(key='local:'+sha[:12],origin='sample-consistent' if len(pairs)>=3 else 'provisional-two-sample',
                                         family=dict(A=f'0x{a:08X}',B=f'0x{b:08X}',K=f'0x{k:08X}',name=row['part'])))
        for entry in families:
            family = entry['family']
            try:
                b = int(family['B'],16)
                if not b or (b & -b)>1024: raise ValueError('Underdetermined family; more than 1024 possible solutions')
                entry['candidates'] = [f'{v:08X}' for v in compute_hpt_solutions(serial,family)]
            except (KeyError,ValueError) as exc: entry['error']=str(exc)
        return dict(part=row['part'],serial=f'{serial:08X}',distinct_samples=len(pairs),conflicting_samples=conflicting,families=families,
                    note='Two samples define a provisional relation. Additional matching samples are consistency evidence, not authentication. No image or global registry is modified.')

    def export_submission(self, hashes, destination):
        hashes = sorted(set(hashes))
        if not hashes: raise ValueError('Select images to submit')
        images = [(sha,self.data(sha)) for sha in hashes]
        # Deliberately omit absolute source paths. Raw images still contain serials/vendor data.
        manifest = dict(schema='spd-tool-submission/1',status='prepared-offline',images=[dict(sha256=s,length=len(d),file=f'images/{s}.bin') for s,d in images])
        with Path(destination).open('xb') as handle:
            with zipfile.ZipFile(handle,'w',zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('manifest.json',json.dumps(manifest,indent=2))
                for sha,data in images: archive.writestr(f'images/{sha}.bin',data)
        return manifest
