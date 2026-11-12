# SPDX-License-Identifier: MIT
"""Portable, content-addressed SPD collection; never edits imported originals."""
from contextlib import contextmanager
from datetime import datetime, timezone
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


def label(value):
    return 'Unknown' if value is None else 'Yes' if value is True else 'No' if value is False else str(value)


def normalized(value):
    return re.sub(r'[^A-Z0-9]', '', value.upper())


def describe(data):
    spd = SPD(data)
    decoded = spd.decoded_data
    mfg, general = decoded.get('manufacturing', {}), decoded.get('general', {})
    date = mfg.get('manufacture_date')
    match = re.fullmatch(r'(\d{4})-W(\d{2})', str(date))
    year = None
    if match:
        try:
            datetime.fromisocalendar(int(match[1]), int(match[2]), 1)
            year = int(match[1])
        except ValueError: pass
    capacity = decoded.get('module_size_MiB')
    if capacity is None and decoded.get('module_size_GiB') is not None:
        capacity = decoded['module_size_GiB']*1024
    return dict(metadata_version=2, memory=spd.mem_type_name,
                manufacturer=mfg.get('module_mfg_id', 'Unknown manufacturer'),
                dram_manufacturer=mfg.get('dram_mfg_id') or 'Unknown',
                part=mfg.get('module_part_number', mfg.get('part_number', '')) or 'Unknown model',
                serial=str(mfg.get('serial_number', '')) or 'No serial',
                manufacture_date=date if year else None, manufacture_year=year,
                module_type=general.get('module_type') or 'Unknown', capacity_mib=capacity,
                data_rate_MTps=decoded.get('max_data_rate_MTps'), ranks=decoded.get('ranks'),
                ecc='ECC' if decoded.get('ecc_bits', 0) else 'Non-ECC',
                hpt_present=data[2]==11 and len(data)>=184 and data[176:180]==b'HPT\0',
                hpt_code=data[180:184].hex().upper() if data[2]==11 and len(data)>=184 and data[176:180]==b'HPT\0' else None,
                integrity=integrity_info(data)['status'], length=len(data))


class Catalog:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS images (sha TEXT PRIMARY KEY, path TEXT UNIQUE NOT NULL, metadata TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS families (id TEXT PRIMARY KEY, record TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS sources (sha TEXT NOT NULL, source TEXT NOT NULL, UNIQUE(sha,source))')
        # Backfill existing catalogs once; source paths and managed filenames remain unchanged.
        with self.connect() as db:
            for row in db.execute('SELECT sha,metadata FROM images').fetchall():
                old = json.loads(row['metadata'])
                if old.get('metadata_version') != 2:
                    old.update(describe(self.data(row['sha'])))
                    db.execute('UPDATE images SET metadata=? WHERE sha=?',(json.dumps(old),row['sha']))


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
        metadata = dict(describe(data), sha256=sha, path=relative.as_posix())
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

    def rows(self, search='', filters=None, year_from=None, year_to=None, sort='Model'):
        if year_from is not None and year_to is not None and int(year_from)>int(year_to):
            raise ValueError('Manufacturing year From must not exceed To')
        with self.connect() as db:
            rows = [json.loads(row['metadata']) for row in db.execute('SELECT metadata FROM images ORDER BY path')]
        result=[]
        for row in rows:
            if search.casefold() not in ' '.join(str(v) for v in row.values()).casefold(): continue
            if any(label(row.get(k))!=str(v) for k,v in (filters or {}).items() if v!='All'): continue
            year=row.get('manufacture_year')
            if year_from is not None and (year is None or year<int(year_from)): continue
            if year_to is not None and (year is None or year>int(year_to)): continue
            result.append(row)
        key,reverse={'Model':('part',False),'Vendor':('manufacturer',False),'Date oldest':('manufacture_date',False),
                     'Date newest':('manufacture_date',True),'Capacity':('capacity_mib',False),
                     'Speed':('data_rate_MTps',False),'Serial':('serial',False)}.get(sort,('part',False))
        known=[r for r in result if r.get(key) is not None]
        return sorted(known,key=lambda r:(r[key],r['sha256']),reverse=reverse)+[r for r in result if r.get(key) is None]

    def facets(self):
        rows=self.rows()
        keys=('manufacturer','dram_manufacturer','memory','module_type','capacity_mib','data_rate_MTps',
              'ranks','ecc','integrity','hpt_present','length','manufacture_year')
        result={key:sorted({label(r.get(key)) for r in rows}) for key in keys}
        for key in ('capacity_mib','data_rate_MTps','ranks','length','manufacture_year'):
            result[key].sort(key=lambda v:(v=='Unknown',float(v) if v!='Unknown' else 0))
        return result

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
        with self.connect() as db:
            saved = [json.loads(r['record']) for r in db.execute('SELECT record FROM families')]
        for record in saved:
            if record['manufacturer']==row['manufacturer'] and record['part_normalized']==normalized(row['part']) and record['organization']==data[3:9].hex():
                registry[record['id']] = dict(record['family'], equivalents=[row['part']])
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
                a,b,k=(int(family[c],16) for c in ('A','B','K'))
                if conflicting or any((a*s+b*h)&0xFFFFFFFF!=k for s,h in pairs):
                    raise ValueError('Current collection evidence conflicts with this family')
                if not b or (b & -b)>1024: raise ValueError('Underdetermined family; more than 1024 possible solutions')
                entry['candidates'] = [f'{v:08X}' for v in compute_hpt_solutions(serial,family)]
            except (KeyError,ValueError) as exc: entry['error']=str(exc)
        return dict(part=row['part'],serial=f'{serial:08X}',distinct_samples=len(pairs),conflicting_samples=conflicting,families=families,
                    note='Two samples define a provisional relation. Additional matching samples are consistency evidence, not authentication. No image or global registry is modified.')

    def mine_families(self):
        groups, errors = {}, []
        for row in self.rows():
            if row['memory']!='DDR3' or row['part']=='Unknown model': continue
            try:
                raw=self.data(row['sha256'])
                if len(raw)<184 or raw[176:180]!=b'HPT\0' or integrity_info(raw)['status']!='VALID': continue
                key=(row['manufacturer'], normalized(row['part']), raw[3:9].hex())
                group=groups.setdefault(key,dict(part=row['part'],samples={}))
                serial=int.from_bytes(raw[122:126],'big');hpt=int.from_bytes(raw[180:184],'big')
                group['samples'].setdefault(serial,{}).setdefault(hpt,[]).append(row['sha256'])
            except (ValueError,OSError) as exc: errors.append(dict(sha256=row['sha256'],manufacturer=row['manufacturer'],part_normalized=normalized(row['part']),error=str(exc)))
        results=[]
        registry=load_registry(str(Path(__file__).with_name('hp_families.json')))
        for (vendor,part,organization),group in sorted(groups.items()):
            samples=group['samples']
            evidence=sorted(sha for values in samples.values() for hashes in values.values() for sha in hashes)
            identity=json.dumps([vendor,part,organization],ensure_ascii=True)
            result=dict(id='collection:'+hashlib.sha256(identity.encode()).hexdigest(), manufacturer=vendor,
                        part=group['part'],part_normalized=part,organization=organization,
                        distinct_serials=len(samples), evidence_sha256=evidence, status='insufficient',family=None)
            if any(len(values)!=1 for values in samples.values()): result['status']='conflicting-serial'
            elif len(samples)>=2:
                pairs=sorted((serial,next(iter(values))) for serial,values in samples.items())
                even=next((p for p in pairs if not p[0]&1),None);odd=next((p for p in pairs if p[0]&1),None)
                first,second=(even,odd) if even and odd else pairs[:2]
                a,b,k=learn_family_from_two(*first,*second)
                if not all((a*serial+b*hpt)&0xFFFFFFFF==k for serial,hpt in pairs): result['status']='inconsistent'
                elif not b or (b & -b)>1024: result['status']='underdetermined'
                else:
                    result.update(status='candidate', evaluation='sample-consistent' if len(samples)>=3 else 'provisional-two-sample',
                                  solutions_per_serial=b & -b,constant_hpt=len({h for _,h in pairs})==1,
                                  family=dict(A=f'0x{a:08X}',B=f'0x{b:08X}',K=f'0x{k:08X}',name=group['part']))
            matches=[]
            for key,family in registry.items():
                if part not in [normalized(n) for n in [family.get('name',''),*family.get('equivalents',[])]]: continue
                try:
                    a,b,k=(int(family[c],16) for c in ('A','B','K'))
                    if all((a*serial+b*hpt)&0xFFFFFFFF==k for serial,values in samples.items() for hpt in values):
                        matches.append(dict(key=key,name=family.get('name',key)))
                except (KeyError,TypeError,ValueError): pass
            if any(e['manufacturer']==vendor and e['part_normalized']==part for e in errors):
                result['status']='unreadable-evidence'
            result['known_matches']=matches
            results.append(result)
        with self.connect() as db:
            saved={r['id']:json.loads(r['record']) for r in db.execute('SELECT id,record FROM families')}
        for result in results:
            result['saved']=result['id'] in saved
            result['saved_family']=saved.get(result['id'],{}).get('family')
        return dict(groups=results,errors=errors,note='Candidates are empirical relations, not authenticated HP family identities. Review before saving.')

    def save_family(self, candidate, name=None):
        # Re-mine instead of trusting editable UI/JSON coefficients or stale evidence.
        current=next((r for r in self.mine_families()['groups'] if r['id']==candidate['id']),None)
        if not current or current['status']!='candidate' or current['evidence_sha256']!=candidate['evidence_sha256']:
            raise ValueError('Family evidence changed or is not eligible; mine the collection again')
        with self.connect() as db:
            existing=db.execute('SELECT record FROM families WHERE id=?',(current['id'],)).fetchone()
            if existing:
                old=json.loads(existing['record'])
                if any(old['family'][k]!=current['family'][k] for k in ('A','B','K')):
                    raise ValueError('A different family is already saved for this model; existing coefficients were retained')
            if name: current['family']['name']=str(name).strip()[:128]
            elif existing: current['family']['name']=old['family']['name']
            current['saved']=True
            current.pop('saved_family',None)
            current['saved_at']=datetime.now(timezone.utc).isoformat()
            db.execute('INSERT OR REPLACE INTO families VALUES (?,?)',(current['id'],json.dumps(current)))
        return current

    def saved_families(self):
        with self.connect() as db:
            return [json.loads(r['record']) for r in db.execute('SELECT record FROM families ORDER BY id')]

    def export_submission(self, hashes, destination):
        hashes = sorted(set(hashes))
        if not hashes: raise ValueError('Select images to submit')
        images = [(sha,self.data(sha)) for sha in hashes]
        # Deliberately omit absolute source paths. Raw images still contain serials/vendor data.
        entries=[]
        for sha,data in images:
            metadata=describe(data)
            entries.append(dict(metadata,sha256=sha,file=f'images/{sha}.bin',part_number=metadata['part']))
        manifest = dict(schema='spd-tool-submission/2',status='prepared-offline',images=entries)
        with Path(destination).open('xb') as handle:
            with zipfile.ZipFile(handle,'w',zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('manifest.json',json.dumps(manifest,indent=2))
                for sha,data in images: archive.writestr(f'images/{sha}.bin',data)
        return manifest
