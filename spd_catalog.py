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
    from spd_vendor import vendor_metadata
    return dict(metadata_version=3, vendor_data=vendor_metadata(data,decoded), memory=spd.mem_type_name,
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


def hp_part(details):
    if normalized(details.get('oem_name','')) not in ('HP','HPE','HEWLETTPACKARD','HEWLETTPACKARDENTERPRISE'):return ''
    return details.get('hp_family_part_number') or details.get('part_number','')


def family_scope(row,data):
    hp=row.get('hp_family_part_number')
    # A manually supplied HP family PN crosses vendor/organization boundaries.
    # Consistency checks still evaluate every distinct serial/HPT pair together.
    return ('OEM:HP',normalized(hp),'HP-PN') if hp else (row['manufacturer'],normalized(row['part']),data[3:9].hex())


class Catalog:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS merge_recipes (id TEXT PRIMARY KEY, name TEXT NOT NULL, record TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS images (sha TEXT PRIMARY KEY, path TEXT UNIQUE NOT NULL, metadata TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS vendor_profiles (id TEXT PRIMARY KEY, record TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS generated_images (sha TEXT PRIMARY KEY, provenance TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS annotations (sha TEXT PRIMARY KEY, details TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS families (id TEXT PRIMARY KEY, record TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS sources (sha TEXT NOT NULL, source TEXT NOT NULL, UNIQUE(sha,source))')
        # Backfill existing catalogs once; source paths and managed filenames remain unchanged.
        with self.connect() as db:
            for row in db.execute('SELECT sha,metadata FROM images').fetchall():
                old = json.loads(row['metadata'])
                if old.get('metadata_version') != 3:
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
        with self.connect() as db:
            generated={r['sha']:json.loads(r['provenance']) for r in db.execute('SELECT sha,provenance FROM generated_images')}
            annotations={r['sha']:json.loads(r['details']) for r in db.execute('SELECT sha,details FROM annotations')}
        result=[]
        for row in rows:
            details=annotations.get(row['sha256'],{})
            row.update(generated_vendor_profile=row['sha256'] in generated, vendor_profile_application=generated.get(row['sha256']), oem=details, oem_name=details.get('oem_name',''), oem_part_number=details.get('part_number',''),
                       oem_spare_number=details.get('spare_number',''), oem_assembly_number=details.get('assembly_number',''),
                       hp_family_part_number=hp_part(details))
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
        keys=('oem_name','manufacturer','dram_manufacturer','memory','module_type','capacity_mib','data_rate_MTps',
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

    def oem_details(self, sha):
        with self.connect() as db:
            row=db.execute('SELECT details FROM annotations WHERE sha=?',(sha,)).fetchone()
        return json.loads(row['details']) if row else {}

    def set_oem_details(self, sha, details):
        self.data(sha)  # Only annotate a verified collection entry.
        allowed=('oem_name','part_number','spare_number','assembly_number','model','hp_family_part_number','dram_chip_part_number','pcb_revision','register_part_number','notes')
        if set(details)-set(allowed):raise ValueError('Unknown OEM detail field')
        cleaned={}
        for key,value in details.items():
            if not isinstance(value,str):raise ValueError('OEM details must be text')
            value=value.strip()
            limit=2000 if key=='notes' else 128
            if len(value)>limit or any(ord(c)<32 and (key!='notes' or c not in '\n\t') for c in value):raise ValueError('OEM detail is too long or contains control characters')
            if value:cleaned[key]=value
        if cleaned:
            cleaned.update(source='user-entered sticker metadata',updated_at=datetime.now(timezone.utc).isoformat())
        with self.connect() as db:
            if cleaned:db.execute('INSERT OR REPLACE INTO annotations VALUES (?,?)',(sha,json.dumps(cleaned)))
            else:db.execute('DELETE FROM annotations WHERE sha=?',(sha,))
        return cleaned

    def hp_analysis(self, sha, serial=None):
        data = self.data(sha)
        if data[2] != 11 or len(data)<184: raise ValueError('HPT analysis requires DDR3 with the customer block present')
        all_rows=self.rows();by_sha={r['sha256']:r for r in all_rows}
        row = by_sha[sha]
        registry = load_registry(str(Path(__file__).with_name('hp_families.json')))
        with self.connect() as db:
            saved = [json.loads(r['record']) for r in db.execute('SELECT record FROM families')]
        scope=family_scope(row,data)
        for record in saved:
            record_scope=tuple(record.get('scope',[record['manufacturer'],record['part_normalized'],record['organization']]))
            if record_scope==scope:
                family=dict(record['family'],equivalents=[row['part'],row.get('hp_family_part_number','')])
                try:
                    if any(member not in by_sha or by_sha[member].get('generated_vendor_profile') or family_scope(by_sha[member],self.data(member))!=scope for member in record['evidence_sha256']):
                        family['_evidence_error']='Saved family OEM/model assignments changed; mine and review the collection again'
                except (ValueError,OSError):family['_evidence_error']='Saved family evidence could not be verified'
                registry[record['id']] = family
        serial = int.from_bytes(data[122:126],'big') if serial is None else serial
        families = []
        names_to_match={normalized(row['part'])}
        if row.get('hp_family_part_number'):names_to_match.add(normalized(row['hp_family_part_number']))
        for key, family in registry.items():
            names = [key,family.get('name',''), *family.get('equivalents',[])]
            if not names_to_match.intersection(normalized(name) for name in names if name): continue
            if all(k in family for k in ('A','B','K')):
                families.append(dict(key=key,origin='registry',family=family))
        samples = {}
        for other in all_rows:
            if other.get('generated_vendor_profile'):continue
            raw=self.data(other['sha256'])
            if len(raw)<184 or raw[2]!=11 or raw[176:180]!=b'HPT\0':continue
            if family_scope(other,raw)!=scope:continue
            if integrity_info(raw)['status']!='VALID':continue
            sample_serial,h=int.from_bytes(raw[122:126],'big'),int.from_bytes(raw[180:184],'big')
            samples.setdefault(sample_serial,set()).add(h)
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
                if family.get('_evidence_error'):raise ValueError(family['_evidence_error'])
                a,b,k=(int(family[c],16) for c in ('A','B','K'))
                if conflicting or any((a*s+b*h)&0xFFFFFFFF!=k for s,h in pairs):
                    raise ValueError('Current collection evidence conflicts with this family')
                if not b or (b & -b)>1024: raise ValueError('Underdetermined family; more than 1024 possible solutions')
                entry['candidates'] = [f'{v:08X}' for v in compute_hpt_solutions(serial,family)]
            except (KeyError,ValueError) as exc: entry['error']=str(exc)
        return dict(part=row['part'],hp_family_part_number=row.get('hp_family_part_number'),scope=scope,serial=f'{serial:08X}',distinct_samples=len(pairs),conflicting_samples=conflicting,families=families,
                    note='Two samples define a provisional relation. Additional matching samples are consistency evidence, not authentication. No image or global registry is modified.')

    def mine_families(self):
        groups, errors = {}, []
        for row in self.rows():
            if row.get('generated_vendor_profile'):continue
            if row['memory']!='DDR3' or row['part']=='Unknown model' and not row.get('hp_family_part_number'): continue
            try:
                raw=self.data(row['sha256'])
                if len(raw)<184 or raw[176:180]!=b'HPT\0' or integrity_info(raw)['status']!='VALID': continue
                key=family_scope(row,raw)
                group=groups.setdefault(key,dict(part=row.get('hp_family_part_number') or row['part'],samples={},members=[]))
                group['members'].append(dict(sha256=row['sha256'],manufacturer=row['manufacturer'],part_number=row['part'],oem=row.get('oem',{})))
                serial=int.from_bytes(raw[122:126],'big');hpt=int.from_bytes(raw[180:184],'big')
                group['samples'].setdefault(serial,{}).setdefault(hpt,[]).append(row['sha256'])
            except (ValueError,OSError) as exc: errors.append(dict(sha256=row['sha256'],manufacturer=row['manufacturer'],part_normalized=normalized(row['part']),hp_family_part_number=row.get('hp_family_part_number'),error=str(exc)))
        results=[]
        registry=load_registry(str(Path(__file__).with_name('hp_families.json')))
        for (vendor,part,organization),group in sorted(groups.items()):
            samples=group['samples']
            evidence=sorted(sha for values in samples.values() for hashes in values.values() for sha in hashes)
            identity=json.dumps([vendor,part,organization],ensure_ascii=True)
            result=dict(id='collection:'+hashlib.sha256(identity.encode()).hexdigest(), manufacturer=vendor,
                        part=group['part'],part_normalized=part,organization=organization,scope=[vendor,part,organization],members=group['members'],hp_family_part_number=group['part'] if vendor=='OEM:HP' else None,
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
            if any((vendor=='OEM:HP' and normalized(e.get('hp_family_part_number') or '')==part) or (e['manufacturer']==vendor and e['part_normalized']==part) for e in errors):
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
        if not current or current['status']!='candidate' or current['evidence_sha256']!=candidate['evidence_sha256'] or current.get('members')!=candidate.get('members'):
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

    def vendor_observations(self,sha):
        from spd_vendor import vendor_metadata
        return dict(vendor_metadata(self.data(sha)), oem_sticker_details=self.oem_details(sha))

    def vendor_profiles(self):
        with self.connect() as db:
            return [json.loads(r['record']) for r in db.execute('SELECT record FROM vendor_profiles ORDER BY id')]

    def create_hp_profile(self, donor_sha, family_key, name, copy_opaque=False):
        from spd_vendor import sha256
        donor=self.data(donor_sha)
        row=next(r for r in self.rows() if r['sha256']==donor_sha)
        if row.get('generated_vendor_profile'):raise ValueError('A generated image cannot serve as independent donor evidence')
        if len(donor)<184 or donor[2]!=11 or donor[176:180]!=b'HPT\0' or integrity_info(donor)['status']!='VALID':
            raise ValueError('Choose an integrity-valid DDR3 donor with an observed HPT signature')
        analysis=self.hp_analysis(donor_sha)
        entry=next((f for f in analysis['families'] if f['key']==family_key),None)
        if not entry or entry.get('error') or donor[180:184].hex().upper() not in entry.get('candidates',[]):
            raise ValueError('Selected family does not validate the donor HPT; analyze or mine its family first')
        if copy_opaque and len(donor)!=256:raise ValueError('Opaque templates require a 256-byte donor')
        name=str(name).strip()
        if not name or len(name)>128:raise ValueError('Supply a profile name of 1–128 characters')
        coefficients={k:entry['family'][k] for k in ('A','B','K')}
        identity=json.dumps([donor_sha,family_key,coefficients,bool(copy_opaque)],sort_keys=True)
        profile=dict(id=sha256(identity.encode()),kind='hp-hpt-v1',name=name,donor_sha256=donor_sha,
                     manufacturer_part_number=row['part'],family_key=family_key,family_name=entry['family'].get('name',family_key),
                     coefficients=coefficients,origin=entry['origin'],copy_opaque=bool(copy_opaque),
                     created_at=datetime.now(timezone.utc).isoformat())
        with self.connect() as db:db.execute('INSERT OR REPLACE INTO vendor_profiles VALUES (?,?)',(profile['id'],json.dumps(profile)))
        return profile

    def hp_profile_options(self, profile_id, target):
        from spd_vendor import compatible_target,sha256
        profile=next((p for p in self.vendor_profiles() if p['id']==profile_id),None)
        if not profile:raise ValueError('Unknown vendor profile')
        if profile.get('kind')!='hp-hpt-v1':raise ValueError('Unsupported vendor profile format')
        if any(r['sha256']==profile['donor_sha256'] and r.get('generated_vendor_profile') for r in self.rows()):
            raise ValueError('Generated images cannot serve as independent donors')
        donor=self.data(profile['donor_sha256'])
        compatible_target(donor,target)
        # Revalidate the donor under its current family scope and evidence.
        original=self.hp_analysis(profile['donor_sha256'])
        entry=next((f for f in original['families'] if f['key']==profile['family_key']),None)
        if (not entry or entry.get('error') or any(entry['family'][k]!=profile['coefficients'][k] for k in ('A','B','K'))
                or donor[180:184].hex().upper() not in entry.get('candidates',[])):
            raise ValueError('Donor family/evidence changed; recreate the profile after review')
        target_serial=int.from_bytes(target[122:126],'big')
        # Existing helper handles even B; never enumerate an unbounded relation.
        b=int(profile['coefficients']['B'],16)
        if not b or (b & -b)>1024:raise ValueError('Profile has an underdetermined HPT relation')
        candidates=[f'{code:08X}' for code in compute_hpt_solutions(target_serial,profile['coefficients'])]
        if not candidates:raise ValueError('This family has no HPT solution for the target serial')
        return dict(profile=profile,donor_sha256=profile['donor_sha256'],target_sha256=sha256(target),
                    target_serial=f'{target_serial:08X}',candidates=candidates,
                    identity_warnings=['Target serial is zero or erased; this profile does not create a unique hardware identity'] if target_serial in (0,0xFFFFFFFF) else [],
                    warning='Empirical HPT compatibility is not HP certification or a guarantee of server acceptance. Multiple solutions require an explicit choice.')

    def preview_hp_profile(self,profile_id,target,hpt,replace_existing=False):
        from spd_vendor import apply_hp_template,sha256
        options=self.hp_profile_options(profile_id,bytes(target))
        if hpt.upper() not in options['candidates']:raise ValueError('Choose an HPT value from this target serial’s solutions')
        donor=self.data(options['donor_sha256'])
        result=apply_hp_template(donor,bytes(target),hpt,options['profile']['copy_opaque'],replace_existing)
        report=dict(options,chosen_hpt=hpt.upper(),result_sha256=sha256(result),
                    changes=[dict(offset=i,before=a,after=b) for i,(a,b) in enumerate(zip(target,result)) if a!=b],
                    generated=True)
        return result,report

    def mark_profile_generated(self, sha, report):
        from spd_vendor import sha256
        data=self.data(sha)
        if not report.get('generated') or report.get('result_sha256')!=sha256(data):
            raise ValueError('Generated-image provenance does not match this image')
        with self.connect() as db:db.execute('INSERT OR REPLACE INTO generated_images VALUES (?,?)',(sha,json.dumps(report)))

    def save_recipe(self,name,bundle):
        from spd_merge import replay,digest
        recipe=bundle['recipe'];sources={k:bytes.fromhex(v) for k,v in bundle['sources'].items()}
        if 'target_hex' in bundle:
            target=bytes.fromhex(bundle['target_hex'])
            if digest(target)!=recipe['target_sha256']:raise ValueError('Recipe target hash mismatch')
        else:target=self.data(recipe['target_sha256'])
        rebuilt=replay(target,recipe,sources)
        self.add(target,'merge recipe original target')
        for sha,data in sources.items():self.add(data,'merge recipe donor')
        generated=self.add(rebuilt['data'],'merge recipe generated result')
        self.mark_profile_generated(generated['sha256'],dict(kind='engineering-merge',generated=True,target_sha256=digest(target),result_sha256=generated['sha256'],recipe=recipe))
        record=json.dumps(bundle,sort_keys=True);key=digest(record.encode())
        with self.connect() as db:db.execute('INSERT OR REPLACE INTO merge_recipes VALUES (?,?,?)',(key,str(name),record))
        return key

    def recipes(self):
        with self.connect() as db:return [dict(id=r['id'],name=r['name'],bundle=json.loads(r['record'])) for r in db.execute('SELECT * FROM merge_recipes ORDER BY name')]

    def refresh_sources(self):
        # Original source paths are observations. Changed files become new immutable images.
        with self.connect() as db:paths=[r['source'] for r in db.execute('SELECT DISTINCT source FROM sources')]
        existing=[Path(p) for p in paths if Path(p).is_file()]
        rows,errors=self.import_files(existing)
        return dict(checked=len(existing),images=len(rows),errors=errors,missing=[p for p in paths if not Path(p).is_file()])

    def export_submission(self, hashes, destination):
        hashes = sorted(set(hashes))
        if not hashes: raise ValueError('Select images to submit')
        images = [(sha,self.data(sha)) for sha in hashes]
        # Deliberately omit absolute source paths. Raw images still contain serials/vendor data.
        entries=[]
        for sha,data in images:
            metadata=describe(data)
            details=self.oem_details(sha)
            if details: metadata['oem']=details
            with self.connect() as db:
                derived=db.execute('SELECT provenance FROM generated_images WHERE sha=?',(sha,)).fetchone()
            if derived:metadata['vendor_profile_application']=json.loads(derived['provenance'])
            entries.append(dict(metadata,sha256=sha,file=f'images/{sha}.bin',part_number=metadata['part']))
        manifest = dict(schema='spd-tool-submission/2',status='prepared-offline',images=entries)
        with Path(destination).open('xb') as handle:
            with zipfile.ZipFile(handle,'w',zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('manifest.json',json.dumps(manifest,indent=2))
                for sha,data in images: archive.writestr(f'images/{sha}.bin',data)
        return manifest
