# SPDX-License-Identifier: MIT
"""Reviewable collection maintenance; removal quarantines managed files only."""
import hashlib,json,os,re,shutil,uuid
from pathlib import Path
from spd_containers import exclusive_output,sha256,EXTENSIONS

TABLE_KEYS={'images':('sha',),'annotations':('sha',),'generated_images':('sha',),'sources':('sha','source'),'imports':('image_sha','source_sha','name'),'vendor_profiles':('id',),'merge_recipes':('id',),'families':('id',)}


def _contains(value,hashes):
    if isinstance(value,str):return value in hashes
    if isinstance(value,dict):return any(_contains(k,hashes) or _contains(v,hashes) for k,v in value.items())
    if isinstance(value,list):return any(_contains(v,hashes) for v in value)
    return False


def _path(catalog,relative,trash=False):
    p=Path(relative)
    if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] not in (('.trash',) if trash else ('modules','originals')):raise ValueError('Not a managed collection path')
    path=catalog.root/p
    if catalog.root not in path.parent.resolve().parents and path.parent.resolve()!=catalog.root:raise ValueError('Managed parent escapes collection')
    return path


def _state(path):
    if path.is_symlink():return dict(kind='symlink',target=os.readlink(path))
    if not path.exists():return dict(kind='missing')
    if not path.is_file():raise ValueError('Expected a managed file')
    if path.stat().st_size>1024*1024:raise ValueError('Managed artifact unexpectedly exceeds 1 MiB')
    return dict(kind='file',sha256=sha256(path.read_bytes()),length=path.stat().st_size)


def removal_plan(catalog,hashes):
    hashes=sorted(set(hashes))
    if not hashes:raise ValueError('Select images to remove')
    selected=set(hashes);tables={};files=set()
    with catalog.connect() as db:
        images=[dict(r) for r in db.execute('SELECT * FROM images')]
        if not selected<={r['sha'] for r in images}:raise ValueError('Selected image is no longer in the collection')
        tables['images']=[r for r in images if r['sha'] in selected]
        files.update(r['path'] for r in tables['images'])
        for name in ('annotations','generated_images','sources','imports'):
            column='image_sha' if name=='imports' else 'sha';tables[name]=[dict(r) for r in db.execute('SELECT * FROM '+name) if r[column] in selected]
        retained={json.loads(r['record']).get('original_path') for r in db.execute('SELECT * FROM imports') if r['image_sha'] not in selected}
        files.update(json.loads(r['record'])['original_path'] for r in tables['imports'] if json.loads(r['record']).get('original_path') and json.loads(r['record'])['original_path'] not in retained)
        for name in ('vendor_profiles','merge_recipes','families'):tables[name]=[dict(r) for r in db.execute('SELECT * FROM '+name) if _contains(json.loads(r['record']),selected)]
    states=[dict(path=path,state=_state(_path(catalog,path))) for path in sorted(files)]
    result=dict(schema='spd-tool-removal/1',root=str(catalog.root),hashes=hashes,tables=tables,files=states,
                dependents={k:len(tables[k]) for k in ('vendor_profiles','merge_recipes','families')},
                note='Managed files move to collection trash; external source files are never deleted. Shared originals remain active.')
    result['review_sha256']=sha256(json.dumps(result,sort_keys=True).encode());return result


def remove_images(catalog,plan,include_dependents=False):
    # Lock database writes while comparing the review and moving files.
    moved=[];trash_id=uuid.uuid4().hex;directory=catalog.root/'.trash'/trash_id
    with catalog.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        current=removal_plan(catalog,plan['hashes'])
        if current['review_sha256']!=plan.get('review_sha256'):raise ValueError('Collection/removal selection changed; preview removal again')
        if any(current['dependents'].values()) and not include_dependents:raise ValueError('Removal affects donor profiles, recipes or learned families; review and explicitly include those dependencies')
        if (catalog.root/'.trash').is_symlink():raise ValueError('Collection trash must not be a symbolic link')
        directory.mkdir(parents=True,mode=0o700);exclusive_output(directory/'manifest.json',json.dumps(current,indent=2).encode())
        try:
            for file in current['files']:
                if file['state']['kind']=='missing':continue
                source=_path(catalog,file['path']);target=directory/'files'/file['path'];target.parent.mkdir(parents=True,exist_ok=True)
                os.replace(source,target);moved.append((source,target))
            for table,rows in current['tables'].items():
                for row in rows:
                    keys=TABLE_KEYS[table];db.execute('DELETE FROM '+table+' WHERE '+' AND '.join(k+'=?' for k in keys),[row[k] for k in keys])
            # Commit before leaving the filesystem rollback scope.
            db.commit()
        except BaseException:
            db.rollback()
            for source,target in reversed(moved):source.parent.mkdir(parents=True,exist_ok=True);os.replace(target,source)
            shutil.rmtree(directory);raise
    return dict(removed=len(current['hashes']),trash_id=trash_id,files_quarantined=len(moved),dependents=current['dependents'])


def trash_entries(catalog):
    directory=catalog.root/'.trash'
    if directory.is_symlink():raise ValueError('Collection trash must not be a symbolic link')
    result=[]
    if directory.exists():
        for p in sorted(directory.iterdir()):
            if not re.fullmatch('[0-9a-f]{32}',p.name) or p.is_symlink() or not p.is_dir():continue
            try:
                record=json.loads((p/'manifest.json').read_text());result.append(dict(id=p.name,images=len(record['hashes']),files=sum(f['state']['kind']!='missing' for f in record['files'])))
            except (ValueError,OSError,KeyError):continue
    return result


def restore_trash(catalog,trash_id):
    if not re.fullmatch('[0-9a-f]{32}',trash_id):raise ValueError('Invalid trash identifier')
    directory=_path(catalog,'.trash/'+trash_id,True)
    if directory.is_symlink() or not directory.is_dir():raise ValueError('Trash entry is unavailable')
    plan=json.loads((directory/'manifest.json').read_text());review=plan.pop('review_sha256',None)
    if plan.get('schema')!='spd-tool-removal/1' or sha256(json.dumps(plan,sort_keys=True).encode())!=review:raise ValueError('Trash manifest failed verification')
    moved=[]
    with catalog.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        for table,rows in plan['tables'].items():
            if table not in TABLE_KEYS:raise ValueError('Invalid trash table')
            for row in rows:
                keys=TABLE_KEYS[table]
                existing=db.execute('SELECT * FROM '+table+' WHERE '+' AND '.join(k+'=?' for k in keys),[row[k] for k in keys]).fetchone()
                if existing and dict(existing)!=row:raise ValueError('Restoration would overwrite changed collection metadata; resolve the conflict first')
        for file in plan['files']:
            destination=_path(catalog,file['path'])
            if (destination.exists() or destination.is_symlink()) and _state(destination)!=file['state']:raise ValueError('Restoration would overwrite a managed file')
            if file['state']['kind']=='missing':continue
            source=directory/'files'/file['path']
            if directory.resolve() not in source.parent.resolve().parents:raise ValueError('Quarantined path escapes trash')
            if not source.exists() and not source.is_symlink() and _state(destination)==file['state']:continue
            if _state(source)!=file['state']:raise ValueError('Quarantined file failed verification')
        try:
            for file in plan['files']:
                if file['state']['kind']=='missing':continue
                source=directory/'files'/file['path'];destination=_path(catalog,file['path'])
                if destination.exists() or destination.is_symlink():continue
                destination.parent.mkdir(parents=True,exist_ok=True);os.replace(source,destination);moved.append((source,destination))
            for table,rows in plan['tables'].items():
                for row in rows:
                    # Column names come from the table schema, never arbitrary JSON SQL.
                    columns=[r['name'] for r in db.execute('PRAGMA table_info('+table+')')]
                    if set(row)!=set(columns):raise ValueError('Trash schema differs from current collection')
                    db.execute('INSERT OR IGNORE INTO '+table+' ('+','.join(columns)+') VALUES ('+','.join('?' for _ in columns)+')',[row[k] for k in columns])
            db.commit()
        except BaseException:
            db.rollback()
            for source,destination in reversed(moved):source.parent.mkdir(parents=True,exist_ok=True);os.replace(destination,source)
            raise
    shutil.rmtree(directory);return dict(restored=len(plan['hashes']),trash_id=trash_id)


def empty_trash(catalog,ids):
    available={r['id'] for r in trash_entries(catalog)}
    if not set(ids)<=available:raise ValueError('Trash selection changed; refresh it')
    # A crash before SQLite commit can leave active rows whose files are in trash.
    # Require recovery before permanently emptying those remaining copies.
    with catalog.connect() as db:active={r['sha']:r['path'] for r in db.execute('SELECT sha,path FROM images')}
    for key in ids:
        directory=_path(catalog,'.trash/'+key,True);plan=json.loads((directory/'manifest.json').read_text())
        for sha in plan['hashes']:
            if sha in active:
                path=_path(catalog,active[sha])
                if not path.is_file() or path.is_symlink() or path.stat().st_size>1024*1024 or sha256(path.read_bytes())!=sha:raise ValueError('Trash may contain the remaining copy for an active entry; restore/recover it before emptying trash')
    for key in ids:shutil.rmtree(_path(catalog,'.trash/'+key,True))
    return dict(permanently_removed=len(ids))


def missing_references(catalog):
    records=[];unreadable=[]
    with catalog.connect() as db:
        for row in db.execute('SELECT sha,source FROM sources ORDER BY source,sha'):
            value=row['source'];path=Path(value)
            # Labels such as "editor snapshot" and recipe observations are not files.
            if not path.is_absolute() and path.suffix.lower() not in EXTENSIONS and '/' not in value and '\\' not in value:continue
            if not path.is_absolute():
                unreadable.append(dict(source=value,error='Legacy relative reference has no recorded base directory; retained for manual review'));continue
            try:
                resolved=path.resolve()
                if resolved==catalog.root or catalog.root in resolved.parents:continue
                try:path.stat();continue
                except (FileNotFoundError,NotADirectoryError):pass
                records.append(dict(sha=row['sha'],source=value))
            except OSError as exc:unreadable.append(dict(source=value,error=str(exc)))
    return dict(missing=records,unreadable=unreadable,note='Only stale external source pointers are removed; managed images and original sources are preserved.')


def cleanup_references(catalog,review):
    current={(r['sha'],r['source']) for r in missing_references(catalog)['missing']};removed=0
    with catalog.connect() as db:
        for row in review['missing']:
            if (row['sha'],row['source']) in current:removed+=db.execute('DELETE FROM sources WHERE sha=? AND source=?',(row['sha'],row['source'])).rowcount
    return dict(references_removed=removed,images_removed=0)
