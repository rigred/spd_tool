# SPDX-License-Identifier: MIT
"""Open SPD Bundle v1: ordinary ZIP, UTF-8 JSON, raw images and SHA-256.

Checksums detect accidental damage; they do not authenticate who made a dump.
"""
import hashlib,json,re,zipfile,io
from pathlib import Path
from spd_containers import sha256,safe_member,MAX_FILE,MAX_ARCHIVE,MAX_ENTRIES,exclusive_output

FORMAT='open-spd-bundle'
VERSION=1


def _json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('Duplicate JSON key: '+key)
            result[key]=value
        return result
    def invalid(value):raise ValueError('Nonfinite JSON number: '+value)
    try:return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=invalid)
    except (UnicodeError,json.JSONDecodeError) as exc:raise ValueError('Invalid UTF-8 JSON manifest') from exc


def _hash(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value):raise ValueError('Expected lowercase SHA-256 hex')
    return value


def _payload(members,entry,minimum=1):
    if not isinstance(entry,dict):raise ValueError('Manifest entry must be an object')
    name=safe_member(entry.get('file'));digest=_hash(entry.get('sha256'));length=entry.get('length')
    if type(length) is not int or not minimum<=length<=MAX_FILE:raise ValueError('Invalid declared payload length')
    if name not in members:raise ValueError('Missing bundle payload: '+name)
    data=members[name]
    if len(data)!=length or sha256(data)!=digest:raise ValueError('Bundle SHA-256/length mismatch: '+name)
    return data


def decode_bundle_members(members):
    if 'manifest.json' not in members:raise ValueError('Missing manifest.json')
    raw=members['manifest.json'];manifest=_json(raw)
    if not isinstance(manifest,dict) or manifest.get('format')!=FORMAT or type(manifest.get('version')) is not int or manifest['version']!=VERSION:raise ValueError('Unknown SPD bundle format/version')
    check=members.get('manifest.sha256')
    if check!=(sha256(raw)+'  manifest.json\n').encode('ascii'):raise ValueError('Manifest checksum is absent or invalid')
    images=manifest.get('images')
    if not isinstance(images,list) or not images or len(images)>MAX_ENTRIES:raise ValueError('Bundle needs a nonempty images array')
    used={'manifest.json','manifest.sha256'};seen=set();records=[]
    for entry in images:
        data=_payload(members,entry);digest=entry['sha256']
        if digest in seen or entry['file']!='images/'+digest+'.bin':raise ValueError('Duplicate image or noncanonical image path')
        seen.add(digest);used.add(entry['file'])
        if not 3<=len(data)<=65536 or type(entry.get('memory_type')) is not int or entry['memory_type']!=data[2]:raise ValueError('Memory type does not match raw image')
        metadata=entry.get('metadata',{})
        if not isinstance(metadata,dict):raise ValueError('Image metadata must be an object')
        provenance=metadata.get('provenance')
        if provenance is not None and (not isinstance(provenance,dict) or not isinstance(provenance.get('generated'),bool) or provenance.get('result_sha256')!=digest):raise ValueError('Generated provenance must match the verified result image')
        sources=entry.get('sources',[])
        if not isinstance(sources,list):raise ValueError('Image sources must be an array')
        originals=[]
        for source in sources:
            if not isinstance(source,dict):raise ValueError('Source must be an object')
            if not isinstance(source.get('format'),str) or not isinstance(source.get('name'),str) or len(source['name'])>1024:raise ValueError('Source format/name must be bounded text')
            _hash(source.get('sha256'))
            if 'decoded_sha256' in source:_hash(source['decoded_sha256'])
            if 'decoded_length' in source and (type(source['decoded_length']) is not int or not 3<=source['decoded_length']<=65536):raise ValueError('Invalid decoded source length')
            if 'details' in source and not isinstance(source['details'],dict):raise ValueError('Source details must be an object')
            if type(source.get('length')) is not int or not 0<=source['length']<=MAX_FILE:raise ValueError('Invalid source length')
            original=None
            if 'file' in source:
                original=_payload(members,source,minimum=0);used.add(source['file'])
                if not source['file'].startswith('sources/'):raise ValueError('Original sources belong under sources/')
            originals.append(dict(source=source,original=original))
        records.append(dict(data=data,source=dict(format=FORMAT,name=entry['file'],sha256=digest,length=len(data)),original=None,sources=originals,metadata=metadata))
    if set(members)!=used:raise ValueError('Bundle contains unlisted payloads')
    return records


def write_bundle(records,destination):
    images={};payloads={}
    for record in records:
        data=bytes(record['data']);digest=sha256(data)
        if not 3<=len(data)<=65536:raise ValueError('Bundle raw image length must be 3–65536 bytes')
        metadata=record.get('metadata',{})
        if not isinstance(metadata,dict):raise ValueError('Image metadata must be an object')
        entry=images.get(digest)
        if entry is None:
            entry=dict(file='images/'+digest+'.bin',length=len(data),sha256=digest,memory_type=data[2],metadata=metadata,sources=[]);images[digest]=entry;payloads[entry['file']]=data
        elif entry['metadata']!=metadata:raise ValueError('Conflicting metadata for an identical image; resolve it before export')
        sources=record.get('sources',[dict(source=record.get('source',{}),original=record.get('original'))])
        for item in sources:
            source=dict(item.get('source',{}));original=item.get('original')
            if not source:continue
            source.pop('file',None)
            # Only basenames are public; source paths remain local to the collection.
            if 'name' in source:source['name']=Path(source['name']).name
            if original is not None:
                original=bytes(original)
                if len(original)>MAX_FILE:raise ValueError('Original source exceeds 1 MiB')
                digest_source=sha256(original)
                if source.get('sha256')!=digest_source or source.get('length')!=len(original):raise ValueError('Original source hash/length mismatch')
                extension='.thp' if source.get('format','').startswith('thaiphoon-th') else {'rw-everything':'.rw','hex-text':'.txt'}.get(source.get('format'),'.dat')
                source['file']='sources/'+digest_source+extension;payloads[source['file']]=original
            if source not in entry['sources']:entry['sources'].append(source)
    if not images:raise ValueError('Select at least one image')
    manifest=dict(format=FORMAT,version=VERSION,images=[images[key] for key in sorted(images)])
    raw=json.dumps(manifest,indent=2,sort_keys=True,ensure_ascii=False,allow_nan=False).encode('utf-8')
    if len(raw)>MAX_FILE or sum(map(len,payloads.values()))+len(raw)>MAX_ARCHIVE or len(payloads)+2>MAX_ENTRIES:raise ValueError('Bundle exceeds reader limits')
    payloads['manifest.json']=raw;payloads['manifest.sha256']=(sha256(raw)+'  manifest.json\n').encode('ascii')
    # Validate our own manifest/payload relationships before creating an output file.
    decode_bundle_members(payloads)
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as archive:
        for name,data in sorted(payloads.items()):archive.writestr(name,data)
    try:exclusive_output(destination,stream.getvalue())
    except FileExistsError as exc:raise ValueError('Output already exists; choose a new bundle filename') from exc
    return manifest
