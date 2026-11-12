# SPDX-License-Identifier: MIT
"""Lossless TH20/RW import and bounded ZIP/7z ingestion. No integrity repair."""
import hashlib,io,json,re,stat,zipfile,os,tempfile,zlib
from pathlib import Path,PurePosixPath

MAX_FILE=1024*1024
MAX_ARCHIVE=64*1024*1024
MAX_ENTRIES=4096
EXTENSIONS={'.bin','.spd','.thp','.hex','.txt','.rw','.spdz','.zip','.7z'}


def sha256(data):return hashlib.sha256(data).hexdigest()


def exclusive_output(path,data):
    """Publish complete bytes atomically without overwriting an existing file."""
    destination=Path(path);temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent,prefix='.spd-',delete=False) as stream:
            temporary=stream.name;stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.link(temporary,destination)
    finally:
        if temporary is not None:Path(temporary).unlink(missing_ok=True)


def safe_member(name):
    if not isinstance(name,str) or not name or len(name)>1024 or '\\' in name or ':' in name or '\0' in name or any(ord(c)<32 for c in name):raise ValueError('Unsafe archive member name')
    parts=name.rstrip('/').split('/')
    if any(part in ('','.','..') for part in parts) or name.startswith('/'):raise ValueError('Unsafe archive member path: '+name)
    return name


def decode_image(raw,name='image'):
    """Return exact decoded bytes and reversible source observations."""
    if len(raw)>MAX_FILE:raise ValueError('Image source exceeds 1 MiB')
    kind='binary';details={}
    if raw.startswith(b'\x04TH'):
        if raw[:5]!=b'\x04TH20':raise ValueError('Unsupported THP version '+repr(raw[:5])+'; TH20 samples are supported, later layouts are not guessed')
        if len(raw)!=262:raise ValueError('TH20 requires exactly 262 bytes (5-byte header, 256-byte payload, 1-byte trailer)')
        data=bytes(value^offset for offset,value in enumerate(raw[5:261]));kind='thaiphoon-th20'
        details=dict(header_hex=raw[:5].hex(),trailer_hex=raw[261:].hex(),transform='spd[i] = file[5+i] XOR i; 0 <= i < 256',container_integrity='No independently verified TH20 container checksum')
    elif Path(name).suffix.lower()=='.thp':raise ValueError('Unrecognized THP signature; no raw or heuristic fallback')
    elif raw.startswith(b'Type:DIMM SPD'):
        try:text=raw.decode('ascii').replace('\\r\\n','\n').replace('\\n','\n')
        except UnicodeDecodeError as exc:raise ValueError('RW dump must be ASCII') from exc
        lines=text.splitlines()
        if len(lines)<3 or lines[1].strip()!='Width:01':raise ValueError('Unsupported RW dump width/header')
        pairs=[];comments=[]
        for line in lines[2:]:
            line=line.strip()
            if line.startswith(';'):comments.append(line[1:].strip());continue
            if not line:continue
            tokens=line.split()
            for token in tokens:
                match=re.fullmatch(r'([0-9A-Fa-f]{2})=([0-9A-Fa-f]{2})',token)
                if not match or int(match[1],16)!=len(pairs):raise ValueError('RW dump has malformed, missing or reordered offsets')
                pairs.append(int(match[2],16))
        if len(pairs) not in (128,256):raise ValueError('RW dump requires exactly 128 or 256 sequential byte records')
        data=bytes(pairs);kind='rw-everything';details=dict(comments=comments)
    else:
        from spd_library import _try_load_text_hex
        parsed=_try_load_text_hex(raw)
        if parsed is not None:data=parsed;kind='hex-text'
        elif raw and all(b in b'\t\r\n' or 32<=b<=126 for b in raw):raise ValueError('Invalid hex-text SPD dump')
        else:data=bytes(raw)
        if not 128<=len(data)<=256:raise ValueError('Raw SPD image must contain 128–256 bytes')
    source=dict(format=kind,name=Path(name).name,sha256=sha256(raw),length=len(raw),decoded_sha256=sha256(data),decoded_length=len(data),details=details)
    return dict(data=data,source=source,original=bytes(raw) if kind!='binary' else None,metadata={})


def zip_members(raw):
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries=archive.infolist()
            if len(entries)>MAX_ENTRIES:raise ValueError('Archive exceeds 4096 entries')
            seen=set();size=0
            for item in entries:
                safe_member(item.filename)
                if item.filename in seen:raise ValueError('Duplicate ZIP member: '+item.filename)
                seen.add(item.filename)
                mode=item.external_attr>>16
                if stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR):raise ValueError('Archive links/special files are unsupported')
                if item.flag_bits&1:raise ValueError('Encrypted ZIP members are unsupported')
                if item.is_dir():continue
                size+=item.file_size
                if item.file_size>MAX_FILE or size>MAX_ARCHIVE:raise ValueError('Archive expansion limit exceeded')
            return {item.filename:archive.read(item) for item in entries if not item.is_dir()}
    except (zipfile.BadZipFile,RuntimeError,NotImplementedError,zlib.error) as exc:raise ValueError('Invalid/unsupported ZIP: '+str(exc)) from exc


def sevenzip_members(raw):
    try:
        import py7zr
        from py7zr.io import Py7zIO,WriterFactory
    except ImportError as exc:raise ImportError('7z import requires py7zr: python -m pip install -r requirements-archives.txt; THP, ZIP and binary imports need no extra package') from exc
    from threading import Lock
    class Buffer(Py7zIO):
        def __init__(self,factory):self.buffer=io.BytesIO();self.factory=factory
        def write(self,data):
            with self.factory.lock:
                end=max(self.size(),self.buffer.tell()+len(data));growth=end-self.size()
                if end>MAX_FILE or self.factory.total+growth>MAX_ARCHIVE:raise ValueError('7z expansion limit exceeded')
                self.factory.total+=growth;return self.buffer.write(data)
        def read(self,size=None):return self.buffer.read(-1 if size is None else size)
        def seek(self,offset,whence=0):return self.buffer.seek(offset,whence)
        def flush(self):pass
        def size(self):return len(self.buffer.getbuffer())
    class Factory(WriterFactory):
        def __init__(self):self.products={};self.total=0;self.lock=Lock()
        def create(self,name):
            safe_member(name)
            if name in self.products:raise ValueError('Duplicate 7z member')
            result=Buffer(self);self.products[name]=result;return result
    try:
        with py7zr.SevenZipFile(io.BytesIO(raw),'r') as archive:
            if archive.needs_password():raise ValueError('Encrypted 7z archives are unsupported')
            entries=archive.list();seen=set();size=0
            if len(entries)>MAX_ENTRIES:raise ValueError('Archive exceeds 4096 entries')
            expected={}
            for item in entries:
                safe_member(item.filename)
                if item.filename in seen:raise ValueError('Duplicate 7z member')
                seen.add(item.filename)
                if item.is_symlink or (not item.is_directory and not item.is_file):raise ValueError('Archive links/special files are unsupported')
                if item.is_directory:continue
                size+=item.uncompressed
                if item.uncompressed>MAX_FILE or size>MAX_ARCHIVE:raise ValueError('Archive expansion limit exceeded')
                expected[item.filename]=item.uncompressed
            factory=Factory();archive.extractall(factory=factory)
            result={name:product.buffer.getvalue() for name,product in factory.products.items()}
            if set(result)!=set(expected) or any(len(result[name])!=size for name,size in expected.items()):raise ValueError('7z member length/list mismatch')
            return result
    except Exception as exc:
        if isinstance(exc,ValueError):raise
        raise ValueError('Invalid/unsupported 7z: '+str(exc)) from exc


def read_inputs(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise ValueError('Choose a regular input file, not a symbolic link')
    if path.stat().st_size>MAX_ARCHIVE:raise ValueError('Input exceeds 64 MiB')
    raw=path.read_bytes()
    archive=raw.startswith(b'PK\x03\x04') or path.suffix.lower() in ('.zip','.spdz')
    seven=raw.startswith(b'7z\xbc\xaf\x27\x1c') or path.suffix.lower()=='.7z'
    if not archive and not seven:return [decode_image(raw,path.name)],[]
    members=zip_members(raw) if archive else sevenzip_members(raw)
    if Path(path).suffix.lower()=='.spdz' and 'manifest.json' not in members:raise ValueError('Open SPD bundles require manifest.json')
    if 'manifest.json' in members:
        from spd_bundle import decode_bundle_members
        return decode_bundle_members(members),[]
    records=[];errors=[]
    for name,data in members.items():
        if Path(name).suffix.lower() not in EXTENSIONS:errors.append(dict(path=str(path)+'#'+name,error='Unsupported archive member extension'));continue
        if Path(name).suffix.lower() in ('.zip','.spdz','.7z'):errors.append(dict(path=str(path)+'#'+name,error='Nested archives are not imported'));continue
        try:
            record=decode_image(data,name);record['source'].update(member=name,archive_name=path.name,archive_sha256=sha256(raw));records.append(record)
        except (ValueError,NotImplementedError) as exc:errors.append(dict(path=str(path)+'#'+name,error=str(exc)))
    return records,errors
