# SPDX-License-Identifier: MIT
"""Explicit lossless conversion and collection import CLI; no EEPROM access."""
import json
from pathlib import Path
from spd_containers import read_inputs,sha256,exclusive_output
from spd_bundle import write_bundle


def image_metadata(data):
    from spd_catalog import describe
    from spd_archive import archive_integrity
    try:
        row=describe(data)
        return dict(manufacturer=row['manufacturer'],part_number=row['part'],serial=row['serial'],spd_integrity=archive_integrity(data),editable=row['editable'],support=row['support'],warnings=row['warnings'])
    except (ValueError,NotImplementedError) as exc:return dict(decoder_error=str(exc))


def convert_files(paths,out=None,out_dir=None,format=None):
    records=[];errors=[]
    for path in paths:
        try:
            images,problems=read_inputs(path);errors.extend(problems)
            for image in images:
                # Preserve metadata already verified by an open-bundle reader.
                image['metadata']=dict(image_metadata(image['data']),**image.get('metadata',{}));records.append(image)
        except (ValueError,OSError,ImportError,NotImplementedError) as exc:errors.append(dict(path=str(path),error=str(exc)))
    if not records:return dict(outputs=[],errors=errors or [dict(error='No images to convert')])
    if (out is None)==(out_dir is None):raise ValueError('Choose exactly one of --out and --out-dir')
    kind=format or ('spdz' if out and Path(out).suffix.lower() in ('.zip','.spdz') else 'bin')
    if kind not in ('bin','spdz'):raise ValueError('Output format must be bin or spdz')
    outputs=[]
    if out:
        if errors:raise ValueError('Input contains errors; use bulk --out-dir for per-image conversion, or fix the input first: '+str(errors))
        if kind=='spdz':write_bundle(records,out);outputs.append(dict(file=str(out),images=len({sha256(r['data']) for r in records})))
        else:
            if len(records)!=1:raise ValueError('Multiple images require --out-dir or an open bundle output')
            if Path(out).suffix.lower() in ('.thp','.rw','.zip','.spdz','.7z'):raise ValueError('Binary output must not use a container filename extension')
            exclusive_output(out,records[0]['data'])
            outputs.append(dict(file=str(out),sha256=sha256(records[0]['data']),length=len(records[0]['data']),metadata=records[0]['metadata']))
    else:
        directory=Path(out_dir);directory.mkdir(parents=True,exist_ok=True);seen=set()
        for record in records:
            digest=sha256(record['data'])
            if digest in seen:continue
            seen.add(digest);target=directory/(digest+('.spdz' if kind=='spdz' else '.bin'))
            try:
                if kind=='spdz':write_bundle([record],target)
                else:
                    try:
                        exclusive_output(target,record['data'])
                    except FileExistsError:
                        if target.is_symlink() or target.stat().st_size!=len(record['data']) or target.read_bytes()!=record['data']:raise ValueError('Existing output failed hash verification')
                outputs.append(dict(file=str(target),sha256=digest,length=len(record['data']),metadata=record['metadata']))
            except (OSError,ValueError) as exc:errors.append(dict(path=str(target),error=str(exc)))
    return dict(outputs=outputs,errors=errors)


def add_parsers(subparsers):
    p=subparsers.add_parser('convert',help='Losslessly convert supported THP, raw/text dumps or open bundles to binary or open ZIP bundles.')
    p.add_argument('--source',action='append',required=True,help='Input file/archive; repeat for bulk conversion.')
    group=p.add_mutually_exclusive_group(required=True);group.add_argument('--out');group.add_argument('--out-dir')
    p.add_argument('--format',choices=('bin','spdz'),help='Default: infer spdz from an --out .spdz/.zip extension, otherwise bin.')
    def convert(args):
        result=convert_files(args.source,args.out,args.out_dir,args.format);print(json.dumps(result,indent=2))
        if result['errors']:raise SystemExit(2)
    p.set_defaults(func=convert)
    p=subparsers.add_parser('library-import',help='Bulk import/convert source files into a managed SQLite SPD collection.')
    p.add_argument('--collection',required=True);p.add_argument('--source',action='append',required=True,help='File, archive or directory; repeat for multiple sources.')
    def library_import(args):
        from spd_catalog import Catalog
        from spd_import_report import import_report
        rows,errors=Catalog(args.collection).import_files(args.source);print(json.dumps(import_report(rows,errors),indent=2))
        if errors:raise SystemExit(2)
    p.set_defaults(func=library_import)
