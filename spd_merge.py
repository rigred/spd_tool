# SPDX-License-Identifier: MIT
"""Auditable multi-donor bitfield/region composition with explicit conflicts."""
import hashlib
from spd_fields import module_fields
from spd_library import SPD
from spd_integrity import repair_integrity
from spd_compatibility import assess


def digest(data):return hashlib.sha256(data).hexdigest()


def elements(data):
    """Atomic blocks protect known signatures, serial-bound HPT, and extension dependencies."""
    result={f.key:dict(key=f.key,label=f.label,group=f.group,operation='metadata' if f.group=='Manufacturing' else 'register' if any(s in f.group.lower() for s in ('register','buffer','personality')) else 'hardware',
                       masks={f.offset:f.maximum<<f.shift},dependencies=f.note) for f in module_fields(data) if 'timing' not in f.group.lower()}
    ranges=([(117,119,'manufacturer'),(119,120,'location'),(120,122,'date'),(122,126,'serial'),(128,146,'part_number'),(146,148,'revision'),(148,150,'dram_manufacturer'),(150,176,'manufacturer_payload'),(176,len(data),'customer_payload')]
            if data[2]==11 else [(64,72,'manufacturer'),(72,73,'location'),(73,91,'part_number'),(91,93,'revision'),(93,95,'date'),(95,99,'serial'),(99,128,'manufacturer_payload'),(128,len(data),'customer_payload')])
    for start,end,key in ranges:
        if end>start and end<=len(data):result[key]=dict(key=key,label=key.replace('_',' ').title(),group='Identity' if 'payload' not in key else 'Vendor data',operation='metadata',masks={i:255 for i in range(start,end)},dependencies='Opaque payload requires an explicit review reason; HPT must be recomputed separately' if 'payload' in key else '')
    from spd_native import native_timings
    for key,value in native_timings(data).items():result['timing:'+key]=dict(key='timing:'+key,label=key+' (ns)',group='Timings',operation='timing',masks={},dependencies='Semantic encoder; tRAS/tRP/tRC and tCK/CAS must remain coherent')
    result['native_timings']=dict(key='native_timings',label='Complete native timing configuration',group='Timings',operation='timing',masks={},dependencies='Semantic generation-specific encoding, all minima and CAS; preserve geometry')
    return result


def merge(target,selections,resolutions=None):
    """selections: [{data: bytes, keys: [...], overrides: {reason: text}}]."""
    SPD(target);out=bytearray(target);claims={};audit=[];reports=[];resolutions=resolutions or {}
    for selection in selections:
        donor=selection['data'];sha=digest(donor);available=elements(donor)
        for key in selection['keys']:
            if key not in available:raise ValueError('Unknown donor field: '+key)
            field=available[key];override=selection.get('overrides',{});operation=field['operation']
            if operation=='hardware':raise ValueError('Hardware descriptors are inspectable but cannot be transplanted; use the structured field editor deliberately')
            report=assess(donor,target,operation,override);reports.append(report)
            if not report['allowed']:raise ValueError('; '.join(report['hard']+['Required evidence: '+k for k in report['missing_overrides']]))
            if (key in ('serial','manufacturer','date','location','part_number','revision','dram_manufacturer') or field['group']=='Manufacturing') and not override.get('identity'):raise ValueError('Identity transfer requires an explicit identity reason; target identity is preserved by default')
            if 'payload' in key:
                if donor[2]==11 and key=='customer_payload' and donor[176:178]==b'\x0c\x4a':
                    from spd_xmp import read_profile
                    if donor[179] not in (0x11,0x12,0x13):raise ValueError('Unknown XMP revision cannot be transplanted')
                    for slot in (1,2):
                        if donor[178]&(1<<(slot-1)):read_profile(donor,slot)
                    if not override.get('timing'):raise ValueError('XMP block transfer requires a timing review reason')
                if donor[2]==8 and key=='manufacturer_payload' and donor[99:102]==bytes.fromhex('6d564e'):
                    from spd_epp import decode_epp
                    if donor[20]!=2:raise ValueError('Published EPP transfer requires a DDR2 UDIMM')
                    parsed=decode_epp(donor)
                    if parsed['format']=='unknown' or any(p['errors'] for p in parsed['profiles'] if p['enabled']):raise ValueError('EPP donor extension is invalid/unknown')
                    if not override.get('timing'):raise ValueError('EPP block transfer requires a timing review reason')
                if not override.get('opaque'):raise ValueError('Uninterpreted payload requires an opaque-data review reason')
                if key=='customer_payload' and donor[2]==11 and donor[176:180]==b'HPT\0':raise ValueError('Serial-bound HPT cannot be copied; compute HPT for the target serial separately')
            for offset,mask in field['masks'].items():
                if offset>=len(target):raise ValueError('Target does not contain this entire block')
                for bit in range(8):
                    if mask&(1<<bit):claims.setdefault((offset,bit),[]).append((sha,(donor[offset]>>bit)&1,key))
            audit.append(dict(source_sha256=sha,key=key,masks=field['masks'],overrides=override,dependencies=field['dependencies']))
    conflicts=[]
    for (offset,bit),values in claims.items():
        if len({v[1] for v in values})>1:
            choice=resolutions.get(str(offset)+':'+str(bit));chosen=[v for v in values if v[0]==choice]
            if not chosen:conflicts.append(dict(offset=offset,bit=bit,sources=values));continue
            value=chosen[0][1]
        else:value=values[0][1]
        out[offset]=(out[offset]&~(1<<bit))|(value<<bit)
    if conflicts:return dict(data=None,conflicts=conflicts,audit=audit,reports=reports)
    for selection in selections:
        for key in selection['keys']:
            if key in ('device_mfg_bank','device_mfg_code'):
                off=65 if key=='device_mfg_bank' else 66
                value=out[off]&127;out[off]=value | (128 if bin(value).count('1')%2==0 else 0)
    from spd_native import native_timings,encode_native
    timing_claims={};cas_claims={}
    for selection in selections:
        donor=selection['data'];sha=digest(donor);times=native_timings(donor)
        for key in selection['keys']:
            if key=='native_timings':
                for timing,value in times.items():timing_claims.setdefault('timing:'+timing,{})[sha]=value
                cas_claims[sha]=SPD(donor).decoded_data['cas_latencies_supported']
            elif key.startswith('timing:'):timing_claims.setdefault(key,{})[sha]=times[key[7:]]
    chosen_timings={};timing_conflicts=[];cas=None
    for key,values in list(timing_claims.items())+([('CAS',cas_claims)] if cas_claims else []):
        if len({str(v) for v in values.values()})>1:
            source=resolutions.get(key)
            if source not in values:
                timing_conflicts.append(dict(field=key,sources=list(values)));continue
            value=values[source]
        else:value=next(iter(values.values()))
        if key=='CAS':cas=value
        else:chosen_timings[key[7:]]=value
    if timing_conflicts:return dict(data=None,conflicts=timing_conflicts,audit=audit,reports=reports)
    if chosen_timings or cas is not None:out=encode_native(out,chosen_timings,cas)
    result=repair_integrity(out)
    return dict(data=result,conflicts=[],audit=audit,reports=reports,recipe=dict(schema='spd-tool-merge/1',target_sha256=digest(target),result_sha256=digest(result),selections=audit,resolutions=resolutions,integrity='generation-specific base repair'))


def replay(target,recipe,sources):
    if recipe.get('schema')!='spd-tool-merge/1' or digest(target)!=recipe.get('target_sha256'):raise ValueError('Recipe target hash/schema mismatch')
    selections=[]
    for row in recipe['selections']:
        data=sources[row['source_sha256']]
        if digest(data)!=row['source_sha256']:raise ValueError('Donor hash mismatch')
        selections.append(dict(data=data,keys=[row['key']],overrides=row['overrides']))
    result=merge(target,selections,recipe.get('resolutions'))
    if result['data'] is None or digest(result['data'])!=recipe['result_sha256']:raise ValueError('Recipe replay differs from recorded result')
    return result
