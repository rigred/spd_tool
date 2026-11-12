# SPDX-License-Identifier: MIT
"""Operation-scoped, explainable donor compatibility; never attests hardware."""
from spd_library import SPD
from spd_integrity import integrity_info
from spd_native import native_timings
from spd_vendor import normalize


def architecture(data):
    if data[2]==11:return ('DDR3 module type',data[3]&15)
    if data[2]==8:return ('DDR2 module type',data[20])
    return ('Legacy wiring',data[21]&0x3f)


def geometry(data):
    if data[2]==11:return tuple(data[i]&m for i,m in ((4,127),(5,63),(7,63),(8,31),(33,252)))
    if data[2]==8:return tuple(data[i]&m for i,m in ((3,15),(4,15),(5,23),(6,255),(7,255),(11,3),(13,255),(14,255),(17,255)))
    return tuple(data[i] for i in (3,4,5,6,7,11,13,14,17))


def assess(donor,target,operation='metadata',overrides=None):
    overrides=overrides or {};d,t=SPD(donor),SPD(target);hard=[];warnings=[];required=[];matches=[]
    if d.mem_type!=t.mem_type:hard.append('Memory generations differ')
    elif architecture(donor)!=architecture(target):hard.append('Module buffering/wiring architecture differs')
    elif geometry(donor)!=geometry(target):hard.append('Geometry, rank, package, width or ECC configuration differs')
    else:matches.append('Generation, architecture and encoded geometry match')
    for label,data in [('Donor',donor),('Target',target)]:
        if integrity_info(data)['status']!='VALID':hard.append(label+' base integrity is invalid')
    dm=d.decoded_data['manufacturing'];tm=t.decoded_data['manufacturing']
    dp=normalize(dm.get('module_part_number',''));tp=normalize(tm.get('module_part_number',''))
    if not dp or not tp or dp!=tp:
        warnings.append('Manufacturer part numbers differ or are absent; physical equivalence needs evidence')
        required.append('hardware_equivalence')
    else:matches.append('Manufacturer part numbers match')
    if dm.get('module_mfg_id')!=tm.get('module_mfg_id') or dm.get('dram_mfg_id')!=tm.get('dram_mfg_id'):
        warnings.append('Manufacturer identifiers differ; review actual chips and board')
        required.append('hardware_equivalence')
    electrical_difference=donor[2]==target[2]==11 and (donor[6]&7)!=(target[6]&7)
    if electrical_difference:
        warnings.append('Nominal voltage capabilities differ; target electrical declarations are preserved')
        if operation in ('timing','register'):required.append('hardware_equivalence')
    timing_difference=native_timings(donor)!=native_timings(target)
    if timing_difference:
        warnings.append('Native timings differ; metadata operations preserve target timings')
        if operation=='timing':required.append('timing')
    register_difference=False
    if donor[2]==target[2]==11 and donor[3]&15 in (1,5,9,11):
        if donor[3]&15!=11 and donor[68]&7!=target[68]&7:hard.append('Register device architectures differ')
        register_difference=donor[63:69]!=target[63:69] or donor[62]!=target[62]
        if register_difference:
            warnings.append('Register supplier/revision/configuration differs; no automatic control-word transfer')
            if operation=='register':required.append('register_equivalence')
    if donor[2]==target[2]==11 and (donor[62]&0x9f)!=(target[62]&0x9f):
        warnings.append('Reference raw-card identifiers differ; review PCB equivalence')
        required.append('hardware_equivalence')
    required=sorted(set(required));missing=[k for k in required if not isinstance(overrides.get(k),str) or not overrides[k].strip()]
    classification='Incompatible' if hard else 'Conditional match' if required else 'Hardware-equivalent' if timing_difference or register_difference or electrical_difference else 'Exact match'
    return dict(classification=classification,allowed=not hard and not missing,hard=hard,warnings=warnings,matches=matches,
                required_overrides=required,missing_overrides=missing,overrides={k:overrides[k] for k in required if k not in missing},operation=operation,
                note='Encoded compatibility is an inference. Matching part numbers do not prove chip identity, board equivalence or tested operation.')
