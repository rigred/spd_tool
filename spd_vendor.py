# SPDX-License-Identifier: MIT
"""Conservative vendor observations and serial-preserving HP donor templates."""
import hashlib
import re

from hp_smartmemory_ident import load_registry
from pathlib import Path
from spd_integrity import integrity_info, repair_integrity
from spd_library import SPD


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def normalize(part):
    return re.sub(r'\s+','',part.upper()).strip('\0')


def vendor_metadata(data, decoded=None):
    decoded = SPD(data).decoded_data if decoded is None else decoded
    mfg = decoded.get('manufacturing', {})
    regions=[]
    ranges=[(150,176,'Manufacturer-specific'),(176,len(data),'Customer-use')] if data[2]==11 else [(99,min(126,len(data)),'Manufacturer-specific'),(128,len(data),'Extended data')]
    for start,end,name in ranges:
        if start>=end:continue
        raw=data[start:end]
        strings=[dict(offset=start+m.start(),text=m.group().decode('ascii')) for m in re.finditer(rb'[\x20-\x7e]{4,}',raw)]
        regions.append(dict(name=name,start=start,end=end-1,nonblank=any(b not in (0,255) for b in raw),hex=raw.hex().upper(),text=strings))
    hpt=data[2]==11 and len(data)>=184 and data[176:180]==b'HPT\0'
    matches=[]
    if hpt:
        serial=int.from_bytes(data[122:126],'big');code=int.from_bytes(data[180:184],'big')
        for key,family in load_registry(str(Path(__file__).with_name('hp_families.json'))).items():
            try:
                a,b,k=(int(family[c],16) for c in ('A','B','K'))
                if (a*serial+b*code)&0xFFFFFFFF==k:matches.append(dict(key=key,name=family.get('name',key),basis='serial/HPT equation match'))
            except (ValueError,KeyError,TypeError):pass
    hints=[];identifiers=[]
    for region in regions:
        for item in region['text']:
            for candidate in re.finditer(r'(?<![A-Z0-9])[0-9]{6}-[0-9]{3}(?![A-Z0-9])',item['text'],re.I):
                identifiers.append(dict(value=candidate.group(),offset=item['offset']+candidate.start(),basis='unverified numeric part-number pattern'))
            for name,pattern in [('HP/HPE',r'\b(?:HP|HPE|HEWLETT[ -]PACKARD)\b'),('Dell',r'\bDELL\b'),('Lenovo',r'\bLENOVO\b'),('IBM',r'\bIBM\b'),('Cisco',r'\bCISCO\b'),('Samsung',r'\bSAMSUNG\b'),('Micron',r'\bMICRON\b'),('SK hynix',r'\b(?:SK[ -])?HYNIX\b'),('Kingston',r'\bKINGSTON\b')]:
                if re.search(pattern,item['text'],re.I):hints.append(dict(vendor=name,offset=item['offset'],basis='unverified text hint'))
    return dict(module_manufacturer=mfg.get('module_mfg_id'),dram_manufacturer=mfg.get('dram_mfg_id'),
                manufacturer_part_number=mfg.get('module_part_number',mfg.get('part_number')),
                hpt_signature_present=hpt,possible_oem='HP/HPE-compatible HPT layout' if hpt else None,
                hpt_code=data[180:184].hex().upper() if hpt else None,
                registry_matches=matches,text_hints=hints,possible_part_numbers=identifiers,regions=regions,
                note='Decoded manufacturer IDs, observed signatures and text hints are separate from sticker metadata. Signatures and equation matches do not authenticate OEM origin.')


def compatible_target(donor, target):
    if len(donor)<184 or len(target)<184 or donor[2]!=11 or target[2]!=11:
        raise ValueError('HP donor profiles require DDR3 images containing bytes 176–183')
    from spd_compatibility import assess
    report=assess(donor,target)
    if not report['allowed']:raise ValueError('; '.join(report['hard']+['Required review: '+key for key in report['missing_overrides']]))
    return report


def apply_hp_template(donor, target, hpt, copy_opaque=False, replace_existing=False):
    compatible_target(donor,target)
    if donor[176:180]!=b'HPT\0':raise ValueError('Donor lacks an HP HPT signature')
    if not re.fullmatch(r'[0-9A-Fa-f]{8}',hpt):raise ValueError('Choose an eight-digit HPT value')
    current=target[176:184]
    if current[:4]!=b'HPT\0' and any(b not in (0,255) for b in current) and not replace_existing:
        raise ValueError('Target has existing customer data (possibly XMP); explicitly permit replacement after review')
    result=bytearray(target)
    if copy_opaque:
        if len(donor)!=256 or len(target)!=256:
            raise ValueError('Opaque vendor/customer templates require full 256-byte donor and target images')
        result[150:176]=donor[150:176]
        result[184:256]=donor[184:256]
    result[176:184]=b'HPT\0'+bytes.fromhex(hpt)
    result=repair_integrity(result)
    assert result[117:150]==target[117:150]  # Manufacturer, date, serial, part and revisions.
    assert result[3:117]==target[3:117]
    return bytes(result)
