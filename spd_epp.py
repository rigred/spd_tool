# SPDX-License-Identifier: MIT
"""NVIDIA SP-02496-001 rev01 DDR2 UDIMM EPP full/abbreviated profiles."""
from fractions import Fraction
from spd_xmp import number,integer
from spd_native import lookup_encode,count
from ddr2_decoder import cycle_time

MAGIC=bytes.fromhex('6d564e')


def epp_cycle(raw):return 1.875 if raw==0x1E else cycle_time(raw)


def require(data):
    if len(data)<128 or data[2]!=8:raise ValueError('EPP is defined here for DDR2, not other generations')


def decode_epp(data):
    require(data)
    if data[99:102]!=MAGIC:return None
    if data[102] not in (0xA1,0xB1):return dict(format='unknown',raw=data[99:128].hex(),profiles=[])
    full=data[102]==0xB1;size=12 if full else 6;profiles=[]
    for index in range(2 if full else 4):
        base=104+index*size;timing=base+5 if full else base+1
        mask=data[timing+1];cas=[c for c in range(2,7) if mask&(1<<c)]
        times=dict(tCKmin=epp_cycle(data[timing]),tRCDmin=data[timing+2]/4,tRPmin=data[timing+3]/4,tRASmin=data[timing+4])
        p=dict(index=index,enabled=bool(data[103]&(1<<(4+index))),voltage_V=1.8+(data[base]&127)*.025,
               command_rate=2 if data[base]&128 else 1,cas=cas[0] if len(cas)==1 else None,timings_ns=times)
        p['errors']=[]
        if data[base]&127>28:p['errors'].append('Reserved EPP voltage encoding')
        if len(cas)!=1 or mask!=sum(1<<c for c in cas):p['errors'].append('EPP requires exactly one CAS 2–6')
        if any(not value or value<=0 for value in times.values()):p['errors'].append('Timing fields must be positive')
        if not times['tCKmin']:p['errors'].append('Invalid cycle encoding')
        if full:
            p.update(address_drive=data[base+1]&3,cs_drive=(data[base+1]>>2)&3,clock_drive=(data[base+1]>>4)&3,
                     data_drive=data[base+1]>>6,dqs_drive=data[base+2]&3,address_delay=data[base+3]&31,
                     address_setup=(data[base+3]>>5)&1,cs_delay=data[base+4]&31,cs_setup=(data[base+4]>>5)&1)
            times.update(tWRmin=data[base+10]/4,tRCmin=data[base+11])
            if times['tRCmin']<times['tRASmin']+times['tRPmin']:p['errors'].append('tRC < tRAS + tRP')
            if not times['tWRmin']:p['errors'].append('tWR is zero')
        profiles.append(p)
    return dict(format='full' if full else 'abbreviated',optimal=data[103]&3,profiles=profiles)


def encode_epp(data,index,profile,format='full',replace=False,optimal=None,allow_inconsistent=False):
    require(data)
    if data[20]!=2:raise ValueError('This published EPP format is scoped to DDR2 unbuffered DIMMs (UDIMM)')
    if format not in ('full','abbreviated'):raise ValueError('Unknown EPP format')
    full=format=='full';index=integer(index,0,1 if full else 3,'EPP index');out=bytearray(data)
    kind=0xB1 if full else 0xA1
    if out[99:102]!=MAGIC or out[102]!=kind:
        if any(b not in (0,255) for b in out[99:128]) and not replace:raise ValueError('Replacing manufacturer data/EPP format requires explicit permission')
        out[99:128]=bytes(29);out[99:102]=MAGIC;out[102]=kind
    base=104+index*(12 if full else 6);timing=base+5 if full else base+1
    voltage=(number(profile['voltage_V'])-Fraction(18,10))/Fraction(25,1000)
    if voltage.denominator!=1 or not 0<=voltage<=28:raise ValueError('EPP VDD is 1.8–2.5 V in 0.025 V steps (encoding range, not a safe recommendation)')
    command=integer(profile['command_rate'],1,2,'Command rate')
    out[base]=int(voltage)|((command-1)<<7)
    t=profile['timings_ns'];out[timing]=lookup_encode(t['tCKmin'],epp_cycle)
    out[timing+1]=1<<integer(profile['cas'],2,6,'CAS')
    out[timing+2]=count(t['tRCDmin'],'.25');out[timing+3]=count(t['tRPmin'],'.25');out[timing+4]=count(t['tRASmin'],1)
    if not allow_inconsistent and full and number(t['tRCmin']) < number(t['tRASmin'])+number(t['tRPmin']):raise ValueError('tRC must be at least tRAS + tRP')
    if full:
        out[base+10]=count(t['tWRmin'],'.25');out[base+11]=count(t['tRCmin'],1)
        for key,off,shift,bits in [('address_drive',1,0,2),('cs_drive',1,2,2),('clock_drive',1,4,2),('data_drive',1,6,2),('dqs_drive',2,0,2),
                                   ('address_delay',3,0,5),('address_setup',3,5,1),('cs_delay',4,0,5),('cs_setup',4,5,1)]:
            if key in profile:
                mask=((1<<bits)-1)<<shift;out[base+off]=(out[base+off]&~mask)|(integer(profile[key],0,(1<<bits)-1,key)<<shift)
    flag=1<<(4+index)
    if not isinstance(profile.get('enabled',True),bool):raise ValueError('Enabled must be true/false')
    out[103]=(out[103]|flag) if profile.get('enabled',True) else (out[103]&~flag)
    valid=[i for i in range(2 if full else 4) if out[103]&(1<<(4+i))]
    if not valid:raise ValueError('At least one EPP profile must be enabled')
    best=integer(optimal,0,1 if full else 3,'Optimal profile') if optimal is not None else out[103]&3
    if best not in valid:
        if optimal is not None:raise ValueError('Optimal EPP profile must be enabled')
        best=valid[0]
    out[103]=(out[103]&~3)|best
    return bytes(out)


def duplicate_epp(data,source,destination):
    parsed=decode_epp(data)
    if not parsed or parsed['format']=='unknown':raise ValueError('No supported EPP profiles')
    p=parsed['profiles'][integer(source,0,len(parsed['profiles'])-1,'Source')]
    return encode_epp(data,destination,p,parsed['format'])
