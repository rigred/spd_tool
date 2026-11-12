# SPDX-License-Identifier: MIT
"""Generation-specific primary timing encoders. No extension bytes are copied."""
import math
from fractions import Fraction
from spd_library import SPD
from spd_integrity import repair_integrity
from spd_xmp import number, integer, quantize
from ddr2_decoder import cycle_time,access_time
from legacy_decoder import _tenths,_hundredths


def lookup_encode(value,decode,maximum=255):
    value=number(value)
    if value<=0:raise ValueError('Timing must be positive')
    candidates=[(number(decode(raw)),raw) for raw in range(1,maximum+1) if decode(raw) is not None and number(decode(raw))>=value]
    if not candidates:raise ValueError('Timing cannot be represented without rounding below its minimum')
    return min(candidates)[1]


def count(value,scale,bits=8):
    result=math.ceil(number(value)/number(scale))
    if not 1<=result<(1<<bits):raise ValueError('Timing exceeds its native field')
    return result


def native_timings(data):
    decoded=SPD(data).decoded_data
    return {k:v for k,v in decoded['timings_ns'].items() if v is not None and (k.endswith('min') or k in ('tACmax',))}


def encode_native(data,timings,cas=None):
    spd=SPD(data);mem=data[2];out=bytearray(data)
    original=spd.decoded_data
    allowed=set(native_timings(data))
    unknown=set(timings)-allowed
    if unknown:raise ValueError('Unsupported native timing fields: '+', '.join(sorted(unknown)))
    if any(number(v)<=0 for v in timings.values()):raise ValueError('Timing minima must be positive')
    timings={k:v for k,v in timings.items() if number(v)!=number(original['timings_ns'][k])}
    if mem==11:
        if not data[10] or not data[11] or not data[9]>>4 or not data[9]&15:raise ValueError('Invalid native DDR3 timebases')
        mtb=Fraction(data[10],data[11]);ftb=Fraction(data[9]>>4,data[9]&15)/1000
        fields={'tCKmin':(12,8,34),'tAAmin':(16,8,35),'tWRmin':(17,8,None),'tRCDmin':(18,8,36),
                'tRRDmin':(19,8,None),'tRPmin':(20,8,37),'tRASmin':(22,12,None),'tRCmin':(23,12,38),
                'tRFCmin':(24,16,None),'tWTRmin':(26,8,None),'tRTPmin':(27,8,None),'tFAWmin':(29,12,None)}
        for key,value in timings.items():
            offset,width,fine=fields[key];coarse,delta,_=quantize(value,mtb,ftb if fine is not None else 0,width)
            if width==8:out[offset]=coarse
            elif width==16:out[offset:offset+2]=coarse.to_bytes(2,'little')
            elif key=='tRASmin':out[21]=(out[21]&240)|(coarse>>8);out[22]=coarse&255
            elif key=='tRCmin':out[21]=(out[21]&15)|((coarse>>8)<<4);out[23]=coarse&255
            else:out[28]=(out[28]&240)|(coarse>>8);out[29]=coarse&255
            if fine is not None:out[fine]=delta&255
        if cas is not None:
            values={integer(c,4,18,'CAS') for c in cas}
            if not values:raise ValueError('At least one CAS is required')
            bitmap=sum(1<<(c-4) for c in values);out[14:16]=bitmap.to_bytes(2,'little')
    else:
        if 'tCKmin' in timings:
            decode=cycle_time if mem==8 else _tenths
            out[9]=lookup_encode(timings['tCKmin'],decode)
        if 'tACmax' in timings:
            # Access time is a maximum: conservative upward encoding reports a slower part.
            out[10]=lookup_encode(timings['tACmax'],access_time if mem==8 else _hundredths if mem==7 else _tenths)
        for key,offset in [('tRPmin',27),('tRRDmin',28),('tRCDmin',29),('tRASmin',30),
                           ('tWRmin',36),('tWTRmin',37),('tRTPmin',38)]:
            if key in timings:out[offset]=count(timings[key],1 if mem==4 or offset==30 else '.25')
        for key,offset in [('tRCmin',41),('tRFCmin',42)]:
            if key not in timings:continue
            if mem==8:
                fractions=[Fraction(0),Fraction(1,4),Fraction(33,100),Fraction(1,2),Fraction(66,100),Fraction(3,4)]
                options=[]
                for high in range(2 if key=='tRFCmin' else 1):
                    for code,fraction in enumerate(fractions):
                        lo=math.ceil(number(timings[key])-256*high-fraction)
                        if 0<=lo<=255:options.append((lo+256*high+fraction,lo,code,high))
                if not options:raise ValueError('Extended timing exceeds native DDR2 representation')
                _,lo,code,high=min(options);out[offset]=lo
                if key=='tRCmin':out[40]=(out[40]&0x8F)|(code<<4)
                else:out[40]=(out[40]&0xF0)|(code<<1)|high
            else:out[offset]=count(timings[key],1)
        if cas is not None:
            values={number(c) for c in cas}
            legal={Fraction(i,2):i-2 for i in range(2,9)} if mem==7 else {Fraction(i):i if mem==8 else i-1 for i in range(2 if mem==8 else 1,7 if mem==8 else 8)}
            if not values or not values<=legal.keys():raise ValueError('CAS cannot be represented in this generation')
            out[18]=sum(1<<legal[c] for c in values)
            # Lower-CAS points are tied to the highest CAS. Invalidate stale points.
            if out[18]!=data[18]:out[23:27]=bytes(4)
    result=repair_integrity(out);decoded=SPD(result).decoded_data;actual=decoded['timings_ns']
    if actual.get('tRCmin') is not None and actual.get('tRPmin') and actual.get('tRASmin') and actual['tRCmin']+1e-6<actual['tRPmin']+actual['tRASmin']:
        raise ValueError('Encoded tRC is below tRAS + tRP; include coherent dependent timings')
    if mem==11 and not decoded.get('timings_clocks',{}).get('CL'):raise ValueError('Native CAS bitmap cannot satisfy tAA/tCK')
    return result


def promote_xmp(data,index,acknowledged=False):
    if not acknowledged:raise ValueError('Danger Zone conversion requires explicit tested-hardware acknowledgment')
    from spd_xmp import read_profile
    p=read_profile(data,index)
    if not p['enabled']:raise ValueError('Select an enabled XMP profile')
    fields={k:v for k,v in p['timings_ns'].items() if k in native_timings(data)}
    if not data[10] or not data[11] or not data[9]>>4 or not data[9]&15:raise ValueError('Invalid native DDR3 timebases')
    mtb=Fraction(data[10],data[11]);ftb=Fraction(data[9]>>4,data[9]&15)/1000
    ras=quantize(fields['tRASmin'],mtb,0,12)[2];rp=quantize(fields['tRPmin'],mtb,ftb,8)[2]
    fields['tRCmin']=max(number(fields['tRCmin']),ras+rp)
    result=encode_native(data,fields,p['cas_latencies'])
    return result,dict(source=f'XMP {index}',voltage_V=p['voltage_V'],untranslated=['tCWLmin','tREFI','command rate','XMP VDD/controller assumptions'],
                       note='Native SPD cannot request arbitrary XMP voltage. Controller support and real operation remain unverified.')
