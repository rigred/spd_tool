# SPDX-License-Identifier: MIT
"""DDR3 XMP 1.1–1.3 authoring. Exact arithmetic and conservative quantization."""
from fractions import Fraction
import math
from ddr3_xmp_decoder import decode_xmp

TIMINGS=('tCKmin','tAAmin','tCWLmin','tRPmin','tRCDmin','tWRmin','tRASmin','tRCmin','tREFI','tRFCmin','tRTPmin','tRRDmin','tFAWmin','tWTRmin')
# (profile-relative coarse byte, width, fine byte when XMP 1.3)
FIELDS={'tCKmin':(1,8,26),'tAAmin':(2,8,27),'tCWLmin':(5,8,None),
        'tRPmin':(6,8,28),'tRCDmin':(7,8,29),'tWRmin':(8,8,None),
        'tRASmin':(10,12,None),'tRCmin':(11,12,30),'tREFI':(12,16,None),
        'tRFCmin':(14,16,None),'tRTPmin':(16,8,None),'tRRDmin':(17,8,None),
        'tFAWmin':(19,12,None),'tWTRmin':(20,8,None)}
RAW_FIELDS={'turnaround_raw':21,'back_to_back_raw':22,'command_rate_raw':23,'asr_raw':24,'controller_voltage_raw':25,'personality_raw':34}


def number(value):
    try:return Fraction(str(value))
    except (ValueError,ZeroDivisionError,TypeError) as exc:raise ValueError('Enter a finite number or fraction') from exc


def integer(value,low,high,label):
    value=number(value)
    if value.denominator!=1 or not low<=value<=high:raise ValueError(f'{label} must be an integer {low}–{high}')
    return int(value)


def require(data):
    if len(data)!=256 or data[2]!=11:raise ValueError('XMP authoring requires a complete 256-byte DDR3 SPD image')


def read_profile(data,index):
    require(data);index=integer(index,1,2,'Profile')
    if data[176:178]!=b'\x0c\x4a':raise ValueError('No DDR3 XMP header')
    if data[179] not in (0x11,0x12,0x13):raise ValueError('Unsupported XMP revision; use raw editing for unknown layouts')
    temp=bytearray(data);temp[178]|=1<<(index-1)
    parsed=decode_xmp(temp)
    entry=next((p for p in parsed.get('xmp_profiles_detailed',[]) if p['profile']==index),None)
    if not entry:raise ValueError('Profile is incomplete or has an invalid timebase/clock')
    base=185+(index-1)*35;mtb=180+(index-1)*2
    return dict(encoded_max_rate_MTps=2000/entry['timings_ns']['tCKmin'], enabled=bool(data[178]&(1<<(index-1))),dimms_per_channel=entry['dimms_per_channel'],
                voltage_V=entry['voltage_V'],cas_latencies=entry['cas_latencies_supported'],
                mtb_dividend=data[mtb],mtb_divisor=data[mtb+1],timings_ns=entry['timings_ns'],
                **{key:data[base+offset] for key,offset in RAW_FIELDS.items()})


def quantize(value,mtb,ftb,width,upper=False):
    value=number(value)
    if value<=0:raise ValueError('Timing values must be positive')
    maximum=(1<<width)-1
    if not ftb:
        count=math.floor(value/mtb) if upper else math.ceil(value/mtb)
        if not 1<=count<=maximum:raise ValueError('Timing exceeds its encoded field/timebase')
        return count,0,count*mtb
    best=None
    lower=math.floor((value-127*ftb)/mtb)-1
    upper=math.ceil((value+128*ftb)/mtb)+1
    for count in range(max(1,lower),min(maximum,upper)+1):
        fine=max(-128,math.ceil((value-count*mtb)/ftb))
        encoded=count*mtb+fine*ftb
        if fine>127 or encoded<value or encoded<=0:continue
        if best is None or encoded<best[2] or encoded==best[2] and abs(fine)<abs(best[1]):best=(count,fine,encoded)
    if best is None:raise ValueError('Timing cannot fit the selected MTB/FTB fields')
    return best


def encode_profile(data,index,profile,replace_customer=False,allow_inconsistent=False):
    require(data);index=integer(index,1,2,'Profile');result=bytearray(data)
    required=('voltage_V','cas_latencies','mtb_dividend','mtb_divisor','timings_ns')
    if not isinstance(profile,dict) or any(k not in profile for k in required):raise ValueError('Incomplete XMP profile object')
    if not isinstance(profile['timings_ns'],dict) or any(k not in profile['timings_ns'] for k in TIMINGS):raise ValueError('Supply all XMP timing fields')
    if not isinstance(profile['cas_latencies'],(list,tuple)):raise ValueError('CAS latencies must be a list')
    existing=data[176:178]==b'\x0c\x4a'
    if not existing:
        if any(b not in (0,255) for b in data[176:256]) and not replace_customer:
            raise ValueError('Customer region contains HP HPT/vendor data; explicitly permit replacing it with XMP')
        result[176:256]=bytes(80)
        result[176:185]=bytes.fromhex('0c 4a 00 13 01 08 01 08 11')
    revision=result[179]
    if revision not in (0x11,0x12,0x13):raise ValueError('Unsupported XMP revision')
    div=integer(profile['mtb_dividend'],1,255,'MTB dividend');den=integer(profile['mtb_divisor'],1,255,'MTB divisor')
    mtb=Fraction(div,den);ftb=0
    if revision==0x13:
        if not result[184]>>4 or not result[184]&15:raise ValueError('Invalid global XMP fine timebase')
        ftb=Fraction(result[184]>>4,result[184]&15)/1000
    base=185+(index-1)*35;mtbo=180+(index-1)*2
    result[mtbo:mtbo+2]=bytes((div,den))
    enabled=profile.get('enabled',True)
    if not isinstance(enabled,bool):raise ValueError('Profile enabled must be true/false')
    flag=1<<(index-1);shift=2+(index-1)*2
    dimms=integer(profile.get('dimms_per_channel',1),1,4,'DIMMs per channel')
    result[178]=(result[178]&~(flag|(3<<shift))) | (flag if enabled else 0)|((dimms-1)<<shift)
    voltage=number(profile['voltage_V'])
    if voltage<=0 or voltage>=3 or (voltage*20).denominator!=1:raise ValueError('VDD must be positive, below 3 V and in 0.05 V steps; this is an encoding limit, not a safe-voltage recommendation')
    units=voltage.numerator//voltage.denominator;remaining=voltage-units
    tenths=math.floor(remaining*10);half=int((remaining-Fraction(tenths,10))*20)
    result[base]=(result[base]&128)|(units<<5)|(tenths<<1)|half
    cas=sorted({integer(v,4,18,'CAS latency') for v in profile['cas_latencies']})
    if not cas:raise ValueError('Select at least one CAS latency')
    bitmap=sum(1<<(cl-4) for cl in cas)
    result[base+3]=bitmap&255;result[base+4]=(result[base+4]&128)|((bitmap>>8)&127)
    actual={}
    for key,(offset,width,fine_offset) in FIELDS.items():
        count,fine,value=quantize(profile['timings_ns'][key],mtb*1000 if key=='tREFI' else mtb,ftb if fine_offset is not None else 0,width,key=='tREFI')
        actual[key]=value
        if width==8:result[base+offset]=count
        elif width==16:result[base+offset:base+offset+2]=count.to_bytes(2,'little')
        elif key=='tRASmin':
            result[base+9]=(result[base+9]&240)|(count>>8);result[base+10]=count&255
        elif key=='tRCmin':
            result[base+9]=(result[base+9]&15)|((count>>8)<<4);result[base+11]=count&255
        else:
            result[base+18]=(result[base+18]&240)|(count>>8);result[base+19]=count&255
        if fine_offset is not None and revision==0x13:result[base+fine_offset]=fine&255
    if not allow_inconsistent and max(cas)*actual['tCKmin']<actual['tAAmin']:raise ValueError('No selected CAS latency satisfies encoded tAA at encoded tCK')
    if not allow_inconsistent and actual['tRCmin']<actual['tRASmin']+actual['tRPmin']:raise ValueError('Encoded tRC must cover encoded tRAS + tRP')
    for key,offset in RAW_FIELDS.items():
        if key in profile:result[base+offset]=integer(profile[key],0,255,key)
    # All XMP fields live outside base CRC; JEDEC, identity and the other profile stay unchanged.
    assert result[:176]==data[:176]
    return bytes(result)
