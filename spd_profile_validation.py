# SPDX-License-Identifier: MIT
"""Live profile diagnostics using the same exact quantization as the encoder.

Clock envelopes are encoding/CAS constraints, never measured chip speed ranges.
"""
import math
from fractions import Fraction
from spd_xmp import FIELDS,TIMINGS,number,integer,quantize,encode_profile


def validate_xmp(data,index,profile,replace=False,evidence=None):
    errors={};warnings={};actual={};envelope=None
    def error(key,message):errors.setdefault(key,[]).append(message)
    try:
        dividend=integer(profile.get('mtb_dividend'),1,255,'MTB dividend')
        divisor=integer(profile.get('mtb_divisor'),1,255,'MTB divisor');mtb=Fraction(dividend,divisor)
    except ValueError as exc:
        error('mtb_dividend',str(exc));error('mtb_divisor',str(exc));mtb=None
    if len(data)!=256 or data[2]!=11:error('_image','A complete 256-byte DDR3 image is required')
    existing=len(data)==256 and data[176:178]==b'\x0c\x4a'
    revision=data[179] if existing else 0x13
    if revision not in (0x11,0x12,0x13):error('_format','Unsupported XMP revision')
    ftb=Fraction(1,1000)
    if revision==0x13 and existing:
        if not data[184]>>4 or not data[184]&15:error('mtb_dividend','Global XMP fine timebase is invalid');mtb=None
        else:ftb=Fraction(data[184]>>4,data[184]&15)/1000
    if revision!=0x13:ftb=0
    for key,(offset,width,fine) in FIELDS.items():
        try:
            value=number(profile.get('timings_ns',{}).get(key,''))
            if value<=0:raise ValueError('Enter a positive timing')
            if mtb is not None:
                _,_,encoded=quantize(value,mtb*1000 if key=='tREFI' else mtb,ftb if fine is not None else 0,width,key=='tREFI')
                actual[key]=encoded
                if encoded!=value:warnings[key]=[f'Encoded as {float(encoded):g} ns ({"down" if key=="tREFI" else "up"}ward quantization)']
        except ValueError as exc:error(key,str(exc))
    try:
        cas=sorted({integer(c,4,18,'CAS') for c in profile.get('cas_latencies',[])})
        if not cas:raise ValueError('Select at least one CAS 4–18')
    except (ValueError,TypeError) as exc:error('cas_latencies',str(exc));cas=[]
    if cas and 'tAAmin' in actual and 'tCKmin' in actual:
        required=math.ceil(actual['tAAmin']/actual['tCKmin'])
        if max(cas)<required:
            text=f'Needs CL ≥ {required} at encoded tCK {float(actual["tCKmin"]):g} ns; selected CAS stops at {max(cas)}'
            for key in ('cas_latencies','tAAmin','tCKmin'):warnings.setdefault(key,[]).append(text)
        else:required=None
        if mtb is not None:
            try:
                low=quantize(actual['tAAmin']/max(cas),mtb,ftb,8)[2]
                high=255*mtb+(127*ftb if ftb else 0)
                envelope=dict(min_tCK_ns=float(low),max_tCK_ns=float(high),min_clock_MHz=float(1000/high),max_clock_MHz=float(1000/low),
                              min_rate_MTps=float(2000/high),max_rate_MTps=float(2000/low))
            except ValueError: warnings.setdefault('cas_latencies',[]).append('No representable clock satisfies selected CAS / tAA')
    if all(k in actual for k in ('tRCmin','tRASmin','tRPmin')) and actual['tRCmin']<actual['tRASmin']+actual['tRPmin']:
        for key in ('tRCmin','tRASmin','tRPmin'):warnings.setdefault(key,[]).append('Encoded tRC is below encoded tRAS + tRP')
    for key,lo,hi in [('dimms_per_channel',1,4)]:
        try:integer(profile.get(key,1),lo,hi,key)
        except ValueError as exc:error(key,str(exc))
    try:
        v=number(profile.get('voltage_V'))
        if not 0<v<3 or (v*20).denominator!=1:raise ValueError('VDD needs 0.05 V steps, positive and below 3 V')
    except ValueError as exc:error('voltage_V',str(exc))
    evidence_issues=[]
    if evidence:
        from spd_timing_planner import validate_evidence
        try:
            validated=validate_evidence(data,evidence);sheet=validated.get('datasheet',{});period=actual.get('tCKmin');voltage=number(profile.get('voltage_V'))
            def limit(key,message):warnings.setdefault(key,[]).append(message);evidence_issues.append(message)
            if period:
                rate=2000/period
                if sheet.get('max_rate_MTps') and rate>number(sheet['max_rate_MTps']):limit('tCKmin','Above the supplied datasheet maximum rate')
                if sheet.get('tCKmin_ns') and period<number(sheet['tCKmin_ns']):limit('tCKmin','Below the supplied datasheet minimum period')
                for key,bounds in sheet.get('timings',{}).items():
                    if key not in actual:continue
                    floor=max(number(bounds.get('min_ns',0)),number(bounds.get('min_cycles',0))*period)
                    if key!='tREFI' and actual[key]<floor:limit(key,'Below supplied datasheet minimum')
                    if key=='tREFI' and actual[key]>number(bounds.get('max_ns',actual[key])):limit(key,'Refresh interval exceeds supplied maximum')
                for point in validated.get('tested_points',[]):
                    if not point['passed'] and number(point['rate_MTps'])==rate and number(point['voltage_V'])==voltage:limit('tCKmin','A supplied failed test exists at this speed/voltage')
            if sheet.get('voltage_min_V') and voltage<number(sheet['voltage_min_V']):limit('voltage_V','Below supplied voltage envelope')
            if sheet.get('voltage_max_V') and voltage>number(sheet['voltage_max_V']):limit('voltage_V','Above supplied voltage envelope')
        except ValueError as exc:error('_evidence',str(exc))
    return dict(errors=errors,warnings=warnings,actual_ns={k:float(v) for k,v in actual.items()},clock_envelope=envelope,
                logical_valid=not evidence_issues and not any('Needs CL' in message or 'tRC is below' in message or 'No representable' in message for values in warnings.values() for message in values))


def generate_xmp_at_rate(data,index,profile,rate,evidence=None,source='current',override=False):
    """Preserve absolute minima; regenerate cycle-derived values for a chosen rate."""
    from spd_timing_planner import plan_bins,cwl_default
    from spd_xmp import read_profile
    rate=number(rate)
    if not 1<=rate<=10000:raise ValueError('Choose a positive rate of 1–10000 MT/s')
    if source=='SPD':
        rows=plan_bins(data,[rate],profile['voltage_V'],profile['timings_ns'].get('tREFI',7800),evidence=evidence)
        row=rows[0]
        if row['violations'] and not override:raise ValueError('; '.join(row['violations']))
        result=row['profile']
        if result is None and row['violations'] and override:
            result=plan_bins(data,[rate],profile['voltage_V'],profile['timings_ns'].get('tREFI',7800))[0]['profile']
        if result is None:raise ValueError(row['profile_error'] or 'Cannot generate this XMP proposal')
        lineage=dict(row,evidence=evidence or {},overridden_constraints=row['violations'] if override else [])
    else:
        from spd_timing_planner import validate_evidence
        evidence=validate_evidence(data,evidence or {})
        sheet=evidence.get('datasheet',{})
        period=Fraction(2000,1)/rate
        violations=[]
        if sheet.get('max_rate_MTps') and rate>number(sheet['max_rate_MTps']):violations.append('Target exceeds datasheet maximum rate')
        if sheet.get('tCKmin_ns') and period<number(sheet['tCKmin_ns']):violations.append('Target period is below datasheet minimum')
        voltage=number(profile['voltage_V'])
        if sheet.get('voltage_min_V') and voltage<number(sheet['voltage_min_V']):violations.append('Below datasheet voltage envelope')
        if sheet.get('voltage_max_V') and voltage>number(sheet['voltage_max_V']):violations.append('Above datasheet voltage envelope')
        if any(not p['passed'] and number(p['rate_MTps'])==rate and number(p['voltage_V'])==voltage for p in evidence.get('tested_points',[])):violations.append('Failed test at this speed/voltage')
        if violations and not override:raise ValueError('; '.join(violations))
        result=dict(profile,timings_ns=dict(profile['timings_ns']))
        # Reject malformed inputs, but permit repairing logically inconsistent drafts.
        validation=validate_xmp(data,index,profile)
        if validation['errors']:raise ValueError('Fix unencodable fields before generation: '+', '.join(validation['errors']))
        result['timings_ns']['tCKmin']=float(period)
        for key in TIMINGS:
            if key in ('tCKmin','tREFI','tCWLmin'):continue
            result['timings_ns'][key]=float(math.ceil(number(profile['timings_ns'][key])/period)*period)
        for key,bounds in sheet.get('timings',{}).items():
            if key not in result['timings_ns']:continue
            if key=='tREFI':result['timings_ns'][key]=float(min(number(result['timings_ns'][key]),number(bounds.get('max_ns',result['timings_ns'][key]))))
            else:result['timings_ns'][key]=float(max(number(result['timings_ns'][key]),number(bounds.get('min_ns',0)),number(bounds.get('min_cycles',0))*period))
        cwl=cwl_default(period)
        if cwl is None:raise ValueError('No reference CWL for this period; configure a profile manually')
        step=Fraction(integer(result['mtb_dividend'],1,255,'MTB dividend'),integer(result['mtb_divisor'],1,255,'MTB divisor'))
        result['timings_ns']['tCWLmin']=float(math.floor(cwl*period/step)*step)
        # Keep the draft's own timebase; derive CAS from the actual encoded tCK/tAA.
        v=validate_xmp(data,index,result)
        if v['errors']:raise ValueError('Generated timings exceed fields: '+', '.join(v['errors']))
        encoded=v['actual_ns'];cl=math.ceil(number(encoded['tAAmin'])/number(encoded['tCKmin']))
        if not 4<=cl<=18:raise ValueError(f'Required CAS {cl} cannot fit DDR3 XMP (4–18)')
        result['cas_latencies']=[max(4,cl)]
        result['timings_ns']['tRCmin']=max(result['timings_ns']['tRCmin'],encoded['tRASmin']+encoded['tRPmin'])
        lineage=dict(anchor='current XMP absolute timing minima',rate_MTps=float(rate),classification='extrapolated; untested',evidence=evidence or {},warnings=['No voltage increase or stability inference']+violations)
    # The real encoder is the final authority, including reserved/global timebases.
    encoded=encode_profile(data,index,result,True,allow_inconsistent=override)
    actual=read_profile(encoded,index)
    return result,dict(lineage,requested_rate_MTps=float(rate),encoded_rate_MTps=actual['encoded_max_rate_MTps'],override=override)
