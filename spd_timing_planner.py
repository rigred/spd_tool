# SPDX-License-Identifier: MIT
"""Clock-bin proposals from absolute timing anchors and explicit external evidence."""
import hashlib
import math
from fractions import Fraction
from spd_library import SPD
from spd_xmp import TIMINGS, number, integer, quantize, encode_profile


def cwl_default(period):
    # DDR3 reference ranges used by U-Boot's compute_cas_write_latency.
    for boundary,value in [('2.5',5),('1.875',6),('1.5',7),('1.25',8),('1.07',9),('.935',10),('.833',11),('.75',12)]:
        if period>=number(boundary):return value
    return None


def evidence_template(data):
    return dict(schema='spd-tool-timing-evidence/1',module_sha256=hashlib.sha256(data).hexdigest(),
                datasheet=dict(reference='',chip_part_number='',timings={}),tested_points=[])


def validate_evidence(data,evidence):
    if evidence is None:return {}
    if not isinstance(evidence,dict):raise ValueError('Evidence must be a JSON object')
    if not evidence:return {}
    if evidence.get('schema')!='spd-tool-timing-evidence/1' or evidence.get('module_sha256')!=hashlib.sha256(data).hexdigest():
        raise ValueError('Evidence schema or module SHA-256 does not match the current image')
    allowed={'schema','module_sha256','datasheet','tested_points'}
    if set(evidence)-allowed:raise ValueError('Unknown evidence fields')
    sheet=evidence.get('datasheet',{})
    if not isinstance(sheet,dict) or set(sheet)-{'reference','chip_part_number','max_rate_MTps','voltage_min_V','voltage_max_V','tCKmin_ns','timings','conditions'}:
        raise ValueError('Unknown datasheet constraint fields')
    for key in ('reference','chip_part_number','conditions'):
        if key in sheet and not isinstance(sheet[key],str):raise ValueError('Datasheet references and conditions must be text')
    if sheet.get('timings') or any(k in sheet for k in ('max_rate_MTps','voltage_min_V','voltage_max_V','tCKmin_ns')):
        if not sheet.get('reference') or not sheet.get('chip_part_number'):raise ValueError('Datasheet constraints need a chip part number and source/page reference')
    if not isinstance(sheet.get('timings',{}),dict):raise ValueError('Datasheet timings must be an object')
    for key,value in sheet.get('timings',{}).items():
        if key not in TIMINGS or key=='tCKmin' or not isinstance(value,dict) or set(value)-{'min_ns','min_cycles','max_ns'}:raise ValueError('Unknown timing constraint')
        if key=='tREFI' and set(value)-{'max_ns'}:raise ValueError('tREFI is a maximum refresh interval; use max_ns')
        if key!='tREFI' and 'max_ns' in value:raise ValueError('Minimum timings use min_ns/min_cycles')
        if any(number(v)<=0 for v in value.values()):raise ValueError('Timing constraints must be positive')
    for key in ('max_rate_MTps','voltage_min_V','voltage_max_V','tCKmin_ns'):
        if key in sheet and number(sheet[key])<=0:raise ValueError('Operating limits must be positive')
    if 'voltage_min_V' in sheet and 'voltage_max_V' in sheet and number(sheet['voltage_min_V'])>number(sheet['voltage_max_V']):raise ValueError('Datasheet voltage range is reversed')
    points=evidence.get('tested_points',[])
    if not isinstance(points,list) or len(points)>256:raise ValueError('Use at most 256 tested points')
    for point in points:
        if not isinstance(point,dict) or set(point)-{'rate_MTps','voltage_V','timings_cycles','reference','passed','notes','temperature_C'}:
            raise ValueError('Unknown test-point fields')
        if not isinstance(point.get('reference'),str) or not point['reference'] or not isinstance(point.get('passed'),bool):raise ValueError('Tests require a reference and explicit passed true/false')
        if number(point.get('rate_MTps',0))<=0 or number(point.get('voltage_V',0))<=0:raise ValueError('Tests need positive rate and voltage')
        if not isinstance(point.get('timings_cycles'),dict) or not point['timings_cycles']:raise ValueError('Tests need timings_cycles')
        for key,value in point['timings_cycles'].items():
            if key not in TIMINGS or key in ('tCKmin','tREFI') or number(value)<=0:raise ValueError('Use timing names such as tAAmin/tRCDmin, with positive cycle counts')
    requested=set(sheet.get('timings',{}))|{key for point in points for key in point['timings_cycles']}
    if data[2]!=11 and 'tCWLmin' in requested:raise ValueError('This CWL representation is DDR3-specific')
    if data[2] not in (8,11) and 'tFAWmin' in requested:raise ValueError('tFAW is not part of this legacy generation model')
    return evidence


def plan_bins(data,rates,voltage='1.5',refresh_ns='7800',evidence=None,anchor_index=None,cwl_cycles=None,datasheet_anchor=False):
    spd=SPD(data);decoded=spd.decoded_data
    evidence=validate_evidence(data,{} if evidence is None else evidence)
    rates=list(rates)
    if not 1<=len(rates)<=32:raise ValueError('Plan 1–32 target rates')
    voltage=number(voltage);refresh=number(refresh_ns)
    if voltage<=0 or refresh<=0:raise ValueError('Enter positive voltage and refresh interval')
    factor=1000 if spd.mem_type==4 else 2000
    baseline={k:number(v) for k,v in decoded.get('timings_ns',{}).items() if k in TIMINGS and v is not None and number(v)>0}
    period=baseline.get('tCKmin')
    if not period:raise ValueError('SPD lacks a usable clock/timing anchor')
    if 'tAAmin' not in baseline:
        cas=decoded.get('cas_latencies_supported',[])
        if cas:baseline['tAAmin']=number(max(cas))*period
    if 'tAAmin' not in baseline:raise ValueError('No CAS-time anchor can be derived')
    if cwl_cycles is not None:cwl_cycles=integer(cwl_cycles,1,255,'CWL cycles')
    if datasheet_anchor:
        supplied=evidence.get('datasheet',{}).get('timings',{})
        if not supplied:raise ValueError('Datasheet anchor mode needs transcribed timing constraints')
        for key,limit in supplied.items():
            if key=='tREFI':continue
            if 'min_ns' in limit:baseline[key]=number(limit['min_ns'])
            elif 'min_cycles' in limit:baseline.pop(key,None)
    anchor=None
    if anchor_index is not None:
        index=integer(anchor_index,0,len(evidence.get('tested_points',[]))-1,'Test anchor')
        anchor=evidence['tested_points'][index]
        if not anchor['passed']:raise ValueError('A failed test cannot be used as a timing anchor')
        if number(anchor['voltage_V'])!=voltage:raise ValueError('Test-anchor voltage must match the planned voltage; no voltage scaling is assumed')
        anchor_period=Fraction(factor,1)/number(anchor['rate_MTps'])
        for key,value in anchor['timings_cycles'].items():baseline[key]=number(value)*anchor_period
    sheet=evidence.get('datasheet',{});constraints=sheet.get('timings',{})
    result=[]
    for rate in rates:
        rate=number(rate)
        if not 1<=rate<=10000:raise ValueError('Target data rates must be 1–10000 MT/s')
        tck=Fraction(factor,1)/rate
        warnings=['Untested proposal: matching absolute timing minima does not establish that the chips, controller or board run at this clock.']
        violations=[]
        if rate>Fraction(factor,1)/period:warnings.append('Forward extrapolation above the SPD operating point')
        if anchor and rate!=number(anchor['rate_MTps']):warnings.append('Extrapolated from the selected user-reported test; this target speed was not established by that test')
        if 'max_rate_MTps' in sheet and rate>number(sheet['max_rate_MTps']):violations.append('Target exceeds the supplied datasheet speed limit')
        if 'tCKmin_ns' in sheet and tck<number(sheet['tCKmin_ns']):violations.append('Target period is below the supplied datasheet tCK minimum')
        for key,comparison in [('voltage_min_V',lambda v:voltage<v),('voltage_max_V',lambda v:voltage>v)]:
            if key in sheet and comparison(number(sheet[key])):violations.append('Voltage is outside the supplied datasheet envelope')
        if any(not p['passed'] and number(p['rate_MTps'])==rate and number(p['voltage_V'])==voltage for p in evidence.get('tested_points',[])):
            violations.append('A user-reported failed test exists at this rate/voltage')
        values={k:v for k,v in baseline.items() if k!='tCKmin'}
        values['tREFI']=min(refresh,number(constraints.get('tREFI',{}).get('max_ns',refresh)))
        for key,limit in constraints.items():
            if key=='tREFI':continue
            floor=max(number(limit.get('min_ns',0)),number(limit.get('min_cycles',0))*tck)
            values[key]=max(values.get(key,Fraction(0)),floor)
        cycles={k:math.ceil(v/tck) for k,v in values.items() if k!='tREFI'}
        if 'tAAmin' not in cycles:raise ValueError('No CAS-time constraint for this target')
        if spd.mem_type==7:cycles['tAAmin']=float(Fraction(math.ceil(values['tAAmin']/tck*2),2))
        if spd.mem_type==11 and 'tCWLmin' not in cycles:
            cwl=number(cwl_cycles) if cwl_cycles is not None else cwl_default(tck)
            if cwl:cycles['tCWLmin']=int(cwl)
        if cycles['tAAmin'] not in decoded.get('cas_latencies_supported',[]):warnings.append('Proposed CAS is outside the base SPD CAS bitmap; chip/controller support is unverified')
        if all(k in cycles for k in ('tRASmin','tRPmin','tRCmin')):cycles['tRCmin']=max(cycles['tRCmin'],cycles['tRASmin']+cycles['tRPmin'])
        proposal={k:float(number(v)*tck) for k,v in cycles.items()};proposal.update(tCKmin=float(tck),tREFI=float(values['tREFI']))
        profile=None;error=None
        if spd.mem_type==11:
            missing=[k for k in TIMINGS if k not in proposal]
            if missing:error='Missing values: '+', '.join(missing)
            elif not violations:
                # Account for coarse tRAS quantization before enforcing tRC >= tRAS+tRP.
                ras=quantize(proposal['tRASmin'],Fraction(1,8),0,12)[2]
                rp=quantize(proposal['tRPmin'],Fraction(1,8),Fraction(1,1000),8)[2]
                proposal['tRCmin']=float(max(number(proposal['tRCmin']),ras+rp))
                profile=dict(enabled=True,dimms_per_channel=1,voltage_V=float(voltage),cas_latencies=[cycles['tAAmin']],
                             mtb_dividend=1,mtb_divisor=8,timings_ns=dict(proposal),command_rate_raw=0)
                try:
                    encoded_tck=quantize(proposal['tCKmin'],Fraction(1,8),Fraction(1,1000),8)[2]
                    cwl=cycles['tCWLmin']
                    threshold=math.floor(cwl*encoded_tck/Fraction(1,8))*Fraction(1,8)
                    if threshold<=0 or math.ceil(threshold/encoded_tck)!=cwl:raise ValueError('CWL selector cannot represent the requested cycle count')
                    profile['timings_ns']['tCWLmin']=float(threshold)
                    probe=data[:176]+bytes(80)
                    encode_profile(probe,1,profile)
                except ValueError as exc:
                    error='XMP encoding: '+str(exc);profile=None
        result.append(dict(rate_MTps=float(rate),clock_MHz=float(rate/(1 if spd.mem_type==4 else 2)),tCK_ns=float(tck),
                           cycles=cycles,timings_ns=proposal,profile=profile,profile_error=error,
                           anchor='user-reported tested input' if anchor else 'transcribed datasheet anchor' if datasheet_anchor else 'SPD absolute-time anchor',
                           refresh_max_cycles=math.floor(values['tREFI']/tck),
                           datasheet_reference=sheet.get('reference'),violations=violations,warnings=warnings,
                           module_sha256=hashlib.sha256(data).hexdigest(),voltage_V=float(voltage)))
    return result
