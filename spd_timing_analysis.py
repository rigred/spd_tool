# SPDX-License-Identifier: MIT
"""Minimum command scheduling for explicit single-rank, no-turnaround examples.

These are separate illustrative workloads, not a DRAM controller simulator.
Unspecified constraints are reported rather than silently replaced by defaults.
"""
import math
from spd_library import SPD


def configuration(data,kind='Native',index=0):
    spd=SPD(data);decoded=spd.decoded_data;times=dict(decoded['timings_ns']);cas=decoded.get('cas_latencies_supported',[])
    if kind=='XMP':
        from spd_xmp import read_profile
        profile=read_profile(data,index+1)
        if not profile['enabled']:raise ValueError('XMP profile is disabled')
        times=profile['timings_ns'];cas=profile['cas_latencies']
    if kind=='EPP':
        from spd_epp import decode_epp
        parsed=decode_epp(data)
        if not parsed or index>=len(parsed['profiles']):raise ValueError('No such EPP profile')
        profile=parsed['profiles'][index]
        if not profile['enabled'] or profile['errors']:raise ValueError('EPP profile disabled or invalid')
        times=profile['timings_ns'];cas=[profile['cas']]
    tck=times.get('tCKmin')
    if not tck or tck<=0:raise ValueError('Configuration has no positive tCK')
    cl=min((c for c in cas if c*tck+1e-6>=times.get('tAAmin',0)),default=None) if spd.mem_type==11 else max(cas,default=None)
    parameters={k.removesuffix('min'):v for k,v in times.items() if k.endswith('min') and v and v>0 and k!='tCKmin'}
    if cl is not None:parameters['CL']=cl
    parameters['tCK']=tck
    if 'tREFI' in times:parameters['tREFI']=times['tREFI']
    return dict(generation=spd.mem_type,label=kind,parameters=parameters,bank_count=decoded.get('banks_per_chip',decoded.get('banks_per_device')))


def schedule(generation,parameters,burst_length=4,command_rate=1,bank_count=None):
    if generation not in (4,7,8,11):raise ValueError('Unsupported generation')
    if command_rate not in (1,2) or burst_length not in ((1,2,4,8) if generation==4 else (2,4,8)):raise ValueError('Unsupported command rate/burst length assumption')
    p={k:float(v) for k,v in parameters.items()};tck=p.get('tCK',0)
    if tck<=0 or any(not math.isfinite(v) or v<=0 for v in p.values()):raise ValueError('Parameters must be finite and positive')
    cycles={k:math.ceil(v/tck-1e-10) for k,v in p.items() if k not in ('CL','tCK','tREFI')}
    cl=p.get('CL');missing=[];violations=[];events=[];windows=[]
    def get(key):
        if key not in cycles:missing.append(key);return None
        return cycles[key]
    def event(lane,name,at,reason):events.append(dict(lane=lane,command=name,cycle=at,ns=at*tck,reason=reason))
    def window(lane,name,start,end,critical=False):windows.append(dict(lane=lane,name=name,start=start,end=end,critical=critical))
    rcd,rp,ras,rc=get('tRCD'),get('tRP'),get('tRAS'),get('tRC')
    if all(v is not None for v in (ras,rp,rc)) and rc<ras+rp:violations.append('tRC < tRAS + tRP after cycle quantization')
    burst=burst_length if generation==4 else burst_length/2
    # Read/precharge example: missing legacy read-to-precharge is not assumed zero.
    if cl is None:missing.append('CL')
    if rcd is not None and cl is not None:
        event('Read / same bank','ACT',0,'Closed bank assumed at start');event('Read / same bank','READ',max(rcd,command_rate),'tRCD / command rate')
        read=max(rcd,command_rate);window('Read / same bank','tRCD',0,read,True)
        event('Read / same bank','DATA',read+cl,'CAS latency');window('Read / same bank','CL + burst',read,read+cl+burst)
        rtp=get('tRTP')
        if all(v is not None for v in (rtp,ras,rp,rc)):
            pre=max(ras,read+rtp,read+cl+burst,read+command_rate);nextact=max(rc,pre+rp,pre+command_rate)
            event('Read / same bank','PRE',pre,'max(tRAS, tRTP, full burst completion) conservative explicit PRE');event('Read / same bank','ACT',nextact,'max(tRC, PRE+tRP)')
            window('Read / same bank','tRAS',0,ras);window('Read / same bank','tRP',pre,nextact,True)
    wr=get('tWR')
    if generation==7:wl=1
    elif generation==4:wl=0
    elif generation==8:wl=cl-1 if cl else None
    else:wl=cycles.get('tCWL')
    if wl is None:missing.append('tCWL (supply controller operating value)')
    if all(v is not None for v in (rcd,ras,rp,rc,wr,wl)):
        write=max(rcd,command_rate);end=write+wl+burst;pre=max(ras,end+wr,write+command_rate)
        event('Write / same bank','ACT',0,'Closed bank assumed');event('Write / same bank','WRITE',write,'tRCD');event('Write / same bank','DATA',write+wl,'Write latency assumption')
        event('Write / same bank','PRE',pre,'max(tRAS, end of data+tWR)');event('Write / same bank','ACT',max(rc,pre+rp,pre+command_rate),'tRC / tRP')
        window('Write / same bank','tWR',end,pre,True)
        wtr=get('tWTR')
        if wtr is not None:
            event('Write → read / open row','WRITE',0,'Row already open in this independent workload')
            event('Write → read / open row','DATA',wl,'Write latency assumption')
            event('Write → read / open row','READ',max(wl+burst+wtr,command_rate),'End of write data + tWTR; same open row')
            window('Write → read / open row','tWTR',wl+burst,wl+burst+wtr,True)
    rfc=get('tRFC')
    if rfc is not None:
        event('Refresh / all precharged','REF',0,'All banks precharged and tRP already elapsed');event('Refresh / all precharged','ACT',max(rfc,command_rate),'tRFC / command rate');window('Refresh / all precharged','tRFC',0,rfc,True)
    rrd=get('tRRD');faw=get('tFAW') if generation in (8,11) else None
    if rrd is not None:
        issued=[];bank_acts={};last_command=-command_rate
        for i in range(5 if faw is not None else 4):
            bank=i % bank_count if bank_count else i
            at=max((issued[-1]+rrd) if issued else 0,last_command+command_rate)
            if bank in bank_acts:
                if any(v is None for v in (ras,rp,rc)):missing.append('Bank reuse needs tRAS, tRP and tRC');break
                pre=max(bank_acts[bank]+ras,last_command+command_rate)
                event('ACT / bank sweep',f'PRE B{bank}',pre,'Close reused bank after tRAS; command bus spacing')
                at=max(at,pre+rp,pre+command_rate,bank_acts[bank]+rc)
            if i>=4 and faw is not None:at=max(at,issued[i-4]+faw)
            event('ACT / bank sweep',f'ACT B{bank}',at,'max(tRRD, tFAW rolling window, command spacing, same-bank tRC/tRP)')
            issued.append(at);bank_acts[bank]=at;last_command=at
        if faw is not None:window('ACT / bank sweep','tFAW',0,faw,True)
    if 'tREFI' in p and rfc is not None and rfc>math.floor(p['tREFI']/tck):violations.append('tRFC exceeds the supplied maximum refresh interval')
    if 'tCCD' in cycles and cl is not None:
        event('Column / open row','READ',0,'Row already active');event('Column / open row','READ',max(cycles['tCCD'],command_rate,burst),'max(tCCD, burst, command rate)')
    if 'tREFI' not in p:missing.append('tREFI / temperature refresh requirement')
    return dict(tCK_ns=tck,events=events,windows=windows,cycles=cycles,missing=sorted(set(missing)),violations=violations,
                assumptions=[f'BL={burst_length}, command rate={command_rate}T, one rank; each lane is an independent workload.',
                             'Explicit PRE waits for read burst completion (conservative). No auto-precharge, bank groups, rank switching, queueing or bus turnaround optimization.',
                             f'Bank sweep uses {bank_count} banks with explicit PRE before reuse.' if bank_count else 'Bank count unknown: ACT sweep assumes distinct banks; confirm geometry before interpreting it.',
                             'Scheduling is illustrative, not a hardware acceptance result.'])
