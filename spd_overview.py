# SPDX-License-Identifier: MIT
"""Presentation model for the module overview; values always come from SPD."""
import math


def module_overview(spd,hp=None):
    data=spd.decoded_data
    general=data.get('general',{})
    mfg=data.get('manufacturing',{})
    timing=data.get('timings_ns',{})
    crc=data.get('crc_info',{})
    features=data.get('sdram_features',{})
    reg=data.get('registered_info',{})
    unavailable='Not specified'
    def value(v):
        return unavailable if v is None or v=='' else str(v)
    def number(v,unit=''):
        return f'{v:g} {unit}'.strip() if isinstance(v,(int,float)) and math.isfinite(v) else unavailable
    period=timing.get('tCKmin')
    rate=data.get('max_data_rate_MTps')
    clocks=data.get('timings_clocks',{})
    operating=data.get('derived',{}).get('profiles',[])
    primary='-'.join(str(clocks.get(k,'?')) for k in ('CL','tRCD','tRP','tRAS')) if clocks else operating[0].get('timings',unavailable) if operating else unavailable
    voltage=general.get('voltages_supported') or [general.get('interface_voltage')]
    size=data.get('module_size_GiB')
    capacity=number(size,'GiB') if isinstance(size,(int,float)) and size>=1 else number(data.get('module_size_MiB'),'MiB') if data.get('module_size_MiB') is not None else value(data.get('module_size_str'))
    field_data=data.get('module_specific_fields',{})
    sections={
        'Module identity':[
            ('Part number',value(mfg.get('module_part_number',mfg.get('part_number')))),
            ('Module manufacturer',value(mfg.get('module_mfg_id',mfg.get('jedec_ids_readable')))),
            ('DRAM manufacturer',value(mfg.get('dram_mfg_id'))),
            ('Serial / SPD byte order',value(mfg.get('serial_number',mfg.get('serial_number_hex')))),
            ('Manufacturing date',value(mfg.get('manufacture_date'))),
            ('SPD revision',value(general.get('spd_revision')))],
        'Organization':[
            ('Memory family',spd.mem_type_name),('Module type',value(general.get('module_type'))),
            ('Usable capacity',capacity),
            ('Ranks',number(data.get('ranks'))),('SDRAM device width',f"x{data['sdram_device_width']}" if data.get('sdram_device_width') else unavailable),
            ('Data / checking width',f"{data.get('data_width_bits','?')} + {data.get('ecc_bits','?')} bits"),
            ('Banks per device',number(data.get('banks_per_device',data.get('banks_per_chip')))),
            ('Operating voltage',', '.join(str(v) for v in voltage if v) or unavailable)],
        'Operating point':[
            ('SPD maximum data rate',number(rate,'MT/s')),
            ('Clock at tCKmin',number(1000/period if period and period>0 else None,'MHz')),
            ('Minimum clock period',number(period,'ns')),
            ('CL - tRCD - tRP - tRAS',primary),
            ('Bandwidth designation',value(data.get('jedec_standard_name'))),
            ('Module thermal sensor','Present' if features.get('thermal_sensor_present') else 'Not indicated')],
        'Register / buffer':[
            ('Component manufacturer',value(reg.get('mfg_id'))),
            ('Component revision',f"0x{reg['revision']:02X}" if isinstance(reg.get('revision'),int) else unavailable),
            ('Register devices',value(reg.get('registers',field_data.get('register_count',{}).get('meaning')))),
            ('DRAM package rows',value(reg.get('dram_rows',field_data.get('dram_rows',{}).get('meaning')))),
            ('Buffer orientation',value(reg.get('buffer_orientation'))),
            ('Component family','Legacy register/buffer' if spd.mem_type in (4,7) and reg.get('registered') else 'LRDIMM memory buffer' if general.get('module_type')=='LRDIMM' else 'RDIMM register' if reg.get('mfg_id') else 'Unbuffered'),
            ('Registered address/control',('Yes' if reg.get('attributes',{}).get('registered_addr') else 'No') if spd.mem_type in (4,7) else 'See module-specific layout')],
    }
    profiles=[]
    for item in operating:
        profiles.append((f"{item.get('data_rate_MTps','?')} MT/s",item.get('timings',''),number(item.get('tCK_ns'),'ns'),'SPD CAS point'))
    for item in data.get('jedec_downbins',[]):
        profiles.append((item.get('speed',''),item.get('timings',''),'','Derived from SPD'))
    for item in data.get('xmp_profiles',[]):
        profiles.append((f"XMP {item.get('profile','?')}: {item.get('data_rate_MTps','?')} MT/s",item.get('timings',''),
                         number(item.get('voltage_V'),'V'),'XMP profile'))
    integrity=[('Stored',f"0x{crc['stored']:04X}" if isinstance(crc.get('stored'),int) else unavailable),
               ('Computed',f"0x{crc['computed']:04X}" if isinstance(crc.get('computed'),int) else unavailable),
               ('Algorithm',value(crc.get('variant',crc.get('type')))),('Coverage',value(crc.get('coverage')))]
    warnings=list(data.get('warnings',[]))
    if crc.get('diagnostic'):warnings.append(crc['diagnostic'])
    if crc.get('status') not in ('VALID','ok'):warnings.insert(0,'SPD integrity check failed; review the raw image before use.')
    hp=hp or {}
    if hp.get('present'):
        match=', '.join(item['name'] for item in hp.get('matches',[])) or 'No learned family match'
        integrity.extend([('HP HPT',hp.get('hpt',unavailable)),('HP family',match)])
    return dict(title=value(mfg.get('module_part_number',mfg.get('part_number'))) if mfg.get('module_part_number',mfg.get('part_number')) else f'{spd.mem_type_name} module',
                capacity=capacity,family=spd.mem_type_name,module_type=value(general.get('module_type')),
                speed=number(rate,'MT/s'),integrity=crc.get('status','Unknown'),sections=sections,
                timings=[(key,number(val,'ns')) for key,val in timing.items() if isinstance(val,(int,float)) and key!='random_read_delay_clocks'],
                profiles=profiles,integrity_fields=integrity,warnings=warnings,
                note='SPD capability data. Configured host speed and memory-training results are not measured by this view.')
