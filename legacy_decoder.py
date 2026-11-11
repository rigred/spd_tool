# SPDX-License-Identifier: MIT
"""JEDEC SDR and DDR1 SPD, including registered/buffered module attributes.

There are no RDIMM control-word tables in these legacy layouts. Byte 21
reports physical register/buffer/PLL wiring; it does not program a register.
"""
import json
import math
from spd_integrity import integrity_info, patch_image
from spd_fields import decoded_fields, registered_warnings

LEGACY_FIELDS = [
    (0,2,'Header'),(3,4,'Rank address geometry'),(5,5,'Module ranks'),(6,7,'Total bus width'),
    (8,8,'Interface voltage'),(9,10,'Fastest CAS cycle/access'),(11,12,'Error checking/refresh'),
    (13,14,'Primary/ECC device organization'),(15,15,'Back-to-back delay'),(16,17,'Burst lengths/banks'),
    (18,20,'CAS/CS/WE support'),(21,21,'Register/buffer/PLL attributes'),(22,22,'Device features'),
    (23,26,'Lower-CAS cycle/access'),(27,30,'tRP/tRRD/tRCD/tRAS'),(31,31,'Rank density bitmap'),
    (32,35,'Setup/hold timings'),(36,40,'Reserved'),(41,45,'DDR tRC/tRFC/tCKmax/skew'),
    (46,46,'Reserved'),(47,47,'DDR module height'),(48,61,'Reserved/vendor'),(62,62,'SPD revision'),
    (63,63,'Base checksum'),(64,71,'JEP106 continuation ID'),(72,72,'Manufacturing location'),
    (73,90,'Part number'),(91,92,'Revision'),(93,94,'Manufacturing date'),(95,98,'Serial number'),
    (99,125,'Manufacturer data'),(126,127,'Intel PC SDR extension / reserved'),(128,255,'Customer data')]


def _tenths(value, extended=False):
    whole, fraction = value >> 4, value & 15
    if fraction > 9:
        return None
    if extended and whole in (1,2,3):
        whole += 15
    return whole + fraction/10


def _hundredths(value):
    return round((value >> 4)/10 + (value & 15)/100, 3) if (value & 15) <=9 else None


def _address(value):
    return value+15 if value in (1,2,3) else value


def legacy_manufacturing(d):
    # JEP106 legacy IDs are a continuation sequence, not bank/code pairs.
    from ddr3_decoder import DDR3Decoder
    bank, code = 0, 0
    for value in d[64:72]:
        if value == 0x7F:
            bank += 1
        else:
            code = value
            break
    part = d[73:91].decode('ascii',errors='replace').rstrip('\0 ').strip()
    year,week=d[93:95]
    bcd=lambda v:(v>>4)*10+(v&15)
    valid_date=all((v&15)<10 and (v>>4)<10 for v in (year,week)) and 1<=bcd(week)<=53
    # Legacy dates are two-digit years. Do not silently move 1998 modules into 2098.
    date=f'{bcd(year):02d}-W{bcd(week):02d}' if valid_date else 'Unknown'
    name=DDR3Decoder._decode_jep106(None,bank,code)
    return dict(module_mfg_id=name,jedec_ids_readable=name,mfg_id_bank=bank,mfg_id_code=code,
                module_part_number=part,part_number=part,manufacturing_location=d[72],location_code=d[72],
                rev_lo=d[91],rev_hi=d[92],revision=d[91:93].hex().upper(),
                manufacture_date=date,manufacture_year_two_digit=bcd(year) if valid_date else None,
                serial_number=d[95:99].hex().upper(),serial_number_hex=d[95:99].hex().upper())


class LegacyDecoder:
    memory_type = None
    def __init__(self,data):
        if len(data)<128 or data[2] != self.memory_type:
            raise ValueError(f'{self.__class__.__name__} requires 128 bytes and type 0x{self.memory_type:02X}')
        self.data=bytes(data)

    def decode(self):
        d=self.data
        ddr=d[2]==7
        name='DDR' if ddr else 'SDR'
        warnings=[]
        flags=d[21]
        features={key:bool(flags & (1<<bit)) for bit,key in enumerate(
            ('buffered_addr','registered_addr','on_card_PLL','buffered_dqmb','registered_dqmb','diff_clock','redundant_address'))}
        registered=bool(flags & (2|16))
        buffered=bool(flags & (1|8))
        module_type='Registered DIMM' if registered else 'Buffered DIMM' if buffered else 'Unbuffered DIMM'
        total_width=int.from_bytes(d[6:8],'little')
        # Legacy byte 14 is an ECC *component* width, not the ECC bus width.
        # Standard x64/x72 and x128/x144 modules use 8/16 checking bits.
        checking = total_width//9 if d[11] in (1,2) and total_width%9==0 else 0
        if d[11] in (1,2) and not checking:
            warnings.append('Nonstandard parity/ECC bus width; usable width could not be separated')
        width=total_width-checking
        ranks=d[5]
        rank_geometries=[]
        for rank in range(ranks if 0<ranks<=8 else 0):
            row=_address((d[3]>>4) if rank and d[3]>>4 else d[3]&15)
            col=_address((d[4]>>4) if rank and d[4]>>4 else d[4]&15)
            rank_geometries.append(dict(rank=rank,row_bits=row,column_bits=col))
        valid_geometry=bool(rank_geometries) and d[17] in (2,4,8) and width>0 and all(
            8<=r['row_bits']<=18 and 8<=r['column_bits']<=18 for r in rank_geometries)
        addr_mib=sum((1<<(r['row_bits']+r['column_bits']))*d[17]*width/8/2**20 for r in rank_geometries) if valid_geometry else None
        # DDR reuses low bits for 1/2 GiB ranks. Late SDR modules also reused
        # those bits; select the high-density SDR interpretation when geometry
        # corroborates it, otherwise retain the older 4/8 MiB interpretation.
        density_table=[1024,2048,16,32,64,128,256,512] if ddr else [4,8,16,32,64,128,256,512]
        density_sizes=[density_table[bit] for bit in range(8) if d[31] & (1<<bit)]
        if not ddr and d[31]&3 and valid_geometry:
            large=[([1024,2048,16,32,64,128,256,512][bit]) for bit in range(8) if d[31] & (1<<bit)]
            large_size=large[0]*ranks if len(large)==1 else sum(large) if len(large)==ranks else None
            if large_size==addr_mib:
                density_sizes=large
                warnings.append('SDR low density bits use the high-density extension, corroborated by addressing')
        density_mib=None
        if ranks and len(density_sizes)==1:
            density_mib=density_sizes[0]*ranks
        elif len(density_sizes)==ranks:
            density_mib=sum(density_sizes)
        size=density_mib if density_mib is not None else addr_mib
        if not valid_geometry:warnings.append('Missing or invalid address geometry')
        if addr_mib is not None and density_mib is not None and addr_mib!=density_mib:
            warnings.append('Rank density and address geometry disagree on capacity')
        if flags & 0x80:warnings.append('Reserved module attribute bit 7 is set')
        cas=[(1+bit/2 if ddr else bit+1) for bit in range(7) if d[18]&(1<<bit)]
        timings={key:d[off]/4 if ddr and off!=30 else float(d[off]) for key,off in
                 (('tRPmin',27),('tRRDmin',28),('tRCDmin',29),('tRASmin',30))}
        profiles=[]
        for index,off in enumerate((9,23,25)):
            if ddr:
                cl=max(cas)-index*.5 if cas else None
                period=_tenths(d[off]);access=_hundredths(d[off+1])
            else:
                cl=sorted(cas,reverse=True)[index] if len(cas)>index else None
                period=d[off]/4 if index==2 else _tenths(d[off],extended=index==1)
                access=d[off+1]/4 if index==2 else _tenths(d[off+1],extended=index==1)
            if cl not in cas or not period or d[off] in (0,255):continue
            profile=dict(label=('highest','medium','short')[index],CL=cl,tCK_ns=period,tAC_ns=access,
                         freq_MHz=round(1000/period,3),data_rate_MTps=round((2000 if ddr else 1000)/period),
                         data_rate_MBps=round((2000 if ddr else 1000)/period*max(width,0)/8))
            for key in ('tRCD','tRP','tRAS','tRRD'):
                profile[key]=math.ceil(timings[key+'min']/period-1e-9)
            profile['timings']=f'{cl:g}-{profile["tRCD"]}-{profile["tRP"]}-{profile["tRAS"]}'
            profile['registered_command_latency_note']='Module register adds command/address pipeline latency; CAS remains the DRAM CAS value.' if registered else ''
            profiles.append(profile)
        timings.update(tCKmin=profiles[0]['tCK_ns'] if profiles else None,
                       tACmax=profiles[0]['tAC_ns'] if profiles else None)
        if not profiles:warnings.append('No valid CAS operating point')
        for key,off in (('tIS',32),('tIH',33),('tDS',34),('tDH',35)):
            timings[key]=_hundredths(d[off]) if ddr else (-1 if d[off]&128 else 1)*((_tenths(d[off]&127)) or 0)
        if ddr:
            timings.update(tRCmin=float(d[41]),tRFCmin=float(d[42]),
                           tCKmax=None if d[43] in (0,255) else d[43]/4,
                           tDQSQ=d[44]/100,tQHS=_hundredths(d[45]))
        else:
            timings['random_read_delay_clocks']=d[15]
        mfg=legacy_manufacturing(d)
        if mfg['manufacture_date']=='Unknown':warnings.append('Manufacturing date missing or invalid BCD')
        if d[64] in (0,255):warnings.append('Manufacturer ID missing')
        if not mfg['module_part_number']:warnings.append('Part number missing')
        warnings.extend(registered_warnings(d))
        rate=profiles[0]['data_rate_MTps'] if profiles else 0
        downbins=[]
        for speed,period in ((200,10),(266,7.5),(333,6),(400,5)) if ddr else ((66,15),(100,10),(133,7.5)):
            eligible=[p for p in profiles if p['tCK_ns']<=period]
            if not eligible:continue
            if ddr and timings['tCKmax'] and period>timings['tCKmax']:continue
            cl=min(p['CL'] for p in eligible)
            counts=[math.ceil(timings[k]/period-1e-9) for k in ('tRCDmin','tRPmin','tRASmin')]
            downbins.append(dict(speed=f'DDR-{speed}' if ddr else f'PC{speed}',
                                 timings=f'{cl:g}-'+ '-'.join(map(str,counts))))
        module_info=dict(registered=registered,buffered=buffered,pll=bool(flags&4),
                         attributes=features,raw_attributes=flags,
                         register_control_words='Not present in this generation of SPD',
                         command_latency_note='Registered address/control inputs add a command pipeline stage; no adjustment is applied to DRAM CAS.')
        return dict(general=dict(memory_type=f'{name} SDRAM',module_type=module_type,
                                 spd_revision=f'{d[62]>>4}.{d[62]&15}',bytes_present=d[0],eeprom_log2_size=d[1],
                                 interface_voltage={0:'TTL 5 V',1:'LVTTL 3.3 V',2:'HSTL 1.5 V',3:'SSTL 3.3 V',4:'SSTL 2.5 V'}.get(d[8],'Reserved')),
                    ranks=ranks,data_width_bits=width,ecc_bits=checking,total_width_bits=total_width,
                    sdram_device_width=d[13]&127,banks_per_device=d[17],rank_geometries=rank_geometries,
                    module_size_MiB=size,module_size_GiB=size/1024 if size is not None else None,
                    module_size_str=f'{size:g} MiB' if size is not None else 'Unknown',
                    addressing_module_size_MiB=addr_mib,density_bitmap_rank_sizes_MiB=density_sizes,
                    timings_ns=timings,cas_latencies_supported=cas,max_data_rate_MTps=rate,
                    derived={'profiles':profiles},jedec_downbins=downbins,manufacturing=mfg,registered_info=module_info,
                    module_specific_fields=decoded_fields(d),
                    addressing=dict(module_data_width_bits=total_width,banks_on_module=ranks,
                                    bank1_row_bits=_address(d[3]&15),bank1_col_bits=_address(d[4]&15),banks_per_device=d[17]),
                    capabilities=dict(module_features=features,cas_latencies=cas,
                                      cs_latencies=[b for b in range(7) if d[19]&(1<<b)],
                                      we_latencies=[b for b in range(7) if d[20]&(1<<b)],
                                      burst_lengths_supported=[1<<b for b in range(4) if d[16]&(1<<b)],
                                      full_page_burst=bool(d[16]&128),self_refresh=bool(d[12]&128),
                                      refresh_interval_us={0:15.625,1:3.9,2:7.8,3:31.3,4:62.5,5:125}.get(d[12]&127),
                                      primary_second_rank_double_width=bool(d[13]&128),ecc_device_width=d[14]&127,
                                      ecc_second_rank_double_width=bool(d[14]&128)),
                    intel_info={'byte126':d[126],'byte127':d[127]} if not ddr else {},
                    crc_info=integrity_info(d),warnings=warnings,
                    raw_fields={label:d[start:end+1].hex() for start,end,label in LEGACY_FIELDS if start<len(d)})

    def patch(self,source_data,args):
        return patch_image(self.data,source_data,args)

    def pretty_print(self,data,programmer_mode=False):
        print(json.dumps(data,indent=2))
        if programmer_mode:print(self.dump_field_map())

    def dump_field_map(self):
        return '\n'.join(f'{start:03d}-{min(end,len(self.data)-1):03d}  {label:<36} '+self.data[start:end+1].hex(' ').upper()
                         for start,end,label in LEGACY_FIELDS if start<len(self.data))
