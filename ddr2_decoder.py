#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""DDR2 SPD base, timing, organization and manufacturing decoder.

Reserved/vendor-specific bytes remain available in the raw field map.
"""
import json
import math
from spd_integrity import integrity_info, patch_image
from ddr3_decoder import DDR3Decoder

DDR2_FIELDS = [
    (0, 2, 'SPD header'), (3, 4, 'Row/column address bits'),
    (5, 5, 'Ranks/package/height'), (6, 7, 'Module total width'),
    (8, 8, 'Voltage'), (9, 10, 'tCK/tAC at highest CAS'),
    (11, 12, 'Configuration/refresh'), (13, 15, 'Device widths/reserved'),
    (16, 18, 'Burst/banks/CAS bitmap'), (19, 22, 'Mechanical/module attributes'),
    (23, 26, 'tCK/tAC at lower CAS'), (27, 30, 'tRP/tRRD/tRCD/tRAS'),
    (31, 31, 'Rank density bitmap'), (32, 35, 'Setup/hold times'),
    (36, 38, 'tWR/tWTR/tRTP'), (39, 40, 'Probe/extended timings'),
    (41, 46, 'tRC/tRFC/tCKmax/skew/PLL'), (47, 61, 'Thermal/reserved'),
    (62, 63, 'Revision/checksum'), (64, 71, 'JEDEC manufacturer ID'),
    (72, 72, 'Manufacturing location'), (73, 90, 'Part number'),
    (91, 92, 'Revision'), (93, 94, 'Date'), (95, 98, 'Serial'),
    (99, 127, 'Manufacturer specific'), (128, 255, 'Customer/vendor extensions'),
]


def cycle_time(value):
    fraction = value & 15
    fractions = {10: .25, 11: .33, 12: .66, 13: .75}
    if fraction > 13:
        return None
    return round((value >> 4) + (fraction / 10 if fraction < 10 else fractions[fraction]), 3)


def access_time(value):
    if value & 15 > 9:return None
    return round((value >> 4) / 10 + (value & 15) / 100, 3)


class DDR2Decoder:
    def __init__(self, data):
        if len(data) < 128 or data[2] != 0x08:
            raise ValueError('DDR2 requires a 128-byte base block and type 0x08')
        self.data = bytes(data)

    def decode(self):
        d = self.data
        warnings = []
        ranks, rows, cols = (d[5] & 7) + 1, d[3] & 15, d[4] & 15
        total_width = int.from_bytes(d[6:8], 'little')
        ecc = d[14] if d[11] & 3 else 0
        width = total_width - ecc
        banks = d[17]
        size_bytes = (1 << (rows + cols)) * banks * width * ranks // 8
        size_mib = size_bytes / 2**20
        types = [name for bit, name in enumerate(
            ('RDIMM', 'UDIMM', 'SO-DIMM', 'Micro-DIMM', 'Mini-RDIMM', 'Mini-UDIMM')) if d[20] & (1 << bit)]
        cas = [i for i in range(2, 7) if d[18] & (1 << i)]
        tck = cycle_time(d[9])
        timings = {'tCKmin': tck, 'tACmax': access_time(d[10]), 'tRASmin': float(d[30]),
                   'tCKmax': cycle_time(d[43])}
        for name, offset in [('tRPmin', 27), ('tRRDmin', 28), ('tRCDmin', 29),
                             ('tWRmin', 36), ('tWTRmin', 37), ('tRTPmin', 38)]:
            timings[name] = d[offset] / 4
        fractions = (0, .25, .33, .5, .66, .75)
        for name, off, code, high in [('tRCmin', 41, (d[40] >> 4) & 7, 0),
                                      ('tRFCmin', 42, (d[40] >> 1) & 7, d[40] & 1)]:
            timings[name] = d[off] + high * 256 + fractions[code] if code < 6 else None
            if code >= 6:
                warnings.append(f'{name}: reserved fractional encoding {code}')
        for name, off in [('tIS', 32), ('tIH', 33), ('tDS', 34), ('tDH', 35)]:
            timings[name] = access_time(d[off])
        timings.update(tDQSQ=d[44] / 100, tQHS=d[45] / 100)
        profiles = []
        if cas:
            highest = max(cas)
            for delta, off in enumerate((9, 23, 25)):
                cl, period = highest - delta, cycle_time(d[off])
                if cl in cas and period and d[off] != 255:
                    profiles.append(dict(CL=cl, tCK_ns=period, tAC_ns=access_time(d[off + 1]),
                                         data_rate_MTps=round(2000 / period),
                                         timings=f'{cl}-{math.ceil(timings["tRCDmin"] / period)}-'
                                                 f'{math.ceil(timings["tRPmin"] / period)}-{math.ceil(d[30] / period)}'))
        downbins = []
        max_period = timings['tCKmax']
        for speed, period in ((400, 5), (533, 3.75), (667, 3), (800, 2.5), (1066, 1.875)):
            eligible = [p['CL'] for p in profiles if period >= p['tCK_ns']]
            if not eligible or not tck or period < tck or (max_period and period > max_period):
                continue
            cl = min(eligible)
            values = [cl] + [math.ceil(timings[k] / period - 1e-9) for k in ('tRCDmin', 'tRPmin', 'tRASmin')]
            downbins.append(dict(speed=f'DDR2-{speed}', timings='-'.join(map(str, values))))
        rate = round(2000 / tck) if tck else 0
        if not tck:
            warnings.append('Invalid or zero minimum cycle time')
        if not cas:
            warnings.append('No supported CAS latencies')
        if width <= 0 or banks not in (4, 8) or not 12 <= rows <= 16 or not 9 <= cols <= 12:
            warnings.append('Invalid or reserved module organization')
        bank = 0
        for code in d[64:72]:
            if code == 0x7F:
                bank += 1
            else:
                break
        else:
            code = 0
        mfg = DDR3Decoder._decode_jep106(self, bank, code)
        def bcd(v):
            return (v >> 4) * 10 + (v & 15)
        date = f'20{bcd(d[93]):02d}-W{bcd(d[94]):02d}'
        if any((x & 15) > 9 or (x >> 4) > 9 for x in d[93:95]) or not 1 <= bcd(d[94]) <= 53:
            date = 'Unknown'
            warnings.append('Manufacturing date missing or invalid BCD')
        density_sizes = [128 << ((bit + 3) % 8) for bit in range(8) if d[31] & (1 << bit)]
        if len(density_sizes) == 1 and density_sizes[0] * ranks != size_mib:
            warnings.append('Rank density bitmap disagrees with addressing capacity')
        return {
            'general': dict(memory_type='DDR2 SDRAM', spd_revision=f'{d[62] >> 4}.{d[62] & 15}',
                            module_type=', '.join(types) or 'Unknown', bytes_present=d[0],
                            eeprom_log2_size=d[1], voltages_supported=['1.8V'] if d[8] == 5 else [],
                            package='Stacked' if d[5] & 16 else 'Planar',
                            module_height={0:'<25.4 mm',1:'25.4 mm',2:'25.4–30 mm',3:'30 mm',4:'30.5 mm',5:'>30.5 mm'}.get(d[5] >> 5, 'Reserved')),
            'module_size_MiB': size_mib, 'module_size_GiB': size_bytes / 2**30,
            'module_size_str': f'{size_mib:g} MiB', 'ranks': ranks,
            'data_width_bits': width, 'ecc_bits': ecc, 'sdram_device_width': d[13],
            'row_address_bits': rows, 'col_address_bits': cols, 'banks_per_device': banks,
            'timings_ns': timings, 'max_data_rate_MTps': rate,
            'jedec_standard_name': f'PC2-{int(rate * max(width, 0) / 8 / 100) * 100}',
            'cas_latencies_supported': cas, 'jedec_downbins': downbins, 'derived': {'profiles': profiles},
            'capabilities': dict(burst_lengths_supported=[n for n, bit in ((4, 2), (8, 3)) if d[16] & (1 << bit)],
                                 self_refresh=bool(d[12] & 128), refresh_code=d[12] & 127,
                                 module_attributes=d[21], device_attributes=d[22],
                                 refresh_interval_us={0:15.625,1:3.9,2:7.8,3:31.3,4:62.5,5:125}.get(d[12] & 127),
                                 configuration={0:'None',1:'Parity',2:'ECC',3:'ECC + parity'}.get(d[11] & 3),
                                 differential_clock=bool(d[21] & 32),
                                 probe_characteristics_raw=d[39], thermal_options_raw=d[47:62].hex(),
                                 rank_density_MiB=density_sizes, pll_relock_us=d[46]),
            'manufacturing': dict(module_mfg_id=mfg, jedec_ids_readable=mfg,
                                  module_part_number=d[73:91].decode('ascii', errors='replace').rstrip('\0 ').strip(),
                                  part_number=d[73:91].decode('ascii', errors='replace').rstrip('\0 ').strip(),
                                  manufacturing_location=d[72], revision=d[91:93].hex().upper(),
                                  serial_number=d[95:99].hex().upper(), manufacture_date=date),
            'crc_info': integrity_info(d), 'warnings': warnings,
            'raw_fields': {name: d[start:min(end + 1, len(d))].hex() for start, end, name in DDR2_FIELDS if start < len(d)},
        }

    def patch(self, source_data, args):
        return patch_image(self.data, source_data, args)

    def pretty_print(self, data, programmer_mode=False):
        print(json.dumps(data, indent=2))
        if programmer_mode:
            print(self.dump_field_map())

    def dump_field_map(self):
        return '\n'.join(f'{start:03d}-{min(end, len(self.data)-1):03d}  {name:<32} '
                         + self.data[start:end + 1].hex(' ').upper()
                         for start, end, name in DDR2_FIELDS if start < len(self.data))
