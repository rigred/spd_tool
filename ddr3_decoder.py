#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# ddr3_decoder.py
#
# Contains all logic specific to decoding and patching DDR3 SPD binaries.
#
from typing import Dict, Optional
import math
from ddr3_xmp_decoder import decode_xmp
from spd_integrity import integrity_info, patch_image

# --- Constants and Data Maps for DDR3 ---

# Common module/DRAM vendors. Codes below are parity-stripped by the lookup;
# unmapped vendors retain their bank/code instead of being guessed.
JEP106_MAP = {
    (0, 0x04): 'Fujitsu', (0, 0x1C): 'Mitsubishi', (0, 0x2C): 'Micron Technology',
    (0, 0x2D): 'SK hynix', (0, 0x33): 'IDT', (0, 0x4E): 'Samsung',
    (0, 0x54): 'Hewlett-Packard (HP)', (1, 0x18): 'Kingston',
    (1, 0x32): 'Mushkin Enhanced Memory', (2, 0x1E): 'Corsair',
    (4, 0x4D): 'G.Skill', (4, 0x4B): 'A-DATA Technology',
    (5, 0x1B): 'Crucial Technology',
}


DDR3_FIELDS = [
    (0, 0, "Size/CRC coverage"),
    (1, 1,   "SPD Revision"), (2, 2,   "Memory Type"), (3, 3,   "Module Type"),
    (4, 5,   "Density/Banks/Addressing"), (6, 8,   "Voltage/Organization/Width"),
    (9, 9,   "Fine Time Base"), (10,11,  "Medium Time Base"), (12,12,  "tCKmin"), (13,13, "Reserved"),
    (14,15,  "CAS Latency bitmap"), (16,16,  "tAAmin"), (17,17,  "tWRmin"),
    (18,18,  "tRCDmin"), (19,19,  "tRRDmin"), (20,20,  "tRPmin"),
    (21,21,  "Hi nibbles: tRC/tRAS"), (22,22,  "tRASmin LSB"), (23,23,  "tRCmin LSB"),
    (24,25,  "tRFCmin"), (26,26,  "tWTRmin"), (27,27,  "tRTPmin"), (28,29,  "tFAWmin"),
    (30,33,  "SDRAM Features"), (34,38,  "FTB corrections"), (41,41, "Maximum Activate Count"), (60,76,  "Module specific"),
    (117,118,"Module Mfg ID"), (119,119,"Mfg Location"), (120,121,"Mfg Date"),
    (122,125,"Module Serial"), (126,127,"Base CRC"), (128,145,"Module Part Number"),
    (146,147,"Module Revision"), (148,149,"DRAM Mfg ID"), (150,175,"Mfg-specific"),
    (176,255,"Customer-use"),
]

class DDR3Decoder:
    """Decodes the specifics of a DDR3 SPD binary."""
    def __init__(self, data: bytes):
        if len(data) < 128 or data[2] != 0x0B:
            raise ValueError("DDR3 requires a 128-byte base block and type 0x0B")
        self.available_length = len(data)
        self.raw_data = bytes(data)
        # Optional blocks are gated by available_length, never written as padding.
        self.data = bytes(data).ljust(256, b"\0")

    def decode(self) -> Dict:
        """Performs a full decode of the DDR3 SPD data."""
        decoded = {}
        decoded["general"] = self._decode_general()
        decoded.update(self._decode_organization_and_addressing())
        decoded["sdram_features"] = self._decode_sdram_features()
        decoded.update(self._decode_timings())
        decoded.update(self._calculate_jedec_downbins(decoded['timings_ns'], decoded['max_data_rate_MTps']))
        decoded["manufacturing"] = self._decode_manufacturing()
        decoded["hpt_info"] = self._decode_hpt()

        mech = self._decode_mechanical_info()
        if mech:
            decoded["mechanical_info"] = mech

        
        unbuffered_info = self._decode_unbuffered_info()
        if unbuffered_info:
            decoded["unbuffered_info"] = unbuffered_info

        reg_info = self._decode_registered_info()
        if reg_info:
            decoded["registered_info"] = reg_info

        xmp = decode_xmp(self.raw_data)
        if xmp:
            decoded.update(xmp)
            
        decoded["crc_info"] = self._detect_base_crc()
        decoded.update(self._find_gaps())
        warnings = []
        if self.available_length < 256:
            warnings.append(f'Partial image: {self.available_length} bytes; missing optional data is unavailable')
            for key, stop in [('module_part_number',146), ('module_die_revision',147),
                              ('module_pcb_revision',148), ('dram_mfg_id',150)]:
                if self.available_length < stop:
                    decoded['manufacturing'][key] = 'Unavailable' if key.endswith('id') or key.endswith('number') else 0
        if not decoded['time_bases']['valid']:
            warnings.append('Invalid time base; timing values cannot be trusted')
        if not decoded['cas_latencies_supported'] or not decoded['timings_clocks']['CL']:
            warnings.append('No supported CAS latency satisfies tAA at tCKmin')
        if decoded['timings_ns']['tCKmin'] <= 0:
            warnings.append('Invalid or zero minimum cycle time')
        if self.data[4] & 15 > 6 or self.data[7] & 7 > 3 or self.data[8] & 7 > 3 or (self.data[8] >> 3) & 3 > 1:
            warnings.append('Reserved density or width encoding')
        decoded['sdram_features']['device_type_raw'] = self.data[33]
        decoded['sdram_features']['non_monolithic_package'] = bool(self.data[33] & 128)
        decoded['sdram_features']['die_count_code'] = (self.data[33] >> 4) & 7
        decoded['sdram_features']['signal_loading_code'] = self.data[33] & 3
        decoded['sdram_features']['maximum_activate_count_raw'] = self.data[41]
        if decoded['module_size_GiB'] != decoded['addressing_module_size_GiB']:
            warnings.append('Density and address geometry disagree on capacity')
        if decoded['manufacturing']['manufacture_date'] == 'Unknown':
            warnings.append('Manufacturing date missing or invalid BCD')
        decoded['warnings'] = warnings
        decoded['raw_fields'] = {name: self.raw_data[start:end+1].hex()
                                 for start, end, name in DDR3_FIELDS if start < self.available_length}
        return decoded

    def patch(self, source_data: bytes, args) -> bytes:
        return patch_image(self.raw_data, source_data, args)

    def pretty_print(self, data: Dict, programmer_mode: bool = False):
        """Prints the decoded SPD data in a human-readable format."""
        def p(offset_info, name, value, hex_info=None):
            if programmer_mode:
                offset_str = ""
                if isinstance(offset_info, int):
                    offset_str = f"[{offset_info:03d}]"
                elif isinstance(offset_info, tuple) and len(offset_info) == 2:
                    offset_str = f"[{offset_info[0]:03d}-{offset_info[1]:03d}]"
                elif isinstance(offset_info, str): # Bitfield
                    byte_off, bits = offset_info.split(',')
                    offset_str = f"[{int(byte_off):03d}, {bits.strip()}]"
                
                hex_str = ""
                if hex_info is not None:
                    if isinstance(hex_info, int):
                        hex_str = f"(0x{hex_info:02X})"
                    elif isinstance(hex_info, (bytes, list, tuple)):
                         hex_str = f"({' '.join(f'{b:02X}' for b in hex_info)})"

                print(f"  {offset_str:<18} {name:<28} {value} {hex_str}")
            else:
                print(f"  {name:<28} {value}")

        print("--- SPD General ---")
        p(1, "SPD Revision", data["general"]["spd_revision"], self.data[1])
        p(2, "Memory Type", data["general"]["memory_type"], self.data[2])
        p(3, "Module Type", data["general"]["module_type"], self.data[3])
        p(0, "Raw Info (Byte 0)", data["general"]["byte0_info"], self.data[0])
        
        print("\n--- Module Configuration ---")
        p(4, "Module Size", data['module_size_str'])
        p("4, bits 3:0", "Individual DRAM Chip Size", data['chip_size_str'], self.data[4])
        p("7, bits 5:3", "Ranks", data['ranks'], self.data[7])
        p("7, bits 2:0", "SDRAM Device Width", f"x{data['sdram_device_width']}", self.data[7])
        p(None, "Total Chip Count", data['total_chips_str'])
        p(8, "Bus Width", f"{data['data_width_bits']}-bit (+{data['ecc_bits']} ECC)")
        p(6, "Voltage", ", ".join(data['general']['voltages_supported']), self.data[6])
        p(12, "JEDEC Standard", data['jedec_standard_name'])
        
        print("\n--- SDRAM Addressing ---")
        p("4, bits 5:3", "Bank Address Bits", data['bank_address_bits'], self.data[4])
        p("5, bits 5:3", "Row Address Bits", data['row_address_bits'], self.data[5])
        p("5, bits 2:0", "Column Address Bits", data['col_address_bits'], self.data[5])
        p(None, "Capacity from Addressing", f"{data['addressing_module_size_GiB']} GiB")

        if "sdram_features" in data:
            print("\n--- SDRAM Optional Features ---")
            feat = data["sdram_features"]
            p("30, bit 7", "DLL-Off Mode Support", "Supported" if feat['dll_off_support'] else "Not Supported", self.data[30])
            p("30, bit 1", "RZQ/7 Support", "Supported" if feat['rzq_7_support'] else "Not Supported", self.data[30])
            p("30, bit 0", "RZQ/6 Support", "Supported" if feat['rzq_6_support'] else "Not Supported", self.data[30])
            
            print("\n--- SDRAM Thermal & Refresh Features ---")
            p("31, bit 7", "PASR Support", "Supported" if feat['pasr_support'] else "Not Supported", self.data[31])
            p("31, bit 3", "ODTS Readout Support", "Supported" if feat['odts_readout_support'] else "Not Supported", self.data[31])
            p("31, bit 2", "ASR Support", "Supported" if feat['asr_support'] else "Not Supported", self.data[31])
            p("31, bit 1", "Extended Temp Refresh", "1X Rate" if feat['ext_temp_refresh_1x'] else "2X Rate", self.data[31])
            p("31, bit 0", "Extended Temp Range", "Supported" if feat['ext_temp_range_support'] else "Not Supported", self.data[31])
            p("32, bit 7", "Module Thermal Sensor", "Present" if feat['thermal_sensor_present'] else "Absent", self.data[32])

        if "mechanical_info" in data:
            print("\n--- Module Mechanical Details ---")
            m = data["mechanical_info"]
            p("60, bits 4:0", "Nominal Height", m['nominal_height'], self.data[60])
            p("61, bits 3:0", "Max Thickness (Front)", m['max_thickness_front'], self.data[61])
            p("61, bits 7:4", "Max Thickness (Back)", m['max_thickness_back'], self.data[61])
            p(62, "Reference Raw Card", f"{m['ref_raw_card']} Rev {m['ref_raw_card_rev']}", self.data[62])


        if "unbuffered_info" in data:
            print("\n--- Unbuffered Module Details ---")
            ub = data["unbuffered_info"]
            p("63, bit 0", "Rank 1 Mapping", "Mirrored" if ub['rank_1_mapping_mirrored'] else "Standard", self.data[63])

        if "registered_info" in data:
            print("\n--- Registered/Buffered Info ---")
            reg = data["registered_info"]
            mfg_label = "Memory Buffer Manufacturer" if data["general"]["module_type"] == "LRDIMM" else "Register Manufacturer"
            p((reg['mfg_id_offset']), mfg_label, reg['mfg_id'], self.data[reg['mfg_id_offset']:reg['mfg_id_offset']+2])
            p(reg.get('revision_offset', reg['mfg_id_offset']+2), "Register Revision", f"0x{reg['revision']:02X}", reg['revision'])
            if 'dram_rows' in reg:
                p("63, bits 3:2", "DRAM Rows", reg['dram_rows'], self.data[63])
                p("63, bits 1:0", "Registers", reg['registers'], self.data[63])
                p("64, bit 7", "Heat Spreader", "Present" if reg['heat_spreader'] else "Absent", self.data[64])
            if 'thermal_sensor' in reg:
                p(73, "Thermal Sensor", "Present" if reg['thermal_sensor'] else "Absent", self.data[73])
            if 'control_words' in reg:
                print("  Register Control Words:")
                for i, val in enumerate(reg['control_words']):
                    p(69 + i, f"  RC{i*2}/RC{i*2+1}", f"0x{val:02X}", val)
            if 'personality_bytes' in reg:
                print("  LRDIMM Personality Bytes:")
                for i, byte in enumerate(reg['personality_bytes']):
                    p(102 + i, f"  Byte {i}", f"0x{byte:02X}", byte)

        print("\n--- JEDEC Timing Parameters (ns) ---")
        t_ns = data['timings_ns']
        rate = data['max_data_rate_MTps']
        p(12, "tCKmin", f"{t_ns['tCKmin']:<7} ns (DDR3-{rate})", self.data[12])
        p(16, "tAAmin", f"{t_ns['tAAmin']:<7} ns", self.data[16])
        p(18, "tRCDmin", f"{t_ns['tRCDmin']:<7} ns", self.data[18])
        p(20, "tRPmin", f"{t_ns['tRPmin']:<7} ns", self.data[20])
        p((21, 22), "tRASmin", f"{t_ns['tRASmin']:<7} ns", self.data[21:23])
        p((23, 21), "tRCmin", f"{t_ns['tRCmin']:<7} ns", self.data[23])
        p((24, 25), "tRFCmin", f"{t_ns['tRFCmin']:<7} ns", self.data[24:26])
        
        for key, offset in [('tWRmin', 17), ('tRRDmin', 19), ('tWTRmin', 26), ('tRTPmin', 27), ('tFAWmin', (28,29))]:
            p(offset, key, f"{t_ns[key]} ns")

        print("\n--- Timings in Clocks (at tCKmin) ---")
        t_clk = data['timings_clocks']
        cl_str = f"{t_clk['CL']}-{t_clk['tRCD']}-{t_clk['tRP']}-{t_clk['tRAS']}"
        p(16, "Derived (CL-tRCD-tRP-tRAS)", cl_str)
        
        supported_cls = data['cas_latencies_supported']
        cas_text = ', '.join(map(str, supported_cls))
        if programmer_mode:
            binary_str = f"[0b{self.data[15]:08b}_{self.data[14]:08b}]"
            cas_text = f"{cas_text} {binary_str}"
        p((14,15), "CAS Latencies Supported", cas_text, self.data[14:16])

        if supported_cls and t_clk['CL'] not in supported_cls:
             print("  [!] Warning: Derived CL is not in the list of supported CAS latencies.")
        
        if "jedec_downbins" in data and data["jedec_downbins"]:
            print("\n--- Standard JEDEC Down-clock Profiles ---")
            for profile in data["jedec_downbins"]:
                p(None, profile['speed'], profile['timings'])

        if "xmp_profiles" in data:
            print("\n--- XMP Profiles ---")
            for profile in data["xmp_profiles"]:
                print(f"  Profile {profile['profile']}: DDR3-{profile['data_rate_MTps']} {profile['timings']}-{profile['command_rate_T']}T at {profile['voltage_V']}V")

        print("\n--- Manufacturing Information ---")
        mfg = data["manufacturing"]
        p((128,145), "Module Part Number", f"'{mfg['module_part_number']}'")
        p(146, "Module Die Revision", f"0x{mfg['module_die_revision']:02X}", mfg['module_die_revision'])
        p(147, "Module PCB Revision", f"0x{mfg['module_pcb_revision']:02X}", mfg['module_pcb_revision'])
        p(119, "Manufacturing Location", f"0x{mfg['manufacturing_location']:02X}", mfg['manufacturing_location'])
        p((117,118), "Module Mfg ID", mfg['module_mfg_id'], self.data[117:119])
        p((148,149), "DRAM Mfg ID", mfg['dram_mfg_id'], self.data[148:150])
        p((122,125), "Serial Number", mfg['serial_number'], self.data[122:126])
        p((120,121), "Manufacture Date", mfg['manufacture_date'], self.data[120:122])
        
        print("\n--- HP SmartMemory Information ---")
        hpt = data['hpt_info']
        p(176, "HPT Block", 'Present' if hpt['present'] else '<absent>', self.data[176:180])
        if hpt['present']:
            p(180, "HPT Code", hpt['code'], self.data[180:184])

        print("\n--- SPD CRC Verification ---")
        crc = data['crc_info']
        p((126,127), "Coverage", crc['coverage'])
        p((126,127), "Stored", f"0x{crc['stored']:04X}", self.data[126:128])
        p((126,127), "Computed", f"0x{crc['computed']:04X} ({crc['variant']})")
        p((126,127), "Status", crc['status'])
        if not crc['coverage_match']:
             print("  [!] Note: CRC matches non-declared coverage and is not JEDEC-valid.")

        for warning in data.get('warnings', []):
            print(f"  [!] {warning}")

        if programmer_mode and "undecoded_gaps" in data and data["undecoded_gaps"]:
            print("\n--- Undecoded/Reserved Gaps ---")
            for start, end in data["undecoded_gaps"]:
                hex_dump = ' '.join(f'{b:02X}' for b in self.data[start:end+1])
                print(f"  [{start:03d}-{end:03d}]              {hex_dump}")

    def dump_field_map(self) -> str:
        """Returns a raw, formatted string of all SPD fields for diffing."""
        lines = []
        for start, end, name in DDR3_FIELDS:
            if start >= self.available_length:
                continue
            end = min(end, self.available_length - 1)
            seg = self.raw_data[start:end+1]
            if start == 128 and end == 145:
                txt = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in seg).rstrip()
                lines.append(f"{start:03d}-{end:03d}  {name:<25} '{txt}'")
            else:
                hexs = ' '.join(f"{c:02X}" for c in seg)
                lines.append(f"{start:03d}-{end:03d}  {name:<25} {hexs}")
        return "\n".join(lines)

    # --- Private decoding methods for DDR3 ---
    def _decode_general(self) -> Dict:
        voltages = []
        if (self.data[6] & 0b001) == 0: voltages.append("1.5V")
        if (self.data[6] & 0b010) != 0: voltages.append("1.35V")
        if (self.data[6] & 0b100) != 0: voltages.append("1.25V")
        
        return { 
            "spd_revision": f"{self.data[1] >> 4}.{self.data[1] & 0x0F}", 
            "memory_type": "DDR3 SDRAM", 
            "module_type": self._ddr3_module_type_name(self.data[3]), 
            "byte0_info": self._decode_byte0_info(self.data[0]),
            "voltages_supported": voltages
        }
    def _decode_organization_and_addressing(self) -> Dict:
        b4, b5, b7, b8 = self.data[4], self.data[5], self.data[7], self.data[8]

        # SDRAM device density (per-chip) from Byte 4 low nibble (0=x256Mb, ...)
        bits_per_chip = 1 << (28 + (b4 & 0x0F))  # 256Mb << n
        chip_size_Mb = bits_per_chip / (1024**2)
        chip_size_str = f"{int(chip_size_Mb)}Mb" if chip_size_Mb < 1024 else f"{int(chip_size_Mb / 1024)}Gb"

        # Module organization (Bytes 7-8) — same for UDIMM/RDIMM/LRDIMM
        ranks = ((b7 >> 3) & 0x7) + 1                 # 0=1 rank, ...
        sdram_device_width = 4 * (2 ** (b7 & 0x7))    # 0->x4,1->x8,2->x16,3->x32

        # Primary bus width (bits 2:0) and ECC width (bits 5:3)
        data_width_bits = 1 << ((b8 & 0x7) + 3)       # 0->8,1->16,2->32,3->64
        ecc_code = (b8 >> 3) & 0x3                    # 0=none,1=8-bit,2=16-bit
        ecc_bits = 8 if ecc_code == 0b01 else (16 if ecc_code == 0b10 else 0)

        # Chip counts per rank
        data_chips_per_rank = data_width_bits // sdram_device_width if sdram_device_width else 0
        ecc_chips_per_rank  = ecc_bits       // sdram_device_width if sdram_device_width else 0
        total_data_chips = ranks * data_chips_per_rank
        total_ecc_chips  = ranks * ecc_chips_per_rank
        total_chips      = total_data_chips + total_ecc_chips

        # Capacity math
        bank_bits = 3 + ((b4 >> 4) & 7)
        banks_per_chip = 1 << bank_bits
        data_bytes = (bits_per_chip * total_data_chips) // 8
        ecc_bytes  = (bits_per_chip * total_ecc_chips)  // 8
        data_gib = round(data_bytes / (1024**3), 2)
        ecc_gib  = round(ecc_bytes  / (1024**3), 2)

        module_size_str = f"{data_gib} GiB"
        if ecc_gib > 0:
            module_size_str += f" + {ecc_gib} GiB ECC"

        total_chips_str = str(total_data_chips)
        if total_ecc_chips > 0:
            total_chips_str += f" + {total_ecc_chips} ECC"

        # Address-derived size (row/col from Byte 5). Uses number of banks, not bit-count
        row_address_bits = 12 + ((b5 >> 3) & 0x7)
        col_address_bits = 9  + (b5 & 0x7)
        addr_chip_bits   = (2 ** row_address_bits) * (2 ** col_address_bits) * banks_per_chip * sdram_device_width
        addr_module_bytes = (addr_chip_bits * total_data_chips) // 8

        return {
            "module_size_GiB": data_gib,
            "module_size_str": module_size_str,
            "chip_size_str": chip_size_str,
            "ranks": ranks,
            "sdram_device_width": sdram_device_width,
            "total_chips": total_chips,
            "total_chips_str": total_chips_str,
            "data_width_bits": data_width_bits,
            "ecc_bits": ecc_bits,
            "bank_address_bits": bank_bits,
            "banks_per_device": banks_per_chip,
            "row_address_bits": row_address_bits,
            "col_address_bits": col_address_bits,
            "addressing_module_size_GiB": round(addr_module_bytes / (1024**3), 2)
        }

    def _decode_sdram_features(self) -> Dict:
        b30 = self.data[30]
        b31 = self.data[31]
        b32 = self.data[32]
        return {
            "dll_off_support": (b30 & 0x80) != 0,
            "rzq_7_support": (b30 & 0x02) != 0,
            "rzq_6_support": (b30 & 0x01) != 0,
            "pasr_support": (b31 & 0x80) != 0,
            "odts_readout_support": (b31 & 0x08) != 0,
            "asr_support": (b31 & 0x04) != 0,
            "ext_temp_refresh_1x": (b31 & 0x02) != 0,
            "ext_temp_range_support": (b31 & 0x01) != 0,
            "thermal_sensor_present": (b32 & 0x80) != 0,
        }
    def _decode_timings(self) -> Dict:
        d = self.data
        valid_mtb = bool(d[10] and d[11])
        valid_ftb = bool(d[9] >> 4 and d[9] & 15)
        mtb = d[10] / d[11] if valid_mtb else 0
        ftb = (d[9] >> 4) / (d[9] & 15) / 1000 if valid_ftb else 0
        t = {}
        for name, coarse, fine in [('tCKmin', 12, 34), ('tAAmin', 16, 35),
                                    ('tRCDmin', 18, 36), ('tRPmin', 20, 37)]:
            t[name] = d[coarse] * mtb + self._s8(d[fine]) * ftb if valid_mtb else 0
        for name, offset in [('tWRmin', 17), ('tRRDmin', 19), ('tWTRmin', 26), ('tRTPmin', 27)]:
            t[name] = d[offset] * mtb
        t['tRASmin'] = ((d[21] & 15) * 256 + d[22]) * mtb
        t['tRCmin'] = ((d[21] >> 4) * 256 + d[23]) * mtb + self._s8(d[38]) * ftb
        t['tRFCmin'] = int.from_bytes(d[24:26], 'little') * mtb
        t['tFAWmin'] = ((d[28] & 15) * 256 + d[29]) * mtb
        t = {k: round(v, 6) for k, v in t.items()}
        cas = [cl for cl in range(4, 19) if int.from_bytes(d[14:16], 'little') & (1 << (cl-4))]
        period = t['tCKmin']
        clocks = {name.removesuffix('min'): math.ceil(value / period - 1e-9) if period > 0 else 0
                  for name, value in t.items() if name != 'tCKmin'}
        required = clocks.pop('tAA')
        clocks['CL'] = next((cl for cl in cas if cl >= required), 0)
        return dict(timings_ns=t, timings_clocks=clocks, cas_latencies_supported=cas,
                    time_bases=dict(mtb_ns=mtb, ftb_ns=ftb, valid=valid_mtb and valid_ftb),
                    max_data_rate_MTps=round(2000 / period) if period > 0 else 0)

    def _calculate_jedec_downbins(self, timings_ns: Dict, max_rate: int) -> Dict:
        cas = [cl for cl in range(4, 19) if int.from_bytes(self.data[14:16], 'little') & (1 << (cl-4))]
        downbins = []
        for speed, period in [(800, 2.5), (1066, 1.875), (1333, 1.5), (1600, 1.25),
                              (1866, 15/14), (2133, 15/16)]:
            if period + .001 < timings_ns['tCKmin'] or not max_rate:
                continue
            required = math.ceil(timings_ns['tAAmin'] / period - 1e-9)
            cl = next((cl for cl in cas if cl >= required and cl * period <= 20), None)
            if cl is None:
                continue
            values = [cl] + [math.ceil(timings_ns[k] / period - 1e-9)
                             for k in ('tRCDmin', 'tRPmin', 'tRASmin')]
            downbins.append(dict(speed=f'DDR3-{speed}', timings='-'.join(map(str, values))))
        suffix = 'L' if self.data[6] & 2 else ''
        width = 8 << (self.data[8] & 7)
        return dict(jedec_downbins=downbins,
                    jedec_standard_name=f'PC3{suffix}-{int(max_rate * width / 8 / 100) * 100}')

    def _decode_mechanical_info(self) -> Optional[Dict]:
        """Decode physical/mechanical fields present on both UDIMM and RDIMM:
        Byte60: Nominal height (5b) + Raw Card Extension (3b)
        Byte61: Max thickness back/front (4b/4b)
        Byte62: Reference raw card + Rev (and bank select for letter table)
        Byte63 bit0: rank-1 address mapping mirror (UDIMM; still meaningful on RDIMM)
        """
        module_type = self.data[3] & 15
        # Apply to UDIMM/SO-DIMM/Micro-DIMM and also LR/RDIMM family (0x01, 0x05, 0x09)
        if module_type not in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D]:
            return None

        b60, b61, b62 = self.data[60], self.data[61], self.data[62]

        height_code = b60 & 0x1F
        height_str = (f"{14 + height_code} < height <= {15 + height_code} mm" if height_code > 0
                    else "height <= 15 mm")

        back_thick  = (b61 >> 4) & 0xF
        front_thick = b61 & 0xF

        raw_card_ext = (b60 >> 5) & 0x7
        raw_card_rev = (b62 >> 5) & 0x3
        if raw_card_ext > 0:
            raw_card_rev = raw_card_ext

        card_map_a = { 0:'A', 1:'B', 2:'C', 3:'D', 4:'E', 5:'F', 6:'G', 7:'H', 8:'J', 9:'K', 10:'L', 11:'M', 12:'N', 13:'P', 14:'R', 15:'T', 16:'U', 17:'V', 18:'W', 19:'Y', 20:'AA', 21:'AB', 22:'AC', 23:'AD', 24:'AE', 25:'AF', 26:'AG', 27:'AH', 28:'AJ', 29:'AK', 30:'AL', 31:'ZZ' }
        card_map_b = { 0:'AM', 1:'AN', 2:'AP', 3:'AR', 4:'AT', 5:'AU', 6:'AV', 7:'AW', 8:'AY', 9:'BA', 10:'BB', 11:'BC', 12:'BD', 13:'BE', 14:'BF', 15:'BG', 16:'BH', 17:'BJ', 18:'BK', 19:'BL', 20:'BM', 21:'BN', 22:'BP', 23:'BR', 24:'BT', 25:'BU', 26:'BV', 27:'BW', 28:'BY', 29:'CA', 30:'CB', 31:'ZZ' }

        card_letter = card_map_b.get(b62 & 0x1F) if (b62 & 0x80) else card_map_a.get(b62 & 0x1F)

        return {
            "nominal_height": height_str,
            "max_thickness_front": (f"{front_thick} < thickness <= {front_thick+1} mm" if front_thick > 0 else "thickness <= 1 mm"),
            "max_thickness_back":  (f"{back_thick} < thickness <= {back_thick+1} mm"   if back_thick  > 0 else "thickness <= 1 mm"),
            "ref_raw_card": card_letter,
            "ref_raw_card_rev": raw_card_rev,
            "rank_1_mapping_mirrored": (self.data[63] & 0x01) != 0
        }
        
    def _decode_manufacturing(self) -> Dict:
        year_bcd = self.data[120]
        week_bcd = self.data[121]
        year = self._bcd_to_int(year_bcd)
        week = self._bcd_to_int(week_bcd)
        return {
            "module_part_number": ''.join(chr(c) for c in self.data[128:146] if 32 <= c <= 126).strip(),
            "module_die_revision": self.data[146],
            "module_pcb_revision": self.data[147],
            "manufacturing_location": self.data[119],
            "module_mfg_id": self._decode_jep106(self.data[117], self.data[118]),
            "dram_mfg_id": self._decode_jep106(self.data[148], self.data[149]),
            "serial_number": self.data[122:126].hex().upper(),
            "manufacture_date": (f"20{year:02d}-W{week:02d}" if 1 <= week <= 53 and
                                 all((b & 15) < 10 and (b >> 4) < 10 for b in (year_bcd, week_bcd)) else "Unknown"),
        }
    def _decode_hpt(self) -> Dict: present = self.data[176:180] == b'HPT\x00'; return { "present": present, "code": self.data[180:184].hex(' ').upper() if present else None }
    def _decode_registered_info(self) -> Optional[Dict]:
        module_type = self.data[3] & 15
        if module_type in [0x01, 0x05, 0x09]: # RDIMM types
            b63 = self.data[63]
            dram_rows_map = {1: "1 row", 2: "2 rows", 3: "4 rows"}
            registers_map = {1: "1 register", 2: "2 registers", 3: "4 registers"}
            return {
                "mfg_id_offset": 65,
                "mfg_id": self._decode_jep106(self.data[65], self.data[66]),
                "revision": self.data[67],
                "dram_rows": dram_rows_map.get((b63 >> 2) & 0x3, "Undefined"),
                "registers": registers_map.get(b63 & 0x3, "Undefined"),
                "heat_spreader": (self.data[64] & 0x80) != 0,
                "control_words": list(self.data[69:77])
            }
        elif module_type == 0x0B: # LRDIMM
            return {
                "mfg_id_offset": 65,
                "mfg_id": self._decode_jep106(self.data[65], self.data[66]),
                "revision": self.data[64],
                "revision_offset": 64,
                "buffer_orientation": "Horizontal" if self.data[63] & 16 else "Vertical",
                "rank_numbering": "Even only" if self.data[63] & 32 else "Contiguous",
                "personality_bytes": list(self.data[102:117]),
                "buffer_parameters_raw": self.data[67:102].hex()
            }
        return None
    def _decode_unbuffered_info(self) -> Optional[Dict]:
        module_type = self.data[3] & 15
        if module_type not in [0x02, 0x03, 0x04, 0x06, 0x08, 0x0C, 0x0D]:
            return None
        
        return self._decode_mechanical_info()

    def _find_gaps(self) -> Dict:
        used_bytes = set()
        used_bytes.update(range(0, 33 + 1))
        used_bytes.add(41)
        used_bytes.update(range(34, 38 + 1))
        used_bytes.update(range(117, 125 + 1))
        used_bytes.update(range(128, 149 + 1))
        used_bytes.update(range(126, 127 + 1))
        
        module_type = self.data[3] & 15
        if module_type in [0x02, 0x03, 0x04, 0x06, 0x08, 0x0C, 0x0D]: used_bytes.update(range(60, 63 + 1))
        elif module_type in [0x01, 0x05, 0x09]: used_bytes.update(range(60, 77 + 1))
        elif module_type == 0x0B: used_bytes.update(range(60, 117))
            
        if decode_xmp(self.raw_data) or self._decode_hpt()['present']:
            used_bytes.update(range(176, 255 + 1))
            
        gap_bytes = sorted(list(set(range(self.available_length)) - used_bytes))
        if not gap_bytes: return {"undecoded_gaps": []}
            
        ranges = []
        start = end = gap_bytes[0]
        for i in range(1, len(gap_bytes)):
            if gap_bytes[i] == end + 1: end = gap_bytes[i]
            else: ranges.append((start, end)); start = end = gap_bytes[i]
        ranges.append((start, end))
        
        return {"undecoded_gaps": ranges}
    def _detect_base_crc(self, data=None) -> Dict:
        return integrity_info(self.raw_data if data is None else data)
    def _s8(self, x: int) -> int: return x - 256 if x > 127 else x
    def _bcd_to_int(self, bcd_byte: int) -> int:
        """Converts a Binary Coded Decimal byte to an integer."""
        return ((bcd_byte >> 4) * 10) + (bcd_byte & 0x0F)
    def _ddr3_module_type_name(self, v: int) -> str:
        return {0: 'Undefined', 1: 'RDIMM', 2: 'UDIMM', 3: 'SO-DIMM', 4: 'Micro-DIMM',
                5: 'Mini-RDIMM', 6: 'Mini-UDIMM', 7: 'Mini-CDIMM', 8: '72b-SO-UDIMM',
                9: '72b-SO-RDIMM', 10: '72b-SO-CDIMM', 11: 'LRDIMM',
                12: '16b-SO-DIMM', 13: '32b-SO-DIMM'}.get(v & 15, f'Reserved (0x{v:02X})')
    def _decode_byte0_info(self, b0: int) -> str:
        crc = "0..125" if (b0 & 0x80) == 0 else "0..116"
        size = "256 bytes" if ((b0 >> 4) & 0x7) == 1 else "reserved"
        used = {1: '128', 2: '176', 3: '256'}.get(b0 & 0xF, 'reserved')
        return f"CRC Coverage: {crc}; Total Size: {size}; Bytes Used: {used}"
    def _decode_jep106(self, lsb: int, msb: int) -> str:
        bank, code = lsb & 0x7F, msb
        name = next((name for (b, c), name in JEP106_MAP.items()
                     if b == bank and c & 0x7F == code & 0x7F), None); return f"{name} (Bank {bank}, Code 0x{code:02X})" if name else f"Unknown (Bank {bank}, Code 0x{code:02X})"
