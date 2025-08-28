#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# ddr3_decoder.py
#
# Contains all logic specific to decoding and patching DDR3 SPD binaries.
#
from typing import Dict, List, Optional, Tuple
import sys
import math

# --- Constants and Data Maps for DDR3 ---

JEP106_MAP = {
    # Bank 0
    (0, 0x1C): "Mitsubishi",
    (0, 0x2C): "Micron Technology",
    (0, 0x2D): "SK Hynix (Hyundai)",
    (0, 0x33): "IDT (Integrated Device Technology)",
    (0, 0x4E): "Samsung",
    (0, 0x54): "Hewlett-Packard (HP)",
    (0, 0x98): "Kingston",
    (0, 0xAD): "SK hynix",
    (0, 0xCE): "Samsung",
    (0, 0xFE): "ELPIDA",
    (0, 0x04): "HP Inc.",
    # Bank 1
    (1, 0x0D): "Patriot Scientific",
    (1, 0x98): "Kingston",
    (1, 0x2C): "Micron Technology",
    (1, 0x32): "Mushkin Enhanced Memory",
    (1, 0x9E): "Corsair",
    # Bank 2
    (2, 0x1E): "Corsair",
    (2, 0x4D): "G.Skill Intl",
    (2, 0x7E): "Elpida (now Micron)",
    (2, 0x9B): "G.Skill",
    (2, 0x9E): "Corsair",
    # Bank 3
    (3, 0x02): "Patriot Memory",
    (3, 0x1B): "Crucial Technology",
    (3, 0x4B): "A-DATA Technology",
    (3, 0x51): "Qimonda",
    (3, 0x6F): "Team Group Inc.",
    # Bank 4
    (4, 0x33): "IDT (Integrated Device Technology)",
    (4, 0x51): "Qimonda",
    # Bank 5
    (5, 0x9B): "G.Skill",
    # Bank 16
    (16, 0x33): "IDT (Integrated Device Technology)",
}


CRC16_VARIANTS = {
    "XMODEM": (0x1021, 0x0000, False, False, 0x0000),
    "JEDEC_DDR3_STANDARD": (0x8005, 0x0000, True,  True,  0x0000),
    "MODBUS":   (0x8005, 0xFFFF, True,  True,  0x0000),
    "X25":      (0x1021, 0xFFFF, True,  True,  0xFFFF),
    "KERMIT":   (0x1021, 0x0000, True,  True,  0x0000),
}

DDR3_FIELDS = [
    (1, 1,   "SPD Revision"), (2, 2,   "Memory Type"), (3, 3,   "Module Type"),
    (4, 5,   "Density/Banks/Addressing"), (6, 8,   "Voltage/Organization/Width"),
    (9, 9,   "Fine Time Base"), (10,11,  "Medium Time Base"), (12,12,  "tCKmin"),
    (14,15,  "CAS Latency bitmap"), (16,16,  "tAAmin"), (17,17,  "tWRmin"),
    (18,18,  "tRCDmin"), (19,19,  "tRRDmin"), (20,20,  "tRPmin"),
    (21,21,  "Hi nibbles: tRC/tRAS"), (22,22,  "tRASmin LSB"), (23,23,  "tRCmin LSB"),
    (24,25,  "tRFCmin"), (26,26,  "tWTRmin"), (27,27,  "tRTPmin"), (28,29,  "tFAWmin"),
    (30,32,  "SDRAM Features"), (34,38,  "FTB corrections"), (60,76,  "Module specific"),
    (117,118,"Module Mfg ID"), (119,119,"Mfg Location"), (120,121,"Mfg Date"),
    (122,125,"Module Serial"), (126,127,"Base CRC"), (128,145,"Module Part Number"),
    (146,147,"Module Revision"), (148,149,"DRAM Mfg ID"), (150,175,"Mfg-specific"),
    (176,255,"Customer-use"),
]

class DDR3Decoder:
    """Decodes the specifics of a DDR3 SPD binary."""
    def __init__(self, data: bytes):
        self.data = data

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
        
        unbuffered_info = self._decode_unbuffered_info()
        if unbuffered_info:
            decoded["unbuffered_info"] = unbuffered_info

        reg_info = self._decode_registered_info()
        if reg_info:
            decoded["registered_info"] = reg_info

        xmp = self._decode_xmp()
        if xmp:
            decoded.update(xmp)
        decoded["crc_info"] = self._detect_base_crc()
        decoded.update(self._find_gaps())
        return decoded

    def patch(self, source_data: bytes, args) -> bytes:
        """Applies patches to a bytearray of target data."""
        target = bytearray(self.data)
        
        if source_data[3] != target[3]:
            print(f"[WARN] Module types differ: {self._ddr3_module_type_name(source_data[3])} vs {self._ddr3_module_type_name(target[3])}")
        if (args.copy_hpt or args.set_hpt) and not self._decode_jep106(target[117], target[118]).startswith("HP") and not args.force:
            raise SystemExit("[ERROR] Target is not an HP module. Use --force to apply HPT block.")

        changed = False
        if args.copy_vendor: target[176:256] = source_data[176:256]; changed = True
        if args.copy_hpt: target[176:184] = source_data[176:184]; changed = True
        if args.set_hpt: self._set_hpt_code(target, args.set_hpt); changed = True
        if args.copy_mfgid: target[117:119] = source_data[117:119]; changed = True
        if args.copy_partnum: target[128:146] = source_data[128:146]; changed = True
        for r in args.copy_range or []:
            try:
                s, e = r.split(":"); start = int(s, 0); end = int(e, 0)
            except Exception:
                raise SystemExit(f"Invalid range format: {r}")
            if not (0 <= start <= end < 256): raise SystemExit(f"Invalid range: {r}")
            target[start:end+1] = source_data[start:end+1]; changed = True

        if not changed:
            print("Nothing selected to patch.")
            sys.exit(1)

        if self._needs_base_crc_update(self.data, target):
            self._rewrite_base_crc(target)
        
        if not self._detect_base_crc(target)["status"].startswith("VALID"):
            raise SystemExit("[ERROR] Post-patch CRC validation failed. Aborting write.")
            
        return bytes(target)

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

        if "unbuffered_info" in data:
            print("\n--- Unbuffered Module Details ---")
            ub = data["unbuffered_info"]
            p("60, bits 4:0", "Nominal Height", ub['nominal_height'], self.data[60])
            p("61, bits 3:0", "Max Thickness (Front)", ub['max_thickness_front'], self.data[61])
            p("61, bits 7:4", "Max Thickness (Back)", ub['max_thickness_back'], self.data[61])
            p(62, "Reference Raw Card", f"{ub['ref_raw_card']} Rev {ub['ref_raw_card_rev']}", self.data[62])
            p("63, bit 0", "Rank 1 Mapping", "Mirrored" if ub['rank_1_mapping_mirrored'] else "Standard", self.data[63])

        if "registered_info" in data:
            print("\n--- Registered/Buffered Info ---")
            reg = data["registered_info"]
            mfg_label = "Memory Buffer Manufacturer" if data["general"]["module_type"] == "LRDIMM" else "Register Manufacturer"
            p((reg['mfg_id_offset']), mfg_label, reg['mfg_id'], self.data[reg['mfg_id_offset']:reg['mfg_id_offset']+2])
            p(reg['mfg_id_offset']+2, "Register Revision", f"0x{reg['revision']:02X}", reg['revision'])
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
                    p(102 + i, f"  Byte {i+1}", f"0x{byte:02X}", byte)

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
             print("  [!] Note: Matched using a non-declared CRC coverage area.")

        if programmer_mode and "undecoded_gaps" in data and data["undecoded_gaps"]:
            print("\n--- Undecoded/Reserved Gaps ---")
            for start, end in data["undecoded_gaps"]:
                hex_dump = ' '.join(f'{b:02X}' for b in self.data[start:end+1])
                print(f"  [{start:03d}-{end:03d}]              {hex_dump}")

    def dump_field_map(self) -> str:
        """Returns a raw, formatted string of all SPD fields for diffing."""
        lines = []
        lines.append(f"000-000  Byte0 Info: {self._decode_byte0_info(self.data[0])}")
        for start, end, name in DDR3_FIELDS:
            seg = self.data[start:end+1]
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
        
        bits_per_chip = 1 << (28 + (b4 & 0x0F))
        chip_size_Mb = bits_per_chip / (1024**2)
        chip_size_str = f"{int(chip_size_Mb)}Mb" if chip_size_Mb < 1024 else f"{int(chip_size_Mb / 1024)}Gb"

        ranks = ((b7 >> 3) & 0x7) + 1
        sdram_device_width = 4 * (2**(b7 & 0x7))
        data_width_bits = 1 << ((b8 & 0x7) + 3)
        ecc_bits = 8 if ((b8 >> 3) & 0x3) == 0b01 else 0
        
        data_chips_per_rank = data_width_bits // sdram_device_width if sdram_device_width else 0
        ecc_chips_per_rank = ecc_bits // sdram_device_width if sdram_device_width else 0
        total_data_chips = ranks * data_chips_per_rank
        total_ecc_chips = ranks * ecc_chips_per_rank
        total_chips = total_data_chips + total_ecc_chips

        data_bytes = (bits_per_chip * total_data_chips) // 8
        ecc_bytes = (bits_per_chip * total_ecc_chips) // 8
        data_gib = round(data_bytes / (1024**3), 2)
        ecc_gib = round(ecc_bytes / (1024**3), 2)

        module_size_str = f"{data_gib} GiB"
        if ecc_gib > 0:
            module_size_str += f" + {ecc_gib} GiB ECC"
        
        total_chips_str = str(total_data_chips)
        if total_ecc_chips > 0:
            total_chips_str += f" + {total_ecc_chips} ECC"

        bank_address_bits = 8 # Fixed for DDR3
        row_address_bits = 12 + ((b5 >> 3) & 0x7)
        col_address_bits = 9 + (b5 & 0x7)
        
        addr_chip_bits = (2**row_address_bits) * (2**col_address_bits) * bank_address_bits * sdram_device_width
        addr_module_bytes = (addr_chip_bits * total_chips) // 8

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
            "bank_address_bits": bank_address_bits,
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
        mtb_ns = (self.data[10] or 1) / (self.data[11] or 1); ftb_div_ps = self.data[9] & 0xF; ftb_ns = ((self.data[9] >> 4) & 0xF) / (ftb_div_ps or 1) / 1000.0 if ftb_div_ps != 0 else 0.001
        def mtb_ftb(mtb_raw: int, ftb_idx: int) -> float: return (mtb_raw * mtb_ns) + (self._s8(self.data[ftb_idx]) * ftb_ns)
        tCKmin_ns = mtb_ftb(self.data[12], 34); tAAmin_ns = mtb_ftb(self.data[16], 35); tRCDmin_ns = mtb_ftb(self.data[18], 36); tRPmin_ns = mtb_ftb(self.data[20], 37); tRASmin_ns = (((self.data[21] & 0x0F) << 8) | self.data[22]) * mtb_ns
        tRCmin_ns = ((((self.data[21] & 0xF0) >> 4) << 8) | self.data[23]) * mtb_ns + (self._s8(self.data[38]) * ftb_ns)
        tRFCmin_ns = ((self.data[25] << 8) | self.data[24]) * mtb_ns
        cl_bits = (self.data[15] << 8) | self.data[14]; cas_latencies = [cl for cl in range(4, 19) if (cl_bits & (1 << (cl - 4))) != 0]
        rate = int(round(2000.0 / tCKmin_ns)) if tCKmin_ns > 0 else 0
        return { "timings_ns": { "tCKmin": round(tCKmin_ns, 3), "tAAmin": round(tAAmin_ns, 3), "tRCDmin": round(tRCDmin_ns, 3), "tRPmin": round(tRPmin_ns, 3), "tRASmin": round(tRASmin_ns, 3), "tRCmin": round(tRCmin_ns, 3), "tRFCmin": round(tRFCmin_ns, 3) }, "timings_clocks": { "CL": math.ceil(tAAmin_ns / tCKmin_ns) if tCKmin_ns > 0 else 0, "tRCD": math.ceil(tRCDmin_ns / tCKmin_ns) if tCKmin_ns > 0 else 0, "tRP": math.ceil(tRPmin_ns / tCKmin_ns) if tCKmin_ns > 0 else 0, "tRAS": math.ceil(tRASmin_ns / tCKmin_ns) if tCKmin_ns > 0 else 0 }, "cas_latencies_supported": cas_latencies, "max_data_rate_MTps": rate }
    def _calculate_jedec_downbins(self, timings_ns: Dict, max_rate: int) -> Dict:
        jedec_speeds = { 800: 2.5, 1066: 1.875, 1333: 1.5, 1600: 1.25, 1866: 1.07, 2133: 0.937 }
        downbins = []
        for speed, tck in jedec_speeds.items():
            if speed < max_rate:
                cl = math.ceil(timings_ns['tAAmin'] / tck)
                trcd = math.ceil(timings_ns['tRCDmin'] / tck)
                trp = math.ceil(timings_ns['tRPmin'] / tck)
                tras = math.ceil(timings_ns['tRASmin'] / tck)
                downbins.append({ "speed": f"DDR3-{speed}", "timings": f"{cl}-{trcd}-{trp}-{tras}" })
        
        voltage_suffix = "L" if "1.35V" in self._decode_general()['voltages_supported'] else ""
        bandwidth = int(max_rate * 8 / 100) * 100
        jedec_standard_name = f"PC3{voltage_suffix}-{bandwidth}"
        
        return {"jedec_downbins": downbins, "jedec_standard_name": jedec_standard_name}
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
            "manufacture_date": f"20{year:02d}-W{week:02d}",
        }
    def _decode_hpt(self) -> Dict: present = self.data[176:180] == b'HPT\x00'; return { "present": present, "code": self.data[180:184].hex(' ').upper() if present else None }
    def _decode_xmp(self) -> Optional[Dict]:
        """
        Parse Intel XMP (DDR3) profile block at 176..255.

        Fixes vs. old version:
        • Validate header (0x0C, 0x4A) and use revision at [178].
        • Treat XMP fields as LITTLE‑ENDIAN words where appropriate.
        • tCKmin is a 16‑bit MTB count (not a single byte). Multiply by SPD MTB.
        • Voltage is a 16‑bit little‑endian value in mV → divide by 1000.
        • Keep byte layout you relied on; profile 2 is +35 bytes from profile 1.

        Layout used here (per your existing offsets, normalized):
        Profile 1 base = 182
            +0..+1 : VDD in mV (u16 LE)
            +2..+3 : tCKmin in MTB units (u16 LE)
            +4     : CL (cycles)
            +6     : tRCD (cycles)
            +8     : tRP (cycles)
            +10..+11: tRAS (u12 LE: LSB @+10, low nibble of +11)
            +12    : command rate T (cycles)
        Profile 2 base = 217 (= 182 + 35)
        """
        # Header check
        if not (len(self.data) >= 230 and self.data[176] == 0x0C and self.data[177] == 0x4A):
            return None

        xmp_rev = self.data[178]  # e.g., 0x12 for XMP 1.2

        def u16le(off: int) -> int:
            return (self.data[off] | (self.data[off + 1] << 8)) & 0xFFFF

        def u12le(off: int) -> int:
            return (self.data[off] | ((self.data[off + 1] & 0x0F) << 8)) & 0x0FFF

        # SPD Medium Timebase (ns) — use the module's MTB for XMP scaling
        mtb_ns = (self.data[10] or 1) / (self.data[11] or 1)

        def build_profile(base: int, idx: int) -> Optional[Dict]:
            try:
                v_mV = u16le(base + 0)
                tck_mtb = u16le(base + 2)
                if tck_mtb == 0:
                    return None
                tck_ns = tck_mtb * mtb_ns
                data_rate = int(round(2000.0 / tck_ns)) if tck_ns > 0 else 0
                cl = int(self.data[base + 4])
                trcd = int(self.data[base + 6])
                trp = int(self.data[base + 8])
                tras = u12le(base + 10)
                cmd = int(self.data[base + 12])
                return {
                    "profile": idx,
                    "data_rate_MTps": data_rate,
                    "voltage_V": round(v_mV / 1000.0, 3),
                    "timings": f"{cl}-{trcd}-{trp}-{tras}",
                    "command_rate_T": cmd,
                    "xmp_revision": xmp_rev,
                }
            except IndexError:
                return None

        profiles: List[Dict] = []
        p1 = build_profile(182, 1)
        if p1:
            profiles.append(p1)
        # second profile lives +35 bytes after p1 in your layout
        p2 = build_profile(217, 2)
        if p2:
            profiles.append(p2)

        return {"xmp_profiles": profiles} if profiles else None

    def _decode_registered_info(self) -> Optional[Dict]:
        module_type = self.data[3]
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
                "control_words": self.data[69:77]
            }
        elif module_type == 0x0B: # LRDIMM
            return {
                "mfg_id_offset": 60,
                "mfg_id": self._decode_jep106(self.data[60], self.data[61]),
                "revision": self.data[62],
                "personality_bytes": self.data[102:115]
            }
        return None
    def _decode_unbuffered_info(self) -> Optional[Dict]:
        module_type = self.data[3]
        if module_type not in [0x02, 0x03, 0x04, 0x06, 0x08, 0x0C, 0x0D]:
            return None
        
        b60, b61, b62 = self.data[60], self.data[61], self.data[62]
        
        height_code = b60 & 0x1F
        height_str = f"{15 + height_code -1} < height <= {15 + height_code} mm" if height_code > 0 else "height <= 15 mm"
        
        back_thick = (b61 >> 4) & 0xF
        front_thick = b61 & 0xF
        
        raw_card_ext = (b60 >> 5) & 0x7
        raw_card_rev = (b62 >> 5) & 0x3
        if raw_card_ext > 0: raw_card_rev += 4
        
        card_map_a = { 0:'A', 1:'B', 2:'C', 3:'D', 4:'E', 5:'F', 6:'G', 7:'H', 8:'J', 9:'K', 10:'L', 11:'M', 12:'N', 13:'P', 14:'R', 15:'T', 16:'U', 17:'V', 18:'W', 19:'Y', 20:'AA', 21:'AB', 22:'AC', 23:'AD', 24:'AE', 25:'AF', 26:'AG', 27:'AH', 28:'AJ', 29:'AK', 30:'AL', 31:'ZZ' }
        card_map_b = { 0:'AM', 1:'AN', 2:'AP', 3:'AR', 4:'AT', 5:'AU', 6:'AV', 7:'AW', 8:'AY', 9:'BA', 10:'BB', 11:'BC', 12:'BD', 13:'BE', 14:'BF', 15:'BG', 16:'BH', 17:'BJ', 18:'BK', 19:'BL', 20:'BM', 21:'BN', 22:'BP', 23:'BR', 24:'BT', 25:'BU', 26:'BV', 27:'BW', 28:'BY', 29:'CA', 30:'CB', 31:'ZZ' }
        
        card_letter = card_map_b.get(b62 & 0x1F) if (b62 & 0x80) else card_map_a.get(b62 & 0x1F)

        return {
            "nominal_height": height_str,
            "max_thickness_front": f"{front_thick} < thickness <= {front_thick+1} mm" if front_thick > 0 else "thickness <= 1 mm",
            "max_thickness_back": f"{back_thick} < thickness <= {back_thick+1} mm" if back_thick > 0 else "thickness <= 1 mm",
            "ref_raw_card": card_letter,
            "ref_raw_card_rev": raw_card_rev,
            "rank_1_mapping_mirrored": (self.data[63] & 0x01) != 0
        }
    def _find_gaps(self) -> Dict:
        used_bytes = set()
        used_bytes.update(range(0, 32 + 1))
        used_bytes.update(range(34, 38 + 1))
        used_bytes.update(range(117, 125 + 1))
        used_bytes.update(range(128, 149 + 1))
        used_bytes.update(range(126, 127 + 1))
        
        module_type = self.data[3]
        if module_type in [0x02, 0x03, 0x04, 0x06, 0x08, 0x0C, 0x0D]: used_bytes.update(range(60, 63 + 1))
        elif module_type in [0x01, 0x05, 0x09]: used_bytes.update(range(60, 77 + 1))
        elif module_type == 0x0B: used_bytes.update(range(60, 62 + 1)); used_bytes.update(range(102, 115 + 1))
            
        if self._decode_xmp() or self._decode_hpt()['present']:
            used_bytes.update(range(176, 255 + 1))
            
        gap_bytes = sorted(list(set(range(0, 256)) - used_bytes))
        if not gap_bytes: return {"undecoded_gaps": []}
            
        ranges = []
        start = end = gap_bytes[0]
        for i in range(1, len(gap_bytes)):
            if gap_bytes[i] == end + 1: end = gap_bytes[i]
            else: ranges.append((start, end)); start = end = gap_bytes[i]
        ranges.append((start, end))
        
        return {"undecoded_gaps": ranges}
    def _detect_base_crc(self) -> Dict:
        lsb, msb = self.data[126], self.data[127]; stored_val = (msb << 8) | lsb; start, end = self._get_crc_coverage(declared=True); declared_name = self._try_match_crc16(self.data[start:end+1], stored_val)
        if declared_name: return {"status": "VALID", "stored": stored_val, "computed": stored_val, "coverage": f"0..{end}", "variant": declared_name, "coverage_match": True}
        start_alt, end_alt = self._get_crc_coverage(declared=False); alternate_name = self._try_match_crc16(self.data[start_alt:end_alt+1], stored_val)
        if alternate_name: return {"status": "VALID (alternate coverage)", "stored": stored_val, "computed": stored_val, "coverage": f"0..{end_alt}", "variant": alternate_name, "coverage_match": False}
        calc_default = self._compute_crc16_variant("XMODEM", self.data[start:end+1]); return {"status": "INVALID", "stored": stored_val, "computed": calc_default, "coverage": f"0..{end}", "variant": "XMODEM*guess", "coverage_match": False}
    def _s8(self, x: int) -> int: return x - 256 if x > 127 else x
    def _bcd_to_int(self, bcd_byte: int) -> int:
        """Converts a Binary Coded Decimal byte to an integer."""
        return ((bcd_byte >> 4) * 10) + (bcd_byte & 0x0F)
    def _ddr3_module_type_name(self, v: int) -> str: return {0: "Undefined", 1: "RDIMM", 2: "UDIMM", 3: "SO-DIMM", 4: "Micro-DIMM", 8: "Mini-RDIMM", 9: "Mini-UDIMM", 11: "LRDIMM"}.get(v, f"Unknown (0x{v:02X})")
    def _decode_byte0_info(self, b0: int) -> str:
        crc = "0..125" if (b0 & 0x80) == 0 else "0..116"
        size = "256 bytes" if ((b0 >> 4) & 0x7) == 1 else "reserved"
        used = {1: '128', 2: '176', 3: '256'}.get(b0 & 0xF, 'reserved')
        return f"CRC Coverage: {crc}; Total Size: {size}; Bytes Used: {used}"
    def _get_crc_coverage(self, declared: bool = True) -> Tuple[int, int]: end = 125 if (self.data[0] & 0x80) == 0 else 116; return (0, end) if declared else (0, 116 if end == 125 else 125)
    def _try_match_crc16(self, data: bytes, stored_val: int) -> Optional[str]:
        for name, params in CRC16_VARIANTS.items():
            if self._crc16_generic(data, *params) == stored_val: return name
        return None
    def _compute_crc16_variant(self, name: str, data: bytes) -> int: return self._crc16_generic(data, *CRC16_VARIANTS[name])
    def _decode_jep106(self, lsb: int, msb: int) -> str:
        bank, code = lsb & 0x7F, msb; name = JEP106_MAP.get((bank, code)); return f"{name} (Bank {bank}, Code 0x{code:02X})" if name else f"Unknown (Bank {bank}, Code 0x{code:02X})"
    def _needs_base_crc_update(self, before: bytes, after: bytes) -> bool: _, end = self._get_crc_coverage(); return before[:end+1] != after[:end+1]
    def _rewrite_base_crc(self, spd_mut: bytearray): start, end = self._get_crc_coverage(); calc = self._compute_crc16_variant("XMODEM", spd_mut[start:end+1]); spd_mut[126] = calc & 0xFF; spd_mut[127] = (calc >> 8) & 0xFF
    def _set_hpt_code(self, spd_mut: bytearray, code: bytes):
        if len(code) != 4: raise ValueError("HPT code must be 4 bytes")
        spd_mut[176:180] = b'HPT\x00'; spd_mut[180:184] = code
    def _crc16_generic(self, data: bytes, poly: int, init: int, refin: bool, refout: bool, xorout: int, width: int = 16) -> int:
        reg = init & ((1 << width) - 1); data_iter = (self._reflect_bits(b, 8) for b in data) if refin else data
        for b in data_iter:
            reg ^= (b << (width - 8)) & ((1 << width) - 1)
            for _ in range(8):
                if reg & (1 << (width - 1)): reg = ((reg << 1) & ((1 << width) - 1)) ^ poly
                else: reg = (reg << 1) & ((1 << width) - 1)
        if refout: reg = self._reflect_bits(reg, width)
        return reg ^ xorout
    def _reflect_bits(self, val: int, width: int) -> int:
        res = 0
        for i in range(width):
            if val & (1 << i): res |= 1 << (width - 1 - i)
        return res
