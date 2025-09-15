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
from ddr3_xmp_decoder import decode_xmp # Import the new function

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

        mech = self._decode_mechanical_info()
        if mech:
            decoded["mechanical_info"] = mech

        
        unbuffered_info = self._decode_unbuffered_info()
        if unbuffered_info:
            decoded["unbuffered_info"] = unbuffered_info

        reg_info = self._decode_registered_info()
        if reg_info:
            decoded["registered_info"] = reg_info

        xmp = decode_xmp(self.data) # Call the imported function
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
            p("63, bit 0", "Rank 1 Mapping", "Mirrored" if m['rank_1_mapping_mirrored'] else "Standard", self.data[63])

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
        banks_per_chip = 8  # DDR3 SDRAM has 8 internal banks
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
            "bank_address_bits": banks_per_chip,  # kept for display; value is number of banks
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


    
    def _decode_mechanical_info(self) -> Optional[Dict]:
        """Decode physical/mechanical fields present on both UDIMM and RDIMM:
        Byte60: Nominal height (5b) + Raw Card Extension (3b)
        Byte61: Max thickness back/front (4b/4b)
        Byte62: Reference raw card + Rev (and bank select for letter table)
        Byte63 bit0: rank-1 address mapping mirror (UDIMM; still meaningful on RDIMM)
        """
        module_type = self.data[3]
        # Apply to UDIMM/SO-DIMM/Micro-DIMM and also LR/RDIMM family (0x01, 0x05, 0x09)
        if module_type not in [0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0B, 0x0C, 0x0D, 0x11]:
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
            raw_card_rev += 4

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
            "manufacture_date": f"20{year:02d}-W{week:02d}",
        }
    def _decode_hpt(self) -> Dict: present = self.data[176:180] == b'HPT\x00'; return { "present": present, "code": self.data[180:184].hex(' ').upper() if present else None }
    def _decode_xmp(self) -> Optional[Dict]:
        """
        Intel XMP for DDR3 (per XMP 1.1/1.2 table).

        Header (176..183):
        176 = 0x0C, 177 = 0x4A (magic)
        178: bit0 P1 enable, bit1 P2 enable, bits3:2 P1 DIMMs/ch (enc 0..3 -> 1..4),
            bits5:4 P2 DIMMs/ch (enc 0..3 -> 1..4)
        179: [7:4]=major, [3:0]=minor
        180..181: Profile1 MTB (dividend, divisor)  ns = dividend / divisor
        182..183: Profile2 MTB (dividend, divisor)  ns = dividend / divisor

        Profile blocks start at 185 (P1) and 220 (P2):
        185/220: Voltage bits   [6:5]=units (0..2), [4:1]=tenths (0..9), [0]=twentieth (0 or 1 -> +0.05)
        186/221: tCKmin (MTB units, u8)
        187/222: tAAmin (MTB units, u8)
        188/223: CAS bitmap bits 0..7 -> CL 4..11
        189/224: CAS bitmap bits 0..6 -> CL 12..18
        190/225: tCWLmin (MTB units, u8)
        191/226: tRPmin  (MTB units, u8)
        192/227: tRCDmin (MTB units, u8)
        193/228: tWRmin  (MTB units, u8)
        194/229: upper nibbles: [3:0]=tRAS upper, [7:4]=tRC upper
        195/230: tRAS LSB
        196/231: tRC LSB
        197/232: tREFI LSB  (u16 LE in MTB units)
        198/233: tREFI MSB
        199/234: tRFC  LSB  (u16 LE in MTB units)
        200/235: tRFC  MSB
        201/236: tRTP  (MTB, u8)
        202/237: tRRD  (MTB, u8)
        203/238: tFAW upper nibble in [3:0]
        204/239: tFAW LSB (u8)
        205/240: tWTR  (MTB, u8)
        206/241: turnaround adj (R<->W/W<->R) with signs — exposed raw
        207/242: back-to-back adj with sign — exposed raw
        208/243: system CMD rate mode (units of MTB × tCK/ns) — exposed raw, plus a best-effort To guess
        209/244: ASR perf (raw)
        219/254: vendor-specific personality code (raw)
        """
        import math

        def bits(v, hi, lo):
            mask = (1 << (hi - lo + 1)) - 1
            return (v >> lo) & mask

        # 1) Validate header
        if len(self.data) < 220 or self.data[176] != 0x0C or self.data[177] != 0x4A:
            return None

        b178 = self.data[178]
        b179 = self.data[179]

        p1_enabled = bool(b178 & 0x01)
        p2_enabled = bool(b178 & 0x02)
        p1_dimms_per_ch = bits(b178, 3, 2) + 1
        p2_dimms_per_ch = bits(b178, 5, 4) + 1

        xmp_major = bits(b179, 7, 4)
        xmp_minor = bits(b179, 3, 0)
        xmp_version = f"{xmp_major}.{xmp_minor}"

        def mtb_ns_from(dd_off, dv_off):
            dd = self.data[dd_off]
            dv = self.data[dv_off]
            if dv == 0:
                # Fallback to base SPD MTB (bytes 10/11) if divisor is zero
                base_div = self.data[11] or 1
                return (self.data[10] or 1) / base_div
            return dd / dv

        mtb_p1_ns = mtb_ns_from(180, 181)
        mtb_p2_ns = mtb_ns_from(182, 183)

        def decode_voltage(vb: int) -> float:
            units = bits(vb, 6, 5)          # 0..2
            tenths = bits(vb, 4, 1)         # 0..9
            twentieth = bits(vb, 0, 0)      # 0 or 1 (adds +0.05)
            return round(units + tenths / 10.0 + (0.05 if twentieth else 0.0), 3)

        def cas_bitmap(b0: int, b1: int):
            out = []
            for i in range(8):
                if b0 & (1 << i):
                    out.append(4 + i)
            for i in range(7):
                if b1 & (1 << i):
                    out.append(12 + i)
            return out

        def u16le(lo: int, hi: int) -> int:
            return (self.data[lo] | (self.data[hi] << 8)) & 0xFFFF

        def t_in_ns(count_mtb: int, mtb_ns: float) -> float:
            return round(count_mtb * mtb_ns, 3)

        def clocks_from_ns(ns_val: float, tck_ns: float) -> int:
            return int(math.ceil(ns_val / tck_ns)) if tck_ns > 0 else 0

        def parse_profile(base: int, mtb_ns: float, enabled: bool, dimms_per_ch: int, idx: int):
            try:
                vb = self.data[base + 0]
                v_dd = decode_voltage(vb)
                tck_mtb = self.data[base + 1]  # 186/221 stored at base+1
                tAA_mtb = self.data[base + 2]
                clmap0 = self.data[base + 3]
                clmap1 = self.data[base + 4]
                tCWL_mtb = self.data[base + 5]
                tRP_mtb  = self.data[base + 6]
                tRCD_mtb = self.data[base + 7]
                tWR_mtb  = self.data[base + 8]
                upper    = self.data[base + 9]
                tRAS_lsb = self.data[base +10]
                tRC_lsb  = self.data[base +11]
                tREFI    = u16le(base +12, base +13)
                tRFC     = u16le(base +14, base +15)
                tRTP_mtb = self.data[base +16]
                tRRD_mtb = self.data[base +17]
                tFAW_up  = self.data[base +18]
                tFAW_lsb = self.data[base +19]
                tWTR_mtb = self.data[base +20]
                w2r_raw  = self.data[base +21]
                b2b_raw  = self.data[base +22]
                cmd_mode = self.data[base +23]
                asr_raw  = self.data[base +24]
                vend_raw = self.data[base +34] if (base + 34) < 256 else 0

                if tck_mtb == 0:
                    return None

                # Compose 12-bit values
                tRAS_mtb = ((upper & 0x0F) << 8) | tRAS_lsb
                tRC_mtb  = ((upper >> 4) << 8) | tRC_lsb
                tFAW_mtb = ((tFAW_up & 0x0F) << 8) | tFAW_lsb

                # Convert to ns
                tCK_ns  = t_in_ns(tck_mtb, mtb_ns)
                tAA_ns  = t_in_ns(tAA_mtb, mtb_ns)
                tCWL_ns = t_in_ns(tCWL_mtb, mtb_ns)
                tRP_ns  = t_in_ns(tRP_mtb, mtb_ns)
                tRCD_ns = t_in_ns(tRCD_mtb, mtb_ns)
                tWR_ns  = t_in_ns(tWR_mtb, mtb_ns)
                tRAS_ns = t_in_ns(tRAS_mtb, mtb_ns)
                tRC_ns  = t_in_ns(tRC_mtb,  mtb_ns)
                tREFI_ns= t_in_ns(tREFI,    mtb_ns)
                tRFC_ns = t_in_ns(tRFC,     mtb_ns)
                tRTP_ns = t_in_ns(tRTP_mtb, mtb_ns)
                tRRD_ns = t_in_ns(tRRD_mtb, mtb_ns)
                tFAW_ns = t_in_ns(tFAW_mtb, mtb_ns)
                tWTR_ns = t_in_ns(tWTR_mtb, mtb_ns)

                data_rate = int(round(2000.0 / tCK_ns)) if tCK_ns > 0 else 0

                # Timings in clocks
                CL   = clocks_from_ns(tAA_ns,  tCK_ns)
                tRCD = clocks_from_ns(tRCD_ns, tCK_ns)
                tRP  = clocks_from_ns(tRP_ns,  tCK_ns)
                tRAS = clocks_from_ns(tRAS_ns, tCK_ns)

                # CAS support bitmap
                cas_list = cas_bitmap(clmap0, clmap1)

                # Command rate guess (best-effort): value is in units of MTB * tCK/ns
                # cycles ≈ cmd_mode * (mtb_ns / tCK_ns)
                cmd_rate_guess = None
                if cmd_mode:
                    guess = int(round(cmd_mode * (mtb_ns / tCK_ns))) if tCK_ns > 0 else None
                    if guess in (1, 2):
                        cmd_rate_guess = guess

                return {
                    "profile": idx,
                    "enabled": enabled,
                    "dimms_per_channel": dimms_per_ch,
                    "xmp_version": xmp_version,
                    "mtb_ns": round(mtb_ns, 6),
                    "data_rate_MTps": data_rate,
                    "voltage_V": v_dd,
                    "timings": f"{CL}-{tRCD}-{tRP}-{tRAS}",
                    "command_rate_T": cmd_rate_guess,
                    "cas_latencies_supported": cas_list,
                    "timings_ns": {
                        "tCKmin": tCK_ns, "tAAmin": tAA_ns, "tCWLmin": tCWL_ns,
                        "tRPmin": tRP_ns, "tRCDmin": tRCD_ns, "tWRmin": tWR_ns,
                        "tRASmin": tRAS_ns, "tRCmin": tRC_ns, "tREFI": tREFI_ns,
                        "tRFCmin": tRFC_ns, "tRTPmin": tRTP_ns, "tRRDmin": tRRD_ns,
                        "tFAWmin": tFAW_ns, "tWTRmin": tWTR_ns,
                    },
                    "raw": {
                        "turnaround_W2R": w2r_raw, "back_to_back": b2b_raw,
                        "cmd_rate_mode_raw": cmd_mode, "asr_perf_raw": asr_raw,
                        "vendor_personality": vend_raw,
                    },
                }
            except IndexError:
                return None

        profiles = []
        p1 = parse_profile(185, mtb_p1_ns, p1_enabled, p1_dimms_per_ch, 1)
        if p1:
            profiles.append(p1)
        p2 = parse_profile(220, mtb_p2_ns, p2_enabled, p2_dimms_per_ch, 2)
        if p2:
            profiles.append(p2)

        header = {
            "xmp_version": xmp_version,
            "profile_1_enabled": p1_enabled,
            "profile_2_enabled": p2_enabled,
            "profile_1_dimms_per_channel": p1_dimms_per_ch,
            "profile_2_dimms_per_channel": p2_dimms_per_ch,
            "profile_1_mtb_ns": round(mtb_p1_ns, 6),
            "profile_2_mtb_ns": round(mtb_p2_ns, 6),
        }

        # Back-compat with pretty_print: expose simplified list
        simple_list = []
        for pr in profiles:
            simple_list.append({
                "profile": pr["profile"],
                "data_rate_MTps": pr["data_rate_MTps"],
                "timings": pr["timings"],
                "command_rate_T": (pr["command_rate_T"] if pr["command_rate_T"] is not None else "N/A"),
                "voltage_V": pr["voltage_V"],
                "enabled": pr["enabled"],
                "dimms_per_channel": pr["dimms_per_channel"],
            })

        return {"xmp_header": header, "xmp_profiles": simple_list, "xmp_profiles_detailed": profiles} if profiles else {"xmp_header": header}

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
