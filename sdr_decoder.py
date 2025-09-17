#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# sdr_decoder.py
#
# SDR (PC66/PC100/PC133) SPD decoder per JEDEC SDR SDRAM SPD (bytes per table).

from typing import Dict, List, Optional, Tuple
import math

JEP106_BANK_NAME = {
    # You can extend this with your map; for now we render raw codes if unknown
    (0, 0x04): "HP Inc.",
    (0, 0x1C): "Mitsubishi",
    (0, 0x2C): "Micron Technology",
    (0, 0x2D): "SK hynix (Hyundai)",
    (0, 0x4E): "Samsung",
    (1, 0x98): "Kingston",
    (2, 0x9E): "Corsair",
    (3, 0x1B): "Crucial Technology",
}

def _sum8(data: bytes) -> int:
    return sum(data) & 0xFF

def _u16le(lo: int, hi: int) -> int:
    return (lo | (hi << 8)) & 0xFFFF

def _ns_tenths(b: int) -> float:
    # high nibble = integer ns (0..15), low nibble = tenths (0..9)
    return ((b >> 4) & 0xF) + (b & 0xF) / 10.0

def _ns_quarter(b: int) -> float:
    # upper 6 bits = integer ns (1..63), lower 2 bits encodes .00, .25, .50, .75
    whole = (b >> 2) & 0x3F
    frac  = (b & 0x3) * 0.25
    return whole + frac

def _signed_ns_tenths(b: int) -> float:
    sign = -1.0 if (b & 0x80) else 1.0
    ns   = ((b >> 4) & 0x7) + (b & 0xF) / 10.0
    return sign * ns

def _interface_voltage_label(code: int) -> str:
    # Byte 8 “interface voltage” — common encodings seen in modules
    return {
        0x00: "TTL (5V tolerant)",
        0x01: "LVTTL (3.3V tolerant)",
        0x02: "HSTL",
        0x03: "SSTL 3.3V",
        0x04: "SSTL 2.5V",
    }.get(code & 0x07, f"Unknown (0x{code & 0x07:02X})")

def _mhz_from_tck_ns(tck_ns: float) -> float:
    return 0.0 if tck_ns <= 0.0 else 1000.0 / tck_ns  # MHz

def _cycles(ns_val: float, tck_ns: float) -> int:
    if tck_ns <= 0.0:
        return 0
    # Use round() instead of math.ceil() for more realistic timings.
    return int(round(ns_val / tck_ns))

def _pc_rating_from_mhz(mhz: float) -> str:
    rounded = int(round(mhz))
    if 60 <= rounded <= 72:  return "PC66"
    if 90 <= rounded <= 110: return "PC100"
    if 124 <= rounded <= 140:return "PC133"
    # Fallback: bandwidth-ish
    return f"PC{int(round(mhz*8.0))}"

def _bool(b: int, bit: int) -> bool:
    return (b >> bit) & 1 == 1

def _decode_density_bitmap(b31: int) -> List[str]:
    # Byte 31 bitmap (bit7..0) = {512,256,128,64,32,16,8,4 MiB}
    sizes = [4, 8, 16, 32, 64, 128, 256, 512]
    out = []
    for i in range(8):
        if (b31 >> i) & 1:
            out.append(f"{sizes[i]} MiB")
    return out

def _decode_burst_lengths(b16: int) -> List[int]:
    out = []
    for bit, bl in enumerate([1, 2, 4, 8]):  # bits 0..3 correspond to 1,2,4,8
        if _bool(b16, bit):
            out.append(bl)
    return out

def _decode_bitmap_latencies(b: int, start_label: str, add_one: bool = False) -> List[int]:
    # Simple “bit -> integer” list (CAS/CS/WE “complement” latency bitmaps)
    # Bytes 18/19/20: bits 0..6 are documented; bit7 reserved.
    vals = []
    for v in range(0, 7 + 1):
        if v == 7:
            continue  # ignore bit7 per table
        if _bool(b, v):
            vals.append(v + 1 if add_one else v) # Use the new parameter
    return vals

def _decode_manufacturer_id(bank_bytes_le: bytes) -> str:
    # Bytes 64..71 store JEDEC ID in little-endian pairs, trailing zero-padded.
    # Common layout (little-endian pairs): [LSB(bank0), MSB(code0), LSB(bank1), MSB(code1), ...]
    pairs = []
    for i in range(0, len(bank_bytes_le), 2):
        lsb = bank_bytes_le[i]
        msb = bank_bytes_le[i+1] if i+1 < len(bank_bytes_le) else 0
        if lsb == 0 and msb == 0:
            break
        bank = lsb & 0x7F
        code = msb
        name = JEP106_BANK_NAME.get((bank, code))
        pairs.append(f"{name}" if name else f"JEDEC(b{bank:02X},c{code:02X})")
    return ", ".join(pairs) if pairs else ""

class SDRDecoder:
    """Decoder for 128-byte SDR SPD per JEDEC table."""

    def __init__(self, data: bytes):
        self.data = data
        if len(self.data) < 128:
            raise ValueError("SDR SPD must be 128 bytes (got %d)." % len(self.data))

    # ----- Public API -----

    def decode(self) -> Dict:
        d = self.data
        warnings = []

        # ---- General (JEDEC table for SDR) ----
        row_addr_b1 = d[3] & 0x0F
        row_addr_b2 = (d[3] >> 4) & 0x0F   # 0 → same as bank1
        col_addr_b1 = d[4] & 0x0F
        col_addr_b2 = (d[4] >> 4) & 0x0F   # 0 → same as bank1
        banks_on_module = d[5]
        width_bits = _u16le(d[6], d[7])

        general = {
            "bytes_present": d[0],
            "eeprom_log2_size": d[1],
            "memory_type": 0x04,  # SDR
            "interface_voltage": _interface_voltage_label(d[8]),
            "spd_revision": f"{(d[62] >> 4) & 0xF}.{d[62] & 0xF}",
        }

        # ---- Addressing / module config (DDR3-like section names) ----
        addressing = {
            "module_data_width_bits": width_bits,
            "banks_on_module": banks_on_module,
            "bank1_row_bits": row_addr_b1 or None,
            "bank1_col_bits": col_addr_b1 or None,
            "bank2_row_bits": (row_addr_b2 if row_addr_b2 != 0 else row_addr_b1) or None,
            "bank2_col_bits": (col_addr_b2 if col_addr_b2 != 0 else col_addr_b1) or None,
            "banks_per_device": d[17],
        }

        # Timings (ns)
        timings = {
            # CHANGE THESE KEYS
            "tCK_highestCL_ns": _ns_tenths(d[9]),
            "tAC_highestCL_ns": _ns_tenths(d[10]),
            "tCK_mediumCL_ns":  _ns_tenths(d[23]),
            "tAC_mediumCL_ns":  _ns_tenths(d[24]),
            "tCK_shortCL_ns": _ns_quarter(d[25]),
            "tAC_shortCL_ns": _ns_quarter(d[26]),
            # ADD "_min_" SUFFIX TO THESE KEYS
            "tRP_min_ns": float(d[27]),
            "tRRD_min_ns": float(d[28]),
            "tRCD_min_ns": float(d[29]),
            "tRAS_min_ns": float(d[30]),
        }

        if timings["tCK_mediumCL_ns"] == 0 or timings["tCK_shortCL_ns"] == 0:
            warnings.append("SPD contains an incomplete timing profile; slower speeds were extrapolated.")

        # Capabilities (unified shape like DDR3 pretty printer)
        ecc_mode = {0: "non-ECC", 1: "parity", 2: "ECC"}.get(d[11] & 0x03, f"0x{d[11] & 0x03:02X}")
        capabilities = {
            "dimm_config": {"ecc_mode": ecc_mode},
            "refresh_rate": {0: "64 kHz", 1: "256 kHz", 2: "128 kHz", 3: "32 kHz", 4: "16 kHz", 5: "8 kHz"}.get(d[12] & 0x07, f"0x{d[12] & 0x07:02X}"),
            "burst_lengths_supported": _decode_burst_lengths(d[16]),
            "cas_latencies": _decode_bitmap_latencies(d[18], "CAS", add_one=True), # CAS needs +1
            "cs_latencies":  _decode_bitmap_latencies(d[19], "CS"),                # CS does not
            "we_latencies":  _decode_bitmap_latencies(d[20], "WE"),                # WE does not
            "module_features": {
                "buffered_addr":   _bool(d[21], 0),
                "registered_addr": _bool(d[21], 1),
                "on_card_PLL":     _bool(d[21], 2),
                "buffered_data":   _bool(d[21], 3),
                "registered_data": _bool(d[21], 4),
                "diff_clock":      _bool(d[21], 5),
            },
            "chip_features": {
                "early_RAS_precharge": _bool(d[22], 0),
                "auto_precharge":      _bool(d[22], 1),
                "precharge_all":       _bool(d[22], 2),
                "write_read_burst":    _bool(d[22], 3),
                "Vcc_lower_tol":       _bool(d[22], 4),
                "Vcc_upper_tol":       _bool(d[22], 5),
            },
            "module_density_bitmap": _decode_density_bitmap(d[31]),
            "addr_cmd_setup_ns": _signed_ns_tenths(d[32]),
            "addr_cmd_hold_ns":  _signed_ns_tenths(d[33]),
            "din_setup_ns":      _signed_ns_tenths(d[34]),
            "din_hold_ns":       _signed_ns_tenths(d[35]),
        }

        if not capabilities["cas_latencies"]:
            warnings.append("Byte 18 specifies no supported CAS Latencies.")

        # ---- Derived speeds & cycle timings --------------------------------
        # We have three operating points from the spec:
        #   - "highest CL" uses bytes 9/10 (tCK,tAC)      -> label "high"
        #   - "medium  CL" uses bytes 23/24 (tCK,tAC)     -> label "med"
        #   - "short   CL" uses bytes 25/26 (tCK,tAC/quarter) -> label "short"
        # Some modules leave "short" zeroed; we skip any tCK==0 entries.
# ---- Derived speeds & cycle timings --------------------------------
        profiles = []
        
        # This is the user's latest "better fix" from the previous prompt
        def add_profile(label: str, tck_ns: float, tac_ns: float):
            if tck_ns <= 0.0:
                return
            
            supported_cls = capabilities["cas_latencies"]
            
            mhz = _mhz_from_tck_ns(tck_ns)
            pc = _pc_rating_from_mhz(mhz)
            
            # Calculate initial CL and clamp it to the supported range
            calculated_cl = _cycles(tac_ns, tck_ns)
            final_cl = max(calculated_cl, min(supported_cls)) if supported_cls else calculated_cl
            
            prof = {
                "label": label,
                "tCK_ns": round(tck_ns, 3),
                "tAC_ns": round(tac_ns, 3),
                "freq_MHz": round(mhz, 1),
                "data_rate_MTps": int(round(mhz)),
                "pc_rating": pc,
                "CL": final_cl,
                "tRCD": _cycles(timings["tRCD_min_ns"], tck_ns),
                "tRP": _cycles(timings["tRP_min_ns"],  tck_ns),
                "tRAS": _cycles(timings["tRAS_min_ns"], tck_ns),
                "tRRD": _cycles(timings["tRRD_min_ns"], tck_ns),
            }
            # Prevent adding duplicate profiles based on tCK
            if not any(p['tCK_ns'] == prof['tCK_ns'] for p in profiles):
                profiles.append(prof)

        # 1. Add profiles that are explicitly defined in the SPD
        add_profile("highest", timings["tCK_highestCL_ns"], timings["tAC_highestCL_ns"])
        add_profile("medium",  timings["tCK_mediumCL_ns"],  timings["tAC_mediumCL_ns"])
        add_profile("short",   timings["tCK_shortCL_ns"],   timings["tAC_shortCL_ns"])

        # 2. Extrapolate any missing standard profiles
        # We use the fastest available tAC as the base access time for calculations.
        base_tac_ns = timings.get("tAC_highestCL_ns")
        if base_tac_ns and base_tac_ns > 0:
            standard_profiles = [
                ("PC133", 7.5),
                ("PC100", 10.0),
                ("PC66", 15.0),
            ]
            for label, tck_ns in standard_profiles:
                # The label here is descriptive; it won't be used for hex lookup
                add_profile(f"extrapolated_{label}", tck_ns, base_tac_ns)
        
        # Sort profiles from fastest to slowest
        profiles.sort(key=lambda p: p["freq_MHz"], reverse=True)

        derived = {
            "profiles": profiles,
        }

        add_profile("highest", timings["tCK_highestCL_ns"], timings["tAC_highestCL_ns"])
        add_profile("medium",  timings["tCK_mediumCL_ns"],  timings["tAC_mediumCL_ns"])
        add_profile("short",   timings["tCK_shortCL_ns"],   timings["tAC_shortCL_ns"])

        derived = {
            "profiles": profiles,  # ordered list for printing
        }

        # Manufacturing block
        jedec_ids = _decode_manufacturer_id(d[64:72])
        part_num = bytes(d[73:91]).decode("ascii", errors="replace").rstrip('\x00').strip()
        serial_num_hex = d[95:99].hex().upper()
        rev_lo, rev_hi = d[91], d[92]
        year = (d[93] & 0x0F) + 10 * ((d[93] >> 4) & 0x0F)  # YY in BCD
        week = (d[94] & 0x0F) + 10 * ((d[94] >> 4) & 0x0F)  # WW in BCD
        manufacturing = {
            "jedec_ids_readable": jedec_ids or "",
            "location_code": d[72],
            "part_number": part_num or "Unknown",
            "rev_lo": rev_lo,
            "rev_hi": rev_hi,
            "manufacture_date": f"20{year:02d}-W{week:02d}",
            "serial_number_hex": d[95:99].hex().upper(),
        }

        # Intel bytes
        intel_info = {
            "intel_freq_support_byte126": d[126],
            "intel_feature_bitmap_byte127": d[127],
        }

        # Checksum (byte 63) is simple sum of 0..62 (not negated)
        stored = d[63]
        computed = _sum8(d[0:63])
        crc_info = {
            "type": "checksum8(sum0..62)",
            "stored": stored,
            "computed": computed,
            "status": "ok" if stored == computed else "bad",
            "coverage": "0..62",
        }

        if not jedec_ids:
            warnings.append("Manufacturing block is missing a JEDEC ID.")
        if not part_num:
            warnings.append("Manufacturing block is missing a Part Number.")
        if serial_num_hex == "00000000":
            warnings.append("Serial number is all zeros.")

        # Return DDR3-like top-level keys so the shared UI/HTML just works
        return {
            "general": general,
            "addressing": addressing,
            "timings_ns": timings,
            "derived": derived,
            "capabilities": capabilities,
            "manufacturing": manufacturing,
            "intel_info": intel_info,
            "crc_info": crc_info,
            "warnings": warnings,
        }


    def pretty_print(self, data: Dict, programmer_mode: bool = False):
        def p(offset_info, name, value, hex_info=None):
            if programmer_mode:
                if isinstance(offset_info, int):
                    off = f"[{offset_info:03d}]"
                elif isinstance(offset_info, tuple) and len(offset_info) == 2:
                    off = f"[{offset_info[0]:03d}-{offset_info[1]:03d}]"
                elif isinstance(offset_info, str):
                    byte_off, bits = offset_info.split(",", 1)
                    off = f"[{int(byte_off):03d}, {bits.strip()}]"
                else:
                    off = ""
                hx = ""
                if hex_info is not None:
                    if isinstance(hex_info, int):
                        hx = f"(0x{hex_info:02X})"
                    elif isinstance(hex_info, (bytes, bytearray)):
                        hx = f"({' '.join(f'{b:02X}' for b in hex_info)})"
                    elif isinstance(hex_info, (list, tuple)):
                        hx = f"({' '.join(f'{int(b)&0xFF:02X}' for b in hex_info)})"
                print(f"  {off:<18} {name:<28} {value} {hx}")
            else:
                print(f"  {name:<28} {value}")

        g = data.get("general", {})
        a = data.get("addressing", {})
        t = data.get("timings_ns", {})
        c = data.get("capabilities", {})
        m = data.get("manufacturing", {})
        crc = data.get("crc_info", {})

        # --- SPD General ---
        print("--- SPD General ---")
        p(0,  "Bytes Present",         g.get("bytes_present"),                  self.data[0])
        p(1,  "EEPROM Size (log2)",    g.get("eeprom_log2_size"),               self.data[1])
        p(2,  "Memory Type",           "SDR SDRAM (0x04)",                      self.data[2])
        p(8,  "Interface Voltage",     g.get("interface_voltage",""),           self.data[8])
        p(62, "SPD Revision",          g.get("spd_revision",""),                self.data[62])
        p(3,  "Row/Col (Bank1)",       f"r{a.get('bank1_row_bits','?')} c{a.get('bank1_col_bits','?')}", self.data[3])
        p(4,  "Row/Col (Bank2)",       f"r{a.get('bank2_row_bits','?')} c{a.get('bank2_col_bits','?')}", self.data[4])

        # --- Module Configuration ---
        print("\n--- Module Configuration ---")
        p((6,7), "Module Data Width",  f"{a.get('module_data_width_bits','?')} bits", self.data[6:8])
        p(5,     "Banks on Module",    a.get("banks_on_module","?"),            self.data[5])
        p(17,    "Banks per SDRAM",    a.get("banks_per_device","?"),           self.data[17])

        # --- Timing (ns) ---
        print("\n--- Timing (ns) ---")
        p(9,  "tCK @ highest CL", f"{t.get('tCK_highestCL_ns',0):.1f} ns", self.data[9])
        p(10, "tAC @ highest CL", f"{t.get('tAC_highestCL_ns',0):.1f} ns", self.data[10])
        p(23, "tCK @ medium  CL", f"{t.get('tCK_mediumCL_ns',0):.1f} ns", self.data[23])
        p(24, "tAC @ medium  CL", f"{t.get('tAC_mediumCL_ns',0):.1f} ns", self.data[24])
        p(25, "tCK @ short   CL", f"{t.get('tCK_shortCL_ns',0):.2f} ns", self.data[25])
        p(26, "tAC @ short   CL", f"{t.get('tAC_shortCL_ns',0):.2f} ns", self.data[26])
        p(27, "tRP / tRRD / tRCD / tRAS",
            # And also use the CORRECT keys here (with the "_min_" suffix)
            f"{t.get('tRP_min_ns',0):.1f} / {t.get('tRRD_min_ns',0):.1f} / {t.get('tRCD_min_ns',0):.1f} / {t.get('tRAS_min_ns',0):.1f} ns",
            self.data[27:31])

        # --- Derived Speeds & Timings (clocks) ---
        derv = data.get("derived", {})
        profs = derv.get("profiles", [])
        if profs:
            print("\n--- Derived Speeds & Timings (clocks) ---")
            for pr in profs:
                # e.g. "@133.3 MHz (tCK 7.500 ns)  →  CL-3 tRCD-3 tRP-3 tRAS-6  · PC1066 (~1066 MB/s)"
                mhz   = pr["freq_MHz"]
                tck   = pr["tCK_ns"]
                pc    = pr["pc_rating"]
                mbps  = int(round(mhz * 8.0))
                cl    = pr["CL"]
                trcd  = pr["tRCD"]
                trp   = pr["tRP"]
                tras  = pr["tRAS"]
                trrd  = pr["tRRD"]
                # programmer-mode raw source bytes for tCK/tAC if desired
                raw_off = {"highest": (9,10), "medium": (23,24), "short": (25,26)}.get(pr["label"])
                hex_pair = ""
                if programmer_mode and raw_off:
                    lo, hi = raw_off
                    hex_pair = f" ({self.data[lo]:02X} {self.data[hi]:02X})"
                print(f"  @{mhz:>6.1f} MHz (tCK {tck:.3f} ns){hex_pair}  →  "
                      f"CL-{cl} tRCD-{trcd} tRP-{trp} tRAS-{tras} tRRD-{trrd}  · {pc} (~{mbps} MB/s)")


        # --- Capabilities ---
        print("\n--- Capabilities ---")
        ecc_mode = (c.get("dimm_config") or {}).get("ecc_mode","")
        p(11, "DIMM Configuration",    f"{ecc_mode}   · Refresh {c.get('refresh_rate','')}", self.data[11])
        bl = c.get("burst_lengths_supported", [])
        p(16, "Burst Lengths",         "[" + ", ".join(str(x) for x in bl) + "]", self.data[16])
        p(18, "CAS Latencies",         "[" + ", ".join(str(x) for x in c.get('cas_latencies', [])) + "]", self.data[18])
        p(19, "CS  Latencies",         "[" + ", ".join(str(x) for x in c.get('cs_latencies', []))  + "]", self.data[19])
        p(20, "WE  Latencies",         "[" + ", ".join(str(x) for x in c.get('we_latencies', []))  + "]", self.data[20])
        p(21, "Module Features",       c.get("module_features", {}),            self.data[21])
        p(22, "Chip Features",         c.get("chip_features", {}),              self.data[22])
        p(31, "Module Density Bitmap", c.get("module_density_bitmap", []),      self.data[31])
        p(32, "Addr/Cmd setup/hold",   f"{c.get('addr_cmd_setup_ns',0)} / {c.get('addr_cmd_hold_ns',0)} ns", self.data[32])
        p(34, "DIN  setup/hold",       f"{c.get('din_setup_ns',0)} / {c.get('din_hold_ns',0)} ns",           self.data[34])

        # --- Manufacturing ---
        print("\n--- Manufacturing ---")
        p((64,71), "JEDEC IDs",        m.get("jedec_ids_readable","") or "<unknown>", self.data[64:72])
        p(72,      "Location Code",    f"0x{m.get('location_code',0):02X}",      self.data[72])
        p((73,90), "Part Number",      f"'{m.get('part_number','Unknown')}'",    self.data[73:91])
        p((91,92), "Revision Code",    f"0x{m.get('rev_lo',0):02X} 0x{m.get('rev_hi',0):02X}", self.data[91:93])
        p((93,94), "Manufacture Date", m.get("manufacture_date",""),             self.data[93:95])
        p((95,98), "Serial Number",    m.get("serial_number_hex",""),            self.data[95:99])

        # --- SPD Checksum ---
        print("\n--- SPD Checksum ---")
        if crc:
            p(63, "Stored / Computed",
            f"0x{crc.get('stored',0):02X} / 0x{crc.get('computed',0):02X}  ({crc.get('coverage','')})  [{crc.get('status','')}]", self.data[63])
        
        warnings = data.get("warnings", [])
        if warnings:
            print("\n--- Warnings ---")
            for i, warning in enumerate(warnings):
                print(f"  [{i+1}] {warning}")


    def dump_field_map(self) -> str:
        """Optional: raw field map for 'diff --show-maps' parity with DDR3."""
        segs = [
            (0, 0,  "Bytes Present"),
            (1, 1,  "EEPROM log2 size"),
            (2, 2,  "Memory Type"),
            (3, 3,  "Row bits (B2|B1)"),
            (4, 4,  "Col bits (B2|B1)"),
            (5, 5,  "Banks on Module"),
            (6, 7,  "Module Data Width"),
            (8, 8,  "Interface Voltage"),
            (9, 10, "tCK/tAC @ highest CL"),
            (11,11, "DIMM config"),
            (12,12, "Refresh rate"),
            (13,14, "Primary/ECC SDRAM width"),
            (15,15, "Random read clock delay"),
            (16,16, "Burst lengths"),
            (17,17, "Banks per SDRAM"),
            (18,20, "CAS/CS/WE bitmaps"),
            (21,21, "Module features"),
            (22,22, "Chip features"),
            (23,26, "tCK/tAC @ medium/short CL"),
            (27,30, "tRP/tRRD/tRCD/tRAS"),
            (31,31, "Module density bitmap"),
            (32,35, "AC/ADDR/DIN setup/hold"),
            (62,62, "SPD revision"),
            (63,63, "Checksum"),
            (64,71, "JEDEC IDs"),
            (72,72, "Mfg location"),
            (73,90, "Part number"),
            (91,92, "Module revision"),
            (93,94, "Mfg date YY/WW"),
            (95,98, "Serial number"),
            (99,125,"Vendor-specific"),
            (126,127,"Intel extensions"),
        ]
        lines = []
        for start, end, name in segs:
            seg = self.data[start:end+1]
            hexs = ' '.join(f"{b:02X}" for b in seg)
            lines.append(f"{start:03d}-{end:03d}  {name:<26} {hexs}")
        return "\n".join(lines)