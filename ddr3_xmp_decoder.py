#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# xmp_decoder.py
#
# Contains all logic specific to decoding Intel XMP profiles from DDR3 SPD binaries.
#
from typing import Dict, Optional
import math

def decode_xmp(data: bytes) -> Optional[Dict]:
    """
    Intel XMP for DDR3 (per XMP 1.1/1.2 table you provided).

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
      208/243: system CMD rate mode (units of MTB × tCK/ns) — exposed raw, plus a best-effort T guess
      209/244: ASR perf (raw)
      219/254: vendor-specific personality code (raw)
    """
    import math

    def bits(v, hi, lo):
        mask = (1 << (hi - lo + 1)) - 1
        return (v >> lo) & mask

    # 1) Validate header
    if len(data) < 220 or data[176] != 0x0C or data[177] != 0x4A:
        return None

    b178 = data[178]
    b179 = data[179]

    p1_enabled = bool(b178 & 0x01)
    p2_enabled = bool(b178 & 0x02)
    p1_dimms_per_ch = bits(b178, 3, 2) + 1
    p2_dimms_per_ch = bits(b178, 5, 4) + 1

    xmp_major = bits(b179, 7, 4)
    xmp_minor = bits(b179, 3, 0)
    xmp_version = f"{xmp_major}.{xmp_minor}"

    def mtb_ns_from(dd_off, dv_off):
        dd = data[dd_off]
        dv = data[dv_off]
        if dv == 0:
            # Fallback to base SPD MTB (bytes 10/11) if divisor is zero
            base_div = data[11] or 1
            return (data[10] or 1) / base_div
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
        return (data[lo] | (data[hi] << 8)) & 0xFFFF

    def t_in_ns(count_mtb: int, mtb_ns: float) -> float:
        return round(count_mtb * mtb_ns, 3)

    def clocks_from_ns(ns_val: float, tck_ns: float) -> int:
        return int(math.ceil(ns_val / tck_ns)) if tck_ns > 0 else 0

    def parse_profile(base: int, mtb_ns: float, enabled: bool, dimms_per_ch: int, idx: int):
        try:
            vb = data[base + 0]
            v_dd = decode_voltage(vb)
            tck_mtb = data[base + 1]  # 186/221 stored at base+1
            tAA_mtb = data[base + 2]
            clmap0 = data[base + 3]
            clmap1 = data[base + 4]
            tCWL_mtb = data[base + 5]
            tRP_mtb  = data[base + 6]
            tRCD_mtb = data[base + 7]
            tWR_mtb  = data[base + 8]
            upper    = data[base + 9]
            tRAS_lsb = data[base +10]
            tRC_lsb  = data[base +11]
            tREFI    = u16le(base +12, base +13)
            tRFC     = u16le(base +14, base +15)
            tRTP_mtb = data[base +16]
            tRRD_mtb = data[base +17]
            tFAW_up  = data[base +18]
            tFAW_lsb = data[base +19]
            tWTR_mtb = data[base +20]
            w2r_raw  = data[base +21]
            b2b_raw  = data[base +22]
            cmd_mode = data[base +23]
            asr_raw  = data[base +24]
            vend_raw = data[base +34] if (base + 34) < 256 else 0

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
