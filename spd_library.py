#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# spd_library.py
#
import re
from typing import Dict, List, Tuple, Optional

from sdr_decoder import SDRDecoder
from ddr_decoder import DDRDecoder
from ddr2_decoder import DDR2Decoder
from ddr3_decoder import DDR3Decoder

# JEDEC memory-type byte (SPD[2])
MEM_SDR   = 0x04   # PC SDR SDRAM (legacy 128B SPD)
MEM_DDR1  = 0x07
MEM_DDR2  = 0x08
MEM_DDR3  = 0x0B   # DDR3 (typically 256B SPD)

class SPD:
    """Holds and decodes an SPD image (128B legacy or 256B newer)."""
    def __init__(self, data: bytes, path: str = ""):
        if len(data) < 128:
            raise ValueError("SPD data must be at least 128 bytes (128B legacy or 256B).")

        if len(data) > 256:
            raise ValueError("Images larger than 256 bytes are unsupported; extract one SPD first.")
        self.data = bytes(data)

        self.path = path
        self.mem_type = self.data[2]
        self.mem_type_name = self._mem_type_label(self.mem_type)

        self.decoder = self._get_decoder()
        self.decoded_data = self.decoder.decode()
        if self.mem_type==MEM_DDR2:
            from spd_epp import decode_epp
            self.decoded_data["epp"]=decode_epp(self.data)

    def _mem_type_label(self, v: int) -> str:
        return {
            MEM_SDR:  "SDR",
            MEM_DDR1: "DDR",
            MEM_DDR3: "DDR3",
            MEM_DDR2: "DDR2",
        }.get(v, f"Unknown(0x{v:02X})")

    def _get_decoder(self):
        """Select a decoder strictly by the memory-type byte."""
        if self.mem_type == MEM_SDR:
            return SDRDecoder(self.data)
        if self.mem_type == MEM_DDR1:
            return DDRDecoder(self.data)
        if self.mem_type == MEM_DDR2:
            return DDR2Decoder(self.data)
        if self.mem_type == MEM_DDR3:
            return DDR3Decoder(self.data)

        raise NotImplementedError(
            f"Memory type 0x{self.mem_type:02X} not supported yet "
            f"(len={len(self.data)})."
        )

    def get_decoded_data(self) -> Dict:
        return self.decoded_data

    def patch(self, source_spd: 'SPD', args) -> bytes:
        if self.mem_type not in (MEM_SDR, MEM_DDR1, MEM_DDR2, MEM_DDR3):
            raise ValueError('Patching requires SDR, DDR, DDR2 or DDR3')
        return self.decoder.patch(source_spd.data, args)

def _try_load_text_hex(raw: bytes) -> Optional[bytes]:
    """Parse strict byte tokens, optional offset prefixes and #/; comments.

    Reject all other text rather than extracting accidental hex from words.
    """
    try:
        txt = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    vals = []
    expected_offset = 0
    for line in txt.splitlines():
        line = re.split(r"[#;]", line, maxsplit=1)[0].strip()
        if not line:
            continue
        prefix = re.match(r"^(?:0x)?([0-9a-fA-F]{2,8}):\s*", line)
        if prefix:
            if int(prefix[1], 16) != expected_offset:
                return None
            line = line[prefix.end():]
        for token in re.split(r"[\s,]+", line):
            if not token:
                continue
            if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{2}", token):
                return None
            vals.append(int(token, 16))
            expected_offset += 1
    return bytes(vals) if 128 <= len(vals) <= 256 else None


def load_spd_file(path: str) -> SPD:
    """Read a binary image or strict hex-text dump without truncation."""
    with open(path, "rb") as f:
        raw = f.read()
    parsed = _try_load_text_hex(raw)
    if parsed is not None:
        return SPD(parsed, path)
    if raw and all(b in b"\t\r\n" or 32 <= b <= 126 for b in raw):
        raise ValueError(f"{path}: Invalid hex-text SPD dump")
    return SPD(raw, path)


def hexdiff(a: bytes, b: bytes) -> List[Tuple[int, Optional[int], Optional[int]]]:
    """
    Compare two byte strings and return a list of (offset, a_byte, b_byte) for all differing positions.
    Unlike zip-based diffs, this also reports tail differences when lengths differ.
    """
    diffs: List[Tuple[int, Optional[int], Optional[int]]] = []
    la, lb = len(a), len(b)
    L = max(la, lb)
    for i in range(L):
        av = a[i] if i < la else None
        bv = b[i] if i < lb else None
        if av != bv:
            diffs.append((i, av, bv))
    return diffs
