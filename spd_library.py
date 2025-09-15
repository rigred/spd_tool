#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# spd_library.py
#
import re
from typing import Dict, List, Tuple, Optional

from sdr_decoder import SDRDecoder
from ddr3_decoder import DDR3Decoder

# JEDEC memory-type byte (SPD[2])
MEM_SDR   = 0x04   # PC SDR SDRAM (legacy 128B SPD)
MEM_DDR1  = 0x07   # (not implemented here)
MEM_DDR3  = 0x0B   # DDR3 (typically 256B SPD)

_TEXT_HEX_RE = re.compile(
    r"""
    (?:0x)?                # optional '0x'
    ([0-9A-Fa-f]{2})       # exactly two hex digits
    """,
    re.VERBOSE,
)

class SPD:
    """Holds and decodes an SPD image (128B legacy or 256B newer)."""
    def __init__(self, data: bytes, path: str = ""):
        if len(data) < 128:
            raise ValueError("SPD data must be at least 128 bytes (128B legacy or 256B).")

        # Normalize to 128 or 256 bytes (favor full 256 when present)
        if len(data) >= 256:
            self.data = data[:256]
        else:
            self.data = data[:128]

        self.path = path
        self.mem_type = self.data[2]
        self.mem_type_name = self._mem_type_label(self.mem_type)

        # Choose decoder. If mem_type looks unknown but the image is 128B,
        # attempt SDR as a heuristic—some very old dumps have byte2==0x00.
        self.decoder = self._get_decoder_with_fallback()
        self.decoded_data = self.decoder.decode()

    def _mem_type_label(self, v: int) -> str:
        return {
            MEM_SDR:  "SDR",
            MEM_DDR1: "DDR",
            MEM_DDR3: "DDR3",
        }.get(v, f"Unknown(0x{v:02X})")

    def _get_decoder_with_fallback(self):
        """Select the proper decoder based on SPD Byte 2, with a safe SDR fallback for 128B dumps."""
        if self.mem_type == MEM_SDR:
            return SDRDecoder(self.data)
        if self.mem_type == MEM_DDR3:
            return DDR3Decoder(self.data)

        # Heuristic fallback: legacy 128B images are almost always SDR/DDR era.
        # Try SDR first; if it explodes, re-raise NotImplemented below.
        if len(self.data) == 128:
            try:
                return SDRDecoder(self.data)
            except Exception:
                pass

        raise NotImplementedError(
            f"Memory type 0x{self.mem_type:02X} not supported yet "
            f"(len={len(self.data)})."
        )

    def get_decoded_data(self) -> Dict:
        return self.decoded_data

    def patch(self, source_spd: 'SPD', args) -> bytes:
        return self.decoder.patch(source_spd.data, args)

def _try_load_text_hex(raw: bytes) -> Optional[bytes]:
    """
    Accepts text with hex tokens and returns bytes if >=128 bytes found.
    Rules:
      - Only exact byte tokens (HH or 0xHH), no single hex nibble.
      - Ignores separators, commas, newlines, comments, etc.
    """
    try:
        txt = raw.decode("utf-8", errors="ignore")
    except Exception:
        return None

    vals: List[int] = []
    for m in _TEXT_HEX_RE.finditer(txt):
        vals.append(int(m.group(1), 16))

    if len(vals) >= 256:
        return bytes(vals[:256])
    if len(vals) >= 128:
        return bytes(vals[:128])
    return None

def load_spd_file(path: str) -> SPD:
    """Loads an SPD file (binary or text-hex) and returns an SPD object."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found at '{path}'")

    # Binary first
    if len(raw) >= 256:
        return SPD(raw[:256], path)
    if 128 <= len(raw) < 256:
        return SPD(raw[:128], path)

    # Text-hex fallback
    parsed = _try_load_text_hex(raw)
    if parsed:
        return SPD(parsed, path)

    raise ValueError(f"{path}: Not a valid SPD image (need ≥128 bytes in binary or text-hex).")

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
