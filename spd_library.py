#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# spd_library.py
#
# Core library for the SPD tool. Contains the main SPD factory class
# and file loading utilities.
#
import re
from typing import Dict, List, Tuple
from ddr3_decoder import DDR3Decoder # Import the specific decoder

class SPD:
    """A generic class to hold and decode SPD data."""
    def __init__(self, data: bytes, path: str = ""):
        if len(data) < 256:
            raise ValueError("SPD data must be at least 256 bytes.")
        self.data = data
        self.path = path
        self.mem_type = self.data[2]
        self.decoder = self._get_decoder()
        self.decoded_data = self.decoder.decode()

    def _get_decoder(self):
        """Factory to select the correct decoder based on memory type."""
        if self.mem_type == 0x0B: # DDR3
            return DDR3Decoder(self.data)
        # Future: Add logic for DDR4 (0x0C), DDR5 (0x12), etc.
        # elif self.mem_type == 0x0C:
        #     return DDR4Decoder(self.data)
        else:
            raise NotImplementedError(f"Memory type 0x{self.mem_type:02X} is not supported.")

    def get_decoded_data(self) -> Dict:
        return self.decoded_data

    def patch(self, source_spd: 'SPD', args) -> bytes:
        """Applies patches from a source SPD to this SPD's data."""
        return self.decoder.patch(source_spd.data, args)

def load_spd_file(path: str) -> SPD:
    """Loads an SPD file and returns an SPD object."""
    HEX_TOKEN_RE = re.compile(r"0x([0-9A-Fa-f]{1,2})")
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found at '{path}'")

    if len(raw) >= 256:
        return SPD(raw[:256], path)

    try:
        txt = raw.decode("utf-8", errors="ignore")
        toks = HEX_TOKEN_RE.findall(txt)
        if toks:
            data = bytes(int(h, 16) for h in toks)
            if len(data) >= 256:
                return SPD(data[:256], path)
    except Exception:
        pass

    raise ValueError(f"{path}: Not a valid 256-byte binary or text-hex SPD file.")

def hexdiff(a: bytes, b: bytes) -> List[Tuple[int, int, int]]:
    """Compares two byte strings and returns a list of differences."""
    return [(i, x, y) for i, (x, y) in enumerate(zip(a, b)) if x != y]
