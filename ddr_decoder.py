#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""DDR1 SDRAM SPD decoding, including registered modules."""
from legacy_decoder import LegacyDecoder


class DDRDecoder(LegacyDecoder):
    memory_type = 0x07
