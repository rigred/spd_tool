#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""PC SDR SDRAM SPD decoding, including registered modules."""
from legacy_decoder import LegacyDecoder


class SDRDecoder(LegacyDecoder):
    memory_type = 0x04
