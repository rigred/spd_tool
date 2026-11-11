# SPDX-License-Identifier: MIT
"""JEDEC integrity checks shared by decoders, editor and hardware tools."""
import binascii


def integrity_info(data):
    if len(data) < 128:
        raise ValueError('SPD base block requires 128 bytes')
    if data[2] in (0x04, 0x07, 0x08):
        stored, computed = data[63], sum(data[:63]) & 255
        end, variant = 62, 'SUM8'
    elif data[2] == 0x0B:
        end = 116 if data[0] & 0x80 else 125
        stored = int.from_bytes(data[126:128], 'little')
        computed = binascii.crc_hqx(data[:end + 1], 0)
        variant = 'XMODEM'
    else:
        raise ValueError(f'Integrity repair unsupported for memory type 0x{data[2]:02X}')
    result = dict(stored=stored, computed=computed, coverage=f'0..{end}',
                  variant=variant, status='VALID' if stored == computed else 'INVALID',
                  coverage_match=True)
    if data[2] == 0x0B and stored != computed:
        alternate = 125 if end == 116 else 116
        if stored == binascii.crc_hqx(data[:alternate + 1], 0):
            result['diagnostic'] = f'CRC matches undeclared coverage 0..{alternate}'
            result['coverage_match'] = False
    return result


def repair_integrity(data):
    result = bytearray(data)
    info = integrity_info(result)
    if result[2] == 0x0B:
        result[126:128] = info['computed'].to_bytes(2, 'little')
    else:
        result[63] = info['computed']
    return bytes(result)


def patch_image(target, source, args):
    """Copy inclusive byte ranges without resizing or changing memory generation."""
    if target[2] != source[2]:
        raise ValueError('Cannot patch between different memory generations')
    ddr3 = target[2] == 0x0B
    if target[2] not in (0x04, 0x07, 0x08, 0x0B):
        raise ValueError('Patching requires SDR, DDR, DDR2 or DDR3')
    type_offset = 3 if ddr3 else 20 if target[2] == 8 else 21
    if target[type_offset] != source[type_offset] and not getattr(args, 'force', False):
        raise ValueError('Module types differ; use --force after reviewing compatibility')
    ranges = []
    if getattr(args, 'copy_vendor', False):
        ranges.append((176, 256) if ddr3 else (99, min(len(target), len(source))))
    if getattr(args, 'copy_mfgid', False):
        ranges.append((117, 119) if ddr3 else (64, 72))
    if getattr(args, 'copy_partnum', False):
        ranges.append((128, 146) if ddr3 else (73, 91))
    hpt = getattr(args, 'set_hpt', None)
    copy_hpt = getattr(args, 'copy_hpt', False)
    if hpt is not None or copy_hpt:
        if not ddr3:
            raise ValueError('HP HPT patches require DDR3')
        if len(target) < 184:
            raise ValueError('HPT block missing from truncated target')
        if not getattr(args, 'force', False) and (target[117] & 127, target[118] & 127) != (0, 0x54):
            raise ValueError('Target is not HP; use --force to apply HPT')
        if copy_hpt:
            ranges.append((176, 184))
        if hpt is not None and len(hpt) != 4:
            raise ValueError('HPT code must be exactly 4 bytes')
    for item in getattr(args, 'copy_range', None) or []:
        try:
            start, end = (int(x, 0) for x in item.split(':'))
        except ValueError as exc:
            raise ValueError(f'Invalid range: {item}') from exc
        ranges.append((start, end + 1))
    if not ranges and hpt is None:
        raise ValueError('Nothing selected to patch')
    result = bytearray(target)
    for start, stop in ranges:
        if not 0 <= start < stop <= min(len(target), len(source)):
            raise ValueError(f'Range {start}:{stop - 1} exceeds source or target')
        result[start:stop] = source[start:stop]
    if hpt is not None:
        result[176:184] = b'HPT\0' + hpt
    if result[2] != target[2]:
        raise ValueError('A patch cannot change the memory type')
    return repair_integrity(result)
