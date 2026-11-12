# SPDX-License-Identifier: MIT
"""Offline SPD carving from firmware images and already unpacked UEFI trees.

The default artifact is a 128-byte base block, never an invented EEPROM image.
Header filters reduce false positives; integrity never proves runtime selection.
"""
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from spd_integrity import integrity_info


TYPES = {4: 'SDR', 7: 'DDR', 8: 'DDR2', 11: 'DDR3', 12: 'DDR4',
         15: 'LPDDR3', 16: 'LPDDR4', 17: 'LPDDR4X', 0xF1: 'LPDDR3-Intel'}
TYPE_BYTES = re.compile(b'[\x04\x07\x08\x0b\x0c\x0f\x10\x11\xf1]')
MAX_FILES = 20000
MAX_CANDIDATES = 10000


def _plausible(d):
    """Conservative supported-layout filters, not a complete JEDEC validator."""
    t = d[2]
    if t in (4, 7, 8):
        return (64 <= d[0] <= 255 and 7 <= d[1] <= 12
                and 9 <= (d[3] & 15) <= 15 and 7 <= (d[4] & 15) <= 13
                and d[6] in (8, 16, 32, 64, 72, 80, 128, 144)
                and d[7] == 0 and d[13] in (4, 8, 16, 32)
                and d[17] in (2, 4, 8, 16) and d[9] not in (0, 255)
                and d[18] != 0)
    if not (d[1] >> 4 in (1, 2) and d[5] & 0xC0 == 0
            and d[5] & 7 <= 4 and (d[5] >> 3) & 7 <= 6):
        return False
    if t in (11, 0xF1):
        return (d[0] & 0x70 == 0x10 and 1 <= d[0] & 15 <= 3
                and d[3] & 15 in range(1, 15) and d[4] & 15 <= 6
                and d[7] & 0xC0 == 0 and d[7] & 7 <= 3
                and d[8] & 0xE0 == 0 and d[8] & 7 <= 3
                and d[12] not in (0, 255)
                and (d[14] or d[15]) and d[16] != 0 and d[18] != 0)
    # DDR4 and JEDEC low-power layouts share base header / timing locations.
    low_power = t in (15, 16, 17)
    return (d[0] & 0x80 == 0 and (d[0] >> 4) in (1, 2)
            and 1 <= d[0] & 15 <= 4
            and d[3] & 15 in ((7, 14) if low_power else range(1, 14))
            and d[4] & 15 <= 11 and d[12] & 0x80 == 0 and d[12] & 7 <= 3
            and d[13] & 7 <= 3 and d[17] == 0
            and d[18] not in (0, 255) and any(d[20:24])
            and d[24] != 0 and d[26] != 0)


def _check(d):
    t = d[2]
    if t in (4, 7, 8, 11):
        return integrity_info(d)
    if t == 0xF1:
        # Intel's vendor-defined type is not a JEDEC DDR3 memory-type value.
        # Do not confer JEDEC validity by reinterpreting the block as DDR3.
        return dict(status='UNVERIFIED', variant='vendor-defined', coverage=None,
                    stored=None, computed=None)
    computed = binascii.crc_hqx(d[:126], 0)
    stored = int.from_bytes(d[126:128], 'little')
    return dict(status='VALID' if computed == stored else 'INVALID',
                variant='XMODEM', coverage='0..125', stored=stored, computed=computed)


def scan_blob(data, include_invalid=False, length=128):
    """Return candidate dictionaries with exact bytes at arbitrary byte offsets.

    Extended extraction is explicit context carving: bytes beyond 127 have no
    inferred ownership. Missing context is reported, never padded.
    """
    if length not in (128, 256, 512):
        raise ValueError('Extraction length must be 128, 256 or 512')
    candidates = []
    for match in TYPE_BYTES.finditer(data):
        offset = match.start() - 2
        if offset < 0 or offset + 128 > len(data):
            continue
        base = data[offset:offset + 128]
        if not _plausible(base):
            continue
        check = _check(base)
        if check['status'] != 'VALID' and not include_invalid:
            continue
        available = len(data) - offset
        extracted_length = length if available >= length else 128
        raw = bytes(data[offset:offset + extracted_length])
        warnings = ['A candidate does not identify the installed or selected RAM profile.',
                    'Integrity covers only the stated range, not the entire extracted artifact.']
        if extracted_length > 128:
            warnings.append('Bytes after 127 are adjacent context; the firmware table boundary is unverified.')
        if available < length:
            warnings.append(f'Requested {length} bytes unavailable; only the 128-byte base block was extracted.')
        if check['status'] != 'VALID':
            warnings.append('Heuristic candidate only; integrity is missing, invalid or vendor-defined.')
        if base[2] not in (4, 7, 8, 11):
            warnings.append('Extraction only: this memory type is not supported by the core decoder/editor.')
        candidates.append(dict(offset=offset, offset_hex=f'0x{offset:X}',
                               memory_type=TYPES[base[2]], memory_type_code=base[2],
                               confidence='integrity-checked' if check['status'] == 'VALID' else 'heuristic',
                               integrity=check, length=extracted_length,
                               base_sha256=hashlib.sha256(base).hexdigest(),
                               sha256=hashlib.sha256(raw).hexdigest(), warnings=warnings, data=raw))
        if len(candidates) > MAX_CANDIDATES:
            raise ValueError(f'Candidate limit ({MAX_CANDIDATES}) exceeded')
    return candidates


def _input_files(source):
    if source.is_symlink():
        raise ValueError('Input must not be a symbolic link')
    if source.is_file():
        return [source]
    if not source.is_dir():
        raise ValueError('Input must be a regular firmware file or extracted directory')
    result = []
    def walk_error(error):
        raise error
    for directory, dirs, files in os.walk(source, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            if not path.is_symlink() and path.is_file():
                result.append(path)
                if len(result) > MAX_FILES:
                    raise ValueError(f'Input file limit ({MAX_FILES}) exceeded')
    return result


def scan_firmware(source, out=None, include_invalid=False, length=128,
                  max_file_mib=128, max_total_mib=1024):
    """Scan regular files only, with bounded reads and no firmware/hardware writes.

    A new output directory is required to prevent overwriting existing data.
    Identical base blocks share a profile ID, while all occurrences are retained.
    """
    if max_file_mib <= 0 or max_total_mib <= 0:
        raise ValueError('Size limits must be positive')
    if length not in (128, 256, 512):
        raise ValueError('Extraction length must be 128, 256 or 512')
    source = Path(source).absolute()
    destination = Path(out).absolute() if out is not None else None
    if destination is not None and (destination.exists() or destination.is_symlink()):
        raise ValueError('Output directory already exists; choose a new directory')
    paths = _input_files(source)
    report = dict(schema_version=1, input=str(source), extraction_length=length,
                  include_invalid=include_invalid, files=[], candidates=[],
                  errors=[], bytes_scanned=0, unique_base_profiles=0,
                  notes=['Offsets refer to the named input file, not physical flash addresses.',
                         'Compressed/encrypted firmware and constructed timing tables may need external unpacking or analysis.',
                         'No candidates does not establish that the firmware lacks memory-down configuration.'])
    payloads = []
    profiles = {}
    for path in paths:
        name = str(path.relative_to(source)) if source.is_dir() else path.name
        try:
            # O_NONBLOCK prevents a replaced FIFO from hanging acquisition.
            flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
            fd = os.open(path, flags)
            with os.fdopen(fd, 'rb') as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('Not a regular file')
                limit = min(max_file_mib * 1024**2,
                            max_total_mib * 1024**2 - report['bytes_scanned'])
                if info.st_size > limit:
                    raise ValueError('File exceeds the per-file or remaining total scan size limit')
                data = handle.read(limit + 1)
                if len(data) > limit:
                    raise ValueError('File grew beyond the scan size limit')
            report['bytes_scanned'] += len(data)
            hits = scan_blob(data, include_invalid, length)
            if len(report['candidates']) + len(hits) > MAX_CANDIDATES:
                raise ValueError(f'Total candidate limit ({MAX_CANDIDATES}) exceeded')
            report['files'].append(dict(path=name, size=len(data), sha256=hashlib.sha256(data).hexdigest(), candidates=len(hits)))
            for hit in hits:
                payload = hit.pop('data')
                hit['source'] = name
                hit['profile_id'] = profiles.setdefault(hit['base_sha256'], f'profile-{len(profiles) + 1:04d}')
                index = len(report['candidates']) + 1
                filename = f'{index:04d}-{hit["memory_type"]}-{hit["offset_hex"]}-{hit["sha256"][:12]}.bin'
                hit['output'] = filename if destination is not None else None
                report['candidates'].append(hit)
                payloads.append((filename, payload))
        except (OSError, ValueError) as exc:
            report['errors'].append(dict(path=name, error=str(exc)))
    report['unique_base_profiles'] = len(profiles)
    if destination is not None:
        destination.mkdir(parents=True, exist_ok=False)
        for name, payload in payloads:
            with (destination / name).open('xb') as handle:
                handle.write(payload)
        with (destination / 'report.json').open('x', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2)
            handle.write('\n')
    return report


def cmd_scan(args):
    report = scan_firmware(args.input, args.out, args.include_invalid, args.length,
                           args.max_file_mib, args.max_total_mib)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for hit in report['candidates']:
            print(f'{hit["source"]} @ {hit["offset_hex"]}: {hit["memory_type"]}, '
                  f'{hit["integrity"]["status"]}, {hit["length"]} bytes, {hit["profile_id"]}')
        print(f'{len(report["candidates"])} candidates / {report["unique_base_profiles"]} unique base profiles; '
              f'{report["bytes_scanned"]} bytes scanned.')
        if not report['candidates']:
            print('No matching candidates. Try unpacked UEFI sections and, if needed, --include-invalid.')
        if args.out:
            print(f'Extraction and report: {args.out}')
        for error in report['errors']:
            print(f'Error: {error["path"]}: {error["error"]}')
    if report['errors']:
        raise SystemExit(1)


def add_parser(subparsers):
    parser = subparsers.add_parser('firmware', help='Find and extract embedded SPD data from firmware files.')
    commands = parser.add_subparsers(dest='firmware_command', required=True)
    scan = commands.add_parser('scan', help='Scan a BIOS image or unpacked UEFI directory offline.')
    scan.add_argument('--input', required=True, help='Firmware image or recursively scanned directory.')
    scan.add_argument('--out', help='New extraction directory, including report.json; omit for scan only.')
    scan.add_argument('--include-invalid', action='store_true', help='Also include heuristic candidates without valid integrity.')
    scan.add_argument('--length', type=int, choices=(128, 256, 512), default=128,
                      help='Bytes per candidate; extended bytes are unverified adjacent context (default: 128).')
    scan.add_argument('--max-file-mib', type=int, default=128)
    scan.add_argument('--max-total-mib', type=int, default=1024)
    scan.add_argument('--json', action='store_true', help='Print the full report as JSON.')
    scan.set_defaults(func=cmd_scan)
