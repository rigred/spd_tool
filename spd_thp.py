# SPDX-License-Identifier: MIT
"""Observed Thaiphoon containers. Transforms only; never repair SPD bytes.

See docs/THP_IMPORT.md for layouts, evidence and limits. Constants describe
the on-disk format; no proprietary runtime or third-party code is used.
"""

LAYOUTS={'TH20':256,'TH40':512,'TH41':512,'TH42':512,'TH43':512,
         'TH50':1024,'TH53':1024}
MASK41=b'0A30CD6F8C7890C5DAB95F68F18A6AF7420CD3D630A4C439AB98FAD1C83C6F7A568AB26CD39D1AF1D2'
MASK42=b'5531A7648C7390C1D8A91F34F5656A77440F93F610A57F38A442FBD8C03C328B7D8E715C317A3A'


def decode_thp(raw):
    version=raw[1:5].decode('ascii',errors='replace')
    if raw[:3]!=b'\x04TH' or version not in LAYOUTS:
        raise ValueError('Unsupported THP version '+repr(raw[:5])+'; supported: '+', '.join(LAYOUTS))
    length=LAYOUTS[version]
    if len(raw)!=length+6:
        raise ValueError(f'{version} requires exactly {length+6} bytes (5-byte header, {length}-byte payload, 1-byte trailer)')
    payload=raw[5:-1]
    if version in ('TH20','TH40'):
        data=bytes(value^(i&255) for i,value in enumerate(payload))
        transform='spd[i] = payload[i] XOR (i & 255)'
    elif version in ('TH41','TH42','TH50'):
        mask=MASK42 if version=='TH42' else MASK41
        data=bytes(value^(mask[i%len(mask)] if i else 0) for i,value in enumerate(payload))
        transform=f'Byte 0 unchanged; spd[i] = payload[i] XOR MASK{42 if version=="TH42" else 41}[i % {len(mask)}] for i >= 1'
    else:
        state=471;decoded=bytearray()
        for value in payload:
            decoded.append(value^(state>>8))
            # Feedback uses the original ciphertext byte, not the decoded byte.
            state=(state+value+12719)&65535
        data=bytes(decoded)
        transform='state=471; spd[i]=payload[i] XOR (state >> 8); state=(state+payload[i]+12719) & 65535'
    return data,dict(header_hex=raw[:5].hex(),trailer_hex=raw[-1:].hex(),
                     transform=transform,container_integrity='No independently verified THP container checksum')
