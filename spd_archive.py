# SPDX-License-Identifier: MIT
"""Read-only collection observations for images outside the legacy editor.

This module deliberately offers no repair, timing or programming operations.
DDR4/DDR5 identity fields are observations, not a complete SPD decoder.
"""
import binascii
from datetime import datetime


def archive_integrity(data):
    from spd_integrity import integrity_info
    if len(data)<128:raise ValueError('SPD integrity inspection requires at least 128 bytes')
    if len(data)>=128 and data[2] in (4,7,8,11):return integrity_info(data)
    regions=[]
    if len(data)>=256 and data[2]==12:regions=[(0,126),(128,254)]
    elif len(data)>=512 and data[2]==18:regions=[(0,510)]
    blocks=[]
    for start,end in regions:
        stored=int.from_bytes(data[end:end+2],'little');computed=binascii.crc_hqx(data[start:end],0)
        blocks.append(dict(coverage=f'{start}..{end-1}',stored=stored,computed=computed,
                           status='VALID' if stored==computed else 'INVALID'))
    return dict(status=('VALID' if all(b['status']=='VALID' for b in blocks) else 'INVALID') if blocks else 'UNKNOWN',
                variant='XMODEM' if blocks else 'Unsupported',blocks=blocks,
                scope='DDR4 base and module-specific blocks' if data[2]==12 else 'DDR5 bytes 0..509' if data[2]==18 else 'No established integrity check',
                diagnostic='Checks cover the listed SPD regions only; vendor/XMP regions are not validated. No repair performed.')


def describe_archive(data,reason):
    from ddr3_decoder import DDR3Decoder
    warnings=[('DDR4/DDR5 support is limited to read-only identity and integrity inspection; timing editing and programming are unavailable.' if data[2] in (12,18) else str(reason))]
    memory={4:'SDR',7:'DDR',8:'DDR2',11:'DDR3',12:'DDR4',18:'DDR5'}.get(data[2],f'Unknown(0x{data[2]:02X})')
    manufacturer='Unknown manufacturer';dram='Unknown';part='Unknown model';serial='No serial';date=None;year=None;module_type='Unknown'
    offsets={12:(320,323,325,329,349),18:(512,515,517,521,551)}
    def vendor(offset):
        if data[offset+1]&127 in (0,127):return 'Unknown manufacturer'
        return DDR3Decoder._decode_jep106(None,data[offset],data[offset+1])
    if data[2] in offsets:
        m,d,s,p,end=offsets[data[2]]
        if len(data)>=end:
            manufacturer=vendor(m)
            text=data[p:end].strip(b'\x00\xff ')
            if text and all(32<=c<=126 for c in text):part=text.decode('ascii')
            elif text:warnings.append('Part-number field contains non-ASCII or control bytes')
            if data[s:s+4] not in (bytes(4),b'\xff'*4):serial=data[s:s+4].hex().upper()
            yy,ww=data[d:d+2]
            if all((v&15)<=9 and (v>>4)<=9 for v in (yy,ww)):
                y=2000+(yy>>4)*10+(yy&15);week=(ww>>4)*10+(ww&15)
                try:datetime.fromisocalendar(y,week,1);date=f'{y:04d}-W{week:02d}';year=y
                except ValueError:pass
            if date is None:warnings.append('Manufacturing date is absent or invalid')
        else:warnings.append('Manufacturing identity block is missing')
        if data[2]==12:
            module_type={1:'RDIMM',2:'UDIMM',3:'SO-DIMM',4:'LRDIMM',5:'Mini-RDIMM',6:'Mini-UDIMM',8:'72b SO-RDIMM',9:'72b SO-UDIMM',12:'16b SO-DIMM',13:'32b SO-DIMM'}.get(data[3]&15,f'Unknown (0x{data[3]&15:02X})')
            if len(data)>=352:dram=vendor(350)
        else:module_type=f'Module type code 0x{data[3]&15:02X}'
    integrity=archive_integrity(data)
    if integrity['status']=='INVALID':warnings.append('SPD CRC/checksum mismatch; imported bytes have been preserved')
    return dict(metadata_version=4,memory=memory,manufacturer=manufacturer,dram_manufacturer=dram,
                part=part,serial=serial,manufacture_date=date,manufacture_year=year,module_type=module_type,
                capacity_mib=None,data_rate_MTps=None,ranks=None,ecc='Unknown',hpt_present=False,hpt_code=None,
                integrity=integrity['status'],integrity_details=integrity,length=len(data),vendor_data={},
                editable=False,support='Read-only archive',warnings=warnings)
