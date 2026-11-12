# SPDX-License-Identifier: MIT
"""Typed SPD bitfields. Encoders preserve every bit outside the selected field.

Layout references and revision scope are documented in REGISTERED_MODULES.md.
Values passed to set_field are the displayed engineering values, not bit masks.
"""
from dataclasses import dataclass
from fractions import Fraction


@dataclass(frozen=True)
class Field:
    key: str
    group: str
    label: str
    offset: int
    shift: int = 0
    bits: int = 8
    choices: object = None
    unit: str = ''
    scale: object = 1
    note: str = ''
    expert: bool = False

    @property
    def maximum(self):
        return (1 << self.bits) - 1

    def raw(self, data):
        return (data[self.offset] >> self.shift) & self.maximum

    def value(self, data):
        return float(Fraction(self.raw(data)) * Fraction(str(self.scale))) if self.scale != 1 else self.raw(data)

    def display(self, data):
        raw = self.raw(data)
        if self.choices is not None:
            return self.choices.get(raw, f'Reserved ({raw})')
        return f'{self.value(data):g} {self.unit}'.strip()

    def encode(self, data, value):
        if self.offset >= len(data):
            raise ValueError('Field is absent from this image')
        try:
            if isinstance(value, str) and value.lower().startswith('0x'):
                number = Fraction(int(value, 16))
            else:
                number = Fraction(str(value)) / Fraction(str(self.scale))
        except (ValueError, ZeroDivisionError) as exc:
            raise ValueError('Enter a numeric value or hexadecimal integer') from exc
        if number.denominator != 1 or not 0 <= number <= self.maximum:
            raise ValueError(f'Value must fit {self.bits} bits in steps of {self.scale} {self.unit}')
        raw = int(number)
        if self.choices is not None and raw not in self.choices:
            raise ValueError('Reserved encoding; use the byte editor for deliberate raw changes')
        result = bytearray(data)
        mask = self.maximum << self.shift
        result[self.offset] = (result[self.offset] & ~mask) | (raw << self.shift)
        return bytes(result)


BOOL = {0: 'No', 1: 'Yes'}
DRIVE = {0: 'Light', 1: 'Moderate', 2: 'Strong'}
DRIVE4 = DRIVE | {3: 'Very strong'}
ROWS = {0: 'Undefined', 1: '1 row', 2: '2 rows', 3: '4 rows'}
PERSONALITY = [(14,0),(14,1),(14,2),(14,3),(14,4),(14,5),(14,6),(15,6),
               (14,8),(14,9),(14,10),(14,11),(14,12),(14,13),(14,14),(14,15),
               (15,0),(15,1),(15,2),(15,3),(15,4),(15,5),(15,8),(15,9),
               (15,10),(15,11),(15,12),(15,13),(15,14),(15,15)]


def module_fields(data):
    """Return only fields valid for this memory generation and module family."""
    fields = []
    def add(key, group, label, offset, shift=0, bits=8, **kw):
        if offset < len(data):
            fields.append(Field(key, group, label, offset, shift, bits, **kw))
    mem = data[2]
    if mem in (4, 7):
        group = 'Legacy organization'
        add('ranks', group, 'Module ranks / rows', 5, choices={i:str(i) for i in range(1,9)})
        for offset, label in ((3,'Row'), (4,'Column')):
            for shift, rank in ((0,'first'), (4,'second')):
                add(f'{label.lower()}_{rank}', group, f'{label} address bits, {rank} rank', offset, shift, 4,
                    note='Second-rank zero means same as first. Codes 1-3 represent 16-18 address bits.')
        add('voltage', group, 'Interface voltage', 8, choices={0:'TTL 5 V',1:'LVTTL 3.3 V',2:'HSTL 1.5 V',3:'SSTL 3.3 V',4:'SSTL 2.5 V'})
        add('configuration', group, 'Error checking', 11, 0, 2, choices={0:'None',1:'Parity',2:'ECC'})
        add('device_width', group, 'Primary SDRAM width', 13, 0, 7, choices={i:f'x{i}' for i in (4,8,16,32)})
        add('device_banks', group, 'Banks per SDRAM', 17, choices={i:str(i) for i in (2,4,8)})
        for bit, (key,label) in enumerate((('buffered_address','Buffered address/control'),('registered_address','Registered address/control'),
                    ('pll','On-module PLL'),('buffered_dqmb','Buffered DQMB'),('registered_dqmb','Registered DQMB'),
                    ('differential_clock','Differential clock'),('redundant_address','Redundant row addressing'))):
            add(key, 'Legacy register / buffer', label, 21, bit, 1, choices=BOOL,
                note='Describes physical module wiring; editing SPD does not change the hardware.')
        for bit in range(7):
            cl = bit+1 if mem == 4 else 1+bit/2
            add(f'cas_{cl:g}', 'Legacy capabilities', f'CAS {cl:g} supported', 18, bit, 1, choices=BOOL)
        for bit, label in enumerate(('Early RAS precharge','Auto precharge','Precharge all','Write-one/read burst','Vcc lower tolerance 5%','Vcc upper tolerance 5%')):
            add(f'feature_{bit}', 'Legacy capabilities', label, 22, bit, 1, choices=BOOL)
        add('self_refresh', 'Legacy capabilities', 'Self refresh', 12, 7, 1, choices=BOOL)
        add('refresh', 'Legacy capabilities', 'Refresh interval', 12, 0, 7,
            choices={0:'15.625 us',1:'3.9 us',2:'7.8 us',3:'31.3 us',4:'62.5 us',5:'125 us'})
        for key, off in (('tRP',27),('tRRD',28),('tRCD',29),('tRAS',30)):
            add(key, 'Legacy timings', key, off, unit='ns', scale=.25 if mem==7 and off !=30 else 1)
        if mem == 7:
            for key, off in (('tRC',41),('tRFC',42)):
                add(key, 'Legacy timings', key, off, unit='ns')
            add('tCKmax','Legacy timings','Maximum clock period',43,unit='ns',scale=.25,
                note='0xFF means no minimum frequency; use raw editor to set this sentinel.')
        return fields
    if mem != 11:
        return fields
    family = data[3] & 15
    rdimm, lrdimm = family in (1,5,9), family==11
    if not (rdimm or lrdimm):
        return fields
    group = 'Module / buffer identity'
    add('height_code','Module mechanics','Height upper-bound code',60,0,5,
        choices={i:f'<= {15+i} mm' for i in range(32)})
    add('thickness_front','Module mechanics','Front maximum thickness',61,0,4,
        choices={i:f'<= {1+i} mm' for i in range(16)})
    add('thickness_back','Module mechanics','Back maximum thickness',61,4,4,
        choices={i:f'<= {1+i} mm' for i in range(16)})
    add('raw_card_code','Module mechanics','Reference raw card code',62,0,5)
    add('raw_card_bank','Module mechanics','Reference raw card extended bank',62,7,1,choices=BOOL)
    add('raw_card_revision','Module mechanics','Reference raw card revision code',62,5,2)
    add('raw_card_extension','Module mechanics','Extended raw card revision',60,5,3)
    add('rank_count_code','Module organization','Rank count',7,3,3,choices={i:str(i+1) for i in range(8)})
    add('device_width_code','Module organization','SDRAM device width',7,0,3,choices={0:'x4',1:'x8',2:'x16',3:'x32'})
    add('primary_width_code','Module organization','Primary bus width',8,0,3,choices={0:'8 bits',1:'16 bits',2:'32 bits',3:'64 bits'})
    add('ecc_width_code','Module organization','Bus width extension',8,3,2,choices={0:'None',1:'8 bits'})
    add('density_code','Module organization','DRAM density',4,0,4,choices={i:f'{256*(1<<i)} Mbit' for i in range(7)})
    add('dram_rows',group,'DRAM package rows',63,2,2,choices=ROWS if rdimm else {0:'Undefined',1:'1 row',2:'2 rows'})
    if rdimm:
        add('register_count',group,'Number of register devices',63,0,2,choices={0:'Undefined',1:'1',2:'2',3:'4'})
        add('heat_spreader',group,'Heat spreader present',64,7,1,choices=BOOL)
        add('register_type',group,'Register device type',68,0,3,choices={0:'SSTE32882'})
    else:
        add('mirroring',group,'Rank address mirroring',63,0,2,choices={0:'None',1:'Odd ranks'})
        add('orientation',group,'Buffer orientation',63,4,1,choices={0:'Vertical',1:'Horizontal'})
        add('even_ranks',group,'Even rank numbering only',63,5,1,choices=BOOL)
        add('heat_spreader',group,'Heat spreader present',63,7,1,choices=BOOL)
    add('device_revision',group,'Register / buffer revision',67 if rdimm else 64,
        note='Hex revision; 0xFF means unspecified.')
    add('device_mfg_bank',group,'Register / buffer JEP106 bank',65,0,7,
        note='Continuation count; odd parity is updated automatically.')
    add('device_mfg_code',group,'Register / buffer JEP106 code',66,0,7,
        note='Parity-stripped code; odd parity is updated automatically.')
    if lrdimm and data[1] < 0x10:
        # Early development images used different personality placement.
        return fields
    if rdimm and data[68] & 7:
        for offset in range(69,77):
            for shift,half in ((0,'low'),(4,'high')):
                add(f'raw{offset}_{half}','Unknown register layout',f'Byte {offset} {half} nibble',offset,shift,4,expert=True,
                    note='Register type is not SSTE32882; no standard register semantics are assumed.')
        return fields
    if rdimm:
        # Byte 70 RC3; byte 71 RC4/RC5. Other nibbles are exposed as expert registers.
        for key, label, off, shift, choices in (
            ('ca_a','CA A drive',70,4,DRIVE),('ca_b','CA B drive',70,6,DRIVE),
            ('control_a','Control A drive',71,0,{0:'Light',1:'Moderate'}),
            ('control_b','Control B drive',71,2,{0:'Light',1:'Moderate'}),
            ('clock_13','Clock Y1/Y3 drive',71,4,DRIVE),('clock_02','Clock Y0/Y2 drive',71,6,DRIVE)):
            add(key,'RDIMM drive strengths',label,off,shift,2,choices=choices)
        # Device semantics from JESD82-29A.01. These words are mostly RESERVED
        # in the SPD annex and may be supplied/replaced by firmware at boot.
        runtime_note='SSTE32882 runtime meaning (JESD82-29A.01). This SPD word is reserved in Annex K; firmware commonly supplies its own value. Vendor/revision support must be checked.'
        for key,label,off,shift,choices in (
            ('rc0_inversion','RC0 output inversion',69,0,{0:'Enabled',1:'Disabled'}),
            ('rc0_float','RC0 output floating',69,1,BOOL),
            ('rc0_disable_a','RC0 A outputs disabled',69,2,BOOL),
            ('rc0_disable_b','RC0 B outputs disabled',69,3,BOOL),
            ('rc2_prelaunch','RC2 CA prelaunch',70,0,{0:'1/2 clock',1:'3/4 clock (optional)'}),
            ('rc2_3t','RC2 3T output timing',70,1,BOOL),
            ('rc2_ibt','RC2 input termination',70,2,{0:'100 ohm',1:'150 ohm'}),
            ('rc2_test','RC2 test frequency band',70,3,BOOL),
            ('rc8_mirror_ibt','RC8 IBT active when MIRROR high',73,3,BOOL),
            ('rc9_weak','RC9 weak drive',73,4,BOOL),
            ('rc9_pd_ibt_off','RC9 power-down IBT off / ODT low',73,6,BOOL),
            ('rc9_pd_enable','RC9 CKE power-down enabled',73,7,BOOL),
            ('rc11_internal_vref','RC11 internal VrefCA',74,6,BOOL)):
            add(key,'RDIMM runtime register semantics',label,off,shift,1,choices=choices,expert=True,note=runtime_note)
        for clock in range(4):
            add(f'rc1_disable_y{clock}','RDIMM runtime register semantics',f'RC1 Y{clock} clock disabled',69,4+clock,1,
                choices=BOOL,expert=True,note=runtime_note)
        add('rc8_ibt','RDIMM runtime register semantics','RC8 input termination override',73,0,3,
            choices={0:'Use RC2',2:'200 ohm',4:'300 ohm',7:'Off'},expert=True,note=runtime_note)
        add('rc10_speed','RDIMM runtime register semantics','RC10 operating speed code',74,0,3,
            choices={0:'800 MT/s',1:'1066 MT/s',2:'1333 MT/s',3:'1600 MT/s',4:'1866 MT/s'},expert=True,note=runtime_note)
        add('rc11_voltage','RDIMM runtime register semantics','RC11 operating VDD',74,4,2,
            choices={0:'1.5 V',1:'1.35 V',2:'1.25 V'},expert=True,note=runtime_note)
        for rc in range(16):
            add(f'RC{rc}','RDIMM control words',f'RC{rc}',69+rc//2,4*(rc%2),4,expert=True,
                note='SPD nibble copied to register. Most RC words are reserved in SPD; firmware may override them. Consult the register datasheet.')
        return fields
    # Global LRDIMM controls.
    add('prelaunch','LRDIMM timing','CA prelaunch uses F1RC12',67,0,1,choices=BOOL)
    add('rank_swap','LRDIMM timing','Swap ranks 1 and 5',67,1,1,choices=BOOL)
    for key,label,off,shift,choices in (
        ('ca','CA drive',67,4,DRIVE4),('cs','CS drive',67,6,DRIVE),
        ('odt','ODT drive',68,0,DRIVE),('cke','CKE drive',68,2,DRIVE),
        ('clock13','Clock Y1/Y3 drive',68,4,DRIVE),('clock02','Clock Y0/Y2 drive',68,6,DRIVE)):
        add(key,'LRDIMM drive strengths',label,off,shift,2,choices=choices)
    for shift, name in enumerate(('clock','cs','odt','cke')):
        add(f'ext_delay_{name}','LRDIMM timing',f'{name.upper()} extended delay',69,shift*2,2,
            choices={i:f'{i}/128 tCK' for i in range(4)})
    for name,off,shift in (('clock',70,0),('cs',70,4),('odt',71,0),('cke',71,4)):
        add(f'add_delay_{name}','LRDIMM timing',f'{name.upper()} additive delay',off,shift,3,
            choices={i:f'{8-i}/32 tCK' for i in range(8)})
        if name != 'clock':
            add(f'add_enable_{name}','LRDIMM timing',f'{name.upper()} additive delay enabled',off,shift+3,1,choices=BOOL)
    for index, speed in enumerate(('800_1066','1333_1600','1866_2133')):
        base = 72+index*6
        group = f'LRDIMM DDR3-{speed.replace("_", "/")}'
        add(f'{speed}.mdq_odt',group,'Buffer MDQ termination',base,0,3,
            choices={0:'Off',1:'60 ohm',2:'120 ohm',3:'40 ohm',5:'30 ohm',6:'240 ohm',7:'80 ohm'})
        add(f'{speed}.mdq_drive',group,'Buffer MDQ drive',base,4,3,
            choices={0:'RZQ/6',1:'RZQ/7',2:'RZQ/4',3:'RZQ/9',4:'RZQ/12'})
        for rank in range(8):
            for mode,shift in (('read',0),('write',4)):
                for line in range(2):
                    add(f'{speed}.rank{rank}.{mode}.odt{line}',group,f'Rank {rank} {mode} ODT{line}',
                        base+1+rank//2, shift+(rank%2)*2+line,1,choices={0:'Deasserted',1:'Asserted'})
        add(f'{speed}.dram_drive',group,'DRAM drive impedance',base+5,0,2,choices={0:'RZQ/6 (40 ohm)',1:'RZQ/7 (34 ohm)'})
        add(f'{speed}.rtt_nom',group,'DRAM RTT_NOM, ranks 0/1',base+5,2,3,
            choices={0:'Off',1:'60 ohm',2:'120 ohm',3:'40 ohm',4:'20 ohm',5:'30 ohm'})
        add(f'{speed}.rtt_wr',group,'DRAM RTT_WR, all ranks',base+5,6,2,choices={0:'Off',1:'60 ohm',2:'120 ohm'})
    mtb = Fraction(data[10],data[11]) if data[10] and data[11] else None
    if mtb:
        for index,voltage in enumerate(('1.5','1.35','1.25')):
            for delta, bound in ((0,'min'),(1,'max')):
                add(f'delay_{voltage}_{bound}','LRDIMM module delays',f'{voltage} V {bound} delay',90+index*2+delta,0,7,
                    unit='ns',scale=mtb,note='Delay in module MTB units; excludes additional per-lane read delay.')
    for index,(function,rc) in enumerate(PERSONALITY):
        add(f'F{function}RC{rc}','LRDIMM personality',f'F{function}RC{rc}',102+index//2,4*(index%2),4,expert=True,
            note='Vendor-defined personality nibble; destination is defined by JEDEC. Byte 105 maps F14RC6 / F15RC6.')
    for offset, low, high in ((67,'F0RC2','F0RC3'),(68,'F0RC4','F0RC5'),(69,'F1RC8','F1RC11'),
                              (70,'F1RC12','F1RC13'),(71,'F1RC14','F1RC15')):
        for shift,key in ((0,low),(4,high)):
            add(key,'LRDIMM control words',key,offset,shift,4,expert=True,
                note='Complete control-word nibble; includes bits reserved by the SPD layout.')
    return fields


def field_by_key(data, key):
    found = next((field for field in module_fields(data) if field.key == key), None)
    if found is None:
        raise ValueError(f'Field {key!r} does not apply to this module')
    return found


def edit_field(data, key, value):
    field = field_by_key(data,key)
    result = bytearray(field.encode(data,value))
    if key in ('device_mfg_bank','device_mfg_code'):
        b = result[field.offset] & 127
        result[field.offset] = b | (128 if bin(b).count('1') % 2 == 0 else 0)
    return bytes(result)


def decoded_fields(data):
    return {field.key: dict(group=field.group, label=field.label, offset=field.offset,
                           bits=f'{field.shift + field.bits - 1}:{field.shift}',
                           value=field.value(data), meaning=field.display(data), expert=field.expert)
            for field in module_fields(data)}


def registered_warnings(data):
    result = []
    for field in module_fields(data):
        if field.choices is not None and field.raw(data) not in field.choices:
            result.append(f'{field.label}: reserved encoding {field.raw(data)} at byte {field.offset}')
    if data[2]==11:
        family=data[3]&15
        if family in (1,5,9) and not data[68] & 7:
            for rc in (0,1,2,6,7,8,9,10,11,12,13,14,15):
                f=field_by_key(data,f'RC{rc}')
                if f.raw(data): result.append(f'RC{rc}: nonzero SPD reserved/vendor control word; firmware may override it')
        elif family==11 and data[1]>=0x10:
            for offset,mask in ((63,0x40),(67,0x0C),(70,0x08),(72,0x88),(77,0x20),(78,0x88),
                                (83,0x20),(84,0x88),(89,0x20),*( (i,0x80) for i in range(90,96))):
                if data[offset]&mask: result.append(f'LRDIMM reserved bits set at byte {offset}')
            if any(data[96:102]):result.append('LRDIMM reserved bytes 96-101 are nonzero')
            for i in range(90,96,2):
                if (data[i]&127)>(data[i+1]&127):result.append(f'LRDIMM minimum delay exceeds maximum at bytes {i}-{i+1}')
    return result

# Shared standard descriptors supplement the detailed registered-module tables.
_module_specific_fields = module_fields

def module_fields(data):
    fields=_module_specific_fields(data);known={f.key for f in fields};mem=data[2]
    def add(key,label,off,shift=0,bits=8,choices=None,group='Standard organization',**kw):
        if key not in known and off<len(data):
            fields.append(Field(key,group,label,off,shift,bits,choices=choices,**kw));known.add(key)
    if mem in (4,7,8):
        add('total_width_low','Module width, low byte',6)
        add('total_width_high','Module width, high byte',7)
        add('ecc_device_width','Error-check device width',14)
        add('burst_bitmap','Burst lengths supported bitmap',16,group='Standard capabilities',note='Bit positions describe supported burst lengths; consult the generation layout before changing capabilities.')
        add('revision_low','Module revision low',91,group='Manufacturing')
        add('revision_high','Module revision high',92,group='Manufacturing')
        add('manufacturing_location','Manufacturing location',72,group='Manufacturing')
        add('manufacturing_year','Manufacturing year BCD',93,group='Manufacturing',note='BCD year, raw encoding')
        add('manufacturing_week','Manufacturing week BCD',94,group='Manufacturing',note='BCD week, raw encoding')
    if mem==8:
        add('row_bits','Row address bits',3,0,4,choices={i:str(i) for i in range(12,17)})
        add('column_bits','Column address bits',4,0,4,choices={i:str(i) for i in range(8,13)})
        add('rank_count','Rank count code',5,0,3,choices={i:str(i+1) for i in range(8)})
        add('package','DRAM package type',5,4,1,choices={0:'Planar',1:'Stacked'})
        add('height','Module height code',5,5,3)
        add('voltage','Voltage interface',8,choices={5:'SSTL 1.8 V'})
        add('configuration','Error checking',11,0,2,choices={0:'None',1:'Parity',2:'ECC',3:'Parity + ECC'})
        add('self_refresh','Self refresh',12,7,1,choices=BOOL)
        add('refresh','Refresh interval',12,0,7,choices={0:'15.625 us',1:'3.9 us',2:'7.8 us',3:'31.3 us',4:'62.5 us',5:'125 us'})
        add('device_width','Primary device width',13,choices={i:f'x{i}' for i in (4,8,16,32)})
        add('device_banks','Banks per device',17,choices={4:'4',8:'8'})
        add('module_type','Module architecture',20,choices={1:'RDIMM',2:'UDIMM',4:'SO-DIMM',8:'Micro-DIMM',16:'Mini-RDIMM',32:'Mini-UDIMM'})
        for c in range(2,7):add(f'cas_{c}',f'CAS {c} supported',18,c,1,choices=BOOL,group='Standard capabilities')
        add('module_attributes','Module attributes bitmap',21,group='Register / module attributes',note='Physical attributes; do not infer register IC settings from another generation.')
        add('device_attributes','Device attributes bitmap',22,group='Standard capabilities')
        add('rank_density','Rank density bitmap',31)
        for key,off in [('tRP',27),('tRRD',28),('tRCD',29),('tRAS',30),('tWR',36),('tWTR',37),('tRTP',38)]:
            add(key,key,off,group='Native timings',unit='ns',scale=1 if off==30 else .25)
    if mem==11:
        add('module_type','Module architecture',3,0,4,choices={1:'RDIMM',2:'UDIMM',3:'SO-DIMM',5:'Mini-RDIMM',9:'72b SO-RDIMM',11:'LRDIMM'})
        add('density_code','DRAM density',4,0,4,choices={i:f'{256*(1<<i)} Mbit' for i in range(7)})
        add('bank_code','Bank address bits code',4,4,3,choices={0:'3 bank bits (8 banks)'})
        add('column_bits','Column address bits code',5,0,3,choices={i:str(i+9) for i in range(4)})
        add('row_bits','Row address bits code',5,3,3,choices={i:str(i+12) for i in range(5)})
        add('rank_count_code','Rank count',7,3,3,choices={i:str(i+1) for i in range(8)})
        add('device_width_code','Device width',7,0,3,choices={i:f'x{4<<i}' for i in range(4)})
        add('primary_width_code','Primary bus width',8,0,3,choices={i:str(8<<i) for i in range(4)})
        add('ecc_width_code','ECC width',8,3,2,choices={0:'None',1:'8 bits'})
        for bit,label in [(0,'1.5 V not operable'),(1,'1.35 V operable'),(2,'1.25 V operable')]:add(f'voltage_{bit}',label,6,bit,1,choices=BOOL,group='Standard capabilities')
        add('package_type','SDRAM package type',33,7,1,choices={0:'Standard monolithic',1:'Nonstandard'},group='Standard organization')
        add('package_die_count','Package die-count code',33,4,3,choices={0:'Not specified',1:'Single die',2:'2 dies',3:'4 dies',4:'8 dies'},group='Standard organization')
        add('package_loading','Package signal loading',33,2,2,choices={0:'Not specified',1:'Multiple loads',2:'Single load'},group='Standard organization')
        for key,off,bit,label in [('dll_off',30,7,'DLL-off support'),('rzq7',30,1,'RZQ/7 supported'),('rzq6',30,0,'RZQ/6 supported'),('pasr',31,7,'Partial-array self refresh'),('odts',31,3,'ODTS readout'),('asr',31,2,'Automatic self refresh'),('temp_refresh',31,1,'Extended-temperature 1x refresh'),('temp_range',31,0,'Extended temperature range'),('thermal_sensor',32,7,'Thermal sensor present')]:add(key,label,off,bit,1,choices=BOOL,group='Standard capabilities')
        for key,label,off,shift,bits in [('height_code','Module height code',60,0,5),('thickness_front','Front thickness code',61,0,4),('thickness_back','Back thickness code',61,4,4),('raw_card_code','Reference raw-card code',62,0,5),('raw_card_bank','Reference raw-card bank',62,7,1),('raw_card_revision','Raw-card revision',62,5,2)]:add(key,label,off,shift,bits,group='Module mechanics')
        for key,off in [('manufacturing_location',119),('manufacturing_year',120),('manufacturing_week',121),('module_revision',146),('dram_stepping',147)]:add(key,key.replace('_',' ').title(),off,group='Manufacturing')
    return fields
