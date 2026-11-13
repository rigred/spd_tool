# SPDX-License-Identifier: MIT
"""Windows PawnIO device interface; no DLL, driver installation or raw port I/O.

The public device ABI is documented by namazso/PawnIO's pawnio_um.h and
PawnIOLib. Only pinned official SMBus modules and named operations are exposed.
"""
from contextlib import contextmanager
import ctypes as C
import hashlib
import os
import platform
from pathlib import Path
import struct
import sys

MODULE_RELEASE='0.2.11'
MODULES={
    'i801':('SmbusI801.bin','a0f7d066e7efda28c0e754c1f52dbd8dc280d388ba8575b514a80cb67490530c',b'i801',0x8086),
    'piix4':('SmbusPIIX4.bin','91f9b4b1c39e3d399ce48477a89d8f6bd3e58a2241064a4daec3a1513dff56e5',b'PIIX4',0x1022),
}
IOCTL_LOAD=(41394<<16)|(0x821<<2)
IOCTL_EXECUTE=(41394<<16)|(0x841<<2)
IOCTL_VERSION=(41394<<16)|(0x861<<2)
OPERATIONS={'ioctl_identity','ioctl_write_protection','ioctl_piix4_port_sel','ioctl_smbus_xfer'}


def module_directory(directory=None):
    return Path(directory or os.environ.get('SPD_TOOL_PAWNIO_DIR') or Path(__file__).parent/'resources'/'windows'/'PawnIO').resolve()


def module_bytes(profile,directory=None):
    if profile not in MODULES:raise ValueError('Windows adapter must be i801 or piix4')
    name,expected,_,_=MODULES[profile];path=module_directory(directory)/name
    if path.is_symlink() or not path.is_file():raise ValueError('Official PawnIO SMBus modules are missing. Run packaging/fetch_windows_modules.py or choose their folder. See docs/WINDOWS.md')
    if path.stat().st_size>1024*1024:raise ValueError('PawnIO module exceeds 1 MiB')
    data=path.read_bytes()
    if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('PawnIO module hash mismatch: '+name+'; expected official release '+MODULE_RELEASE)
    return data


def execution_request(name,values=()):
    if name not in OPERATIONS:raise ValueError('Unsupported PawnIO operation')
    values=tuple(values)
    if len(values)>9 or any(type(v) is not int or not -(1<<63)<=v<(1<<63) for v in values):raise ValueError('Invalid PawnIO argument cells')
    return name.encode('ascii').ljust(32,b'\0')+struct.pack('<'+'q'*len(values),*values)


class WindowsAPI:
    """Fixed-width Windows ABI declarations, initialized only on Windows."""
    def __init__(self):
        if sys.platform!='win32' or C.sizeof(C.c_void_p)!=8 or platform.machine().lower() not in ('amd64','x86_64'):raise ValueError('Native PawnIO access requires x86-64 Windows; USB serial works on other platforms')
        self.kernel=C.WinDLL('kernel32',use_last_error=True)
        specs={
            'CreateFileW':([C.c_wchar_p,C.c_uint32,C.c_uint32,C.c_void_p,C.c_uint32,C.c_uint32,C.c_void_p],C.c_void_p),
            'DeviceIoControl':([C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,C.c_void_p,C.c_uint32,C.POINTER(C.c_uint32),C.c_void_p],C.c_int),
            'CloseHandle':([C.c_void_p],C.c_int),
            'CreateMutexW':([C.c_void_p,C.c_int,C.c_wchar_p],C.c_void_p),
            'WaitForSingleObject':([C.c_void_p,C.c_uint32],C.c_uint32),
            'ReleaseMutex':([C.c_void_p],C.c_int),
        }
        for name,(args,result) in specs.items():
            function=getattr(self.kernel,name);function.argtypes=args;function.restype=result

    def error(self,operation):
        code=C.get_last_error()
        return C.WinError(code,operation+': '+C.FormatError(code)+'; install the official signed PawnIO driver and run hardware operations as Administrator. Driver/security policies are not changed by SPD Tool.')

    def open(self):
        handle=self.kernel.CreateFileW(r'\\?\GLOBALROOT\Device\PawnIO',0xC0000000,3,None,3,0x80,None)
        if handle in (None,C.c_void_p(-1).value):raise self.error('Cannot open PawnIO')
        return handle

    def ioctl(self,handle,code,data,size):
        incoming=C.create_string_buffer(data or b'\0');outgoing=C.create_string_buffer(max(size,1));count=C.c_uint32()
        if not self.kernel.DeviceIoControl(handle,code,incoming,len(data),outgoing,size,C.byref(count),None):raise self.error('PawnIO request failed')
        if count.value!=size:raise OSError('Short/oversized PawnIO result; transaction state is not assumed')
        return outgoing.raw[:size]

    def close(self,handle):
        if not self.kernel.CloseHandle(handle):raise self.error('Cannot close Windows handle')

    @contextmanager
    def lock(self):
        # Same global mutex used by cooperating Windows hardware-monitor tools.
        handle=self.kernel.CreateMutexW(None,False,r'Global\Access_SMBUS.HTP.Method')
        if not handle:raise self.error('Cannot open the global SMBus mutex')
        owned=False
        try:
            state=self.kernel.WaitForSingleObject(handle,2000)
            owned=state in (0,0x80)
            if state==0x80:raise OSError('Previous SMBus owner terminated unexpectedly; operation refused without resetting the bus')
            if state==0x102:raise OSError('SMBus is busy in another application (mutex timeout)')
            if state!=0:raise self.error('Cannot acquire the global SMBus mutex')
            yield
        finally:
            try:
                if owned and not self.kernel.ReleaseMutex(handle):raise self.error('Cannot release SMBus mutex')
            finally:self.close(handle)


class PawnIOSession:
    def __init__(self,profile,directory=None,api=None):
        if profile not in MODULES:raise ValueError('Windows adapter must be i801 or piix4')
        self.profile,self.directory,self.api,self.handle=profile,directory,api,None
        self._lock=None

    def __enter__(self):
        # Validate the file before obtaining any driver/device handle.
        data=module_bytes(self.profile,self.directory)
        self.api=self.api or WindowsAPI();self._lock=self.api.lock();self._lock.__enter__()
        try:
            self.handle=self.api.open()
            self.driver_version=struct.unpack('<I',self.api.ioctl(self.handle,IOCTL_VERSION,b'',4))[0]
            self.api.ioctl(self.handle,IOCTL_LOAD,data,0)
            identity=self.execute('ioctl_identity',(),3)
            expected=MODULES[self.profile]
            if identity[0].to_bytes(8,'little').rstrip(b'\0')!=expected[2] or identity[2]&65535!=expected[3] or (identity[2]>>16)&65535 in (0,65535):raise ValueError('Unexpected SMBus controller identity; SPD access refused')
            self.identity=dict(profile=self.profile,type=expected[2].decode(),base=identity[1],vendor_id=f'{identity[2]&65535:04X}',device_id=f'{identity[2]>>16&65535:04X}',driver_version=self.driver_version)
            if self.profile=='piix4' and self.execute('ioctl_piix4_port_sel',(-1,),1)[0]!=0:raise ValueError('AMD SMBus is not on primary port 0; automatic mux/port changes are not supported')
            return self
        except BaseException:
            self.__exit__(*sys.exc_info());raise

    def execute(self,name,values=(),count=0):
        values=tuple(values)
        if name=='ioctl_smbus_xfer':
            if len(values)!=5 or any(type(v) is not int for v in values) or not 0x50<=values[0]<=0x57 or values[1] not in (0,1) or not 0<=values[2]<=255 or values[3]!=2 or not 0<=values[4]<=255 or count!=(1 if values[1] else 0):raise ValueError('Only SPD-address SMBus byte-data reads/writes are permitted')
        elif name=='ioctl_piix4_port_sel' and (values!=(-1,) or count!=1):raise ValueError('SMBus port/mux changes are not permitted')
        elif name=='ioctl_identity' and (values or count!=3):raise ValueError('Invalid identity request')
        elif name=='ioctl_write_protection' and (values or count!=1):raise ValueError('Invalid write-protection query')
        request=execution_request(name,values)
        if self.handle is None:raise ValueError('PawnIO session is closed')
        if type(count) is not int or not 0<=count<=5:raise ValueError('Invalid PawnIO output cell count')
        output=self.api.ioctl(self.handle,IOCTL_EXECUTE,request,count*8)
        if len(output)!=count*8:raise OSError('Unexpected PawnIO output length')
        return struct.unpack('<'+'Q'*count,output)

    def write_protected(self):
        return bool(self.execute('ioctl_write_protection',(),1)[0]) if self.profile=='i801' else None

    def __exit__(self,kind,value,traceback):
        try:
            if self.handle is not None:
                handle,self.handle=self.handle,None;self.api.close(handle)
        finally:
            if self._lock is not None:
                lock,self._lock=self._lock,None;lock.__exit__(kind,value,traceback)
