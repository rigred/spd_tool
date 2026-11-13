# SPDX-License-Identifier: MIT
"""Windows driver boundaries are simulated; tests never load/access a driver."""
from contextlib import contextmanager
import ctypes
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

import spd_pawnio as low
from spd_windows import WindowsBackend,inventory
from spd_hardware import prepare_programming,execute_programming
from spd_integrity import repair_integrity
from tests.test_spd import ddr3


class DriverAPI:
    def __init__(self,identity=b'i801',short=False):self.calls=[];self.depth=0;self.closed=[];self.identity=identity;self.short=short
    @contextmanager
    def lock(self):
        self.depth+=1
        try:yield
        finally:self.depth-=1
    def open(self):return 123
    def close(self,h):self.closed.append(h)
    def ioctl(self,h,code,data,size):
        assert self.depth==1
        self.calls.append((code,data,size))
        if code==low.IOCTL_VERSION:return struct.pack('<I',0x20000)
        if code==low.IOCTL_LOAD:return b''
        name=data[:32].split(b'\0')[0]
        if name==b'ioctl_identity':return struct.pack('<QQQ',int.from_bytes(self.identity.ljust(8,b'\0'),'little'),0xF000,(0x1C22<<16)|0x8086)
        if name==b'ioctl_smbus_xfer':return struct.pack('<Q',0xAB) if size else b''
        return bytes(size)


class PawnIOABITests(unittest.TestCase):
    def test_real_pinned_module_files_are_not_needed_for_driver_boundary_tests(self):
        api=DriverAPI()
        with patch.object(low,'module_bytes',return_value=b'module'):
            with low.PawnIOSession('i801',api=api) as session:
                self.assertEqual(session.execute('ioctl_smbus_xfer',(0x50,1,0xFF,2,0),1),(0xAB,))
                data=api.calls[-1][1]
                self.assertEqual(data[:32],b'ioctl_smbus_xfer'.ljust(32,b'\0'));self.assertEqual(struct.unpack('<5q',data[32:]),(0x50,1,0xFF,2,0))
                self.assertFalse(session.write_protected())
                before=len(api.calls)
                for args in [(0x36,1,0,2,0),(0xA0,1,0,2,0),(0x50,2,0,2,0),(0x50,1,256,2,0),(0x50,1,0,3,0)]:
                    with self.assertRaises(ValueError):session.execute('ioctl_smbus_xfer',args,1)
                with self.assertRaises(ValueError):session.execute('ioctl_piix4_port_sel',(1,),1)
                self.assertEqual(len(api.calls),before)
        self.assertEqual(api.closed,[123]);self.assertEqual(api.depth,0)

    def test_wrong_controller_identity_closes_driver_and_mutex(self):
        api=DriverAPI(identity=b'wrong')
        with patch.object(low,'module_bytes',return_value=b'module'),self.assertRaisesRegex(ValueError,'identity'):
            with low.PawnIOSession('i801',api=api):pass
        self.assertEqual(api.closed,[123]);self.assertEqual(api.depth,0)

    def test_missing_or_tampered_module_fails_before_kernel_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            api=DriverAPI()
            with self.assertRaisesRegex(ValueError,'missing'):
                with low.PawnIOSession('i801',tmp,api):pass
            (Path(tmp)/'SmbusI801.bin').write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError,'hash mismatch'):
                with low.PawnIOSession('i801',tmp,api):pass
            self.assertFalse(api.calls);self.assertFalse(api.closed)

    def test_pinned_module_hash_verification(self):
        data=b'fixture';entry=('SmbusI801.bin',hashlib.sha256(data).hexdigest(),b'i801',0x8086)
        with tempfile.TemporaryDirectory() as tmp,patch.dict(low.MODULES,{'i801':entry}):
            (Path(tmp)/entry[0]).write_bytes(data);self.assertEqual(low.module_bytes('i801',tmp),data)

    def test_abandoned_and_busy_global_mutex_fail_closed_and_release_resources(self):
        class Kernel:
            def __init__(self,state):self.state=state;self.releases=0;self.closes=0
            def CreateMutexW(self,*a):return 77
            def WaitForSingleObject(self,h,timeout):return self.state
            def ReleaseMutex(self,h):self.releases+=1;return 1
            def CloseHandle(self,h):self.closes+=1;return 1
        for state,releases in [(0x80,1),(0x102,0)]:
            api=object.__new__(low.WindowsAPI);api.kernel=Kernel(state)
            with self.assertRaises(OSError):
                with api.lock():self.fail('Failed lock admitted hardware access')
            self.assertEqual(api.kernel.releases,releases);self.assertEqual(api.kernel.closes,1)


class MemoryBus:
    def __init__(self):
        self.memory=bytearray(ddr3());self.calls=[];self.writes=[];self.protected=False;self.controller=0xF000;self.active=False;self.opens=0;self.ambiguous_write=False;self.unstable=False;self.snapshots=0
    def factory(self,profile,directory):
        owner=self
        class Session:
            def __enter__(self):
                owner.active=True;owner.opens+=1
                self.identity=dict(profile=profile,type='i801',base=owner.controller,vendor_id='8086',device_id='1C22');return self
            def __exit__(self,*a):owner.active=False
            def write_protected(self):return owner.protected
            def execute(self,name,values,count):
                assert owner.active;owner.calls.append((name,values,count))
                a,r,o,p,v=values
                assert 0x50<=a<=0x57 and p==2 and 0<=o<=255
                if a!=0x50:raise OSError('No device')
                if r:
                    if o==0:
                        owner.snapshots+=1
                        if owner.unstable and owner.snapshots%2==0:owner.memory[130]^=1
                    return (owner.memory[o],)
                owner.writes.append((o,v));owner.memory[o]=v
                if owner.ambiguous_write:raise OSError('Ambiguous completed write')
                return ()
        return Session()


class WindowsHardwareTests(unittest.TestCase):
    def setUp(self):self.bus=MemoryBus();self.backend=WindowsBackend('i801',session_factory=self.bus.factory)
    def test_stable_read_and_explicit_spd_only_scan(self):
        self.assertEqual(self.backend.read(0x50).data,ddr3());self.assertFalse(self.bus.writes)
        with self.assertRaisesRegex(ValueError,'Enable probing'):self.backend.scan()
        self.bus.calls=[];images,errors=self.backend.scan(active=True)
        self.assertEqual(len(images),1);self.assertEqual(len(errors),7)
        self.assertEqual({args[0] for _,args,_ in self.bus.calls},set(range(0x50,0x58)))
    def test_invalid_address_cancellation_and_changed_snapshots(self):
        for value in (-1,0x36,0xA0,True):
            with self.assertRaises(ValueError):self.backend.read(value)
        self.assertEqual(self.bus.opens,0)
        event=threading.Event();event.set()
        with self.assertRaisesRegex(ValueError,'cancelled'):self.backend.read(0x50,event)
        self.assertEqual(self.bus.opens,0)
        self.bus.unstable=True
        with self.assertRaisesRegex(ValueError,'snapshots differ'):self.backend.read(0x50)
    def test_protected_host_and_controller_change_block_programming(self):
        self.bus.protected=True
        with self.assertRaisesRegex(ValueError,'write protection'):prepare_programming(self.backend,0x50,ddr3(),0,255)
        self.assertFalse(self.bus.writes)
        self.bus.protected=False;self.backend.read(0x50);self.bus.controller+=16
        with self.assertRaisesRegex(ValueError,'identity changed'):self.backend.read(0x50)
    def edited(self):
        data=bytearray(ddr3());data[130]=ord('X');return repair_integrity(data)
    def test_review_backup_programming_and_full_verification(self):
        original=ddr3();expected=self.edited();plan=prepare_programming(self.backend,0x50,expected,0,255)
        self.assertFalse(self.bus.writes)
        with tempfile.TemporaryDirectory() as tmp:
            backup=Path(tmp)/'original.bin';result=execute_programming(self.backend,plan,backup)
            self.assertTrue(result['verified']);self.assertEqual(backup.read_bytes(),original);self.assertEqual(bytes(self.bus.memory),expected)
            self.assertTrue(Path(str(backup)+'.json').is_file());self.assertEqual(len(self.bus.writes),len(plan.changes))
    def test_ambiguous_write_is_not_retried_and_keeps_the_backup(self):
        plan=prepare_programming(self.backend,0x50,self.edited(),0,255);self.bus.ambiguous_write=True
        with tempfile.TemporaryDirectory() as tmp:
            backup=Path(tmp)/'original.bin'
            with self.assertRaisesRegex(OSError,'Ambiguous'):execute_programming(self.backend,plan,backup)
            self.assertEqual(backup.read_bytes(),ddr3());self.assertEqual(len(self.bus.writes),1)
    def test_changed_target_and_existing_backup_prevent_writes(self):
        plan=prepare_programming(self.backend,0x50,self.edited(),0,255)
        with tempfile.TemporaryDirectory() as tmp:
            backup=Path(tmp)/'old.bin';backup.write_bytes(b'existing')
            with self.assertRaises(FileExistsError):execute_programming(self.backend,plan,backup)
            self.assertFalse(self.bus.writes);self.assertEqual(backup.read_bytes(),b'existing')
            self.bus.memory[140]^=1
            with self.assertRaisesRegex(ValueError,'changed since review'):execute_programming(self.backend,plan,Path(tmp)/'new.bin')
            self.assertFalse(self.bus.writes)
    def test_inventory_has_no_spd_probes(self):
        result=inventory(session_factory=self.bus.factory)
        self.assertEqual(len(result['adapters']),2);self.assertFalse(self.bus.calls);self.assertFalse(self.bus.writes)


class WindowsCLITests(unittest.TestCase):
    def test_cli_preview_is_read_only_and_commit_requires_backup(self):
        import spd_tool
        bus=MemoryBus();backend=WindowsBackend(session_factory=bus.factory)
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'edited.bin';data=bytearray(ddr3());data[130]=ord('X');source.write_bytes(repair_integrity(data))
            args=['spd_tool.py','windows-smbus','write','--addr','0x50','--spd',str(source),'--range','0:255']
            output=io.StringIO()
            with patch('sys.argv',args),patch('spd_windows.sys.platform','win32'),patch('spd_windows.WindowsBackend',return_value=backend),patch('sys.stdout',output):spd_tool.main()
            self.assertTrue(json.loads(output.getvalue())['preview']);self.assertFalse(bus.writes)
            with patch('sys.argv',args+['--enable-write']),patch('spd_windows.sys.platform','win32'),patch('spd_windows.WindowsBackend',return_value=backend),patch('sys.stderr',io.StringIO()),self.assertRaises(SystemExit):spd_tool.main()
            self.assertFalse(bus.writes)
