"""Hardware tests mock only OS/device boundaries; no physical bus is touched."""
import binascii
import contextlib
import ctypes as C
import errno
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import spd_smbus as hw
from tests.test_spd import ddr3


@unittest.skipUnless(hw.fcntl is not None,'Linux ioctl ABI tests')
class TransportTests(unittest.TestCase):
    def test_smbus_only_adapter_uses_byte_data_and_normal_claim(self):
        calls=[]
        def ioctl(fd,operation,arg,*extra):
            calls.append(operation)
            if operation==hw.I2C_FUNCS:arg[0]=hw.I2C_FUNC_SMBUS_READ_BYTE_DATA;return 0
            if operation==hw.I2C_SLAVE:self.assertEqual(arg,0x50);return 0
            if operation==hw.I2C_SMBUS:
                self.assertEqual(arg.size,hw.I2C_SMBUS_BYTE_DATA)
                self.assertEqual(arg.read_write,hw.I2C_SMBUS_READ)
                arg.data.contents.byte=arg.command^0xAA
                return 0
            self.fail(f'Unexpected ioctl {operation}')
        with patch.object(hw.fcntl,'ioctl',side_effect=ioctl):
            result=hw.spd_read(7,0x50,254,255)
        self.assertEqual(result,bytes((254^0xAA,255^0xAA)))
        self.assertNotIn(hw.I2C_RDWR,calls)
        self.assertEqual(calls[:2],[hw.I2C_FUNCS,hw.I2C_SLAVE])

    def test_i2c_combined_read_and_short_message_detection(self):
        calls=[]
        def ioctl(fd,operation,arg,*extra):
            if operation==hw.I2C_FUNCS:arg[0]=hw.I2C_FUNC_I2C;return 0
            if operation==hw.I2C_SLAVE:return 0
            self.assertEqual(operation,hw.I2C_RDWR)
            self.assertEqual(arg.nmsgs,2)
            offset=C.cast(arg.msgs[0].buf,C.POINTER(C.c_uint8))[0]
            self.assertEqual(arg.msgs[0].len,1)
            calls.append((offset,arg.msgs[1].len))
            for i in range(arg.msgs[1].len):C.cast(arg.msgs[1].buf,C.POINTER(C.c_uint8))[i]=offset+i
            return 2
        with patch.object(hw.fcntl,'ioctl',side_effect=ioctl):
            self.assertEqual(hw.spd_read(7,0x57,250,255,4),bytes(range(250,256)))
        self.assertEqual(calls,[(250,4),(254,2)])
        with patch.object(hw.fcntl,'ioctl',return_value=1):
            with self.assertRaises(OSError):hw._i2c_rdwr(7,[(0x50,0,bytearray([0])),(0x50,1,bytearray(4))])

    def test_invalid_arguments_do_not_touch_adapter(self):
        with patch.object(hw.fcntl,'ioctl') as ioctl:
            for args in ((7,0xA0,0,255,16),(7,0x50,-1,255,16),(7,0x50,0,256,16),
                         (7,0x50,20,10,16),(7,0x50,0,255,0),(7,0x50,0,255,33)):
                with self.assertRaises(ValueError):hw.spd_read(*args)
            ioctl.assert_not_called()

    def test_busy_claim_never_forced(self):
        with patch.object(hw,'adapter_functions',return_value=hw.I2C_FUNC_I2C),patch.object(hw.fcntl,'ioctl',side_effect=OSError(errno.EBUSY,'bound')) as ioctl,patch.object(hw,'_i2c_rdwr') as transfer:
            with self.assertRaises(OSError):hw.spd_read(7,0x50)
            self.assertEqual(ioctl.call_args.args,(7,hw.I2C_SLAVE,0x50))
            transfer.assert_not_called()

    def test_bounded_retries_and_permanent_errors(self):
        with patch.object(hw.time,'sleep'),patch.object(hw,'_smbus_byte',side_effect=[OSError(errno.EAGAIN,'arbitration'),0x42]) as read,patch.object(hw,'adapter_functions',return_value=hw.I2C_FUNC_SMBUS_READ_BYTE_DATA),patch.object(hw,'_claim'):
            self.assertEqual(hw.spd_read(7,0x50,0,0),b'\x42');self.assertEqual(read.call_count,2)
        with patch.object(hw.time,'sleep'),patch.object(hw,'_smbus_byte',side_effect=OSError(errno.ETIMEDOUT,'timeout')) as read,patch.object(hw,'adapter_functions',return_value=hw.I2C_FUNC_SMBUS_READ_BYTE_DATA),patch.object(hw,'_claim'):
            with self.assertRaises(OSError):hw.spd_read(7,0x50,0,0,retries=2)
            self.assertEqual(read.call_count,3)
        with patch.object(hw.time,'sleep'),patch.object(hw,'_smbus_byte',side_effect=OSError(errno.EACCES,'denied')) as read,patch.object(hw,'adapter_functions',return_value=hw.I2C_FUNC_SMBUS_READ_BYTE_DATA),patch.object(hw,'_claim'):
            with self.assertRaises(OSError):hw.spd_read(7,0x50,0,0,retries=2)
            self.assertEqual(read.call_count,1)

    def test_bus_descriptor_closes_after_error(self):
        with patch.object(hw,'open_bus',return_value=7),patch.object(hw.fcntl,'flock',side_effect=OSError(errno.EBUSY,'busy')),patch.object(hw.os,'close') as close:
            with self.assertRaises(OSError):
                with hw.bus_session(1):pass
            close.assert_called_once_with(7)


@unittest.skipUnless(hw.fcntl is not None,'Linux adapter acquisition tests')
class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.sys_patch=patch.object(hw,'SYS_EE',str(self.root/'devices'));self.sys_patch.start()
        self.dev=Path(hw.ee1004_devpath(1,0x50));self.dev.mkdir(parents=True)
        self.raw=ddr3()
    def tearDown(self):self.sys_patch.stop();self.temp.cleanup()
    def eeprom(self,data=None,name='at24'):
        (self.dev/'eeprom').write_bytes(self.raw if data is None else data)
        (self.dev/'name').write_text(name)

    def test_sysfs_preferred_and_partial_output_is_exact(self):
        self.eeprom()
        with patch.object(hw,'open_bus') as bus:
            result=hw.acquire_spd(1,0x50)
            self.assertEqual(result.data,self.raw)
            self.assertTrue(result.source.startswith('sysfs:'))
            self.assertEqual(hw.acquire_spd(1,0x50,16,31).data,self.raw[16:32])
            self.assertEqual(hw.acquire_spd(1,0x50,176,191).data,bytes(16))
            self.assertFalse(hw.acquire_spd(1,0x50,176,191).report()['integrity_checked'])
            self.assertFalse(hw.ee1004_present(1,0x50))
            bus.assert_not_called()
        target=self.root/'slice.bin'
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(hw.main(['read','--bus','1','--addr','0x50','--start','16','--end','31','--out',str(target)]),0)
        self.assertEqual(target.read_bytes(),self.raw[16:32])

    def test_ee1004_default_full_and_explicit_range(self):
        data=bytearray(512);data[2]=12
        for offset in (0,128):data[offset+126:offset+128]=binascii.crc_hqx(data[offset:offset+126],0).to_bytes(2,'little')
        self.eeprom(data,'ee1004')
        self.assertEqual(len(hw.acquire_spd(1,0x50).data),512)
        self.assertEqual(len(hw.acquire_spd(1,0x50,end=255).data),256)
        self.assertEqual(hw.ee1004_read(1,0x50),data)

    def test_short_and_unstable_reads_preserve_existing_output(self):
        self.eeprom(self.raw[:128])
        with self.assertRaises(OSError):hw.acquire_spd(1,0x50)
        self.eeprom()
        target=self.root/'existing.bin';target.write_bytes(b'keep')
        changed=bytearray(self.raw);changed[176]^=1
        with patch.object(hw,'_read_exact_at',side_effect=[self.raw,bytes(changed)]),patch.object(hw,'open_bus') as raw,contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(hw.main(['read','--bus','1','--addr','0x50','--out',str(target)]),1)
            raw.assert_not_called()
        self.assertEqual(target.read_bytes(),b'keep')

    def test_stable_invalid_image_requires_opt_in_and_is_not_repaired(self):
        damaged=bytearray(self.raw);damaged[16]^=1;self.eeprom(damaged)
        with self.assertRaises(ValueError):hw.acquire_spd(1,0x50)
        result=hw.acquire_spd(1,0x50,allow_invalid=True)
        self.assertEqual(result.data,damaged);self.assertTrue(result.diagnostics)

    def test_bound_raw_device_is_refused(self):
        driver=self.root/'at24';driver.mkdir();(self.dev/'driver').symlink_to(driver,target_is_directory=True)
        with patch.object(hw,'open_bus') as bus:
            with self.assertRaises(OSError):hw.acquire_spd(1,0x50,backend='i2c')
            bus.assert_not_called()

    def test_raw_transport_repeats_and_rejects_ddr4(self):
        with patch.object(hw,'bus_session') as session,patch.object(hw,'adapter_functions',return_value=hw.I2C_FUNC_SMBUS_READ_BYTE_DATA),patch.object(hw,'spd_read',side_effect=[self.raw[:3],self.raw,self.raw]) as read:
            session.return_value.__enter__.return_value=7
            result=hw.acquire_spd(1,0x50)
            self.assertEqual(result.data,self.raw);self.assertEqual(result.snapshots,2)
            self.assertTrue(result.source.startswith('smbus:'))
            self.assertEqual(read.call_count,3)
        with patch.object(hw,'bus_session'),patch.object(hw,'adapter_functions',return_value=hw.I2C_FUNC_I2C),patch.object(hw,'spd_read',return_value=b'\x23\x11\x0c') as read:
            with self.assertRaises(ValueError):hw.acquire_spd(1,0x50)
            self.assertEqual(read.call_count,1)

    def test_no_silent_sysfs_fallback_and_passive_scan(self):
        self.eeprom()
        with patch.object(hw,'_read_exact_at',side_effect=PermissionError('no')),patch.object(hw,'open_bus') as raw:
            with self.assertRaises(PermissionError):hw.acquire_spd(1,0x50)
            raw.assert_not_called()
        with patch.object(hw,'inventory',return_value=[]) as inventory,patch.object(hw,'spd_read') as read,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(hw.main(['scan','--bus','1']),0)
            inventory.assert_called_once_with(1);read.assert_not_called()

    def test_same_output_and_report_rejected_before_access(self):
        with patch.object(hw,'acquire_spd') as read,contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(hw.main(['read','--bus','1','--addr','0x50','--out','x','--report','x']),1)
            read.assert_not_called()

    def test_atomic_failure_and_special_output(self):
        target=self.root/'output';target.write_bytes(b'keep')
        with patch.object(hw.os,'replace',side_effect=OSError('failed')):
            with self.assertRaises(OSError):hw.atomic_output(target,b'new')
        self.assertEqual(target.read_bytes(),b'keep')
        with self.assertRaises(ValueError):hw.atomic_output(self.root,b'new')


@unittest.skipUnless(hw.fcntl is not None,'Linux adapter programming tests')
class ProgrammerTests(unittest.TestCase):
    def test_invalid_programming_never_writes(self):
        with patch.object(hw,'_i2c_rdwr') as transfer,patch.object(hw,'adapter_functions') as caps:
            for kwargs in (dict(start=-1),dict(end=256),dict(page_size=7),dict(t_wr_s=0),dict(t_wr_s=float('nan')),dict(verify=False)):
                with self.assertRaises(ValueError):hw.spd_write(7,0x50,ddr3(),**kwargs)
            transfer.assert_not_called();caps.assert_not_called()
        with patch.object(hw,'open_bus') as bus,contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(hw.main(['write','--bus','1','--addr','0x50','--in','nonexistent.bin']),1)
            bus.assert_not_called()

    def test_page_boundaries_and_mandatory_verification(self):
        raw=ddr3()
        with patch.object(hw,'adapter_functions',return_value=hw.I2C_FUNC_I2C),patch.object(hw,'_claim'),patch.object(hw,'_i2c_rdwr') as transfer,patch.object(hw.time,'sleep'),patch.object(hw,'spd_read',return_value=raw[7:21]) as read:
            hw.spd_write(7,0x50,raw,7,20,page_size=8)
            writes=[call.args[1][0][2] for call in transfer.call_args_list]
            self.assertEqual([value[0] for value in writes],[7,8,16])
            self.assertEqual([len(value)-1 for value in writes],[1,8,5])
            read.assert_called_once()

    def test_backup_precedes_programming_and_final_image_is_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);raw=ddr3();edited=bytearray(raw);edited[128:146]=b'HARDWARE-TEST     '
            image=root/'image.bin';image.write_bytes(edited)
            backup=root/'original.bin'
            def program(*args):self.assertEqual(backup.read_bytes(),raw)
            with patch.object(hw,'_driver',return_value=None),patch.object(hw,'bus_session'),patch.object(hw,'adapter_functions',return_value=hw.I2C_FUNC_I2C),patch.object(hw,'spd_read',side_effect=[raw,raw,bytes(edited)]),patch.object(hw,'spd_write',side_effect=program) as write,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(hw.main(['write','--bus','1','--addr','0x50','--in',str(image),'--range','128:145','--enable-write','--backup',str(backup)]),0)
                write.assert_called_once()
