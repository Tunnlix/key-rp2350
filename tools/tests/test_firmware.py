"""Host-side checks for the update wrapper; no device or signing key is accessed."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('firmware', Path(__file__).parents[1] / 'firmware.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

LAYOUT = '''un-partitioned_space : S(r) NSBOOT(r) NS(-), uf2 { 'absolute' }
0(A) 00002000->000bd000 S(rw) NSBOOT(rw) NS(-), "Firmware A", uf2 { 'rp2350-arm-s' }, arm_boot 1, riscv_boot 0
1(B w/ 0) 000bd000->00178000 S(rw) NSBOOT(rw) NS(-), "Firmware B", uf2 { 'rp2350-arm-s' }, arm_boot 1, riscv_boot 0
2(A) 00178000->00180000 S(rw) NSBOOT(r) NS(-), "Blobs", uf2 { }, arm_boot 0, riscv_boot 0
3(A) 00180000->00200000 S(rw) NSBOOT(r) NS(-), "Credentials", uf2 { }, arm_boot 0, riscv_boot 0
'''


class FirmwareToolTests(unittest.TestCase):
    def test_existing_and_interrupted_output_does_not_block_new_session(self):
        with tempfile.TemporaryDirectory() as directory:
            first = tool.new_session(directory)
            (first / 'INCOMPLETE').touch()
            second = tool.new_session(directory)
            self.assertNotEqual(first, second)
            self.assertTrue((first / 'INCOMPLETE').exists())

    def test_parallel_operation_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with tool.exclusive(Path(directory)):
                with self.assertRaises(ValueError):
                    with tool.exclusive(Path(directory)):
                        self.fail('Second lock was accepted')

    def test_incomplete_bundle_cannot_be_used(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / 'INCOMPLETE').touch()
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                tool.verify(bundle, None)

    def test_layout_rejects_storage_write_access_and_wrong_slot(self):
        tool.verify_layout(LAYOUT)
        for bad in (LAYOUT.replace('NSBOOT(r) NS(-), "Blobs"', 'NSBOOT(rw) NS(-), "Blobs"'),
                    LAYOUT.replace('00178000->00180000', '00177000->00180000'),
                    LAYOUT.replace('B w/ 0', 'A'),
                    LAYOUT.replace("'absolute'", "'rp2350-arm-s'")):
            with self.subTest(layout=bad), self.assertRaises(ValueError):
                tool.verify_layout(bad)

    def test_default_and_enterprise_builds_have_different_valid_commands(self):
        before = dict(serial='test', aaguid='test', pin_set=True, min_pin_length=6,
                      force_pin_change=False, always_uv=False, free_slots=32,
                      long_touch_reset=False, pin_complexity=True)
        after = dict(before, version=[1, 6, 0], firmware_version=0x010600,
                     options={}, config_commands=[2, 3, 4])
        tool.verify_running(before, after, (1, 6, 0))
        after.update(options={'ep': False}, config_commands=[1, 2, 3, 4])
        tool.verify_running(before, after, (1, 6, 0))
        after['config_commands'] = [2, 3, 4]
        with self.assertRaisesRegex(ValueError, 'capability'):
            tool.verify_running(before, after, (1, 6, 0))
        after.update(options={}, pin_set=False)
        with self.assertRaisesRegex(ValueError, 'pin_set'):
            tool.verify_running(before, after, (1, 6, 0))

    def test_verification_failure_never_advances_latest_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            pointer = output / 'latest.json'
            original = '{"bundle":"previous-good-bundle"}\n'
            pointer.write_text(original)
            with patch('sys.argv', ['firmware.py', 'sign', '--output', str(output)]), \
                    patch.object(tool, 'find_picotool', return_value=Path('/test/picotool')), \
                    patch.object(tool, 'sign', side_effect=ValueError('signature invalid')):
                with self.assertRaisesRegex(ValueError, 'signature invalid'):
                    tool.main()
            self.assertEqual(pointer.read_text(), original)
            self.assertEqual(len(list(output.glob('*/result.json'))), 1)


if __name__ == '__main__':
    unittest.main()
