"""Real python-fido2 requests against the C coordinator's subprocess transport.

Run: .venv/Scripts/python.exe -m unittest discover -s tools/python-client -p test_python_fido2.py -v
The suite compiles the harness automatically. It never discovers physical keys.
"""

from pathlib import Path
import os
import subprocess
import sys
import unittest
from unittest.mock import patch
from threading import Event

CLIENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CLIENT_DIR))

from build_harness import build_harness, find_compiler
from fido2_harness import HarnessConnection, open_harness
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2
from fido2 import cbor
from fido2.hid import CAPABILITY, CTAPHID, ConnectionFailure


@unittest.skipUnless(os.name == "nt", "Current subprocess provider requires Windows CNG/DPAPI")
class PythonFido2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.executable = build_harness()

    def setUp(self):
        self.device = open_harness(self.executable)
        self.addCleanup(self.device.close)
        # Inspect the injected connection; no library framing methods are patched.
        self.connection = self.device._connection
        self.assertIsInstance(self.connection, HarnessConnection)

    def assert_ctap_error(self, command, payload, expected):
        with self.assertRaises(CtapError) as raised:
            self.device.call(command, payload)
        self.assertEqual(raised.exception.code, expected)
        reply = self.connection.received_reports[-1]
        self.assertEqual(reply[4:8], bytes([0xBF, 0, 1, int(expected)]))

    def test_init_nonce_channel_and_capabilities(self):
        request = self.connection.sent_reports[0]
        response = self.connection.received_reports[0]
        self.assertEqual(request[:7], bytes.fromhex("ffffffff860008"))
        self.assertEqual(response[:7], bytes.fromhex("ffffffff860011"))
        self.assertEqual(response[7:15], request[7:15])
        cid = int.from_bytes(response[15:19], "big")
        self.assertNotIn(cid, (0, 0xFFFFFFFF))
        self.assertEqual(self.device.version, 2)
        self.assertEqual(self.device.device_version, (0, 1, 0))
        self.assertEqual(self.device.capabilities, CAPABILITY.WINK | CAPABILITY.NMSG | CAPABILITY.CBOR)
        self.assertEqual(self.device.ping(b"actual CID"), b"actual CID")
        self.assertEqual(int.from_bytes(self.connection.sent_reports[-1][:4], "big"), cid)

    @unittest.skipUnless(os.name == "nt", "Windows project compiler fallback")
    def test_compiler_discovery_without_gcc_on_path(self):
        with patch.dict(os.environ, {"PATH": str(Path(os.environ["SystemRoot"]) / "System32")}):
            os.environ.pop("CC", None)
            compiler = find_compiler()
            self.assertTrue(compiler.is_file())
            self.assertEqual(compiler.name.lower(), "gcc.exe")

    def test_ping_fragment_boundaries_and_binary_bytes(self):
        for length in (0, 1, 3, 57, 58, 60, 116, 117, 255, 256, 1024):
            with self.subTest(length=length):
                self.connection.sent_reports.clear()
                self.connection.received_reports.clear()
                payload = bytes(i % 256 for i in range(length))
                self.assertEqual(self.device.ping(payload), payload)
                expected_count = 1 if length <= 57 else 1 + (length - 57 + 58) // 59
                self.assertEqual(len(self.connection.sent_reports), expected_count)
                self.assertEqual(len(self.connection.received_reports), expected_count)
                # A PING reply equals the library-generated request byte for byte.
                self.assertEqual(list(self.connection.sent_reports), list(self.connection.received_reports))
                self.assertTrue(all(len(report) == 64 for report in self.connection.received_reports))

    def test_wink_empty_reply(self):
        self.device.wink()
        self.assertEqual(self.connection.received_reports[-1][4:7], b"\x88\x00\x00")
        self.assertEqual(self.connection.received_reports[-1][7:], bytes(57))

    def test_msg_rejected_without_ctap1_execution(self):
        self.assert_ctap_error(CTAPHID.MSG, b"\x00", CtapError.ERR.INVALID_COMMAND)
        self.assertEqual(self.device.ping(b"still usable"), b"still usable")

    def test_oversized_ping_recovers(self):
        self.assert_ctap_error(CTAPHID.PING, bytes(1025), CtapError.ERR.INVALID_LENGTH)
        self.assertEqual(self.device.ping(b"after oversized request"), b"after oversized request")

    def test_same_channel_init_resynchronizes(self):
        assigned = self.connection.received_reports[0][15:19]
        nonce = b"resync12"
        response = self.device.call(CTAPHID.INIT, nonce)
        self.assertEqual(response[:8], nonce)
        self.assertEqual(response[8:12], assigned)
        self.assertEqual(response[12:], bytes([2, 0, 1, 0, 13]))
        self.assertEqual(self.device.ping(b"resynchronized"), b"resynchronized")

    def test_unimplemented_commands_and_invalid_wink(self):
        self.assertTrue(self.device.capabilities & CAPABILITY.CBOR)
        self.assert_ctap_error(CTAPHID.LOCK, b"\x01", CtapError.ERR.INVALID_COMMAND)
        self.assert_ctap_error(CTAPHID.WINK, b"\x01", CtapError.ERR.INVALID_LENGTH)

    def test_get_info_through_standard_ctap2_client(self):
        client = Ctap2(self.device, strict_cbor=True)
        info = client.get_info()
        self.assertEqual(info.versions, ["FIDO_2_3"])
        self.assertEqual(bytes(info.aaguid), bytes(16))
        self.assertEqual(info.max_msg_size, 1024)
        self.assertEqual(info.options, {"rk": False, "up": True, "plat": False, "makeCredUvNotRqd": True})
        self.assertEqual(info.extensions, ["hmac-secret"])
        self.assertEqual(info.pin_uv_protocols, [2])
        self.assertEqual(info.algorithms, [{"alg": -7, "type": "public-key"}])
        reply = self.device.call(CTAPHID.CBOR, b"\x04")
        self.assertEqual(reply[0], 0)
        decoded = cbor.decode(reply[1:])
        self.assertEqual(set(decoded), {1, 2, 3, 4, 5, 6, 10, 22})
        self.assertEqual(decoded[22], ["packed"])
        self.assertEqual(cbor.encode(decoded), reply[1:])

    def test_ctap_errors_are_cbor_statuses(self):
        client = Ctap2(self.device)
        with self.assertRaises(CtapError) as raised:
            client.send_cbor(Ctap2.CMD.MAKE_CREDENTIAL, {})
        self.assertEqual(raised.exception.code, CtapError.ERR.MISSING_PARAMETER)
        # Invalid CTAP parameters are CBOR replies, not HID transport errors.
        self.assertEqual(self.connection.received_reports[-1][4:8], b"\x90\x00\x01\x14")
        self.assertEqual(self.device.call(CTAPHID.CBOR, b"\x04\xA0"), b"\x03")
        self.assertEqual(client.get_info().versions, ["FIDO_2_3"])

    def test_selection_simulated_touch(self):
        client = Ctap2(self.device)
        self.assertFalse(self.connection.confirm_presence())  # No pre-request touch caching.
        statuses = []

        def confirm(status):
            statuses.append(int(status))
            if status == STATUS.UPNEEDED:
                self.assertTrue(self.connection.confirm_presence())

        client.selection(on_keepalive=confirm)
        self.assertIn(2, statuses)
        self.assertEqual(self.connection.received_reports[-1][4:8], b"\x90\x00\x01\x00")
        # Each new selection requires its own fresh touch.
        client.selection(on_keepalive=confirm)
        self.assertGreaterEqual(statuses.count(2), 2)

    def test_selection_denial_and_cancel(self):
        client = Ctap2(self.device)
        with self.assertRaises(CtapError) as raised:
            client.selection(on_keepalive=lambda status: self.connection.deny_presence() if status == STATUS.UPNEEDED else None)
        self.assertEqual(raised.exception.code, CtapError.ERR.OPERATION_DENIED)
        cancelled = Event()
        with self.assertRaises(CtapError) as raised:
            client.selection(event=cancelled, on_keepalive=lambda status: cancelled.set())
        self.assertEqual(raised.exception.code, CtapError.ERR.KEEPALIVE_CANCEL)
        self.assertTrue(any(report[4] == 0x91 for report in self.connection.sent_reports))
        self.assertEqual(client.get_info().versions, ["FIDO_2_3"])

    def test_selection_without_presence_provider(self):
        other = open_harness(self.executable, user_presence=False)
        try:
            client = Ctap2(other)
            self.assertFalse(client.info.options["up"])
            with self.assertRaises(CtapError) as raised:
                client.selection()
            self.assertEqual(raised.exception.code, CtapError.ERR.INVALID_COMMAND)
        finally:
            other.close()

    def test_manual_main_presence_demo_auto_touch(self):
        result = subprocess.run([str(self.executable), "--presence-demo", "--auto-touch-ms", "200"],
                                capture_output=True, timeout=3.0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"UPNEEDED", result.stdout)
        self.assertIn(b"Selection result: 0x00", result.stdout)

    def test_reset_confirmed_and_state_erased(self):
        client = Ctap2(self.device)
        before = self.connection.storage_state()
        channel = self.connection.sent_reports[-1][:4]
        client.reset(on_keepalive=lambda status: self.connection.confirm_presence() if status == STATUS.UPNEEDED else None)
        after = self.connection.storage_state()
        self.assertEqual(after["generation"], before["generation"] + 1)
        self.assertEqual(after["credential_count"], 0)
        self.assertEqual(after["key_count"], 0)
        self.assertNotEqual(after["device_identifier"], before["device_identifier"])
        self.assertNotEqual(after["credential_store_state"], before["credential_store_state"])
        self.assertEqual(client.get_info().versions, ["FIDO_2_3"])
        self.assertEqual(self.connection.sent_reports[-1][:4], channel)

    def test_reset_denial_and_cancel_preserve_state(self):
        client = Ctap2(self.device)
        before = self.connection.storage_state()
        with self.assertRaises(CtapError) as raised:
            client.reset(on_keepalive=lambda status: self.connection.deny_presence() if status == STATUS.UPNEEDED else None)
        self.assertEqual(raised.exception.code, CtapError.ERR.OPERATION_DENIED)
        self.assertEqual(self.connection.storage_state(), before)
        cancelled = Event()
        with self.assertRaises(CtapError) as raised:
            client.reset(event=cancelled, on_keepalive=lambda status: cancelled.set())
        self.assertEqual(raised.exception.code, CtapError.ERR.KEEPALIVE_CANCEL)
        self.assertEqual(self.connection.storage_state(), before)

    def test_reset_manual_main_auto_touch(self):
        result = subprocess.run([str(self.executable), "--reset-demo", "--auto-touch-ms", "200"],
                                capture_output=True, timeout=3.0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"Reset result: 0x00", result.stdout)
        self.assertIn(b"generation=1, credentials=0, keys=0", result.stdout)
        self.assertEqual(self.device.call(CTAPHID.CBOR, b"\x07\xA0"), b"\x03")

    def test_timeout_while_input_is_silent(self):
        # Reuse the initial report generated by python-fido2 for a valid PING,
        # but omit its continuation to simulate a stalled host. No handcrafted frame.
        self.connection.sent_reports.clear()
        self.assertEqual(self.device.ping(bytes(60)), bytes(60))
        initial_report = self.connection.sent_reports[0]
        self.connection.write_packet(initial_report)
        reply = self.connection.read_packet()
        self.assertEqual(reply[:4], initial_report[:4])
        self.assertEqual(reply[4:8], b"\xBF\x00\x01\x05")
        self.assertEqual(self.device.ping(b"after timeout"), b"after timeout")

    def test_connection_validates_size_and_closes(self):
        with self.assertRaises(ValueError):
            self.connection.write_packet(bytes(65))
        self.connection.close()
        self.connection.close()  # Idempotent cleanup.
        self.assertEqual(self.connection.process.returncode, 0)
        self.assertFalse(self.connection._reader.is_alive())
        with self.assertRaises(ConnectionFailure):
            self.connection.read_packet()

    def test_adapter_timeout_closes_peer(self):
        with HarnessConnection(self.executable, timeout=0.1) as connection:
            with self.assertRaises(TimeoutError):
                connection.read_packet()
            self.assertIsNotNone(connection.process.poll())
            self.assertFalse(connection._reader.is_alive())

    def test_truncated_input_is_rejected(self):
        result = subprocess.run(
            [str(self.executable), "--stdio"], input=bytes(63),
            capture_output=True, timeout=2.0,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Truncated input report: 63/64", result.stderr)

    def test_fragmented_pipe_writes(self):
        # Reuse the library's INIT request, splitting its bytes across writes.
        request = self.connection.sent_reports[0]
        with subprocess.Popen(
            [str(self.executable), "--stdio"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
        ) as process:
            process.stdin.write(request[:5])
            process.stdin.flush()
            output, errors = process.communicate(input=request[5:], timeout=2.0)
        self.assertEqual(process.returncode, 0, errors)
        self.assertEqual(len(output), 64)
        self.assertEqual(output[7:15], request[7:15])


if __name__ == "__main__":
    unittest.main()
