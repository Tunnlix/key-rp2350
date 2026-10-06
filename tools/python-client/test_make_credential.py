"""Registration through real python-fido2 framing; independently verify ECDSA."""

import hashlib
import tempfile
from threading import Event
import os
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.attestation import PackedAttestation, AttestationType
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2
from fido2.hid import CTAPHID

from build_harness import build_harness
from fido2_harness import open_harness


def parameters():
    return {1: hashlib.sha256(b"client data").digest(), 2: {"id": "example.com", "name": "Example"},
            3: {"id": b"user-1", "name": "alice", "displayName": "Alice"},
            4: [{"type": "public-key", "alg": -7}]}


@unittest.skipUnless(os.name == "nt", "Current subprocess provider requires Windows CNG/DPAPI")
class MakeCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.executable = build_harness()

    def setUp(self):
        self.device = open_harness(self.executable)
        self.addCleanup(self.device.close)
        self.connection = self.device._connection
        self.client = Ctap2(self.device, strict_cbor=True)

    def touch(self, status):
        if status == STATUS.UPNEEDED:
            self.assertTrue(self.connection.confirm_presence())

    def create(self, **kwargs):
        request = parameters()
        return self.client.make_credential(request[1], request[2], request[3], request[4],
                                           on_keepalive=self.touch, **kwargs)

    def assert_error(self, request, expected):
        reports = len(self.connection.received_reports)
        with self.assertRaises(CtapError) as error:
            self.client.send_cbor(Ctap2.CMD.MAKE_CREDENTIAL, request)
        self.assertEqual(int(error.exception.code), expected)
        self.assertFalse(any(r[4] == 0xBB for r in list(self.connection.received_reports)[reports:]))
        self.assertEqual(self.device.ping(b"after invalid request"), b"after invalid request")

    def test_es256_registration_and_independent_signature(self):
        self.assertFalse(self.connection.confirm_presence())
        response = self.create()
        self.assertEqual(response.fmt, "packed")
        data = response.auth_data
        self.assertEqual(data.rp_id_hash, hashlib.sha256(b"example.com").digest())
        self.assertEqual(int(data.flags), 0x41)
        self.assertEqual(data.counter, 0)
        credential = data.credential_data
        self.assertEqual(len(credential.credential_id), 32)
        self.assertEqual(bytes(credential.aaguid), bytes(16))
        key = credential.public_key
        self.assertEqual(set(key), {1, 3, -1, -2, -3})
        self.assertEqual((key[1], key[3], key[-1]), (2, -7, 1))
        public = ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], "big"),
                                             int.from_bytes(key[-3], "big"), ec.SECP256R1()).public_key()
        public.verify(response.att_stmt["sig"], bytes(data) + parameters()[1], ec.ECDSA(hashes.SHA256()))
        verified = PackedAttestation().verify(response.att_stmt, data, parameters()[1])
        self.assertEqual(verified.attestation_type, AttestationType.SELF)
        second = self.create()
        self.assertNotEqual(credential.credential_id, second.auth_data.credential_data.credential_id)
        self.assertNotEqual(key[-2], second.auth_data.credential_data.public_key[-2])

    def test_none_attestation_and_unknown_extensions(self):
        request = parameters()
        request[6] = {"futureExtension": {"value": True}}
        request[7] = {"rk": False, "up": True, "futureOption": 42}
        request[11] = ["none"]
        reply = self.client.send_cbor(Ctap2.CMD.MAKE_CREDENTIAL, request, on_keepalive=self.touch)
        self.assertEqual(reply[1], "none")
        self.assertEqual(reply[3], {})
        self.assertEqual(reply[2][32], 0x41)
        self.assertEqual(reply[2][37:53], bytes(16))

    def test_empty_user_id_and_ignored_icon(self):
        request = parameters()
        request[3]["id"] = b""
        request[3]["icon"] = False
        request[2]["icon"] = [1, 2]
        result = self.client.send_cbor(Ctap2.CMD.MAKE_CREDENTIAL, request, on_keepalive=self.touch)
        self.assertEqual(result[1], "packed")

    def test_all_algorithm_entries_are_validated(self):
        for entry, status in (({"type": "public-key"}, 0x12),
                              ({"type": "public-key", "alg": "-7"}, 0x11),
                              (False, 0x11)):
            request = parameters()
            request[4].append(entry)
            self.assert_error(request, status)
        request = parameters()
        request[4] *= 2
        self.assert_error(request, 2)
        request = parameters()
        request[4] = [{"type": "public-key", "alg": -257}, {"type": "public-key", "alg": -7}]
        self.assertEqual(self.client.send_cbor(1, request, on_keepalive=self.touch)[1], "packed")

    def test_missing_required_parameters(self):
        for key in range(1, 5):
            request = parameters()
            del request[key]
            self.assert_error(request, 0x14)

    def test_request_types_lengths_and_unsupported_options(self):
        cases = [(1, b"short", 3), (1, "text", 0x11), (2, [], 0x11),
                 (2, {}, 0x11), (3, {"id": bytes(65)}, 3), (3, {"id": "bad"}, 0x11),
                 (4, [], 0x26), (4, [{"type": "public-key", "alg": -257}], 0x26),
                 (5, [], 2), (5, [{"type": "public-key", "id": False}], 0x11),
                 (6, [], 0x11), (7, {"rk": True}, 0x2B), (7, {"up": False}, 0x2C),
                 (7, {"uv": True}, 0x2C), (7, {"up": 1}, 0x11),
                 (8, bytes(32), 0x14), (10, 1, 2), (11, [1], 0x11)]
        for key, value, status in cases:
            with self.subTest(key=key, value=value):
                request = parameters()
                request[key] = value
                self.assert_error(request, status)
        request = parameters()
        request[8], request[9] = bytes(16), 1
        self.assert_error(request, 2)

    def test_invalid_cbor_is_rejected_before_touch(self):
        encoded = cbor.encode(parameters())
        malformed = [encoded[:-1], encoded + b"\x00", b"\xbf\xff", b"\xa2\x01\x00\x01\x00",
                     b"\xa2\x02\x00\x01\x00", b"\xa1\x18\x01\x00", b"\xa1\x01\xc0\x00",
                     b"\xa1\x01\x62\xc0\xaf", b"\xa1\x18\x63\x81\x81\x81\x81\x00"]
        for data in malformed:
            with self.subTest(data=data):
                self.assertEqual(self.device.call(CTAPHID.CBOR, b"\x01" + data), b"\x12")
        # Valid four-level unknown values, including float, are ignored.
        # python-fido2's small CBOR encoder does not encode floats. Keep its HID
        # client and supply only this CBOR edge-case encoding explicitly.
        data = b"\xa5" + encoded[1:] + b"\x18\x63\x81\x81\xa1\x66future\xfa\x3f\xc0\x00\x00"
        reply = self.device.call(CTAPHID.CBOR, b"\x01" + data, on_keepalive=self.touch)
        self.assertEqual(reply[0], 0)
        self.assertEqual(cbor.decode(reply[1:])[1], "packed")

    def test_exclusion_requires_presence_and_is_rp_bound(self):
        response = self.create()
        exclude = [{"type": "public-key", "id": response.auth_data.credential_data.credential_id,
                    "transports": ["usb"]}]
        touched = []

        def confirm(status):
            touched.append(status)
            self.touch(status)

        request = parameters()
        request[5] = exclude
        with self.assertRaises(CtapError) as error:
            self.client.send_cbor(1, request, on_keepalive=confirm)
        self.assertEqual(int(error.exception.code), 0x19)
        self.assertIn(STATUS.UPNEEDED, touched)
        request[2]["id"] = "different.example"
        self.assertEqual(self.client.send_cbor(1, request, on_keepalive=self.touch)[1], "packed")
        request[5].append({"type": "public-key", "id": "bad"})
        self.assert_error(request, 0x11)  # Validate after a matching exclusion too.

    def test_cancel_and_denial_leave_no_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            peer = open_harness(self.executable, storage_directory=directory)
            try:
                client = Ctap2(peer)
                request = parameters()
                cancelled = Event()
                with self.assertRaises(CtapError) as error:
                    client.send_cbor(1, request, event=cancelled, on_keepalive=lambda _: cancelled.set())
                self.assertEqual(int(error.exception.code), 0x2D)
                with self.assertRaises(CtapError) as error:
                    client.send_cbor(1, request, on_keepalive=lambda _: peer._connection.deny_presence())
                self.assertEqual(int(error.exception.code), 0x27)
                self.assertEqual(client.get_info().versions, ["FIDO_2_3"])
            finally:
                peer.close()
            reopened = open_harness(self.executable, storage_directory=directory)
            try:
                state = reopened._connection.storage_state()
                self.assertEqual((state["credential_count"], state["key_count"]), (0, 0))
            finally:
                reopened.close()

    def test_persistence_exclusion_and_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            peer = open_harness(self.executable, storage_directory=directory)
            try:
                request = parameters()
                result = Ctap2(peer).make_credential(request[1], request[2], request[3], request[4],
                    on_keepalive=lambda _: peer._connection.confirm_presence())
                credential_id = result.auth_data.credential_data.credential_id
            finally:
                peer.close()
            peer = open_harness(self.executable, storage_directory=directory)
            try:
                state = peer._connection.storage_state()
                self.assertEqual((state["credential_count"], state["key_count"]), (1, 1))
                client = Ctap2(peer)
                request[5] = [{"type": "public-key", "id": credential_id}]
                with self.assertRaises(CtapError) as error:
                    client.send_cbor(1, request, on_keepalive=lambda _: peer._connection.confirm_presence())
                self.assertEqual(int(error.exception.code), 0x19)
                client.reset(on_keepalive=lambda _: peer._connection.confirm_presence())
                self.assertEqual(peer._connection.storage_state()["credential_count"], 0)
                self.assertEqual(client.send_cbor(1, request, on_keepalive=lambda _: peer._connection.confirm_presence())[1], "packed")
            finally:
                peer.close()

    def test_provider_capacity_returns_key_store_full(self):
        for _ in range(16):
            self.create()
        with self.assertRaises(CtapError) as error:
            self.create()
        self.assertEqual(int(error.exception.code), 0x28)
        self.assertEqual(self.device.ping(b"full vault"), b"full vault")


if __name__ == "__main__":
    unittest.main()
