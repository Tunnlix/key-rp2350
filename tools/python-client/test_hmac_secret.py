"""Protocol 2 hmac-secret through genuine python-fido2 crypto and HID framing."""

from copy import deepcopy
import ctypes
from ctypes import wintypes
import hashlib
from pathlib import Path
import tempfile
from threading import Event
import os
import unittest

from fido2 import cbor
from fido2.attestation import PackedAttestation
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.webauthn import PublicKeyCredentialRequestOptions, PublicKeyCredentialDescriptor, PublicKeyCredentialType

from build_harness import build_harness
from fido2_harness import open_harness


def rewrite_as_legacy_vault(path, version=1):
    """Construct a valid old-format fixture in a private test directory. No
    decrypted keys/randoms are logged or returned, and live peers are closed."""
    class Blob(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt.CryptUnprotectData.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    crypt.CryptProtectData.argtypes = [ctypes.POINTER(Blob), ctypes.c_wchar_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    vault = path.read_bytes()
    assert vault[:8] == b"APCV\x00\x00\x00\x05"
    sealed = (ctypes.c_ubyte * (len(vault) - 12)).from_buffer_copy(vault[12:])
    incoming, plain = Blob(len(sealed), sealed), Blob()
    assert crypt.CryptUnprotectData(ctypes.byref(incoming), None, None, None, None, 1, ctypes.byref(plain))
    try:
        data = bytearray(ctypes.string_at(plain.data, plain.length))
        assert data[:4] == b"ACP5"
        # These fixtures have no live seventeenth staging key.
        assert data[40 + 16 * 202] == 0
        old = bytearray(b"ACP4") + data[4:40 + 16 * 202]
        record_offset = 40 + 17 * 202
        old.extend(data[record_offset:record_offset + 16 * 168 + 35])
        if version == 4:
            legacy = bytearray(old)
        elif version == 3:
            legacy = bytearray(b"ACP3") + old[4:-16]  # Drop v4 credential policies.
        elif version == 2:
            legacy = bytearray(b"ACP2") + old[4:-35]  # Drop PIN/policy records.
        else:
            assert version == 1
            legacy = bytearray(b"ACP1") + old[4:40]
            for index in range(16):
                offset = 40 + index * 202
                legacy.extend(old[offset:offset + 137])  # Drop secret flag/randoms.
            legacy.extend(old[40 + 16 * 202:40 + 16 * 202 + 16 * 168])
        old[:] = bytes(len(old))
        data[:] = bytes(len(data))
    finally:
        ctypes.memset(plain.data, 0, plain.length)
        kernel.LocalFree(plain.data)
    raw = (ctypes.c_ubyte * len(legacy)).from_buffer_copy(legacy)
    legacy[:] = bytes(len(legacy))
    incoming, encrypted = Blob(len(raw), raw), Blob()
    try:
        assert crypt.CryptProtectData(ctypes.byref(incoming), "Legacy test fixture", None, None, None, 1, ctypes.byref(encrypted))
        path.write_bytes(b"APCV" + version.to_bytes(4, "big") + encrypted.length.to_bytes(4, "big") +
                        ctypes.string_at(encrypted.data, encrypted.length))
    finally:
        ctypes.memset(raw, 0, len(raw))
        if encrypted.data:
            kernel.LocalFree(encrypted.data)


@unittest.skipUnless(os.name == "nt", "Current subprocess provider requires Windows CNG/DPAPI")
class HmacSecretTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.executable = build_harness()

    def setUp(self):
        self.device = open_harness(self.executable)
        self.addCleanup(self.device.close)
        self.client = Ctap2(self.device, strict_cbor=True)
        self.protocol = PinProtocolV2()
        self.client_hash = hashlib.sha256(b"hmac assertion challenge").digest()
        self.created = self.register(self.client, self.device)

    def touch(self, status):
        if status == STATUS.UPNEEDED:
            self.assertTrue(self.device._connection.confirm_presence())

    def register(self, client, peer, extension=True):
        result = client.make_credential(bytes(32), {"id": "example.com"}, {"id": b"user"},
            [{"alg": -7, "type": "public-key"}], extensions=None if extension is None else {"hmac-secret": extension},
            on_keepalive=lambda status: peer._connection.confirm_presence() if status == STATUS.UPNEEDED else None)
        PackedAttestation().verify(result.att_stmt, result.auth_data, bytes(32))
        self.assertEqual(result.auth_data.extensions, {"hmac-secret": True} if extension else None)
        return result

    def request(self, client=None, salt1=None, salt2=None):
        client = client or self.client
        peer_key, shared = ClientPin(client, self.protocol)._get_shared_secret()
        salts = (salt1 if salt1 is not None else bytes(32)) + (salt2 if salt2 is not None else b"")
        encrypted = self.protocol.encrypt(shared, salts)
        return {1: peer_key, 2: encrypted, 3: self.protocol.authenticate(shared, encrypted), 4: 2}, shared

    def assertion(self, request, client=None, peer=None, created=None, **kwargs):
        client, peer, created = client or self.client, peer or self.device, created or self.created
        response = client.get_assertion("example.com", self.client_hash,
            [{"id": created.auth_data.credential_data.credential_id, "type": "public-key"}],
            extensions={"hmac-secret": request},
            on_keepalive=kwargs.pop("on_keepalive", lambda status: peer._connection.confirm_presence() if status == STATUS.UPNEEDED else None),
            **kwargs)
        response.verify(self.client_hash, created.auth_data.credential_data.public_key)
        return response

    def output(self, response, shared):
        self.assertEqual(int(response.auth_data.flags), 0x81)
        encrypted = response.auth_data.extensions["hmac-secret"]
        self.assertIn(len(encrypted), (48, 80))
        return self.protocol.decrypt(shared, encrypted)

    def test_get_info_and_development_client_pin(self):
        info = self.client.get_info()
        self.assertEqual(info.extensions, ["hmac-secret", "credProtect", "hmac-secret-mc"])
        self.assertEqual(info.pin_uv_protocols, [2])
        self.assertFalse(info.options["clientPin"])
        self.assertNotIn("uv", info.options)
        self.assertTrue(info.options["pinUvAuthToken"])
        first = self.client.client_pin(2, ClientPin.CMD.GET_KEY_AGREEMENT)[1]
        self.assertEqual(first, self.client.client_pin(2, ClientPin.CMD.GET_KEY_AGREEMENT)[1])
        self.assertEqual((first[1], first[3], first[-1]), (2, -25, 1))
        for params, status in (({}, 0x14), ({1: 2}, 0x14), ({1: 1, 2: 2}, 2),
                               ({1: "2", 2: 2}, 0x11), ({1: 2, 2: 3}, 0x14), ({1: 2, 2: 9}, 0x14)):
            with self.subTest(params=params), self.assertRaises(CtapError) as error:
                self.client.send_cbor(Ctap2.CMD.CLIENT_PIN, params)
            self.assertEqual(int(error.exception.code), status)

    def test_same_credential_and_salt_repeat_across_sessions(self):
        request, shared = self.request()
        first = self.assertion(request)
        second = self.assertion(request)
        self.assertEqual(self.output(first, shared), self.output(second, shared))
        self.assertNotEqual(first.auth_data.extensions, second.auth_data.extensions)  # Fresh response IV.
        request, new_shared = self.request()
        third = self.assertion(request)
        self.assertEqual(self.output(first, shared), self.output(third, new_shared))
        self.assertEqual([first.auth_data.counter, second.auth_data.counter, third.auth_data.counter], [1, 2, 3])

    def test_two_salts_rotation_and_credential_binding(self):
        salt1, salt2 = bytes(32), bytes([1]) * 32
        request, shared = self.request(salt1=salt1, salt2=salt2)
        outputs = self.output(self.assertion(request), shared)
        self.assertEqual(len(outputs), 64)
        self.assertNotEqual(outputs[:32], outputs[32:])
        for salt, expected in ((salt1, outputs[:32]), (salt2, outputs[32:])):
            request, shared = self.request(salt1=salt)
            self.assertEqual(self.output(self.assertion(request), shared), expected)
        other = self.register(self.client, self.device)
        request, shared = self.request(salt1=salt1)
        self.assertNotEqual(self.output(self.assertion(request, created=other), shared), outputs[:32])

    def test_secrets_also_generated_without_registration_extension(self):
        for extension in (None, False):
            created = self.register(self.client, self.device, extension=extension)
            self.assertEqual(int(created.auth_data.flags), 0x41)
            request, shared = self.request()
            self.assertEqual(len(self.output(self.assertion(request, created=created), shared)), 32)

    def test_none_attestation_still_returns_registration_extension(self):
        response = self.client.send_cbor(1, {1: bytes(32), 2: {"id": "example.com"}, 3: {"id": b"user"},
            4: [{"alg": -7, "type": "public-key"}], 6: {"hmac-secret": True}, 11: ["none"]}, on_keepalive=self.touch)
        self.assertEqual(response[1], "none")
        self.assertEqual(response[3], {})
        self.assertEqual(response[2][32], 0xC1)
        self.assertEqual(response[2][37:53], bytes(16))

    def test_reject_silent_secret_request(self):
        request, _ = self.request()
        with self.assertRaises(CtapError) as error:
            self.assertion(request, options={"up": False})
        self.assertEqual(int(error.exception.code), 0x2B)

    def test_bad_authentication_and_peer_point_never_sign_or_increment(self):
        original, _ = self.request()
        for change, expected in (("auth", 0x33), ("short-auth", 0x33), ("cipher", 0x33), ("point", 2)):
            request = deepcopy(original)
            if change == "auth":
                request[3] = bytes(32)
            elif change == "short-auth":
                request[3] = request[3][:16]
            elif change == "cipher":
                request[2] = request[2][:-1] + bytes([request[2][-1] ^ 1])
            else:
                request[1][-2], request[1][-3] = bytes(32), bytes(32)
            touched = []

            def confirm(status):
                touched.append(status)
                self.touch(status)

            with self.subTest(change=change), self.assertRaises(CtapError) as error:
                self.assertion(request, on_keepalive=confirm)
            self.assertEqual(int(error.exception.code), expected)
            self.assertIn(STATUS.UPNEEDED, touched)
        request, _ = self.request()
        self.assertEqual(self.assertion(request).auth_data.counter, 1)

    def test_extension_structure_validation(self):
        base, _ = self.request()
        cases = [(False, 0x11), ({}, 0x14)]
        for key in (1, 2, 3):
            value = deepcopy(base); del value[key]; cases.append((value, 0x14))
        for key, value, expected in ((4, 1, 2), (4, "2", 0x11), (2, bytes(32), 2),
                                    (2, bytes(96), 2), (2, False, 0x11), (3, bytes(33), 0x33), (3, 1, 0x11)):
            request = deepcopy(base); request[key] = value; cases.append((request, expected))
        missing_protocol = deepcopy(base); del missing_protocol[4]; cases.append((missing_protocol, 0x33))
        for key, value, expected in ((1, 1, 2), (3, -7, 2), (-1, 2, 2), (-2, bytes(31), 2), (-3, "bad", 0x11)):
            request = deepcopy(base); request[1][key] = value; cases.append((request, expected))
        for request, expected in cases:
            with self.subTest(expected=expected), self.assertRaises(CtapError) as error:
                self.assertion(request)
            self.assertEqual(int(error.exception.code), expected)
        with self.assertRaises(CtapError) as error:
            self.client.make_credential(bytes(32), {"id": "example.com"}, {"id": b"user"},
                [{"alg": -7, "type": "public-key"}], extensions={"hmac-secret": 1})
        self.assertEqual(int(error.exception.code), 0x11)

    def test_cancel_and_denial_preserve_counter(self):
        request, _ = self.request()
        cancelled = Event()
        with self.assertRaises(CtapError) as error:
            self.assertion(request, event=cancelled, on_keepalive=lambda _: cancelled.set())
        self.assertEqual(int(error.exception.code), 0x2D)
        with self.assertRaises(CtapError) as error:
            self.assertion(request, on_keepalive=lambda _: self.device._connection.deny_presence())
        self.assertEqual(int(error.exception.code), 0x27)
        self.assertEqual(self.assertion(request).auth_data.counter, 1)

    def test_persistence_and_reset_rotate_agreement_and_remove_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            created, expected, old_key = None, None, None
            for iteration in (0, 1):
                peer = open_harness(self.executable, storage_directory=directory)
                try:
                    client = Ctap2(peer)
                    if created is None:
                        created = self.register(client, peer)
                    request, shared = self.request(client=client)
                    response = self.assertion(request, client, peer, created)
                    result = self.output(response, shared)
                    key = client.client_pin(2, 2)[1]
                    if expected is None:
                        expected, old_key = result, key
                    else:
                        self.assertEqual(result, expected)
                        self.assertNotEqual(key, old_key)  # Ephemeral key changes on power-on.
                        client.reset(on_keepalive=lambda _: peer._connection.confirm_presence())
                        self.assertNotEqual(client.client_pin(2, 2)[1], key)
                        with self.assertRaises(CtapError) as error:
                            self.assertion(request, client, peer, created)
                        self.assertEqual(int(error.exception.code), 0x2E)
                        new_created = self.register(client, peer)
                        # Reset invalidates the old shared secret even with a valid new credential.
                        with self.assertRaises(CtapError) as error:
                            self.assertion(request, client, peer, new_created)
                        self.assertEqual(int(error.exception.code), 0x33)
                        new_request, new_shared = self.request(client=client)
                        self.assertNotEqual(self.output(self.assertion(new_request, client, peer, new_created), new_shared), expected)
                finally:
                    peer.close()

    def test_legacy_vault_credentials_preserved_without_inventing_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            peer = open_harness(self.executable, storage_directory=directory)
            try:
                created = self.register(Ctap2(peer), peer)
            finally:
                peer.close()

            path = Path(directory) / "credentials.vault"
            rewrite_as_legacy_vault(path)
            peer = open_harness(self.executable, storage_directory=directory)
            try:
                client = Ctap2(peer)
                request, _ = self.request(client=client)
                response = self.assertion(request, client, peer, created)
                self.assertIsNone(response.auth_data.extensions)
                self.assertEqual(int(response.auth_data.flags), 1)
                self.assertEqual(response.auth_data.counter, 1)
                # A successful counter update upgrades the file while preserving old keys.
                self.assertEqual(path.read_bytes()[:8], b"APCV\x00\x00\x00\x05")
                new_created = self.register(client, peer)
                request, shared = self.request(client=client)
                self.assertEqual(len(self.output(self.assertion(request, client, peer, new_created), shared)), 32)
            finally:
                peer.close()

    def test_standard_extension_processor_returns_client_outputs(self):
        credential = PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY,
            id=self.created.auth_data.credential_data.credential_id)
        options = PublicKeyCredentialRequestOptions(challenge=b"challenge", rp_id="example.com",
            allow_credentials=[credential], extensions={"hmacGetSecret": {"salt1": bytes(32), "salt2": bytes([1]) * 32}})
        processor = HmacSecretExtension(allow_hmac_secret=True).get_assertion(self.client, options, self.protocol)
        self.assertIsNotNone(processor)
        inputs = processor.prepare_inputs(credential, None)
        response = self.assertion(inputs["hmac-secret"])
        output = processor.prepare_outputs(response, None)["hmacGetSecret"]
        self.assertEqual((len(output.output1), len(output.output2)), (32, 32))
        self.assertNotEqual(output.output1, output.output2)
        request, shared = self.request()
        self.assertEqual(self.output(self.assertion(request), shared), output.output1)


if __name__ == "__main__":
    unittest.main()
