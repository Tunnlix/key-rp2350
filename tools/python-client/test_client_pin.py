"""PIN maintenance, scoped tokens and UV: genuine python-fido2 protocol 2 inputs.

Portable tests call the C handler with Python cryptographic callbacks; Windows
integration tests use actual HID framing, CNG and the DPAPI persistent vault.
Tests cover token scopes/timers, signed UV flags, credential protection and hmac-secret.
"""
import ctypes
import hashlib
import hmac
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import PinProtocolV2, ClientPin
from fido2.hid import CAPABILITY, CTAPHID
from fido2.webauthn import AuthenticatorData

from build_harness import build_harness, build_pin_core_peer
from fido2_harness import open_harness


Primitive = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_uint, ctypes.c_void_p, ctypes.c_size_t,
                            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t)


class PortablePinPeer:
    capabilities = CAPABILITY.CBOR

    def __init__(self, library):
        self.lib = library
        self.errors = []
        self.keys = {}
        self.callback = Primitive(self.primitive)
        self.lib.pin_test_init.argtypes = [Primitive]
        self.lib.pin_test_call.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        self.lib.pin_test_call.restype = ctypes.c_size_t
        if self.lib.pin_test_init(self.callback) != 1:
            raise RuntimeError("Cannot initialize portable PIN test peer")

    def primitive(self, op, a, a_len, b, b_len, out, out_len):
        try:
            first = ctypes.string_at(a, a_len) if a_len else b""
            second = ctypes.string_at(b, b_len) if b_len else b""
            if op == 0:
                result = os.urandom(out_len)
            elif op == 1:
                result = hashlib.sha256(first).digest()
            elif op == 2:
                result = self.key.public_key().public_bytes(serialization.Encoding.X962,
                                                            serialization.PublicFormat.UncompressedPoint)
            elif op == 3:
                peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), first)
                result = self.key.exchange(ec.ECDH(), peer)
            elif op == 4:
                result = hmac.digest(first, second, "sha256")
            elif op in (5, 14):
                cipher = Cipher(algorithms.AES(first), modes.CBC(second[:16]))
                operation = cipher.encryptor() if op == 14 else cipher.decryptor()
                result = operation.update(second[16:]) + operation.finalize()
            elif op == 6:
                self.key = ec.generate_private_key(ec.SECP256R1())
                return 0
            elif op == 7:
                handle = os.urandom(32)
                key = ec.generate_private_key(ec.SECP256R1())
                self.keys[handle] = key, [os.urandom(32), os.urandom(32)]
                result = handle + key.public_key().public_bytes(serialization.Encoding.X962,
                                                               serialization.PublicFormat.UncompressedPoint)
            elif op == 8:
                result = self.keys[first][0].public_key().public_bytes(serialization.Encoding.X962,
                                                                    serialization.PublicFormat.UncompressedPoint)
            elif op == 9:
                signature = self.keys[first][0].sign(second, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                result = bytes([len(signature)]) + signature.ljust(72, b"\0")
            elif op == 10:
                del self.keys[first]
                return 0
            elif op == 11:
                result = bytes([int(first in self.keys)])
            elif op == 12:
                result = hmac.digest(self.keys[first][1][0 if second[0] else 1], second[1:], "sha256")
            elif op == 13:
                self.keys.clear()
                return 0
            else:
                raise ValueError("Unknown test primitive")
            if len(result) != out_len:
                raise ValueError("Test primitive output size")
            ctypes.memmove(out, result, out_len)
            return 0
        except Exception as error:
            self.errors.append(type(error).__name__)
            return 7  # AUTH_CRYPTO_ERROR

    def call(self, command, data, event=None, on_keepalive=None):
        if command != CTAPHID.CBOR:
            raise ValueError("Portable peer accepts CBOR only")
        output = (ctypes.c_ubyte * 513)()
        length = self.lib.pin_test_call(data, len(data), output)
        if self.errors:
            raise RuntimeError(f"Test crypto callback failed: {self.errors}")
        return bytes(output[:length])

    def power_on(self):
        if self.lib.pin_test_power_on() != 1:
            raise RuntimeError("Cannot power on portable peer")

    def reset(self):
        if self.lib.pin_test_reset() != 1:
            raise RuntimeError("Cannot reset portable peer")

    def advance(self, elapsed):
        self.lib.pin_test_advance_time.argtypes = [ctypes.c_uint32]
        self.lib.pin_test_advance_time(elapsed)


class PinCases:
    client_hash = hashlib.sha256(b"PIN authorization integration").digest()

    def touch(self, status):
        if status == STATUS.UPNEEDED and hasattr(self.peer, "_connection"):
            self.peer._connection.confirm_presence()

    def token(self, permissions=3, rp="example.com", pin="1234"):
        return ClientPin(Ctap2(self.peer), PinProtocolV2()).get_pin_token(pin, permissions, rp)

    def registration(self, token=None, policy=None, extensions=None, excludes=None, rp="example.com"):
        params = {1: self.client_hash, 2: {"id": rp}, 3: {"id": b"user"},
                  4: [{"type": "public-key", "alg": -7}]}
        inputs = dict(extensions or {})
        if policy is not None:
            inputs["credProtect"] = policy
        if inputs:
            params[6] = inputs
        if excludes is not None:
            params[5] = excludes
        if token is not None:
            params[8] = PinProtocolV2().authenticate(token, self.client_hash)
            params[9] = 2
        response = self.client.send_cbor(Ctap2.CMD.MAKE_CREDENTIAL, params, on_keepalive=self.touch)
        data = AuthenticatorData(response[2])
        data.credential_data.public_key.verify(bytes(data) + self.client_hash, response[3]["sig"])
        return data

    def assertion(self, credential, token=None, up=True, extension=None):
        params = {1: "example.com", 2: self.client_hash,
                  3: [{"id": credential.credential_data.credential_id, "type": "public-key"}], 5: {"up": up}}
        if token is not None:
            params[6] = PinProtocolV2().authenticate(token, self.client_hash)
            params[7] = 2
        if extension is not None:
            params[4] = {"hmac-secret": extension}
        response = self.client.send_cbor(Ctap2.CMD.GET_ASSERTION, params, on_keepalive=self.touch)
        data = AuthenticatorData(response[2])
        credential.credential_data.public_key.verify(bytes(data) + self.client_hash, response[3])
        return data

    def test_real_client_pin_helpers_and_permission_scopes(self):
        ClientPin(Ctap2(self.peer), PinProtocolV2()).set_pin("1234")
        token = self.token(2)
        self.assertEqual(len(token), 32)
        self.assert_error(0x33, lambda: self.registration(token))
        token = self.token(1, "different.example")
        self.assert_error(0x33, lambda: self.registration(token))
        token = self.token(1)
        modified = bytes([token[0] ^ 1]) + token[1:]
        self.assert_error(0x33, lambda: self.registration(modified))
        credential = self.registration(token, policy=3, extensions={"hmac-secret": True})
        self.assertEqual(int(credential.flags), 0xC5)
        self.assertEqual(credential.extensions, {"credProtect": 3, "hmac-secret": True})
        self.assertEqual(credential.counter, 0)
        self.assert_error(0x33, lambda: self.registration(token))  # Fresh UP consumed MC/GA permissions.
        self.assert_error(0x2E, lambda: self.assertion(credential))
        token = self.token(1)
        self.assert_error(0x33, lambda: self.assertion(credential, token))
        token = self.token(2, "different.example")
        self.assert_error(0x33, lambda: self.assertion(credential, token))
        token = self.token(2)
        assertion = self.assertion(credential, token)
        self.assertEqual(int(assertion.flags), 5)
        self.assertEqual(assertion.counter, 1)
        self.assert_error(0x33, lambda: self.assertion(credential, token))

    def test_pin_change_and_power_on_invalidate_tokens(self):
        self.set_pin("1234")
        token = self.token(1)
        ClientPin(Ctap2(self.peer), PinProtocolV2()).change_pin("1234", "5678")
        self.assert_error(0x33, lambda: self.registration(token))
        token = self.token(1, pin="5678")
        self.power_on()
        self.assert_error(0x33, lambda: self.registration(token))
        token = self.token(1, pin="5678")
        self.factory_reset()
        self.assert_error(0x35, lambda: self.registration(token))

    def test_token_preflight_and_non_uv_presence_consumption(self):
        self.set_pin("1234")
        credential = self.registration(policy=3)
        token = self.token(2)
        first = self.assertion(credential, token, up=False)
        self.assertEqual(int(first.flags), 4)
        second = self.assertion(credential, token)
        self.assertEqual(int(second.flags), 5)
        self.assertEqual(second.counter, first.counter + 1)
        self.assert_error(0x33, lambda: self.assertion(credential, token))
        ordinary = self.registration(policy=1)
        token = self.token(2)
        self.assertEqual(int(self.assertion(ordinary).flags), 1)
        self.assert_error(0x33, lambda: self.assertion(ordinary, token))

    def test_credential_protection_and_exclusion_privacy(self):
        self.set_pin("1234")
        protected = self.registration(policy=3)
        descriptor = {"id": protected.credential_data.credential_id, "type": "public-key"}
        self.assert_error(0x2E, lambda: self.assertion(protected, up=False))
        other = self.registration(policy=2, excludes=[descriptor])
        self.assertEqual(other.extensions, {"credProtect": 2})
        self.assertEqual(int(self.assertion(other).flags), 1)
        self.assert_error(0x19, lambda: self.registration(self.token(1), excludes=[descriptor]))
        for policy, status in ((0, 2), (4, 2), ("3", 0x11)):
            self.assert_error(status, lambda policy=policy: self.registration(policy=policy))

    def test_hmac_secret_uv_random_separation_and_signatures(self):
        self.set_pin("1234")
        credential = self.registration(extensions={"hmac-secret": True})
        protocol = PinProtocolV2()
        salt = hashlib.sha256(b"identical salt across UV domains").digest()

        def evaluate(verified):
            key, shared = protocol.encapsulate(self.key())
            encrypted = protocol.encrypt(shared, salt)
            extension = {1: key, 2: encrypted, 3: protocol.authenticate(shared, encrypted), 4: 2}
            data = self.assertion(credential, self.token(2) if verified else None, extension=extension)
            self.assertEqual(int(data.flags), 0x85 if verified else 0x81)
            return protocol.decrypt(shared, data.extensions["hmac-secret"])

        without_uv = evaluate(False)
        with_uv = evaluate(True)
        self.assertNotEqual(without_uv, with_uv)
        self.assertEqual(evaluate(True), with_uv)
        self.assertEqual(evaluate(False), without_uv)

    def test_token_permission_validation_before_pin_retries(self):
        self.set_pin("1234")
        self.assert_error(0x40, lambda: self.token(4))
        self.assert_error(0x14, lambda: self.token(1, None))
        self.assert_error(2, lambda: self.token(0))
        self.assertEqual(self.retries(), (8, False))
        token = self.token(0x81)  # Undefined permission bit is ignored.
        self.registration(token)
        self.assert_error(0x31, lambda: self.token(1, pin="wrong"))
        self.assertEqual(self.retries(), (7, False))

    def test_empty_auth_parameter_presence_probe(self):
        for set_pin in (False, True):
            if set_pin:
                self.set_pin("1234")
            for command, key in ((Ctap2.CMD.MAKE_CREDENTIAL, 8), (Ctap2.CMD.GET_ASSERTION, 6)):
                self.assert_error(0x31 if set_pin else 0x35,
                                  lambda command=command, key=key: self.client.send_cbor(
                                      command, {key: b""}, on_keepalive=self.touch))

    def retries(self):
        # This subcommand does not require a protocol parameter.
        result = self.client.send_cbor(Ctap2.CMD.CLIENT_PIN, {2: 1})
        return result[3], result[4]

    def key(self):
        return self.client.client_pin(2, 2)[1]

    def inputs(self, new_pin, old_pin=None):
        # Direct requests allow policy/malformed-input tests that library helpers
        # would reject on the platform before sending anything to the authenticator.
        protocol = PinProtocolV2()
        key, shared = protocol.encapsulate(self.key())
        plain = new_pin.encode() if isinstance(new_pin, str) else new_pin
        padded = plain.ljust(64, b"\0")
        encrypted = protocol.encrypt(shared, padded)
        params = {1: 2, 2: 3 if old_pin is None else 4, 3: key, 5: encrypted}
        message = encrypted
        if old_pin is not None:
            params[6] = protocol.encrypt(shared, hashlib.sha256(old_pin.encode()).digest()[:16])
            message += params[6]
        params[4] = protocol.authenticate(shared, message)
        return params

    def set_pin(self, pin):
        self.client.send_cbor(Ctap2.CMD.CLIENT_PIN, self.inputs(pin))

    def change_pin(self, old_pin, new_pin):
        self.client.send_cbor(Ctap2.CMD.CLIENT_PIN, self.inputs(new_pin, old_pin))

    def assert_error(self, status, action):
        with self.assertRaises(CtapError) as caught:
            action()
        self.assertEqual(int(caught.exception.code), status)

    def test_set_change_unicode_and_capability_state(self):
        self.assertEqual(self.retries(), (8, False))
        info = self.client.get_info()
        self.assertFalse(info.options["clientPin"])
        self.assertTrue(info.options["pinUvAuthToken"])
        self.assertNotIn("uv", info.options)
        self.set_pin("😀é12")  # Four code points, eight UTF-8 bytes.
        self.assert_error(0x33, lambda: self.set_pin("5678"))
        self.change_pin("😀é12", "5678")
        self.change_pin("5678", "9012")
        self.assertEqual(self.retries(), (8, False))
        self.assert_error(0x14, lambda: self.client.client_pin(2, 9))
        self.assert_error(0x3E, lambda: self.client.client_pin(2, 5))
        self.assertTrue(self.client.get_info().options["clientPin"])

    def test_invalid_policy_and_request_auth_have_no_retry_effect(self):
        for pin in ("123", "éé", b"\xc0\x8012", b"12\x0034", "a" * 64):
            self.assert_error(0x37, lambda pin=pin: self.set_pin(pin))
        self.set_pin("a" * 63)
        params = self.inputs("5678", "a" * 63)
        params[4] = bytes([params[4][0] ^ 1]) + params[4][1:]
        self.assert_error(0x33, lambda: self.client.send_cbor(Ctap2.CMD.CLIENT_PIN, params))
        self.assertEqual(self.retries(), (8, False))
        params = self.inputs("5678", "a" * 63)
        params[5] = params[5][:-16]
        self.assert_error(2, lambda: self.client.send_cbor(Ctap2.CMD.CLIENT_PIN, params))
        params = self.inputs("5678", "a" * 63)
        params[3][4] = b"unexpected optional COSE key parameter"
        self.assert_error(2, lambda: self.client.send_cbor(Ctap2.CMD.CLIENT_PIN, params))
        self.assertEqual(self.retries(), (8, False))
        self.change_pin("a" * 63, "1234")

    def test_wrong_pin_rotates_key_and_correct_pin_restores_retries(self):
        self.set_pin("1234")
        first = self.key()
        self.assert_error(0x31, lambda: self.change_pin("wrong", "5678"))
        self.assertNotEqual(first, self.key())
        self.assertEqual(self.retries(), (7, False))
        self.assert_error(0x37, lambda: self.change_pin("1234", "123"))
        self.assertEqual(self.retries(), (8, False))
        self.change_pin("1234", "5678")

    def test_retries_persist_power_cycle_unblocks_and_reset_erases(self):
        self.set_pin("1234")
        for cycle, remaining in enumerate((5, 2, 0)):
            count = 3 if cycle < 2 else 2
            for attempt in range(count):
                status = 0x32 if cycle == 2 and attempt == 1 else (0x34 if attempt == 2 else 0x31)
                self.assert_error(status, lambda: self.change_pin("wrong", "5678"))
            self.assertEqual(self.retries(), (remaining, cycle < 2))
            self.assert_error(0x32 if remaining == 0 else 0x34, lambda: self.change_pin("1234", "5678"))
            self.power_on()
            self.assertEqual(self.retries(), (remaining, False))
        self.assert_error(0x32, lambda: self.change_pin("1234", "5678"))
        self.factory_reset()
        self.assertEqual(self.retries(), (8, False))
        self.set_pin("5678")
        self.change_pin("5678", "9012")

    def test_unset_pin_and_malformed_commands(self):
        self.assert_error(0x35, lambda: self.change_pin("1234", "5678"))
        for params, status in (({}, 0x14), ({2: 3}, 0x14), ({1: 1, 2: 2}, 2),
                               ({1: "2", 2: 2}, 0x11), ({1: 2, 2: 4}, 0x14)):
            self.assert_error(status, lambda params=params: self.client.send_cbor(Ctap2.CMD.CLIENT_PIN, params))
        self.assertEqual(self.retries(), (8, False))


class PortableClientPinTests(PinCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = ctypes.CDLL(str(build_pin_core_peer()))

    def setUp(self):
        self.peer = PortablePinPeer(self.library)
        self.client = Ctap2(self.peer)

    def power_on(self):
        self.peer.power_on()
        self.client = Ctap2(self.peer)

    def factory_reset(self):
        self.peer.reset()
        self.client = Ctap2(self.peer)

    def test_exact_initial_and_maximum_token_expiry(self):
        self.set_pin("1234")
        token = self.token(1)
        self.peer.advance(30000)
        self.assert_error(0x33, lambda: self.registration(token))
        credential = self.registration(policy=3)
        token = self.token(2)
        self.peer.advance(29999)
        self.assertEqual(int(self.assertion(credential, token, up=False).flags), 4)
        self.peer.advance(570000)
        self.assertEqual(int(self.assertion(credential, token, up=False).flags), 4)
        self.peer.advance(1)
        self.assert_error(0x33, lambda: self.assertion(credential, token, up=False))


@unittest.skipUnless(os.name == "nt", "Windows CNG/DPAPI provider required")
class WindowsClientPinTests(PinCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.executable = build_harness()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ctaphid-pin-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "vault"
        self.peer = None
        self.addCleanup(lambda: self.peer.close() if self.peer else None)
        self.power_on()

    def power_on(self):
        if self.peer:
            self.peer.close()
        self.peer = open_harness(self.executable, storage_directory=self.directory)
        self.client = Ctap2(self.peer)

    def factory_reset(self):
        self.client.reset(on_keepalive=lambda status: self.peer._connection.confirm_presence()
                          if status == STATUS.UPNEEDED else None)

    def test_pin_verifier_persists_and_vault_remains_sealed(self):
        self.set_pin("portable-pin-1234")
        self.power_on()
        self.change_pin("portable-pin-1234", "5678")
        encrypted = (self.directory / "credentials.vault").read_bytes()
        self.assertEqual(encrypted[:8], b"APCV\0\0\0\4")
        self.assertNotIn(b"5678", encrypted)
        self.assertNotIn(hashlib.sha256(b"5678").digest()[:16], encrypted)

    def test_v1_v2_v3_vaults_upgrade_without_changing_pin_state(self):
        from test_hmac_secret import rewrite_as_legacy_vault

        for version in (1, 2, 3):
            self.factory_reset()
            self.peer.close()
            self.peer = None
            path = self.directory / "credentials.vault"
            rewrite_as_legacy_vault(path, version)
            self.power_on()
            self.assertEqual(self.retries(), (8, False))
            self.set_pin("1234")
            self.assertEqual(path.read_bytes()[:8], b"APCV\0\0\0\4")
            self.power_on()
            self.change_pin("1234", "5678")

    def test_credential_protection_persists_across_reopen(self):
        self.set_pin("1234")
        protected = self.registration(policy=3)
        self.power_on()
        self.assert_error(0x2E, lambda: self.assertion(protected))
        self.assertEqual(int(self.assertion(protected, self.token(2)).flags), 5)

    def test_v3_migration_preserves_an_existing_pin(self):
        from test_hmac_secret import rewrite_as_legacy_vault

        self.set_pin("1234")
        self.peer.close()
        self.peer = None
        rewrite_as_legacy_vault(self.directory / "credentials.vault", 3)
        self.power_on()
        self.assertTrue(self.client.get_info().options["clientPin"])
        self.change_pin("1234", "5678")


if __name__ == "__main__":
    unittest.main()
