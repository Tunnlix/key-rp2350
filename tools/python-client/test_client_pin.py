"""Development PIN maintenance: genuine python-fido2 protocol 2 inputs.

Portable tests call the C handler with Python cryptographic callbacks; Windows
integration tests use actual HID framing, CNG and the DPAPI persistent vault.
PIN capability stays absent until token authorization/credProtect are complete.
"""
import ctypes
import hashlib
import hmac
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid import CAPABILITY, CTAPHID

from build_harness import build_harness, build_pin_core_peer
from fido2_harness import open_harness


Primitive = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_uint, ctypes.c_void_p, ctypes.c_size_t,
                            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t)


class PortablePinPeer:
    capabilities = CAPABILITY.CBOR

    def __init__(self, library):
        self.lib = library
        self.errors = []
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
            if op == 1:
                result = hashlib.sha256(first).digest()
            elif op == 2:
                result = self.key.public_key().public_bytes(serialization.Encoding.X962,
                                                            serialization.PublicFormat.UncompressedPoint)
            elif op == 3:
                peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), first)
                result = self.key.exchange(ec.ECDH(), peer)
            elif op == 4:
                result = hmac.digest(first, second, "sha256")
            elif op == 5:
                decryptor = Cipher(algorithms.AES(first), modes.CBC(second[:16])).decryptor()
                result = decryptor.update(second[16:]) + decryptor.finalize()
            elif op == 6:
                self.key = ec.generate_private_key(ec.SECP256R1())
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


class PinCases:
    def retries(self):
        # This subcommand does not require a protocol parameter.
        result = self.client.send_cbor(Ctap2.CMD.CLIENT_PIN, {2: 1})
        return result[3], result[4]

    def key(self):
        return self.client.client_pin(2, 2)[1]

    def inputs(self, new_pin, old_pin=None):
        # ClientPin.set_pin/change_pin deliberately refuse unadvertised support.
        # Exercise the development commands directly using the same real library
        # protocol implementation; never modify GetInfo to bypass feature checks.
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

    def test_set_change_unicode_and_no_capability_claim(self):
        self.assertEqual(self.retries(), (8, False))
        for option in ("clientPin", "uv", "pinUvAuthToken"):
            self.assertNotIn(option, self.client.get_info().options)
        self.set_pin("😀é12")  # Four code points, eight UTF-8 bytes.
        self.assert_error(0x33, lambda: self.set_pin("5678"))
        self.change_pin("😀é12", "5678")
        self.change_pin("5678", "9012")
        self.assertEqual(self.retries(), (8, False))
        self.assert_error(0x3E, lambda: self.client.client_pin(2, 9))
        self.assert_error(0x3E, lambda: self.client.client_pin(2, 5))
        self.assertNotIn("clientPin", self.client.get_info().options)

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
        self.assertEqual(encrypted[:8], b"APCV\0\0\0\3")
        self.assertNotIn(b"5678", encrypted)
        self.assertNotIn(hashlib.sha256(b"5678").digest()[:16], encrypted)

    def test_v1_v2_vaults_start_without_pin_and_upgrade_on_write(self):
        from test_hmac_secret import rewrite_as_legacy_vault

        for version in (1, 2):
            self.factory_reset()
            self.peer.close()
            self.peer = None
            path = self.directory / "credentials.vault"
            rewrite_as_legacy_vault(path, version)
            self.power_on()
            self.assertEqual(self.retries(), (8, False))
            self.set_pin("1234")
            self.assertEqual(path.read_bytes()[:8], b"APCV\0\0\0\3")
            self.power_on()
            self.change_pin("1234", "5678")


if __name__ == "__main__":
    unittest.main()
