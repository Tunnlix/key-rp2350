"""Independent verification of persistent PC crypto/storage and CTAP reset.

Run: .venv/Scripts/python.exe -m unittest discover -s tools/python-client -p test_*.py -v
All files/keys are owned by private temporary test directories.
"""

from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fido2.ctap import STATUS
from fido2.ctap2 import Ctap2

from build_harness import build_harness, build_provider_test_driver
from fido2_harness import open_harness


@unittest.skipUnless(os.name == "nt", "Current PC provider is Windows CNG/DPAPI")
class PcProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = build_harness()
        cls.driver = build_provider_test_driver()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ctaphid-vault-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "vault"

    def run_driver(self, command, expected=0):
        result = subprocess.run([str(self.driver), command, str(self.directory)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def verify_signature(self, signed):
        digest = bytes.fromhex(signed["digest"])
        self.assertEqual(digest, hashlib.sha256(b"portable authenticator test").digest())
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(signed["public_key"]))
        signature = bytes.fromhex(signed["signature"])
        public.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        with self.assertRaises(InvalidSignature):
            public.verify(signature, hashlib.sha256(b"different data").digest(), ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    def test_persistence_and_independent_ecdsa_verification(self):
        first = self.run_driver("create")
        second = self.run_driver("reopen")
        self.verify_signature(first)
        self.verify_signature(second)
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(first["key_handle"], second["key_handle"])
        self.assertEqual(first["public_key"], second["public_key"])
        self.assertEqual((first["counter"], second["counter"]), (1, 2))
        encrypted = (self.directory / "credentials.vault").read_bytes()
        self.assertEqual(encrypted[:4], b"APCV")
        self.assertNotIn(b"portable-user-id", encrypted)
        self.assertNotIn(bytes.fromhex(first["key_handle"]), encrypted)

    def test_metadata_and_key_deletion(self):
        self.run_driver("create")
        self.assertEqual(self.run_driver("delete"), {"credential_count": 0, "key_count": 0})
        self.assertEqual(self.run_driver("status")["credential_count"], 0)

    def test_backend_capacity_binding_and_atomic_reset(self):
        self.assertEqual(self.run_driver("exercise"), {"exercise": "passed"})

    def test_exclusive_vault_lock(self):
        self.assertEqual(self.run_driver("lock"), {"lock": "passed"})
        device = open_harness(self.harness, storage_directory=self.directory)
        try:
            self.assertEqual(self.run_driver("status", expected=28)["open_status"], 8)
        finally:
            device.close()

    def test_corrupt_vault_fails_closed(self):
        self.run_driver("create")
        path = self.directory / "credentials.vault"
        corrupted = bytearray(path.read_bytes())
        corrupted[-17] ^= 0x80
        path.write_bytes(corrupted)
        self.assertEqual(self.run_driver("status", expected=26)["open_status"], 6)
        self.assertEqual(path.read_bytes(), corrupted)  # Never replace corruption with an empty vault.
        path.write_bytes(b"truncated")
        self.assertEqual(self.run_driver("status", expected=26)["open_status"], 6)
        self.assertEqual(path.read_bytes(), b"truncated")

    def test_real_ctap_reset_erases_persistent_credentials_and_keys(self):
        self.run_driver("create")
        device = open_harness(self.harness, storage_directory=self.directory)
        try:
            client = Ctap2(device)
            before = device._connection.storage_state()
            self.assertEqual((before["credential_count"], before["key_count"]), (1, 1))
            client.reset(on_keepalive=lambda status: device._connection.confirm_presence() if status == STATUS.UPNEEDED else None)
            after = device._connection.storage_state()
            self.assertEqual((after["credential_count"], after["key_count"]), (0, 0))
            self.assertNotEqual(before["device_identifier"], after["device_identifier"])
            self.assertEqual(after["generation"], before["generation"] + 1)
        finally:
            device.close()
        self.assertEqual(self.run_driver("status"), {"credential_count": 0, "key_count": 0, "generation": 1})


if __name__ == "__main__":
    unittest.main()
