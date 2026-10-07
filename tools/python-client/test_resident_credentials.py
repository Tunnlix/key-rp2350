"""Discoverable credentials and management using genuine python-fido2 requests.

Portable tests exercise C with real cryptographic providers in the test bridge;
Windows tests exercise the actual subprocess HID transport and persistent vault.
"""
import ctypes
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from fido2.ctap2 import Ctap2
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import PinProtocolV2
from fido2.webauthn import PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity
from fido2.server import Fido2Server
from fido2.webauthn import (PublicKeyCredentialRpEntity, CollectedClientData, RegistrationResponse,
    AuthenticationResponse, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse,
    AttestationObject, UserVerificationRequirement)

from build_harness import build_harness, build_pin_core_peer
from fido2_harness import open_harness
from test_client_pin import PinCases, PortablePinPeer


class ResidentCases:
    client_hash = PinCases.client_hash
    token = PinCases.token
    touch = PinCases.touch
    set_pin = PinCases.set_pin
    inputs = PinCases.inputs
    key = PinCases.key
    assert_error = PinCases.assert_error

    def resident(self, user=b"alice", rp="example.com", policy=1, verified=True,
                 name="Alice", display="Alice Example"):
        token = self.token(1, rp) if verified else None
        result = self.client.make_credential(
            self.client_hash, {"id": rp, "name": "Example RP"},
            {"id": user, "name": name, "displayName": display}, [{"type": "public-key", "alg": -7}],
            extensions={"credProtect": policy, "hmac-secret": True}, options={"rk": True},
            pin_uv_param=PinProtocolV2().authenticate(token, self.client_hash) if token else None,
            pin_uv_protocol=2 if token else None, on_keepalive=self.touch)
        credential = result.auth_data.credential_data
        credential.public_key.verify(bytes(result.auth_data) + self.client_hash, result.att_stmt["sig"])
        return credential

    def discover(self, token=None, rp="example.com"):
        return self.client.get_assertions(rp, self.client_hash,
            pin_uv_param=PinProtocolV2().authenticate(token, self.client_hash) if token else None,
            pin_uv_protocol=2 if token else None, on_keepalive=self.touch)

    def manager(self, rp=None, permissions=4):
        return CredentialManagement(Ctap2(self.peer), PinProtocolV2(), self.token(permissions, rp))

    @staticmethod
    def descriptor(credential):
        return PublicKeyCredentialDescriptor(type="public-key", id=credential.credential_id)

    def test_discovery_newest_first_user_handles_and_real_signatures(self):
        alice = self.resident(b"alice", policy=3)
        bob = self.resident(b"bob", name="Bob", display="Bob Example", policy=2)
        self.resident(b"other", rp="other.example")
        responses = self.discover(self.token(2))
        self.assertEqual(len(responses), 2)
        for response, credential, user in zip(responses, (bob, alice), (b"bob", b"alice")):
            self.assertEqual(response.credential["id"], credential.credential_id)
            self.assertEqual(response.user["id"], user)
            self.assertIn("name", response.user)
            self.assertEqual(int(response.auth_data.flags), 5)
            self.assertEqual(response.auth_data.counter, 1)
            credential.public_key.verify(bytes(response.auth_data) + self.client_hash, response.signature)
        self.assertEqual(responses[0].number_of_credentials, 2)
        self.assertIsNone(responses[1].number_of_credentials)
        self.assert_error(0x30, self.client.get_next_assertion)
        info = self.client.get_info()
        self.assertEqual(info.min_pin_length, 4)
        self.assertTrue(info.options["rk"])
        self.assertTrue(info.options["credMgmt"])

    def test_unauthenticated_discovery_filters_policies_and_names(self):
        visible = self.resident(b"visible", policy=1)
        self.resident(b"list-only", policy=2)
        self.resident(b"verified-only", policy=3)
        results = self.discover()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].user, {"id": b"visible"})
        self.assertEqual(results[0].credential["id"], visible.credential_id)
        self.assertEqual(int(results[0].auth_data.flags), 1)
        self.assert_error(0x2E, lambda: self.discover(rp="missing.example"))

    def test_same_account_replacement_is_atomic_and_invalidates_old_id(self):
        old = self.resident(b"same")
        newer = self.resident(b"same", name="Updated")
        self.assertNotEqual(old.credential_id, newer.credential_id)
        self.assert_error(0x2E, lambda: self.client.get_assertion("example.com", self.client_hash,
            [{"type": "public-key", "id": old.credential_id}], options={"up": False}))
        self.assertEqual(self.manager().get_metadata()[1], 1)
        results = self.discover(self.token(2))
        self.assertEqual(results[0].credential["id"], newer.credential_id)
        self.assertEqual(results[0].user, {"id": b"same"})
        self.assertEqual(results[0].auth_data.counter, 1)

    def test_replacement_at_capacity_and_new_account_capacity_failure(self):
        capacity = self.manager().get_metadata()[2]
        for i in range(capacity):
            self.resident(bytes([i]))
        self.assert_error(0x28, lambda: self.resident(b"extra"))
        replaced = self.resident(bytes([0]))
        results = self.discover(self.token(2))
        self.assertEqual(len(results), capacity)
        self.assertEqual(results[0].credential["id"], replaced.credential_id)
        manager = self.manager()
        self.assertEqual(manager.get_metadata()[1], capacity)
        self.assertEqual(manager.get_metadata()[2], 0)

    def test_credential_management_metadata_rps_and_credentials(self):
        first = self.resident(b"first", policy=2)
        second = self.resident(b"second", policy=3)
        self.resident(b"foreign", rp="other.example")
        manager = self.manager()
        self.assertEqual(manager.get_metadata()[1], 3)
        rps = manager.enumerate_rps()
        self.assertEqual({entry[3]["id"] for entry in rps}, {"example.com", "other.example"})
        credentials = manager.enumerate_creds(hashlib.sha256(b"example.com").digest())
        self.assertEqual({entry[7]["id"] for entry in credentials}, {first.credential_id, second.credential_id})
        keys = {first.credential_id: first.public_key, second.credential_id: second.public_key}
        for entry in credentials:
            self.assertEqual(entry[8], keys[entry[7]["id"]])
            self.assertIn(entry[10], (2, 3))
            self.assertIn("name", entry[6])
        self.assertEqual(manager.enumerate_creds(bytes(32)), [])

    def test_update_user_information_and_delete_credential(self):
        credential = self.resident(b"account")
        manager = self.manager()
        manager.update_user_info(self.descriptor(credential), PublicKeyCredentialUserEntity(
            id=b"account", name="Renamed", display_name="New Display"))
        result = self.discover(self.token(2))[0]
        self.assertEqual(result.user, {"id": b"account"})
        self.assertEqual(self.manager().enumerate_creds(hashlib.sha256(b"example.com").digest())[0][6],
            {"id": b"account", "name": "Renamed", "displayName": "New Display"})
        manager = self.manager()
        self.assert_error(2, lambda: manager.update_user_info(self.descriptor(credential),
            PublicKeyCredentialUserEntity(id=b"different", name="bad")))
        manager.update_user_info(self.descriptor(credential), PublicKeyCredentialUserEntity(id=b"account"))
        self.assertEqual(manager.enumerate_creds(hashlib.sha256(b"example.com").digest())[0][6], {"id": b"account"})
        manager.delete_cred(self.descriptor(credential))
        self.assertEqual(manager.get_metadata()[1], 0)
        self.assert_error(0x2E, lambda: manager.delete_cred(self.descriptor(credential)))
        self.assert_error(0x2E, lambda: self.discover())

    def test_scoped_management_cannot_enumerate_or_modify_other_rp(self):
        own = self.resident(b"own")
        other = self.resident(b"other", rp="other.example")
        manager = self.manager("example.com")
        self.assert_error(0x33, manager.get_metadata)
        self.assert_error(0x33, manager.enumerate_rps)
        self.assert_error(0x33, lambda: manager.enumerate_creds(hashlib.sha256(b"example.com").digest()))
        self.assert_error(0x33, lambda: manager.delete_cred(self.descriptor(other)))
        manager.delete_cred(self.descriptor(own))
        self.assertEqual(self.manager().get_metadata()[1], 1)

    def test_management_authentication_and_user_validation(self):
        credential = self.resident()
        self.assert_error(0x36, lambda: self.client.credential_mgmt(1))
        token = self.token(4, None)
        self.assert_error(0x33, lambda: CredentialManagement(Ctap2(self.peer), PinProtocolV2(), bytes(32)).get_metadata())
        # A correctly authenticated but malformed user map cannot mutate records.
        params = {2: {"id": credential.credential_id, "type": "public-key"}, 3: {"id": b"alice", "name": 4}}
        from fido2 import cbor
        mac = PinProtocolV2().authenticate(token, b"\x07" + cbor.encode(params))
        self.assert_error(0x11, lambda: self.client.credential_mgmt(7, params, 2, mac))
        self.assertEqual(self.manager().get_metadata()[1], 1)

    def test_unicode_names_are_truncated_without_splitting_code_points(self):
        self.resident(name="é" * 40, display="😀" * 20)
        user = self.manager().enumerate_creds(hashlib.sha256(b"example.com").digest())[0][6]
        self.assertEqual(user["name"], "é" * 32)
        self.assertEqual(user["displayName"], "😀" * 16)

    def test_full_rp_identifier_is_retained_and_bound(self):
        rp = "custom:" + "a" * 700 + ".example"
        self.resident(rp=rp)
        entry = self.manager().enumerate_rps()[0]
        self.assertEqual(entry[3]["id"], rp)
        self.assertEqual(entry[4], hashlib.sha256(rp.encode()).digest())

    def test_webauthn_server_accepts_discovery_with_required_uv(self):
        server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="Example"))
        options, state = server.register_begin(PublicKeyCredentialUserEntity(id=b"user", name="alice"),
            user_verification=UserVerificationRequirement.REQUIRED)
        client_data = CollectedClientData.create("webauthn.create", options.public_key.challenge, "https://example.com")
        token = self.token(1)
        created = self.client.make_credential(client_data.hash, {"id": "example.com"}, {"id": b"user", "name": "alice"},
            [{"type": "public-key", "alg": -7}], options={"rk": True},
            pin_uv_param=PinProtocolV2().authenticate(token, client_data.hash), pin_uv_protocol=2, on_keepalive=self.touch)
        registered = server.register_complete(state, RegistrationResponse(
            raw_id=created.auth_data.credential_data.credential_id,
            response=AuthenticatorAttestationResponse(client_data=client_data,
                attestation_object=AttestationObject.create(created.fmt, created.auth_data, created.att_stmt))))
        credential = registered.credential_data
        options, state = server.authenticate_begin(user_verification=UserVerificationRequirement.REQUIRED)
        self.assertFalse(options.public_key.allow_credentials)
        client_data = CollectedClientData.create("webauthn.get", options.public_key.challenge, "https://example.com")
        token = self.token(2)
        assertion = self.client.get_assertion("example.com", client_data.hash,
            pin_uv_param=PinProtocolV2().authenticate(token, client_data.hash), pin_uv_protocol=2, on_keepalive=self.touch)
        authenticated = server.authenticate_complete(state, [credential], AuthenticationResponse(
            raw_id=assertion.credential["id"], response=AuthenticatorAssertionResponse(
                client_data=client_data, authenticator_data=assertion.auth_data, signature=assertion.signature,
                user_handle=assertion.user["id"])))
        self.assertEqual(authenticated.credential_id, credential.credential_id)
        self.assertEqual(assertion.user["id"], b"user")

    def test_hmac_secret_outputs_across_next_assertions(self):
        first = self.resident(b"first", policy=3)
        second = self.resident(b"second", policy=3)
        protocol = PinProtocolV2()
        key, shared = protocol.encapsulate(self.key())
        encrypted = protocol.encrypt(shared, hashlib.sha256(b"resident salts").digest())
        extension = {1: key, 2: encrypted, 3: protocol.authenticate(shared, encrypted), 4: 2}
        token = self.token(2)
        results = self.client.get_assertions("example.com", self.client_hash,
            extensions={"hmac-secret": extension}, pin_uv_param=protocol.authenticate(token, self.client_hash),
            pin_uv_protocol=2, on_keepalive=self.touch)
        outputs = []
        for result, credential in zip(results, (second, first)):
            self.assertEqual(int(result.auth_data.flags), 0x85)
            credential.public_key.verify(bytes(result.auth_data) + self.client_hash, result.signature)
            outputs.append(protocol.decrypt(shared, result.auth_data.extensions["hmac-secret"]))
        self.assertNotEqual(outputs[0], outputs[1])

    def test_hmac_secret_mc_matches_assertion_for_both_credential_types(self):
        protocol = PinProtocolV2()
        self.assertIn("hmac-secret-mc", self.client.get_info().extensions)
        for resident in (False, True):
            for verified in (False, True):
                with self.subTest(resident=resident, verified=verified):
                    self.factory_reset()
                    if verified:
                        self.set_pin("1234")
                    key, shared = protocol.encapsulate(self.key())
                    salts = hashlib.sha256(b"salt one").digest()
                    if verified:
                        salts += hashlib.sha256(b"salt two").digest()
                    encrypted = protocol.encrypt(shared, salts)
                    extension = {1: key, 2: encrypted, 3: protocol.authenticate(shared, encrypted), 4: 2}
                    token = self.token(1) if verified else None
                    created = self.client.make_credential(self.client_hash, {"id": "example.com"},
                        {"id": b"mc-secret"}, [{"type": "public-key", "alg": -7}],
                        extensions={"hmac-secret": True, "hmac-secret-mc": extension, "credProtect": 1},
                        options={"rk": resident},
                        pin_uv_param=protocol.authenticate(token, self.client_hash) if token else None,
                        pin_uv_protocol=2 if token else None, on_keepalive=self.touch)
                    data = created.auth_data
                    credential = data.credential_data
                    credential.public_key.verify(bytes(data) + self.client_hash, created.att_stmt["sig"])
                    self.assertEqual(int(data.flags), 0xC5 if verified else 0xC1)
                    self.assertIs(data.extensions["hmac-secret"], True)
                    self.assertEqual(data.extensions["credProtect"], 1)
                    output = protocol.decrypt(shared, data.extensions["hmac-secret-mc"])
                    self.assertEqual(len(output), len(salts))
                    token = self.token(2) if verified else None
                    assertion = self.client.get_assertion("example.com", self.client_hash,
                        [{"type": "public-key", "id": credential.credential_id}],
                        extensions={"hmac-secret": extension},
                        pin_uv_param=protocol.authenticate(token, self.client_hash) if token else None,
                        pin_uv_protocol=2 if token else None, on_keepalive=self.touch)
                    credential.public_key.verify(bytes(assertion.auth_data) + self.client_hash, assertion.signature)
                    if resident:
                        self.assertEqual(assertion.user, {"id": b"mc-secret"})
                    self.assertEqual(output, protocol.decrypt(shared, assertion.auth_data.extensions["hmac-secret"]))

    def test_hmac_secret_mc_invalid_input_preserves_resident_credential(self):
        original = self.resident(b"same")
        protocol = PinProtocolV2()
        key, shared = protocol.encapsulate(self.key())
        encrypted = protocol.encrypt(shared, bytes(32))
        extension = {1: key, 2: encrypted, 3: protocol.authenticate(shared, encrypted), 4: 2}
        cases = [
            (0x14, {"hmac-secret-mc": extension}),
            (0x14, {"hmac-secret": False, "hmac-secret-mc": extension}),
            (0x11, {"hmac-secret": True, "hmac-secret-mc": True}),
            (0x02, {"hmac-secret": True, "hmac-secret-mc": extension | {2: bytes(47)}}),
            (0x33, {"hmac-secret": True, "hmac-secret-mc": extension | {3: bytes(32)}}),
        ]
        for status, extensions in cases:
            with self.subTest(status=status):
                token = self.token(1)
                self.assert_error(status, lambda: self.client.make_credential(self.client_hash,
                    {"id": "example.com"}, {"id": b"same"}, [{"type": "public-key", "alg": -7}],
                    extensions=extensions, options={"rk": True},
                    pin_uv_param=protocol.authenticate(token, self.client_hash), pin_uv_protocol=2,
                    on_keepalive=self.touch))
                self.assertEqual(self.discover()[0].credential["id"], original.credential_id)

    def test_resident_registration_requires_uv_once_pin_is_set(self):
        self.assert_error(0x36, lambda: self.resident(verified=False))
        self.factory_reset()
        credential = self.resident(verified=False)
        self.assertEqual(self.discover()[0].credential["id"], credential.credential_id)


class PortableResidentTests(ResidentCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = ctypes.CDLL(str(build_pin_core_peer()))

    def setUp(self):
        self.peer = PortablePinPeer(self.library)
        self.client = Ctap2(self.peer)
        self.set_pin("1234")

    def factory_reset(self):
        self.peer.reset()
        self.client = Ctap2(self.peer)

    def test_assertion_sequence_timeout_and_intervening_command(self):
        for i in range(3):
            self.resident(bytes([i]))
        token = self.token(2)
        first = self.client.get_assertion("example.com", self.client_hash,
            pin_uv_param=PinProtocolV2().authenticate(token, self.client_hash), pin_uv_protocol=2, on_keepalive=self.touch)
        self.assertEqual(first.number_of_credentials, 3)
        self.peer.advance(30000)
        self.assertIsNone(self.client.get_next_assertion().number_of_credentials)
        self.peer.advance(30001)
        self.assert_error(0x30, self.client.get_next_assertion)
        token = self.token(2)
        self.client.get_assertion("example.com", self.client_hash,
            pin_uv_param=PinProtocolV2().authenticate(token, self.client_hash), pin_uv_protocol=2, on_keepalive=self.touch)
        self.client.get_info()
        self.assert_error(0x30, self.client.get_next_assertion)

    def test_management_continuation_timeout_and_token_replacement(self):
        self.resident(rp="first.example")
        self.resident(rp="second.example")
        manager = self.manager()
        self.assertEqual(manager.enumerate_rps_begin()[5], 2)
        self.peer.advance(30001)
        self.assert_error(0x30, manager.enumerate_rps_next)
        manager = self.manager()
        manager.enumerate_rps_begin()
        self.token(4, None)
        self.assert_error(0x30, manager.enumerate_rps_next)


@unittest.skipUnless(os.name == "nt", "Windows CNG/DPAPI provider required")
class WindowsResidentTests(ResidentCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.executable = build_harness()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ctaphid-resident-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "vault"
        self.peer = open_harness(self.executable, storage_directory=self.directory)
        self.addCleanup(lambda: self.peer.close())
        self.client = Ctap2(self.peer)
        self.set_pin("1234")

    def factory_reset(self):
        self.client.reset(on_keepalive=self.touch)

    def test_resident_metadata_and_management_persist(self):
        credential = self.resident()
        self.peer.close()
        self.peer = open_harness(self.executable, storage_directory=self.directory)
        self.client = Ctap2(self.peer)
        result = self.discover(self.token(2))[0]
        self.assertEqual(result.credential["id"], credential.credential_id)
        self.assertEqual(result.user, {"id": b"alice"})
        self.assertEqual(self.manager().enumerate_creds(hashlib.sha256(b"example.com").digest())[0][6]["name"], "Alice")
        self.manager().delete_cred(self.descriptor(credential))
        self.peer.close()
        self.peer = open_harness(self.executable, storage_directory=self.directory)
        self.client = Ctap2(self.peer)
        self.assertEqual(self.manager().get_metadata()[1], 0)
        self.assertEqual((self.directory / "credentials.vault").read_bytes()[:8], b"APCV\0\0\0\5")


if __name__ == "__main__":
    unittest.main()
