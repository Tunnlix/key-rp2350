"""Register and authenticate through python-fido2; verify real ES256 signatures."""

import hashlib
import tempfile
from threading import Event
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2
from fido2.hid import CTAPHID
from fido2.server import Fido2Server
from fido2.webauthn import (AttestationObject, CollectedClientData, RegistrationResponse,
    AuthenticationResponse, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse,
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, UserVerificationRequirement)

from build_harness import build_harness
from fido2_harness import open_harness


class GetAssertionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.executable = build_harness()

    def setUp(self):
        self.device = open_harness(self.executable)
        self.addCleanup(self.device.close)
        self.connection = self.device._connection
        self.client = Ctap2(self.device, strict_cbor=True)
        self.credential = self.register(self.client, self.connection)
        self.client_hash = hashlib.sha256(b"authentication challenge").digest()

    def register(self, client, connection, rp="example.com"):
        response = client.make_credential(hashlib.sha256(b"registration").digest(), {"id": rp},
            {"id": b"user-1", "name": "alice", "displayName": "Alice"},
            [{"alg": -7, "type": "public-key"}],
            on_keepalive=lambda status: connection.confirm_presence() if status == STATUS.UPNEEDED else None)
        return response.auth_data.credential_data

    def touch(self, status):
        if status == STATUS.UPNEEDED:
            self.assertTrue(self.connection.confirm_presence())

    def descriptor(self, credential=None):
        credential = credential or self.credential
        return {"id": credential.credential_id, "type": "public-key"}

    def request(self):
        return {1: "example.com", 2: self.client_hash, 3: [self.descriptor()]}

    def assert_error(self, request, expected):
        self.connection.received_reports.clear()
        with self.assertRaises(CtapError) as error:
            self.client.send_cbor(Ctap2.CMD.GET_ASSERTION, request)
        self.assertEqual(int(error.exception.code), expected)
        self.assertFalse(any(r[4] == 0xBB for r in self.connection.received_reports))
        self.assertEqual(self.device.ping(b"recovered"), b"recovered")

    def verify_independently(self, response, credential=None, client_hash=None):
        credential = credential or self.credential
        client_hash = client_hash or self.client_hash
        key = credential.public_key
        public = ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], "big"),
            int.from_bytes(key[-3], "big"), ec.SECP256R1()).public_key()
        public.verify(response.signature, bytes(response.auth_data) + client_hash, ec.ECDSA(hashes.SHA256()))
        response.verify(client_hash, key)
        return public

    def test_authenticated_assertion_signature_flags_and_counters(self):
        # A queued simulation event still tagged to registration cannot satisfy
        # the new assertion's gate, even if the old IPC request file is present.
        self.connection.confirm_presence()
        statuses = []

        def confirm(status):
            statuses.append(status)
            self.touch(status)

        for counter in (1, 2):
            assertions = self.client.get_assertions("example.com", self.client_hash, [self.descriptor()], on_keepalive=confirm)
            self.assertEqual(len(assertions), 1)
            response = assertions[0]
            self.assertEqual(response.credential, self.descriptor())
            self.assertEqual(len(response.auth_data), 37)
            self.assertEqual(response.auth_data.rp_id_hash, hashlib.sha256(b"example.com").digest())
            self.assertEqual(int(response.auth_data.flags), 1)
            self.assertEqual(response.auth_data.counter, counter)
            self.assertIsNone(response.user)
            self.assertIsNone(response.number_of_credentials)
            self.assertIsNone(response.user_selected)
            public = self.verify_independently(response)
            with self.assertRaises(InvalidSignature):
                public.verify(response.signature, bytes(response.auth_data) + bytes(32), ec.ECDSA(hashes.SHA256()))
        self.assertEqual(statuses.count(STATUS.UPNEEDED), 2)

    def test_silent_preflight_has_no_touch_and_up_bit_clear(self):
        self.connection.received_reports.clear()
        response = self.client.get_assertion("example.com", self.client_hash, [self.descriptor()], options={"up": False})
        self.assertEqual(int(response.auth_data.flags), 0)
        self.assertEqual(response.auth_data.counter, 1)
        self.assertFalse(any(r[4] == 0xBB for r in self.connection.received_reports))
        self.verify_independently(response)
        # A later normal assertion still requires fresh UP and the next counter.
        response = self.client.get_assertion("example.com", self.client_hash, [self.descriptor()], on_keepalive=self.touch)
        self.assertEqual((int(response.auth_data.flags), response.auth_data.counter), (1, 2))

    def test_wrong_rp_unknown_ids_and_no_discovery(self):
        for request in ({1: "wrong.example", 2: self.client_hash, 3: [self.descriptor()]},
                        {1: "example.com", 2: self.client_hash, 3: [{"type": "public-key", "id": bytes(32)}]},
                        {1: "example.com", 2: self.client_hash, 3: [{"type": "public-key", "id": b"foreign id"}]},
                        {1: "example.com", 2: self.client_hash}):
            self.assert_error(request, 0x2E)
        response = self.client.get_assertion("example.com", self.client_hash, [self.descriptor()], options={"up": False})
        self.assertEqual(response.auth_data.counter, 1)  # Rejected requests never increment it.

    def test_allow_list_selection_validates_every_descriptor(self):
        other = self.register(self.client, self.connection)
        foreign = self.register(self.client, self.connection, "other.example")
        allow = [{"id": b"foreign-id", "type": "public-key"}, self.descriptor(foreign),
                 {"id": self.credential.credential_id, "type": "future-type"}, self.descriptor(other), self.descriptor()]
        response = self.client.get_assertion("example.com", self.client_hash, allow, on_keepalive=self.touch)
        self.assertEqual(response.credential, self.descriptor(other))
        self.assertIsNone(response.number_of_credentials)  # allowList returns exactly one assertion.
        self.verify_independently(response, other)
        request = self.request()
        request[3].append({"type": "public-key", "id": False})
        self.assert_error(request, 0x11)
        response = self.client.get_assertion("example.com", self.client_hash, [self.descriptor()], options={"up": False})
        self.assertEqual(response.auth_data.counter, 1)

    def test_canonical_response_and_unknown_fields(self):
        request = self.request()
        request[3][0]["transports"] = ["usb", "future-transport"]
        request[3][0]["future"] = True
        request[4] = {"future-extension": {"enabled": True}}
        request[5] = {"up": True, "uv": False, "future-option": 42}
        request[99] = [[True]]
        reply = self.device.call(CTAPHID.CBOR, b"\x02" + cbor.encode(request), on_keepalive=self.touch)
        self.assertEqual(reply[0], 0)
        decoded = cbor.decode(reply[1:])
        self.assertEqual(set(decoded), {1, 2, 3})
        self.assertEqual(cbor.encode(decoded), reply[1:])
        self.assertEqual(set(decoded[1]), {"id", "type"})

    def test_parameter_validation_and_unsupported_features(self):
        for missing in (1, 2):
            request = self.request()
            del request[missing]
            self.assert_error(request, 0x14)
        cases = [(1, b"example.com", 0x11), (1, "", 2), (2, "hash", 0x11), (2, bytes(31), 3),
                 (3, {}, 0x11), (3, [], 2), (3, [False], 0x11),
                 (3, [{"id": self.credential.credential_id}], 0x11),
                 (3, [{"type": "public-key", "id": self.credential.credential_id, "transports": [1]}], 0x11),
                 (4, [], 0x11), (5, [], 0x11), (5, {"rk": False}, 0x2B), (5, {"rk": True}, 0x2B),
                 (5, {"uv": True}, 0x2C), (5, {"up": 0}, 0x11), (6, b"", 0x14), (7, "1", 0x11)]
        for key, value, expected in cases:
            with self.subTest(key=key, value=value):
                request = self.request()
                request[key] = value
                self.assert_error(request, expected)
        request = self.request()
        request[6], request[7] = bytes(16), 1
        self.assert_error(request, 2)
        response = self.client.get_assertion("example.com", self.client_hash, [self.descriptor()], options={"up": False})
        self.assertEqual(response.auth_data.counter, 1)

    def test_malformed_cbor_is_rejected_before_touch(self):
        valid = cbor.encode(self.request())
        for data in (valid[:-1], valid + b"\x00", b"\xbf\xff", b"\xa2\x01\x00\x01\x00",
                     b"\xa1\x18\x01\x00", b"\xa1\x01\xc0\x00", b"\xa1\x01\x62\xc0\xaf"):
            with self.subTest(data=data):
                self.assertEqual(self.device.call(CTAPHID.CBOR, b"\x02" + data), b"\x12")

    def test_cancel_and_denial_preserve_counter(self):
        cancelled = Event()
        with self.assertRaises(CtapError) as error:
            self.client.get_assertion("example.com", self.client_hash, [self.descriptor()],
                event=cancelled, on_keepalive=lambda _: cancelled.set())
        self.assertEqual(int(error.exception.code), 0x2D)
        with self.assertRaises(CtapError) as error:
            self.client.get_assertion("example.com", self.client_hash, [self.descriptor()],
                on_keepalive=lambda _: self.connection.deny_presence())
        self.assertEqual(int(error.exception.code), 0x27)
        response = self.client.get_assertion("example.com", self.client_hash, [self.descriptor()], on_keepalive=self.touch)
        self.assertEqual(response.auth_data.counter, 1)
        self.verify_independently(response)

    def test_reopen_preserves_counter_and_reset_invalidates_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            credential = None
            for expected in (1, 2):
                peer = open_harness(self.executable, storage_directory=directory)
                try:
                    client = Ctap2(peer, strict_cbor=True)
                    if credential is None:
                        credential = self.register(client, peer._connection)
                    response = client.get_assertion("example.com", self.client_hash, [self.descriptor(credential)],
                        on_keepalive=lambda _: peer._connection.confirm_presence())
                    self.assertEqual(response.auth_data.counter, expected)
                    self.verify_independently(response, credential)
                    if expected == 2:
                        client.reset(on_keepalive=lambda _: peer._connection.confirm_presence())
                        with self.assertRaises(CtapError) as error:
                            client.get_assertion("example.com", self.client_hash, [self.descriptor(credential)])
                        self.assertEqual(int(error.exception.code), 0x2E)
                finally:
                    peer.close()

    def test_webauthn_server_accepts_registration_and_authentication(self):
        # Supply the browser's clientData in the test, then let the genuine
        # server validate challenge, origin, RP hash, UP and the signature.
        server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="Example"))
        options, state = server.register_begin(PublicKeyCredentialUserEntity(id=b"user", name="alice"),
            user_verification=UserVerificationRequirement.DISCOURAGED)
        client_data = CollectedClientData.create("webauthn.create", options.public_key.challenge, "https://example.com")
        created = self.client.make_credential(client_data.hash, {"id": "example.com"}, {"id": b"user"},
            [{"type": "public-key", "alg": -7}], on_keepalive=self.touch)
        registered = server.register_complete(state, RegistrationResponse(
            raw_id=created.auth_data.credential_data.credential_id,
            response=AuthenticatorAttestationResponse(client_data=client_data,
                attestation_object=AttestationObject.create(created.fmt, created.auth_data, created.att_stmt))))
        credential = registered.credential_data
        options, state = server.authenticate_begin([credential], user_verification=UserVerificationRequirement.DISCOURAGED)
        client_data = CollectedClientData.create("webauthn.get", options.public_key.challenge, "https://example.com")
        assertion = self.client.get_assertion("example.com", client_data.hash,
            [self.descriptor(credential)], on_keepalive=self.touch)
        authenticated = server.authenticate_complete(state, [credential], AuthenticationResponse(
            raw_id=assertion.credential["id"], response=AuthenticatorAssertionResponse(
                client_data=client_data, authenticator_data=assertion.auth_data, signature=assertion.signature)))
        self.assertEqual(authenticated.credential_id, credential.credential_id)
        self.assertEqual(assertion.auth_data.counter, 1)


if __name__ == "__main__":
    unittest.main()
