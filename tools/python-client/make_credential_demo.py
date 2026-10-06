"""Interactive ES256 registration against the portable C test authenticator.

Run: .venv/Scripts/python.exe tools/python-client/make_credential_demo.py
Add --store-dir PATH to keep the PC vault across runs.
Add --authenticate to request/verify an assertion after registration.
Add --hmac-secret to create and retrieve a credential-bound secret with protocol 2.
"""

import argparse
import hashlib
import secrets
from threading import Event

from fido2.attestation import PackedAttestation
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2

from build_harness import build_harness
from fido2_harness import open_harness


def main():
    parser = argparse.ArgumentParser(description="Test ES256 registration with a simulated touch")
    parser.add_argument("--store-dir", help="Keep credentials in this PC vault directory")
    parser.add_argument("--authenticate", action="store_true", help="Authenticate with the newly created credential")
    parser.add_argument("--hmac-secret", action="store_true", help="Register and test the hmac-secret extension")
    args = parser.parse_args()
    device = open_harness(build_harness(), storage_directory=args.store_dir)
    cancelled = Event()
    action = "Create a credential"

    def prompt(status):
        if status != STATUS.UPNEEDED:
            return
        choice = input(f"{action} for example.com? Enter=touch, d=deny, c=cancel: ").strip().lower()
        if choice == "c":
            cancelled.set()
        elif choice == "d":
            device._connection.deny_presence()
        elif choice == "":
            device._connection.confirm_presence()

    try:
        client_data_hash = hashlib.sha256(secrets.token_bytes(32)).digest()
        client = Ctap2(device, strict_cbor=True)
        result = client.make_credential(client_data_hash,
            {"id": "example.com", "name": "Example"}, {"id": b"demo-user", "name": "Demo"},
            [{"type": "public-key", "alg": -7}], extensions={"hmac-secret": True} if args.hmac_secret else None,
            event=cancelled, on_keepalive=prompt)
        PackedAttestation().verify(result.att_stmt, result.auth_data, client_data_hash)
        print("Created ES256 credential; packed self-attestation signature verified.")
        print("Credential ID:", result.auth_data.credential_data.credential_id.hex())
        print("RP hash:", result.auth_data.rp_id_hash.hex())
        if args.authenticate or args.hmac_secret:
            action = "Authenticate"
            credential = result.auth_data.credential_data
            assertion_hash = hashlib.sha256(secrets.token_bytes(32)).digest()
            extension = None
            if args.hmac_secret:
                protocol = PinProtocolV2()
                peer_key, shared = ClientPin(client, protocol)._get_shared_secret()
                encrypted = protocol.encrypt(shared, secrets.token_bytes(32))
                extension = {"hmac-secret": {1: peer_key, 2: encrypted,
                    3: protocol.authenticate(shared, encrypted), 4: 2}}
            assertion = client.get_assertion("example.com", assertion_hash,
                [{"id": credential.credential_id, "type": "public-key"}], extensions=extension,
                event=cancelled, on_keepalive=prompt)
            assertion.verify(assertion_hash, credential.public_key)
            print("Authentication signature verified; counter:", assertion.auth_data.counter)
            if args.hmac_secret:
                result = protocol.decrypt(shared, assertion.auth_data.extensions["hmac-secret"])
                print("Credential-bound hmac-secret retrieved and decrypted:", len(result), "bytes")
    except CtapError as error:
        print(f"Operation ended: {error}")
    finally:
        device.close()


if __name__ == "__main__":
    main()
