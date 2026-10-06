"""Interactive ES256 registration against the portable C test authenticator.

Run: .venv/Scripts/python.exe tools/python-client/make_credential_demo.py
Add --store-dir PATH to keep the PC vault across runs.
"""

import argparse
import hashlib
import secrets
from threading import Event

from fido2.attestation import PackedAttestation
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2

from build_harness import build_harness
from fido2_harness import open_harness


def main():
    parser = argparse.ArgumentParser(description="Test ES256 registration with a simulated touch")
    parser.add_argument("--store-dir", help="Keep credentials in this PC vault directory")
    args = parser.parse_args()
    device = open_harness(build_harness(), storage_directory=args.store_dir)
    cancelled = Event()

    def prompt(status):
        if status != STATUS.UPNEEDED:
            return
        choice = input("Create a credential for example.com? Enter=touch, d=deny, c=cancel: ").strip().lower()
        if choice == "c":
            cancelled.set()
        elif choice == "d":
            device._connection.deny_presence()
        elif choice == "":
            device._connection.confirm_presence()

    try:
        client_data_hash = hashlib.sha256(secrets.token_bytes(32)).digest()
        result = Ctap2(device, strict_cbor=True).make_credential(client_data_hash,
            {"id": "example.com", "name": "Example"}, {"id": b"demo-user", "name": "Demo"},
            [{"type": "public-key", "alg": -7}], event=cancelled, on_keepalive=prompt)
        PackedAttestation().verify(result.att_stmt, result.auth_data, client_data_hash)
        print("Created ES256 credential; packed self-attestation signature verified.")
        print("Credential ID:", result.auth_data.credential_data.credential_id.hex())
        print("RP hash:", result.auth_data.rp_id_hash.hex())
    except CtapError as error:
        print(f"Registration ended: {error}")
    finally:
        device.close()


if __name__ == "__main__":
    main()
