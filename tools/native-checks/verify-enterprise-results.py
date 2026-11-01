#!/usr/bin/env python3
"""Independently verify public native-test enterprise replies (cryptography, fido2)."""
import argparse
import hashlib
import json
from pathlib import Path
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.webauthn import AuthenticatorData

p=argparse.ArgumentParser(description=__doc__);p.add_argument('identity',type=Path);p.add_argument('replies',type=Path);p.add_argument('--batch-identity',type=Path);a=p.parse_args()
root=x509.load_pem_x509_certificate((a.identity/'lab-ca.pem').read_bytes())
leaf=x509.load_pem_x509_certificate((a.identity/'attestation.pem').read_bytes())
root.public_key().verify(leaf.signature,leaf.tbs_certificate_bytes,ec.ECDSA(leaf.signature_hash_algorithm))
expected=bytes.fromhex('fa024a59a2a641d9bd40ed6a78915bca')
def check_credential(path,data):
    _,protocol,resident,ed,mode=path.stem.split('-')
    credential=AuthenticatorData(data).credential_data
    assert credential is not None
    assert credential.public_key[3]==(-8 if ed=='1' else -7)
    assert len(credential.credential_id)==(32 if resident=='1' else 256)

count=0
for path in sorted(a.replies.glob('reply-*.cbor')):
    response=cbor.decode(path.read_bytes());assert response[1]=='packed' and response[4] is True
    data=response[2];check_credential(path,data);statement=response[3];assert statement['alg']==-7 and len(statement['x5c'])==1
    cert=x509.load_der_x509_certificate(statement['x5c'][0])
    assert cert.fingerprint(hashes.SHA256())==leaf.fingerprint(hashes.SHA256())
    assert data[:32]==hashlib.sha256(b'audit.invalid').digest() and data[32]&0x45==0x45 and data[37:53]==expected
    signed=data+bytes([7])+bytes(31)
    cert.public_key().verify(statement['sig'],signed,ec.ECDSA(hashes.SHA256()))
    try:cert.public_key().verify(statement['sig'],signed[:-1]+b'\x01',ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:pass
    else:raise AssertionError('Tampered enterprise response signature accepted')
    count+=1
assert count==16,count
print(json.dumps({'verified_registration_replies':count,'certificate_chain':'passed','ES256_attestation_signatures':'passed','tamper_rejection':'passed','credential_algorithms':['ES256','Ed25519'],'credentials':['resident','sealed'],'PIN_protocols':[1,2],'enterprise_modes':[1,2]},indent=2))

# Optional dual-identity profile: verify ordinary and wrong-RP fallback with a
# genuinely different signer, plus explicit none suppressing both identities.
if a.batch_identity:
    batch_root=x509.load_pem_x509_certificate((a.batch_identity/'lab-ca.pem').read_bytes())
    batch_leaf=x509.load_pem_x509_certificate((a.batch_identity/'attestation.pem').read_bytes())
    batch_root.public_key().verify(batch_leaf.signature,batch_leaf.tbs_certificate_bytes,ec.ECDSA(batch_leaf.signature_hash_algorithm))
    assert batch_leaf.public_key().public_numbers()!=leaf.public_key().public_numbers()
    assert batch_leaf.fingerprint(hashes.SHA256())!=leaf.fingerprint(hashes.SHA256())
    counts={}
    for role in ('ordinary','fallback','none'):
        files=sorted(a.replies.glob(role+'-*.cbor'));assert len(files)==16,(role,len(files))
        for path in files:
            r=cbor.decode(path.read_bytes());data=r[2];check_credential(path,data);statement=r[3]
            assert 4 not in r
            rp=b'denied.invalid' if role=='fallback' else b'audit.invalid'
            assert data[:32]==hashlib.sha256(rp).digest() and data[32]&0x45==0x45
            if role=='none':
                assert r[1]=='none' and statement=={} and data[37:53]==bytes(16)
                continue
            assert r[1]=='packed' and statement['alg']==-7 and len(statement['x5c'])==1
            assert statement['x5c'][0]==batch_leaf.public_bytes(serialization.Encoding.DER)
            assert data[37:53]==expected
            signed=data+bytes([7])+bytes(31)
            batch_leaf.public_key().verify(statement['sig'],signed,ec.ECDSA(hashes.SHA256()))
            try:batch_leaf.public_key().verify(statement['sig'],signed[:-1]+b'\x01',ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:pass
            else:raise AssertionError('Tampered batch response accepted')
        counts[role]=len(files)
    print(json.dumps({'dual_identity_additional_replies':counts,'different_public_keys_and_certificates':True,'ordinary_and_wrong_RP_signatures':'passed','enterprise_identity_withheld':'passed','explicit_none_suppresses_both':'passed'},indent=2))
