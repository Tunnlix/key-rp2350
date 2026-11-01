#!/usr/bin/env python3
"""Create isolated lab credentials or validate/export an enterprise identity.

Requires cryptography. Private inputs and generated headers belong outside Git.
Production identities must use a distinct, organization-controlled attestation key.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

AAGUID=bytes.fromhex('fa024a59a2a641d9bd40ed6a78915bca')

def test_leaf_expiry(now):
    """Five calendar years plus ten days for the lab-test validity margin."""
    try:anniversary=now.replace(year=now.year+5)
    except ValueError:anniversary=now.replace(year=now.year+5,day=28)
    return anniversary+dt.timedelta(days=10)

def write_private(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data)

def create_test(folder,rps,platform,batch=False):
    if batch and (rps or platform):raise ValueError('Ordinary batch identity cannot contain enterprise routing policy')
    folder.mkdir(mode=0o700,parents=True,exist_ok=False)
    now=dt.datetime.now(dt.timezone.utc)
    ca=ec.generate_private_key(ec.SECP256R1());key=ec.generate_private_key(ec.SECP256R1())
    root_name=x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME,'BG'),x509.NameAttribute(NameOID.ORGANIZATION_NAME,'Tunnlix TEST ONLY'),x509.NameAttribute(NameOID.COMMON_NAME,'Tunnlix ordinary batch LAB CA' if batch else 'Tunnlix enterprise LAB CA')])
    root=(x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name).public_key(ca.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(days=1)).not_valid_after(now+dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True).sign(ca,hashes.SHA256()))
    serial=x509.random_serial_number()
    name=x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME,'BG'),x509.NameAttribute(NameOID.ORGANIZATION_NAME,'Tunnlix TEST ONLY'),x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,'Authenticator Attestation'),x509.NameAttribute(NameOID.COMMON_NAME,f'TEST ONLY {"batch" if batch else "Key"} {serial:x}')])
    leaf=(x509.CertificateBuilder().subject_name(name).issuer_name(root.subject).public_key(key.public_key())
        .serial_number(serial).not_valid_before(now-dt.timedelta(days=1)).not_valid_after(test_leaf_expiry(now))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),critical=True)
        .add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4'),b'\x04\x10'+AAGUID),critical=False).sign(ca,hashes.SHA256()))
    for name,value in [('lab-ca-private.pem',ca),('attestation-private.pem',key)]:
        write_private(folder/name,value.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    for name,value in [('lab-ca.pem',root),('attestation.pem',leaf)]:
        (folder/name).write_bytes(value.public_bytes(serialization.Encoding.PEM))
    (folder/'identity.json').write_text(json.dumps({'test_identity':True,'rp_ids':rps,'platform_managed':platform},indent=2)+'\n')
    print('Created TEST ONLY identity; private files have mode 0600. No device was provisioned.')

def compile_identity(folder,output,allow_test,batch=False,distinct_from=None):
    meta=json.loads((folder/'identity.json').read_text())
    if type(meta.get('test_identity')) is not bool or type(meta.get('platform_managed')) is not bool:raise ValueError('Identity flags must be explicit booleans')
    if meta['test_identity'] and not allow_test:raise ValueError('Test identity requires explicit --allow-test-identity')
    rps=meta.get('rp_ids')
    if not isinstance(rps,list) or len(rps)>8 or any(not isinstance(r,str) or not r or len(r.encode())>2048 or '\x00' in r for r in rps):raise ValueError('Invalid bounded RP list')
    if batch and (rps or meta['platform_managed']):raise ValueError('Ordinary batch identity cannot contain enterprise routing policy')
    if len(rps)!=len(set(rps)) or (not batch and not rps and not meta['platform_managed']):raise ValueError('Vendor-facilitated mode requires distinct RPs')
    key=serialization.load_pem_private_key((folder/'attestation-private.pem').read_bytes(),password=None)
    if not isinstance(key,ec.EllipticCurvePrivateKey) or not isinstance(key.curve,ec.SECP256R1):raise ValueError('Attestation requires an ES256 key')
    leaf=x509.load_pem_x509_certificate((folder/'attestation.pem').read_bytes())
    root=x509.load_pem_x509_certificate((folder/'lab-ca.pem').read_bytes())
    # Tools 1.9.3 hard-codes this public, shared TEST fixture. Its legacy
    # certificate omits KU and AAGUID extensions. Only this exact leaf/root
    # pair may use that lab-only exception; production checks stay strict.
    official_fixture=(leaf.fingerprint(hashes.SHA256()).hex(),root.fingerprint(hashes.SHA256()).hex()) == (
        '1c0b949287eb9a3bbbaca313cbd56331b2ff202fe3ca01379a6612f636f9208b',
        '985b1873d04418831e379c78a26e1cf48107c45e38c931e43edaa0177b09a832')
    marked_test=official_fixture or any('TEST ONLY' in attr.value or 'LAB CA' in attr.value or 'TEST ROOT' in attr.value for name in (leaf.subject,root.subject) for attr in name)
    if marked_test and not meta['test_identity']:raise ValueError('Lab certificate must be marked test_identity')
    if leaf.public_key().public_numbers()!=key.public_key().public_numbers():raise ValueError('Certificate and private key do not match')
    if batch and official_fixture:raise ValueError('Enterprise conformance fixture cannot be used as ordinary batch identity')
    if distinct_from is not None:
        other=x509.load_pem_x509_certificate((distinct_from/'attestation.pem').read_bytes())
        if other.public_key().public_numbers()==leaf.public_key().public_numbers():raise ValueError('Ordinary and enterprise attestation must use different keys')

    def usage_allowed(cert,attribute):
        try:return getattr(cert.extensions.get_extension_for_class(x509.KeyUsage).value,attribute)
        except x509.ExtensionNotFound:return official_fixture
    if leaf.issuer!=root.subject or not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca or not usage_allowed(root,'key_cert_sign'):raise ValueError('Invalid issuer')
    issuer=root.public_key()
    if not isinstance(issuer,ec.EllipticCurvePublicKey) or not (isinstance(issuer.curve,(ec.SECP256R1,ec.SECP384R1,ec.SECP521R1)) or (official_fixture and isinstance(issuer.curve,ec.SECP256K1))):raise ValueError('Unsupported issuer curve')
    if not isinstance(leaf.signature_hash_algorithm,(hashes.SHA256,hashes.SHA384,hashes.SHA512)):raise ValueError('Unsupported certificate signature hash')
    root.public_key().verify(leaf.signature,leaf.tbs_certificate_bytes,ec.ECDSA(leaf.signature_hash_algorithm))
    if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca or not usage_allowed(leaf,'digital_signature'):raise ValueError('Invalid attestation certificate purpose')
    for oid in (NameOID.COUNTRY_NAME,NameOID.ORGANIZATION_NAME,NameOID.COMMON_NAME):
        values=leaf.subject.get_attributes_for_oid(oid)
        if len(values)!=1 or not values[0].value or (oid==NameOID.COUNTRY_NAME and len(values[0].value)!=2):raise ValueError('Invalid packed-attestation subject')
    if not any(x.value=='Authenticator Attestation' for x in leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)):raise ValueError('Missing packed-attestation OU')
    now=dt.datetime.now(dt.timezone.utc)
    for cert in (root,leaf):
        if not cert.not_valid_before_utc<=now<=cert.not_valid_after_utc:raise ValueError('Certificate is outside validity period')
    try:ext=leaf.extensions.get_extension_for_oid(ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4'))
    except x509.ExtensionNotFound:
        if not official_fixture:raise ValueError('Missing model AAGUID certificate extension')
    else:
        if ext.critical or ext.value.value!=b'\x04\x10'+AAGUID:raise ValueError('AAGUID certificate extension mismatch')
    der=leaf.public_bytes(serialization.Encoding.DER)
    if len(der)>1024:raise ValueError('Certificate exceeds bounded chain size')
    rp_hashes=sorted(hashlib.sha256(r.encode()).digest() for r in rps)
    fingerprint=hashlib.sha256(b'Tunnlix EP identity policy v1\x00'+der+bytes([meta['platform_managed']])+b''.join(rp_hashes)).digest()
    def array(name,data):return 'static const unsigned char '+name+'[] = {'+','.join(str(x) for x in data)+'};\n'
    prefix='batch' if batch else 'enterprise'
    source='/* PRIVATE generated identity: never commit this header. */\n'
    source+=array(prefix+'_scalar',key.private_numbers().private_value.to_bytes(32,'big'))
    source+=array(prefix+'_certificate',der)
    if not batch:
        source+=array('enterprise_fingerprint',fingerprint)
        source+='static const unsigned char enterprise_rps[][32] = {'+','.join('{'+','.join(str(x) for x in h)+'}' for h in rp_hashes)+('' if rp_hashes else '{0}')+'};\n'
        source+=f'#define ENTERPRISE_RP_COUNT {len(rps)}U\n#define ENTERPRISE_PLATFORM_MANAGED {int(meta["platform_managed"])}\n'
    output.parent.mkdir(parents=True,exist_ok=True)
    # Replace the directory entry atomically; never follow an existing symlink
    # or expose a partially written private header to a concurrent build.
    fd,temporary=tempfile.mkstemp(prefix='.enterprise-',dir=output.parent)
    try:
        with os.fdopen(fd,'w') as f:
            f.write(source)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary,output)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
    print('Validated identity; exported private header. Certificate SHA-256: '+hashlib.sha256(der).hexdigest())

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='command',required=True)
    c=s.add_parser('create-test');c.add_argument('directory',type=Path);c.add_argument('--rp',action='append',default=[]);c.add_argument('--platform-managed',action='store_true');c.add_argument('--batch',action='store_true')
    c=s.add_parser('compile');c.add_argument('directory',type=Path);c.add_argument('output',type=Path);c.add_argument('--allow-test-identity',action='store_true');c.add_argument('--batch',action='store_true');c.add_argument('--distinct-from',type=Path)
    a=p.parse_args()
    if a.command=='create-test':create_test(a.directory,a.rp,a.platform_managed,a.batch)
    else:compile_identity(a.directory,a.output,a.allow_test_identity,a.batch,a.distinct_from)
