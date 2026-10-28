#!/usr/bin/env python3
"""Sign local Key images; never connect to a device or program OTP."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import tempfile


def output(*args):
    return subprocess.check_output(args, text=True)


def load_ranges(path, ram_only, ab=False):
    data = path.read_bytes()
    if len(data) < 52 or data[:6] != b"\x7fELF\x01\x01":
        raise ValueError(f"Not a little-endian ELF32 image: {path}")
    if struct.unpack_from("<H", data, 18)[0] != 40:
        raise ValueError("Expected an Arm image")
    offset = struct.unpack_from("<I", data, 28)[0]
    entry_size, count = struct.unpack_from("<HH", data, 42)
    if entry_size != 32 or count == 0 or offset + count * entry_size > len(data):
        raise ValueError("Invalid ELF program table")
    bounds = (0x20000000, 0x2007C000) if ram_only else (
        0x10000000, 0x100BB000 if ab else 0x10178000)
    ranges = []
    for index in range(count):
        kind, at, _, address, size, _, _, _ = struct.unpack_from(
            "<8I", data, offset + index * entry_size)
        if kind != 1 or size == 0:
            continue
        if at + size > len(data) or not bounds[0] <= address < address + size <= bounds[1]:
            raise ValueError(f"Image payload outside permitted range: {address:#x}+{size:#x}")
        if any(address < end and address + size > start for start, end in ranges):
            raise ValueError("Overlapping ELF load segments")
        ranges.append((address, address + size))
    if not ranges:
        raise ValueError("No loadable image payload")
    return ranges


def uf2_payload(path, family, start, end):
    """Reject routing blocks or payloads outside the artifact's reviewed region."""
    data = path.read_bytes()
    if not data or len(data) % 512:
        raise ValueError("Invalid UF2 length")
    payloads = {}
    for index in range(len(data) // 512):
        block = data[index * 512:(index + 1) * 512]
        magic1, magic2, flags, address, size, number, count, identifier = struct.unpack_from("<8I", block)
        if (magic1, magic2, struct.unpack_from("<I", block, 508)[0]) != (
                0x0A324655, 0x9E5D5157, 0x0AB16F30):
            raise ValueError("Invalid UF2 magic")
        if (flags != 0x2000 or identifier != family or size != 256 or
                number != index or count != len(data) // 512 or address % 256 or
                not start <= address < address + size <= end or address in payloads):
            raise ValueError("Unexpected UF2 routing, bounds or block sequence")
        payloads[address] = block[32:32 + size]
    return payloads


def verify_signature(details, expected_point):
    keys = re.findall(r"^\s*public key:\s*([0-9A-Fa-f]+)\s*$", details, re.M)
    if not keys or any(key.upper() != expected_point for key in keys):
        raise ValueError("Signed artifact contains an unexpected signing key")
    if not re.search(r"^\s*signature:\s*verified\s*$", details, re.M) or "incorrect" in details:
        raise ValueError("Artifact signature verification failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--picotool", default="picotool")
    parser.add_argument("--ab", action="store_true", help="Build signed A/B update and initial-install artifacts")
    parser.add_argument("--layout-recovery", type=Path, help="RAM-only boot-layout reset ELF")
    parser.add_argument("private_key", type=Path)
    parser.add_argument("public_key", type=Path)
    parser.add_argument("application", type=Path)
    parser.add_argument("recovery", type=Path)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if not output(args.picotool, "version").startswith("picotool v2.3.1 "):
        raise ValueError("Use the reviewed picotool 2.3.1")
    if "ASN1 OID: secp256k1" not in output(
            "openssl", "pkey", "-pubin", "-in", str(args.public_key), "-text", "-noout"):
        raise ValueError("Expected a secp256k1 public key")
    expected = subprocess.check_output([
        "openssl", "pkey", "-pubin", "-in", str(args.public_key), "-pubout", "-outform", "DER"])
    if len(expected) < 65 or expected[-65] != 4:
        raise ValueError("Expected an uncompressed EC public key")
    expected_point = expected[-64:].hex().upper()
    if args.ab and not args.layout_recovery:
        raise ValueError("A/B signing requires --layout-recovery so a signed layout rescue is available")
    images = [(args.application, "Key", False), (args.recovery, "Key-recovery", True)]
    if args.layout_recovery:
        images.append((args.layout_recovery, "Key-layout-recovery", True))
    for source, _, ram_only in images:
        load_ranges(source, ram_only, args.ab)
        details = output(args.picotool, "info", "-a", str(source))
        summary = details.split("\nFixed Pin Information", 1)[0]
        trial = bool(re.search(r"^\s*tbyb:\s*not bought\s*$", summary, re.M))
        if trial != (args.ab and not ram_only):
            raise ValueError("A/B application must be unconfirmed TBYB; RAM recovery must not be TBYB")
        if re.search(r"^\s*rollback version:\s*[1-9]", details, re.M):
            raise ValueError("OTP rollback-version changes are outside this signing workflow")
    destination = args.output_directory
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    marker = destination / "INCOMPLETE"
    marker.write_text("Do not use these artifacts until signing completes.\n")

    def interrupted(signum, _frame):
        raise SystemExit(f"Signing interrupted by signal {signum}")

    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    # picotool 2.3.1 cannot unlock encrypted PEM. Never put the unlocked copy
    # in the checkout or ordinary temporary directory. OpenSSL owns its prompt.
    with tempfile.TemporaryDirectory(prefix="key-sign-", dir="/dev/shm") as scratch:
        unlocked = Path(scratch) / "private.pem"
        subprocess.run(["openssl", "pkey", "-in", str(args.private_key),
                        "-out", str(unlocked)], check=True)
        subprocess.run(["openssl", "pkey", "-in", str(unlocked), "-check", "-noout"],
                       check=True, stdout=subprocess.DEVNULL)
        actual = subprocess.check_output([
            "openssl", "pkey", "-in", str(unlocked), "-pubout", "-outform", "DER"])
        if actual != expected:
            raise ValueError("Private key does not match the supplied public key")
        artifacts = {}
        for source, stem, ram_only in images:
            signed = destination / f"{stem}.signed.elf"
            subprocess.run([args.picotool, "seal", "--quiet", "--sign",
                            str(source), str(signed), str(unlocked)], check=True)
            ranges = load_ranges(signed, ram_only, args.ab)
            details = output(args.picotool, "info", "-a", str(signed))
            verify_signature(details, expected_point)
            summary = details.split("\nFixed Pin Information", 1)[0]
            if bool(re.search(r"^\s*tbyb:\s*not bought\s*$", summary, re.M)) != (args.ab and not ram_only):
                raise ValueError("Sealing changed the required trial-boot state")
            if (not re.search(r"^\s*target chip:\s*RP2350\s*$", details, re.M) or
                    not re.search(r"^\s*image type:\s*ARM Secure\s*$", details, re.M)):
                raise ValueError("Unexpected chip/image type")
            (destination / f"{stem}.verification.txt").write_text(details)
            uf2 = destination / f"{stem}.signed.uf2"
            subprocess.run([args.picotool, "uf2", "convert", "--quiet", str(signed),
                            str(uf2), "--family", "rp2350-arm-s"], check=True)
            # Verify the actual file used for USB recovery, not only its ELF.
            uf2_details = output(args.picotool, "info", "-a", str(uf2))
            verify_signature(uf2_details, expected_point)
            start, end = (0x20000000, 0x2007C000) if ram_only else (
                0x10000000, 0x100BB000 if args.ab else 0x10178000)
            payloads = uf2_payload(uf2, 0xE48BFF59, start, end)
            files = [signed, uf2]
            if args.ab and not ram_only:
                # Initial conversion stages B before touching the old image or
                # table. Runtime addresses inside the signed image stay unchanged.
                initial = destination / "Key-initial-slot-B.bin"
                image = bytearray(b"\xff" * (max(payloads) + 256 - start))
                for address, payload in payloads.items():
                    image[address - start:address - start + 256] = payload
                initial.write_bytes(image)
                files.append(initial)
            artifacts[stem] = {
                "ram_only": ram_only, "load_ranges": ranges,
                "files": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in files}}
        if args.ab:
            table = Path(__file__).resolve().parent.parent / "firmware/rp2350/partitions.json"
            signed_table = destination / "Key-partition-table.signed.uf2"
            subprocess.run([args.picotool, "partition", "create", "--quiet", str(table),
                            str(signed_table), "--sign", str(unlocked), "--no-btstack-flash-bank"], check=True)
            details = output(args.picotool, "info", "-a", str(signed_table))
            verify_signature(details, expected_point)
            uf2_payload(signed_table, 0xE48BFF57, 0x10000000, 0x10002000)
            (destination / "Key-partition-table.verification.txt").write_text(details)
            artifacts["Key-partition-table"] = {
                "files": {signed_table.name: hashlib.sha256(signed_table.read_bytes()).hexdigest()},
                "source_sha256": hashlib.sha256(table.read_bytes()).hexdigest()}
    manifest = {
        "public_key_spki_sha256": hashlib.sha256(expected).hexdigest(),
        "signature_verified": True, "ab": args.ab, "device_accessed": False,
        "otp_programmed": False, "artifacts": artifacts}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    marker.unlink()
    print(f"Signed images verified in {destination}. No device or OTP was accessed.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Signing failed: {error}") from None
