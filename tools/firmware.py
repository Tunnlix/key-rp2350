#!/usr/bin/env python3
"""Build, sign, verify and update an existing Tunnlix Key A/B installation (Linux)."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
HOME = Path.home()
TARGETS = ('rp2350_application', 'rp2350_recovery', 'rp2350_layout_recovery')


def status(message):
    print(f'[PASS] {message}', flush=True)


def run(command, **kwargs):
    return subprocess.run([str(x) for x in command], check=True, cwd=ROOT, **kwargs)


def output(command):
    return run(command, capture_output=True, text=True).stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def find_picotool(value):
    candidate = value or shutil.which('picotool') or HOME / '.pico-sdk/picotool/2.3.1/picotool/picotool'
    candidate = Path(candidate).expanduser().resolve()
    if not output([candidate, 'version']).startswith('picotool v2.3.1 '):
        raise ValueError('picotool 2.3.1 is required; use --picotool PATH')
    return candidate


@contextmanager
def exclusive(directory):
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / '.operation.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another firmware operation is running in this output directory') from None
        yield


def new_session(directory):
    # Never remove a previous good bundle or reuse an interrupted signing directory.
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-')
    return Path(tempfile.mkdtemp(prefix=stamp, dir=directory))


def build(args, session):
    directory = session / 'build'
    sdk = args.sdk or os.environ.get('PICO_SDK_PATH') or HOME / '.pico-sdk/sdk/2.3.1'
    compiler = args.toolchain or os.environ.get('PICO_TOOLCHAIN_PATH') or HOME / '.pico-sdk/toolchain/15_2_Rel1'
    command = ['cmake', '-S', ROOT / 'firmware/rp2350', '-B', directory, '-G', 'Ninja',
               '-DCMAKE_BUILD_TYPE=Release', f'-DPICO_SDK_PATH={sdk}',
               f'-DPICO_TOOLCHAIN_PATH={compiler}', f'-Dpicotool_DIR={args.picotool.parent}',
               '-DTUNNLIX_KEY_CORE_REQUIRE_RELEASE=ON', '-DRP2350_BUILD_RECOVERY=ON',
               f'-DCTAP_PIN_COMPLEXITY={args.complexity}']
    run(command)
    run(['cmake', '--build', directory, '--parallel', args.jobs, '--target', *TARGETS])
    provenance = json.loads((directory / 'key-core-provenance.json').read_text())
    if provenance['local_source_override'] or provenance['source_dirty']:
        raise ValueError('Signing requires the pinned release core without source overrides')
    save(session / 'build-provenance.json', {
        'source_commit': output(['git', 'rev-parse', 'HEAD']).strip(),
        'source_dirty': bool(output(['git', 'status', '--porcelain']).strip()),
        'pin_complexity': args.complexity, 'core': provenance})
    status('Build complete: application and both recovery images')
    return directory


def signer_module():
    spec = importlib.util.spec_from_file_location('tunnlix_signer', ROOT / 'tools/sign-firmware.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(bundle, args):
    bundle = bundle.resolve()
    if (bundle / 'INCOMPLETE').exists():
        raise ValueError('Bundle is incomplete; sign again to create a new bundle')
    manifest = json.loads((bundle / 'manifest.json').read_text())
    if not manifest.get('ab') or not manifest.get('signature_verified'):
        raise ValueError('Expected a verified A/B signing manifest')
    der = subprocess.check_output(['openssl', 'pkey', '-pubin', '-in', str(args.public_key),
                                   '-pubout', '-outform', 'DER'])
    if hashlib.sha256(der).hexdigest() != manifest['public_key_spki_sha256']:
        raise ValueError('Bundle does not match the selected owner public key')
    signer = signer_module()
    required = {
        'Key': {'Key.signed.elf', 'Key.signed.uf2', 'Key-initial-slot-B.bin'},
        'Key-recovery': {'Key-recovery.signed.elf', 'Key-recovery.signed.uf2'},
        'Key-layout-recovery': {'Key-layout-recovery.signed.elf', 'Key-layout-recovery.signed.uf2'},
        'Key-partition-table': {'Key-partition-table.signed.uf2'}}
    if set(manifest['artifacts']) != set(required):
        raise ValueError('Bundle must include application, both recovery images and partition table')
    version = None
    for stem, names in required.items():
        files = manifest['artifacts'][stem]['files']
        if set(files) != names:
            raise ValueError(f'Unexpected files in {stem}')
        for name, expected in files.items():
            path = bundle / name
            if path.is_symlink() or digest(path) != expected:
                raise ValueError(f'Artifact hash mismatch: {name}')
            if path.suffix not in ('.elf', '.uf2'):
                continue
            details = output([args.picotool, 'info', '-a', path])
            signer.verify_signature(details, der[-64:].hex().upper())
            table = stem == 'Key-partition-table'
            ram = stem in ('Key-recovery', 'Key-layout-recovery')
            if path.suffix == '.elf':
                signer.load_ranges(path, ram, True)
            else:
                start, end = (0x10000000, 0x10002000) if table else (
                    (0x20000000, 0x2007C000) if ram else (0x10000000, 0x100BB000))
                signer.uf2_payload(path, 0xE48BFF57 if table else 0xE48BFF59, start, end)
            if stem == 'Key':
                match = re.search(r'^\s*version:\s*(\d+)\.(\d+)\.(\d+)\s*$', details, re.M)
                if not match or not re.search(r'^\s*tbyb:\s*not bought\s*$', details, re.M):
                    raise ValueError('Expected a versioned, unconfirmed application image')
                current = tuple(map(int, match.groups()))
                if version is not None and current != version:
                    raise ValueError('ELF and UF2 versions differ')
                version = current
    status('Signed bundle verified: 7 signatures and 8 artifact hashes')
    return version


def sign(args, session):
    directory = args.build_dir or build(args, session)
    directory = directory.resolve()
    core = json.loads((directory / 'key-core-provenance.json').read_text())
    if core['local_source_override'] or core['source_dirty'] or core['dependency_mode'] != 'release-archive':
        raise ValueError('Signing requires a verified release core, not a source override')
    shutil.copyfile(directory / 'key-core-provenance.json', session / 'key-core-provenance.json')
    bundle = session / 'signed'
    sources = [directory / 'rp2350_application.elf', directory / 'recovery/rp2350_recovery.elf',
               directory / 'recovery/rp2350_layout_recovery.elf', ROOT / 'firmware/rp2350/partitions.json',
               ROOT / 'tools/sign-firmware.py']
    hashes = {str(path): digest(path) for path in sources}
    save(session / 'signing-inputs.json', hashes)
    print('Enter the signing-key passphrase at the OpenSSL prompt. Typing is invisible.', flush=True)
    run([sys.executable, ROOT / 'tools/sign-firmware.py', '--ab', '--layout-recovery', sources[2],
         '--picotool', args.picotool, args.private_key, args.public_key, sources[0], sources[1], bundle])
    if any(digest(Path(path)) != value for path, value in hashes.items()):
        (bundle / 'INCOMPLETE').write_text('Signing inputs changed during signing.\n')
        raise ValueError('Signing inputs changed; bundle must not be used')
    verify(bundle, args)
    return bundle


def hid_imports():
    try:
        from fido2.ctap2 import Ctap2
        from fido2.hid import CtapHidDevice, linux
    except ImportError:
        raise ValueError('Flashing needs python-fido2 in this Python environment (pip install fido2)') from None
    return Ctap2, CtapHidDevice, linux


def devices():
    _, _, linux = hid_imports()
    return [d for d in linux.list_descriptors() if (d.vid, d.pid) == (0x1209, 1)]


def open_device(serial):
    _, CtapHidDevice, linux = hid_imports()
    import select

    class Bounded(linux.LinuxCtapHidConnection):
        def __init__(self, descriptor):
            super().__init__(descriptor)
            self.deadline = time.monotonic() + 40

        def read_packet(self):
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.handle], [], [], remaining)[0]:
                raise TimeoutError('No HID response before the operation deadline')
            return super().read_packet()

    matches = [d for d in devices() if d.serial_number == serial]
    if len(matches) != 1:
        raise ValueError('Selected key is not uniquely visible in application mode')
    return CtapHidDevice(matches[0], Bounded(matches[0]))


def snapshot(serial):
    Ctap2, _, _ = hid_imports()
    with open_device(serial) as device:
        info = Ctap2(device).info
        if device.ping(b'Tunnlix firmware check') != b'Tunnlix firmware check':
            raise ValueError('Device PING failed')
        return {'serial': device.serial_number, 'version': list(device.device_version),
                'firmware_version': info.firmware_version, 'aaguid': info.aaguid.hex(),
                'pin_set': info.options.get('clientPin'), 'min_pin_length': info.min_pin_length,
                'force_pin_change': info.force_pin_change, 'always_uv': info.options.get('alwaysUv'),
                'free_slots': info.remaining_disc_creds, 'long_touch_reset': info.long_touch_for_reset,
                'pin_complexity': info.pin_complexity_policy, 'options': dict(info.options),
                'config_commands': info.authenticator_config_commands, 'max_msg_size': info.max_msg_size}


def verify_layout(text):
    text = re.sub(r'\n\s*(?=NSBOOT\(|NS\()', ' ', text)
    rows = re.findall(r'^\s*(\d+)\(([^)]*)\)\s*([0-9a-fA-F]{8})->([0-9a-fA-F]{8})([^\n]*)$', text, re.M)
    expected = [
        ('0', 'A', '00002000', '000bd000', 'rw', 'Firmware A', "'rp2350-arm-s'", '1'),
        ('1', 'B w/ 0', '000bd000', '00178000', 'rw', 'Firmware B', "'rp2350-arm-s'", '1'),
        ('2', 'A', '00178000', '00180000', 'r', 'Blobs', '', '0'),
        ('3', 'A', '00180000', '00200000', 'r', 'Credentials', '', '0')]
    header = re.search(r'^un-partitioned_space\s*:\s*(.*)$', text, re.M)
    if not header or ' '.join(header[1].split()) != "S(r) NSBOOT(r) NS(-), uf2 { 'absolute' }" or len(rows) != 4:
        raise ValueError('Unsupported partition layout; automatic update refused')
    for row, want in zip(rows, expected):
        n, link, start, end, tail = row
        prefix, name, family, arm = want[4:]
        expected_tail = f'S(rw) NSBOOT({prefix}) NS(-), "{name}", uf2 {{ {family} }}, arm_boot {arm}, riscv_boot 0'
        if (n, link.strip(), start.lower(), end.lower()) != want[:4] or ' '.join(tail.split()) != ' '.join(expected_tail.split()):
            raise ValueError('Unexpected partition routing or permissions; update refused')


def verify_running(before, after, version):
    if after['version'] != list(version) or after['firmware_version'] != (version[0] << 16 | version[1] << 8 | version[2]):
        raise ValueError('Device returned with an unexpected firmware version')
    for field in ('serial', 'aaguid', 'pin_set', 'min_pin_length', 'force_pin_change',
                  'always_uv', 'free_slots', 'long_touch_reset', 'pin_complexity'):
        if after[field] != before[field]:
            raise ValueError(f'Post-update state differs: {field}; inspect before.json and after.json')
    # Enterprise command 1 depends on the identity compiled into THIS image.
    expected_commands = [1, 2, 3, 4] if 'ep' in after['options'] else [2, 3, 4]
    if after['config_commands'] != expected_commands:
        raise ValueError('GetInfo enterprise capability and configuration commands disagree')


def flash(args, bundle, session, result):
    version = verify(bundle, args)
    matches = [d for d in devices() if not args.serial or d.serial_number == args.serial]
    if len(matches) != 1 or not matches[0].serial_number:
        raise ValueError('Connect exactly one key, or select one with --serial SERIAL')
    serial = matches[0].serial_number
    before = snapshot(serial)
    save(session / 'before.json', before)
    print(f'Update key {serial} to {".".join(map(str, version))}. Keep USB connected and D0 released.', flush=True)
    input('Press Enter when ready at D0 (Ctrl+C cancels): ')
    Ctap2, _, _ = hid_imports()
    with open_device(serial) as device:
        ctap = Ctap2(device)
        protocol = ctap.send_cbor(0x50, {1: 2, 2: 0})
        if protocol.get(1) != 'Key' or protocol.get(2) != 2 or protocol.get(5) != 3000:
            raise ValueError('Unsupported physical-consent update protocol')
        print('HOLD D0 NOW for about 3 seconds. Release when amber flashes quickly.', flush=True)
        ctap.send_cbor(0x50, {1: 2, 2: 1}, on_keepalive=lambda _: None)
    deadline = time.monotonic() + 25
    while True:
        rom = subprocess.run([str(args.picotool), 'info', '-a', '--ser', serial],
                             capture_output=True, text=True, timeout=6)
        if rom.returncode == 0:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError('Key did not appear in ROM update mode; no flash write attempted')
        time.sleep(.5)
    if not re.search(r'^\s*chipid:\s*0x0*' + re.escape(serial.lstrip('0')) + r'\s*$', rom.stdout, re.I | re.M):
        raise ValueError('ROM chip identity mismatch')
    if not re.search(r'^\s*type:\s*RP2350\s*$', rom.stdout, re.M) or not re.search(r'^\s*flash size:\s*2048K\s*$', rom.stdout, re.M):
        raise ValueError('Unexpected chip or flash geometry')
    layout = output([args.picotool, 'partition', 'info', '--ser', serial])
    (session / 'partition-layout.txt').write_text(layout)
    verify_layout(layout)
    # Recheck files immediately before writing; never install partition tables or erase storage here.
    verify(bundle, args)
    status('Same chip and existing A/B layout verified; updating application only')
    result['device_write_attempted'] = True
    result['device_written'] = None  # A failed load can have partially written the inactive slot.
    save(session / 'result.json', result)
    with (session / 'flash.log').open('w') as log:
        run([args.picotool, 'load', '-v', '-x', bundle / 'Key.signed.uf2', '--ser', serial],
            stdout=log, stderr=subprocess.STDOUT, timeout=150)
    result['device_written'] = True
    save(session / 'result.json', result)
    status('Application written and flash contents verified')
    deadline = time.monotonic() + 40
    while True:
        try:
            after = snapshot(serial)
            break
        except (OSError, ValueError, TimeoutError):
            if time.monotonic() >= deadline:
                raise TimeoutError('Application did not return; inspect flash.log') from None
            time.sleep(.5)
    save(session / 'after.json', after)
    verify_running(before, after, version)
    status('Running firmware verified: INIT, GetInfo, PING and public persistent settings')
    return after


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='all', choices=['all', 'build', 'sign', 'verify', 'flash'])
    parser.add_argument('--output', type=Path, default=ROOT / 'build/firmware')
    parser.add_argument('--build-dir', type=Path, help='Sign existing build instead of compiling a fresh default build')
    parser.add_argument('--bundle', type=Path, help='Existing signed bundle for verify/flash; defaults to latest successful signing')
    parser.add_argument('--private-key', type=Path, default=HOME / '.local/share/tunnlix-signing/firmware-signing.pem')
    parser.add_argument('--public-key', type=Path, default=HOME / '.local/share/tunnlix-signing/firmware-signing-public.pem')
    parser.add_argument('--picotool')
    parser.add_argument('--sdk', type=Path)
    parser.add_argument('--toolchain', type=Path)
    parser.add_argument('--complexity', choices=['ON', 'OFF'], default='ON')
    parser.add_argument('--jobs', type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument('--serial', help='Select a particular connected key')
    parser.add_argument('--pause', action='store_true', help='Keep a standalone terminal open after the result')
    args = parser.parse_args()
    args.output = args.output.expanduser().resolve()
    args.public_key = args.public_key.expanduser().resolve()
    args.private_key = args.private_key.expanduser().resolve()
    os.umask(0o077)
    with exclusive(args.output):
        session = new_session(args.output)
        result = {'status': 'running', 'action': args.action, 'device_written': False}
        print(f'Logs and output: {session}', flush=True)
        try:
            args.picotool = find_picotool(args.picotool)
            if args.action == 'build':
                result['build'] = str(build(args, session))
            elif args.action in ('all', 'sign'):
                bundle = sign(args, session)
                result['bundle'] = str(bundle)
                pointer = args.output / 'latest.json.tmp'
                save(pointer, {'bundle': str(bundle)})
                pointer.replace(args.output / 'latest.json')
                if args.action == 'all':
                    try:
                        available = devices()
                    except ValueError as exc:
                        print(f'[INFO] Signed successfully. {exc}', flush=True)
                        available = []
                    if available and input('Signing passed. Flash a connected key now? [y/N]: ').strip().lower() in ('y', 'yes'):
                        result['device_write_requested'] = True
                        result['device'] = flash(args, bundle, session, result)
                        result['device_written'] = True
                    else:
                        print('[INFO] Signed bundle ready; flashing skipped.', flush=True)
            else:
                pointer = args.output / 'latest.json'
                if not args.bundle and not pointer.exists():
                    raise ValueError('No signed bundle selected. Sign first, or use --bundle PATH')
                bundle = args.bundle or Path(json.loads(pointer.read_text())['bundle'])
                bundle = bundle.expanduser().resolve()
                result['bundle'] = str(bundle)
                if args.action == 'verify':
                    result['version'] = verify(bundle, args)
                else:
                    result['device_write_requested'] = True
                    result['device'] = flash(args, bundle, session, result)
                    result['device_written'] = True
            result['status'] = 'passed'
            print(f'RESULT: PASSED — {args.action}' + ('; flash verified' if result['device_written'] else ''), flush=True)
        except BaseException as exc:
            result['status'] = 'cancelled' if isinstance(exc, (KeyboardInterrupt, EOFError)) else 'failed'
            result['error'] = str(exc) or type(exc).__name__
            print(f'RESULT: {result["status"].upper()} — {result["error"]}', flush=True)
            raise
        finally:
            save(session / 'result.json', result)
            if args.pause and sys.stdin.isatty():
                try:
                    input('Press Enter to close: ')
                except (KeyboardInterrupt, EOFError):
                    pass


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(f'Firmware tool: {error or "cancelled"}', file=sys.stderr)
        sys.exit(1)
