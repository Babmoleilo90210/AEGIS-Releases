#!/usr/bin/env python3
"""Offline structural verification; it does not replace native OS acceptance.

Usage: python3 packaging/verify_client_release.py OUTPUT_DIRECTORY
Requires the matching OUTPUT_DIRECTORY/stage produced by package-clients.py.
Uses only Python's standard library and the bundled AppImage runtime.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import stat
import struct
import zipfile
from verify_appimage import verify

ROOT_KEY = b'MCowBQYDK2VwAyEAswWYCFStSEhQdrgqUJFF3x12ltmfUA0PvQtlh684B2g='
ICON_SIZES = {16, 24, 32, 48, 64, 128, 256}


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ico_images(data):
    reserved, kind, count = struct.unpack_from('<HHH', data)
    if (reserved, kind, count) != (0, 1, 7):
        raise ValueError('Expected a seven-size application ICO')
    images = {}
    for index in range(count):
        width, height, _, _, _, _, size, offset = struct.unpack_from('<BBBBHHII', data, 6 + index * 16)
        width, height = width or 256, height or 256
        if width != height or offset + size > len(data) or width in images:
            raise ValueError('Malformed ICO directory')
        images[width] = data[offset:offset + size]
    if set(images) != ICON_SIZES:
        raise ValueError('Missing ICO size')
    return images


def pe_check(path, expected_icons, require_amd64=True):
    data = path.read_bytes()
    if data[:2] != b'MZ':
        raise ValueError('Missing PE DOS header: ' + path.name)
    pe = struct.unpack_from('<I', data, 60)[0]
    if data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('Missing PE signature')
    machine, section_count = struct.unpack_from('<HH', data, pe + 4)
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from('<H', data, optional)[0]
    if (require_amd64 and (machine, magic) != (0x8664, 0x20b)) or magic not in (0x10b, 0x20b):
        raise ValueError('Unexpected PE architecture')
    subsystem, flags = struct.unpack_from('<HH', data, optional + 68)
    if subsystem != 2 or flags & 0x140 != 0x140:
        raise ValueError('PE must be a GUI executable with ASLR and NX')
    directory = optional + (112 if magic == 0x20b else 96)
    resource_rva, resource_size = struct.unpack_from('<II', data, directory + 16)
    sections = []
    for index in range(section_count):
        offset = optional + optional_size + index * 40
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', data, offset + 8)
        sections.append((rva, max(virtual_size, raw_size), raw_offset, raw_size))

    def position(rva, size):
        for start, length, raw, raw_size in sections:
            if start <= rva and rva + size <= start + length and rva - start + size <= raw_size:
                result = raw + rva - start
                if result + size <= len(data):
                    return result
        raise ValueError('Resource RVA outside a file section')

    base = position(resource_rva, resource_size)
    leaves = {}

    def walk(relative, names):
        if len(names) > 3 or relative + 16 > resource_size:
            raise ValueError('Malformed resource directory')
        named, ids = struct.unpack_from('<HH', data, base + relative + 12)
        if named + ids > 4096 or relative + 16 + (named + ids) * 8 > resource_size:
            raise ValueError('Oversized resource table')
        for index in range(named + ids):
            name, target = struct.unpack_from('<II', data, base + relative + 16 + index * 8)
            if name & 0x80000000:
                text_offset = name & 0x7fffffff
                count = struct.unpack_from('<H', data, base + text_offset)[0]
                name = data[base + text_offset + 2:base + text_offset + 2 + count * 2].decode('utf-16le')
            key = (*names, name)
            if target & 0x80000000:
                walk(target & 0x7fffffff, key)
            else:
                if target + 16 > resource_size:
                    raise ValueError('Malformed resource data entry')
                rva, size = struct.unpack_from('<II', data, base + target)
                offset = position(rva, size)
                leaves[key] = data[offset:offset + size]

    walk(0, ())
    manifests = [value for key, value in leaves.items() if key[0] == 24]
    if not any(b'asInvoker' in value or 'asInvoker'.encode('utf-16le') in value for value in manifests):
        raise ValueError('Missing asInvoker manifest')
    groups = [value for key, value in leaves.items() if key[0] == 14]
    matched_sizes = set()
    for group in groups:
        reserved, kind, count = struct.unpack_from('<HHH', group)
        if (reserved, kind) != (0, 1):
            raise ValueError('Malformed group icon')
        for index in range(count):
            width, height, _, _, _, _, size, icon_id = struct.unpack_from('<BBBBHHIH', group, 6 + index * 14)
            width, height = width or 256, height or 256
            candidates = [value for key, value in leaves.items() if key[0] == 3 and key[1] == icon_id]
            if width == height and width in expected_icons and any(value == expected_icons[width] and len(value) == size for value in candidates):
                matched_sizes.add(width)
    if matched_sizes != ICON_SIZES:
        raise ValueError('Executable icon differs from the supplied seven-size ICO: ' + path.name)
    return {'machine': 'AMD64' if machine == 0x8664 else 'I386', 'PE32_plus': magic == 0x20b,
            'GUI': True, 'ASLR': True, 'NX': True, 'asInvoker': True,
            'icon_sizes': sorted(matched_sizes), 'icon_payload_matches_ICO': True}


def app_jars(app):
    if list(app.glob('*relay*')):
        raise ValueError('Relay JAR must not be shipped in a client')
    names = ['client-core-1.1.1.jar', 'client-ui-1.1.1.jar', 'common-protocol-0.2.0.jar']
    for name in names:
        with zipfile.ZipFile(app / name) as archive:
            if archive.testzip() is not None:
                raise ValueError('JAR CRC failure')
            if any('/test/' in item or item.endswith('Test.class') for item in archive.namelist()):
                raise ValueError('Test classes found in application JAR')
            if name.startswith('client-core'):
                clazz = archive.read('org/securemail/client/update/SignedManifest.class')
                if ROOT_KEY not in clazz or 'org/securemail/client/update/UpdaterMain.class' not in archive.namelist():
                    raise ValueError('Pinned production public key or updater helper missing')
    return {name: sha256(app / name) for name in names}


def verify_release(output):
    output = Path(output).resolve()
    windows = output / 'stage/AEGIS'
    linux = output / 'stage/AEGIS.AppDir'
    icons = ico_images((windows / 'resources/icon.ico').read_bytes())
    pe = {name: pe_check(windows / name, icons) for name in ['AEGIS.exe', 'AEGIS-Maintenance.exe', 'AEGIS-Updater.exe']}
    setup = output / 'AEGIS-Setup-1.1.1-x64.exe'
    setup_check = pe_check(setup, icons, require_amd64=False)
    payload = output / 'AEGIS-1.1.1-Windows-x64.zip'
    with zipfile.ZipFile(payload) as archive:
        if archive.testzip() is not None:
            raise ValueError('Windows ZIP CRC failure')
        actual = set()
        for item in archive.infolist():
            path = PurePosixPath(item.filename)
            if path.is_absolute() or path.parts[0] != 'AEGIS' or '..' in path.parts or '\\' in item.filename or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('Unsafe Windows ZIP entry')
            if item.filename in actual or item.is_dir():
                raise ValueError('Duplicate or unexpected directory ZIP entry')
            actual.add(item.filename)
            expected = windows / Path(*path.parts[1:])
            if not expected.is_file() or expected.is_symlink():
                raise ValueError('Unexpected ZIP payload')
            with archive.open(item) as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != sha256(expected):
                    raise ValueError('ZIP payload mismatch')
        required = {'AEGIS/runtime/bin/javaw.exe', 'AEGIS/tor/tor.exe',
                    'AEGIS/tor/pluggable_transports/lyrebird.exe', 'AEGIS/native/libsodium.dll',
                    'AEGIS/AEGIS.exe', 'AEGIS/AEGIS-Updater.exe'}
        expected = {'AEGIS/' + path.relative_to(windows).as_posix() for path in windows.rglob('*') if path.is_file()}
        if actual != expected or not required <= actual:
            raise ValueError('Incomplete Windows ZIP')
        zip_file_count = len(actual)
    if 'JAVA_VERSION="21.' not in (windows / 'runtime/release').read_text('utf-8'):
        raise ValueError('Windows Java runtime is not version 21')
    win_jars, linux_jars = app_jars(windows / 'app'), app_jars(linux / 'app')
    if win_jars != linux_jars:
        raise ValueError('Client application/common JARs differ between platforms')
    for app, platform in [(windows, 'win'), (linux, 'linux')]:
        stage = Path(__file__).resolve().parents[1] / 'client-ui/build/stage' / platform
        expected = {path.name: sha256(path) for path in stage.glob('*.jar')}
        actual = {path.name: sha256(path) for path in (app / 'app').glob('*.jar')}
        if actual != expected:
            raise ValueError('Packaged JARs differ from final Gradle stage')
    image = output / 'AEGIS-1.1.1-CachyOS-x86_64.AppImage'
    appimage = verify(image, linux)
    names = [setup.name, payload.name, image.name]
    return {'verification_type': 'offline_structural_and_payload', 'native_OS_acceptance': 'PENDING',
            'artifacts': [{'name': name, 'bytes': (output / name).stat().st_size, 'sha256': sha256(output / name)} for name in names],
            'windows': {'launcher_PE': pe, 'setup_PE': setup_check, 'zip_CRC': 'OK',
                        'all_payload_files_SHA256_match': True, 'file_count': zip_file_count,
                        'java_21_included': True, 'tor_PT_sodium_included': True},
            'appimage': appimage, 'application_JAR_SHA256': win_jars,
            'Windows_Linux_application_JARs_identical': True, 'final_Gradle_stage_matches_packages': True,
            'pinned_public_key_embedded_in_both_core_JARs': ROOT_KEY.decode('ascii'),
            'relay_JAR_in_client': False, 'production_signature_created': False,
            'ICO_SHA256': sha256(windows / 'resources/icon.ico'),
            'source_icon_SHA256': sha256(windows / 'resources/icon-original.png')}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_release(args.output), indent=2) + '\n', end='')
