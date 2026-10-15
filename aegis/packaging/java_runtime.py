"""Verify explicit Java 21 runtime inputs against the reviewed release registry."""
from pathlib import Path
import hashlib
import json
import re
import struct

REGISTRY = Path(__file__).resolve().parent / 'native-kit/java-runtime-provenance-2.5.0.json'


def verify_java_runtime(directory, platform, *, registry=None):
    if platform not in ('linux', 'win'):
        raise ValueError('Unsupported Java runtime platform')
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Java runtime must be a real explicit directory')
    root = root.resolve()
    document = json.loads((registry or REGISTRY).read_text('utf-8'))
    expected = document['runtimes'][platform]
    files = {}
    for path in root.rglob('*'):
        if path.is_symlink() and (not path.resolve().is_relative_to(root) or not path.resolve().is_file()):
            raise ValueError('Unsafe link in Java runtime')
        if path.is_file():
            with path.open('rb') as stream:
                files[path.relative_to(root).as_posix()] = hashlib.file_digest(stream, 'sha256').hexdigest()
        elif not path.is_dir():
            raise ValueError('Special file in Java runtime')
    if files != expected['files']:
        raise ValueError('Java runtime files differ from the reviewed vendor/build input')
    release = (root / 'release').read_text('utf-8')
    version = re.search(r'^JAVA_VERSION="([^"]+)"$', release, re.M)
    modules = re.search(r'^MODULES="([^"]+)"$', release, re.M)
    if not version or not version.group(1).startswith('21.') or not modules or 'jdk.localedata' not in modules.group(1).split():
        raise ValueError('Java 21 with Russian locale data is required')
    if not (root / 'legal/jdk.localedata').is_dir():
        raise ValueError('Java locale module licence information is missing')
    executable = root / ('bin/javaw.exe' if platform == 'win' else 'bin/java')
    data = executable.read_bytes()
    if platform == 'linux':
        valid = len(data) >= 20 and data[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', data, 18)[0] == 62
    else:
        offset = struct.unpack_from('<I', data, 60)[0] if len(data) >= 64 and data[:2] == b'MZ' else len(data)
        valid = offset + 26 <= len(data) and data[offset:offset + 4] == b'PE\0\0' and struct.unpack_from('<H', data, offset + 4)[0] == 0x8664 and struct.unpack_from('<H', data, offset + 24)[0] == 0x20b
    if not valid:
        raise ValueError('Java launcher architecture is not x86_64')
    return {'version': version.group(1), 'modules': modules.group(1).split(),
            'fileCount': len(files), 'allFilesMatchReviewedRegistry': True,
            'localeModuleIncluded': True, 'targetNativeAcceptance': 'NOT_RUN'}
