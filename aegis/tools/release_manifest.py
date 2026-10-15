"""Local release tooling. No network, private-key storage or custom crypto."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime

REPOSITORY = 'Babmoleilo90210/AEGIS-Releases'
PUBLIC_KEY = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAswWYCFStSEhQdrgqUJFF3x12ltmfUA0PvQtlh684B2g=\n-----END PUBLIC KEY-----\n'
MAX_MANIFEST = 65536
MAX_ASSET = 512 * 1024 * 1024


def release_url(number, name):
    """One exact version/tag namespace shared by generation and validation."""
    version(number)
    return f'https://github.com/{REPOSITORY}/releases/download/v{number}/{name}'


def expected_artifacts(number):
    version(number)
    return {
        f'AEGIS-Setup-{number}-x64.exe': ('windows-x64', 'installer'),
        f'AEGIS-{number}-Windows-x64.zip': ('windows-x64', 'portable'),
        f'AEGIS-{number}-CachyOS-x86_64.AppImage': ('cachyos-x86_64', 'appimage'),
        f'AEGIS-{number}-client-source.zip': ('source', 'source'),
    }


def version(value):
    pattern = r'(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(?:-([A-Za-z0-9.-]{1,64}))?'
    match = re.fullmatch(pattern, value) if isinstance(value, str) else None
    if not match: raise ValueError('Invalid semantic version')
    base = tuple(map(int, match.group(1, 2, 3)))
    prerelease = match.group(4)
    if prerelease is None: return (*base, 1, ())
    parts = prerelease.split('.')
    if any(not p or p.isdigit() and len(p) > 1 and p[0] == '0' for p in parts):
        raise ValueError('Invalid semantic prerelease')
    return (*base, 0, tuple((0, int(p)) if p.isdigit() else (1, p) for p in parts))


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def exact_bytes(path, limit=MAX_MANIFEST):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('A regular file is required')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError('Invalid file size')
    return data


def openssl(args, interactive=False):
    return subprocess.run(['openssl', *map(str, args)], check=True,
                          stdout=subprocess.DEVNULL,
                          stderr=None if interactive else subprocess.DEVNULL, timeout=60)


def verify_signature(data, signature):
    if len(signature) != 64 or not 0 < len(data) <= MAX_MANIFEST:
        raise ValueError('Invalid manifest/signature length')
    with tempfile.TemporaryDirectory(prefix='aegis-release-verify-') as directory:
        root = Path(directory)
        (root / 'manifest').write_bytes(data)
        (root / 'signature').write_bytes(signature)
        (root / 'public.pem').write_bytes(PUBLIC_KEY)
        try:
            openssl(['pkeyutl', '-verify', '-pubin', '-rawin', '-inkey', root / 'public.pem',
                     '-in', root / 'manifest', '-sigfile', root / 'signature'])
        except subprocess.CalledProcessError:
            raise ValueError('Ed25519 signature rejected') from None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def parse_manifest(data, minimum_version='0.0.0'):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_MANIFEST:
        raise ValueError('Invalid manifest size')
    document = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object)
    fields = {'schemaVersion', 'application', 'channel', 'version', 'tag', 'repository',
              'protocolVersion', 'relayCompatibility', 'artifacts', 'checksums', 'changelog',
              'minimumSupported', 'updatePolicy', 'announcement', 'releaseNotes'}
    if not isinstance(document, dict) or set(document) != fields:
        raise ValueError('Unknown manifest schema')
    if (type(document['schemaVersion']) is not int or document['schemaVersion'] != 1
            or document['application'] != 'AEGIS' or document['channel'] not in ('stable','beta')
            or document['repository'] != REPOSITORY
            or type(document['protocolVersion']) is not int or document['protocolVersion'] != 1
            or document['relayCompatibility'] != ['0.2.0']):
        raise ValueError('Wrong release/protocol/repository')
    number = document['version']
    parsed_version = version(number)
    if document['channel'] == 'stable' and '-' in number:
        raise ValueError('Prerelease is not a stable release')
    if parsed_version < version(minimum_version):
        raise ValueError('Version rollback rejected')
    if document['tag'] != 'v' + number:
        raise ValueError('Release tag mismatch')
    if version(document['minimumSupported']) > version(number):
        raise ValueError('Invalid minimum supported version')
    if document['updatePolicy'] not in ('optional', 'required'):
        raise ValueError('Invalid update policy')
    announcement = document['announcement']
    notes = document['releaseNotes']
    if not isinstance(announcement, dict) or set(announcement) != {'title', 'summary', 'showAsLetter'}:
        raise ValueError('Invalid announcement schema')
    if not isinstance(notes, dict) or set(notes) != {'publishedAt', 'type', 'text'}:
        raise ValueError('Invalid release notes schema')
    for obj, name, limit in [(announcement, 'title', 140), (announcement, 'summary', 1500),
                             (notes, 'publishedAt', 40), (notes, 'text', 12000)]:
        if not isinstance(obj[name], str) or not 0 < len(obj[name]) <= limit or '\0' in obj[name]:
            raise ValueError('Invalid release metadata text')
    if type(announcement['showAsLetter']) is not bool or notes['type'] not in ('Feature', 'Fix', 'Security'):
        raise ValueError('Invalid announcement/notes value')
    try:
        timestamp = datetime.fromisoformat(notes['publishedAt'].replace('Z', '+00:00'))
        if timestamp.tzinfo is None: raise ValueError()
    except ValueError:
        raise ValueError('Invalid release timestamp') from None
    if (document['updatePolicy'] == 'required' and notes['type'] != 'Security'
            and version(document['minimumSupported']) <= version(minimum_version)):
        raise ValueError('Unsupported mandatory update')
    expected = expected_artifacts(number)
    artifacts = document['artifacts']
    if not isinstance(artifacts, list) or len(artifacts) != len(expected):
        raise ValueError('Wrong artifact count')
    seen = set()
    for item in artifacts:
        validate_file(item, number, {'fileName', 'platform', 'kind', 'size', 'sha256', 'url'})
        name = item['fileName']
        if name in seen or name not in expected or (item['platform'], item['kind']) != expected[name]:
            raise ValueError('Wrong artifact platform/name')
        seen.add(name)
    for field, name in [('checksums', 'SHA256SUMS'), ('changelog', f'CHANGELOG-{number}.md')]:
        validate_file(document[field], number, {'fileName', 'size', 'sha256', 'url'})
        if document[field]['fileName'] != name:
            raise ValueError('Wrong auxiliary asset')
    return document


def validate_file(item, number, fields):
    if not isinstance(item, dict) or set(item) != fields:
        raise ValueError('Unknown asset schema')
    name = item['fileName']
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,179}', name):
        raise ValueError('Unsafe asset filename')
    if type(item['size']) is not int or not 0 < item['size'] <= MAX_ASSET:
        raise ValueError('Invalid asset size')
    if not isinstance(item['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', item['sha256']):
        raise ValueError('Invalid asset SHA-256')
    expected_url = release_url(number, name)
    if item['url'] != expected_url:
        raise ValueError('Asset URL rejected')


def entries(document):
    return [*document['artifacts'], document['checksums'], document['changelog']]


def verify_assets(document, directory):
    root = Path(directory).resolve()
    for item in entries(document):
        path = root / item['fileName']
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item['size']:
            raise ValueError('Asset missing or size mismatch: ' + item['fileName'])
        if sha256(path) != item['sha256']:
            raise ValueError('Asset hash mismatch: ' + item['fileName'])


def verify(manifest, signature, assets=None, minimum_version='0.0.0'):
    data = exact_bytes(manifest)
    # Authenticate EXACT bytes before any JSON parsing.
    verify_signature(data, exact_bytes(signature, 64))
    document = parse_manifest(data, minimum_version)
    if assets is not None:
        verify_assets(document, assets)
    return document


def sign(manifest, private_key, output):
    manifest, private_key, output = map(Path, (manifest, private_key, output))
    data = exact_bytes(manifest)
    parse_manifest(data)
    if output.exists() or output.is_symlink():
        raise ValueError('Signature output already exists')
    if not private_key.is_file():
        raise ValueError('Offline private key file not found')
    # OpenSSL alone reads the original offline key. No key is copied or logged.
    with tempfile.TemporaryDirectory(prefix='aegis-release-sign-') as directory:
        root = Path(directory)
        (root / 'manifest').write_bytes(data)
        openssl(['pkeyutl', '-sign', '-rawin', '-inkey', private_key.resolve(),
                 '-in', root / 'manifest', '-out', root / 'signature'], interactive=True)
        signature = exact_bytes(root / 'signature', 64)
        verify_signature(data, signature)  # Refuse a key other than the owner's pinned key.
        if exact_bytes(manifest) != data:
            raise ValueError('Manifest changed during signing')
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(signature)
            stream.flush()
            os.fsync(stream.fileno())
    return hashlib.sha256(data).hexdigest()
