"""Offline 5.0 Tor Expert staging from independently signature-verified pinned bytes.

No download, trust-key change, external command or execution occurs here. The
reviewed source registry is the trust anchor; callers cannot supply another one.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / 'packaging/native-kit500/tor-runtime-provenance-5.0.0.json'


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_relative(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or '\\' in name or path.as_posix() != name or any(ord(c) < 32 for c in name):
        raise ValueError('Unsafe Tor runtime member path')
    return Path(*path.parts)


def registry():
    if REGISTRY.is_symlink() or not REGISTRY.is_file() or REGISTRY.stat().st_size > 65536:
        raise ValueError('Unsafe source Tor runtime registry')
    value = json.loads(REGISTRY.read_text(encoding='utf-8'))
    if value['schema'] != 1 or value['clientVersion'] != '5.0.0' or value['expertVersion'] != '15.0.25' \
            or value['torVersion'] != '0.4.9.14' or value['opensslVersion'] != '3.5.9' \
            or value['primaryFingerprint'] != 'EF6E286DDA85EA2A4BA7DE684E2C6E8793298290':
        raise ValueError('Unreviewed Tor runtime registry version or trust')
    return value


def checked_file(path, record):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size != record['bytes'] or sha256(path) != record['sha256']:
        raise ValueError('Missing or changed signature-verified Tor runtime input: ' + path.name)
    return path


def expected_runtime(platform):
    source = registry()
    if platform not in source['platforms']:
        raise ValueError('Unsupported Tor runtime platform')
    files = {}
    for member in source['platforms'][platform]['members'].values():
        if member['runtimePath'] is not None:
            relative = safe_relative(member['runtimePath']).as_posix()
            if relative in files:
                raise ValueError('Duplicate Tor runtime target')
            files[relative] = {'sha256': member['sha256'], 'bytes': member['bytes']}
    configuration = source['aegisConfiguration']
    relative = safe_relative(configuration['runtimePath']).as_posix()
    if relative in files:
        raise ValueError('Conflicting AEGIS Tor configuration')
    files[relative] = {'sha256': configuration['sha256'], 'bytes': configuration['bytes']}
    return source, files


def verify_runtime(folder, platform):
    """Verify complete runtime against source pins, never its writable sidecar."""
    folder = Path(folder)
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError('Unsafe Tor runtime directory')
    source, expected = expected_runtime(platform)
    files = {}; directories = {'.'}
    for name in expected:
        directories.update(p.as_posix() for p in Path(name).parents)
    for path in folder.rglob('*'):
        name = path.relative_to(folder).as_posix()
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('Link or special node in Tor runtime')
        if path.is_dir():
            if name not in directories:
                raise ValueError('Unexpected Tor runtime directory')
        else:
            if name not in expected:
                raise ValueError('Unexpected or stale Tor runtime file: ' + name)
            checked_file(path, expected[name]); files[name] = expected[name]
    if files.keys() != expected.keys():
        raise ValueError('Incomplete Tor runtime')
    return {'schema': 1, 'clientVersion': '5.0.0', 'expertVersion': source['expertVersion'],
            'torVersion': source['torVersion'], 'opensslVersion': source['opensslVersion'],
            'platform': platform, 'sourceRegistrySha256': sha256(REGISTRY),
            'upstreamArchive': source['platforms'][platform]['archive'],
            'upstreamSignature': source['platforms'][platform]['signature'],
            'primaryFingerprint': source['primaryFingerprint'], 'runtimeFiles': files,
            'nativeTargetAcceptance': 'NOT_RUN', 'networkBootstrapAcceptance': 'NOT_RUN'}


def stage_runtime(archive, signature, platform, destination):
    source, expected = expected_runtime(platform)
    inputs = source['platforms'][platform]
    archive = checked_file(archive, inputs['archive']); checked_file(signature, inputs['signature'])
    config = checked_file(ROOT / safe_relative(source['aegisConfiguration']['sourcePath']), source['aegisConfiguration'])
    destination = Path(destination).absolute()
    if destination.is_symlink() or any(destination.resolve() == p.resolve() or destination.resolve() in p.resolve().parents
                                      for p in [archive, Path(signature), config]):
        raise ValueError('Unsafe Tor runtime destination')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.tor-runtime500-', dir=destination.parent) as directory:
        candidate = Path(directory) / 'tor'; candidate.mkdir()
        seen = set()
        with tarfile.open(archive, 'r:gz') as bundle:
            for member in bundle:
                raw = member.name.removeprefix('./').rstrip('/')
                relative = safe_relative(raw)
                if member.isdir():
                    continue
                if not member.isfile() or member.issym() or member.islnk() or raw in seen or raw not in inputs['members']:
                    raise ValueError('Unexpected/duplicate/link member in verified Tor archive')
                seen.add(raw); record = inputs['members'][raw]
                if member.size != record['bytes']:
                    raise ValueError('Tor archive member size mismatch')
                with bundle.extractfile(member) as stream:
                    if record['runtimePath'] is None:
                        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                    else:
                        target = candidate / safe_relative(record['runtimePath']); target.parent.mkdir(parents=True, exist_ok=True)
                        h = hashlib.sha256()
                        with target.open('xb') as output:
                            while chunk := stream.read(1024 * 1024):
                                output.write(chunk); h.update(chunk)
                        digest = h.hexdigest(); target.chmod(0o755 if member.mode & 0o111 else 0o644)
                    if digest != record['sha256']:
                        raise ValueError('Tor archive member SHA mismatch')
        if seen != inputs['members'].keys():
            raise ValueError('Incomplete verified Tor archive')
        shutil.copyfile(config, candidate / safe_relative(source['aegisConfiguration']['runtimePath']))
        proof = verify_runtime(candidate, platform)
        previous = destination.with_name('.' + destination.name + '.previous-' + str(uuid.uuid4()))
        had_previous = destination.exists()
        if had_previous:
            os.replace(destination, previous)
        try:
            os.replace(candidate, destination)
        except BaseException:
            if had_previous: os.replace(previous, destination)
            raise
        if had_previous: shutil.rmtree(previous)
    return proof
