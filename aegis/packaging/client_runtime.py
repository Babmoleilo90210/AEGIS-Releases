"""Pinned 2.5 client runtime inputs shared by staging and package verification.

These hashes match Gradle verification metadata from official Maven Central inputs.
This module never downloads files, starts Tor Browser, signs, or publishes a release.
"""
from pathlib import Path
import hashlib
import zipfile
import re
import json
import struct

SAFE_WEB_RUNTIME = {
    'bcpg-jdk18on-1.86.jar': '8a52ea45b2063f6d41b8ca94409f255a1f4604922f7451c18a7cfd3a3c5b85ab',
    'bcutil-jdk18on-1.86.jar': '1c268e15f785aafb1e4670d8d6e5f856f69475e96c162dadcd1ff9b350e9139f',
    'bcprov-jdk18on-1.86.jar': '2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f',
    'commons-compress-1.28.0.jar': 'e1522945218456f3649a39bc4afd70ce4bd466221519dba7d378f2141a4642ca',
    'xz-1.12.jar': '3e158a87bd73d8afb4b6e8239c013b7d049c48563f45860ce99cd2e448cf4a6b',
    'commons-io-2.20.0.jar': 'df90bba0fe3cb586b7f164e78fe8f8f4da3f2dd5c27fa645f888100ccc25dd72',
    'commons-lang3-3.18.0.jar': '4eeeae8d20c078abb64b015ec158add383ac581571cddc45c68f0c9ae0230720',
    'commons-codec-1.19.0.jar': '5c3881e4f556855e9c532927ee0c9dfde94cc66760d5805c031a59887070af5f',
}
TOR_BROWSER_PUBLIC_KEY = 'org/securemail/client/safeweb/tor-browser-developers.asc'
TOR_BROWSER_KEY_PROVENANCE = 'org/securemail/client/safeweb/tor-browser-developers-provenance.json'
TOR_BROWSER_PUBLIC_KEY_SHA256 = '7cec103d0be11b608f61850143101e56f0ba45383b61f44835300ff54ef93032'
SAFE_WEB_ARTIFACTS = {re.fullmatch(r'(.+)-[0-9][^-]*\.jar', name).group(1) for name in SAFE_WEB_RUNTIME}

ROOT = Path(__file__).resolve().parents[1]
CORE_JAR = 'client-core-2.5.0.jar'
VOICE_REGISTRY = 'org/securemail/client/voice/voice-runtime.json'
VOICE_REGISTRY_SOURCE = ROOT / 'client-core/src/main/resources' / VOICE_REGISTRY
VOICE_PROVENANCE = ROOT / 'packaging/native-kit/voice-runtime-provenance.json'
VOICE_FILES = {'linux-x86_64': {'libopus.so', 'libspeexdsp.so'},
               'windows-x86_64': {'opus.dll', 'speexdsp.dll'}}
VOICE_SOURCE_ARCHIVES = {
    'opus-1.6.1.tar.gz': '6ffcb593207be92584df15b32466ed64bbec99109f007c82205f0194572411a1',
    'speexdsp-1.2.1.tar.gz': '8c777343e4a6399569c72abc38a95b24db56882c83dbdb6c6424a5f4aeb54d3d',
}
VOICE_LICENSES = {
    'opus-1.6.1-LICENSE': '01e1167d54a096d123cf6dfbbeb19587278845c6481d2d66d545669846079551',
    'speexdsp-1.2.1-LICENSE': '2654a4264b2bfe298dedc508748d140111840c315cc8eb646a3a68c13fa75b01',
}
VOICE_CORE_CLASSES = [
    'org/securemail/client/voice/' + name + '.class' for name in [
        'GlasAudioSession', 'GlasNativeAudio', 'GlasAudioLibraries', 'GlasAudioDevices',
        'GlasJitterBuffer', 'VoiceCallService', 'VoiceFrames', 'VoiceHistory', 'VoiceTls']
]


def sha256(file):
    with Path(file).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_safe_web_runtime(app, *, verify_core=True, core_jar_name=CORE_JAR):
    """Fail closed on missing/transitively incomplete or changed installer inputs."""
    app = Path(app)
    inventory = {}
    for file in app.glob('*.jar'):
        if any(file.name.startswith(artifact + '-') for artifact in SAFE_WEB_ARTIFACTS) and file.name not in SAFE_WEB_RUNTIME:
            raise ValueError('Conflicting runtime dependency version in client: ' + file.name)
    for name, expected in SAFE_WEB_RUNTIME.items():
        file = app / name
        if file.is_symlink() or not file.is_file() or sha256(file) != expected:
            raise ValueError('Missing or changed pinned client runtime dependency: ' + name)
        with zipfile.ZipFile(file) as archive:
            if archive.testzip() is not None:
                raise ValueError('Runtime JAR CRC failure: ' + name)
        inventory[name] = expected
    if verify_core:
        if Path(core_jar_name).name != core_jar_name or not re.fullmatch(r'client-core-[0-9]+\.[0-9]+\.[0-9]+\.jar', core_jar_name):
            raise ValueError('Unsafe explicit client core JAR name')
        core = app / core_jar_name
        if core.is_symlink() or not core.is_file():
            raise ValueError('Missing or unsafe client core JAR')
        with zipfile.ZipFile(core) as archive:
            for name in ['org/securemail/client/safeweb/TorBrowserInstaller.class',
                         'org/securemail/client/safeweb/TorBrowserSignature.class',
                         'org/securemail/client/safeweb/SandboxPrerequisites.class',
                         'org/securemail/client/safeweb/TorBrowserDiscovery.class',
                         'org/securemail/client/safeweb/TorBrowserDownloadService.class',
                         TOR_BROWSER_PUBLIC_KEY, TOR_BROWSER_KEY_PROVENANCE, VOICE_REGISTRY, *VOICE_CORE_CLASSES]:
                if name not in archive.namelist():
                    raise ValueError('Safe Web installer class/resource missing from core JAR: ' + name)
            if hashlib.sha256(archive.read(TOR_BROWSER_PUBLIC_KEY)).hexdigest() != TOR_BROWSER_PUBLIC_KEY_SHA256:
                raise ValueError('Bundled Tor Browser public verification key differs from its reviewed snapshot')
        voice_registry(core)
    return inventory


def _json(data, limit):
    if len(data) > limit:
        raise ValueError('Oversized trusted runtime metadata')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate runtime metadata key')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('Invalid trusted runtime metadata') from error


def voice_registry(core_jar=None):
    """Match the full compiled JAR registry to all four reviewed native build outputs."""
    if core_jar is None:
        if VOICE_REGISTRY_SOURCE.is_symlink() or not VOICE_REGISTRY_SOURCE.is_file():
            raise ValueError('Missing trusted voice registry source')
        registry = _json(VOICE_REGISTRY_SOURCE.read_bytes(), 16384)
    else:
        core_jar = Path(core_jar)
        if core_jar.is_symlink() or not core_jar.is_file():
            raise ValueError('Missing or unsafe voice core JAR')
        with zipfile.ZipFile(core_jar) as archive:
            if archive.namelist().count(VOICE_REGISTRY) != 1 or archive.getinfo(VOICE_REGISTRY).file_size > 16384:
                raise ValueError('Missing, duplicate or oversized compiled voice registry')
            registry = _json(archive.read(VOICE_REGISTRY), 16384)
    if not isinstance(registry, dict) or registry.get('schema') != 1 or set(registry) != {'schema', 'libraries'}:
        raise ValueError('Invalid compiled voice registry schema')
    libraries = registry.get('libraries')
    if not isinstance(libraries, dict) or set(libraries) != set(VOICE_FILES):
        raise ValueError('Incomplete compiled voice platform inventory')
    for platform, files in VOICE_FILES.items():
        if not isinstance(libraries[platform], dict) or set(libraries[platform]) != files:
            raise ValueError('Incomplete compiled voice native inventory')
        if any(not isinstance(pin, str) or not re.fullmatch('[0-9a-f]{64}', pin) for pin in libraries[platform].values()):
            raise ValueError('Invalid compiled voice SHA-256 pin')
    provenance = _json(VOICE_PROVENANCE.read_bytes(), 65536)
    if not isinstance(provenance, dict):
        raise ValueError('Invalid voice native build provenance')
    if provenance.get('sourceArchives') != VOICE_SOURCE_ARCHIVES:
        raise ValueError('Voice source archive pins differ from reviewed official archives')
    actual = {platform: {} for platform in VOICE_FILES}
    for item in provenance.get('binaries', []):
        platform, name = item.get('platform'), item.get('filename')
        if platform not in actual or name not in VOICE_FILES[platform] or name in actual[platform]:
            raise ValueError('Unexpected or duplicate voice build inventory')
        expected_component = ('opus', '1.6.1') if name in ('opus.dll', 'libopus.so') else ('speexdsp', '1.2.1')
        if (item.get('name'), item.get('version')) != expected_component:
            raise ValueError('Unexpected voice codec build version')
        actual[platform][name] = item.get('binarySHA256')
    if actual != libraries:
        raise ValueError('Compiled voice pins differ from reviewed native build provenance')
    return libraries


def _voice_architecture(file, platform):
    with file.open('rb') as stream:
        header = stream.read(4096)
    if platform == 'linux-x86_64':
        if len(header) < 64 or header[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<HH', header, 16) != (3, 62):
            raise ValueError('Voice library is not an AMD64 ELF64 shared object: ' + file.name)
    else:
        if len(header) < 64 or header[:2] != b'MZ':
            raise ValueError('Voice library is not a PE64 AMD64 DLL: ' + file.name)
        pe = struct.unpack_from('<I', header, 60)[0]
        if pe > 1024 or len(header) < pe + 26 or header[pe:pe + 4] != b'PE\0\0' or \
                struct.unpack_from('<H', header, pe + 4)[0] != 0x8664 or \
                struct.unpack_from('<H', header, pe + 24)[0] != 0x20b or \
                struct.unpack_from('<H', header, pe + 22)[0] & 0x2000 == 0:
            raise ValueError('Voice library is not a PE64 AMD64 DLL: ' + file.name)


def verify_voice_native(bundle, platform, *, core_jar=None):
    """Check architecture and pinned bytes against the compiled registry, never a system codec.

    Pre-copy input validation may use the reviewed registry source. Final structural
    verification MUST provide the packaged core_jar or a bundle/app/core JAR.
    """
    platforms = {'win': 'windows-x86_64', 'linux': 'linux-x86_64'}
    if platform not in platforms:
        raise ValueError('Unsupported voice package platform')
    bundle = Path(bundle)
    candidate = bundle / 'app' / CORE_JAR
    if core_jar is None and candidate.exists():
        core_jar = candidate
    for directory in (bundle / 'native', bundle / 'licenses'):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('Missing or unsafe voice runtime directory')
    expected_platform = platforms[platform]
    pins = voice_registry(core_jar)[expected_platform]
    result = {}
    for file in (bundle / 'native').iterdir():
        if file.name.startswith(('libopus', 'opus', 'libspeexdsp', 'speexdsp')) and file.name not in pins:
            raise ValueError('Unexpected shadow voice native library: ' + file.name)
    for name, expected in pins.items():
        file = bundle / 'native' / name
        if file.is_symlink() or not file.is_file() or sha256(file) != expected:
            raise ValueError('Missing or changed pinned voice native library: ' + name)
        _voice_architecture(file, expected_platform)
        result[name] = expected
    for name, expected in VOICE_LICENSES.items():
        file = bundle / 'licenses' / name
        if file.is_symlink() or not file.is_file() or sha256(file) != expected:
            raise ValueError('Missing or changed voice license: ' + name)
    return result
