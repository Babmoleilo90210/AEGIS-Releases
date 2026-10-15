"""Pinned 2.0 client runtime inputs shared by staging and package verification.

These hashes match Gradle verification metadata from official Maven Central inputs.
This module never downloads files, starts Tor Browser, signs, or publishes a release.
"""
from pathlib import Path
import hashlib
import zipfile
import re

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


def sha256(file):
    with Path(file).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_safe_web_runtime(app, *, verify_core=True):
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
        with zipfile.ZipFile(app / 'client-core-2.0.0.jar') as archive:
            for name in ['org/securemail/client/safeweb/TorBrowserInstaller.class',
                         'org/securemail/client/safeweb/TorBrowserSignature.class',
                         TOR_BROWSER_PUBLIC_KEY, TOR_BROWSER_KEY_PROVENANCE]:
                if name not in archive.namelist():
                    raise ValueError('Safe Web installer class/resource missing from core JAR: ' + name)
            if hashlib.sha256(archive.read(TOR_BROWSER_PUBLIC_KEY)).hexdigest() != TOR_BROWSER_PUBLIC_KEY_SHA256:
                raise ValueError('Bundled Tor Browser public verification key differs from its reviewed snapshot')
    return inventory
