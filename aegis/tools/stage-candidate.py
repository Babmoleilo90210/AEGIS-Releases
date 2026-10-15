#!/usr/bin/env python3
"""Offline 2.0 client staging from already compiled JARs and reviewed native bases.

No compilation, network, release signing, final packages, or publication occurs.
Runtime extras must match the same pins as Gradle and package verification.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packaging'))
from client_runtime import SAFE_WEB_ARTIFACTS, SAFE_WEB_RUNTIME, sha256, verify_safe_web_runtime

MODULES = {'client-core': '2.0.0', 'client-ui': '2.0.0', 'common-protocol': '0.2.0'}
OWN_PREFIXES = ('client-core-', 'client-ui-', 'common-protocol-', 'relay-server-')


def stage(linux_base, windows_base, build, dependencies, destination):
    linux_base, windows_base, build = (Path(p).resolve() for p in (linux_base, windows_base, build))
    destination = Path(destination).absolute()
    inputs = [linux_base, windows_base, build] + [Path(p).resolve() for p in dependencies]
    resolved_destination = destination.resolve()
    if destination.is_symlink() or any(resolved_destination == p or resolved_destination in p.parents or p in resolved_destination.parents for p in inputs):
        raise ValueError('Staging destination must not overlap an input directory or symlink')
    destination.parent.mkdir(parents=True, exist_ok=True)
    dependency_files = {}
    for folder in inputs:
        candidates = list(folder.glob('*.jar')) + list((folder / 'app').glob('*.jar'))
        for candidate in candidates:
            if candidate.name in SAFE_WEB_RUNTIME:
                if candidate.is_symlink() or sha256(candidate) != SAFE_WEB_RUNTIME[candidate.name]:
                    raise ValueError('Changed pinned dependency input: ' + candidate.name)
                dependency_files[candidate.name] = candidate
    missing = SAFE_WEB_RUNTIME.keys() - dependency_files.keys()
    if missing:
        raise ValueError('Missing explicit runtime dependencies: ' + ', '.join(sorted(missing)))
    for module in MODULES:
        file = build / (module + '.jar')
        if file.is_symlink() or not file.is_file():
            raise ValueError('Compiled module missing: ' + str(file))
    previous = destination.with_name('.' + destination.name + '.previous-' + str(uuid.uuid4()))
    with tempfile.TemporaryDirectory(prefix='.stage-candidate-', dir=destination.parent) as temp:
        prepared = Path(temp) / 'stage'
        prepared.mkdir()
        inventories = {}
        for platform, base in [('linux', linux_base), ('win', windows_base)]:
            app = prepared / platform
            app.mkdir()
            for jar in (base / 'app').glob('*.jar'):
                if jar.is_symlink():
                    raise ValueError('Symlink runtime input: ' + jar.name)
                if not jar.name.startswith(OWN_PREFIXES):
                    if jar.name.startswith(('junit-', 'openjfx-monocle-', 'password4j-', 'sqlite-jdbc-')):
                        raise ValueError('Test/server JAR in native client base: ' + jar.name)
                    if jar.name.startswith('javafx-') and ('-win' if platform == 'linux' else '-linux') in jar.name:
                        raise ValueError('Wrong platform JavaFX runtime input: ' + jar.name)
                    if any(jar.name.startswith(artifact + '-') for artifact in SAFE_WEB_ARTIFACTS):
                        continue  # The selected pinned version below replaces all older copies.
                    shutil.copy2(jar, app / jar.name)
            for name, source in dependency_files.items():
                shutil.copy2(source, app / name)
            for module, version in MODULES.items():
                shutil.copy2(build / (module + '.jar'), app / (module + '-' + version + '.jar'))
            verify_safe_web_runtime(app)
            inventories[platform] = {p.name: sha256(p) for p in sorted(app.glob('*.jar'))}
        for module, version in MODULES.items():
            name = module + '-' + version + '.jar'
            if inventories['linux'][name] != inventories['win'][name]:
                raise ValueError('Application JAR differs between client platforms: ' + name)
        (prepared / 'RUNTIME-STAGE-2.0.0.json').write_text(json.dumps({
            'version': '2.0.0', 'productionReady': False,
            'scope': 'offline copied runtime inventory; compilation/native acceptance not asserted',
            'applicationJarHashesMatchAcrossPlatforms': True,
            'runtimeJars': inventories, 'safeWebRuntimePins': SAFE_WEB_RUNTIME,
            'ownerPrivateKeyUsed': False, 'stableFeedChanged': False,
        }, indent=2) + '\n', encoding='utf-8')
        had_previous = destination.exists()
        if had_previous:
            os.replace(destination, previous)
        try:
            os.replace(prepared, destination)
        except BaseException:
            if had_previous:
                os.replace(previous, destination)
            raise
        if had_previous:
            shutil.rmtree(previous)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linux-base', required=True, type=Path)
    parser.add_argument('--windows-base', required=True, type=Path)
    parser.add_argument('--build', type=Path, default=ROOT / 'build/local-java21')
    parser.add_argument('--deps', type=Path, action='append', default=[])
    parser.add_argument('--out', type=Path, default=ROOT / 'client-ui/build/stage')
    args = parser.parse_args()
    result = stage(args.linux_base, args.windows_base, args.build, args.deps, args.out)
    print('Staged verified client runtime JARs in ' + str(result) + '; no final packages or native PASS.')


if __name__ == '__main__':
    main()
