#!/usr/bin/env python3
"""Compile a separate 2.5.0 owner acceptance kit from the exact source/client ZIPs.

Offline: no package downloads, signatures, publishing, production profile changes,
physical microphone capture, browser launch, or native acceptance execution.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import uuid
import zipfile

VERSION = '2.5.0'
APPLICATION_JARS = ('client-core-2.5.0.jar', 'client-ui-2.5.0.jar', 'common-protocol-0.2.0.jar')
OBSOLETE_UI = {'SafeWeb200Smoke.java', 'Interface200Smoke.java'}
REQUIRED_UI = ('Interface250RefinementSmoke.java', 'VzorGlas250Smoke.java', 'SettingsResponsive200Smoke.java')


def sha(file):
    with file.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def extract(file, destination):
    """Reject traversal, duplicates, links and oversized input before extraction."""
    with zipfile.ZipFile(file) as archive:
        names = set()
        total = 0
        if len(archive.infolist()) > 200_000:
            raise ValueError('Too many ZIP entries')
        for info in archive.infolist():
            path = pathlib.PurePosixPath(info.filename)
            if (not path.parts or path.is_absolute() or '..' in path.parts
                    or '\\' in info.filename or ':' in info.filename
                    or any(ord(char) < 32 or ord(char) == 127 for char in info.filename)
                    or ((info.external_attr >> 16) & 0o170000) == 0o120000):
                raise ValueError('Unsafe ZIP member')
            normalized = path.as_posix().casefold()
            if normalized in names:
                raise ValueError('Duplicate ZIP member')
            names.add(normalized)
            total += info.file_size
            if info.file_size > 4_000_000_000 or total > 12_000_000_000:
                raise ValueError('ZIP exceeds extraction limits')
        bad = archive.testzip()
        if bad is not None:
            raise ValueError('ZIP CRC failed')
        archive.extractall(destination)


def compile_java(javac, sources, classpath, classes, arguments_file):
    classes.mkdir(parents=True, exist_ok=True)
    for source in sources:
        if not source.is_file():
            raise ValueError('Missing current native-kit source: ' + str(source))
    arguments_file.write_text('\n'.join('"' + str(path).replace('\\', '\\\\').replace('"', '\\"') + '"'
                                        for path in sources) + '\n', encoding='utf-8')
    subprocess.run([str(javac), '--release', '21', '-encoding', 'UTF-8', '-cp', classpath,
                    '-d', str(classes), '@' + str(arguments_file)], check=True, timeout=180)


def jar_classes(jar, classes, output, resources=None):
    command = [str(jar), '--create', '--file', str(output), '-C', str(classes), '.']
    if resources is not None and resources.is_dir():
        command += ['-C', str(resources), '.']
    subprocess.run(command, check=True, timeout=45)


def copy_wrappers(source, kit):
    folder = source / 'packaging/native-kit250'
    required = ['AppearanceNativeLauncher.java', 'Common-CachyOS.sh', 'Run-Windows.cmd', 'Run-CachyOS.sh',
                'Run-Appearance-Windows.cmd', 'Run-Appearance-CachyOS.sh',
                'Run-Voice-Windows.cmd', 'Run-Voice-CachyOS.sh', 'README.md']
    for name in required:
        path = folder / name
        if not path.is_file():
            raise ValueError('Missing 2.5.0 native wrapper: ' + name)
        if path.suffix == '.cmd':
            (kit / name).write_bytes(('\r\n'.join(path.read_text('utf-8').splitlines()) + '\r\n').encode('utf-8'))
        else:
            shutil.copy2(path, kit / name)
        if path.suffix == '.sh':
            (kit / name).chmod(0o755)


def copy_frozen_fixtures(source, kit):
    frozen = source / 'client-core/src/test/resources/org/securemail/client/update/frozen'
    provenance = json.loads((frozen / 'PROVENANCE.json').read_text('utf-8'))
    for label in ('v150', 'v200'):
        for name, metadata in provenance['snapshots'][label]['files'].items():
            file = frozen / label / name
            if pathlib.PurePosixPath(name).name != name or sha(file) != metadata['sha256']:
                raise ValueError('Changed frozen historical parser source: ' + label + '/' + name)
    target = kit / 'fixtures/manifest-compatibility'
    target.mkdir(parents=True)
    shutil.copytree(frozen, target / 'frozen')
    for name in ('generate-release-manifest.py', 'test_generate_release_manifest.py'):
        shutil.copy2(source / 'tools' / name, target / name)
    shutil.copy2(source / 'client-core/src/test/java/org/securemail/client/update/SignedManifestCompatibility250Test.java', target)
    (target / 'README.md').write_text(
        '# Historical parser fixtures\n\nExact v1.5.0 and v2.0.0 Git source snapshots and their provenance, '
        'with the current unsigned generator and compatibility test. Source hashes are checked during kit packaging. '
        'These are test-only sources, not executable production classes; no release private key or signing fixture key is stored. '
        'They are not added to app/*.jar or the native runtime classpath. Re-running the JUnit compatibility test '
        'requires a Java 21 JDK, Python 3, vetted JUnit/Gson dependencies and the full source tree; the bundled JRE is insufficient. '
        'Ephemeral test signatures and successful old-parser checks do not prove owner signing, native installation, '
        'restart, migration or rollback E2E. Full updater E2E remains NOT_RUN.\n', encoding='utf-8')
    return provenance


def staging_probes(source, kit, app, deps, temporary, javac, jar):
    """Compile the disposable Relay from the SAME frozen source ZIP, not a local build."""
    common = kit / 'staging'
    common.mkdir()
    for dep in sorted(deps.glob('*.jar')):
        if dep.name.startswith(('password4j-', 'sqlite-jdbc-', 'slf4j-')):
            shutil.copy2(dep, common / dep.name)
    for prefix in ('password4j-', 'sqlite-jdbc-', 'slf4j-'):
        if not any(file.name.startswith(prefix) for file in common.glob('*.jar')):
            raise ValueError('Missing disposable staging dependency: ' + prefix)
    classpath = str(app / 'app/*') + os.pathsep + str(common / '*')
    relay_classes = temporary / 'relay-classes'
    compile_java(javac, sorted((source / 'relay-server/src/main/java').rglob('*.java')), classpath,
                 relay_classes, temporary / 'relay.sources')
    jar_classes(jar, relay_classes, common / 'relay-server.jar', source / 'relay-server/src/main/resources')
    for filename, output in [('LifecycleTorProbe.java', 'lifecycle-tor-tests.jar'),
                             ('PublicProfileTorProbe.java', 'public-profile-tor-tests.jar')]:
        classes = temporary / output.removesuffix('.jar')
        compile_java(javac, [source / 'integration-tests/src/test/java/org/securemail/integration' / filename],
                     classpath, classes, temporary / (output + '.sources'))
        jar_classes(jar, classes, common / output)
    (common / 'README.md').write_text(
        'Disposable current-candidate Relay/probes compiled from the same source ZIP. '
        'Keep these JARs outside app/. Linux-only Relay filesystem permissions. '
        'The probes generate temporary test identities/accounts/database and onion services through actual bundled Tor; '
        'they do not use production accounts, Relay or update feeds. Tor bootstrap failure leaves dependent cases NOT_RUN. '
        'A same-host disposable-Relay result does not replace Windows11/KDE/cross-network acceptance.\n', encoding='utf-8')
    for filename, main, output in [('Run-Public-Profiles-CachyOS.sh', 'PublicProfileTorProbe', 'public-profile-results'),
                                   ('Run-Lifecycle-CachyOS.sh', 'LifecycleTorProbe', 'lifecycle-results')]:
        script = '''#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/Common-CachyOS.sh"
aegis_native_prepare "${1:-}"
"$aegis_test_app/runtime/bin/java" -Xmx768m -Daegis.native.root="$aegis_test_app" -cp "$aegis_test_app/app/*:$aegis_test_kit/staging/*" org.securemail.integration.MAIN "$aegis_test_app" "$aegis_test_kit/OUTPUT"MODE
'''.replace('MAIN', main).replace('OUTPUT', output).replace('MODE', ' snowflake' if main == 'PublicProfileTorProbe' else '')
        (kit / filename).write_text(script, encoding='utf-8')
        (kit / filename).chmod(0o755)


def package(args):
    artifacts = args.artifacts.resolve()
    jdk = args.jdk.resolve()
    suffix = '.exe' if (jdk / 'bin/javac.exe').is_file() else ''
    javac, jar = jdk / ('bin/javac' + suffix), jdk / ('bin/jar' + suffix)
    version = subprocess.run([str(javac), '-version'], check=True, text=True, capture_output=True).stdout
    if not version.startswith('javac 21.'):
        raise ValueError('A Java 21 JDK is required')
    source_zip = artifacts / f'AEGIS-{VERSION}-client-source.zip'
    client_zip = artifacts / f'AEGIS-{VERSION}-Windows-x64.zip'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='aegis250-native-kit-build-') as temporary:
        temporary = pathlib.Path(temporary)
        extract(source_zip, temporary / 'source')
        extract(client_zip, temporary / 'client')
        source, app = temporary / 'source/aegis', temporary / 'client/AEGIS'
        for name in APPLICATION_JARS:
            if not (app / 'app' / name).is_file():
                raise ValueError('Missing current release application JAR: ' + name)
        for file in (app / 'app').glob('*.jar'):
            if file.name.startswith(('client-core-', 'client-ui-', 'common-protocol-')) and file.name not in APPLICATION_JARS:
                raise ValueError('Mixed application versions in client: ' + file.name)
            if file.name.startswith(('relay-server', 'aegis-native-tests', 'aegis-ui-tests', 'junit-')):
                raise ValueError('Server/test JAR leaked into production client: ' + file.name)
        kit = temporary / 'native-acceptance'
        kit.mkdir()
        copy_wrappers(source, kit)
        native = source / 'client-core/src/test/java/org/securemail/client/security'
        ui = source / 'client-ui/src/smoke/java'
        for name in REQUIRED_UI:
            if not (ui / 'org/securemail/ui' / name).is_file():
                raise ValueError('Current 2.5.0 smoke is not ready: ' + name)
        sources = [native / name for name in ('NativeAcceptanceMain.java', 'NativeCredentialStoreSmoke.java', 'VoiceNativeAcceptanceMain.java')]
        sources += [file for file in sorted(ui.rglob('*.java')) if file.name not in OBSOLETE_UI]
        sources.append(kit / 'AppearanceNativeLauncher.java')
        classes = temporary / 'classes'
        compile_java(javac, sources, str(app / 'app/*'), classes, temporary / 'sources')
        native_classes, ui_classes = temporary / 'native-classes', temporary / 'ui-classes'
        native_classes.mkdir()
        ui_classes.mkdir()
        for file in classes.rglob('*.class'):
            relative = file.relative_to(classes)
            destination = (native_classes if 'security' in relative.parts else ui_classes) / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, destination)
        jar_classes(jar, native_classes, kit / 'aegis-native-tests.jar')
        jar_classes(jar, ui_classes, kit / 'aegis-ui-tests.jar')
        with zipfile.ZipFile(kit / 'aegis-ui-tests.jar') as zipped:
            names = zipped.namelist()
            if any('SafeWeb200Smoke' in name or 'Interface200Smoke' in name for name in names):
                raise ValueError('Obsolete 2.0.0 UI acceptance leaked into the current kit')
            for name in ('Interface250RefinementSmoke', 'VzorGlas250Smoke', 'AppearanceNativeLauncher'):
                if f'org/securemail/ui/{name}.class' not in names:
                    raise ValueError('Missing current UI test class: ' + name)
        provenance = copy_frozen_fixtures(source, kit)
        for name in ('NATIVE-ACCEPTANCE-2.5.0.md', 'VZOR-2.5.0.md', 'VZOR-THREAT-MODEL-2.5.0.md',
                     'GLAS-2.5.0.md', 'GLAS-CRYPTOGRAPHY-2.5.0.md'):
            shutil.copy2(source / name, kit / name)
        shutil.copy2(source / 'packaging/native-kit/voice-runtime-provenance.json', kit / 'voice-runtime-provenance.json')
        metadata = {
            'version': VERSION, 'productionReady': False, 'nativeAcceptanceExecuted': False,
            'applicationJarSha256': {name: sha(app / 'app' / name) for name in APPLICATION_JARS},
            'sourceZipSha256': sha(source_zip), 'windowsClientZipSha256': sha(client_zip),
            'productionClientClasspathModified': False, 'signatureFixture': 'EPHEMERAL_TEST_KEY_IN_MEMORY_ONLY',
            'currentUiFixtures': ['Interface250RefinementSmoke', 'SettingsResponsive200Smoke', 'VzorGlas250Smoke'],
            'voiceNativeFixture': 'VoiceNativeAcceptanceMain', 'microphoneOpenedByPackaging': False,
            'frozenParserSources': {name: value['clientVersion'] for name, value in provenance['snapshots'].items()},
            'targetPlatforms': {'Windows11x64': 'NOT_RUN', 'CachyOSKDEWayland': 'NOT_RUN', 'CachyOSKDEX11': 'NOT_RUN'},
        }
        (kit / 'TESTED-ARTIFACTS.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
        if args.staging_deps:
            staging_probes(source, kit, app, args.staging_deps.resolve(), temporary, javac, jar)
        shutil.copy2(pathlib.Path(__file__), kit / 'package-native250.py')
        (kit / 'SHA256SUMS').write_text(''.join(sha(file) + '  ' + file.relative_to(kit).as_posix() + '\n'
                                                    for file in sorted(kit.rglob('*')) if file.is_file() and file.name != 'SHA256SUMS'), encoding='ascii')
        archive = artifacts / f'AEGIS-{VERSION}-native-acceptance.zip'
        partial = artifacts / ('.native-acceptance-' + str(uuid.uuid4()) + '.zip.part')
        try:
            with zipfile.ZipFile(partial, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zipped:
                for file in sorted(kit.rglob('*')):
                    if file.is_file():
                        zipped.write(file, 'native-acceptance/' + file.relative_to(kit).as_posix())
            with zipfile.ZipFile(partial) as zipped:
                if zipped.testzip() is not None:
                    raise ValueError('Native kit ZIP CRC failed')
            # Preserve any earlier owner reports on repack; never delete an old kit.
            destination = artifacts / 'native-acceptance'
            staged = artifacts / ('.native-acceptance-stage-' + str(uuid.uuid4()))
            previous = None
            try:
                shutil.copytree(kit, staged)
                if destination.exists():
                    previous = artifacts / ('native-acceptance-previous-' + str(uuid.uuid4()))
                    destination.rename(previous)
                try:
                    staged.rename(destination)
                except OSError:
                    if previous is not None and not destination.exists():
                        previous.rename(destination)
                    raise
                partial.replace(archive)
            finally:
                if staged.exists():
                    shutil.rmtree(staged)
        finally:
            partial.unlink(missing_ok=True)
    print(json.dumps({'file': archive.name, 'size': archive.stat().st_size, 'sha256': sha(archive),
                      'nativeAcceptanceExecuted': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jdk', required=True, type=pathlib.Path)
    parser.add_argument('--artifacts', required=True, type=pathlib.Path)
    parser.add_argument('--staging-deps', type=pathlib.Path)
    package(parser.parse_args())


if __name__ == '__main__':
    main()
