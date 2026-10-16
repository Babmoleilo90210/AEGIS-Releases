#!/usr/bin/env python3
"""Build 5.0 client-only Setup/Portable/AppImage from one clean frozen commit.

Native bases must match the exact reviewed 2.5.0 release artifacts. This program
never deploys servers, signs, publishes, updates feeds or claims native acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile

from client_runtime500 import sha256, verify_safe_web_runtime, verify_voice_native
from java_runtime import verify_java_runtime
from verify_appimage import verify as verify_image
from verify_appimage500 import verify as verify_image500
from tor_runtime500 import stage_runtime as stage_tor_runtime

ROOT = Path(__file__).resolve().parents[1]
VERSION = '5.0.0'


def run(arguments, **kwargs):
    return subprocess.run([str(value) for value in arguments], check=True, **kwargs)


def normalize_payload(root):
    """SquashFS owner is root; do not ship root-only extraction/umask modes."""
    for file in [Path(root), *Path(root).rglob('*')]:
        if file.is_symlink():
            raise ValueError('Unexpected symlink in distributable payload')
        if file.is_dir():
            file.chmod(0o755)
        elif file.is_file():
            file.chmod(0o755 if file.stat().st_mode & 0o111 else 0o644)
        else:
            raise ValueError('Special file in distributable payload')


def require_frozen_commit(expected):
    if not re.fullmatch('[0-9a-f]{40}', expected):
        raise ValueError('Full frozen source commit is required')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    status = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT, text=True)
    if actual != expected or status.strip():
        raise ValueError('Package only the clean exact frozen source commit')
    epoch = subprocess.check_output(['git', 'show', '-s', '--format=%ct', actual], cwd=ROOT, text=True).strip()
    return actual, int(epoch)


def verify_windows_base(archive, folder):
    """Actual SHA comparison to the checked ZIP, not trusting an extracted exe."""
    folder = Path(folder).resolve()
    expected = set()
    with zipfile.ZipFile(archive) as zipped:
        if zipped.testzip() is not None:
            raise ValueError('2.5 Windows base ZIP CRC failure')
        for item in zipped.infolist():
            entry = PurePosixPath(item.filename)
            if item.is_dir():
                continue
            if not entry.parts or entry.parts[0] != 'AEGIS' or entry.is_absolute() or '..' in entry.parts or '\\' in item.filename:
                raise ValueError('Unsafe base ZIP entry')
            relative = Path(*entry.parts[1:])
            if relative in expected or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('Duplicate/link in base ZIP')
            expected.add(relative)
            file = folder / relative
            if file.is_symlink() or not file.is_file() or file.stat().st_size != item.file_size:
                raise ValueError('Extracted Windows base differs from the reviewed ZIP')
            with zipped.open(item) as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != sha256(file):
                    raise ValueError('Extracted Windows base SHA mismatch')
        actual = {file.relative_to(folder) for file in folder.rglob('*') if file.is_file() or file.is_symlink()}
        if actual != expected:
            raise ValueError('Extra or missing Windows base files')
    return {'allFilesMatchCheckedZip': True, 'files': len(expected)}


def verify_bases(args):
    document = json.loads(args.base_provenance.read_text('utf-8'))
    if document.get('version') != '2.5.0' or not re.fullmatch('[0-9a-f]{40}', document.get('implementationCommit', '')):
        raise ValueError('Exact 2.5.0 build provenance is required')
    records = {item['path']: item for item in document['artifacts']}
    for file, name in [(args.windows_base_zip, 'AEGIS-2.5.0-Windows-x64.zip'),
                       (args.linux_base_image, 'AEGIS-2.5.0-CachyOS-x86_64.AppImage')]:
        expected = records[name]
        if file.is_symlink() or file.stat().st_size != expected['bytes'] or sha256(file) != expected['sha256']:
            raise ValueError('Native base artifact differs from the exact 2.5.0 provenance')
    windows = verify_windows_base(args.windows_base_zip, args.windows_base)
    linux = verify_image(args.linux_base_image, args.linux_base)
    # Only an exact prefix of that same reviewed Type 2 runtime may execute as
    # the new AppImage bootstrap. It is not an arbitrary downloaded executable.
    offset = linux['SquashFS_offset']
    with args.linux_base_image.open('rb') as source:
        runtime_hash = hashlib.sha256(source.read(offset)).hexdigest()
    if args.appimage_runtime.is_symlink() or args.appimage_runtime.stat().st_size != offset or sha256(args.appimage_runtime) != runtime_hash:
        raise ValueError('AppImage runtime differs from the checked 2.5.0 release prefix')
    return {'version': '2.5.0', 'sourceCommit': document['implementationCommit'],
            'windowsArtifactSHA256': records['AEGIS-2.5.0-Windows-x64.zip']['sha256'],
            'linuxArtifactSHA256': records['AEGIS-2.5.0-CachyOS-x86_64.AppImage']['sha256'],
            'windowsPayload': windows, 'linuxPayload': linux,
            'appimageRuntimeSHA256': runtime_hash, 'nativeAcceptance': 'NOT_RUN'}


def copy_docs(target):
    names = {'README.md', 'README-WINDOWS.md', 'README-CACHYOS.md', 'SECURITY.md',
             'THREAT_MODEL.md', 'PRIVACY.md', 'PROTOCOL.md', 'CRYPTO-1.0.0.md', 'ARCHIVE-1.5.0.md'}
    names.update(file.name for file in ROOT.glob('*5.0.0*.md'))
    names.update(file.name for file in ROOT.glob('*5.0.0*.json'))
    for name in sorted(names):
        if (ROOT / name).is_file():
            shutil.copy2(ROOT / name, target / name)
    # Evidence and historical failed test attempts belong to the separate owner
    # evidence ZIP, not every ordinary client installation.
    if (ROOT / 'docs/third-party').is_dir():
        shutil.copytree(ROOT / 'docs/third-party', target / 'docs/third-party')
    shutil.copytree(ROOT / 'resources', target / 'resources')


def prepare(args, stage, name, platform, base, base_proof, source_commit):
    target = stage / name
    if target.exists():
        shutil.rmtree(target)
    target.mkdir()
    for directory in ['native', 'licenses']:
        shutil.copytree(base / directory, target / directory)
    tor_archive = args.tor_windows_archive if platform == 'win' else args.tor_linux_archive
    tor_signature = args.tor_windows_signature if platform == 'win' else args.tor_linux_signature
    tor_proof = stage_tor_runtime(tor_archive, tor_signature, platform, target / 'tor')
    java = args.java_windows if platform == 'win' else args.java_linux
    java_info = verify_java_runtime(java, platform)
    shutil.copytree(java, target / 'runtime')
    verify_java_runtime(target / 'runtime', platform)
    voice = args.voice_windows if platform == 'win' else args.voice_linux
    verify_voice_native(voice, platform)
    shutil.copytree(voice / 'native', target / 'native', dirs_exist_ok=True)
    shutil.copytree(voice / 'licenses', target / 'licenses', dirs_exist_ok=True)
    shutil.copytree(ROOT / 'client-ui/build/stage' / platform, target / 'app')
    pins = verify_safe_web_runtime(target / 'app')
    if any(file.name.startswith(('relay-server-', 'community-server-', 'news-worker-')) for file in (target / 'app').glob('*.jar')):
        raise ValueError('A server artifact must never be packaged as a client dependency')
    copy_docs(target)
    (target / 'JAVA-RUNTIME-5.0.0.json').write_text(json.dumps(java_info, indent=2) + '\n')
    (target / 'TOR-RUNTIME-5.0.0.json').write_text(json.dumps(tor_proof, indent=2) + '\n')
    (target / 'BUILD-INPUTS.json').write_text(json.dumps({'clientVersion': VERSION, 'sourceCommit': source_commit,
            'reusedExactBase': base_proof, 'java': java_info, 'patchedTor': tor_proof,
            'nativeAcceptance': 'NOT_RUN'}, indent=2) + '\n')
    (target / 'RUNTIME-DEPENDENCIES-5.0.0.json').write_text(json.dumps({'version': VERSION, 'platform': platform,
            'sourceCommit': source_commit, 'safeWebRuntimePins': pins,
            'runtimeJars': {file.name: sha256(file) for file in sorted((target / 'app').glob('*.jar'))}}, indent=2) + '\n')
    for jar in (target / 'app').glob('*.jar'):
        with zipfile.ZipFile(jar) as archive:
            for name in archive.namelist():
                leaf = PurePosixPath(name).name
                if not name.endswith('/') and name.startswith('META-INF/') and leaf.upper().startswith(('LICENSE', 'NOTICE', 'COPYING')):
                    if archive.getinfo(name).file_size > 262144:
                        raise ValueError('Oversized dependency licence')
                    (target / 'licenses' / (jar.stem + '-' + leaf)).write_bytes(archive.read(name))
    return target


def package(args):
    source_commit, epoch = require_frozen_commit(args.expected_commit)
    if args.out.is_symlink():
        raise ValueError('Package output must not be a symlink')
    args.out = args.out.resolve()
    inputs = [ROOT, args.linux_base.resolve(), args.windows_base.resolve(), args.java_linux.resolve(),
              args.java_windows.resolve(), args.voice_linux.resolve(), args.voice_windows.resolve(), args.mingw.resolve()]
    if any(args.out == source or args.out in source.parents or source in args.out.parents for source in inputs):
        raise ValueError('Package output must not overlap source/native/tool inputs')
    args.out.mkdir(parents=True, exist_ok=True)
    stage = args.out / 'stage'
    if stage.is_symlink():
        raise ValueError('Package staging directory must not be a symlink')
    stage.mkdir(exist_ok=True)
    proof = verify_bases(args)
    (args.out / 'REUSED-BASE-2.5.0-VERIFICATION.json').write_text(json.dumps(proof, indent=2) + '\n')
    windows = prepare(args, stage, 'AEGIS', 'win', args.windows_base, proof, source_commit)
    mingw = args.mingw.resolve()
    compiler = next((mingw / name for name in ['x86_64-w64-mingw32-clang', 'x86_64-w64-mingw32-gcc', 'x86_64-w64-mingw32-gcc-win32']
                     if (mingw / name).is_file()), None)
    if compiler is None:
        raise ValueError('Explicit reviewed MinGW compiler is required')
    resource = stage / 'launcher500.res'
    run([mingw / 'x86_64-w64-mingw32-windres', '--codepage=65001', 'launcher500.rc', '-O', 'coff', '-o', resource], cwd=ROOT / 'packaging/windows')
    for source, name, libraries in [('launcher.c', 'AEGIS.exe', ['-luser32']),
                                     ('maintenance500.c', 'AEGIS-Maintenance.exe', ['-luser32', '-lshell32', '-ladvapi32']),
                                     ('updater.c', 'AEGIS-Updater.exe', ['-luser32', '-lshell32'])]:
        run([compiler, '-Os', '-municode', '-mwindows', '-finput-charset=UTF-8', ROOT / 'packaging/windows' / source, resource,
             '-Wl,--dynamicbase,--nxcompat,--high-entropy-va,--no-insert-timestamp', *libraries, '-o', windows / name])
    resource.unlink()
    shutil.copy2(ROOT / 'packaging/windows/CreateShortcuts.ps1', windows / 'CreateShortcuts.ps1')
    normalize_payload(windows)
    with zipfile.ZipFile(args.out / 'AEGIS-5.0.0-Windows-x64.zip', 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for file in sorted(windows.rglob('*')):
            if file.is_file():
                info = zipfile.ZipInfo('AEGIS/' + file.relative_to(windows).as_posix(), time.gmtime(epoch)[:6])
                info.create_system = 3; info.external_attr = (0o100644 << 16); info.compress_type = zipfile.ZIP_DEFLATED
                with file.open('rb') as source, archive.open(info, 'w') as target:
                    shutil.copyfileobj(source, target)
    run([args.makensis.resolve(), '-V2', '-DPAYLOAD=' + str(windows), '-DOUTFILE=' + str(args.out / 'AEGIS-Setup-5.0.0-x64.exe'),
         'installer500.nsi'], cwd=ROOT / 'packaging/windows')
    linux = prepare(args, stage, 'AEGIS.AppDir', 'linux', args.linux_base, proof, source_commit)
    for file in [linux / 'tor/tor', linux / 'tor/pluggable_transports/lyrebird']:
        file.chmod(0o755)
    shutil.copy2(ROOT / 'packaging/linux/AppRun', linux / 'AppRun'); (linux / 'AppRun').chmod(0o755)
    shutil.copy2(ROOT / 'packaging/linux/aegis500.desktop', linux / 'aegis.desktop')
    for name in ['aegis.png', '.DirIcon']:
        shutil.copy2(ROOT / 'resources/aegis.png', linux / name)
    normalize_payload(linux)
    image = args.out / 'AEGIS-5.0.0-CachyOS-x86_64.AppImage'
    with tempfile.TemporaryDirectory(prefix='.appimage-build500-', dir=args.out) as directory:
        candidate, squash = Path(directory) / image.name, Path(directory) / 'payload.squashfs'
        run([args.mksquashfs.resolve(), linux, squash, '-noappend', '-processors', '2', '-comp', 'zstd', '-b', '131072',
             '-all-root', '-no-xattrs', '-mkfs-time', str(epoch), '-all-time', str(epoch)])
        with candidate.open('wb') as output:
            for part in [args.appimage_runtime, squash]:
                with part.open('rb') as source:
                    shutil.copyfileobj(source, output)
        candidate.chmod(0o755)
        image_proof = verify_image500(candidate, linux, args.mksquashfs.resolve().with_name('unsquashfs'))
        with candidate.open('rb') as stream:
            os.fsync(stream.fileno())
        os.replace(candidate, image)
    (args.out / 'APPIMAGE-PERMISSIONS-5.0.0.json').write_text(json.dumps({'artifactSHA256': sha256(image),
            'verification': image_proof, 'nativeAcceptance': 'NOT_RUN'}, indent=2) + '\n')
    require_frozen_commit(args.expected_commit)
    print('Created 5.0 Windows Setup, Portable ZIP and CachyOS AppImage from frozen source. Native acceptance is separate; no publication.')


def parser():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['java-linux', 'java-windows', 'voice-linux', 'voice-windows', 'linux-base', 'windows-base',
                 'linux-base-image', 'windows-base-zip', 'base-provenance', 'mingw', 'makensis', 'appimage-runtime', 'mksquashfs',
                 'tor-linux-archive', 'tor-windows-archive', 'tor-linux-signature', 'tor-windows-signature', 'out']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    return parser


if __name__ == '__main__':
    package(parser().parse_args())
