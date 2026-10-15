#!/usr/bin/env python3
"""Offline, fail-closed installation of an official, signed Tor Browser bundle.

No network access, AEGIS keys, browser preferences, Tor configuration or update
feed is used. Supply the official archive/portable installer, its detached .asc,
and the exported Tor Browser Developers public keyring. Linux is extracted here;
Windows portable installation runs the authenticated official NSIS installer on
Windows only. --verify-only works on either host and never executes the package.

--check-installed compares every immutable file/link with the freshly verified
package. --reseal additionally replaces local inventories ONLY after that exact
comparison succeeds. Use this after the official Tor Browser updater, supplying
the corresponding new signed official package; local hashes alone are not an
update authentication mechanism. Tor Browser's own updater remains unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

FINGERPRINT = 'EF6E286DDA85EA2A4BA7DE684E2C6E8793298290'
MAX_ARCHIVE = 1_000_000_000
MAX_EXPANDED = 3_000_000_000
MAX_MEMBERS = 20000
INVENTORY = 'aegis-verified.sha256'
LINKS = 'aegis-verified-links.json'
RECEIPT = 'aegis-verification.json'
LOCAL_FILES = {INVENTORY, LINKS, RECEIPT}
PACKAGE_RE = re.compile(r'^tor-browser-(linux-x86_64|windows-x86_64-portable)-([0-9]+(?:\.[0-9]+){1,3})\.(tar\.xz|exe)$')
# The official Linux launcher rewrites the ROOT .desktop shortcut on each launch.
# Its canonical Browser/start-tor-browser.desktop remains immutable and checked.
MUTABLE_FILES = {'start-tor-browser.desktop'}
MUTABLE_DIRS = ('Browser/TorBrowser/Data/', 'aegis-downloads/')


def sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular_input(path: Path, maximum: int) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError('Regular, non-symlink input files required')
    if not 0 < path.stat().st_size <= maximum:
        raise ValueError('Input is empty or exceeds the size limit')


def snapshot_input(source: Path, destination: Path, maximum: int) -> None:
    """Verification and extraction use the SAME private snapshot, avoiding races."""
    regular_input(source, maximum)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(source, flags)
    with os.fdopen(descriptor, 'rb') as src, destination.open('xb') as dst:
        info = os.fstat(src.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise ValueError('Regular bounded input required')
        remaining = maximum
        while block := src.read(min(1 << 20, remaining + 1)):
            remaining -= len(block)
            if remaining < 0:
                raise ValueError('Input grew beyond its size limit')
            dst.write(block)
    destination.chmod(0o600)


def verify_signature(archive: Path, signature: Path, keyring: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix='gpgv-', dir=archive.parent) as gnupg:
        result = subprocess.run(
            ['gpgv', '--homedir', gnupg, '--status-fd', '1', '--keyring', str(keyring.resolve()),
             str(signature.resolve()), str(archive.resolve())],
            capture_output=True, text=True, timeout=120, check=False)
    # VALIDSIG: signing-fpr date timestamp expiry version reserved pubkey hash class [primary-fpr]
    rows = [line.split()[2:] for line in result.stdout.splitlines()
            if line.startswith('[GNUPG:] VALIDSIG ')]
    valid = [row for row in rows if row and (row[0] == FINGERPRINT or
                                           (len(row) >= 10 and row[9] == FINGERPRINT))]
    rejected = ('BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'NO_PUBKEY', 'NODATA', 'FAILURE')
    if (result.returncode or len(rows) != 1 or not valid or len(valid[0]) < 9
            or valid[0][7] not in {'8', '9', '10'} or valid[0][8] != '00' or any(
            f'[GNUPG:] {tag} ' in result.stdout for tag in rejected)):
        raise ValueError('Official Tor Browser Developers signature required; refresh its public keyring if expired')
    row = valid[0]
    return {'primaryFingerprint': FINGERPRINT, 'signingFingerprint': row[0],
            'signatureTimestamp': row[2] if len(row) > 2 else None}


def package_info(filename: str) -> tuple[str, str]:
    match = PACKAGE_RE.fullmatch(filename)
    if not match:
        raise ValueError('Official stable Linux x86_64 tar.xz or Windows x86_64 portable.exe filename required')
    raw_platform, version, suffix = match.groups()
    if (raw_platform.startswith('linux') and suffix != 'tar.xz') or (raw_platform.startswith('windows') and suffix != 'exe'):
        raise ValueError('Package extension does not match its platform')
    return ('linux-x86_64' if raw_platform.startswith('linux') else 'windows-x86_64', version)


def safe_path(value: str) -> PurePosixPath:
    # Reject Windows paths as well: manifests are portable and later consumed on Windows.
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value) or '\\' in value or ':' in value:
        raise ValueError('Unsafe archive path')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('Unsafe archive path')
    return path


def normalized_link(member: PurePosixPath, target: str, hardlink: bool = False) -> PurePosixPath:
    if not target or any(ord(c) < 32 or ord(c) == 127 for c in target) or '\\' in target or ':' in target:
        raise ValueError('Unsafe archive link')
    path = PurePosixPath(target)
    if path.is_absolute():
        raise ValueError('Absolute archive link')
    parts = [] if hardlink else list(member.parent.parts)
    for part in path.parts:
        if part == '..':
            if not parts:
                raise ValueError('Escaping archive link')
            parts.pop()
        elif part != '.':
            parts.append(part)
    result = PurePosixPath(*parts)
    if not result.parts or result.parts[0] != member.parts[0]:
        raise ValueError('Escaping archive link')
    return result


def inspect_tar(tar: tarfile.TarFile) -> tuple[dict, str]:
    entries = {}
    expanded = 0
    for item in tar:
        path = safe_path(item.name)
        name = path.as_posix()
        if name in entries:
            raise ValueError('Duplicate archive member')
        if not (item.isfile() or item.isdir() or item.issym() or item.islnk()):
            raise ValueError('Device, FIFO or unsupported archive member')
        if item.size < 0:
            raise ValueError('Invalid archive size')
        expanded += item.size
        entries[name] = item
        if len(entries) > MAX_MEMBERS or expanded > MAX_EXPANDED:
            raise ValueError('Expanded archive exceeds limits')
    roots = {PurePosixPath(name).parts[0] for name in entries}
    if len(roots) != 1:
        raise ValueError('A single official bundle root required')
    root = roots.pop()
    for name, item in entries.items():
        for parent in PurePosixPath(name).parents:
            ancestor = entries.get(parent.as_posix())
            if ancestor is not None and not ancestor.isdir():
                raise ValueError('Archive member underneath a link or regular file')
        if item.issym() or item.islnk():
            current, visited = name, set()
            while True:
                if current in visited:
                    raise ValueError('Cyclic archive link')
                visited.add(current)
                target = entries.get(current)
                # Many tar producers omit explicit directory members. File targets must exist.
                if target is None:
                    if any(key.startswith(current + '/') for key in entries):
                        break
                    raise ValueError('Dangling archive link')
                if not (target.issym() or target.islnk()):
                    if item.islnk() and not target.isfile():
                        raise ValueError('Hardlink must target a regular file')
                    break
                current = normalized_link(PurePosixPath(current), target.linkname, target.islnk()).as_posix()
    return entries, root


def extract_linux(archive: Path, target: Path) -> Path:
    target.mkdir(mode=0o700)
    with tarfile.open(archive, 'r:xz') as tar:
        entries, root = inspect_tar(tar)
        # No extractall: special files, archive ownership and setuid bits never propagate.
        for name, item in sorted(entries.items(), key=lambda pair: len(PurePosixPath(pair[0]).parts)):
            path = target.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if item.isdir():
                path.mkdir(mode=0o700, exist_ok=True)
            elif item.isfile():
                with tar.extractfile(item) as src, path.open('xb') as dst:
                    shutil.copyfileobj(src, dst, length=1 << 20)
                path.chmod(0o700 if item.mode & 0o111 else 0o600)
        # Hardlink chains are flattened to their validated regular target (same bytes/inode).
        for name, item in entries.items():
            if not item.islnk():
                continue
            current = name
            while entries[current].islnk() or entries[current].issym():
                entry = entries[current]
                current = normalized_link(PurePosixPath(current), entry.linkname, entry.islnk()).as_posix()
            path = target.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.link(target.joinpath(*PurePosixPath(current).parts), path)
        for name, item in entries.items():
            if item.issym():
                path = target.joinpath(*PurePosixPath(name).parts)
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.symlink_to(item.linkname)
    bundle = target / root
    for required in ('Browser/start-tor-browser', 'Browser/firefox', 'Browser/application.ini', 'Browser/TorBrowser/Tor/tor'):
        if not (bundle / required).is_file():
            raise ValueError(f'Official Linux bundle layout required: {required}')
    return bundle


def install_windows(archive: Path, destination: Path) -> Path:
    if os.name != 'nt':
        raise ValueError('Native Windows required for official portable installer; --verify-only is available on this host')
    # NSIS /D= is the final, UNQUOTED parameter; CreateProcess receives this string
    # directly (shell=False), so ampersands are literal path characters, not commands.
    text = str(destination.resolve())
    if any(ord(c) < 32 for c in text) or '"' in text:
        raise ValueError('Unsafe Windows destination')
    command = subprocess.list2cmdline([str(archive.resolve()), '/S']) + ' /D=' + text
    result = subprocess.run(command, shell=False, timeout=600, check=False)
    if result.returncode:
        raise ValueError(f'Official Windows portable installer failed ({result.returncode})')
    for required in ('Browser/firefox.exe', 'Browser/application.ini', 'Browser/TorBrowser/Tor/tor.exe'):
        if not (destination / required).is_file():
            raise ValueError(f'Official Windows portable bundle layout required: {required}')
    return destination


def mutable(relative: str) -> bool:
    return relative in MUTABLE_FILES or any(relative.startswith(prefix) or relative == prefix[:-1] for prefix in MUTABLE_DIRS)


def inventories(bundle: Path) -> tuple[dict[str, str], dict[str, str]]:
    files, links = {}, {}
    for current, dirs, names in os.walk(bundle, followlinks=False):
        directory = Path(current)
        for name in [*dirs, *names]:
            path = directory / name
            relative = path.relative_to(bundle).as_posix()
            safe_path(relative)
            if relative in LOCAL_FILES or mutable(relative):
                if path.is_symlink():
                    raise ValueError('Mutable/profile/inventory root cannot be a symlink')
                if name in dirs:
                    dirs.remove(name)
                continue
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                # Reject even a harmless-looking link if an ancestor/final target escapes.
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(bundle.resolve()):
                    raise ValueError('Installed link escapes bundle')
                links[relative] = os.readlink(path)
                if name in dirs:
                    dirs.remove(name)
            elif stat.S_ISREG(info.st_mode):
                files[relative] = sha256(path)
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError('Installed bundle contains a special file')
    return dict(sorted(files.items())), dict(sorted(links.items()))


def write_inventories(bundle: Path, files: dict, links: dict, receipt: dict) -> None:
    raw = ''.join(f'{digest}  {name}\n' for name, digest in files.items())
    raw_links = json.dumps({'schemaVersion': 1, 'links': links}, indent=2, sort_keys=True) + '\n'
    receipt = {**receipt, 'manifestSHA256': hashlib.sha256(raw.encode()).hexdigest(),
               'linksSHA256': hashlib.sha256(raw_links.encode()).hexdigest()}
    for name, value in ((INVENTORY, raw), (LINKS, raw_links),
                        (RECEIPT, json.dumps(receipt, indent=2, sort_keys=True) + '\n')):
        path = bundle / name
        if path.is_symlink():
            raise ValueError('Unsafe local inventory path')
        temporary = bundle / (name + '.new')
        with temporary.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(value)
        temporary.chmod(0o600)
        temporary.replace(path)


def run(args: argparse.Namespace) -> dict:
    platform, version = package_info(args.archive.name)
    if args.expected_version and version != args.expected_version:
        raise ValueError('Package version differs from the expected version')
    if args.expected_sha256 and not re.fullmatch('[0-9a-fA-F]{64}', args.expected_sha256):
        raise ValueError('Expected SHA-256 must be 64 hexadecimal characters')
    with tempfile.TemporaryDirectory(prefix='aegis-tor-verify-') as scratch:
        work = Path(scratch)
        archive, signature, keyring = work / args.archive.name, work / 'signature.asc', work / 'tor.keyring'
        snapshot_input(args.archive, archive, MAX_ARCHIVE)
        snapshot_input(args.signature, signature, 100_000)
        snapshot_input(args.keyring, keyring, 20_000_000)
        verified = verify_signature(archive, signature, keyring)
        digest = sha256(archive)
        if args.expected_sha256 and digest != args.expected_sha256.lower():
            raise ValueError('Package differs from expected SHA-256')
        receipt = {'schemaVersion': 1, 'platform': platform, 'packageVersionLabel': version, 'versionLabelSource': 'filename-not-authenticated',
                   'archiveName': args.archive.name, 'archiveSHA256': digest,
                   'signatureSHA256': sha256(signature), 'signature': verified,
                   'updater': 'official-tor-browser-unchanged',
                   'authentication': 'detached-openpgp-pinned-primary-fingerprint'}
        if args.verify_only:
            return {**receipt, 'operation': 'signature-verification', 'installed': False}
        destination = args.destination.absolute()
        if destination.is_symlink():
            raise ValueError('Destination cannot be a symlink')
        if args.check_installed or args.reseal:
            if not destination.is_dir():
                raise ValueError('Installed bundle directory required')
        elif destination.exists():
            raise ValueError('Destination must not exist; existing profiles are never overwritten')
        if platform == 'linux-x86_64':
            expected = extract_linux(archive, work / 'unpack')
        else:
            expected = install_windows(archive, work / 'windows-unpack')
        files, links = inventories(expected)
        if len(files) < 10:
            raise ValueError('Incomplete official bundle inventory')
        receipt['immutableFiles'] = len(files)
        receipt['internalSymlinks'] = len(links)
        if args.check_installed or args.reseal:
            actual = inventories(destination)
            if actual != (files, links):
                changed = sorted(set(actual[0]) ^ set(files) | {x for x in files.keys() & actual[0].keys() if files[x] != actual[0][x]})
                raise ValueError('Installed immutable content differs from signed package' + (': ' + changed[0] if changed else ' (links)'))
            if args.reseal:
                write_inventories(destination, files, links, receipt)
            return {**receipt, 'operation': 'authenticated-reseal' if args.reseal else 'installed-comparison', 'installed': True}
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.mkdir(mode=0o700)  # exclusive creation; never remove a pre-existing path
        try:
            shutil.copytree(expected, destination, dirs_exist_ok=True, symlinks=True)
            if inventories(destination) != (files, links):
                raise ValueError('Installed copy verification failed')
            write_inventories(destination, files, links, receipt)
        except BaseException:
            shutil.rmtree(destination)
            raise
        return {**receipt, 'operation': 'installation', 'installed': True}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--signature', type=Path, required=True)
    parser.add_argument('--keyring', type=Path, required=True)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--expected-version')
    parser.add_argument('--expected-sha256')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--verify-only', action='store_true')
    mode.add_argument('--check-installed', action='store_true')
    mode.add_argument('--reseal', action='store_true')
    args = parser.parse_args(argv)
    if not args.verify_only and args.destination is None:
        parser.error('--destination required for installation/comparison/reseal')
    try:
        result = run(args)
    except (ValueError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(2, f'Verification/install refused: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
