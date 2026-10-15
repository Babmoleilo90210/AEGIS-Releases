#!/usr/bin/env python3
"""Validate the finished Type 2 AppImage, including every extracted payload file."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').digest()


def verify(image, appdir):
    image, appdir = Path(image).resolve(), Path(appdir).resolve()
    with image.open('rb') as stream:
        header = stream.read(16)
        if header[:4] != b'\x7fELF' or header[8:11] != b'AI\x02':
            raise RuntimeError('AppImage does not contain a Type 2 ELF runtime')
    offset = int(subprocess.check_output([image, '--appimage-offset'], timeout=30).strip())
    with image.open('rb') as stream:
        stream.seek(offset)
        if stream.read(4) != b'hsqs':
            raise RuntimeError('AppImage SquashFS superblock is missing')
    with tempfile.TemporaryDirectory(prefix='aegis-appimage-check-', dir=image.parent) as directory:
        subprocess.run([image, '--appimage-extract'], cwd=directory,
                       stdout=subprocess.DEVNULL, check=True, timeout=120)
        extracted = Path(directory) / 'squashfs-root'
        count = 0
        expected = set()
        for source in appdir.rglob('*'):
            relative = source.relative_to(appdir)
            target = extracted / relative
            if source.is_symlink():
                raise RuntimeError(f'Unexpected payload symlink: {relative}')
            if source.is_file():
                expected.add(relative)
                if target.is_symlink() or not target.is_file() or digest(source) != digest(target):
                    raise RuntimeError(f'AppImage payload mismatch: {relative}')
                if source.stat().st_mode & 0o111 and not target.stat().st_mode & 0o111:
                    raise RuntimeError(f'AppImage executable mode lost: {relative}')
                count += 1
        actual = {p.relative_to(extracted) for p in extracted.rglob('*') if p.is_file() or p.is_symlink()}
        if actual != expected:
            raise RuntimeError('AppImage contains unexpected or missing files')
        version = subprocess.run([extracted / 'runtime/bin/java', '-version'],
                                 capture_output=True, text=True, check=True, timeout=30).stderr.strip()
        if 'version "21.' not in version:
            raise RuntimeError('AppImage Java runtime is not version 21')
    return {'ELF_Type_2': True, 'SquashFS_offset': offset, 'extraction': 'OK',
            'all_payload_files_SHA256_match': True, 'file_count': count,
            'executable_modes_preserved': True, 'java_version': version}


if __name__ == '__main__':
    print(json.dumps(verify(sys.argv[1], sys.argv[2]), indent=2))
