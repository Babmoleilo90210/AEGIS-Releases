"""5.0 AppImage bytes + actual SquashFS ownership/permissions, not native OS QA."""
from pathlib import Path
import subprocess
from verify_appimage import verify as verify_payload


def listing_permissions(text, expected):
    actual = set(); directories = files = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 5)
        if len(fields) != 6:
            raise ValueError('Malformed SquashFS listing')
        mode, owner, _, _, _, path = fields
        if path in actual or path not in expected:
            raise ValueError('Unexpected or duplicate SquashFS metadata entry')
        actual.add(path)
        if owner != '0/0':
            raise ValueError('Unexpected distributable SquashFS owner')
        if mode == 'drwxr-xr-x':
            directories += 1
        elif mode in ('-rw-r--r--', '-rwxr-xr-x'):
            files += 1
        else:
            raise ValueError('SquashFS metadata is unreadable by ordinary users or has special permissions')
    if actual != expected:
        raise ValueError('Incomplete SquashFS metadata listing')
    return {'actualSquashFSOwnersAreRoot': True, 'actualSquashFSReadableByUnprivilegedUsers': True,
            'directories': directories, 'files': files, 'setuidSetgidOrSpecialNodes': False}


def verify(image, appdir, unsquashfs):
    image, appdir, unsquashfs = map(lambda path: Path(path).resolve(), (image, appdir, unsquashfs))
    result = verify_payload(image, appdir)
    process = subprocess.run([str(unsquashfs), '-lln', '-o', str(result['SquashFS_offset']), str(image)],
                             capture_output=True, text=True, check=True, timeout=60)
    if len(process.stdout) > 8_000_000:
        raise ValueError('Oversized SquashFS metadata listing')
    expected = {'squashfs-root'} | {'squashfs-root/' + path.relative_to(appdir).as_posix() for path in appdir.rglob('*')}
    result['squashFSMetadataPermissions'] = listing_permissions(process.stdout, expected)
    return result
