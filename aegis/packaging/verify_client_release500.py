#!/usr/bin/env python3
"""5.0 offline payload/PE/version verification; native acceptance remains separate."""
from pathlib import Path
import argparse
import json
import stat
import zipfile
from client_runtime500 import verify_safe_web_runtime
from verify_client_release import verify_release as _verify_release
from verify_appimage500 import verify as verify_image500
from tor_runtime500 import verify_runtime as verify_tor_runtime


def verify_client_package_boundary(archive):
    for entry in archive.infolist():
        # Gradle includes parent directory records before shared protocol classes.
        # Empty directory records contain no implementation; files still obey
        # the strict package boundary regardless of their extension.
        if entry.is_dir():
            continue
        name = entry.filename
        if name.startswith('org/securemail/worker/') or (name.startswith('org/securemail/community/')
                and not name.startswith('org/securemail/community/protocol/')):
            raise ValueError('Server/worker implementation classes found in client package')


def verify_release(output, *, unsquashfs):
    output = Path(output).resolve()
    result = _verify_release(output, version='5.0.0')
    for platform, bundle in [('linux', output / 'stage/AEGIS.AppDir'), ('win', output / 'stage/AEGIS')]:
        verify_safe_web_runtime(bundle / 'app')
        result.setdefault('patchedTorRuntime', {})[platform] = verify_tor_runtime(bundle / 'tor', platform)
        for jar in (bundle / 'app').glob('*.jar'):
            with zipfile.ZipFile(jar) as archive:
                verify_client_package_boundary(archive)
        with zipfile.ZipFile(bundle / 'app/client-ui-5.0.0.jar') as archive:
            expected = {'org/securemail/ui/' + name + '.class' for name in [
                'OrganizationsView', 'NewsView', 'KnowledgeLibraryView', 'KnowledgeGraph', 'AdminView', 'DocumentEditor']}
            if not expected <= set(archive.namelist()):
                raise ValueError('5.0 client UI modules missing from packaged application')
        if platform == 'linux':
            # SquashFS uses root ownership; owner-only extracted directories would
            # otherwise fail for normal users even if a root build host can launch.
            for path in [bundle, *bundle.rglob('*')]:
                if path.is_symlink():
                    raise ValueError('Unexpected symlink in normalized AppImage payload')
                mode = stat.S_IMODE(path.stat().st_mode)
                if path.is_dir() and mode != 0o755:
                    raise ValueError('Non-distributable AppImage directory permissions')
                if path.is_file() and (mode & 0o444 != 0o444 or mode & 0o6000):
                    raise ValueError('Non-distributable AppImage file permissions')
    result['version'] = '5.0.0'
    result['appimage'] = verify_image500(output / 'AEGIS-5.0.0-CachyOS-x86_64.AppImage',
                                       output / 'stage/AEGIS.AppDir', unsquashfs)
    result['serverOrNewsWorkerCodeInClient'] = False
    result['linuxPayloadReadableByUnprivilegedUsers'] = True
    result['productionReady'] = False
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--unsquashfs', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_release(args.output, unsquashfs=args.unsquashfs), indent=2) + '\n', end='')
