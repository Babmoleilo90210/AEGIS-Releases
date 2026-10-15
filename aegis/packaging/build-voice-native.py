#!/usr/bin/env python3
"""Build pinned official Xiph audio libraries. Build-time network only; never run by the app.
Requires Python 3.11+, make, a C compiler, and the standard Linux or MinGW x64 toolchain.
Examples:
  python3 packaging/build-voice-native.py --platform linux --output /tmp/audio-linux
  python3 packaging/build-voice-native.py --platform windows --cc x86_64-w64-mingw32-gcc --output /tmp/audio-win
The output native/ and licenses/ directories belong in the signed application package.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

SOURCES = {
    'opus': ('1.6.1', 'https://downloads.xiph.org/releases/opus/opus-1.6.1.tar.gz',
             '6ffcb593207be92584df15b32466ed64bbec99109f007c82205f0194572411a1'),
    'speexdsp': ('1.2.1', 'https://downloads.xiph.org/releases/speex/speexdsp-1.2.1.tar.gz',
                 '8c777343e4a6399569c72abc38a95b24db56882c83dbdb6c6424a5f4aeb54d3d'),
}

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--platform', choices=['linux', 'windows'], required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--work', type=Path, default=Path('.build-inputs/voice'))
    p.add_argument('--archive-cache', type=Path)
    p.add_argument('--cc')
    p.add_argument('--jobs', type=int, default=4)
    p.add_argument('--compiled-registry', type=Path, help='Explicitly regenerate this trusted JAR resource from this fresh verified-source build')
    a = p.parse_args()
    if not 1 <= a.jobs <= 32: p.error('jobs must be 1..32')
    work = a.work.resolve(); work.mkdir(parents=True, exist_ok=True)
    cache = (a.archive_cache or work).resolve(); cache.mkdir(parents=True, exist_ok=True)
    output = a.output.resolve(); (output / 'native').mkdir(parents=True, exist_ok=True)
    (output / 'licenses').mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    if a.cc: env['CC'] = a.cc
    elif a.platform == 'windows': env['CC'] = 'x86_64-w64-mingw32-gcc'
    compiler = env.get('CC', 'cc')
    compiler_version = subprocess.check_output([compiler, '--version'], text=True).splitlines()[0]
    target = subprocess.check_output([compiler, '-dumpmachine'], text=True).strip()
    if not target.startswith('x86_64') or (a.platform == 'windows') != ('mingw' in target):
        raise ValueError('Compiler target does not match requested x86_64 platform: ' + target)
    provenance = {'platform': a.platform + '-x86_64', 'compiler': compiler_version,
                  'sourceDateEpoch': env.get('SOURCE_DATE_EPOCH'), 'libraries': []}
    for name, (version, url, expected) in SOURCES.items():
        archive = cache / f'{name}-{version}.tar.gz'
        if not archive.exists():
            temporary = archive.with_suffix('.download')
            try:
                with urllib.request.urlopen(url, timeout=180) as source, temporary.open('wb') as target:
                    shutil.copyfileobj(source, target)
                if sha(temporary) != expected: raise ValueError('Official archive SHA-256 mismatch: ' + name)
                temporary.replace(archive)
            finally:
                temporary.unlink(missing_ok=True)
        if sha(archive) != expected: raise ValueError('Cached archive SHA-256 mismatch: ' + name)
        src = work / f'{name}-{version}'
        build = work / (a.platform + '-' + name)
        # Do not seal pre-existing objects or a locally modified source tree as trusted.
        for generated in (src, build):
            if generated.is_symlink(): raise ValueError('Build path is a symbolic link')
            if generated.exists(): shutil.rmtree(generated)
        with tarfile.open(archive) as source:
            source.extractall(work, filter='data')
        build.mkdir()
        args = [str(src / 'configure'), '--disable-static', '--enable-shared']
        if a.platform == 'windows': args += ['--host=x86_64-w64-mingw32', 'LDFLAGS=-static-libgcc']
        if name == 'opus':
            args += ['--disable-extra-programs', '--disable-doc', '--disable-deep-plc', '--disable-dred', '--disable-osce']
        else: args += ['--disable-examples']
        with (build / 'configure.log').open('w') as log:
            subprocess.run(args, cwd=build, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        with (build / 'make.log').open('w') as log:
            subprocess.run(['make', '-j' + str(a.jobs)], cwd=build, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        folder = build / ('.libs' if name == 'opus' else 'libspeexdsp/.libs')
        original = folder / (('libopus-0.dll' if name == 'opus' else 'libspeexdsp-1.dll') if a.platform == 'windows' else 'lib' + name + '.so')
        filename = (name + '.dll') if a.platform == 'windows' else ('lib' + name + '.so')
        library = output / 'native' / filename; shutil.copyfile(original, library)
        license_file = output / 'licenses' / (name + '-' + version + '-LICENSE'); shutil.copyfile(src / 'COPYING', license_file)
        provenance['libraries'].append({'name': name, 'version': version, 'source': url,
            'sourceSHA256': expected, 'filename': filename, 'binarySHA256': sha(library),
            'license': 'BSD-3-Clause', 'licenseSHA256': sha(license_file), 'configure': args[1:]})
    (output / 'voice-runtime-provenance.json').write_text(json.dumps(provenance, ensure_ascii=False, indent=2) + '\n')
    if a.compiled_registry:
        registry = {'schema': 1, 'libraries': {}}
        if a.compiled_registry.exists(): registry = json.loads(a.compiled_registry.read_text())
        registry['libraries'][a.platform + '-x86_64'] = {item['filename']: item['binarySHA256'] for item in provenance['libraries']}
        a.compiled_registry.parent.mkdir(parents=True, exist_ok=True)
        a.compiled_registry.write_text(json.dumps(registry, indent=2) + '\n')
    print('Built verified Xiph voice libraries in ' + str(output))

if __name__ == '__main__': main()
