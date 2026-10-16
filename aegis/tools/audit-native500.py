#!/usr/bin/env python3
"""Inventory reviewed AEGIS native inputs; advisory gaps never become PASS."""
import argparse, datetime, hashlib, json, os, pathlib, re, shutil, subprocess, sys


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def classify_response(data):
    """Tor's network error document is HTTP 200, not usable release metadata."""
    if b'Site Unavailable' in data or b'Site unavailable' in data:
        return 'NOT_RUN_SITE_UNAVAILABLE'
    return 'FETCHED_PRIMARY_SOURCE'


def source_record(item, data):
    """Public evidence is provenance only; fetched documents stay outside releases."""
    record = dict(item)
    actual = hashlib.sha256(data).hexdigest()
    if item.get('sha256') and actual != item['sha256']:
        raise ValueError('Evidence hash mismatch: ' + item['name'])
    record.update(responseSha256=actual, responseBytes=len(data),
                  rawResponseIncluded=False, auditStatus=classify_response(data))
    return record


def command(argv, env=None):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15, env=env)
        return {'argv': argv, 'exitCode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
                'status': 'EXECUTED' if result.returncode == 0 else 'FAILED'}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'argv': argv, 'status': 'NOT_RUN', 'reason': type(error).__name__}


def inspect_native(linux, windows):
    result = []
    for platform, root in [('linux-x86_64', linux), ('windows-x86_64', windows)]:
        entries = [('Tor', 'tor/tor' if platform.startswith('linux') else 'tor/tor.exe'),
                   ('libsodium', 'native/libsodium.so' if platform.startswith('linux') else 'native/libsodium.dll'),
                   ('Opus', 'native/libopus.so' if platform.startswith('linux') else 'native/opus.dll'),
                   ('SpeexDSP', 'native/libspeexdsp.so' if platform.startswith('linux') else 'native/speexdsp.dll'),
                   ('Java', 'runtime/release')]
        for name, relative in entries:
            path = root / relative
            item = {'component': name, 'platform': platform, 'relativePath': relative, 'exists': path.is_file(),
                    'advisoryCoverage': 'NOT_RUN_EXACT_NATIVE_ECOSYSTEM_MAPPING',
                    'nativeTargetAcceptance': 'NOT_RUN'}
            if path.is_file():
                item.update(sha256=digest(path), bytes=path.stat().st_size)
                if name == 'Java':
                    item['releaseMetadata'] = path.read_text()
                if platform.startswith('windows'):
                    item['execution'] = 'NOT_RUN_WINDOWS_UNAVAILABLE'
            result.append(item)
    # Only already reviewed baseline binaries are probed. No downloaded candidate is executed here.
    env = dict(os.environ, LD_LIBRARY_PATH=str(linux / 'tor'))
    probes = {'torVersion': command([str(linux / 'tor/tor'), '--version'], env),
              'javaVersion': command([str(linux / 'runtime/bin/java'), '-version']),
              'torImports': command(['nm', '-D', str(linux / 'tor/tor')])}
    if probes['torImports']['status'] == 'EXECUTED':
        raw = probes['torImports']['stdout']
        probes['torImports']['stdout'] = '\n'.join(line for line in raw.splitlines()
                                                    if re.search(r'\b(?:SSL_|TLS_|DTLS_|BIO_)', line)) + '\n'
        probes['torImports']['unfilteredOutputSha256'] = hashlib.sha256(raw.encode()).hexdigest()
    for name, relative, symbol in [('sodiumVersion', 'native/libsodium.so', 'sodium_version_string'),
                                   ('opusVersion', 'native/libopus.so', 'opus_get_version_string'),
                                   ('opensslVersion', 'tor/libcrypto.so.3', 'OpenSSL_version'),
                                   ('libeventVersion', 'tor/libevent-2.1.so.7', 'event_get_version')]:
        code = 'import ctypes,sys;l=ctypes.CDLL(sys.argv[1]);f=getattr(l,sys.argv[2]);f.restype=ctypes.c_char_p;print((f(0) if sys.argv[2]=="OpenSSL_version" else f()).decode("ascii"))'
        probes[name] = command([sys.executable, '-c', code, str(linux / relative), symbol], env)
    return result, probes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linux-root', type=pathlib.Path, required=True)
    parser.add_argument('--windows-root', type=pathlib.Path, required=True)
    parser.add_argument('--source-cache', type=pathlib.Path, required=True)
    parser.add_argument('--base-verification', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--raw-archive', type=pathlib.Path,
                        help='Optional private build archive outside --out; never copied into public evidence')
    args = parser.parse_args()
    base = json.loads(args.base_verification.read_text())
    if not (base.get('windowsPayload', {}).get('allFilesMatchCheckedZip') and
            base.get('linuxPayload', {}).get('all_payload_files_SHA256_match')):
        raise SystemExit('Reviewed baseline payload evidence is required before native execution')
    args.out.mkdir(parents=True, exist_ok=True)
    if args.raw_archive:
        archive = args.raw_archive.resolve()
        public = args.out.resolve()
        if archive == public or public in archive.parents:
            raise SystemExit('Raw response archive must be outside public evidence')
        archive.mkdir(parents=True, exist_ok=True)
    sources = []
    for manifest in sorted(args.source_cache.glob('FETCH*.json')):
        for item in json.loads(manifest.read_text()):
            source = args.source_cache / (item['name'] + '.response')
            record = dict(item)
            if source.is_file():
                data = source.read_bytes()
                record = source_record(item, data)
                if args.raw_archive:
                    shutil.copyfile(source, args.raw_archive / source.name)
            else:
                record['auditStatus'] = 'NOT_RUN_FETCH_FAILED'
            sources.append(record)
    inventory, probes = inspect_native(args.linux_root.resolve(), args.windows_root.resolve())
    report = {'schema': 1, 'version': '5.0.0', 'timestampUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'status': 'PARTIAL_REVIEW_REQUIRED', 'productionReady': False,
              'scope': 'Reviewed 2.5.0 baseline inputs, not a final 5.0.0 payload scan; target Windows/CachyOS acceptance is separate',
              'baseCommit': base['sourceCommit'], 'baseVerificationSha256': digest(args.base_verification),
              'inventory': inventory, 'probes': probes, 'primarySources': sources, 'rawResponsesIncluded': False,
              'limitations': ['Native upstream versions are not Debian/Alpine package versions; no fabricated OSV ecosystem mapping.',
                             'Empty GitHub advisory API arrays are not proof of absence of CVEs.',
                             'OpenJDK official advisory fetch was unavailable: Java CVE assessment NOT_RUN.',
                             'SpeexDSP version comes from reviewed build provenance, not an exported runtime version function.',
                             'Tor reports host glibc/zlib: distribution backports and host OS vulnerabilities require a separate package audit.',
                             'Unsigned mirror listings are discovery only; new Tor runtime bytes require pinned OpenPGP signature verification.']}
    (args.out / 'NATIVE-DEPENDENCY-INVENTORY-5.0.0.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'components': len(inventory), 'sources': len(sources)}))


if __name__ == '__main__':
    main()
