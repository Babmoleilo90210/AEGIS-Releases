#!/usr/bin/env python3
"""Fresh bounded public-identifier OSV/primary-source review of 6.0.0 inputs.

No secrets, source text or user documents are sent. An empty query is reported
as NO_INDEXED_HITS, never as proof that a component has no vulnerabilities.
The input SBOM is not an inventory of a final signed package.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import urllib.error
import urllib.request
from xml.etree import ElementTree as E

MAX_RESPONSE = 8 * 1024 * 1024
PRIMARY = {
    'openssl-vulnerabilities': 'https://openssl-library.org/news/vulnerabilities/',
    'openssl-35-release-notes': 'https://openssl-library.org/news/openssl-3.5-notes/',
    'libsodium-security-advisories': 'https://api.github.com/repos/jedisct1/libsodium/security-advisories?per_page=100',
    'pdfbox-security': 'https://pdfbox.apache.org/security.html',
    'commons-compress-security': 'https://commons.apache.org/proper/commons-compress/security.html',
    'sqlite-security': 'https://www.sqlite.org/security.html',
    'opus-security': 'https://opus-codec.org/security/',
    'gson-security-advisories': 'https://api.github.com/repos/google/gson/security-advisories?per_page=100',
}


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', 'utf-8')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'Audit redirects are rejected', headers, fp)


def fetch(url, target, body=None):
    record = {'requestedAtUtc': datetime.now(timezone.utc).isoformat(), 'url': url,
              'method': 'POST' if body is not None else 'GET', 'tlsVerification': True}
    try:
        request = urllib.request.Request(url, data=body, headers={
            'User-Agent': 'AEGIS-public-dependency-review/6.0.0',
            'Accept': 'application/json,text/html,text/plain', 'Content-Type': 'application/json'})
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            raw = response.read(MAX_RESPONSE + 1)
            record['httpStatus'] = response.status
            if response.status != 200 or len(raw) > MAX_RESPONSE:
                raise ValueError('Incomplete or oversized source response')
        target.write_bytes(raw)
        record.update(status='FETCHED', bytes=len(raw), sha256=sha(target), file=target.name)
        if body is not None:
            record['requestSha256'] = hashlib.sha256(body).hexdigest()
    except (OSError, ValueError) as error:
        record.update(status='BLOCKED', errorType=type(error).__name__, httpStatus=getattr(error, 'code', record.get('httpStatus')))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--maven-dir', type=Path, required=True)
    parser.add_argument('--android-sdk', type=Path, required=True)
    parser.add_argument('--sodium-source', type=Path, required=True)
    parser.add_argument('--sodium-signature', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.project.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    metadata, dependencies = root / 'gradle/verification-metadata.xml', root / 'android/third-party/DEPENDENCIES.json'
    spec = importlib.util.spec_from_file_location('legacy_sca', root / 'tools/audit-dependencies500.py')
    legacy = importlib.util.module_from_spec(spec); spec.loader.exec_module(legacy)
    runtime, pin_files = legacy.pins(root)
    source_files = [metadata, dependencies, root / 'android/build-native.py',
                    root / 'docs/test-results/6.0.0/android-tor-dependency-review/upstream/SUBMODULE-PINS.json']
    before = {str(p.relative_to(root)): sha(p) for p in source_files}
    ns = {'v': 'https://schema.gradle.org/dependency-verification'}
    jars, queries = [], {}
    for component in E.parse(metadata).findall('.//v:component', ns):
        gav = tuple(component.get(k) for k in ('group', 'name', 'version'))
        for artifact in component.findall('v:artifact', ns):
            name = artifact.get('name')
            if not name.endswith('.jar'):
                continue
            path = args.maven_dir / name
            if not path.is_file():
                raise ValueError('Missing pinned JAR: ' + name)
            expected = {h.get('value') for h in artifact.findall('v:sha256', ns)}
            digest = sha(path)
            if digest not in expected:
                raise ValueError('Verification metadata mismatch: ' + name)
            jars.append({'file': name, 'bytes': path.stat().st_size, 'sha256': digest,
                         'coordinate': ':'.join(gav), 'declaredRuntimePin': gav in runtime})
            queries[gav] = {'package': {'ecosystem': 'Maven', 'name': gav[0] + ':' + gav[1]}, 'version': gav[2]}
    supplied = {p.name for p in args.maven_dir.glob('*.jar')}
    recorded = {p['file'] for p in jars}
    for name in sorted(supplied - recorded):
        if name != 'junit-platform-console-standalone-1.13.4.jar':
            raise ValueError('Unmapped restored JAR: ' + name)
        path = args.maven_dir / name
        if sha(path) != '3fdfc37e29744a9a67dd5365e81467e26fbde0b7aa204e6f8bbe79eeaa7ae892':
            raise ValueError('Explicit console test-tool pin differs')
        gav = ('org.junit.platform', 'junit-platform-console-standalone', '1.13.4')
        jars.append({'file': name, 'bytes': path.stat().st_size, 'sha256': sha(path),
                     'coordinate': ':'.join(gav), 'declaredRuntimePin': False, 'scope': 'test-tool'})
        queries[gav] = {'package': {'ecosystem': 'Maven', 'name': gav[0] + ':' + gav[1]}, 'version': gav[2]}
    android = json.loads(dependencies.read_text('utf-8'))
    android_gav = {
        'apksig': ('com.android.tools.build', 'apksig'), 'bctls': ('org.bouncycastle', 'bctls-jdk18on'),
        'torAndroid': ('info.guardianproject', 'tor-android'), 'jtorctl': ('info.guardianproject', 'jtorctl'),
        'localbroadcastmanager': ('androidx.localbroadcastmanager', 'localbroadcastmanager'),
        'androidxAnnotation': ('androidx.annotation', 'annotation'),
    }
    android_inputs = []
    for key, (group, artifact) in android_gav.items():
        entry = android[key]; version = entry['version']
        name = artifact + '-' + version + ('.aar' if 'aarSha256' in entry else '.jar')
        path = args.android_sdk / name
        if not path.is_file() or sha(path) != entry.get('jarSha256', entry.get('aarSha256')):
            raise ValueError('Android input differs from reviewed pin: ' + name)
        android_inputs.append({'file': name, 'bytes': path.stat().st_size, 'sha256': sha(path), 'coordinate': f'{group}:{artifact}:{version}'})
        queries[(group, artifact, version)] = {'package': {'ecosystem': 'Maven', 'name': group + ':' + artifact}, 'version': version}
    query_list = list(queries.values())
    native = dict(android['torAndroid']['nativeVersions'])
    native.update(libsodium='1.0.22', opus=android['opus']['version'], speex=android['speexdsp']['version'])
    for name, version in native.items():
        query_list.append({'package': {'ecosystem': 'OSS-Fuzz', 'name': name}, 'version': version.removesuffix('-stable')})
    submodules = json.loads(source_files[3].read_text('utf-8'))
    commits = [p['sha'] for p in submodules['pins'] if p['path'] != 'external/elf-cleaner']
    commits += list(android['hevTunnel']['commits'].values())
    query_list += [{'commit': commit} for commit in sorted(set(commits))]
    # Deliberately vulnerable package is only an API positive control, never a product input.
    control = {'package': {'ecosystem': 'Maven', 'name': 'org.apache.logging.log4j:log4j-core'}, 'version': '2.14.1'}
    payload = {'queries': query_list + [control]}
    encoded = json.dumps(payload, separators=(',', ':')).encode()
    (out / 'OSV-REQUEST.json').write_bytes(encoded)
    receipts = [fetch('https://api.osv.dev/v1/querybatch', out / 'OSV-RESPONSE.json', encoded)]
    query_results, positive, ids = [], {}, set()
    if receipts[0]['status'] == 'FETCHED':
        response = json.loads((out / 'OSV-RESPONSE.json').read_text())
        results = response.get('results')
        if not isinstance(results, list) or len(results) != len(payload['queries']):
            raise ValueError('OSV response omitted query results')
        for query, result in zip(payload['queries'], results):
            findings = [v['id'] for v in result.get('vulns', [])]
            record = {'query': query, 'status': 'FINDINGS' if findings else 'NO_INDEXED_HITS', 'advisoryIds': findings}
            if result.get('next_page_token'):
                record.update(status='BLOCKED', reason='OSV pagination present; complete query required')
            if query is control:
                positive = record
            else:
                query_results.append(record); ids.update(findings)
    else:
        query_results = [{'query': q, 'status': 'BLOCKED', 'reason': 'OSV request failed'} for q in query_list]
    # Do not suppress findings because severity is absent. Public full advisories retained.
    advisory_records = []
    for identity in sorted(ids)[:32]:
        if not re.fullmatch('[A-Za-z0-9._-]{1,128}', identity):
            raise ValueError('Invalid OSV advisory identifier')
        advisory_records.append(fetch('https://api.osv.dev/v1/vulns/' + identity, out / (identity + '.json')))
    jobs = [(name, url) for name, url in PRIMARY.items()]
    with ThreadPoolExecutor(max_workers=3) as workers:
        primary = list(workers.map(lambda item: fetch(item[1], out / (item[0] + '.source')), jobs))
    # Independently check both official minisign signatures for the newly pinned snapshot.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    source = args.sodium_source
    if sha(source) != android['libsodium']['sourceSha256']:
        raise ValueError('Sodium snapshot differs from current official-authenticated pin')
    key = base64.b64decode(android['libsodium']['officialMinisignPublicKey'])
    lines = args.sodium_signature.read_text().splitlines(); sig = base64.b64decode(lines[1])
    if sig[:2] != b'ED' or sig[2:10] != key[2:10] or not lines[2].startswith('trusted comment: '):
        raise ValueError('Unexpected official sodium signature')
    verifier = Ed25519PublicKey.from_public_bytes(key[10:])
    with source.open('rb') as stream:
        digest = hashlib.file_digest(stream, lambda: hashlib.blake2b(digest_size=64)).digest()
    verifier.verify(sig[10:], digest)
    verifier.verify(base64.b64decode(lines[3]), sig[10:] + lines[2].removeprefix('trusted comment: ').encode())
    sodium = {'sourceSha256': sha(source), 'signatureSha256': sha(args.sodium_signature),
              'keyDocumentation': android['libsodium']['officialKeySource'], 'officialPublicKey': android['libsodium']['officialMinisignPublicKey'],
              'payloadSignatureVerified': True, 'commentSignatureVerified': True, 'trustedComment': lines[2],
              'scope': 'Source authentication only. No Android/native execution or vulnerability-free assertion.'}
    save(out / 'SODIUM-REPIN-VERIFICATION.json', sodium)
    after = {str(p.relative_to(root)): sha(p) for p in source_files}
    report = {'schemaVersion': 1, 'reviewedAtUtc': datetime.now(timezone.utc).isoformat(), 'version': '6.0.0',
              'productionReady': False, 'scope': 'Fresh input SCA, not final package or native acceptance',
              'inputSourceHashesBefore': before, 'inputSourceHashesAfter': after, 'inputSourceUnchanged': before == after,
              'mavenJarInventory': jars, 'androidInputInventory': android_inputs, 'nativeVersions': native,
              'gradleRuntimePinFiles': pin_files, 'queryResults': query_results, 'apiPositiveControl': positive,
              'osvReceipts': receipts, 'advisoryReceipts': advisory_records, 'primarySourceReceipts': primary,
              'advisoryLimitExceeded': len(ids) > 32, 'interpretation': 'NO_INDEXED_HITS_FOR_SUBMITTED_IDENTIFIERS is not proof of package recognition, absence of vulnerabilities or complete dependency closure.'}
    save(out / 'DEPENDENCY-REVIEW-6.0.0.json', report)
    sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'timestamp': report['reviewedAtUtc'], 'component': {'type': 'application', 'name': 'AEGIS-input-review', 'version': '6.0.0'},
                         'properties': [{'name': 'aegis:scope', 'value': 'Reviewed build inputs; reconcile against final package SBOM'}]},
            'components': [{'type': 'library', 'name': coordinate[1], 'group': coordinate[0], 'version': coordinate[2],
                            'purl': f'pkg:maven/{coordinate[0]}/{coordinate[1]}@{coordinate[2]}'} for coordinate in sorted(queries)]}
    save(out / 'SBOM-REVIEWED-INPUTS-6.0.0.cdx.json', sbom)
    print(json.dumps({'jars': len(jars), 'androidInputs': len(android_inputs), 'queries': len(query_list),
                      'findings': sorted(ids), 'positiveControl': positive.get('status'), 'inputSourceUnchanged': before == after,
                      'primaryFetched': sum(r['status'] == 'FETCHED' for r in primary)}, ensure_ascii=False))
    return 0 if before == after and receipts[0]['status'] == 'FETCHED' and positive.get('status') == 'FINDINGS' and not ids else 2


if __name__ == '__main__':
    raise SystemExit(main())
