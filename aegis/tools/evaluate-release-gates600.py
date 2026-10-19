#!/usr/bin/env python3
"""Validate source-bound 6.0.0 acceptance evidence; never edit a feed or a signature.

Receipts are reviewable records, not a substitute for independent acceptance.
This program rejects absent gates, altered evidence, old-source receipts and a
recorded readiness value that disagrees with the mandatory results.
"""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

VERSION = '6.0.0'
STATUSES = {'PASS', 'FAIL', 'BLOCKED', 'NOT_RUN', 'SKIPPED'}
# A caller cannot remove an inconvenient gate from the input document.
REQUIRED = {
    'SOURCE-PROVENANCE': ('build', None),
    'AUTOMATED-FULL': ('automated', None),
    'IDENTITY-AND-ADMINISTRATION': ('integration', None),
    'MAIL-AND-MIGRATION': ('integration', None),
    'ATTACHMENTS-500MIB': ('integration', None),
    'LIBRARY-ACL-AND-REVOCATION': ('integration', None),
    'INDEPENDENT-APPLICATION-LIFECYCLE': ('integration', None),
    'ANDROID-FUNCTIONAL-COMPLETENESS': ('integration', None),
    'ANDROID-IPC-AND-SECURE-SCREENS': ('native', 'android13plus-arm64'),
    'ANDROID-VPN-DNS-AND-LIFECYCLE': ('native', 'android13plus-arm64'),
    'ANDROID-BACKGROUND-AND-DOZE': ('native', 'android13plus-arm64'),
    'APK-SIGNING-AND-ROTATION': ('native', 'android13plus-arm64'),
    'VZOR-ISOLATION': ('native', None),
    'GLAS-E2EE-AND-AUDIO': ('native', None),
    'PUBLIC-TOR-NO-FALLBACK': ('public-network', None),
    'NATIVE-WINDOWS11': ('native', 'windows11-x64'),
    'NATIVE-CACHYOS-WAYLAND': ('native', 'cachyos-kde-wayland-x86_64'),
    'NATIVE-CACHYOS-X11': ('native', 'cachyos-kde-x11-x86_64'),
    'NATIVE-DEBIAN13': ('native', 'debian13-x86_64'),
    'NATIVE-ANDROID13-ARM64': ('native', 'android13plus-arm64'),
    'TWO-PHYSICAL-DEVICES-TWO-NETWORKS': ('physical-network', None),
    'UPDATER-END-TO-END-AND-ROLLBACK': ('native', None),
    'LIBRARY-SYNC-POLICY': ('integration', None),
    'NEWS-WORKER-LIVE': ('integration', None),
    'SERVER-BACKUP-RESTORE-AND-RESOURCE-LIMITS': ('native', 'debian13-x86_64'),
    'VISUAL-AND-ACCESSIBILITY': ('native', None),
    'LEGACY500-COMPATIBILITY': ('integration', None),
    'SECURITY-AUDIT': ('security-review', None),
    'ALL-ARTIFACTS-AND-CHECKSUMS': ('build', None),
    'OWNER-FINAL-ACCEPTANCE': ('owner-acceptance', None),
}
REQUIRED_ROLES = {
    'debian13-server', 'windows-installer', 'windows-portable', 'cachyos-appimage',
    'source', 'client-source', 'android-core', 'android-mail', 'android-glas', 'android-strazh',
}
HEX40 = re.compile(r'[0-9a-f]{40}')
HEX64 = re.compile(r'[0-9a-f]{64}')


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON field: ' + key)
        value[key] = item
    return value


def document(path):
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Oversized acceptance document')
    result = json.loads(path.read_text('utf-8'), object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError('Acceptance document must be an object')
    return result


def bounded_file(root, name):
    if not isinstance(name, str) or not name or '\\' in name:
        raise ValueError('Invalid evidence path')
    relative = PurePosixPath(name)
    if relative.is_absolute() or any(p in ('', '.', '..') for p in name.split('/')):
        raise ValueError('Evidence must stay beneath the explicit evidence root')
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('Symlink evidence is not accepted')
    if not current.is_file() or not current.resolve().is_relative_to(root):
        raise ValueError('Missing or escaped evidence: ' + name)
    return current


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verified_reference(root, reference):
    if not isinstance(reference, dict) or set(reference) != {'path', 'sha256'}:
        raise ValueError('Evidence needs an exact path and SHA-256')
    if not isinstance(reference['sha256'], str) or not HEX64.fullmatch(reference['sha256']):
        raise ValueError('Invalid evidence SHA-256')
    path = bounded_file(root, reference['path'])
    if path.stat().st_size > 16 * 1024 ** 3 or sha256(path) != reference['sha256']:
        raise ValueError('Evidence checksum mismatch: ' + reference['path'])
    return path


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('Missing execution timestamp')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Execution timestamp must specify timezone')
    return result


def receipt_qualifies(receipt, gate, commit, tree, artifacts, binary_names):
    if receipt.get('schemaVersion') != 1 or receipt.get('version') != VERSION:
        raise ValueError('Wrong acceptance receipt schema/version')
    if receipt.get('sourceCommit') != commit or receipt.get('sourceTree') != tree:
        raise ValueError('Acceptance receipt belongs to different source')
    gate_ids = receipt.get('gateIds')
    if not isinstance(gate_ids, list) or any(not isinstance(v, str) or v not in REQUIRED for v in gate_ids):
        raise ValueError('Receipt must identify known gate IDs')
    if receipt.get('status') != 'PASS' or gate not in gate_ids:
        raise ValueError('Receipt does not attest this passing gate')
    execution = receipt.get('execution')
    if not isinstance(execution, dict):
        raise ValueError('Missing execution record')
    kind, platform = REQUIRED[gate]
    if execution.get('kind') != kind or platform and execution.get('platform') != platform:
        raise ValueError('Wrong execution environment for ' + gate)
    start, end = timestamp(execution.get('startedAt')), timestamp(execution.get('endedAt'))
    if end < start or not isinstance(execution.get('description'), str) or not execution['description'].strip():
        raise ValueError('Invalid execution record')
    observed = receipt.get('artifactSha256')
    if not isinstance(observed, dict) or not observed:
        raise ValueError('A PASS receipt must bind tested source/archive or binary bytes')
    for name, digest in observed.items():
        if name not in artifacts or artifacts[name] != digest:
            raise ValueError('Receipt tested different artifact bytes')
    if kind in {'native', 'public-network', 'physical-network', 'owner-acceptance'}:
        if not set(observed).intersection(binary_names):
            raise ValueError('Runtime acceptance must bind an actual binary')
    if kind == 'physical-network':
        for key in ('physicalDevices', 'independentNetworks'):
            identifiers = execution.get(key)
            if not isinstance(identifiers, list) or any(not isinstance(v, str) or not v.strip() for v in identifiers) or len(set(identifiers)) < 2:
                raise ValueError('Two distinct physical devices and networks must be recorded')
    if kind == 'security-review':
        if receipt.get('openCritical') != 0 or receipt.get('openHigh') != 0:
            raise ValueError('An open critical/high defect blocks release')
    if kind == 'owner-acceptance' and execution.get('acceptedBy') != 'owner':
        raise ValueError('Final owner acceptance is required for these exact bytes')
    logs = receipt.get('results')
    if not isinstance(logs, list) or not logs:
        raise ValueError('Receipt needs reproducible results/log references')
    return logs


def evaluate(value, evidence_root, expected_commit=None, expected_tree=None):
    root = Path(evidence_root).resolve(strict=True)
    if value.get('schemaVersion') != 2 or value.get('version') != VERSION:
        raise ValueError('Expected 6.0.0 release gate schema 2')
    gates = value.get('mandatory')
    if not isinstance(gates, list) or len(gates) != len(REQUIRED):
        raise ValueError('Complete mandatory 6.0.0 gate registry required')
    by_id = {}
    for gate in gates:
        if not isinstance(gate, dict) or gate.get('id') not in REQUIRED or gate['id'] in by_id:
            raise ValueError('Missing, duplicate or unknown mandatory gate')
        if gate.get('status') not in STATUSES or not isinstance(gate.get('reason'), str) or not gate['reason'].strip():
            raise ValueError('A gate requires a known status and an explanation')
        by_id[gate['id']] = gate
    commit, tree = value.get('sourceCommit'), value.get('sourceTree')
    if (expected_commit is not None and commit != expected_commit) or (expected_tree is not None and tree != expected_tree):
        raise ValueError('Gate document is not bound to the requested source')
    passing = any(g['status'] == 'PASS' for g in gates)
    if passing and (not isinstance(commit, str) or not HEX40.fullmatch(commit) or not isinstance(tree, str) or not HEX40.fullmatch(tree)):
        raise ValueError('PASS requires a fixed source commit and tree')
    records = value.get('artifacts')
    if not isinstance(records, list) or len(records) > 64:
        raise ValueError('Bounded artifact inventory required')
    artifacts, roles, binary_names = {}, set(), set()
    for item in records:
        if not isinstance(item, dict) or set(item) != {'role', 'path', 'sha256'} or item['role'] not in REQUIRED_ROLES or item['role'] in roles:
            raise ValueError('Duplicate or unknown artifact role')
        path = verified_reference(root, {'path': item['path'], 'sha256': item['sha256']})
        if path.name in artifacts or path.stat().st_size == 0:
            raise ValueError('Duplicate artifact filename')
        roles.add(item['role']); artifacts[path.name] = item['sha256']
        if item['role'] not in {'source', 'client-source'}:
            binary_names.add(path.name)
    pending = [identity for identity, gate in by_id.items() if gate['status'] != 'PASS']
    for identity, gate in by_id.items():
        references = gate.get('evidence')
        if not isinstance(references, list) or not references or len(references) > 64:
            raise ValueError('Every gate needs bounded evidence, including a blocker record')
        paths = [verified_reference(root, reference) for reference in references]
        if gate['status'] == 'PASS':
            if not gate.get('receipt') or gate['receipt'] not in [r['path'] for r in references]:
                raise ValueError('PASS needs a hashed acceptance receipt')
            receipt = document(bounded_file(root, gate['receipt']))
            for reference in receipt_qualifies(receipt, identity, commit, tree, artifacts, binary_names):
                verified_reference(root, reference)
    missing = sorted(REQUIRED_ROLES - roles)
    if by_id['ALL-ARTIFACTS-AND-CHECKSUMS']['status'] == 'PASS' and missing:
        raise ValueError('Passing artifact gate omits a required platform artifact')
    ready = not pending and not missing
    if value.get('productionReady') is not ready:
        raise ValueError('Recorded productionReady differs from mandatory evidence')
    return {'schemaVersion': 2, 'version': VERSION, 'sourceCommit': commit,
            'sourceTree': tree, 'productionReady': ready,
            'pendingMandatory': pending, 'missingArtifactRoles': missing,
            'publicationAuthorized': False,
            'scope': 'Evidence consistency validation; not an independent security certification'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('gates', type=Path)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--expected-source-commit')
    parser.add_argument('--expected-source-tree')
    args = parser.parse_args()
    try:
        result = evaluate(document(args.gates), args.evidence_root, args.expected_source_commit, args.expected_source_tree)
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, 'Rejected 6.0.0 acceptance: ' + str(error) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['productionReady'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
