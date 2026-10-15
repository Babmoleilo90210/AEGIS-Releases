#!/usr/bin/env python3
"""Generate exact-byte UNSIGNED metadata from final local assets; never sign or publish."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys

import release_manifest as rm


def checksum_inventory(directory):
    """Verify the existing flat SHA256SUMS; no invented hashes or recursive hash cycle."""
    exact = rm.exact_bytes(directory / 'SHA256SUMS')
    try:
        lines = exact.decode('ascii').splitlines()
    except UnicodeDecodeError:
        raise ValueError('SHA256SUMS must be ASCII') from None
    inventory = {}
    for line in lines:
        match = re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,179})', line)
        if not match:
            raise ValueError('Invalid flat SHA256SUMS entry')
        digest, name = match.groups()
        if name == 'SHA256SUMS' or name in inventory:
            raise ValueError('Duplicate or recursive checksum entry')
        path = directory / name
        if path.is_symlink() or not path.is_file() or rm.sha256(path) != digest:
            raise ValueError('Checksum inventory mismatch: ' + name)
        inventory[name] = digest
    if not inventory:
        raise ValueError('Empty checksum inventory')
    return inventory


def timestamp(value):
    # The old Java Instant parser and the Python verifier both accept this exact form.
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z', value):
        raise ValueError('published-at must be an explicit UTC RFC3339 instant ending in Z')
    datetime.fromisoformat(value.replace('Z', '+00:00'))
    return value


def build_manifest(artifacts, number, channel, *, minimum_supported='1.5.0',
                   published_at=None, title=None, summary=None, notes_type='Feature'):
    rm.version(number)
    if channel not in ('stable', 'beta') or channel == 'stable' and '-' in number:
        raise ValueError('Invalid channel/version combination')
    directory = Path(artifacts)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('A real artifact directory is required')
    directory = directory.resolve()
    expected = rm.expected_artifacts(number)
    changelog = f'CHANGELOG-{number}.md'
    inventory = checksum_inventory(directory)
    for name in (*expected, changelog):
        if name not in inventory:
            raise ValueError('Required final asset missing from SHA256SUMS: ' + name)

    def record(name):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('A regular final asset is required: ' + name)
        result = {'fileName': name, 'size': path.stat().st_size,
                  'sha256': rm.sha256(path), 'url': rm.release_url(number, name)}
        rm.validate_file(result, number, {'fileName', 'size', 'sha256', 'url'})
        return result

    notes = rm.exact_bytes(directory / changelog, 48000).decode('utf-8')
    if not notes.strip() or len(notes) > 12000:
        raise ValueError('CHANGELOG must contain 1..12000 characters of release notes')
    published = timestamp(published_at or datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'))
    document = {
        'schemaVersion': 1, 'application': 'AEGIS', 'channel': channel,
        'version': number, 'tag': 'v' + number, 'repository': rm.REPOSITORY,
        'protocolVersion': 1, 'relayCompatibility': ['0.2.0'],
        'artifacts': [{**record(name), 'platform': platform, 'kind': kind}
                      for name, (platform, kind) in expected.items()],
        'checksums': record('SHA256SUMS'), 'changelog': record(changelog),
        'minimumSupported': minimum_supported, 'updatePolicy': 'optional',
        'announcement': {'title': title or f'Обновление АЕГИС {number}',
                         'summary': summary or f'АЕГИС {number}: подробности в журнале изменений.',
                         'showAsLetter': True},
        'releaseNotes': {'publishedAt': published, 'type': notes_type, 'text': notes},
    }
    exact = (json.dumps(document, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    rm.parse_manifest(exact)
    rm.verify_assets(document, directory)
    # Recheck inventory after hashing all records; a changing build tree must not be signed.
    if checksum_inventory(directory) != inventory:
        raise ValueError('Artifact inventory changed during generation')
    return exact


def write_unsigned(output, exact):
    output = Path(output)
    if not output.name.endswith('.UNSIGNED.json'):
        raise ValueError('Output filename must end in .UNSIGNED.json; feeds are never overwritten')
    rm.parse_manifest(exact)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(exact)
        stream.flush()
        os.fsync(stream.fileno())
    return rm.sha256(output)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--channel', required=True, choices=('stable', 'beta'))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--minimum-supported', default='1.5.0')
    parser.add_argument('--published-at')
    parser.add_argument('--title')
    parser.add_argument('--summary')
    parser.add_argument('--notes-type', choices=('Feature', 'Fix', 'Security'), default='Feature')
    args = parser.parse_args(arguments)
    try:
        exact = build_manifest(args.artifacts, args.version, args.channel,
                               minimum_supported=args.minimum_supported, published_at=args.published_at,
                               title=args.title, summary=args.summary, notes_type=args.notes_type)
        digest = write_unsigned(args.output, exact)
    except (ValueError, OSError, UnicodeError) as error:
        print('Unsigned manifest rejected: ' + str(error), file=sys.stderr)
        return 1
    print(f'UNSIGNED {args.output}; SHA256={digest}; no signature, feed change or publication')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
