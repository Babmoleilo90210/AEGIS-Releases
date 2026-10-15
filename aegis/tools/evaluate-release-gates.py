#!/usr/bin/env python3
"""Read evidence gates and report readiness. Never change a feed, gate or signature."""
import argparse
import json
from pathlib import Path


def evaluate(document):
    gates = document.get('mandatory')
    if not isinstance(gates, list) or not gates:
        raise ValueError('A nonempty mandatory gate list is required')
    identifiers = set()
    pending = []
    for gate in gates:
        identity = gate.get('id')
        if not isinstance(identity, str) or not identity or identity in identifiers:
            raise ValueError('Missing or duplicate gate identity')
        identifiers.add(identity)
        if gate.get('status') not in ('PASS', 'FAIL', 'BLOCKED', 'NOT_RUN'):
            raise ValueError('Unknown gate status')
        if not gate.get('evidence'):
            raise ValueError('Every gate requires evidence or an explicit unavailable-environment reference')
        if gate['status'] != 'PASS':
            pending.append(identity)
    ready = not pending
    if document.get('productionReady') is not ready:
        raise ValueError('Recorded productionReady differs from mandatory evidence gates')
    return {'productionReady': ready, 'pendingMandatory': pending,
            'publicationAuthorized': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('gates', type=Path)
    args = parser.parse_args()
    try:
        result = evaluate(json.loads(args.gates.read_text('utf-8')))
    except (ValueError, OSError, TypeError) as error:
        parser.exit(1, 'Rejected gate document: ' + str(error) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['productionReady'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
