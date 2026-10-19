#!/usr/bin/env python3
"""Read evidence gates and report readiness. Never change a feed, gate or signature."""
import argparse
import json
from pathlib import Path


def evaluate(document):
    if document.get('version') == '6.0.0':
        raise ValueError('6.0.0 requires the source-bound evaluate-release-gates600.py validator')
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
    parser.add_argument('--evidence-root', type=Path)
    args = parser.parse_args()
    try:
        value = json.loads(args.gates.read_text('utf-8'))
        if value.get('version') == '6.0.0':
            import importlib.util
            spec = importlib.util.spec_from_file_location('release_gates600', Path(__file__).with_name('evaluate-release-gates600.py'))
            validator = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(validator)
            result = validator.evaluate(validator.document(args.gates), args.evidence_root or args.gates.parent)
        else:
            result = evaluate(value)
    except (ValueError, OSError, TypeError) as error:
        parser.exit(1, 'Rejected gate document: ' + str(error) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['productionReady'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
