"""Acceptance validator tests use explicit synthetic receipts, never native PASS claims."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('release_gates600', Path(__file__).with_name('evaluate-release-gates600.py'))
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)


class ReleaseGates600Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commit, self.tree = '1' * 40, '2' * 40
        self.blocker = self.file('blocker.json', {'status': 'NOT_RUN', 'reason': 'Synthetic test fixture'})
        self.value = {'schemaVersion': 2, 'version': '6.0.0', 'sourceCommit': self.commit,
                      'sourceTree': self.tree, 'productionReady': False, 'artifacts': [],
                      'mandatory': [{'id': identity, 'status': 'NOT_RUN', 'reason': 'Not executed in synthetic test',
                                     'evidence': [self.blocker]} for identity in gates.REQUIRED]}

    def file(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) if isinstance(value, dict) else value, 'utf-8')
        return {'path': name, 'sha256': gates.sha256(path)}

    def passed(self, identity):
        if not self.value['artifacts']:
            binary = self.file('candidate.bin', 'Synthetic test bytes, not a release')
            self.value['artifacts'].append({'role': 'windows-portable', **binary})
        artifact = self.value['artifacts'][0]
        kind, platform = gates.REQUIRED[identity]
        execution = {'kind': kind, 'platform': platform, 'description': 'Synthetic validator test',
                     'startedAt': '2026-10-19T00:00:00Z', 'endedAt': '2026-10-19T00:01:00Z',
                     'physicalDevices': ['fixture-device-1', 'fixture-device-2'],
                     'independentNetworks': ['fixture-network-1', 'fixture-network-2'], 'acceptedBy': 'owner'}
        receipt = {'schemaVersion': 1, 'version': '6.0.0', 'sourceCommit': self.commit,
                   'sourceTree': self.tree, 'gateIds': [identity], 'status': 'PASS',
                   'artifactSha256': {Path(artifact['path']).name: artifact['sha256']},
                   'execution': execution, 'openCritical': 0, 'openHigh': 0,
                   'results': [self.file('results/' + identity + '.log', 'Synthetic test results')]}
        evidence = self.file('receipts/' + identity + '.json', receipt)
        record = next(v for v in self.value['mandatory'] if v['id'] == identity)
        record.update(status='PASS', reason='Synthetic test receipt', evidence=[evidence], receipt=evidence['path'])
        return receipt, evidence

    def evaluate(self):
        return gates.evaluate(self.value, self.root, self.commit, self.tree)

    def rewrite(self, receipt, reference):
        reference.update(self.file(reference['path'], receipt))

    def test_missing_native_stays_false(self):
        self.passed('AUTOMATED-FULL')
        result = self.evaluate()
        self.assertFalse(result['productionReady'])
        self.assertIn('NATIVE-WINDOWS11', result['pendingMandatory'])

    def test_manual_true_rejected(self):
        self.value['productionReady'] = True
        with self.assertRaises(ValueError): self.evaluate()

    def test_cannot_remove_or_duplicate_required_gate(self):
        for change in (lambda x: x.pop(), lambda x: x.__setitem__(0, copy.deepcopy(x[1]))):
            original = copy.deepcopy(self.value['mandatory'])
            change(self.value['mandatory'])
            with self.assertRaises(ValueError): self.evaluate()
            self.value['mandatory'] = original

    def test_old_commit_and_tree_are_rejected(self):
        receipt, evidence = self.passed('AUTOMATED-FULL')
        for key in ('sourceCommit', 'sourceTree'):
            original = receipt[key]; receipt[key] = '9' * 40; self.rewrite(receipt, evidence)
            with self.assertRaises(ValueError): self.evaluate()
            receipt[key] = original

    def test_expected_source_cannot_be_replaced_in_gate_document(self):
        self.value['sourceCommit'] = '7' * 40
        with self.assertRaises(ValueError): self.evaluate()

    def test_receipt_tampering_is_rejected(self):
        receipt, evidence = self.passed('AUTOMATED-FULL')
        (self.root / evidence['path']).write_text('{}', 'utf-8')
        with self.assertRaises(ValueError): self.evaluate()

    def test_artifact_and_log_tampering_are_rejected(self):
        receipt, evidence = self.passed('AUTOMATED-FULL')
        artifact = self.root / self.value['artifacts'][0]['path']
        old = artifact.read_text(); artifact.write_text('Changed binary')
        with self.assertRaises(ValueError): self.evaluate()
        artifact.write_text(old)
        (self.root / receipt['results'][0]['path']).write_text('Changed test result')
        with self.assertRaises(ValueError): self.evaluate()

    def test_traversal_and_symlinks_are_rejected(self):
        for path in ('../outside', '/absolute', 'a/../outside', './blocker.json', 'a\\file'):
            with self.assertRaises(ValueError): gates.bounded_file(self.root, path)
        (self.root / 'link').symlink_to(self.root / 'blocker.json')
        with self.assertRaises(ValueError): gates.bounded_file(self.root, 'link')
        (self.root / 'dirlink').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): gates.bounded_file(self.root, 'dirlink/blocker.json')

    def test_headless_cannot_claim_native_and_wrong_os_rejected(self):
        receipt, evidence = self.passed('NATIVE-WINDOWS11')
        for key, value in (('kind', 'automated'), ('platform', 'ubuntu-headless')):
            old = receipt['execution'][key]; receipt['execution'][key] = value; self.rewrite(receipt, evidence)
            with self.assertRaises(ValueError): self.evaluate()
            receipt['execution'][key] = old

    def test_physical_devices_and_networks_must_be_distinct(self):
        receipt, evidence = self.passed('TWO-PHYSICAL-DEVICES-TWO-NETWORKS')
        for key in ('physicalDevices', 'independentNetworks'):
            old = receipt['execution'][key]; receipt['execution'][key] = ['same', 'same']; self.rewrite(receipt, evidence)
            with self.assertRaises(ValueError): self.evaluate()
            receipt['execution'][key] = old

    def test_open_high_security_finding_blocks_pass(self):
        receipt, evidence = self.passed('SECURITY-AUDIT')
        receipt['openHigh'] = 1; self.rewrite(receipt, evidence)
        with self.assertRaises(ValueError): self.evaluate()

    def test_missing_artifacts_cannot_pass_artifact_gate(self):
        self.passed('ALL-ARTIFACTS-AND-CHECKSUMS')
        with self.assertRaises(ValueError): self.evaluate()

    def test_source_archive_cannot_replace_native_binary(self):
        receipt, evidence = self.passed('NATIVE-WINDOWS11')
        self.value['artifacts'][0]['role'] = 'source'
        with self.assertRaises(ValueError): self.evaluate()

    def test_all_gates_and_exact_artifacts_make_computed_true_without_publication(self):
        for role in sorted(gates.REQUIRED_ROLES):
            self.value['artifacts'].append({'role': role, **self.file(role + '.bin', 'Synthetic ' + role)})
        for identity in gates.REQUIRED: self.passed(identity)
        self.value['productionReady'] = True
        result = self.evaluate()
        self.assertTrue(result['productionReady'])
        self.assertFalse(result['publicationAuthorized'])

    def test_duplicate_json_field_is_rejected(self):
        (self.root / 'ambiguous.json').write_text('{"productionReady":false,"productionReady":true}')
        with self.assertRaises(ValueError): gates.document(self.root / 'ambiguous.json')


if __name__ == '__main__': unittest.main()
