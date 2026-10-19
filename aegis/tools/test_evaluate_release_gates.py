import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('release_gates_250', Path(__file__).with_name('evaluate-release-gates.py'))
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)


class ReleaseGatesTest(unittest.TestCase):
    def test_legacy_api_cannot_shortcut_source_bound_600_gates(self):
        with self.assertRaises(ValueError):
            gates.evaluate({'version': '6.0.0', 'productionReady': True, 'mandatory': [
                {'id': 'only-build', 'status': 'PASS', 'evidence': ['build.log']}]})

    def test_successful_build_cannot_promote_missing_native_acceptance(self):
        document = {'productionReady': False, 'mandatory': [
            {'id': 'build', 'status': 'PASS', 'evidence': ['build.xml']},
            {'id': 'physical-call', 'status': 'NOT_RUN', 'evidence': ['environment-unavailable.json']}]}
        self.assertEqual(['physical-call'], gates.evaluate(document)['pendingMandatory'])
        document['productionReady'] = True
        with self.assertRaises(ValueError):
            gates.evaluate(document)

    def test_no_empty_gate_shortcut_or_duplicate_identity(self):
        with self.assertRaises(ValueError):
            gates.evaluate({'productionReady': True, 'mandatory': []})
        gate = {'id': 'native', 'status': 'PASS', 'evidence': ['native.json']}
        with self.assertRaises(ValueError):
            gates.evaluate({'productionReady': True, 'mandatory': [gate, gate]})

    def test_evidence_required_and_unknown_status_is_rejected(self):
        for item in [{'id': 'native', 'status': 'PASS'},
                     {'id': 'native', 'status': 'IMPLEMENTED', 'evidence': ['source.java']}]:
            with self.assertRaises(ValueError):
                gates.evaluate({'productionReady': True, 'mandatory': [item]})

    def test_readiness_does_not_authorize_publication(self):
        result = gates.evaluate({'productionReady': True, 'mandatory': [
            {'id': 'native', 'status': 'PASS', 'evidence': ['native.json']}]})
        self.assertTrue(result['productionReady'])
        self.assertFalse(result['publicationAuthorized'])
