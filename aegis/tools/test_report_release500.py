"""Report policy tests on temporary Git/XML fixtures; no actual native/release acceptance."""
import copy
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('report500', ROOT / 'tools/report-release500.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class Report500Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.repo = self.base / 'repo'
        self.project = self.repo / 'aegis'
        self.project.mkdir(parents=True)
        (self.repo / '.gitignore').write_text('build/\n')
        for module in r.MODULES:
            (self.project / module).mkdir()
            (self.project / module / 'build.gradle').write_text('// Synthetic source fixture\n')
        self.git('init', '-q')
        self.git('config', 'user.name', 'Report fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('add', '.')
        self.git('commit', '-qm', 'frozen synthetic source')
        self.commit = self.git('rev-parse', 'HEAD').strip()
        self.receipt = self.base / 'receipt.json'
        self.output = self.base / 'candidate'

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True, stderr=subprocess.DEVNULL)

    def xml(self, module='client-core', classname='fixture.ExampleTest', name='realCase()', status='PASS', timestamp=None):
        timestamp = timestamp or r.now_iso()
        root = ET.Element('testsuite', dict(name=classname, tests='1', failures=str(int(status == 'FAIL')), errors='0', skipped=str(int(status == 'NOT_RUN')), timestamp=timestamp, time='0.01', hostname='private-host-fixture'))
        case = ET.SubElement(root, 'testcase', dict(name=name, classname=classname, time='0.01'))
        if status == 'FAIL':
            ET.SubElement(case, 'failure', {'message': 'private detail'}).text = 'sensitive stack fixture'
        if status == 'NOT_RUN':
            ET.SubElement(case, 'skipped', {'message': 'private environment fixture'})
        ET.SubElement(root, 'system-out').text = 'sensitive stdout fixture'
        ET.SubElement(root, 'system-err').text = 'sensitive stderr fixture'
        target = self.project / module / 'build/test-results/test' / ('TEST-' + classname + '.xml')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(ET.tostring(root, encoding='utf-8', xml_declaration=True))
        return target

    def capture(self):
        return r.capture(self.project, self.receipt, './gradlew test --rerun-tasks --offline')

    def all_xml(self, status='PASS'):
        for module in r.REQUIRED_TEST_MODULES:
            self.xml(module=module, status=status if module == 'client-core' else 'PASS')

    def verified(self, status='PASS'):
        self.capture()
        self.all_xml(status)
        inv = r.inventory(self.project)
        r.verify_receipt(self.project, self.receipt, self.commit, inv)
        return inv

    def test_inventory_counts_actual_cases_and_does_not_count_historical_duplicates(self):
        self.xml(status='FAIL')
        historical = self.project / 'docs/test-results/5.0.0/old'
        historical.mkdir(parents=True)
        (historical / 'RESULTS.json').write_text(json.dumps({'status': 'PASS', 'testsPassed': 9999}))
        self.xml(module='community-server', classname='fixture.Second', name='skip()', status='NOT_RUN')
        inv = r.inventory(self.project)
        self.assertEqual({'tests': 2, 'passed': 0, 'failures': 1, 'errors': 0, 'skipped': 1}, inv['totals'])
        self.assertIsNone(inv['sourceCommit'])
        self.assertFalse(inv['scopedEvidence'][0]['countedIntoGradleTotals'])
        self.assertEqual('NOT_RUN', next(m for m in inv['modules'] if m['module'] == 'client-ui')['status'])

    def test_malformed_counts_duplicate_cases_dtd_and_symlinks_are_rejected(self):
        path = self.xml()
        root = ET.fromstring(path.read_bytes())
        root.set('tests', '2')
        path.write_bytes(ET.tostring(root))
        with self.assertRaisesRegex(ValueError, 'contradict'):
            r.inventory(self.project)
        root.append(copy.deepcopy(root.find('testcase')))
        path.write_bytes(ET.tostring(root))
        parsed = r.inventory(self.project)
        self.assertTrue(all(t['ambiguousDisplayName'] for t in parsed['suites'][0]['testcases']))
        ref = {'module': 'client-core', 'classname': 'fixture.ExampleTest', 'name': 'realCase()'}
        matrix = r.requirements(parsed, {'policy': 'fixture', 'requirements': [{'id': 'ACCESS-01', 'group': 'ACCESS', 'scope': 'local', 'tests': [ref]}]})
        self.assertEqual('NOT_RUN', matrix['requirements'][0]['status'])
        path.write_bytes(b'<!DOCTYPE a [<!ENTITY x "x">]><testsuite/>')
        with self.assertRaisesRegex(ValueError, 'DTD'):
            r.inventory(self.project)
        path.unlink()
        path.symlink_to(self.repo / '.gitignore')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            r.inventory(self.project)

    def test_only_exact_named_mapping_can_pass_and_manual_groups_never_pass(self):
        self.xml()
        inv = r.inventory(self.project)
        ref = {'module': 'client-core', 'classname': 'fixture.ExampleTest', 'name': 'realCase()'}
        definitions = {'policy': 'test fixture', 'requirements': [
            {'id': 'ACCESS-01', 'group': 'ACCESS', 'title': 'exact', 'scope': 'local only', 'tests': [ref]},
            {'id': 'ACCESS-02', 'group': 'ACCESS', 'title': 'similar', 'scope': 'local only', 'tests': [{**ref, 'name': 'realCase'}]},
            {'id': 'ACCESS-03', 'group': 'ACCESS', 'title': 'partial', 'scope': 'partial', 'tests': [], 'relatedTests': [ref]},
            {'id': 'NATIVE-WINDOWS11-01', 'group': 'NATIVE', 'title': 'native', 'scope': 'native', 'tests': [ref]}]}
        matrix = r.requirements(inv, definitions)
        self.assertEqual(['PASS', 'NOT_RUN', 'NOT_RUN', 'NOT_RUN'], [x['status'] for x in matrix['requirements']])
        self.assertEqual('PASS', matrix['requirements'][2]['relatedEvidence'][0]['status'])
        self.assertTrue(all(x['releaseWideAcceptance'] is False for x in matrix['requirements']))

    def test_mapping_has_every_required_scenario_and_no_native_auto_binding(self):
        d = json.loads(r.MATRIX_FILE.read_text())
        from collections import Counter
        self.assertEqual({'MIGRATION': 20, 'ACCESS': 20, 'AI': 30, 'LIB': 30, 'ORG': 24, 'NATIVE': 60, 'PHYSICAL': 15, 'UPDATER': 25}, dict(Counter(x['group'] for x in d['requirements'])))
        self.assertEqual(224, len({x['id'] for x in d['requirements']}))
        self.assertTrue(all(not x['tests'] for x in d['requirements'] if x['group'] in r.FORCED_MANUAL))

    def test_source_capture_requires_clean_commit_outside_repo_and_new_receipt(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            r.capture(self.project, self.repo / 'receipt.json', 'fixture')
        (self.project / 'untracked.java').write_text('untracked source')
        with self.assertRaisesRegex(ValueError, 'Commit and freeze'):
            self.capture()
        (self.project / 'untracked.java').unlink()
        self.capture()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.capture()

    def test_source_modified_even_under_assume_unchanged_cannot_bind_commit(self):
        self.capture()
        path = self.project / 'client-core/build.gradle'
        self.git('update-index', '--assume-unchanged', 'aegis/client-core/build.gradle')
        path.write_text('hidden dirty source')
        with self.assertRaisesRegex(ValueError, 'committed blob'):
            r.source_state(self.project, self.commit)

    def test_wrong_commit_receipt_or_changed_source_rejected(self):
        self.capture()
        self.all_xml()
        inv = r.inventory(self.project)
        with self.assertRaisesRegex(ValueError, 'HEAD differs'):
            r.verify_receipt(self.project, self.receipt, '0' * 40, inv)
        receipt = json.loads(self.receipt.read_text())
        receipt['sourceFilesDigest'] = '0' * 64
        self.receipt.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'differs'):
            r.verify_receipt(self.project, self.receipt, self.commit, inv)

    def test_stale_xml_cannot_be_promoted_by_current_commit_or_mtime_touch(self):
        self.all_xml()
        self.capture()
        import os
        for _, path in r.xml_paths(self.project):
            os.utime(path, None)
        inv = r.inventory(self.project)
        with self.assertRaisesRegex(ValueError, 'Stale'):
            r.verify_receipt(self.project, self.receipt, self.commit, inv)

    def test_missing_required_module_is_not_a_success(self):
        self.capture()
        self.xml()
        with self.assertRaisesRegex(ValueError, 'missing'):
            r.verify_receipt(self.project, self.receipt, self.commit, r.inventory(self.project))

    def test_final_generation_binds_source_and_keeps_false_with_pass_or_skip(self):
        inv = self.verified('NOT_RUN')
        matrix = r.requirements(inv)
        final = r.write_reports(self.project, self.output, self.receipt, inv, matrix)
        self.assertEqual(self.commit, final['sourceCommit'])
        self.assertFalse(final['productionReady'])
        self.assertFalse(final['publicationAuthorized'])
        self.assertEqual(r.file_sha(self.receipt), final['testedSourceReceiptSha256'])
        gates = json.loads((self.output / 'RELEASE-GATES-5.0.0.json').read_text())
        self.assertEqual('BLOCKED', next(g['status'] for g in gates['mandatory'] if g['id'] == 'GATE-22'))
        self.assertEqual('NOT_RUN', gates['mandatory'][-1]['status'])
        self.assertTrue((self.output / 'TEST-REPORT-5.0.0.md').is_file())
        self.assertFalse(list(self.output.glob('*.sig')))
        with zipfile.ZipFile(self.output / 'AEGIS-5.0.0-final-test-evidence.zip') as archive:
            xml = archive.read('gradle/client-core/TEST-fixture.ExampleTest.xml')
            self.assertNotIn(b'sensitive', xml)
            self.assertNotIn(b'private-', xml)
            self.assertIn(b'<skipped', xml)
            self.assertIn('SHA256SUMS', archive.namelist())
            self.assertIn('TESTED-SOURCE-RECEIPT-5.0.0.json', archive.namelist())

    def test_report_generation_rejects_xml_changed_after_inventory(self):
        inv = self.verified()
        self.xml(module='client-core', name='differentCase()')
        with self.assertRaisesRegex(ValueError, 'changed after inventory'):
            r.write_reports(self.project, self.output, self.receipt, inv, r.requirements(inv))
        self.assertFalse((self.output / 'FINAL-VERIFICATION-5.0.0.json').exists())
        self.assertFalse(list(self.output.glob('*.zip')))

    def test_future_timestamp_cannot_make_an_unrun_suite_fresh(self):
        self.capture()
        self.all_xml()
        self.xml(timestamp='2099-01-01T00:00:00+00:00')
        with self.assertRaisesRegex(ValueError, 'Stale'):
            r.verify_receipt(self.project, self.receipt, self.commit, r.inventory(self.project))

    def test_failed_exact_test_and_failed_automated_gate_remain_failed(self):
        inv = self.verified('FAIL')
        gates = r.release_gates(inv, r.requirements(inv))
        self.assertEqual('FAIL', next(g['status'] for g in gates['mandatory'] if g['id'] == 'GATE-22'))
        self.assertFalse(gates['productionReady'])
        ref = {'module': 'client-core', 'classname': 'fixture.ExampleTest', 'name': 'realCase()'}
        matrix = r.requirements(inv, {'policy': 'fixture', 'requirements': [{'id': 'ACCESS-01', 'group': 'ACCESS', 'title': 'exact', 'scope': 'local', 'tests': [ref]}]})
        self.assertEqual('FAIL', matrix['requirements'][0]['status'])


if __name__ == '__main__':
    unittest.main()
