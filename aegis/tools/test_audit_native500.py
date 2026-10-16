import importlib.util, pathlib, unittest
spec = importlib.util.spec_from_file_location('native500', pathlib.Path(__file__).with_name('audit-native500.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class NativeAuditTests(unittest.TestCase):
    def test_tor_http200_error_is_not_a_successful_metadata_fetch(self):
        self.assertEqual('NOT_RUN_SITE_UNAVAILABLE', audit.classify_response(b'<title>Site Unavailable</title>'))

    def test_retrieval_never_claims_vulnerability_audit_pass(self):
        self.assertEqual('FETCHED_PRIMARY_SOURCE', audit.classify_response(b'[]'))

    def test_public_provenance_contains_hash_and_size_without_raw_document(self):
        data = b'<html>retrieved document</html>'
        record = audit.source_record({'name': 'example', 'url': 'https://example.org/'}, data)
        self.assertEqual(len(data), record['responseBytes'])
        self.assertEqual(64, len(record['responseSha256']))
        self.assertFalse(record['rawResponseIncluded'])
        self.assertNotIn('retrieved document', str(record))

    def test_preserved_response_hash_must_match_original(self):
        with self.assertRaises(ValueError):
            audit.source_record({'name': 'example', 'sha256': '0' * 64}, b'changed')


if __name__ == '__main__':
    unittest.main()
