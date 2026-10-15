"""Final-asset fixtures only. This generator never reads a release private key."""
from pathlib import Path
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release_manifest as rm

spec = importlib.util.spec_from_file_location('aegis_unsigned_generator', Path(__file__).with_name('generate-release-manifest.py'))
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class GenerateReleaseManifestTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aegis-unsigned-manifest-test-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def assets(self, number='2.5.0'):
        directory = self.root / number
        directory.mkdir()
        for name in rm.expected_artifacts(number):
            (directory / name).write_bytes(('actual local fixture ' + name).encode('utf-8'))
        (directory / f'CHANGELOG-{number}.md').write_text(f'# АЕГИС {number}\nПроверенные изменения.\n', encoding='utf-8')
        self.sums(directory)
        return directory

    def sums(self, directory):
        (directory / 'SHA256SUMS').write_text(''.join(rm.sha256(p) + '  ' + p.name + '\n'
            for p in sorted(directory.iterdir()) if p.name != 'SHA256SUMS'), encoding='ascii')

    def build(self, directory, number='2.5.0', channel='beta', **options):
        return generator.build_manifest(directory, number, channel, published_at='2026-10-15T09:00:00Z', **options)

    def test_150_200_and_250_exact_tags_urls_names_and_measured_bytes(self):
        for number in ('1.5.0', '2.0.0', '2.5.0'):
            with self.subTest(number=number):
                directory = self.assets(number)
                for channel in ('stable', 'beta'):
                    exact = self.build(directory, number, channel)
                    doc = rm.parse_manifest(exact, '1.5.0')
                    self.assertEqual(doc['tag'], 'v' + number)
                    self.assertEqual(doc['channel'], channel)
                    self.assertEqual({item['fileName'] for item in doc['artifacts']}, set(rm.expected_artifacts(number)))
                    for item in rm.entries(doc):
                        self.assertEqual(item['url'], rm.release_url(number, item['fileName']))
                        self.assertEqual(item['size'], (directory / item['fileName']).stat().st_size)
                        self.assertEqual(item['sha256'], rm.sha256(directory / item['fileName']))
                    rm.verify_assets(doc, directory)

    def test_prerelease_is_explicit_in_version_tag_and_all_asset_names(self):
        number = '2.5.0-beta.1'
        directory = self.assets(number)
        doc = rm.parse_manifest(self.build(directory, number))
        self.assertEqual('v2.5.0-beta.1', doc['tag'])
        self.assertTrue(all('/v2.5.0-beta.1/' in item['url'] for item in rm.entries(doc)))
        with self.assertRaisesRegex(ValueError, 'channel/version'):
            self.build(directory, number, 'stable')

    def test_historical_beta_tag_mismatch_rejected_before_signing_or_key_access(self):
        directory = self.assets('2.0.0')
        doc = json.loads(self.build(directory, '2.0.0'))
        doc['tag'] = 'v2.0.0-beta.1'
        for item in rm.entries(doc):
            item['url'] = item['url'].replace('/v2.0.0/', '/v2.0.0-beta.1/')
        candidate = self.root / 'bad.UNSIGNED.json'
        candidate.write_text(json.dumps(doc), encoding='utf-8')
        signature = self.root / 'not-created.sig'
        with patch.object(rm, 'openssl') as crypto:
            with self.assertRaisesRegex(ValueError, 'tag mismatch'):
                rm.sign(candidate, self.root / 'owner-key-is-not-present', signature)
            crypto.assert_not_called()
        self.assertFalse(signature.exists())

    def test_changed_same_size_binary_or_changelog_is_rejected(self):
        for number, filename in [('2.5.0', 'AEGIS-2.5.0-Windows-x64.zip'), ('2.0.0', 'CHANGELOG-2.0.0.md')]:
            directory = self.assets(number)
            path = directory / filename
            changed = bytearray(path.read_bytes()); changed[0] ^= 1; path.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, 'Checksum inventory mismatch'):
                self.build(directory, number)

    def test_missing_or_wrong_version_artifact_does_not_generate_partial_manifest(self):
        directory = self.assets()
        (directory / 'AEGIS-Setup-2.5.0-x64.exe').unlink()
        self.sums(directory)
        with self.assertRaisesRegex(ValueError, 'Required final asset'):
            self.build(directory)
        with self.assertRaises(ValueError):
            self.build(directory, '2.0.0')

    def test_duplicate_unsafe_recursive_and_corrupt_checksum_entries_are_rejected(self):
        directory = self.assets()
        sums = directory / 'SHA256SUMS'
        original = sums.read_text()
        for bad in (original + original.splitlines()[0] + '\n', '0' * 64 + '  ../escaped\n',
                    '0' * 64 + '  SHA256SUMS\n', 'INVALID SUMS\n'):
            with self.subTest(bad=bad[-30:]):
                sums.write_text(bad)
                with self.assertRaises(ValueError):
                    self.build(directory)

    def test_symlink_artifact_and_checksum_file_are_rejected(self):
        directory = self.assets()
        path = directory / 'AEGIS-Setup-2.5.0-x64.exe'
        target = self.root / 'external'; path.rename(target); path.symlink_to(target)
        with self.assertRaises(ValueError): self.build(directory)
        path.unlink(); path.write_bytes(target.read_bytes())
        sums = directory / 'SHA256SUMS'; real = self.root / 'sums'; sums.rename(real); sums.symlink_to(real)
        with self.assertRaises(ValueError): self.build(directory)

    def test_only_new_unsigned_output_allowed_and_source_assets_unchanged(self):
        directory = self.assets()
        before = {p.name: p.read_bytes() for p in directory.iterdir()}
        exact = self.build(directory)
        output = self.root / 'offline/AEGIS-2.5.0-beta.UNSIGNED.json'
        digest = generator.write_unsigned(output, exact)
        self.assertEqual(digest, rm.sha256(output))
        self.assertEqual(output.read_bytes(), exact)
        with self.assertRaises(FileExistsError): generator.write_unsigned(output, exact)
        for feed in ('stable.json', 'beta.json'):
            with self.assertRaisesRegex(ValueError, 'UNSIGNED'):
                generator.write_unsigned(self.root / 'updates' / feed, exact)
        self.assertFalse((self.root / 'updates').exists())
        self.assertFalse(output.with_name(output.name + '.sig').exists())
        self.assertEqual(before, {p.name: p.read_bytes() for p in directory.iterdir()})

    def test_rollback_channel_signature_and_sha_validation_remain_strict(self):
        directory = self.assets()
        exact = self.build(directory)
        with self.assertRaisesRegex(ValueError, 'rollback'): rm.parse_manifest(exact, '2.5.1')
        for field, value in [('tag', 'v2.0.0'), ('channel', 'other')]:
            doc = json.loads(exact); doc[field] = value
            with self.assertRaises(ValueError): rm.parse_manifest(json.dumps(doc).encode())
        doc = json.loads(exact); doc['artifacts'][0]['sha256'] = 'X' * 64
        with self.assertRaisesRegex(ValueError, 'SHA-256'): rm.parse_manifest(json.dumps(doc).encode())
        with self.assertRaises(ValueError): rm.verify_signature(exact, bytes(64))

    def test_cli_creates_unsigned_only_with_no_signature_or_existing_feed_change(self):
        directory = self.assets()
        output = self.root / 'AEGIS-2.5.0-beta.UNSIGNED.json'
        result = subprocess.run([sys.executable, str(Path(generator.__file__)), '--artifacts', str(directory),
            '--version', '2.5.0', '--channel', 'beta', '--output', str(output),
            '--published-at', '2026-10-15T09:00:00Z'], capture_output=True, text=True, check=True)
        self.assertIn('UNSIGNED', result.stdout)
        self.assertEqual(rm.parse_manifest(output.read_bytes())['tag'], 'v2.5.0')
        self.assertEqual(list(self.root.glob('*.sig')), [])
        self.assertFalse((directory / 'updates').exists())

    def test_timestamp_and_release_notes_must_be_compatible_with_old_java_parser(self):
        directory = self.assets()
        for stamp in ('2026-10-15 09:00:00Z', '2026-10-15T09:00:00', '2026-02-30T09:00:00Z'):
            with self.assertRaises(ValueError):
                generator.build_manifest(directory, '2.5.0', 'beta', published_at=stamp)
        (directory / 'CHANGELOG-2.5.0.md').write_text('x' * 12001)
        self.sums(directory)
        with self.assertRaisesRegex(ValueError, '12000'): self.build(directory)


if __name__ == '__main__':
    unittest.main()
