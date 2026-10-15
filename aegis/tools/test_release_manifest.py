"""Ephemeral test keys only; the owner release key is never requested or used."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
import release_manifest as rm


class ReleaseManifestTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aegis-release-unit-')
        self.root = Path(self.temp.name)
        self.key = self.root / 'ephemeral-test-private.pem'
        self.public = self.root / 'ephemeral-test-public.pem'
        rm.openssl(['genpkey', '-algorithm', 'Ed25519', '-out', self.key])
        self.key.chmod(0o600)
        rm.openssl(['pkey', '-in', self.key, '-pubout', '-out', self.public])
        self.key_patch = patch.object(rm, 'PUBLIC_KEY', self.public.read_bytes())
        self.key_patch.start()
        self.manifest = self.root / 'stable.json'
        self.signature = self.root / 'stable.json.sig'
        self.doc = self.document('1.0.0')

    def tearDown(self):
        self.key_patch.stop()
        self.temp.cleanup()

    def document(self, number):
        assets = []
        for name, platform, kind in [
            (f'AEGIS-Setup-{number}-x64.exe', 'windows-x64', 'installer'),
            (f'AEGIS-{number}-Windows-x64.zip', 'windows-x64', 'portable'),
            (f'AEGIS-{number}-CachyOS-x86_64.AppImage', 'cachyos-x86_64', 'appimage'),
            (f'AEGIS-{number}-client-source.zip', 'source', 'source')]:
            item = self.file(name, number)
            assets.append({**item, 'platform': platform, 'kind': kind})
        return {'schemaVersion': 1, 'application': 'AEGIS', 'channel': 'stable',
                'version': number, 'tag': 'v' + number, 'repository': rm.REPOSITORY,
                'protocolVersion': 1, 'relayCompatibility': ['0.2.0'], 'artifacts': assets,
                'checksums': self.file('SHA256SUMS', number),
                'changelog': self.file(f'CHANGELOG-{number}.md', number),
                'minimumSupported': number, 'updatePolicy': 'optional',
                'announcement': {'title': 'Update', 'summary': 'Test fixture', 'showAsLetter': True},
                'releaseNotes': {'publishedAt': '2026-10-08T00:00:00Z', 'type': 'Fix', 'text': 'Signed test notes'}}

    def file(self, name, number):
        path = self.root / name
        path.write_bytes(('test fixture: ' + name).encode())
        return {'fileName': name, 'size': path.stat().st_size, 'sha256': rm.sha256(path),
                'url': f'https://github.com/{rm.REPOSITORY}/releases/download/v{number}/{name}'}

    def seal(self, doc=None, raw=None, key=None):
        self.manifest.write_bytes(raw if raw is not None else json.dumps(doc or self.doc, separators=(',', ':')).encode())
        rm.openssl(['pkeyutl', '-sign', '-rawin', '-inkey', key or self.key,
                    '-in', self.manifest, '-out', self.signature])

    def verify(self):
        return rm.verify(self.manifest, self.signature, self.root, '1.0.0')

    def test_valid_manifest_and_files(self):
        self.seal()
        self.assertEqual(self.verify()['version'], '1.0.0')

    def test_changed_json_rejected_before_parsing(self):
        self.seal()
        self.manifest.write_bytes(self.manifest.read_bytes() + b' ')
        with patch.object(rm, 'parse_manifest') as parser:
            with self.assertRaises(ValueError): self.verify()
            parser.assert_not_called()

    def test_changed_signature_rejected(self):
        self.seal()
        data = bytearray(self.signature.read_bytes()); data[0] ^= 1
        self.signature.write_bytes(data)
        with self.assertRaises(ValueError): self.verify()

    def test_changed_binary_same_size_rejected(self):
        self.seal()
        path = self.root / self.doc['artifacts'][0]['fileName']
        data = bytearray(path.read_bytes()); data[0] ^= 1; path.write_bytes(data)
        with self.assertRaises(ValueError): self.verify()

    def test_wrong_authenticated_sha_rejected(self):
        self.doc['artifacts'][0]['sha256'] = '0' * 64
        self.seal()
        with self.assertRaises(ValueError): self.verify()

    def test_wrong_authenticated_size_rejected(self):
        self.doc['artifacts'][0]['size'] += 1
        self.seal()
        with self.assertRaises(ValueError): self.verify()

    def test_downgrade_rejected(self):
        self.seal(self.document('0.9.0'))
        with self.assertRaisesRegex(ValueError, 'rollback'): self.verify()

    def test_wrong_public_key_rejected(self):
        self.seal()
        other = self.root / 'other-ephemeral-private.pem'
        other_public = self.root / 'other-ephemeral-public.pem'
        rm.openssl(['genpkey', '-algorithm', 'Ed25519', '-out', other])
        rm.openssl(['pkey', '-in', other, '-pubout', '-out', other_public])
        with patch.object(rm, 'PUBLIC_KEY', other_public.read_bytes()):
            with self.assertRaises(ValueError): self.verify()

    def test_duplicate_json_field_rejected(self):
        raw = json.dumps(self.doc, separators=(',', ':')).encode().replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1')
        self.seal(raw=raw)
        with self.assertRaisesRegex(ValueError, 'Duplicate'): self.verify()

    def test_other_repository_url_rejected(self):
        self.doc['artifacts'][0]['url'] = 'https://example.invalid/AEGIS.exe'
        self.seal()
        with self.assertRaisesRegex(ValueError, 'URL'): self.verify()

    def test_unsafe_filename_rejected(self):
        self.doc['artifacts'][0]['fileName'] = '../AEGIS.exe'
        self.seal()
        with self.assertRaises(ValueError): self.verify()

    def test_signature_length_rejected(self):
        self.seal(); self.signature.write_bytes(b'x' * 63)
        with self.assertRaises(ValueError): self.verify()

    def test_oversize_manifest_rejected(self):
        self.seal(); self.manifest.write_bytes(b'x' * (rm.MAX_MANIFEST + 1))
        with self.assertRaises(ValueError): self.verify()

    def test_artifact_symlink_rejected(self):
        self.seal()
        path = self.root / self.doc['artifacts'][0]['fileName']
        target = self.root / 'fixture-target'; path.rename(target); path.symlink_to(target)
        with self.assertRaises(ValueError): self.verify()

    def test_signing_and_no_overwrite(self):
        self.manifest.write_text(json.dumps(self.doc), encoding='utf-8')
        before = rm.sha256(self.key)
        rm.sign(self.manifest, self.key, self.signature)
        self.assertEqual(before, rm.sha256(self.key))
        self.assertEqual(self.verify()['version'], '1.0.0')
        with self.assertRaises(ValueError): rm.sign(self.manifest, self.key, self.signature)

    def test_wrong_signing_key_has_no_output(self):
        self.manifest.write_text(json.dumps(self.doc), encoding='utf-8')
        other = self.root / 'other-ephemeral-test-private.pem'
        rm.openssl(['genpkey', '-algorithm', 'Ed25519', '-out', other])
        with self.assertRaises(ValueError): rm.sign(self.manifest, other, self.signature)
        self.assertFalse(self.signature.exists())


if __name__ == '__main__':
    unittest.main()
