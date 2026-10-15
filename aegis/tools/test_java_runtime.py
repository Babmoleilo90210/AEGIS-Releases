import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packaging'))
from java_runtime import verify_java_runtime


class JavaRuntimeRegistryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'runtime'
        (self.root / 'bin').mkdir(parents=True)
        (self.root / 'legal/jdk.localedata').mkdir(parents=True)
        (self.root / 'legal/jdk.localedata/LICENSE').write_text('fixture licence')
        self.release = self.root / 'release'
        self.release.write_text('JAVA_VERSION="21.0.12.1"\nMODULES="java.base jdk.localedata"\n')
        binary = bytearray(64)
        binary[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', binary, 18, 62)
        (self.root / 'bin/java').write_bytes(binary)
        self.registry = Path(self.temporary.name) / 'registry.json'
        self.pin()

    def pin(self):
        files = {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in self.root.rglob('*') if p.is_file()}
        self.registry.write_text(json.dumps({'runtimes': {'linux': {'files': files}}}))

    def verify(self):
        return verify_java_runtime(self.root, 'linux', registry=self.registry)

    def test_reviewed_english_only_runtime_still_fails_locale_requirement(self):
        self.assertTrue(self.verify()['localeModuleIncluded'])
        self.release.write_text('JAVA_VERSION="21.0.12.1"\nMODULES="java.base"\n')
        self.pin()
        with self.assertRaisesRegex(ValueError, 'locale data'):
            self.verify()

    def test_same_registry_hash_cannot_hide_wrong_launcher_architecture(self):
        binary = bytearray((self.root / 'bin/java').read_bytes())
        struct.pack_into('<H', binary, 18, 183)
        (self.root / 'bin/java').write_bytes(binary)
        self.pin()
        with self.assertRaisesRegex(ValueError, 'architecture'):
            self.verify()

    def test_changed_bytes_and_unreviewed_helper_are_not_packaged(self):
        (self.root / 'LocaleProbe.class').write_bytes(b'fixture helper')
        with self.assertRaisesRegex(ValueError, 'reviewed'):
            self.verify()
        (self.root / 'LocaleProbe.class').unlink()
        (self.root / 'bin/java').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'reviewed'):
            self.verify()

    def test_external_symlink_is_rejected_even_when_contents_match_registry(self):
        outside = Path(self.temporary.name) / 'outside'
        outside.write_text('fixture licence')
        licence = self.root / 'legal/jdk.localedata/LICENSE'
        licence.unlink()
        licence.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'Unsafe link'):
            self.verify()
