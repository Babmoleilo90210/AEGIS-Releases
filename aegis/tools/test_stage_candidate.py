"""Offline staging regression; tiny synthetic JARs, not application/native execution."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packaging'))
import client_runtime

spec = importlib.util.spec_from_file_location('stage_candidate', ROOT / 'tools/stage-candidate.py')
stage_candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_candidate)


def jar(file, contents):
    file.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(file, 'w') as output:
        for name, data in contents.items():
            output.writestr(name, data)


class CandidateRuntimeStagingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aegis-stage-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.linux, self.windows, self.build, self.deps, self.output = [self.root / x for x in ['linux', 'win', 'compiled', 'deps', 'output']]
        for base, platform in [(self.linux, 'linux'), (self.windows, 'win')]:
            jar(base / 'app' / ('javafx-controls-21.0.12-' + platform + '.jar'), {'platform': platform})
            jar(base / 'app/client-core-1.5.0.jar', {'old': 'unused old module'})
        self.pins = {}
        for name in client_runtime.SAFE_WEB_RUNTIME:
            file = self.deps / name
            jar(file, {'META-INF/LICENSE': 'Synthetic fixture license', 'fixture': name})
            self.pins[name] = client_runtime.sha256(file)
        self.patches = patch.dict(client_runtime.SAFE_WEB_RUNTIME, self.pins, clear=True)
        self.patches.start()
        self.addCleanup(self.patches.stop)
        self.core()
        jar(self.build / 'client-ui.jar', {'fixture': 'same UI bytes for both platforms'})
        jar(self.build / 'common-protocol.jar', {'fixture': 'same protocol bytes for both platforms'})

    def core(self, *, include_key=True):
        contents = {
            'org/securemail/client/safeweb/TorBrowserInstaller.class': b'synthetic class marker',
            'org/securemail/client/safeweb/TorBrowserSignature.class': b'synthetic class marker',
            client_runtime.TOR_BROWSER_KEY_PROVENANCE: (ROOT / 'client-core/src/main/resources' / client_runtime.TOR_BROWSER_KEY_PROVENANCE).read_bytes(),
        }
        if include_key:
            contents[client_runtime.TOR_BROWSER_PUBLIC_KEY] = (ROOT / 'client-core/src/main/resources' / client_runtime.TOR_BROWSER_PUBLIC_KEY).read_bytes()
        jar(self.build / 'client-core.jar', contents)

    def stage(self):
        return stage_candidate.stage(self.linux, self.windows, self.build, [self.deps], self.output)

    def prior(self):
        self.output.mkdir()
        (self.output / 'previous').write_text('old complete stage must survive failures')

    def test_both_platforms_include_transitive_runtime_and_same_application_hashes(self):
        self.stage()
        data = json.loads((self.output / 'RUNTIME-STAGE-2.0.0.json').read_text())
        self.assertFalse(data['productionReady'])
        for platform in ['linux', 'win']:
            self.assertTrue(set(self.pins) <= set(data['runtimeJars'][platform]))
            self.assertFalse((self.output / platform / 'client-core-1.5.0.jar').exists())
            self.assertTrue((self.output / platform / ('javafx-controls-21.0.12-' + platform + '.jar')).is_file())
            client_runtime.verify_safe_web_runtime(self.output / platform)
        for module, version in stage_candidate.MODULES.items():
            name = module + '-' + version + '.jar'
            self.assertEqual(data['runtimeJars']['linux'][name], data['runtimeJars']['win'][name])

    def test_missing_dependency_preserves_previous_stage(self):
        self.prior()
        (self.deps / 'xz-1.12.jar').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing explicit runtime'):
            self.stage()
        self.assertTrue((self.output / 'previous').is_file())

    def test_changed_dependency_and_symlink_are_rejected(self):
        self.prior()
        file = self.deps / 'commons-io-2.20.0.jar'
        file.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'Changed pinned dependency'):
            self.stage()
        self.assertTrue((self.output / 'previous').is_file())
        file.unlink()
        source = self.root / 'source.jar'
        jar(source, {'fixture': 'wrong content behind link'})
        file.symlink_to(source)
        with self.assertRaisesRegex(ValueError, 'Changed pinned dependency'):
            self.stage()

    def test_wrong_javafx_platform_and_missing_official_public_key_fail_closed(self):
        self.prior()
        wrong = self.linux / 'app/javafx-graphics-21.0.12-win.jar'
        jar(wrong, {'fixture': 'Windows natives do not belong to Linux'})
        with self.assertRaisesRegex(ValueError, 'Wrong platform JavaFX'):
            self.stage()
        wrong.unlink()
        self.core(include_key=False)
        with self.assertRaisesRegex(ValueError, 'resource missing'):
            self.stage()
        self.assertTrue((self.output / 'previous').is_file())

    def test_older_runtime_versions_cannot_shadow_pinned_installer_dependencies(self):
        jar(self.linux / 'app/commons-compress-0.1.jar', {'old': 'obsolete runtime'})
        self.stage()
        self.assertFalse((self.output / 'linux/commons-compress-0.1.jar').exists())
        jar(self.output / 'linux/commons-compress-0.1.jar', {'old': 'accidentally reintroduced'})
        with self.assertRaisesRegex(ValueError, 'Conflicting runtime dependency'):
            client_runtime.verify_safe_web_runtime(self.output / 'linux')


if __name__ == '__main__':
    unittest.main()
