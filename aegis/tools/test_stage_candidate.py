"""Offline staging regression; tiny synthetic JARs, not application/native execution."""
import importlib.util
import json
import hashlib
import struct
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packaging'))
import client_runtime
import verify_client_release

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

    def core(self, *, include_key=True, extra=None):
        contents = {
            'org/securemail/client/safeweb/TorBrowserInstaller.class': b'synthetic class marker',
            'org/securemail/client/safeweb/TorBrowserSignature.class': b'synthetic class marker',
            'org/securemail/client/safeweb/SandboxPrerequisites.class': b'synthetic class marker',
            'org/securemail/client/safeweb/TorBrowserDiscovery.class': b'synthetic class marker',
            'org/securemail/client/safeweb/TorBrowserDownloadService.class': b'synthetic class marker',
            client_runtime.VOICE_REGISTRY: client_runtime.VOICE_REGISTRY_SOURCE.read_bytes(),
            **{name: b'synthetic audio class marker' for name in client_runtime.VOICE_CORE_CLASSES},
            'org/securemail/client/update/SignedManifest.class': verify_client_release.ROOT_KEY + b'2.5.0',
            'org/securemail/client/update/UpdaterMain.class': b'synthetic helper marker',
            client_runtime.TOR_BROWSER_KEY_PROVENANCE: (ROOT / 'client-core/src/main/resources' / client_runtime.TOR_BROWSER_KEY_PROVENANCE).read_bytes(),
        }
        if include_key:
            contents[client_runtime.TOR_BROWSER_PUBLIC_KEY] = (ROOT / 'client-core/src/main/resources' / client_runtime.TOR_BROWSER_PUBLIC_KEY).read_bytes()
        if extra: contents.update(extra)
        jar(self.build / 'client-core.jar', contents)

    def stage(self):
        return stage_candidate.stage(self.linux, self.windows, self.build, [self.deps], self.output)

    def prior(self):
        self.output.mkdir()
        (self.output / 'previous').write_text('old complete stage must survive failures')

    def test_both_platforms_include_transitive_runtime_and_same_application_hashes(self):
        self.stage()
        data = json.loads((self.output / 'RUNTIME-STAGE-2.5.0.json').read_text())
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

    def test_structural_module_check_rejects_nested_tests_acceptance_and_fixtures(self):
        for entry in ['org/securemail/client/voice/GlasAudioTest$Fixture.class',
                      'org/securemail/client/security/VoiceNativeAcceptanceMain.class',
                      'org/securemail/client/update/frozen/v150/SignedManifest.class']:
            self.core(extra={entry: b'synthetic test marker'}); self.stage()
            with self.assertRaisesRegex(ValueError, 'Test classes/resources'):
                verify_client_release.app_jars(self.output / 'linux')
        self.core(); self.stage()
        self.assertEqual(verify_client_release.app_jars(self.output / 'linux'), verify_client_release.app_jars(self.output / 'win'))
        jar(self.output / 'linux/client-core-2.0.0.jar', {'old': 'obsolete module'})
        with self.assertRaisesRegex(ValueError, 'Conflicting application'):
            verify_client_release.app_jars(self.output / 'linux')

    def test_missing_voice_class_or_stale_compiled_registry_preserves_previous_stage(self):
        self.prior()
        self.core(extra={client_runtime.VOICE_REGISTRY: b'{"schema":1,"libraries":{}}'})
        with self.assertRaisesRegex(ValueError, 'voice platform inventory'):
            self.stage()
        self.assertTrue((self.output / 'previous').is_file())
        self.core()
        with zipfile.ZipFile(self.build / 'client-core.jar') as archive:
            contents = {name: archive.read(name) for name in archive.namelist() if name != client_runtime.VOICE_CORE_CLASSES[0]}
        jar(self.build / 'client-core.jar', contents)
        with self.assertRaisesRegex(ValueError, 'resource missing'):
            self.stage()
        self.assertTrue((self.output / 'previous').is_file())


class VoiceNativeRuntimeVerificationTest(unittest.TestCase):
    """Synthetic byte-level verifier fixtures; no DLL/ELF code is executed."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aegis-voice-pins-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.registry = self.root / 'registry.json'; self.provenance = self.root / 'provenance.json'
        self.core = self.root / 'client-core.jar'
        self.bundles = {'linux': self.root / 'linux', 'win': self.root / 'win'}
        for platform, bundle in self.bundles.items():
            (bundle / 'native').mkdir(parents=True); (bundle / 'licenses').mkdir()
            key = 'linux-x86_64' if platform == 'linux' else 'windows-x86_64'
            for name in client_runtime.VOICE_FILES[key]:
                (bundle / 'native' / name).write_bytes(self.elf() if platform == 'linux' else self.pe())
            for name in client_runtime.VOICE_LICENSES:
                shutil.copyfile(ROOT / 'docs/third-party' / name, bundle / 'licenses' / name)
        self.pins_patch = patch.multiple(client_runtime, VOICE_REGISTRY_SOURCE=self.registry, VOICE_PROVENANCE=self.provenance)
        self.pins_patch.start(); self.addCleanup(self.pins_patch.stop); self.review_fixture_pins()

    @staticmethod
    def elf(machine=62):
        header = bytearray(64); header[:7] = b'\x7fELF\x02\x01\x01'; struct.pack_into('<HH', header, 16, 3, machine); return bytes(header)

    @staticmethod
    def pe(machine=0x8664, magic=0x20b, dll=True):
        header = bytearray(512); header[:2] = b'MZ'; struct.pack_into('<I', header, 60, 128)
        header[128:132] = b'PE\0\0'; struct.pack_into('<H', header, 132, machine)
        struct.pack_into('<H', header, 150, 0x2000 if dll else 0); struct.pack_into('<H', header, 152, magic); return bytes(header)

    def review_fixture_pins(self):
        libraries = {}; binaries = []
        for platform, bundle in self.bundles.items():
            key = 'linux-x86_64' if platform == 'linux' else 'windows-x86_64'; libraries[key] = {}
            for name in client_runtime.VOICE_FILES[key]:
                pin = client_runtime.sha256(bundle / 'native' / name); libraries[key][name] = pin
                component, version = ('opus', '1.6.1') if name in ('opus.dll', 'libopus.so') else ('speexdsp', '1.2.1')
                binaries.append({'platform': key, 'filename': name, 'binarySHA256': pin, 'name': component, 'version': version})
        data = json.dumps({'schema': 1, 'libraries': libraries}).encode()
        self.registry.write_bytes(data); jar(self.core, {client_runtime.VOICE_REGISTRY: data})
        self.provenance.write_text(json.dumps({'sourceArchives': client_runtime.VOICE_SOURCE_ARCHIVES, 'binaries': binaries}))

    def test_both_native_platforms_match_full_compiled_registry(self):
        for platform, bundle in self.bundles.items():
            pins = client_runtime.verify_voice_native(bundle, platform, core_jar=self.core)
            self.assertEqual(2, len(pins))
        with self.assertRaisesRegex(ValueError, 'Unsupported voice package platform'):
            client_runtime.verify_voice_native(self.bundles['linux'], 'darwin', core_jar=self.core)

    def test_changed_bytes_symlink_and_shadow_codec_are_rejected(self):
        file = self.bundles['linux'] / 'native/libopus.so'; original = file.read_bytes(); file.write_bytes(original + b'tampered')
        with self.assertRaisesRegex(ValueError, 'changed pinned voice'):
            client_runtime.verify_voice_native(self.bundles['linux'], 'linux', core_jar=self.core)
        file.unlink(); target = self.root / 'linked-lib.so'; target.write_bytes(original); file.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'changed pinned voice'):
            client_runtime.verify_voice_native(self.bundles['linux'], 'linux', core_jar=self.core)
        file.unlink(); file.write_bytes(original); (file.parent / 'libopus-old.so').write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'shadow voice'):
            client_runtime.verify_voice_native(self.bundles['linux'], 'linux', core_jar=self.core)

    def test_stale_windows_pin_inside_linux_core_is_rejected(self):
        data = json.loads(self.registry.read_text()); data['libraries']['windows-x86_64']['opus.dll'] = '0' * 64
        jar(self.core, {client_runtime.VOICE_REGISTRY: json.dumps(data)})
        with self.assertRaisesRegex(ValueError, 'pins differ'):
            client_runtime.verify_voice_native(self.bundles['linux'], 'linux', core_jar=self.core)

    def test_matching_hash_cannot_hide_wrong_native_architecture(self):
        for platform, name, invalid in [('linux', 'libopus.so', self.elf(machine=183)),
                                       ('win', 'opus.dll', self.pe(machine=0x14c, magic=0x10b)),
                                       ('win', 'opus.dll', self.pe(dll=False))]:
            (self.bundles[platform] / 'native' / name).write_bytes(invalid); self.review_fixture_pins()
            with self.assertRaisesRegex(ValueError, 'AMD64'):
                client_runtime.verify_voice_native(self.bundles[platform], platform, core_jar=self.core)
            (self.bundles[platform] / 'native' / name).write_bytes(self.elf() if platform == 'linux' else self.pe()); self.review_fixture_pins()

    def test_missing_license_and_duplicate_registry_fail_closed(self):
        license = self.bundles['linux'] / 'licenses/opus-1.6.1-LICENSE'; license.unlink()
        with self.assertRaisesRegex(ValueError, 'voice license'):
            client_runtime.verify_voice_native(self.bundles['linux'], 'linux', core_jar=self.core)
        self.core.unlink()
        with zipfile.ZipFile(self.core, 'w') as archive:
            archive.writestr(client_runtime.VOICE_REGISTRY, self.registry.read_bytes())
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                archive.writestr(client_runtime.VOICE_REGISTRY, self.registry.read_bytes())
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            client_runtime.voice_registry(self.core)

    def test_pe_version_words_use_major_minor_not_patch_shift(self):
        resource = bytearray(32); struct.pack_into('<I', resource, 0, 0xFEEF04BD)
        struct.pack_into('<IIII', resource, 8, 0x00020005, 0, 0x00020005, 0)
        self.assertTrue(verify_client_release.expected_pe_version(resource))
        struct.pack_into('<IIII', resource, 8, 0x00020000, 0x00050000, 0x00020000, 0x00050000)
        self.assertFalse(verify_client_release.expected_pe_version(resource))


if __name__ == '__main__':
    unittest.main()
