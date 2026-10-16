"""5.0 version, frozen source, payload/readability and base-reuse guard checks.

Fixtures are synthetic archives/temporary Git repositories. No host installation,
real client acceptance or privileged process is performed by this test suite.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packaging'))
import client_runtime
import client_runtime500
import verify_client_release
import verify_appimage500
import verify_client_release500


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


package500 = load('package500', ROOT / 'packaging/package-clients500.py')
stage500 = load('stage500', ROOT / 'tools/stage-candidate500.py')


def jar(path, contents):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, 'w') as archive:
        for name, value in contents.items():
            archive.writestr(name, value)


class Packaging500Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aegis-package500-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_real_jar_directory_records_do_not_mask_or_invent_server_implementation(self):
        archive = self.root / 'common-protocol.jar'
        jar(archive, {'org/': b'', 'org/securemail/': b'', 'org/securemail/community/': b'',
                      'org/securemail/community/protocol/': b'',
                      'org/securemail/community/protocol/CommunityAuth.class': b'fixture shared class'})
        with zipfile.ZipFile(archive) as opened:
            self.assertTrue(opened.getinfo('org/securemail/community/').is_dir())
            verify_client_release500.verify_client_package_boundary(opened)
        for forbidden in ['org/securemail/community/access/Authorization.class',
                          'org/securemail/community/private-config.json',
                          'org/securemail/worker/NewsWorker.class',
                          'org/securemail/community/protocol-sibling/Unauthorized.class']:
            jar(archive, {'org/securemail/community/': b'', forbidden: b'forbidden fixture payload'})
            with zipfile.ZipFile(archive) as opened, self.assertRaisesRegex(ValueError, 'Server/worker'):
                verify_client_release500.verify_client_package_boundary(opened)

    def test_normalization_makes_root_squashfs_readable_preserves_executables_and_removes_special_bits(self):
        folder = self.root / 'AppDir'; folder.mkdir(mode=0o700)
        nested = folder / 'runtime/bin'; nested.mkdir(parents=True, mode=0o700)
        data = folder / 'readme'; data.write_text('ordinary'); data.chmod(0o600)
        executable = nested / 'java'; executable.write_bytes(b'fixture'); executable.chmod(0o4700)
        package500.normalize_payload(folder)
        for directory in [folder, folder / 'runtime', nested]:
            self.assertEqual(0o755, stat.S_IMODE(directory.stat().st_mode))
        self.assertEqual(0o644, stat.S_IMODE(data.stat().st_mode))
        self.assertEqual(0o755, stat.S_IMODE(executable.stat().st_mode))

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink policy fixture')
    def test_normalization_does_not_follow_link_outside_payload(self):
        folder = self.root / 'payload'; folder.mkdir()
        external = self.root / 'private'; external.write_text('unchanged'); external.chmod(0o600)
        (folder / 'alias').symlink_to(external)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            package500.normalize_payload(folder)
        self.assertEqual(0o600, stat.S_IMODE(external.stat().st_mode))
        self.assertEqual('unchanged', external.read_text())

    def test_exact_base_zip_bytes_must_match_not_only_executable_presence(self):
        base = self.root / 'base'; (base / 'tor').mkdir(parents=True)
        (base / 'tor/tor.exe').write_bytes(b'fixture original')
        archive = self.root / 'base.zip'; jar(archive, {'AEGIS/tor/tor.exe': b'fixture original'})
        self.assertEqual(1, package500.verify_windows_base(archive, base)['files'])
        (base / 'tor/tor.exe').write_bytes(b'fixture modified')
        with self.assertRaisesRegex(ValueError, 'differs|mismatch'):
            package500.verify_windows_base(archive, base)
        (base / 'tor/tor.exe').write_bytes(b'fixture original'); (base / 'extra').write_text('not in release')
        with self.assertRaisesRegex(ValueError, 'Extra or missing'):
            package500.verify_windows_base(archive, base)

    def test_base_zip_traversal_and_unexpected_root_are_rejected(self):
        base = self.root / 'base'; base.mkdir()
        for name in ['AEGIS/../private', '/AEGIS/tor', 'wrong/tor', 'AEGIS\\tor']:
            archive = self.root / 'bad.zip'; jar(archive, {name: b'fixture'})
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                package500.verify_windows_base(archive, base)

    def test_version_resource_parser_accepts_only_requested_500_version_and_keeps_historical_default(self):
        def resource(version):
            return struct.pack('<IIIIII', 0xFEEF04BD, 0x00010000,
                               version[0] << 16 | version[1], version[2] << 16 | version[3],
                               version[0] << 16 | version[1], version[2] << 16 | version[3])
        self.assertTrue(verify_client_release.expected_pe_version(resource((5, 0, 0, 0)), (5, 0, 0, 0)))
        self.assertFalse(verify_client_release.expected_pe_version(resource((2, 5, 0, 0)), (5, 0, 0, 0)))
        self.assertTrue(verify_client_release.expected_pe_version(resource((2, 5, 0, 0))))
        self.assertFalse(verify_client_release.expected_pe_version(resource((5, 0, 0, 0))))

    def test_frozen_commit_guard_uses_actual_git_tree_and_rejects_modifications(self):
        repository = self.root / 'repo'; repository.mkdir()
        def git(*arguments):
            return subprocess.check_output(['git', *arguments], cwd=repository, text=True, stderr=subprocess.DEVNULL).strip()
        git('init', '-b', 'fixture'); git('config', 'user.name', 'Fixture'); git('config', 'user.email', 'fixture@example.invalid')
        (repository / 'source').write_text('frozen'); git('add', 'source'); git('commit', '-m', 'Fixture source')
        commit = git('rev-parse', 'HEAD')
        with patch.object(package500, 'ROOT', repository):
            self.assertEqual(commit, package500.require_frozen_commit(commit)[0])
            with self.assertRaises(ValueError): package500.require_frozen_commit('a' * 40)
            (repository / 'source').write_text('modified')
            with self.assertRaisesRegex(ValueError, 'clean exact'):
                package500.require_frozen_commit(commit)

    def test_new_installer_and_rollback_helper_agree_on_versioned_rollback_directory(self):
        installer = (ROOT / 'packaging/windows/installer500.nsi').read_text()
        helper = (ROOT / 'packaging/windows/maintenance500.c').read_text()
        self.assertIn('VIProductVersion "5.0.0.0"', installer)
        self.assertIn('.rollback-5.0.0', installer); self.assertIn('.rollback-5.0.0', helper)
        self.assertNotIn('.rollback-1.5.0', helper); self.assertNotIn('.rollback-2.5.0', helper)
        self.assertIn('RequestExecutionLevel user', installer)
        self.assertNotIn('MUI_LANGUAGE "English"', installer)

    def test_actual_squashfs_listing_policy_rejects_root_only_modes_and_unexpected_nodes(self):
        expected = {'squashfs-root', 'squashfs-root/AppRun'}
        valid = 'drwxr-xr-x 0/0 3 2026-10-15 13:00 squashfs-root\n-rwxr-xr-x 0/0 7 2026-10-15 13:00 squashfs-root/AppRun\n'
        self.assertTrue(verify_appimage500.listing_permissions(valid, expected)['actualSquashFSReadableByUnprivilegedUsers'])
        for invalid in [valid.replace('drwxr-xr-x', 'drwx------'), valid.replace('0/0', '1000/1000'),
                        valid + valid.splitlines()[0] + '\n', valid.replace('AppRun', 'Unexpected')]:
            with self.assertRaises(ValueError): verify_appimage500.listing_permissions(invalid, expected)


class Stage500Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aegis-stage500-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.linux, self.windows, self.build, self.deps, self.out = [self.root / p for p in ['linux', 'win', 'build', 'deps', 'out']]
        for base, platform in [(self.linux, 'linux'), (self.windows, 'win')]:
            jar(base / 'app' / ('javafx-controls-21.0.12-' + platform + '.jar'), {'fixture': platform})
            jar(base / 'app/client-core-2.5.0.jar', {'old': 'old client must not ship'})
            jar(base / 'app/commons-logging-1.3.5.jar', {'fixture': 'old transitive version'})
        pins = {}
        for name in client_runtime500.SAFE_WEB_RUNTIME:
            file = self.deps / name; jar(file, {'fixture': name}); pins[name] = client_runtime.sha256(file)
        for mapping, replacement in [(client_runtime.SAFE_WEB_RUNTIME, {n: pins[n] for n in client_runtime.SAFE_WEB_RUNTIME}),
                                     (client_runtime500.SAFE_WEB_RUNTIME, pins)]:
            patcher = patch.dict(mapping, replacement, clear=True); patcher.start(); self.addCleanup(patcher.stop)
        self.core()
        jar(self.build / 'client-ui.jar', {'fixture': 'UI'})
        jar(self.build / 'common-protocol.jar', {'fixture': 'wire compatible protocol'})

    def core(self, *, remove=None, version=b'5.0.0'):
        contents = {name: b'fixture class' for name in [
            'org/securemail/client/safeweb/' + name + '.class' for name in
            ['TorBrowserInstaller', 'TorBrowserSignature', 'SandboxPrerequisites', 'TorBrowserDiscovery', 'TorBrowserDownloadService']
        ] + client_runtime.VOICE_CORE_CLASSES + client_runtime500.REQUIRED_CLASSES}
        for resource in [client_runtime.TOR_BROWSER_PUBLIC_KEY, client_runtime.TOR_BROWSER_KEY_PROVENANCE, client_runtime.VOICE_REGISTRY]:
            contents[resource] = (ROOT / 'client-core/src/main/resources' / resource).read_bytes()
        contents['org/securemail/client/update/SignedManifest.class'] = verify_client_release.ROOT_KEY + version
        contents['org/securemail/client/update/UpdaterMain.class'] = b'fixture updater'
        if remove is not None: contents.pop(remove)
        jar(self.build / 'client-core.jar', contents)

    def stage(self):
        return stage500.stage(self.linux, self.windows, self.build, [self.deps], self.out)

    def test_new_version_stage_keeps_identical_cross_platform_jars_and_required_preparation_classes(self):
        self.stage(); data = json.loads((self.out / 'RUNTIME-STAGE-5.0.0.json').read_text())
        self.assertEqual('5.0.0', data['version']); self.assertFalse(data['productionReady'])
        for platform in ['linux', 'win']:
            self.assertFalse((self.out / platform / 'client-core-2.5.0.jar').exists())
            self.assertEqual(['commons-logging-1.4.0.jar'], [p.name for p in (self.out / platform).glob('commons-logging-*.jar')])
            client_runtime500.verify_safe_web_runtime(self.out / platform)
        self.assertEqual(verify_client_release.app_jars(self.out / 'linux', version='5.0.0'),
                         verify_client_release.app_jars(self.out / 'win', version='5.0.0'))

    def test_stale_or_changed_logging_is_rejected_and_historical_pins_stay_unchanged(self):
        self.assertNotIn('commons-logging-1.4.0.jar', client_runtime.SAFE_WEB_RUNTIME)
        self.stage(); app = self.out / 'linux'
        jar(app / 'commons-logging-1.3.5.jar', {'fixture': 'unexpected older version'})
        with self.assertRaisesRegex(ValueError, 'Conflicting 5.0 runtime'):
            client_runtime500.verify_safe_web_runtime(app)
        (app / 'commons-logging-1.3.5.jar').unlink()
        jar(app / 'commons-logging-1.4.0.jar', {'fixture': 'modified payload'})
        with self.assertRaisesRegex(ValueError, 'changed pinned 5.0 runtime'):
            client_runtime500.verify_safe_web_runtime(app)

    def test_missing_real_preparation_implementation_preserves_previous_stage(self):
        self.out.mkdir(); (self.out / 'previous').write_text('preserved')
        self.core(remove=client_runtime500.REQUIRED_CLASSES[0])
        with self.assertRaisesRegex(ValueError, 'implementation missing'):
            self.stage()
        self.assertEqual('preserved', (self.out / 'previous').read_text())

    def test_stale_core_and_accidental_server_jar_fail_structural_checks(self):
        self.core(version=b'2.5.0'); self.stage()
        with self.assertRaisesRegex(ValueError, 'Pinned production public key or updater'):
            verify_client_release.app_jars(self.out / 'linux', version='5.0.0')
        self.core(); self.stage(); jar(self.out / 'linux/news-worker-5.0.0.jar', {'fixture': 'server'})
        with self.assertRaisesRegex(ValueError, 'server'):
            verify_client_release.app_jars(self.out / 'linux', version='5.0.0')
