"""Installer boundary tests. Tiny generated fixtures are NOT official Tor binaries.

GPG integration uses a disposable TEST-ONLY key and patches the pinned public
fingerprint in-process. It never opens, requests or replaces any release key.
Native Tor Browser execution and official package verification are separate gates.
"""
from argparse import Namespace
import importlib.util
import io
import hashlib
import struct
import time
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('safeweb_install', Path(__file__).with_name('safeweb-install.py'))
sw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sw)


class InstallerBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='aegis-installer-test-')
        self.root = Path(self.tmp.name)
        self.archive = self.root / 'tor-browser-linux-x86_64-15.0.25.tar.xz'

    def tearDown(self):
        self.tmp.cleanup()

    def members(self):
        files = {
            'Browser/start-tor-browser': b'#!/bin/sh\nexit 0\n',
            'Browser/firefox': b'TEST ONLY, NOT A BROWSER',
            'Browser/application.ini': b'[App]\nVersion=140.17.0\n',
            'Browser/TorBrowser/Tor/tor': b'TEST ONLY, NOT TOR',
            'Browser/TorBrowser/Data/Browser/profile.default/prefs.js': b'fixture preferences',
            'Browser/start-tor-browser.desktop': b'fixture canonical launcher',
            'start-tor-browser.desktop': b'fixture writable shortcut',
            **{f'Browser/support-{i}': f'fixture {i}'.encode() for i in range(10)},
        }
        return [('tor-browser/' + k, v, None) for k, v in files.items()]

    def make_archive(self, additional=(), members=None):
        with tarfile.open(self.archive, 'w:xz') as tar:
            for name, data, kind in [*(self.members() if members is None else members), *additional]:
                entry = tarfile.TarInfo(name)
                entry.mode = 0o6755
                if kind == 'symlink':
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = data
                elif kind == 'hardlink':
                    entry.type = tarfile.LNKTYPE
                    entry.linkname = data
                elif kind == 'fifo':
                    entry.type = tarfile.FIFOTYPE
                elif kind == 'directory':
                    entry.type = tarfile.DIRTYPE
                else:
                    entry.size = len(data)
                tar.addfile(entry, None if kind else io.BytesIO(data))
        return self.archive

    def extract(self):
        return sw.extract_linux(self.archive, self.root / 'unpack')

    def test_extract_and_inventory_preserves_only_user_executable_bit(self):
        self.make_archive()
        bundle = self.extract()
        self.assertEqual(stat.S_IMODE((bundle / 'Browser/firefox').stat().st_mode), 0o700)
        files, links = sw.inventories(bundle)
        self.assertIn('Browser/start-tor-browser.desktop', files)
        self.assertNotIn('start-tor-browser.desktop', files)
        self.assertFalse(any('/Data/' in x for x in files))
        self.assertEqual(links, {})

    def test_internal_symlink_preserved_and_authenticated_separately(self):
        self.make_archive([('tor-browser/Browser/alias', 'support-0', 'symlink')])
        bundle = self.extract()
        files, links = sw.inventories(bundle)
        self.assertTrue((bundle / 'Browser/alias').is_symlink())
        self.assertNotIn('Browser/alias', files)
        self.assertEqual(links, {'Browser/alias': 'support-0'})

    def test_internal_directory_symlink_preserved(self):
        self.make_archive([('tor-browser/Browser/TorAlias', 'TorBrowser/Tor', 'symlink')])
        bundle = self.extract()
        self.assertEqual(sw.inventories(bundle)[1], {'Browser/TorAlias': 'TorBrowser/Tor'})

    def test_internal_hardlink_and_forward_chain(self):
        self.make_archive([('tor-browser/Browser/hard1', 'tor-browser/Browser/hard2', 'hardlink'),
                           ('tor-browser/Browser/hard2', 'tor-browser/Browser/support-0', 'hardlink')])
        bundle = self.extract()
        self.assertEqual((bundle / 'Browser/hard1').read_bytes(), b'fixture 0')
        self.assertEqual((bundle / 'Browser/hard1').stat().st_ino, (bundle / 'Browser/support-0').stat().st_ino)

    def test_traversal_absolute_and_cross_platform_paths_rejected(self):
        for member in ['../outside', '/outside', 'tor-browser/../../outside', 'C:/outside',
                       'tor-browser/Browser\\outside', 'tor-browser/Browser/line\nbreak']:
            with self.subTest(member=member):
                self.make_archive([(member, b'x', None)])
                with tarfile.open(self.archive, 'r:xz') as tar, self.assertRaises(ValueError):
                    sw.inspect_tar(tar)

    def test_escaping_and_absolute_symlinks_rejected(self):
        for target in ['../../../secret', '/etc/passwd', 'C:\\secret', '../../outside']:
            with self.subTest(target=target):
                self.make_archive([('tor-browser/Browser/link', target, 'symlink')])
                with tarfile.open(self.archive, 'r:xz') as tar, self.assertRaises(ValueError):
                    sw.inspect_tar(tar)

    def test_link_cycles_and_dangling_rejected(self):
        for additional in [[('tor-browser/Browser/a', 'b', 'symlink'), ('tor-browser/Browser/b', 'a', 'symlink')],
                           [('tor-browser/Browser/a', 'missing', 'symlink')]]:
            self.make_archive(additional)
            with tarfile.open(self.archive, 'r:xz') as tar, self.assertRaises(ValueError):
                sw.inspect_tar(tar)

    def test_file_under_symlink_rejected_even_if_target_internal(self):
        self.make_archive([('tor-browser/Browser/a', 'TorBrowser', 'symlink'),
                           ('tor-browser/Browser/a/payload', b'x', None)])
        with tarfile.open(self.archive, 'r:xz') as tar, self.assertRaisesRegex(ValueError, 'underneath'):
            sw.inspect_tar(tar)

    def test_special_file_duplicate_root_and_limits_rejected(self):
        additions = [[('tor-browser/Browser/fifo', b'', 'fifo')],
                     [('tor-browser/Browser/firefox', b'again', None)],
                     [('other-root/file', b'x', None)]]
        for additional in additions:
            self.make_archive(additional)
            with tarfile.open(self.archive, 'r:xz') as tar, self.assertRaises(ValueError):
                sw.inspect_tar(tar)
        self.make_archive()
        for constant, value in [('MAX_MEMBERS', 1), ('MAX_EXPANDED', 1)]:
            with patch.object(sw, constant, value), tarfile.open(self.archive, 'r:xz') as tar, self.assertRaises(ValueError):
                sw.inspect_tar(tar)

    def test_installed_extra_injection_and_changed_symlink_detected(self):
        self.make_archive([('tor-browser/Browser/alias', 'support-0', 'symlink')])
        bundle = self.extract()
        expected = sw.inventories(bundle)
        (bundle / 'Browser/injected.so').write_bytes(b'injected')
        self.assertNotEqual(sw.inventories(bundle), expected)
        (bundle / 'Browser/injected.so').unlink()
        (bundle / 'Browser/alias').unlink()
        (bundle / 'Browser/alias').symlink_to('support-1')
        self.assertNotEqual(sw.inventories(bundle), expected)
        (bundle / 'Browser/alias').unlink()
        (bundle / 'Browser/alias').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            sw.inventories(bundle)

    def test_input_symlink_empty_and_oversize_rejected(self):
        file = self.root / 'file'
        file.write_bytes(b'12345')
        with self.assertRaises(ValueError):
            sw.snapshot_input(file, self.root / 'too-big', 4)
        file.write_bytes(b'')
        with self.assertRaises(ValueError):
            sw.snapshot_input(file, self.root / 'empty', 4)
        file.unlink()
        file.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            sw.snapshot_input(file, self.root / 'link', 99999)

    def test_non_windows_never_executes_windows_installer(self):
        if os.name == 'nt':
            self.skipTest('This refusal is specific to non-Windows hosts')
        with patch.object(sw.subprocess, 'run') as execute:
            with self.assertRaisesRegex(ValueError, 'Native Windows'):
                sw.install_windows(self.root / 'not-executed.exe', self.root / 'windows')
            execute.assert_not_called()

    def test_package_filename_and_version_are_restricted(self):
        self.assertEqual(sw.package_info(self.archive.name), ('linux-x86_64', '15.0.25'))
        self.assertEqual(sw.package_info('tor-browser-windows-x86_64-portable-15.0.25.exe'), ('windows-x86_64', '15.0.25'))
        for name in ['firefox.exe', 'tor-browser-linux-x86_64-15.0.25.exe',
                     'tor-browser-windows-x86_64-portable-15.0.25.tar.xz',
                     'tor-browser-linux-x86_64-15.0a1.tar.xz']:
            with self.assertRaises(ValueError):
                sw.package_info(name)


@unittest.skipUnless(shutil.which('gpgv'), 'gpgv required')
class GpgVerificationIntegrationTest(unittest.TestCase):
    # Reuse fixture builders without rerunning the whole boundary test class.
    members = InstallerBoundaryTest.members
    make_archive = InstallerBoundaryTest.make_archive
    tearDown = InstallerBoundaryTest.tearDown
    @classmethod
    def setUpClass(cls):
        # Generate TEST-ONLY OpenPGP RSA packets in memory. GPG agent/sockets are
        # deliberately unnecessary, and no private key is written to disk.
        from cryptography.hazmat.primitives.asymmetric import rsa
        cls.key_tmp = tempfile.TemporaryDirectory(prefix='aegis-test-only-gpg-')
        cls.gpg_home = Path(cls.key_tmp.name)
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        number = cls.private.public_key().public_numbers()
        cls.created = int(time.time()) - 60
        cls.public_body = b'\x04' + struct.pack('>I', cls.created) + b'\x01' + cls.mpi(number.n) + cls.mpi(number.e)
        cls.fingerprint = hashlib.sha1(b'\x99' + struct.pack('>H', len(cls.public_body)) + cls.public_body).hexdigest().upper()
        uid = b'AEGIS DISPOSABLE TEST KEY <test@example.invalid>'
        signed = b'\x99' + struct.pack('>H', len(cls.public_body)) + cls.public_body + b'\xb4' + struct.pack('>I', len(uid)) + uid
        public = cls.packet(6, cls.public_body) + cls.packet(13, uid) + cls.packet(2, cls.signature_body(signed, 0x13))
        cls.test_keyring = cls.gpg_home / 'test-public.keyring'
        cls.test_keyring.write_bytes(public)

    @staticmethod
    def mpi(number):
        return struct.pack('>H', number.bit_length()) + number.to_bytes((number.bit_length() + 7) // 8, 'big')

    @staticmethod
    def packet(tag, body):
        size = len(body)
        length = bytes([size]) if size < 192 else (bytes([((size - 192) >> 8) + 192, (size - 192) & 255]) if size < 8384 else b'\xff' + struct.pack('>I', size))
        return bytes([0xc0 | tag]) + length + body

    @classmethod
    def signature_body(cls, data, kind=0):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils
        hashed = b'\x05\x02' + struct.pack('>I', cls.created)
        header = bytes([4, kind, 1, 8]) + struct.pack('>H', len(hashed)) + hashed
        digest = hashlib.sha256(data + header + b'\x04\xff' + struct.pack('>I', len(header))).digest()
        value = cls.private.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        issuer = b'\x09\x10' + bytes.fromhex(cls.fingerprint[-16:])
        return header + struct.pack('>H', len(issuer)) + issuer + digest[:2] + cls.mpi(int.from_bytes(value, 'big'))

    @classmethod
    def tearDownClass(cls):
        cls.private = None
        cls.key_tmp.cleanup()

    def setUp(self):
        InstallerBoundaryTest.setUp(self)
        self.make_archive([('tor-browser/Browser/alias', 'support-0', 'symlink')])
        self.signature = self.root / 'fixture.asc'
        self.sign()
        self.args = Namespace(archive=self.archive, signature=self.signature, keyring=self.test_keyring,
                              destination=self.root / 'installed', expected_version='15.0.25',
                              expected_sha256=None, verify_only=False, check_installed=False, reseal=False)

    def sign(self):
        self.signature.write_bytes(self.packet(2, self.signature_body(self.archive.read_bytes())))

    def test_real_gpgv_rejects_unpinned_test_signer(self):
        # Public production fingerprint stays unchanged for this test.
        with self.assertRaisesRegex(ValueError, 'Official Tor Browser'):
            sw.run(self.args)
        self.assertFalse(self.args.destination.exists())

    def test_real_gpgv_install_compare_reseal_and_tamper_rejection(self):
        # This process-local patch is only a fixture for exercising genuine gpgv I/O.
        with patch.object(sw, 'FINGERPRINT', self.fingerprint):
            result = sw.run(self.args)
            self.assertEqual(result['operation'], 'installation')
            self.assertEqual(result['signature']['primaryFingerprint'], self.fingerprint)
            destination = self.args.destination
            self.assertTrue((destination / 'Browser/alias').is_symlink())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
            profile = destination / 'Browser/TorBrowser/Data/Browser/profile.default/prefs.js'
            profile.write_bytes(b'persisted mutable profile')
            (destination / 'start-tor-browser.desktop').write_bytes(b'official launcher generated path')
            self.args.check_installed = True
            self.assertEqual(sw.run(self.args)['operation'], 'installed-comparison')
            self.args.check_installed, self.args.reseal = False, True
            self.assertEqual(sw.run(self.args)['operation'], 'authenticated-reseal')
            self.assertEqual(profile.read_bytes(), b'persisted mutable profile')
            before = (destination / sw.INVENTORY).read_bytes()
            (destination / 'Browser/firefox').write_bytes(b'corrupted executable')
            with self.assertRaisesRegex(ValueError, 'differs from signed package'):
                sw.run(self.args)
            self.assertEqual((destination / sw.INVENTORY).read_bytes(), before)

    def test_real_gpgv_changed_archive_and_signature_rejected(self):
        with patch.object(sw, 'FINGERPRINT', self.fingerprint):
            self.archive.write_bytes(self.archive.read_bytes() + b'tampered')
            with self.assertRaises(ValueError):
                sw.run(self.args)
            self.make_archive()
            self.sign()
            self.signature.write_text('NOT A SIGNATURE')
            with self.assertRaises(ValueError):
                sw.run(self.args)
        self.assertFalse(self.args.destination.exists())

    def test_existing_destination_not_touched(self):
        self.args.destination.mkdir()
        user_file = self.args.destination / 'KEEP'
        user_file.write_bytes(b'do not change')
        with patch.object(sw, 'FINGERPRINT', self.fingerprint), self.assertRaisesRegex(ValueError, 'must not exist'):
            sw.run(self.args)
        self.assertEqual(user_file.read_bytes(), b'do not change')

    def test_version_and_hash_mismatch_leave_no_installation(self):
        with patch.object(sw, 'FINGERPRINT', self.fingerprint):
            self.args.expected_version = '15.0.24'
            with self.assertRaisesRegex(ValueError, 'version'):
                sw.run(self.args)
            self.args.expected_version, self.args.expected_sha256 = '15.0.25', '0' * 64
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                sw.run(self.args)
        self.assertFalse(self.args.destination.exists())

    def test_verify_only_authenticates_without_extract_or_execute(self):
        self.args.verify_only = True
        with patch.object(sw, 'FINGERPRINT', self.fingerprint), patch.object(sw, 'extract_linux') as extract, patch.object(sw, 'install_windows') as execute:
            result = sw.run(self.args)
            self.assertFalse(result['installed'])
            self.assertEqual(result['operation'], 'signature-verification')
            extract.assert_not_called()
            execute.assert_not_called()
        self.assertFalse(self.args.destination.exists())


if __name__ == '__main__':
    unittest.main()
