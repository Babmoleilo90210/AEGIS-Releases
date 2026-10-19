"""Adversarial parser fixtures plus optional real official SDK/APK verification."""
import os,pathlib,tempfile,unittest,zipfile
from unittest.mock import patch
import apk_public_verify600 as public
PIN='a520a96ed433a309757c8193a9f38a356459b55c4bbf81398da85e7c32c22d58'
GOOD='Verifies\nVerified using v2 scheme (APK Signature Scheme v2): false\nVerified using v3 scheme (APK Signature Scheme v3): true\nNumber of signers: 1\nSigner #1 certificate SHA-256 digest: '+PIN+'\n'
class ParserFixtures(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup);self.root=pathlib.Path(self.directory.name);self.apk=self.root/'fixture.apk';self.apk.write_bytes(b'parser fixture, NOT an actual signed APK');self.tool=self.root/'fixture-apksigner'
    def invoke(self,output,code=0):
        self.tool.write_text('#!/usr/bin/env python3\nimport sys\nsys.stdout.write('+repr(output)+')\nsys.exit('+str(code)+')\n');self.tool.chmod(0o700);return public.verify(self.tool,self.apk,PIN)
    def test_positive_parser_fixture(self):self.assertEqual(PIN,self.invoke(GOOD)['certificateSha256'])
    def test_wrong_pin_fixture(self):
        with self.assertRaises(ValueError):self.invoke(GOOD.replace(PIN,'f'*64))
    def test_duplicate_signer_fixture(self):
        with self.assertRaises(ValueError):self.invoke(GOOD+'Signer #2 certificate SHA-256 digest: '+PIN+'\n')
    def test_duplicate_digest_fixture(self):
        with self.assertRaises(ValueError):self.invoke(GOOD+'Signer #1 certificate SHA-256 digest: '+PIN+'\n')
    def test_duplicate_scheme_fixture(self):
        with self.assertRaises(ValueError):self.invoke(GOOD+'Verified using v3 scheme (APK Signature Scheme v3): true\n')
    def test_v1_only_fixture(self):
        with self.assertRaises(ValueError):self.invoke(GOOD.replace('v3): true','v3): false'))
    def test_process_rejection_fixture(self):
        with self.assertRaises(ValueError):self.invoke(GOOD,1)
    def test_output_bound_fixture(self):
        with self.assertRaises(ValueError):self.invoke(GOOD+'x'*(public.MAX_OUTPUT+1))
    def test_invalid_pin_before_process(self):
        with self.assertRaises(ValueError):public.verify(self.tool,self.apk,PIN.upper())
    def test_timeout_fixture(self):
        self.tool.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(2)\n');self.tool.chmod(0o700)
        with patch.object(public,'TIMEOUT_SECONDS',0.05),self.assertRaises(ValueError):public.verify(self.tool,self.apk,PIN)
class ActualOfficialApksigner(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('AEGIS_TEST_APKSIGNER')and os.environ.get('AEGIS_TEST_SIGNED_APK'),'Real SDK/APK paths not supplied; parser fixtures do not replace this test')
    def test_actual_apk_and_actual_tamper(self):
        # Recovered builds use a fresh explicitly TEST-only key; the old private
        # test key is not restored. Parser fixtures retain their fixed PIN.
        expected_test_certificate=os.environ.get('AEGIS_TEST_CERT_SHA256',PIN)
        apk=pathlib.Path(os.environ['AEGIS_TEST_SIGNED_APK']);tool=pathlib.Path(os.environ['AEGIS_TEST_APKSIGNER']);result=public.verify(tool,apk,expected_test_certificate);self.assertTrue(result['schemes']['v3'])
        with tempfile.TemporaryDirectory()as directory:
            changed=pathlib.Path(directory)/'actual-tampered.apk';data=bytearray(apk.read_bytes())
            with zipfile.ZipFile(apk)as z:
                item=z.getinfo('classes.dex');offset=item.header_offset+30+len(item.filename.encode())+len(item.extra);data[offset+10]^=1
            changed.write_bytes(data)
            with self.assertRaises(ValueError):public.verify(tool,changed,expected_test_certificate)
if __name__=='__main__':unittest.main(verbosity=2)
