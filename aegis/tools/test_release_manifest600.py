"""Measured fixture bytes and a real temporary Git tree; no native artifact or owner signature claim."""
from pathlib import Path
import json,subprocess,tempfile,unittest,zipfile
from unittest.mock import patch
import release_manifest as legacy
import release_manifest600 as release

class Ecosystem600Test(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='aegis600-release-test-');self.root=Path(self.temp.name);self.repo=self.root/'repo';self.project=self.repo/'aegis';self.project.mkdir(parents=True)
  (self.repo/'README').write_text('Real frozen Git fixture\n');(self.project/'Main.java').write_text('// source fixture for metadata tests\n')
  self.git('init','-q');self.git('config','user.name','AEGIS test');self.git('config','user.email','fixture@example.invalid');self.git('add','.');self.git('commit','-qm','Frozen fixture');self.commit=self.git('rev-parse','HEAD')
  self.assets=self.root/'artifacts';self.assets.mkdir();release.prepare_source_archives(self.project,self.commit,self.assets)
  for name in release.ROLES.values():
   if not (self.assets/name).exists():(self.assets/name).write_bytes(('Measured metadata fixture, not a native binary: '+name).encode())
  self.proof='BUILD-PROVENANCE-6.0.0.json';self.write_provenance();(self.assets/'CHANGELOG-6.0.0.md').write_text('# АЕГИС 6.0.0\nMetadata fixture.\n',encoding='utf-8');self.sums()
  self.spec=self.root/'spec.json';self.spec.write_text(json.dumps({'schemaVersion':1,'version':'6.0.0','sourceCommit':self.commit,'artifacts':[{'role':role,'fileName':name,'provenanceFile':self.proof} for role,name in release.ROLES.items()]}))
 def tearDown(self):self.temp.cleanup()
 def git(self,*args):return subprocess.check_output(['git','-C',str(self.repo),*args],stderr=subprocess.DEVNULL,text=True).strip()
 def write_provenance(self,commit=None):
  (self.assets/self.proof).write_text(json.dumps({'sourceCommit':commit or self.commit,'binaryArtifactSha256':{name:legacy.sha256(self.assets/name) for name in release.ROLES.values() if (self.assets/name).exists()}}))
 def sums(self):(self.assets/'SHA256SUMS').write_text(''.join(legacy.sha256(p)+'  '+p.name+'\n' for p in sorted(self.assets.iterdir()) if p.name!='SHA256SUMS'),encoding='ascii')
 def build(self):return release.build(self.project,self.commit,self.assets,self.spec,'2026-10-18T00:00:00Z')
 def test_actual_tree_four_deliverables_and_unchanged_legacy_four_artifact_schema(self):
  files=self.build();old=legacy.parse_manifest(files['AEGIS-6.0.0-stable.UNSIGNED.json'],'5.0.0');self.assertEqual(4,len(old['artifacts']));self.assertEqual('v6.0.0',old['tag']);ecosystem=json.loads(files['AEGIS-6.0.0-ecosystem.UNSIGNED.json']);self.assertFalse(ecosystem['productionReady']);self.assertEqual(self.commit,ecosystem['sourceCommit']);self.assertEqual({'debian13-server','windows11-x64','cachyos-kde-x86_64','android13-arm64'},{x['deliverable'] for x in ecosystem['artifacts'] if x['deliverable'] is not None});self.assertEqual(10,len(ecosystem['artifacts']));self.assertTrue(all(x['sourceCommit']==self.commit for x in ecosystem['artifacts']))
 def test_changed_binary_missing_apk_and_wrong_provenance_are_rejected(self):
  name=release.ROLES['android-core'];original=(self.assets/name).read_bytes();(self.assets/name).write_bytes(original+b'x')
  with self.assertRaisesRegex(ValueError,'Checksum'):self.build()
  (self.assets/name).write_bytes(original);(self.assets/name).unlink();self.write_provenance();self.sums()
  with self.assertRaisesRegex(ValueError,'missing'):self.build()
  (self.assets/name).write_bytes(original);self.write_provenance('0'*40);self.sums()
  with self.assertRaisesRegex(ValueError,'another source'):self.build()
 def test_changed_source_zip_cannot_be_legitimized_by_rehashing_provenance(self):
  path=self.assets/release.ROLES['client-source'];members={}
  with zipfile.ZipFile(path) as z:
   for info in z.infolist():members[info.filename]=(info,z.read(info))
  member='aegis/Main.java';info,data=members[member];members[member]=(info,data.replace(b'source',b'tamper'))
  with zipfile.ZipFile(path,'w') as z:
   for info,data in members.values():z.writestr(info,data)
  self.write_provenance();self.sums()
  with self.assertRaisesRegex(ValueError,'Source ZIP'):self.build()
 def test_dirty_source_wrong_commit_duplicate_role_and_private_data_fail_closed(self):
  (self.project/'Main.java').write_text('// dirty\n')
  with self.assertRaisesRegex(ValueError,'clean HEAD'):self.build()
  self.git('checkout','--','aegis/Main.java');spec=json.loads(self.spec.read_text());spec['artifacts'][-1]=spec['artifacts'][0];self.spec.write_text(json.dumps(spec))
  with self.assertRaisesRegex(ValueError,'role/name'):self.build()
 def test_unsigned_outputs_are_atomic_new_directory_only_and_never_change_feed(self):
  files=self.build();before={p.name:p.read_bytes() for p in self.assets.iterdir()};out=self.root/'owner-offline';result=release.write_outputs(out,files);self.assertEqual(set(files),set(result));self.assertEqual([],list(out.glob('*.sig')));self.assertFalse((self.assets/'updates').exists());self.assertEqual(before,{p.name:p.read_bytes() for p in self.assets.iterdir()})
  with self.assertRaises(ValueError):release.write_outputs(out,files)
  with self.assertRaises(ValueError):release.write_outputs(self.root/'unsafe',{'stable.json':b'{}'})
 def test_public_private_key_file_is_not_accepted_as_auxiliary_asset(self):
  (self.assets/'release-private.pem').write_text('fixture marker, not a key');self.sums()
  with self.assertRaisesRegex(ValueError,'Private data'):self.build()
 def test_proof_must_bind_each_actual_file_not_only_commit(self):
  p=json.loads((self.assets/self.proof).read_text());p['binaryArtifactSha256'][release.ROLES['windows-portable']]='0'*64;(self.assets/self.proof).write_text(json.dumps(p));self.sums()
  with self.assertRaisesRegex(ValueError,'exact artifact bytes'):self.build()
 def test_owner_final_public_mode_requires_all_four_verified_exact_signed_apks_without_auto_ready(self):
  # Metadata integration fixture only; real official apksigner/tamper execution lives in test_apk_public_verify600.
  spec=json.loads(self.spec.read_text());hashes=json.loads((self.assets/self.proof).read_text())['binaryArtifactSha256']
  for item in spec['artifacts']:
   if item['role'] in release.FINAL_ANDROID:
    original=self.assets/item['fileName'];item['fileName']=release.FINAL_ANDROID[item['role']];renamed=self.assets/item['fileName'];original.rename(renamed);hashes[renamed.name]=legacy.sha256(renamed)
  (self.assets/self.proof).write_text(json.dumps({'sourceCommit':self.commit,'binaryArtifactSha256':hashes}));self.spec.write_text(json.dumps(spec));self.sums()
  with self.assertRaises(ValueError):self.build()
  with self.assertRaises(ValueError):release.build(self.project,self.commit,self.assets,self.spec,apksigner=self.root/'tool')
  def checked(tool,path,pin):return {'certificateSha256':pin,'apkSha256':legacy.sha256(path),'signerCount':1,'schemes':{'v2':False,'v3':True,'v3.1':False},'stdoutSha256':'a'*64,'bytes':path.stat().st_size}
  with patch('apk_public_verify600.verify',side_effect=checked) as verify:
   out=release.build(self.project,self.commit,self.assets,self.spec,apksigner=self.root/'tool',expected_apk_certificate='b'*64)
  result=json.loads(out['AEGIS-6.0.0-ecosystem.UNSIGNED.json']);self.assertEqual(4,verify.call_count);self.assertFalse(result['productionReady']);self.assertFalse(result['productionSignatureGenerated']);self.assertTrue(all(x['apkSigning']=='owner-certificate-publicly-verified' for x in result['artifacts'] if x['role'].startswith('android-')))
 def test_owner_final_mode_fails_when_any_apk_verification_fails(self):
  # Even a trusted verifier rejecting a single package aborts the complete manifest generation.
  spec=json.loads(self.spec.read_text());proof=json.loads((self.assets/self.proof).read_text())
  for item in spec['artifacts']:
   if item['role'] in release.FINAL_ANDROID:
    old=self.assets/item['fileName'];item['fileName']=release.FINAL_ANDROID[item['role']];old.rename(self.assets/item['fileName']);proof['binaryArtifactSha256'][item['fileName']]=legacy.sha256(self.assets/item['fileName'])
  self.spec.write_text(json.dumps(spec));(self.assets/self.proof).write_text(json.dumps(proof));self.sums()
  with patch('apk_public_verify600.verify',side_effect=ValueError('Invalid actual signature')):
   with self.assertRaisesRegex(ValueError,'signature'):release.build(self.project,self.commit,self.assets,self.spec,apksigner=self.root/'tool',expected_apk_certificate='b'*64)
 def test_offline_public_inventory_verifier_checks_hashes_after_signature_gate(self):
  # Signature verifier seam exercises metadata policy, never claims an owner signature.
  manifest=self.root/'ecosystem.UNSIGNED.json';manifest.write_bytes(self.build()['AEGIS-6.0.0-ecosystem.UNSIGNED.json']);signature=self.root/'fixture.sig';signature.write_bytes(bytes(64))
  with patch('release_manifest600.legacy.verify_signature') as verifier:
   result=release.verify_signed_inventory(manifest,signature,self.assets);self.assertEqual(self.commit,result['sourceCommit']);verifier.assert_called_once()
   (self.assets/release.ROLES['windows-portable']).write_bytes(b'changed')
   with self.assertRaisesRegex(ValueError,'Checksum'):release.verify_signed_inventory(manifest,signature,self.assets)
 def test_offline_signature_failure_precedes_untrusted_json_parsing(self):
  manifest=self.root/'bad.json';manifest.write_bytes(b'not json');signature=self.root/'bad.sig';signature.write_bytes(bytes(64))
  with self.assertRaisesRegex(ValueError,'signature'):release.verify_signed_inventory(manifest,signature,self.assets)
 def test_offline_public_verifier_rejects_readiness_or_wrong_inventory_binding(self):
  value=json.loads(self.build()['AEGIS-6.0.0-ecosystem.UNSIGNED.json']);signature=self.root/'fixture.sig';signature.write_bytes(bytes(64));manifest=self.root/'fixture.json'
  for change in ({'productionReady':True},{'sourceCommit':'0'*39},{'checksums':{'fileName':'SHA256SUMS','size':1,'sha256':'0'*64}}):
   changed={**value,**change};manifest.write_text(json.dumps(changed))
   with patch('release_manifest600.legacy.verify_signature'),self.assertRaises(ValueError):release.verify_signed_inventory(manifest,signature,self.assets)
 def test_source_archives_reject_overwrite_and_preserve_previous_files(self):
  old=(self.assets/release.ROLES['source']).read_bytes()
  with self.assertRaisesRegex(ValueError,'already exists'):release.prepare_source_archives(self.project,self.commit,self.assets)
  self.assertEqual(old,(self.assets/release.ROLES['source']).read_bytes())
if __name__=='__main__':unittest.main()
