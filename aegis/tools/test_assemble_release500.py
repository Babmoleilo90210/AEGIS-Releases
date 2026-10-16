"""Policy tests on temporary Git/ZIP fixtures. No real release assembly/signing/publication."""
import importlib.util,json,pathlib,subprocess,tempfile,unittest,zipfile,hashlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('assembly500',ROOT/'tools/assemble-release500.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

class Assemble500PolicyTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);self.repo=self.root/'repo';self.project=self.repo/'aegis';self.project.mkdir(parents=True);self.out=self.root/'artifacts';self.out.mkdir()
  self.git('init','-q');self.git('config','user.name','Assembly fixture');self.git('config','user.email','fixture@example.invalid');(self.repo/'README.md').write_text('Public repository file\n');(self.project/'build.gradle').write_text('Synthetic Gradle source fixture\n');(self.project/'empty-source.txt').write_bytes(b'');(self.project/'community-server').mkdir();(self.project/'community-server/README.md').write_text('Synthetic operator documentation\n');(self.repo/'.gitignore').write_text('*.vault\n*.log\n');self.git('add','.');self.git('commit','-qm','base fixture');base=self.git('rev-parse','HEAD').strip();e=self.project/'docs/test-results/5.0.0';(e/'source-audit').mkdir(parents=True);(e/'source-audit/RESULTS.json').write_text(json.dumps({'baseVersion':'2.5.0','baseCommit':base}));(e/'RESULTS.json').write_text('{"status":"NOT_RUN"}\n');self.evidence=e;self.git('add','-f','.');self.git('commit','-qm','frozen fixture');self.commit=self.git('rev-parse','HEAD').strip();self.frozen=a.Frozen(self.project,self.commit)
 def git(self,*args):return subprocess.check_output(['git','-C',str(self.repo),*args],text=True,stderr=subprocess.DEVNULL)
 def test_freeze_rejects_wrong_head_and_dirty_source(self):
  with self.assertRaises(ValueError):a.Frozen(self.project,'0'*40)
  (self.project/'build.gradle').write_text('dirty')
  with self.assertRaises(ValueError):a.Frozen(self.project,self.commit)
 def test_git_archives_are_exact_deterministic_and_exclude_ignored_private_store(self):
  (self.project/'private.vault').write_text('not a committed source')
  a.source_archives(self.frozen,self.out);first=(self.out/a.SOURCE_FILES[1]).read_bytes();a.source_archives(self.frozen,self.out);self.assertEqual(first,(self.out/a.SOURCE_FILES[1]).read_bytes())
  with zipfile.ZipFile(self.out/a.SOURCE_FILES[0])as z:self.assertIn('README.md',z.namelist());self.assertIn('aegis/community-server/README.md',z.namelist());self.assertFalse(any('private.vault'in n for n in z.namelist()))
  with zipfile.ZipFile(self.out/a.SOURCE_FILES[1])as z:self.assertNotIn('README.md',z.namelist());self.assertIn('aegis/community-server/README.md',z.namelist());self.assertEqual(self.frozen.identity,json.loads(z.read('SOURCE-COMMIT-5.0.0.json')))
 def test_modified_source_payload_cannot_pass_with_unchanged_commit_metadata(self):
  a.source_archives(self.frozen,self.out);path=self.out/a.SOURCE_FILES[1]
  with zipfile.ZipFile(path)as z:entries={i.filename:(z.read(i),i.external_attr)for i in z.infolist()}
  entries['aegis/build.gradle']=(b'changed despite same metadata',0o100644<<16)
  with zipfile.ZipFile(path,'w')as z:
   for name,(data,attr)in entries.items():i=zipfile.ZipInfo(name,self.frozen.zip_date);i.external_attr=attr;z.writestr(i,data)
  with self.assertRaisesRegex(ValueError,'payload|hash'):a.validate_source_archive(self.frozen,path,True)
 def test_evidence_whitelist_and_committed_bytes_are_enforced(self):
  self.assertGreater(a.evidence_archive(self.frozen,self.out,self.evidence),0);a.validate_evidence_archive(self.frozen,self.out/'AEGIS-5.0.0-evidence.zip')
  (self.evidence/'untracked.log').write_text('ignored untracked log')
  with self.assertRaisesRegex(ValueError,'Untracked'):a.evidence_archive(self.frozen,self.out,self.evidence)
  with self.assertRaises(ValueError):a.evidence_archive(self.frozen,self.out,self.root)
 def test_empty_actual_process_log_is_preserved_but_empty_report_is_rejected(self):
  log=self.evidence/'successful-compiler.log';log.write_bytes(b'');self.git('add','-f',str(log));self.git('commit','-qm','captured empty stdout')
  frozen=a.Frozen(self.project,self.git('rev-parse','HEAD').strip());a.evidence_archive(frozen,self.out,self.evidence)
  with zipfile.ZipFile(self.out/'AEGIS-5.0.0-evidence.zip') as z:self.assertEqual(b'',z.read('aegis/docs/test-results/5.0.0/successful-compiler.log'))
  for name in a.REQUIRED_DOCS:(self.out/name).write_text('Synthetic nonempty report fixture\n')
  (self.out/'NEWS-5.0.0.md').write_bytes(b'')
  with self.assertRaisesRegex(ValueError,'NEWS-5.0.0'):a.copy_docs(frozen,self.out,True)
 def test_only_exact_extensionless_sha256sums_is_public_evidence(self):
  self.assertTrue(a.evidence_name_allowed('nested/SHA256SUMS'));self.assertFalse(a.evidence_name_allowed('nested/sha256sums'));self.assertFalse(a.evidence_name_allowed('nested/SECRETS'))
  (self.evidence/'SHA256SUMS').write_text('0'*64+'  fixture.txt\n');self.git('add','-f','.');self.git('commit','-qm','public checksums fixture');frozen=a.Frozen(self.project,self.git('rev-parse','HEAD').strip())
  a.evidence_archive(frozen,self.out,self.evidence);target=self.out/'AEGIS-5.0.0-evidence.zip';a.validate_evidence_archive(frozen,target)
  with zipfile.ZipFile(target)as z:self.assertIn('aegis/docs/test-results/5.0.0/SHA256SUMS',z.namelist())
  (self.evidence/'OTHER').write_text('not permitted');self.git('add','-f','.');self.git('commit','-qm','rejected basename fixture');frozen=a.Frozen(self.project,self.git('rev-parse','HEAD').strip())
  with self.assertRaisesRegex(ValueError,'Non-whitelisted'):a.evidence_archive(frozen,self.out,self.evidence)
 def test_raw_http_private_keys_html_and_environment_dumps_are_rejected(self):
  samples=[('page.html',b'<html>'),('trace.log',b'POST /api/v1 HTTP/1.1\r\n'),('trace.log',b'AEGIS-Signature: sensitive\n'),('keys.txt',b'-----BEGIN PRIVATE KEY-----\n'),('pgp.txt',b'-----BEGIN PGP PRIVATE KEY BLOCK-----\n'),('env.log',b'PATH=/bin\n'),('log.txt',b'OPENAI_API_KEY=secret\n')]
  for name,data in samples:
   with self.subTest(name=name,data=data):
    with self.assertRaises(ValueError):a.public_text(name,data)
  a.public_text('RESULTS.json',b'{"machine":{"os":"Linux"},"status":"NOT_RUN"}')
 def test_signature_evidence_does_not_accept_private_pgp_keys(self):
  a.public_text('official.asc',b'-----BEGIN PGP SIGNATURE-----\n\npublic-signature\n-----END PGP SIGNATURE-----\n')
  for data in (b'-----BEGIN PGP PRIVATE KEY BLOCK-----\nsecret\n-----END PGP PRIVATE KEY BLOCK-----',b'arbitrary text'):
   with self.assertRaises(ValueError):a.public_text('secret.asc',data)
 def test_all_required_documents_must_be_real_nonempty_at_finalize(self):
  for name in a.REQUIRED_DOCS:(self.out/name).write_text('Existing owner-generated document\n')
  self.assertEqual([],a.copy_docs(self.frozen,self.out,True));(self.out/'NEWS-5.0.0.md').write_bytes(b'')
  with self.assertRaises(ValueError):a.copy_docs(self.frozen,self.out,True)
  (self.out/'NEWS-5.0.0.md').write_bytes(b'  \n')
  with self.assertRaises(ValueError):a.copy_docs(self.frozen,self.out,True)
 def test_flat_source_identity_cannot_be_spoofed_independently(self):
  for name in(*a.BINARY_FILES,*a.SOURCE_FILES,*a.EXTRA_PACKAGES,*a.REQUIRED_DOCS):(self.out/name).write_text('{}')
  wrong={**self.frozen.identity,'sourceTree':'0'*40};(self.out/'SOURCE-COMMIT-5.0.0.json').write_text(json.dumps(wrong))
  with self.assertRaisesRegex(ValueError,'Flat source identity'):a.validate_bindings(self.frozen,self.out)
 def test_provenance_commit_aliases_cannot_contradict_each_other(self):
  self.assertEqual(self.commit,a.binding({'source':{'implementationCommit':self.commit},'baseCommit':'0'*40}))
  for value in ({},{'sourceCommit':'x'},{'sourceCommit':self.commit,'implementationCommit':'0'*40}):
   with self.assertRaises(ValueError):a.binding(value)
 def test_flat_inventory_ignores_stage_private_files_and_hash_cycles(self):
  for name in ('README.md','SOURCE-COMMIT-5.0.0.json','SIGNING-HASHES-5.0.0.json','stable-5.0.0.UNSIGNED.json',a.OWNER_ZIP,'credentials-5.0.0.json'):(self.out/name).write_text('{}')
  (self.out/'stage').mkdir();(self.out/'stage/private.key').write_text('never include')
  self.assertEqual(['README.md','SOURCE-COMMIT-5.0.0.json'],[p.name for p in a.public_flat_files(self.out)])
 def test_final_test_proof_zip_is_explicitly_included_without_arbitrary_zip_exports(self):
  for name in('AEGIS-5.0.0-final-test-evidence.zip','private-final-results.zip'):
   with zipfile.ZipFile(self.out/name,'w')as z:z.writestr('scope.txt','Synthetic policy fixture, not a real test result.')
  self.assertEqual(['AEGIS-5.0.0-final-test-evidence.zip'],[p.name for p in a.public_flat_files(self.out)])
 def test_final_test_zip_checks_receipt_source_bytes_and_complete_checksum_inventory(self):
  files_sha={name:a.sha(self.repo/name)for name in self.frozen.entries};source_digest=hashlib.sha256((json.dumps(files_sha,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()).hexdigest()
  receipt={'schema':1,'version':'5.0.0',**self.frozen.identity,'kind':'SOURCE_BEFORE_FINAL_TESTS','sourceFilesSha256':files_sha,'sourceFilesDigest':source_digest}
  raw=json.dumps(receipt).encode();receipt_hash=hashlib.sha256(raw).hexdigest()
  shared={'schema':1,**self.frozen.identity,'testedSourceReceiptSha256':receipt_hash,'testedSourceFilesDigest':source_digest,'productionReady':False}
  final={**shared,'status':'UNSIGNED_OWNER_ACCEPTANCE_CANDIDATE'}
  members={'FINAL-VERIFICATION-5.0.0.json':json.dumps(final).encode(),'JUNIT-INVENTORY-5.0.0.json':json.dumps(shared).encode(),'TESTED-SOURCE-RECEIPT-5.0.0.json':raw,'requirements-matrix.json':json.dumps(shared).encode(),'RELEASE-GATES-5.0.0.json':json.dumps(shared).encode(),'TEST-REPORT-5.0.0.md':b'Synthetic proof policy fixture only','gradle/client-core/TEST-fixture.xml':b'<testsuite/>'}
  target=self.out/'AEGIS-5.0.0-final-test-evidence.zip'
  def write():
   with zipfile.ZipFile(target,'w')as z:
    for name,data in members.items():z.writestr(name,data)
    z.writestr('SHA256SUMS',''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n'for name,data in members.items()))
  write();self.assertEqual(final,a.validate_final_test_archive(self.frozen,target))
  receipt['sourceFilesSha256']['aegis/build.gradle']='0'*64;members['TESTED-SOURCE-RECEIPT-5.0.0.json']=json.dumps(receipt).encode();write()
  with self.assertRaisesRegex(ValueError,'receipt digest|source file'):a.validate_final_test_archive(self.frozen,target)
  members['private-token.txt']=b'secret';write()
  with self.assertRaisesRegex(ValueError,'Unexpected'):a.validate_final_test_archive(self.frozen,target)
 def test_complete_finalize_policy_fixture_preserves_false_and_generates_no_signature(self):
  # Synthetic byte payloads exercise hash/binding policy, never executable/native acceptance.
  import shutil
  (self.project/'tools').mkdir()
  for name in('generate-release-manifest.py','release_manifest.py'):shutil.copy2(ROOT/'tools'/name,self.project/'tools'/name)
  self.git('add','.');self.git('commit','-qm','generator fixture');self.commit=self.git('rev-parse','HEAD').strip();frozen=a.Frozen(self.project,self.commit)
  a.source_archives(frozen,self.out);a.evidence_archive(frozen,self.out,self.evidence)
  for name in a.REQUIRED_DOCS:(self.out/name).write_text('Synthetic policy fixture document; no acceptance claim.\n')
  for name in a.PROVENANCE_DOCS:(self.out/name).write_text(json.dumps({'sourceCommit':self.commit,'productionReady':False}))
  def zipped(name,member,document):
   with zipfile.ZipFile(self.out/name,'w')as z:z.writestr(member,json.dumps(document))
  (self.out/a.BINARY_FILES[0]).write_bytes(b'synthetic Setup hash-policy fixture only')
  (self.out/a.BINARY_FILES[2]).write_bytes(b'synthetic AppImage hash-policy fixture only')
  zipped(a.BINARY_FILES[1],'AEGIS/BUILD-INPUTS.json',{'clientVersion':'5.0.0','sourceCommit':self.commit})
  build={'sourceCommit':self.commit,'productionReady':False,'binaryArtifactSha256':{n:a.sha(self.out/n)for n in a.BINARY_FILES}};(self.out/'BUILD-PROVENANCE-5.0.0.json').write_text(json.dumps(build))
  for name in('AEGIS-5.0.0-community-server.zip','AEGIS-5.0.0-news-worker.zip'):zipped(name,'operator/SERVER-BUILD-PROVENANCE-5.0.0.json',{'sourceCommit':self.commit})
  zipped('AEGIS-5.0.0-native-acceptance.zip','native-acceptance/TESTED-ARTIFACTS.json',{'sourceCommit':self.commit,'sourceZipSha256':a.sha(self.out/a.SOURCE_FILES[1]),'windowsClientZipSha256':a.sha(self.out/a.BINARY_FILES[1])})
  bundle=a.finalize(frozen,self.out);self.assertTrue(bundle.is_file());manifest=json.loads((self.out/'stable-5.0.0.UNSIGNED.json').read_text());self.assertEqual('v5.0.0',manifest['tag']);self.assertFalse(json.loads((self.out/'FINAL-VERIFICATION-5.0.0.json').read_text())['productionReady']);self.assertFalse(list(self.out.glob('*.sig')))
  sums=(self.out/'SHA256SUMS').read_text();self.assertNotIn('UNSIGNED',sums);self.assertNotIn(a.OWNER_ZIP,sums);self.assertNotIn('SIGNING-HASHES',sums)
  with zipfile.ZipFile(bundle)as z:self.assertIn('SHA256SUMS',z.namelist());self.assertIn('stable-5.0.0.UNSIGNED.json',z.namelist());self.assertFalse(any('/stage/'in n for n in z.namelist()))
 def test_archive_member_paths_links_and_duplicate_provenance_are_rejected(self):
  for name in('../x','/x','C:/x','a\\x','x\nfile'):
   with self.assertRaises(ValueError):a.safe_relative(name)
  path=self.out/'bad.zip'
  with zipfile.ZipFile(path,'w')as z:z.writestr('a/TESTED-ARTIFACTS.json','{}');z.writestr('b/TESTED-ARTIFACTS.json','{}')
  with self.assertRaisesRegex(ValueError,'ambiguous'):a.zip_json(path,'TESTED-ARTIFACTS.json')
  with zipfile.ZipFile(path,'w')as z:i=zipfile.ZipInfo('link');i.external_attr=0o120777<<16;z.writestr(i,'/private')
  with self.assertRaises(ValueError):a.checked_zip(path)

if __name__=='__main__':unittest.main()
