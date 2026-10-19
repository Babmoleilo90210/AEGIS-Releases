"""Security preflight contracts; no native installer acceptance claim."""
import importlib.util,json,tempfile,unittest
from pathlib import Path
import sys
PACKAGING=Path(__file__).resolve().parents[1];sys.path.insert(0,str(PACKAGING))
spec=importlib.util.spec_from_file_location('package600',PACKAGING/'package-clients600.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class Package600Test(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
 def proof(self,**changes):
  value={'command':['gradle','clean','test','assemble'],'gradleExitCode':0,'sourceUnchanged':True,'sourceDirtyAtStart':False,'sourceCommit':'a'*40,'jars':[{'file':'client-core/build/libs/client-core-6.0.0.jar','sha256':'b'*64,'zipCRC':'PASS'}]};value.update(changes);file=self.root/'proof.json';file.write_text(json.dumps(value));return file
 def test_clean_exact_build_proof_preserves_project_hash(self):self.assertEqual({'client-core-6.0.0.jar':'b'*64},p.checked_proof(self.proof(),'a'*40))
 def test_dirty_changed_failed_and_other_commit_proofs_rejected(self):
  for change in ({'sourceDirtyAtStart':True},{'sourceUnchanged':False},{'gradleExitCode':1},{'sourceCommit':'c'*40}):
   with self.subTest(change=change),self.assertRaises(ValueError):p.checked_proof(self.proof(**change),'a'*40)
 def test_partial_or_filtered_build_cannot_qualify_as_full_verification(self):
  for command in (['gradle','test','assemble'],['gradle','clean','test','assemble','--tests','*Smoke*'],['gradle','clean','test','assemble','-x','test'],['gradle','clean','test','assemble','--exclude-task=test'],['gradle','clean','test','assemble','--dry-run'],['gradle','clean','test','assemble','-m']):
   with self.subTest(command=command),self.assertRaisesRegex(ValueError,'unfiltered full root'):p.checked_proof(self.proof(command=command),'a'*40)
 def test_crc_failed_jar_is_never_accepted_as_built(self):self.assertEqual({},p.checked_proof(self.proof(jars=[{'file':'client-core/build/libs/client-core-6.0.0.jar','sha256':'b'*64,'zipCRC':'FAIL'}]),'a'*40))
 def test_runtime_target_classifier_and_no_test_or_server_jars(self):
  for platform,other in (('linux','win'),('win','linux')):
   names=p.runtime_names(platform);self.assertGreater(len(names),20);self.assertIn('client-ui-6.0.0.jar',names);self.assertIn('javafx-graphics-21.0.12-'+platform+'.jar',names);self.assertNotIn('javafx-graphics-21.0.12-'+other+'.jar',names);self.assertFalse(any(any(bad in n for bad in ('junit','monocle','identity-server','community-server','management-agent','attachment-service')) for n in names))
 def test_extra_classpath_file_is_rejected_before_contents_execute(self):
  stage=self.root/'app';stage.mkdir();(stage/'untrusted.jar').write_bytes(b'not a jar')
  with self.assertRaisesRegex(ValueError,'Runtime JAR set'):p.check_app(stage,'linux',{},p.dependency_pins())
 def test_tool_inventory_tracks_executable_permission_and_link_target(self):
  file=self.root/'compiler';file.write_bytes(b'fixture');file.chmod(0o644);first=p.tool_tree_digest(self.root);file.chmod(0o755);self.assertNotEqual(first,p.tool_tree_digest(self.root));link=self.root/'alias';link.symlink_to('compiler');second=p.tool_tree_digest(self.root);link.unlink();link.symlink_to('missing');self.assertNotEqual(second,p.tool_tree_digest(self.root))
 def test_windows_extraction_rejects_escaping_entry_before_writing(self):
  import zipfile
  archive=self.root/'input.zip';target=self.root/'extracted'
  with zipfile.ZipFile(archive,'w') as z:z.writestr('AEGIS/../escape','untrusted')
  with self.assertRaisesRegex(ValueError,'Unsafe native-base ZIP'):p.extract_windows_base(archive,target)
  self.assertFalse((self.root/'escape').exists())
if __name__=='__main__':unittest.main()
