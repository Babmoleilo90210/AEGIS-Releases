import importlib.util, pathlib, tempfile, unittest, zipfile, subprocess
from unittest.mock import patch
SPEC=importlib.util.spec_from_file_location('community_pack',pathlib.Path(__file__).with_name('package-community500.py'));MOD=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MOD)
class CommunityPackagingTests(unittest.TestCase):
 def test_frozen_git_paths_are_root_relative_from_nested_project(self):
  with tempfile.TemporaryDirectory() as t:
   repo=pathlib.Path(t);project=repo/'aegis';project.mkdir();source=project/'module/Example.java';source.parent.mkdir();source.write_text('class Example {}\n')
   subprocess.run(['git','-C',str(repo),'init','-q'],check=True)
   subprocess.run(['git','-C',str(repo),'add','.'],check=True)
   subprocess.run(['git','-C',str(repo),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture'],check=True)
   with patch.object(MOD,'ROOT',project):records=MOD.tracked_tree()
   self.assertIn('aegis/module/Example.java',records)
   self.assertNotIn('module/Example.java',records)
 def test_payload_compares_every_class_resource_and_rejects_added_class(self):
  with tempfile.TemporaryDirectory()as t:
   root=pathlib.Path(t);classes=root/'classes';classes.mkdir();(classes/'Example.class').write_bytes(b'actual compiled payload comparison fixture');jar=root/'app.jar'
   with zipfile.ZipFile(jar,'w')as z:z.writestr('Example.class',(classes/'Example.class').read_bytes());z.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\r\nCreated-By: 21.0.12 (Eclipse Adoptium)\r\n\r\n')
   self.assertEqual({'Example.class'},set(MOD.verify_payload(jar,classes,root/'resources')))
   with zipfile.ZipFile(jar,'a')as z:z.writestr('Unexpected.class',b'not in source compilation')
   with self.assertRaises(ValueError):MOD.verify_payload(jar,classes,root/'resources')
 def test_manifest_cannot_add_external_classpath_agent_or_native_privilege(self):
  with tempfile.TemporaryDirectory()as t:
   root=pathlib.Path(t)
   for line in ['Class-Path: /tmp/injected.jar','Premain-Class: Evil','Add-Opens: java.base/java.lang','Multi-Release: true']:
    jar=root/'app.jar'
    with zipfile.ZipFile(jar,'w')as z:z.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\r\n'+line+'\r\n\r\n')
    with self.assertRaises(ValueError):MOD.jar_payload(jar)
 def test_dependencies_fail_closed_on_wrong_hash(self):
  with tempfile.TemporaryDirectory()as t:
   folder=pathlib.Path(t)
   for name in MOD.PINNED:(folder/name).write_bytes(b'untrusted jar')
   with self.assertRaisesRegex(ValueError,'SHA-256'):MOD.dependency_inputs([folder])
 def test_unsafe_duplicate_and_symlink_payloads_rejected(self):
  with tempfile.TemporaryDirectory()as t:
   folder=pathlib.Path(t)
   for name in ['../escaped.class','C:/escaped.class','a\\b.class']:
    jar=folder/'bad.jar'
    with zipfile.ZipFile(jar,'w')as z:z.writestr(name,b'bad')
    with self.assertRaises(ValueError):MOD.jar_payload(jar)
   jar=folder/'link.jar'
   with zipfile.ZipFile(jar,'w')as z:
    info=zipfile.ZipInfo('link.class');info.create_system=3;info.external_attr=0o120777<<16;z.writestr(info,'/tmp/other')
   with self.assertRaises(ValueError):MOD.jar_payload(jar)
if __name__=='__main__':unittest.main()
