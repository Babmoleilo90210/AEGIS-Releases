"""Bounded packaging policy fixtures only; no native execution, signing or installation."""
import importlib.util,json,pathlib,tempfile,unittest,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('native500',ROOT/'tools/package-native500.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)

class Native500PackagingTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=pathlib.Path(self.temp.name)
 def metadata(self):return {'version':'5.0.0','sourceCommit':'a'*40,'sourceTree':'b'*40,'baseCommit':'c'*40}
 def test_source_identity_requires_exact_500_frozen_commit_tree_and_base(self):
  p=self.path/'SOURCE-COMMIT-5.0.0.json';p.write_text(json.dumps(self.metadata()));self.assertEqual(self.metadata(),native.source_identity(self.path))
  for key,value in [('version','2.5.0'),('sourceCommit',''),('sourceTree','../source'),('baseCommit','ABC')]:
   m=self.metadata();m[key]=value;p.write_text(json.dumps(m))
   with self.assertRaises(ValueError):native.source_identity(self.path)
 def test_mixed_or_server_jars_cannot_enter_client_test_input(self):
  app=self.path/'AEGIS';folder=app/'app';folder.mkdir(parents=True)
  for n in native.APPLICATION_JARS:(folder/n).write_bytes(b'policy fixture only')
  native.check_client(app)
  for name in ('client-core-2.5.0.jar','community-server-5.0.0.jar','news-worker.jar','junit-test.jar','aegis-community-tests.jar'):
   p=folder/name;p.write_bytes(b'fixture')
   with self.assertRaises(ValueError):native.check_client(app)
   p.unlink()
 def test_all_manual_results_start_not_run_and_never_promote_readiness(self):
  m=native.statuses(self.metadata());self.assertFalse(m['productionReady']);self.assertFalse(m['confirmedByOwner']);self.assertEqual(list(native.PLATFORMS),[p['id']for p in m['platforms']]);self.assertEqual([20,20,20],[len(p['checks'])for p in m['platforms']]);self.assertEqual((15,20,25),(len(m['twoPhysicalDevices']['checks']),len(m['migration']),len(m['updater'])))
  all_checks=sum([p['checks']for p in m['platforms']],[])+m['twoPhysicalDevices']['checks']+m['migration']+m['updater'];self.assertTrue(all(c['status']=='NOT_RUN'and not c['evidence']and c['checkedAtUtc']is None for c in all_checks));m['platforms'][0]['checks'][0]['status']='FAIL';self.assertEqual('NOT_RUN',m['platforms'][1]['checks'][0]['status'])
 def test_result_schema_limits_statuses_requires_evidence_for_pass_and_exact_platforms(self):
  schema=native.results_schema();self.assertIs(schema['properties']['productionReady']['const'],False);platform=schema['properties']['platforms'];self.assertEqual(3,len(platform['allOf']));item=platform['items']['properties']['checks']['items'];self.assertEqual(['PASS','FAIL','BLOCKED','NOT_RUN'],item['properties']['status']['enum']);self.assertEqual(1,item['allOf'][0]['then']['properties']['evidence']['minItems']);self.assertFalse(schema['additionalProperties'])
 def test_current_ui500_is_required_and_obsolete_categories_excluded(self):
  self.assertTrue({'Interface500Smoke.java','ArchiveMenu500Smoke.java','Community500FlowSmoke.java'}.issubset(native.REQUIRED_UI));self.assertTrue({'SettingsResponsive200Smoke.java','Interface200Smoke.java','Interface250RefinementSmoke.java'}.issubset(native.OBSOLETE_UI));self.assertTrue(set(native.REQUIRED_UI).isdisjoint(native.OBSOLETE_UI))
 def test_packager_helpers_reject_traversal_duplicates_and_links(self):
  helper=native.helper()
  for entries in ([('../escape',b'x',0)],[('same',b'a',0),('SAME',b'b',0)],[('link',b'/etc/passwd',0o120777<<16)]):
   z=self.path/'bad.zip'
   with zipfile.ZipFile(z,'w')as archive:
    for name,data,attr in entries:
     i=zipfile.ZipInfo(name);i.external_attr=attr;archive.writestr(i,data)
   with self.assertRaises(ValueError):helper.extract(z,self.path/'unpack')
  self.assertFalse((self.path/'escape').exists())
 def test_wrappers_route_current_classes_and_do_not_execute_legacy_category_checks(self):
  folder=ROOT/'packaging/native-kit500';text=(folder/'AppearanceNativeLauncher500.java').read_text();self.assertIn('Interface500Smoke.main',text);self.assertIn('ArchiveMenu500Smoke.main',text);self.assertNotIn('SettingsResponsive200Smoke.main',text);self.assertNotIn('Interface250RefinementSmoke.main',text)
  for filename in ('Run-Community-Windows.cmd','Run-Community-CachyOS.sh'):
   body=(folder/filename).read_text();self.assertIn('CommunityIntegration500Test',body);self.assertIn('JDK21',body)
 def test_owner_kit_copies_exact_source_tor_pins_and_bridge_configuration(self):
  target=self.path/'kit';target.mkdir();native.copy_wrappers(ROOT,target)
  for name in('tor-runtime-provenance-5.0.0.json','snowflake-bridges.txt'):
   self.assertEqual((ROOT/'packaging/native-kit500'/name).read_bytes(),(target/name).read_bytes())
 def test_community_dependencies_are_pinned_and_remain_separate_from_app(self):
  self.assertEqual(4,len(native.PINNED));self.assertTrue(all(len(d)==64 for d in native.PINNED.values()));self.assertIn('junit-platform-console-standalone-1.13.4.jar',native.PINNED)

if __name__=='__main__':unittest.main()
