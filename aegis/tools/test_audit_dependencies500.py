import importlib.util
import json
import pathlib
import tempfile
import unittest
import zipfile

spec=importlib.util.spec_from_file_location('audit500',pathlib.Path(__file__).with_name('audit-dependencies500.py'))
audit500=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit500)

class DependencyAuditTests(unittest.TestCase):
 def test_matching_embedded_pom_and_actual_hash_are_used(self):
  with tempfile.TemporaryDirectory() as folder:
   jar=pathlib.Path(folder)/'gson-2.14.0.jar'
   with zipfile.ZipFile(jar,'w') as z:z.writestr('META-INF/maven/com.google.code.gson/gson/pom.properties','groupId=com.google.code.gson\nartifactId=gson\nversion=2.14.0\n')
   self.assertEqual(('com.google.code.gson','gson','2.14.0','pom.properties'),audit500.coordinates(jar))
   self.assertEqual(64,len(audit500.sha(jar)))
 def test_classifiers_and_test_only_exclusions_are_explicit(self):
  with tempfile.TemporaryDirectory() as folder:
   jar=pathlib.Path(folder)/'javafx-controls-21.0.12-linux.jar'
   with zipfile.ZipFile(jar,'w'):pass
   self.assertEqual(('org.openjfx','javafx-controls','21.0.12','known-artifact-filename'),audit500.coordinates(jar))
   self.assertIsNone(audit500.coordinates(pathlib.Path(folder)/'junit-platform-console-standalone-1.13.4.jar'))
 def test_network_failure_cannot_be_reported_as_no_vulnerabilities(self):
  with tempfile.TemporaryDirectory() as folder:
   root=pathlib.Path(folder);jars=root/'jars';jars.mkdir();jar=jars/'gson-2.14.0.jar'
   with zipfile.ZipFile(jar,'w'):pass
   original=audit500.fetch
   try:
    def failed(*args):raise TimeoutError('Fixture timeout')
    audit500.fetch=failed
    result=audit500.audit(root,[jars],root/'out')
   finally:audit500.fetch=original
   self.assertEqual('PARTIAL',result['status']);self.assertEqual('NOT_RUN',result['queries'][0]['status']);self.assertEqual(1,result['notRunCount']);self.assertFalse(result['productionReady'])
 def test_high_critical_match_blocks_and_unknown_severity_stays_unknown(self):
  self.assertEqual('UNKNOWN',audit500.severity({'severity':[{'type':'CVSS_V3','score':'CVSS:3.1/AV:N/AC:L'}]}))
  self.assertEqual('HIGH',audit500.severity({'database_specific':{'severity':'HIGH'}}))
  with tempfile.TemporaryDirectory() as folder:
   root=pathlib.Path(folder);jars=root/'jars';jars.mkdir()
   with zipfile.ZipFile(jars/'gson-2.14.0.jar','w'):pass
   original=audit500.fetch
   try:
    audit500.fetch=lambda *args:json.dumps({'vulns':[{'id':'FIXTURE-HIGH','summary':'Synthetic test finding','database_specific':{'severity':'HIGH'}}]}).encode()
    result=audit500.audit(root,[jars],root/'out')
   finally:audit500.fetch=original
   self.assertEqual('BLOCKED_HIGH_CRITICAL',result['status']);self.assertEqual(['FIXTURE-HIGH'],result['blockingAdvisories'])

if __name__=='__main__':unittest.main()
