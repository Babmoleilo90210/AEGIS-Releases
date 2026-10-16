import importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('positive500',pathlib.Path(__file__).with_name('osv-positive-control500.py'))
control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)
class PositiveControlTests(unittest.TestCase):
 def test_empty_or_unrelated_advisories_cannot_pass(self):
  for value in [{},{'vulns':[]},{'vulns':[{'id':'UNRELATED','aliases':['CVE-OTHER']}]}]:self.assertFalse(control.evaluate(value))
 def test_expected_alias_identifies_control_without_product_claim(self):
  self.assertTrue(control.evaluate({'vulns':[{'id':'SYNTHETIC-CONTROL','aliases':['CVE-2021-44228']}]}))
  self.assertEqual('org.apache.logging.log4j:log4j-core',control.QUERY['package']['name'])
if __name__=='__main__':unittest.main()
