"""Synthetic strict-archive/atomic replacement tests; no Tor network or native acceptance."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'packaging'))
import tor_runtime500 as runtime

class TorRuntime500Test(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.config=self.root/'packaging/native-kit500/snowflake-bridges.txt';self.config.parent.mkdir(parents=True);self.config.write_bytes(b'fixed fixture bridge')
  self.document=json.loads((ROOT/'packaging/native-kit500/tor-runtime-provenance-5.0.0.json').read_text())
  self.document['aegisConfiguration'].update(sha256=runtime.sha256(self.config),bytes=self.config.stat().st_size)
  self.archive=self.root/'official.tar.gz';self.signature=self.root/'official.tar.gz.asc';self.signature.write_bytes(b'exact fixture signature')
  self.registry=self.root/'registry.json';self.destination=self.root/'runtime';self.members=[('tor/tor',b'new verified executable','tor'),('tor/libssl.so.3',b'new exact library','libssl.so.3'),('docs/tor.txt',b'licence','licenses/tor.txt')]
  for key,value in [('ROOT',self.root),('REGISTRY',self.registry)]:
   p=patch.object(runtime,key,value);p.start();self.addCleanup(p.stop)
  self.bundle()
 def bundle(self,*,malicious=None):
  entries={}
  with tarfile.open(self.archive,'w:gz')as archive:
   for name,data,target in self.members:
    member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o755 if target=='tor' else 0o644;archive.addfile(member,io.BytesIO(data));entries[name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'runtimePath':target}
   if malicious:
    name,kind=malicious;member=tarfile.TarInfo(name);member.type=tarfile.SYMTYPE if kind=='link' else tarfile.REGTYPE;member.linkname='/private';archive.addfile(member,io.BytesIO(b''));entries[name]={'sha256':hashlib.sha256(b'').hexdigest(),'bytes':0,'runtimePath':name}
  self.document['platforms']['linux']={'archive':{'sha256':runtime.sha256(self.archive),'bytes':self.archive.stat().st_size},'signature':{'sha256':runtime.sha256(self.signature),'bytes':self.signature.stat().st_size},'members':entries}
  self.registry.write_text(json.dumps(self.document))
 def stage(self):return runtime.stage_runtime(self.archive,self.signature,'linux',self.destination)
 def test_whole_runtime_replaces_old_libraries_and_preserves_only_pinned_config(self):
  self.destination.mkdir();(self.destination/'old-libssl.so').write_bytes(b'stale');(self.destination/'old-tor').write_bytes(b'stale')
  proof=self.stage();self.assertEqual('0.4.9.14',proof['torVersion']);self.assertFalse((self.destination/'old-libssl.so').exists());self.assertEqual(4,len(proof['runtimeFiles']));self.assertEqual(self.config.read_bytes(),(self.destination/'snowflake-bridges.txt').read_bytes());runtime.verify_runtime(self.destination,'linux')
 def test_modified_archive_or_signature_preserves_previous_runtime(self):
  self.destination.mkdir();(self.destination/'previous').write_bytes(b'preserved')
  for file in [self.archive,self.signature]:
   original=file.read_bytes();file.write_bytes(original+b'changed')
   with self.assertRaisesRegex(ValueError,'changed signature-verified'):self.stage()
   self.assertEqual(b'preserved',(self.destination/'previous').read_bytes());file.write_bytes(original)
 def test_traversal_and_symlink_are_rejected_even_with_fixture_archive_pin(self):
  for bad in [('../outside','file'),('tor/alias','link')]:
   self.bundle(malicious=bad)
   with self.assertRaisesRegex(ValueError,'Unsafe|link'):self.stage()
   self.assertFalse((self.root/'outside').exists())
 def test_missing_or_duplicate_archive_member_cannot_pass_reviewed_inventory(self):
  self.document['platforms']['linux']['members']['tor/missing']={'sha256':'0'*64,'bytes':1,'runtimePath':'missing'};self.registry.write_text(json.dumps(self.document))
  with self.assertRaisesRegex(ValueError,'Incomplete'):self.stage()
  self.members.append(self.members[0]);self.bundle()
  with self.assertRaisesRegex(ValueError,'duplicate'):self.stage()
 def test_installed_registry_sidecar_cannot_authorize_stale_or_mutated_runtime(self):
  self.stage();(self.destination/'libssl.so.3').write_bytes(b'mutated')
  with self.assertRaisesRegex(ValueError,'changed signature-verified'):runtime.verify_runtime(self.destination,'linux')
  self.stage();(self.destination/'legacy.dll').write_bytes(b'stale')
  with self.assertRaisesRegex(ValueError,'stale'):runtime.verify_runtime(self.destination,'linux')
 def test_unsigned_configuration_change_and_symlink_input_are_rejected(self):
  self.config.write_bytes(b'unreviewed bridge')
  with self.assertRaisesRegex(ValueError,'changed signature-verified'):self.stage()
  self.config.write_bytes(b'fixed fixture bridge');alias=self.root/'alias';alias.symlink_to(self.archive)
  with self.assertRaisesRegex(ValueError,'changed signature-verified'):runtime.stage_runtime(alias,self.signature,'linux',self.destination)
