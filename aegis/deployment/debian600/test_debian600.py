import hashlib, importlib.util, json, pathlib, sqlite3, sys, tempfile, unittest
from unittest.mock import patch
from test_validator_sandbox import trusted_synthetic_validator

ROOT=pathlib.Path(__file__).resolve().parent
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/(name+".py"));obj=importlib.util.module_from_spec(spec);sys.modules[name]=obj;spec.loader.exec_module(obj);return obj
staging=module("staging");backup=module("backup_restore");preflight=module("preflight");deploy=module("deploy");monitor=module("monitoring")

class Debian600Tests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.home=pathlib.Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def test_snapshot_is_consistent_sqlite_online_backup_with_encrypted_chunk_bytes(self):
        source=self.home/"source";source.mkdir();state=source/"identity";state.mkdir();db=sqlite3.connect(state/"state.sqlite");db.execute("PRAGMA journal_mode=WAL");db.execute("CREATE TABLE sample(x INTEGER)");db.execute("INSERT INTO sample VALUES(7)");db.commit()
        (source/"attachments").mkdir();(source/"attachments/0000.chunk").write_bytes(b"opaque-encrypted-bytes");(source/"backup-staging").mkdir();(source/"backup-staging/never-copy").write_text("excluded")
        target=self.home/"snapshot";result=backup.snapshot_tree(source,target,validator=trusted_synthetic_validator);self.assertEqual(2,backup.verify_tree(target));self.assertFalse((target/"backup-staging").exists());self.assertFalse((target/"identity/state.sqlite-wal").exists())
        with sqlite3.connect(target/"identity/state.sqlite") as copy:self.assertEqual([(7,)],copy.execute("SELECT x FROM sample").fetchall())
        self.assertEqual(0o600,(target/"identity/state.sqlite").stat().st_mode&0o777);self.assertEqual(0o700,target.stat().st_mode&0o777);db.close()
    def test_snapshot_prunes_its_own_staging_subtree_instead_of_recursive_copy(self):
        source=self.home/"state";source.mkdir();(source/"data").write_text("preserved");(source/"backup-staging").mkdir(mode=0o700);target=source/"backup-staging/new";backup.snapshot_tree(source,target);self.assertEqual(1,backup.verify_tree(target));self.assertFalse((target/"backup-staging").exists())
    def test_snapshot_rejects_symlink_tamper_and_owner_release_key_without_read(self):
        source=self.home/"state";source.mkdir();outside=self.home/"outside";outside.write_text("private");(source/"link").symlink_to(outside)
        with self.assertRaises(ValueError):backup.snapshot_tree(source,self.home/"bad")
        (source/"link").unlink();(source/"release-private.pem").write_text("not-a-real-key")
        with self.assertRaises(ValueError):backup.snapshot_tree(source,self.home/"bad2")
        (source/"release-private.pem").unlink();(source/"data").write_text("preserved");target=self.home/"ok";backup.snapshot_tree(source,target);(target/"data").write_text("tampered")
        with self.assertRaises(ValueError):backup.verify_tree(target)
    def test_restore_inventory_cannot_escape_root(self):
        target=self.home/"snapshot";target.mkdir();(target/"SNAPSHOT.json").write_text(json.dumps({"schema":1,"files":[{"path":"../outside","bytes":1,"sha256":"0"*64}]}))
        with self.assertRaises(ValueError):backup.verify_tree(target)
    def test_restore_budget_bounds_bytes_objects_and_symlinks(self):
        target=self.home/"restored";target.mkdir();(target/"part").write_bytes(b"0123456789")
        self.assertEqual((10,1),backup.check_restore_budget(target,max_bytes=10,minimum_free=0))
        with self.assertRaises(ValueError):backup.check_restore_budget(target,max_bytes=9,minimum_free=0)
        with self.assertRaises(ValueError):backup.check_restore_budget(target,max_objects=0,minimum_free=0)
        (target/"link").symlink_to(self.home)
        with self.assertRaises(ValueError):backup.check_restore_budget(target,minimum_free=0)
    def test_restore_process_is_stopped_at_deadline_or_oversized_output_tree(self):
        with self.assertRaises(TimeoutError):backup.command([sys.executable,"-c","import time;time.sleep(30)"],timeout=0.1)
        target=self.home/"restore";target.mkdir();(target/"link").symlink_to(self.home)
        with self.assertRaises(ValueError):backup.command([sys.executable,"-c","import time;time.sleep(30)"],restore_root=target)
    def test_backup_config_requires_offsite_and_owner_only_credential_files(self):
        repository=self.home/"repository";repository.write_text("/same-vps-backup");repository.chmod(0o600);password=self.home/"password";password.write_text("synthetic-test-value");password.chmod(0o600);config=self.home/"backup.json";config.write_text(json.dumps({"repositoryFile":str(repository),"passwordFile":str(password),"offsiteConfirmed":True}));config.chmod(0o600)
        with self.assertRaises(ValueError):backup.load_config(config)
        repository.write_text("rest:https://backup.example.test/repo");self.assertEqual((repository,password),backup.load_config(config));password.chmod(0o644)
        with self.assertRaises(ValueError):backup.load_config(config)
        password.chmod(0o600)
        from unittest.mock import patch
        with patch.object(backup.os,'geteuid',return_value=config.stat().st_uid+1):
            with self.assertRaises(ValueError):backup.load_config(config)
    def test_units_preserve_nnp_and_distinct_management_runtime_and_legacy_relay(self):
        for component,spec in staging.COMPONENTS.items():
            unit=staging.unit(component,spec);self.assertIn("NoNewPrivileges=true",unit);self.assertIn("ProtectSystem=strict",unit);self.assertIn("CapabilityBoundingSet=\n",unit);self.assertNotIn("/opt/aegis/relay",unit);self.assertNotIn("After=network.target aegis600-staging-identity.service",unit if component=="identity" else "")
        self.assertIn("RuntimeDirectory=aegis600-management-agent",staging.unit("management",staging.COMPONENTS["management"]));self.assertNotIn("LIBRARY_SYNC",staging.COMPONENTS)
    def test_staging_refuses_existing_root_and_symlink_destination(self):
        with self.assertRaises(ValueError):staging.safe_root(pathlib.Path("/"))
        real=self.home/"real";real.mkdir();link=self.home/"alias";link.symlink_to(real,target_is_directory=True)
        with self.assertRaises(ValueError):staging.safe_root(link)
    def test_runtime_dependency_ambiguity_and_missing_files_are_rejected(self):
        first=self.home/"a";second=self.home/"b";first.mkdir();second.mkdir()
        for name in staging.DEPENDENCIES:(first/name).write_bytes(b"same")
        with patch.object(staging,'dependency_pins',return_value={name:{hashlib.sha256(b"same").hexdigest()} for name in staging.DEPENDENCIES}):
            self.assertEqual(6,len(staging.dependency_files([first])));(second/staging.DEPENDENCIES[0]).write_bytes(b"other")
            with self.assertRaises(ValueError):staging.dependency_files([first,second])
            target=first/staging.DEPENDENCIES[1];target.unlink();target.symlink_to(first/staging.DEPENDENCIES[0])
            with self.assertRaises(ValueError):staging.dependency_files([first])
        with self.assertRaises(ValueError):staging.dependency_files([second])
    def test_server_build_proof_binds_clean_frozen_commit_and_all_eight_jars(self):
        commit='a'*40;proof=self.home/'build.json';jars=self.home/'jars';jars.mkdir();rows=[]
        for name,version in staging.PROJECT_VERSIONS.items():
            blob=('synthetic-jar-receipt-'+name).encode();(jars/(name+'.jar')).write_bytes(blob);rows.append({'file':name+'-'+version+'.jar','sha256':hashlib.sha256(blob).hexdigest(),'zipCRC':'PASS'})
        receipt={'sourceCommit':commit,'gradleExitCode':0,'sourceUnchanged':True,'sourceDirtyAtStart':False,'jars':rows};proof.write_text(json.dumps(receipt))
        self.assertEqual(8,len(staging.checked_build_proof(proof,commit,jars)))
        for field,value in [('sourceCommit','b'*40),('gradleExitCode',1),('sourceUnchanged',False),('sourceDirtyAtStart',True)]:
            invalid=dict(receipt);invalid[field]=value;proof.write_text(json.dumps(invalid))
            with self.assertRaises(ValueError):staging.checked_build_proof(proof,commit,jars)
        proof.write_text(json.dumps(receipt));(jars/'community-server.jar').write_bytes(b'tamper')
        with self.assertRaises(ValueError):staging.checked_build_proof(proof,commit,jars)
        with self.assertRaises(ValueError):staging.checked_build_proof(None,commit,jars)
    def test_six_worker_launcher_never_connects_to_legacy_coordinator(self):
        source=(ROOT/'start-news-worker.py').read_text();self.assertIn('/agent-worker/v6',source);self.assertIn('"--coordinator-mode","service6"',source);self.assertNotIn('/api/v1',source)
    def test_community_staging_uses_identity_gated_six_entrypoint(self):
        launch=staging.launcher('community',staging.COMPONENTS['community'])
        self.assertIn('org.securemail.community.gateway600.CommunityMain600',launch)
        self.assertNotIn('org.securemail.community.CommunityMain ',launch)
        self.assertIn('--serve /var/lib/aegis600/community/state',staging.unit('community',staging.COMPONENTS['community']))
        self.assertNotIn('--port',staging.COMPONENTS['community']['args'])
    def test_backup_and_preflight_never_claim_native_or_offsite_restore_by_default(self):
        result=preflight.collect();self.assertFalse(result["productionReady"]);self.assertEqual("NOT_RUN",result["offsiteRestore"]);self.assertEqual("NOT_RUN",result["nativeServiceAcceptance"])
    def test_deploy_rejects_manifest_traversal_and_privileged_file_mode_before_writes(self):
        bundle=self.home/"bundle";bundle.mkdir();(bundle/"BUILD-PROVENANCE-6.0.0.json").write_text(json.dumps({"sourceCommit":"a"*40,"workingTreeDirty":False,"files":{"opt/aegis600/../../../escape":{"size":1,"sha256":"0"*64,"mode":"0o644"}}}))
        with self.assertRaises(ValueError):deploy.plan(bundle)
        path=bundle/"opt/aegis600/synthetic";path.parent.mkdir(parents=True);path.write_bytes(b"x");(bundle/"BUILD-PROVENANCE-6.0.0.json").write_text(json.dumps({"sourceCommit":"a"*40,"workingTreeDirty":False,"files":{"opt/aegis600/synthetic":{"size":1,"sha256":hashlib.sha256(b"x").hexdigest(),"mode":"0o4755"}}}))
        with self.assertRaises(ValueError):deploy.plan(bundle)
    def test_monitoring_drops_environment_and_unexpected_systemd_values(self):
        result=monitor.parse_properties('ActiveState=active\nSubState=running\nEnvironment=SECRET_VALUE\nMemoryCurrent=123\nTasksCurrent=untrusted/path\nCPUUsageNSec=999\n')
        self.assertEqual({'ActiveState':'active','SubState':'running','MemoryCurrent':'123','CPUUsageNSec':'999'},result)
        with self.assertRaises(ValueError):monitor.parse_properties('x'*8193)
    def test_monitoring_atomic_private_snapshot_rejects_symlink_state(self):
        original=monitor.STATE
        try:
            target=self.home/'monitoring';target.mkdir(mode=0o700);monitor.STATE=target;monitor.publish({'scope':'synthetic-status-only','productionReady':False});self.assertEqual(0o600,(target/'health.json').stat().st_mode&0o777);self.assertFalse(json.loads((target/'health.json').read_text())['productionReady'])
            alias=self.home/'alias-monitor';alias.symlink_to(target,target_is_directory=True);monitor.STATE=alias
            with self.assertRaises(ValueError):monitor.publish({})
        finally:monitor.STATE=original
    def test_privileged_root_helper_never_imports_sqlite_and_copies_malformed_db_opaque(self):
        import ast
        tree=ast.parse((ROOT/'backup_restore.py').read_text());names=[alias.name for node in ast.walk(tree) if isinstance(node,ast.Import) for alias in node.names]
        self.assertNotIn('sqlite3',names)
        source=self.home/'opaque';source.mkdir();(source/'malformed.db').write_bytes(b'not-a-database-untrusted-bytes');target=self.home/'opaque-copy';backup.opaque_snapshot_tree(source,target)
        self.assertEqual(b'not-a-database-untrusted-bytes',(target/'malformed.db').read_bytes())
    def test_validator_transient_plan_has_no_root_network_or_other_state_mount(self):
        job=self.home/'sqlite-validator-fixture';job.mkdir(mode=0o755);args=backup.validator_command(job)
        for prop in ['DynamicUser=yes','NoNewPrivileges=yes','PrivateNetwork=yes','ProtectSystem=strict','CapabilityBoundingSet=','SystemCallFilter=~@network-io @privileged @mount @debug','KillMode=control-group']:
            self.assertIn('--property='+prop,args)
        self.assertEqual(['/usr/bin/python3','-I','-B','/validator.py'],args[-4:]);self.assertNotIn('--property=User=root',args)
        self.assertNotIn('/etc/aegis600/backup-password',' '.join(args))
        with self.assertRaises(RuntimeError):backup.run_systemd_validator(job)
    def test_backup_restarts_every_writer_before_parser_and_cleans_failed_snapshot(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        state=self.home/'state';state.mkdir();(state/'opaque.db').write_bytes(b'untrusted-do-not-parse-as-root');events=[]
        def record(argv,**kwargs):events.append(argv)
        def denied(target,source_bytes):
            self.assertEqual(len(backup.SERVICES),len([e for e in events if e[1]=='start']))
            self.assertIn('/usr/bin/systemctl',events[-1]);self.assertEqual('start',events[-1][1])
            raise RuntimeError('synthetic sandbox unavailable')
        with patch.object(backup,'STATE',state),patch.object(backup,'load_config',return_value=(self.home/'repository',self.home/'password')),patch.object(backup.subprocess,'run',return_value=SimpleNamespace(returncode=0)),patch.object(backup,'command',side_effect=record),patch.object(backup,'finalize_snapshot',side_effect=denied):
            with self.assertRaises(RuntimeError):backup.backup()
        stopped=[e[-1] for e in events if e[1]=='stop'];started=[e[-1] for e in events if e[1]=='start']
        self.assertEqual(list(reversed(stopped)),started);self.assertIn('aegis600-staging-management-broker.service',stopped);self.assertIn('aegis600-staging-tor.service',stopped)
        self.assertEqual([],list((state/'backup-staging').iterdir()))
if __name__=="__main__":unittest.main()
