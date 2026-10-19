"""Actual Linux setuid+chroot+libseccomp fixtures; NOT systemd/AppArmor native acceptance."""
import ctypes,importlib.util,json,os,pathlib,re,resource,shutil,sqlite3,subprocess,sys,tempfile,unittest

ROOT=pathlib.Path(__file__).resolve().parent
_RUNTIME=None

def kernel_caps_available():
    try:
        value=int(next(line.split()[1] for line in pathlib.Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:')),16)
        return os.geteuid()==0 and all(value&(1<<cap) for cap in (6,7,18))
    except (OSError,ValueError,StopIteration):return False

def trusted_synthetic_validator(job):
    """Actual SQLite API functional unit only. This deliberately does not assert process/native isolation."""
    spec=importlib.util.spec_from_file_location('sqlite_validator_functional_fixture',ROOT/'sqlite_validator.py');worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker);worker.consolidate(job/'input',job/'output')


def make_runtime(destination):
    global _RUNTIME
    if _RUNTIME is None:
        _RUNTIME=tempfile.TemporaryDirectory(prefix='aegis-validator-runtime-');base=pathlib.Path(_RUNTIME.name);version=subprocess.check_output(['/usr/bin/python3','-c','import sys;print(str(sys.version_info.major)+"."+str(sys.version_info.minor))'],text=True).strip();stdlib=pathlib.Path('/usr/lib/python'+version)
        (base/'usr/bin').mkdir(parents=True);shutil.copyfile(pathlib.Path('/usr/bin/python3').resolve(),base/'usr/bin/python3');(base/'usr/bin/python3').chmod(0o755);shutil.copytree(stdlib,base/str(stdlib).lstrip('/'),ignore=shutil.ignore_patterns('__pycache__','test','tests','ensurepip'))
        libraries=set()
        for binary in [pathlib.Path('/usr/bin/python3'),*stdlib.glob('lib-dynload/*.so')]:
            result=subprocess.run(['/usr/bin/ldd',str(binary)],capture_output=True,text=True,timeout=5)
            for name in re.findall(r'(/[^\s()]+)',result.stdout):
                path=pathlib.Path(name)
                if path.is_file():libraries.add(path)
        for library in libraries:
            target=base/str(library).lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(library.resolve(),target);target.chmod(0o755)
    base=pathlib.Path(_RUNTIME.name)
    for name in ['usr','lib','lib64']:
        if (base/name).exists():shutil.copytree(base/name,destination/name,dirs_exist_ok=True)
    shutil.copyfile(ROOT/'sqlite_validator.py',destination/'validator.py');(destination/'validator.py').chmod(0o444)

def fixture_validator(job, *, no_network=True, child_uid=65534, script='/validator.py'):
    if not kernel_caps_available() or not pathlib.Path('/lib/x86_64-linux-gnu/libseccomp.so.2').exists():raise unittest.SkipTest('Actual root setuid/chroot/seccomp fixture unavailable; native is NOT_RUN')
    make_runtime(job)
    seccomp=ctypes.CDLL('/lib/x86_64-linux-gnu/libseccomp.so.2',use_errno=True);seccomp.seccomp_init.argtypes=[ctypes.c_uint32];seccomp.seccomp_init.restype=ctypes.c_void_p;seccomp.seccomp_rule_add.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint];seccomp.seccomp_load.argtypes=[ctypes.c_void_p];seccomp.seccomp_release.argtypes=[ctypes.c_void_p];seccomp.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p];seccomp.seccomp_syscall_resolve_name.restype=ctypes.c_int
    libc=ctypes.CDLL(None,use_errno=True)
    def restrict():
        os.chroot(job);os.chdir('/');os.setgroups([]);os.setgid(child_uid);os.setuid(child_uid)
        resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_NOFILE,(32,32));resource.setrlimit(resource.RLIMIT_FSIZE,(1024**3,1024**3));resource.setrlimit(resource.RLIMIT_CPU,(15,15));resource.setrlimit(resource.RLIMIT_AS,(192*1024**2,192*1024**2))
        if libc.prctl(38,1,0,0,0)!=0:os._exit(125)
        if no_network:
            context=seccomp.seccomp_init(0x7fff0000)
            if not context:os._exit(125)
            try:
                for name in ['socket','socketpair','connect','bind','listen','accept','accept4','sendto','sendmsg','recvfrom','recvmsg','recvmmsg','sendmmsg','setsockopt','getsockopt','shutdown','ptrace','mount','umount2','unshare','setns']:
                    number=seccomp.seccomp_syscall_resolve_name(name.encode())
                    if number>=0 and seccomp.seccomp_rule_add(context,0x00050000|1,number,0)!=0:os._exit(125)
                if seccomp.seccomp_load(context)!=0:os._exit(125)
            finally:seccomp.seccomp_release(context)
    process=subprocess.run(['/usr/bin/python3','-I','-B',script],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin','LANG':'C.UTF-8'},preexec_fn=restrict,timeout=25)
    if process.returncode:raise RuntimeError('Actual unprivileged validator failed: '+process.stderr.decode(errors='replace')[:300])
    return process.stdout.decode()

@unittest.skipUnless(kernel_caps_available(),"NOT_RUN: Work removes CAP_SYS_CHROOT/CAP_SETUID/CAP_SETGID; full native sandbox fixture unavailable")
class ValidatorSandboxTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='aegis-validator-tests-');self.home=pathlib.Path(self.temp.name);self.job=self.home/'job';self.job.mkdir(mode=0o755);(self.job/'input').mkdir(mode=0o700);(self.job/'output').mkdir(mode=0o777);(self.job/'output').chmod(0o777);(self.job/'AEGIS-SQLITE-VALIDATOR').write_text('AEGIS-PER-DATABASE-VALIDATOR/v1\n');(self.job/'AEGIS-SQLITE-VALIDATOR').chmod(0o444)
        database=self.job/'input/database.sqlite'
        with sqlite3.connect(database) as db:db.execute('CREATE TABLE sample(x INTEGER)');db.execute('INSERT INTO sample VALUES(7)')
        database.chmod(0o444);(self.job/'input').chmod(0o555)
    def tearDown(self):self.temp.cleanup()
    def test_real_drop_uid_chroot_seccomp_sqlite_backup(self):
        result=json.loads(fixture_validator(self.job));self.assertTrue(result['validated']);output=self.job/'output/validated.sqlite';self.assertEqual(65534,output.stat().st_uid)
        with sqlite3.connect(output) as db:self.assertEqual([(7,)],db.execute('SELECT x FROM sample').fetchall())
    def test_missing_socket_filter_and_root_uid_are_rejected_before_parsing(self):
        with self.assertRaises(RuntimeError):fixture_validator(self.job,no_network=False)
        with self.assertRaises(RuntimeError):fixture_validator(self.job,child_uid=0)
        self.assertFalse((self.job/'output/validated.sqlite').exists())
    def test_corrupt_or_symlinked_database_cannot_produce_validated_result(self):
        (self.job/'input/database.sqlite').chmod(0o644);(self.job/'input/database.sqlite').write_bytes(b'SQLite format 3\x00'+b'x'*1024)
        with self.assertRaises(RuntimeError):fixture_validator(self.job)
        self.assertFalse((self.job/'output/validated.sqlite').exists() and (self.job/'output/validated.sqlite').stat().st_size>0)
    def test_actual_sandbox_cannot_read_host_secret_or_modify_input_or_open_socket(self):
        secret=self.home/'outside-secret';secret.write_text('SYNTHETIC_NOT_A_REAL_KEY');secret.chmod(0o600)
        probe=self.job/'probe.py';probe.write_text('''import os,socket,resource,json\nassert os.geteuid()==65534\nassert not os.path.exists("'''+str(secret)+'''")\ntry:open('/input/database.sqlite','ab');raise AssertionError('input writable')\nexcept PermissionError:pass\nfor family in [socket.AF_INET,socket.AF_INET6,socket.AF_UNIX]:\n try:socket.socket(family,socket.SOCK_STREAM);raise AssertionError('socket allowed')\n except PermissionError:pass\nassert resource.getrlimit(resource.RLIMIT_AS)[0]==192*1024**2\nprint(json.dumps({'isolated':True}))\n''');probe.chmod(0o444)
        self.assertTrue(json.loads(fixture_validator(self.job,script='/probe.py'))['isolated']);self.assertEqual('SYNTHETIC_NOT_A_REAL_KEY',secret.read_text())


# These process checks require no extra capability. They do not stand in for native systemd/chroot acceptance.
def install_network_filter_only():
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(38,1,0,0,0)!=0:os._exit(125)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_AS,(192*1024**2,192*1024**2))
    library=ctypes.CDLL('/lib/x86_64-linux-gnu/libseccomp.so.2',use_errno=True);library.seccomp_init.argtypes=[ctypes.c_uint32];library.seccomp_init.restype=ctypes.c_void_p;library.seccomp_rule_add.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint];library.seccomp_load.argtypes=[ctypes.c_void_p];library.seccomp_release.argtypes=[ctypes.c_void_p];library.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p];library.seccomp_syscall_resolve_name.restype=ctypes.c_int
    context=library.seccomp_init(0x7fff0000)
    if not context:os._exit(125)
    try:
        for name in ('socket','socketpair','connect','bind','listen','accept','accept4','sendto','sendmsg','recvfrom','recvmsg','ptrace','mount','umount2','unshare','setns'):
            syscall=library.seccomp_syscall_resolve_name(name.encode())
            if syscall>=0 and library.seccomp_rule_add(context,0x00050001,syscall,0)!=0:os._exit(125)
        if library.seccomp_load(context)!=0:os._exit(125)
    finally:library.seccomp_release(context)

class ValidatorPortableProcessTests(unittest.TestCase):
    def test_actual_kernel_seccomp_denies_network_and_preserves_memory_limit(self):
        code="""import socket,resource,json
for family in (socket.AF_INET,socket.AF_INET6,socket.AF_UNIX):
 try:socket.socket(family,socket.SOCK_STREAM);raise AssertionError('socket permitted')
 except PermissionError:pass
assert resource.getrlimit(resource.RLIMIT_AS)[0]==192*1024**2
print(json.dumps({'networkSyscallsDenied':True,'scope':'actual-seccomp-process-only-not-chroot-systemd'}))
"""
        p=subprocess.run(['/usr/bin/python3','-I','-c',code],capture_output=True,text=True,preexec_fn=install_network_filter_only,timeout=10)
        if p.returncode==125:self.skipTest('NOT_RUN: seccomp filter setup unavailable')
        self.assertEqual(0,p.returncode,p.stderr);self.assertTrue(json.loads(p.stdout)['networkSyscallsDenied'])
    def test_real_worker_rejects_unsandboxed_root_process(self):
        p=subprocess.run(['/usr/bin/python3','-I','-B',str(ROOT/'sqlite_validator.py')],capture_output=True,text=True,timeout=10)
        self.assertNotEqual(0,p.returncode);self.assertNotIn('validated',p.stdout);self.assertNotIn('/workspace/',p.stderr)

if __name__=='__main__':unittest.main()
