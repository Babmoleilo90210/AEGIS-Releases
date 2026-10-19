from pathlib import Path
import subprocess,os,tempfile,fcntl,json,time,argparse
parser=argparse.ArgumentParser(description="Actual Linux native fcntl/Java FileChannel interoperability, not native desktop acceptance")
for name in ['launcher','java','classpath','out']:parser.add_argument('--'+name,required=True)
a=parser.parse_args();o=Path(a.out);o.mkdir(parents=True,exist_ok=True);java=Path(a.java);cp=a.classpath;wrapper=Path(a.launcher);results=[]
def child(cmd,env):return subprocess.Popen(list(map(str,cmd)),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,text=True)
def stop(p):
 if p.poll() is None:
  p.stdin.close()
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=5)
for case in ['native-shared','java-exclusive','native-bad-symlink']:
 with tempfile.TemporaryDirectory(prefix='aegis-lock-interop-') as d:
  root=Path(d);env=dict(os.environ);env['XDG_DATA_HOME']=str(root);guard=root/'aegis-runtime600-guard/installation.lock'
  if case=='native-shared':
   # Python child deliberately has not loaded Java; wrapper already holds fcntl read lock.
   p=child([wrapper,'/usr/bin/python3','-c','import sys;print("READY",flush=True);sys.stdin.read()'],env)
   try:
    assert p.stdout.readline().strip()=='READY';q=child([java,'-cp',cp,'org.securemail.client.maintenance600.RuntimeLeaseFixture600',guard,'exclusive'],env);assert q.stdout.readline().strip()=='BLOCKED';assert q.wait(timeout=5)==3
    q=child([java,'-cp',cp,'org.securemail.client.maintenance600.RuntimeLeaseFixture600',guard,'shared'],env);assert q.stdout.readline().strip()=='HELD';stop(q)
    with guard.open('r+b') as f:
     try:fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB);raise AssertionError('Native lock was dropped by another JVM close')
     except BlockingIOError:pass
   finally:stop(p)
   with guard.open('r+b') as f:fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  elif case=='java-exclusive':
   p=child([java,'-cp',cp,'org.securemail.client.maintenance600.RuntimeLeaseFixture600',guard,'exclusive'],env)
   try:
    assert p.stdout.readline().strip()=='HELD';q=child([wrapper,'/usr/bin/python3','-c','print("UNSAFE_CHILD_STARTED")'],env);stdout,stderr=q.communicate(timeout=5);assert q.returncode==1 and not stdout;assert 'заблокирован' in stderr
   finally:stop(p)
  else:
   outside=root/'outside';outside.mkdir();(root/'aegis-runtime600-guard').symlink_to(outside,target_is_directory=True)
   q=child([wrapper,'/usr/bin/python3','-c','print("UNSAFE_CHILD_STARTED")'],env);stdout,stderr=q.communicate(timeout=5);assert q.returncode==1 and not stdout and not list(outside.iterdir())
  results.append({'case':case,'result':'PASS'})
(o/'LINUX-GUARD-INTEROP.json').write_text(json.dumps({'tests':results,'scope':'Real compiled Linux parent fcntl guard, child JVM FileChannel interop and symlink rejection on this host. Native CachyOS/Windows installer acceptance NOT_RUN.'},indent=2)+'\n');print(json.dumps(results,indent=2))
