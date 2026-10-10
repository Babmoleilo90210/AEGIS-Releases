"""Bounded tests of exact CI packages. No signing/publication; public update feed is read only through embedded Tor."""
from pathlib import Path
import ctypes, hashlib, json, os, shutil, socket, subprocess, sys, time, zipfile

root=Path.cwd(); inputs=root/'candidates'; out=root/'validation-evidence';out.mkdir(exist_ok=True)
sha={}
for line in (inputs/'SHA256SUMS').read_text().splitlines():
 digest,name=line.split('  ',1)
 if name in {'AEGIS-1.1.5-Windows-x64.zip','AEGIS-Setup-1.1.5-x64.exe','AEGIS-1.1.5-CachyOS-x86_64.AppImage','AEGIS-1.1.5-client-source.zip'}:sha[name]=digest
assert len(sha)==4
for n,h in sha.items():
 with (inputs/n).open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==h,n
with zipfile.ZipFile(inputs/'AEGIS-1.1.5-client-source.zip') as z:
 assert z.testzip() is None
 for entry in z.infolist():
  p=Path(entry.filename);assert not p.is_absolute() and '..' not in p.parts
 z.extractall(root/'test-source')
source=root/'test-source/aegis';windows=sys.platform=='win32'
report={'productionReady':False,'nativeWindows11':'NOT_RUN','nativeCachyOSKDE':'NOT_RUN','artifactSourceCommit':os.environ.get('GITHUB_SHA','local'),'actualOS':os.name,'checks':[]}
def check(name,fn):
 start=time.monotonic()
 try:fn();result={'name':name,'result':'PASS'}
 except Exception as e:result={'name':name,'result':'FAIL_OR_UNAVAILABLE','errorType':type(e).__name__}
 result['elapsedSeconds']=round(time.monotonic()-start,2);report['checks'].append(result);print(json.dumps(result),flush=True)
def run(args,log,timeout=120,env=None,cwd=None):
 with (out/log).open('w',encoding='utf-8') as f:
  subprocess.run([str(x) for x in args],cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=timeout,check=True)
if windows:
 with zipfile.ZipFile(inputs/'AEGIS-1.1.5-Windows-x64.zip') as z:z.extractall(root/'portable with spaces')
 app=root/'portable with spaces/AEGIS';java=app/'runtime/bin/java.exe'
 report['WindowsVersion']=sys.getwindowsversion()._asdict() if hasattr(sys.getwindowsversion(),'_asdict') else str(sys.getwindowsversion())
 kit=root/'native-kit';kit.mkdir(exist_ok=True);classes=kit/'classes';classes.mkdir(exist_ok=True)
 natives=source/'client-core/src/test/java/org/securemail/client/security'
 main=(natives/'NativeAcceptanceMain.java').read_text()
 (kit/'NativeAcceptanceMain.java').write_text(main,encoding='utf-8')
 sources=[kit/'NativeAcceptanceMain.java',natives/'NativeCredentialStoreSmoke.java',source/'client-core/src/test/java/org/securemail/client/update/Bug11RealTorProbe.java',*sorted((source/'client-ui/src/smoke/java').glob('**/*.java'))]
 cp=str(app/'app/*');jdk=Path(os.environ['JAVA_HOME_21_X64'])
 run([jdk/'bin/javac.exe','--release','21','-encoding','UTF-8','-cp',cp,'-d',classes,*sources],'native-compile.log',90)
 run([jdk/'bin/jar.exe','--create','--file',kit/'aegis-native-tests.jar','-C',classes,'.'],'native-jar.log',30)
 shutil.copy2(kit/'aegis-native-tests.jar',kit/'aegis-ui-tests.jar')
 expected={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (app/'app').glob('*.jar') if p.name.startswith(('client-core-','client-ui-','common-protocol-'))}
 (kit/'TESTED-ARTIFACTS.json').write_text(json.dumps({'applicationJarSha256':expected}))
 env=dict(os.environ)
 for n in ['JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH']:env.pop(n,None)
 check('packaged_runtime_native_cryptography_DPAPI_and_JavaFX',lambda:run([java,'-Xmx768m','-cp',str(kit/'aegis-native-tests.jar')+';'+cp,'org.securemail.client.security.NativeAcceptanceMain',app,kit,'--gui'],'native-acceptance.log',600,env, out))
 def install():
  fixture=root/'installer-fixture';fixture.mkdir(exist_ok=True)
  local=dict(env);local['LOCALAPPDATA']=str(fixture)
  run([inputs/'AEGIS-Setup-1.1.5-x64.exe','/S','/D='+str(fixture/'Programs/AEGIS')],'installer.log',100,local)
  target=fixture/'Programs/AEGIS';(out/'installer-files.json').write_text(json.dumps({'target':str(target),'exists':target.exists(),'files':[str(p.relative_to(target)) for p in target.rglob('*') if p.is_file()]},indent=2));assert (target/'AEGIS.exe').is_file()
  for p in (app/'app').glob('*.jar'):
   assert hashlib.sha256(p.read_bytes()).digest()==hashlib.sha256((target/'app'/p.name).read_bytes()).digest()
 check('real_NSIS_silent_install_with_isolated_profile',install)
 def launch():
  fixture=root/'launcher fixture';fixture.mkdir(exist_ok=True)
  local=dict(env);local['LOCALAPPDATA']=str(fixture);local['PATH']=os.environ['SYSTEMROOT']+'\\System32'
  foreigndir=root/'foreign tor';foreigndir.mkdir(exist_ok=True);rc=foreigndir/'torrc';rc.write_text('')
  foreign=subprocess.Popen([str(app/'tor/tor.exe'),'--defaults-torrc',str(rc),'-f',str(rc),'--DataDirectory',str(foreigndir),'--SocksPort','0','--ControlPort','0','--DisableNetwork','1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  client=subprocess.Popen([str(app/'AEGIS.exe')],env=local,cwd=app)
  try:
   log=fixture/'AEGIS/logs/connection.log';end=time.monotonic()+50
   while time.monotonic()<end and client.poll() is None:
    if log.exists() and 'TOR_DIRECT_START' in log.read_text():break
    time.sleep(.2)
   assert client.poll() is None and log.exists() and 'TOR_DIRECT_START' in log.read_text()
   bindings=subprocess.check_output(['netstat','-ano','-p','tcp'],text=True)
   for port in [19050,19051,19052]:
    assert '127.0.0.1:'+str(port) in bindings
    assert '0.0.0.0:'+str(port) not in bindings
   from ctypes import wintypes as w
   user=ctypes.windll.user32;kernel=ctypes.windll.kernel32
   class Entry(ctypes.Structure):
    _fields_=[('dwSize',w.DWORD),('cntUsage',w.DWORD),('pid',w.DWORD),('heap',ctypes.c_size_t),('module',w.DWORD),('threads',w.DWORD),('ppid',w.DWORD),('priority',w.LONG),('flags',w.DWORD),('exe',w.WCHAR*260)]
   kernel.CreateToolhelp32Snapshot.restype=w.HANDLE
   snap=kernel.CreateToolhelp32Snapshot(2,0);e=Entry();e.dwSize=ctypes.sizeof(e);children=set()
   try:
    ok=kernel.Process32FirstW(snap,ctypes.byref(e))
    while ok:
     if e.ppid==client.pid:children.add(e.pid)
     ok=kernel.Process32NextW(snap,ctypes.byref(e))
   finally:kernel.CloseHandle(snap)
   assert children
   callback=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM);closed=[]
   @callback
   def visit(hwnd,param):
    pid=w.DWORD();user.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
    if pid.value in children and user.IsWindowVisible(hwnd):user.PostMessageW(hwnd,0x10,0,0);closed.append(pid.value)
    return True
   user.EnumWindows(visit,0);assert closed
   assert client.wait(timeout=25)==0
   assert foreign.poll() is None
   for port in [19050,19051,19052]:
    with socket.socket() as sock:sock.bind(('127.0.0.1',port))
  finally:
   if client.poll() is None:client.terminate();client.wait(timeout=15)
   if foreign.poll() is None:foreign.terminate();foreign.wait(timeout=10)
 check('real_AEGIS_EXE_no_global_Java_loopback_Tor_own_shutdown',launch)
else:
 appimage=root/'test.AppImage';shutil.copy2(inputs/'AEGIS-1.1.5-CachyOS-x86_64.AppImage',appimage);appimage.chmod(0o755)
 run([appimage,'--appimage-extract'],'appimage-extraction.log',60,cwd=root)
 app=root/'squashfs-root';java=app/'runtime/bin/java'
 classes=root/'probe-classes';classes.mkdir(exist_ok=True);jdk=Path(os.environ['JAVA_HOME_21_X64']);cp=str(app/'app/*')
 run([jdk/'bin/javac','--release','21','-cp',cp,'-d',classes,source/'client-core/src/test/java/org/securemail/client/update/Bug11RealTorProbe.java'],'probe-compile.log',60)
 env=dict(os.environ)
for n in ['JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH']:env.pop(n,None)
probe_cp=str(classes if not windows else kit/'classes')+os.pathsep+cp
check('BUG11_real_embedded_Tor_TLS_production_Ed25519_old_feed',lambda:run([java,'-cp',probe_cp,'org.securemail.client.update.Bug11RealTorProbe',app,out/'tor-after'],'real-tor-updater-after.log',510,env))
# Exact published 1.1.0 binaries, not recompilation, for compatibility and real updater transport.
import urllib.request
oldroot=root/'published-110';oldroot.mkdir(exist_ok=True)
if windows:
 name='AEGIS-1.1.0-Windows-x64.zip';digest='98c6665c0a5c4c6d779d3e8b832bb4ce64517eac8dcff2a1aa8d6905c13c422a'
else:
 name='AEGIS-1.1.0-CachyOS-x86_64.AppImage';digest='41269908cf47e1e91e3e0a61b1213fbd92263271aa3c3e209145abb68f8707d0'
oldfile=oldroot/name
with urllib.request.urlopen('https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.1.0/'+name,timeout=60) as response,oldfile.open('wb') as f:shutil.copyfileobj(response,f)
with oldfile.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==digest
if windows:
 with zipfile.ZipFile(oldfile) as z:z.extractall(oldroot)
 oldapp=oldroot/'AEGIS';oldjava=oldapp/'runtime/bin/java.exe'
else:
 oldfile.chmod(0o755);run([oldfile,'--appimage-extract'],'published-110-extraction.log',60,cwd=oldroot)
 oldapp=oldroot/'squashfs-root';oldjava=oldapp/'runtime/bin/java'
oldclasses=root/'published-110-probes';oldclasses.mkdir(exist_ok=True);oldcp=str(oldapp/'app')+os.sep+'*'
run([jdk/('bin/javac.exe' if windows else 'bin/javac'),'--release','21','-encoding','UTF-8','-cp',oldcp,'-d',oldclasses,*[source/'client-core/src/test/java/org/securemail/client/update'/n for n in ['VisualCompatibilityProbe.java','DemoTorNetworkProbe.java']]],'published-110-probe-compile.log',60)
probe=str(oldclasses)+os.pathsep+oldcp
check('published_110_verifier_beta_schema_exact_111_packages_fixture',lambda:run([oldjava,'-cp',probe,'org.securemail.client.update.VisualCompatibilityProbe',inputs/'updates/stable.json',inputs/'AEGIS-1.1.5-Windows-x64.zip',inputs/'AEGIS-1.1.5-CachyOS-x86_64.AppImage'],'published-110-compatibility.log',120,env))
check('published_110_real_Tor_production_signature_download_resume_SHA256',lambda:run([oldjava,'-cp',probe,'org.securemail.client.update.DemoTorNetworkProbe',oldapp,out/'published-110-real-Tor'],'published-110-real-Tor.log',600,env))
check('published_110_real_Snowflake_signature_download_resume_SHA256',lambda:run([oldjava,'-cp',probe,'org.securemail.client.update.DemoTorNetworkProbe',oldapp,out/'published-110-real-Snowflake','--snowflake'],'published-110-real-Snowflake.log',600,env))
(out/'RESULTS.json').write_text(json.dumps(report,indent=2)+'\n')
if any(x['result']!='PASS' for x in report['checks']):sys.exit(1)
