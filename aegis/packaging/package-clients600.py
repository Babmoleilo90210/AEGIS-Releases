#!/usr/bin/env python3
"""Package only a clean, tested, frozen AEGIS6 commit. No deployment, signing or native-PASS claims."""
import argparse, hashlib, importlib.util, json, os, re, shutil, stat, subprocess, tempfile, time, zipfile
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET
_base_spec=importlib.util.spec_from_file_location('aegis_packaging_base500',Path(__file__).with_name('package-clients500.py'))
_base=importlib.util.module_from_spec(_base_spec);_base_spec.loader.exec_module(_base)
normalize_payload,require_frozen_commit,verify_windows_base=_base.normalize_payload,_base.require_frozen_commit,_base.verify_windows_base
from verify_appimage import verify as verify_image
from verify_appimage500 import verify as verify_permissions
from client_runtime import verify_safe_web_runtime, verify_voice_native
from client_runtime500 import SAFE_WEB_RUNTIME
from java_runtime import verify_java_runtime
ROOT=Path(__file__).resolve().parents[1]
VERSION='6.0.0'
BASE_COMMIT='37779c113553bf5e1a42642e7ca7a010db9bdd4e'
BASE_IMPORT_COMMIT='38a3e6469a40e6edcb1b0448f906a488c73feb5d'
BASE_HASHES={'win':'17b2ffa567ffe4fd9aef149ccaf39a3dc56ad0312db931dda3ae727cf7a31523','linux':'d27209621b936ff9445d5263c9c3bbf9366b00f9fc200704d00d9682d5bbc270'}
PROJECT_JARS={'client-core-6.0.0.jar','client-ui-6.0.0.jar','common-protocol-0.2.0.jar'}

def sha(path):
 with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def run(args,**kwargs):return subprocess.run(list(map(str,args)),check=True,**kwargs)
def write(path,obj):path.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def tool_tree_digest(root):
 digest=hashlib.sha256();count=0
 for file in sorted(root.rglob('*')):
  mode=file.lstat().st_mode;kind='l' if stat.S_ISLNK(mode) else 'f' if stat.S_ISREG(mode) else 'd' if stat.S_ISDIR(mode) else '?'
  if kind=='?':raise ValueError('Special toolchain node rejected')
  digest.update((file.relative_to(root).as_posix()+'\0'+kind+'\0'+str(mode&0o111)+'\0').encode())
  if kind=='l':digest.update(os.readlink(file).encode())
  elif kind=='f':
   with file.open('rb') as stream:digest.update(hashlib.file_digest(stream,'sha256').digest())
   count+=1
  digest.update(b'\0')
 return digest.hexdigest(),count
def verify_tools(root):
 registry=json.loads((ROOT/'packaging/native-kit/packaging-toolchain600.json').read_text());actual,count=tool_tree_digest(root)
 if actual!=registry['payloadTreeSha256'] or count!=registry['payloadRegularFiles']:raise ValueError('Native tool payload differs from authenticated official package registry')
 return registry
def checked_proof(path,commit):
 proof=json.loads(path.read_text());
 command=proof.get('command',[])
 if not isinstance(command,list) or not all(isinstance(x,str) for x in command) or not {'clean','test','assemble'}.issubset(command) or any(x in ('-x','-m') or x.startswith(('--tests','--exclude-task','--dry-run','-x')) for x in command):raise ValueError('Require unfiltered full root clean test assemble proof, not partial tasks')
 if proof.get('gradleExitCode')!=0 or proof.get('sourceUnchanged') is not True or proof.get('sourceDirtyAtStart') is not False or proof.get('sourceCommit')!=commit:raise ValueError('Require successful clean frozen-source build proof, not a diagnostic run')
 return {Path(row['file']).name:row['sha256'] for row in proof['jars'] if row.get('zipCRC')=='PASS'}
def dependency_pins():
 result={}
 for node in ET.parse(ROOT/'gradle/verification-metadata.xml').iter():
  if node.tag.rsplit('}',1)[-1]!='artifact':continue
  values={x.attrib['value'] for x in node if x.tag.rsplit('}',1)[-1]=='sha256'}
  if values:result.setdefault(node.attrib['name'],set()).update(values)
 return result
def runtime_names(platform):
 names=set(PROJECT_JARS)
 for line in (ROOT/'client-ui/gradle.lockfile').read_text().splitlines():
  if line.startswith('#') or '=' not in line:continue
  coordinate,configurations=line.split('=',1)
  if 'runtimeClasspath' not in configurations.split(','):continue
  parts=coordinate.split(':')
  if len(parts)!=3:raise ValueError('Unexpected locked runtime coordinate')
  group,artifact,version=parts
  names.add(artifact+'-'+version+('-'+platform if group=='org.openjfx' else '')+'.jar')
 return names
def extract_windows_base(archive,target):
 # Fresh private extraction and validation happen in this same process. A mutable
 # old extraction cache is never copied into a release, including hidden temp files.
 target.mkdir();seen=set()
 with zipfile.ZipFile(archive) as z:
  if z.testzip() is not None:raise ValueError('Exact-base Windows ZIP CRC failed')
  for item in z.infolist():
   entry=PurePosixPath(item.filename)
   if not entry.parts or entry.parts[0]!='AEGIS' or entry.is_absolute() or '..' in entry.parts or '\\' in item.filename or stat.S_ISLNK(item.external_attr>>16):raise ValueError('Unsafe native-base ZIP entry')
   relative=Path(*entry.parts[1:]);key=relative.as_posix().casefold()
   if item.is_dir():target.joinpath(relative).mkdir(parents=True,exist_ok=True);continue
   if not relative.parts or key in seen:raise ValueError('Duplicate native-base ZIP path')
   seen.add(key);file=target/relative;file.parent.mkdir(parents=True,exist_ok=True)
   with z.open(item) as src,file.open('xb') as dst:shutil.copyfileobj(src,dst)
 return verify_windows_base(archive,target)

def check_app(directory,platform,built,pins):
 if directory.is_symlink() or not directory.is_dir():raise ValueError('App input must be a real directory')
 files=list(directory.iterdir());names={p.name for p in files}
 if names!=runtime_names(platform) or len(files)>96:raise ValueError('Runtime JAR set differs from exact locked production classpath')
 inventory={}
 for file in files:
  if file.is_symlink() or not file.is_file() or file.suffix!='.jar':raise ValueError('Only ordinary JARs allowed in client classpath')
  if file.name.startswith(('relay-server-','identity-server-','community-server-','news-worker-','attachment-service-','management-agent-','glas-signaling-')):raise ValueError('Server JAR prohibited in desktop runtime')
  digest=sha(file)
  if file.name in PROJECT_JARS:
   if built.get(file.name)!=digest:raise ValueError('Project JAR differs from frozen build proof: '+file.name)
  elif digest not in pins.get(file.name,set()):raise ValueError('Dependency missing exact source verification SHA256: '+file.name)
  if file.name.startswith('javafx-') and not file.name.endswith('-'+platform+'.jar'):raise ValueError('Wrong JavaFX target platform')
  with zipfile.ZipFile(file) as z:
   if z.testzip() is not None:raise ValueError('JAR CRC mismatch')
  inventory[file.name]=digest
 verify_safe_web_runtime(directory,core_jar_name='client-core-6.0.0.jar')
 for name,digest in SAFE_WEB_RUNTIME.items():
  if inventory.get(name)!=digest:raise ValueError('Safe browser dependency pin mismatch: '+name)
 with zipfile.ZipFile(directory/'client-core-6.0.0.jar') as z:
  for entry in ['org/securemail/client/maintenance600/RuntimeLease600.class','org/securemail/client/maintenance600/MaintenanceMain600.class','org/securemail/client/safeweb600/VzorLaunch600.class']:
   if entry not in z.namelist():raise ValueError('Missing6 runtime class: '+entry)
 return inventory

def prepare(base,app,target,platform,commit,proof,inventory):
 target.mkdir()
 for name in ['runtime','native','tor','licenses']:shutil.copytree(base/name,target/name)
 java=verify_java_runtime(target/'runtime',platform);verify_voice_native(target,platform)
 shutil.copytree(app,target/'app');shutil.copytree(ROOT/'resources',target/'resources')
 for name in ['README.md','README-WINDOWS.md','README-CACHYOS.md','SECURITY.md','PRIVACY.md','PROTOCOL.md']:
  if (ROOT/name).is_file():shutil.copy2(ROOT/name,target/name)
 for file in sorted(ROOT.glob('*6.0.0*.md')):shutil.copy2(file,target/file.name)
 if (ROOT/'docs/third-party').is_dir():shutil.copytree(ROOT/'docs/third-party',target/'docs/third-party')
 for jar in (target/'app').glob('*.jar'):
  with zipfile.ZipFile(jar) as z:
   for name in z.namelist():
    leaf=Path(name).name
    if not name.endswith('/') and name.startswith('META-INF/') and leaf.upper().startswith(('LICENSE','NOTICE','COPYING')):
     if z.getinfo(name).file_size>262144:raise ValueError('Oversized dependency license')
     (target/'licenses'/(jar.stem+'-'+leaf)).write_bytes(z.read(name))
 runtime='runtime/bin/java.exe' if platform=='win' else 'runtime/bin/java'
 write(target/'components600.json',{'schema':1,'java':{'path':runtime,'sha256':sha(target/runtime)},'jars':{'app/'+name:digest for name,digest in sorted(inventory.items())}})
 write(target/'entrypoints600.json',{'schema':1,'version':VERSION,'core':{'main':'org.securemail.ui.Launcher','launch':'only desktop shortcut'},'components':{'mail':{'main':'org.securemail.ui.ecosystem.ComponentEntrypoint','fixedArguments':['MAIL'],'authorization':'Core authenticated anonymous pipe + Identity session'},'glas':{'main':'org.securemail.ui.ecosystem.ComponentEntrypoint','fixedArguments':['GLAS'],'authorization':'Core authenticated anonymous pipe + Identity session'},'vzor':{'main':'org.securemail.ui.VzorApp600','fixedArguments':[],'authorization':'single-use authorized Core launch nonce, no account capability'},'personalLibrary':{'main':'org.securemail.client.library600.WindowsPersonalObsidianLauncher600' if platform=='win' else 'org.securemail.client.library600.PersonalObsidianLauncher600','authorization':'Core-approved independent boundary grant'}},'nativeAcceptance':'NOT_RUN'})
 write(target/'BUILD-INPUTS.json',{'clientVersion':VERSION,'sourceCommit':commit,'baseVersion':'5.0.0','baseSourceCommit':BASE_COMMIT,'baseLocalImportCommit':BASE_IMPORT_COMMIT,'verifiedBaseArtifacts':BASE_HASHES,'java':java,'buildProofSha256':sha(proof),'runtimeJars':inventory,'nativeAcceptance':'NOT_RUN'})
 # Do not inherit5 native acceptance, release gates, signing metadata or update feed.
 return target

def package(a):
 commit,epoch=require_frozen_commit(a.expected_commit);built=checked_proof(a.build_proof,commit);pins=dependency_pins()
 for platform,file in [('win',a.windows_base_zip),('linux',a.linux_base_image)]:
  if file.is_symlink() or sha(file)!=BASE_HASHES[platform]:raise ValueError('Exact owner-verified5 native base required')
 linux_proof=verify_image(a.linux_base_image,a.linux_base)
 inputs=[ROOT,a.linux_base,a.windows_app,a.linux_app]
 if a.out.is_symlink():raise ValueError('Output cannot be a link')
 out=a.out.resolve()
 if any(out==p.resolve() or out.is_relative_to(p.resolve()) or p.resolve().is_relative_to(out) for p in inputs):raise ValueError('Output overlaps immutable inputs')
 out.mkdir(parents=True,exist_ok=True);stage=out/'stage'
 if stage.exists():raise ValueError('Use a fresh package output; existing stage is preserved')
 stage.mkdir();fresh_windows=stage/'.verified-windows-base';windows_proof=extract_windows_base(a.windows_base_zip,fresh_windows)
 proof={'windows':windows_proof,'linux':linux_proof,'baseSourceCommit':BASE_COMMIT,'baseLocalImportCommit':BASE_IMPORT_COMMIT,'nativeAcceptance':'NOT_RUN'};write(out/'REUSED-BASE-5.0.0-VERIFICATION.json',proof)
 win_inventory=check_app(a.windows_app,'win',built,pins);linux_inventory=check_app(a.linux_app,'linux',built,pins)
 win=prepare(fresh_windows,a.windows_app,stage/'AEGIS','win',commit,a.build_proof,win_inventory);shutil.rmtree(fresh_windows)
 linux=prepare(a.linux_base,a.linux_app,stage/'AEGIS.AppDir','linux',commit,a.build_proof,linux_inventory)
 tools=a.native_tools.resolve();tool_proof=verify_tools(tools);env=dict(os.environ);env['PATH']=str(tools/'usr/bin')+os.pathsep+env.get('PATH','');env['LD_LIBRARY_PATH']=str(tools/'lib/x86_64-linux-gnu')+os.pathsep+str(tools/'usr/lib/x86_64-linux-gnu');env['NSISDIR']=str(tools/'usr/share/nsis');env['SOURCE_DATE_EPOCH']=str(epoch)
 write(out/'NATIVE-TOOLCHAIN-6.0.0.json',{'crossToolchain':tool_proof,'hostCCompiler':{'path':str(a.linux_cc.resolve()),'sha256':sha(a.linux_cc.resolve()),'version':subprocess.check_output([str(a.linux_cc),'--version'],env=env,text=True)},'hermetic':False})
 resource=stage/'launcher600.res';run([tools/'usr/bin/x86_64-w64-mingw32-windres','--preprocessor='+str(tools/'usr/bin/x86_64-w64-mingw32-gcc-posix'),'--preprocessor-arg=-E','--preprocessor-arg=-xc','--preprocessor-arg=-DRC_INVOKED','--codepage=65001','launcher600.rc','-O','coff','-o',resource],cwd=ROOT/'packaging/windows',env=env)
 for source,name,libraries in [('launcher600.c','AEGIS.exe',['-luser32','-lshell32','-ladvapi32']),('maintenance600.c','AEGIS-Maintenance.exe',['-luser32','-lshell32','-ladvapi32']),('updater.c','AEGIS-Updater.exe',['-lshell32'])]:
  run([tools/'usr/bin/x86_64-w64-mingw32-gcc-posix','-Os','-static','-static-libgcc','-municode','-mwindows','-finput-charset=UTF-8',ROOT/'packaging/windows'/source,resource,'-Wl,--dynamicbase,--nxcompat,--high-entropy-va,--no-insert-timestamp',*libraries,'-o',win/name],env=env)
 write(win/'maintenance600.json',{'schema':1,'sha256':sha(win/'AEGIS-Maintenance.exe'),'sourceCommit':commit})
 # NSIS itself is x86 Unicode; its guard DLL must be x86, even for x64 payload.
 run([tools/'usr/bin/i686-w64-mingw32-gcc-posix','-Os','-static','-static-libgcc','-shared',ROOT/'packaging/windows/runtimeguard600.c','-Wl,--dynamicbase,--nxcompat,--no-insert-timestamp','-ladvapi32','-o',win/'AEGIS-RuntimeGuard.dll'],env=env)
 run([a.linux_cc,'-std=c11','-Os','-Wall','-Wextra','-Werror','-Wl,--build-id=none','-ffile-prefix-map='+str(ROOT)+'=.',ROOT/'packaging/linux/launcher600.c','-o',linux/'AEGIS-RuntimeLauncher'],env=env)
 shutil.copy2(ROOT/'packaging/windows/CreateShortcuts.ps1',win/'CreateShortcuts.ps1');shutil.copy2(ROOT/'packaging/linux/AppRun600',linux/'AppRun');(linux/'AppRun').chmod(0o755)
 (linux/'aegis.desktop').write_text((ROOT/'packaging/linux/aegis500.desktop').read_text().replace('5.0.0','6.0.0').replace('Защищённая переписка, организации и библиотека знаний','Главное окно экосистемы АЕГИС'))
 for name in ['aegis.png','.DirIcon']:shutil.copy2(ROOT/'resources/aegis.png',linux/name)
 normalize_payload(win);normalize_payload(linux)
 portable=out/'AEGIS-6.0.0-Windows-x64.zip'
 with zipfile.ZipFile(portable,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
  for file in sorted(win.rglob('*')):
   if file.is_file():
    info=zipfile.ZipInfo('AEGIS/'+file.relative_to(win).as_posix(),time.gmtime(epoch)[:6]);info.create_system=3;info.external_attr=0o100644<<16;info.compress_type=zipfile.ZIP_DEFLATED
    with file.open('rb') as src,z.open(info,'w') as dst:shutil.copyfileobj(src,dst)
 with zipfile.ZipFile(portable) as z:
  if z.testzip() is not None:raise ValueError('Portable ZIP final CRC failed')
 setup=out/'AEGIS-Setup-6.0.0-x64.exe';run([tools/'usr/bin/makensis','-V2','-DPAYLOAD='+str(win),'-DOUTFILE='+str(setup),'installer600.nsi'],cwd=ROOT/'packaging/windows',env=env)
 image=out/'AEGIS-6.0.0-CachyOS-x86_64.AppImage';offset=linux_proof['SquashFS_offset']
 with tempfile.TemporaryDirectory(prefix='.appimage600-',dir=out) as tmp:
  squash=Path(tmp)/'payload.squashfs';run([tools/'usr/bin/mksquashfs',linux,squash,'-noappend','-processors','2','-comp','zstd','-b','131072','-all-root','-no-xattrs','-mkfs-time',epoch,'-all-time',epoch],env=env)
  with image.open('wb') as dst,a.linux_base_image.open('rb') as src:
   prefix=src.read(offset)
   if len(prefix)!=offset or offset>16*1024*1024:raise ValueError('Invalid exact-base AppImage runtime prefix')
   dst.write(prefix)
   with squash.open('rb') as src:shutil.copyfileobj(src,dst)
  image.chmod(0o755);previous=os.environ.get('LD_LIBRARY_PATH');os.environ['LD_LIBRARY_PATH']=env['LD_LIBRARY_PATH']
  try:image_proof=verify_permissions(image,linux,tools/'usr/bin/unsquashfs')
  finally:
   if previous is None:os.environ.pop('LD_LIBRARY_PATH',None)
   else:os.environ['LD_LIBRARY_PATH']=previous
 write(out/'APPIMAGE-PERMISSIONS-6.0.0.json',{'artifactSHA256':sha(image),'verification':image_proof,'nativeAcceptance':'NOT_RUN'})
 require_frozen_commit(commit)
 artifacts=[portable,setup,image];write(out/'CLIENT-PACKAGE-PROVENANCE-6.0.0.json',{'sourceCommit':commit,'buildProofSha256':sha(a.build_proof),'artifacts':[{'path':p.name,'sha256':sha(p),'bytes':p.stat().st_size} for p in artifacts],'nativeAcceptance':'NOT_RUN','productionReady':False})
 (out/'SHA256SUMS-client').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in artifacts))
 print('Created actual6 client packages from clean frozen source. Signing/publication/native acceptance are separate.')

def parser():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ['windows-base-zip','linux-base-image','linux-base','windows-app','linux-app','native-tools','build-proof','out']:p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--linux-cc',type=Path,default=Path('/usr/bin/cc'));p.add_argument('--expected-commit',required=True);return p
if __name__=='__main__':package(parser().parse_args())
