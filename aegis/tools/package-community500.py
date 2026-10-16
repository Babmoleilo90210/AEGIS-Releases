#!/usr/bin/env python3
"""Offline operator server packages, bound to a clean Git HEAD and freshly recompiled class payloads.
No downloads, deployment, owner signatures, credentials, production Relay or feeds.
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shutil, stat, subprocess, tempfile, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
VERSION='5.0.0'
PINNED={
 'gson-2.14.0.jar':'2cbd119bf1961c28788310963dc80ba65f58cdeec1dd139c8bdb1240faa2c36f',
 'sqlite-jdbc-3.53.4.0.jar':'bcb1f51e36f940867e83342f9efbf5968ac44a6bef4d397bb4af7b17b45cd2fb',
 'slf4j-api-2.0.17.jar':'7b751d952061954d5abfed7181c1f645d336091b679891591d63329c622eb832',
 'slf4j-nop-2.0.17.jar':'3716f83649ec66161a2edefd4f49df34d1dd1c51cdcf941996c6987260f0a829',
}
MODULES=('common-protocol','community-server','news-worker')
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def run(args,**kw):return subprocess.run(list(map(str,args)),check=True,timeout=180,**kw)
def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],timeout=30)
def tracked_tree():
 tracked={}
 for record in git('ls-tree','-r','-z','--full-tree','HEAD').split(b'\0'):
  if record:
   meta,path=record.split(b'\t',1);mode,kind,oid=meta.split();tracked[path.decode('utf-8')]=(mode.decode(),oid.decode())
 return tracked
def safe_file(p):
 if p.is_symlink() or not p.is_file() or any(ord(c)<32 for c in str(p)):raise ValueError('Regular non-symlink file required: '+str(p))
 return p

def jar_payload(jar):
 result={};seen=set()
 with zipfile.ZipFile(safe_file(jar)) as z:
  if z.testzip() is not None:raise ValueError('JAR CRC mismatch')
  if len(z.infolist())>20000:raise ValueError('Oversized JAR')
  for i in z.infolist():
   path=pathlib.PurePosixPath(i.filename)
   if path.is_absolute() or '..' in path.parts or '\\' in i.filename or ':' in i.filename or any(ord(c)<32 or ord(c)==127 for c in i.filename) or i.filename.casefold() in seen or stat.S_ISLNK(i.external_attr>>16):raise ValueError('Unsafe/duplicate JAR entry')
   seen.add(i.filename.casefold())
   if i.is_dir():continue
   if i.filename=='META-INF/MANIFEST.MF':
    text=z.read(i).decode('utf-8')
    lines=[line for line in text.splitlines()if line]
    if not lines or lines[0]!='Manifest-Version: 1.0' or any(not(line=='Manifest-Version: 1.0' or line.startswith('Created-By: 21.'))for line in lines):raise ValueError('Unexpected executable JAR manifest attributes')
    continue
   if i.file_size>32*1024*1024:raise ValueError('Oversized JAR entry')
   result[i.filename]=hashlib.sha256(z.read(i)).hexdigest()
 return result

def verify_payload(jar,classes,resources):
 expected={p.relative_to(classes).as_posix():sha(safe_file(p)) for p in classes.rglob('*') if p.is_file()}
 if resources.is_dir():
  for p in resources.rglob('*'):
   if p.is_file():expected[p.relative_to(resources).as_posix()]=sha(safe_file(p))
 actual=jar_payload(jar)
 if actual!=expected:raise ValueError('JAR class/resource payload does not match frozen source: '+jar.name)
 return actual

def dependency_inputs(folders):
 selected={}
 for name,digest in PINNED.items():
  candidates=[p/name for p in folders if (p/name).exists()]
  if not candidates:raise ValueError('Missing pinned dependency: '+name)
  for p in candidates:
   if sha(safe_file(p))!=digest:raise ValueError('Dependency SHA-256 mismatch: '+name)
  selected[name]=candidates[0]
 return selected

def zip_tree(folder,target):
 with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6)as z:
  for p in sorted(folder.rglob('*')):
   if p.is_file():
    safe_file(p);name=folder.name+'/'+p.relative_to(folder).as_posix();info=zipfile.ZipInfo(name,(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.create_system=3;info.external_attr=(0o100755 if p.parent.name=='bin' and p.suffix!='.cmd' else 0o100644)<<16;z.writestr(info,p.read_bytes())
 with zipfile.ZipFile(target)as z:
  if z.testzip() is not None:raise ValueError('Output ZIP CRC mismatch')

def licenses(folder,deps):
 target=folder/'licenses';target.mkdir()
 for name,jar in deps.items():
  with zipfile.ZipFile(jar)as z:
   for member in z.namelist():
    if not member.endswith('/') and any(token in pathlib.PurePosixPath(member).name.lower() for token in ('license','notice','copying')):
     dest=target/(name+'-'+member.replace('/','_'));dest.write_bytes(z.read(member))
 # Gson uses Apache-2.0. The standard full license is already contained in the verified SQLite JAR.
 with zipfile.ZipFile(deps['sqlite-jdbc-3.53.4.0.jar'])as z:(target/'Apache-2.0.txt').write_bytes(z.read('META-INF/maven/org.xerial/sqlite-jdbc/LICENSE'))
 (target/'THIRD-PARTY.md').write_text('Gson 2.14.0: Google, Apache-2.0; https://github.com/google/gson\nSQLite JDBC 3.53.4.0: Xerial, Apache-2.0; SQLite public domain; licenses included in the vendor JAR.\nSLF4J API/NOP 2.0.17: QOS.ch, MIT; vendor license texts extracted above.\nNo JavaFX, JUnit, owner/user keys or externally supplied executable content is included.\n',encoding='utf-8')

def package(args):
 if git('status','--porcelain','--untracked-files=all').strip():raise ValueError('Freeze and commit source before server packaging')
 commit=git('rev-parse','HEAD').decode().strip();tree=git('rev-parse','HEAD^{tree}').decode().strip();repo=pathlib.Path(git('rev-parse','--show-toplevel').decode().strip())
 out=args.out.resolve();jdk=args.jdk.resolve();jars=args.jar_dir.resolve();deps=dependency_inputs([p.resolve()for p in args.deps]);out.mkdir(parents=True,exist_ok=True)
 if out.is_relative_to(repo):raise ValueError('Output must be outside the source checkout')
 javac=jdk/('bin/javac.exe'if os.name=='nt'else'bin/javac');version=run([javac,'-version'],capture_output=True,text=True).stdout.strip()
 if not version.startswith('javac 21.'):raise ValueError('Java 21 JDK required')
 tracked=tracked_tree()
 def frozen(p):
  safe_file(p);relative=p.relative_to(repo).as_posix();raw=p.read_bytes();record=tracked.get(relative)
  if record is None or record[0]not in ('100644','100755')or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=record[1]:raise ValueError('Source/template is not an exact frozen Git blob: '+relative)
  return p
 source_hashes={};payloads={};classpath=list(deps.values())
 with tempfile.TemporaryDirectory(prefix='aegis-community500-')as work_text:
  work=pathlib.Path(work_text)
  for module in MODULES:
   classes=work/(module+'-classes');classes.mkdir();sources=sorted((ROOT/module/'src/main/java').rglob('*.java'));resources=ROOT/module/'src/main/resources'
   if not sources:raise ValueError('Missing module sources: '+module)
   for p in sources+([p for p in resources.rglob('*') if p.is_file()]if resources.is_dir()else[]):source_hashes[p.relative_to(repo).as_posix()]=sha(frozen(p))
   source_list=work/(module+'.sources');source_list.write_text('\n'.join('"'+str(p).replace('\\','\\\\').replace('"','\\"')+'"'for p in sources)+'\n',encoding='utf-8')
   with (work/(module+'-compile.log')).open('w')as log:run([javac,'--release','21','-encoding','UTF-8','-Xlint:all','-parameters','-g','-cp',os.pathsep.join(map(str,classpath)),'-d',classes,'@'+str(source_list)],stdout=log,stderr=subprocess.STDOUT)
   jar=safe_file(jars/(module+'.jar'));payloads[module]={'jarSha256':sha(jar),'classResourceSha256':verify_payload(jar,classes,resources)};classpath.append(jar)
  if git('rev-parse','HEAD').decode().strip()!=commit or git('status','--porcelain','--untracked-files=all').strip():raise ValueError('Source changed during verification')
  for label,modules in [('community-server',('common-protocol','community-server')),('news-worker',MODULES)]:
   folder=work/('AEGIS-'+VERSION+'-'+label);folder.mkdir();lib=folder/'lib';lib.mkdir();bin_dir=folder/'bin';bin_dir.mkdir();templates=ROOT/'packaging/community500'
   for module in modules:
    shutil.copy2(jars/(module+'.jar'),lib/(module+'.jar'))
    if sha(lib/(module+'.jar'))!=payloads[module]['jarSha256']:raise ValueError('JAR changed during packaging')
   for name,path in deps.items():shutil.copy2(path,lib/name)
   launcher='community-server'if label=='community-server'else'news-worker';shutil.copy2(frozen(templates/'bin'/launcher),bin_dir/launcher);(bin_dir/launcher).chmod(0o755)
   if label=='community-server':shutil.copy2(frozen(templates/'bin/community-server.cmd'),bin_dir/'community-server.cmd')
   unit=templates/'systemd/aegis-community.service'if label=='community-server'else ROOT/'news-worker/deploy/aegis-news-worker.service';shutil.copy2(frozen(unit),folder/unit.name)
   shutil.copy2(frozen(templates/'README-RU.md'),folder/'README.md');shutil.copy2(frozen(ROOT/'SERVER-DEPLOYMENT-PROPOSAL-5.0.0-RU.md'),folder/'SERVER-DEPLOYMENT-PROPOSAL-5.0.0-RU.md');shutil.copy2(frozen(ROOT/'community-server/README.md'),folder/'ACCESS-AND-ADMIN.md');licenses(folder,deps)
   provenance={'version':VERSION,'package':label,'sourceCommit':commit,'sourceTree':tree,'compiler':version,'compilerSha256':sha(safe_file(javac)),'sourceFilesSha256':source_hashes,'verifiedPayloads':{m:payloads[m]for m in modules},'dependencies':PINNED,'verification':'Fresh Java 21 recompilation; exact class/resource payload equality; ZIP CRC','operatorJavaBundled':False,'productionReady':False,'nativeServerDeployment':'NOT_RUN','ownerPrivateKeyUsed':False,'credentialsIncluded':False,'productionRelayOrFeedChanged':False}
   (folder/'SERVER-BUILD-PROVENANCE-5.0.0.json').write_text(json.dumps(provenance,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
   files=sorted(p for p in folder.rglob('*')if p.is_file());(folder/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.relative_to(folder).as_posix()+'\n'for p in files),encoding='utf-8')
   target=out/(folder.name+'.zip');temporary=out/(folder.name+'.zip.part');zip_tree(folder,temporary);os.replace(temporary,target)
   (out/(folder.name+'-PROVENANCE.json')).write_text(json.dumps(provenance,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(target.name,sha(target))
 return 0

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--jdk',type=pathlib.Path,required=True);p.add_argument('--jar-dir',type=pathlib.Path,default=ROOT/'build/local-java21');p.add_argument('--deps',type=pathlib.Path,action='append',required=True);p.add_argument('--out',type=pathlib.Path,required=True);return package(p.parse_args())
if __name__=='__main__':raise SystemExit(main())
