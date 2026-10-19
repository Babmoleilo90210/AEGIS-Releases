#!/usr/bin/env python3
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,time,sys
parser=argparse.ArgumentParser(description="Actual Mail 6 encrypted storage/path and headless JavaFX recovery/admin regression suite. Never native acceptance.")
for name in ['jdk','dependencies','native-root','output']:parser.add_argument('--'+name,type=Path,required=True)
parser.add_argument('--classes-root',type=Path)
a=parser.parse_args();project=Path(__file__).resolve().parents[2];ws=project.parent.parent;out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
jdk=a.jdk.resolve()/'bin';native=a.native_root.resolve();compiled=(a.classes_root or project).resolve()
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
modules=['common-protocol','client-core','client-ui','identity-server','community-server','relay-server','management-agent','attachment-service','glas-signaling','news-worker']
classpath=[];classhashes={}
for module in modules:
 for category,relative in [('classes','build/classes/java/main'),('resources','build/resources/main')]:
  src=compiled/module/relative
  if src.exists():
   dest=out/'runtime'/module/category
   before={str(f.relative_to(src)):sha(f) for f in src.rglob('*') if f.is_file()};shutil.copytree(src,dest)
   if before!={str(f.relative_to(src)):sha(f) for f in src.rglob('*') if f.is_file()}:raise SystemExit('Compiled runtime changed while copying '+module)
   if before!={str(f.relative_to(dest)):sha(f) for f in dest.rglob('*') if f.is_file()}:raise SystemExit('Runtime copy mismatch')
   classpath.append(dest);classhashes[str(src.relative_to(compiled))]=before
jars=[p for p in sorted(a.dependencies.resolve().glob('*.jar')) if not p.name.endswith('-win.jar') and p.name not in ['gson-2.13.2.jar','slf4j-api-2.0.12.jar','error_prone_annotations-2.41.0.jar']]
classpath+=jars;cp=':'.join(map(str,classpath));testdir=out/'tests';smokedir=out/'smoke';testdir.mkdir(exist_ok=True);smokedir.mkdir(exist_ok=True)
tests=[project/'client-core/src/test/java/org/securemail/client/ecosystem'/name for name in ['MailFilesystemBoundary600Test.java','MailRecoveryIdentity600Test.java','MailProfileMigration600Test.java']]
smokes=[project/'client-ui/src/smoke/java/org/securemail/ui'/name for name in ['ArchiveBoundarySmoke600.java','AdminIdentityRedirectSmoke600.java','MailDeviceRecoveryAuthorizationSmoke600.java','MailRecoveryFormSmoke600.java']]
main=[project/'client-core/src/main/java/org/securemail/client/ecosystem'/name for name in ['MailFilesystemBoundary600.java','MailRecoveryIdentity600.java','MailProfileMigration600.java']]+[project/'client-ui/src/main/java/org/securemail/ui'/name for name in ['ArchiveView.java','AdminView.java','LegacyMailComponentHost600.java','MailPairingEntrypoint600.java','MessengerApp.java']]
files=[Path(__file__).resolve(),*tests,*smokes,*main,*jars,*[p for p in (native/'native').glob('*') if p.is_file()]];before={str(p.resolve()):sha(p) for p in files}
commands=[('compile-tests',[str(jdk/'javac'),'--release','21','-encoding','UTF-8','-cp',cp,'-d',str(testdir),*map(str,tests)]),('test',[str(jdk/'java'),'-Xmx768m','-Daegis.native.root='+str(native),'-cp',str(testdir)+':'+cp,'org.junit.platform.console.ConsoleLauncher','execute',*[v for t in tests for v in ['--select-class','org.securemail.client.ecosystem.'+t.stem]],'--details=tree','--reports-dir='+str(out/'junit'),'--fail-if-no-tests']),('compile-smoke',[str(jdk/'javac'),'--release','21','-encoding','UTF-8','-cp',cp,'-d',str(smokedir),*map(str,smokes)])]
base=[str(jdk/'java'),'-Xmx768m','-Daegis.native.root='+str(native),'-Djava.awt.headless=true','-Dglass.platform=Monocle','-Dmonocle.platform=Headless','-Dheadless.geometry=1920x1080-32','-Dprism.order=sw','-cp',str(smokedir)+':'+cp]
commands+=[('archive-smoke',base+['org.securemail.ui.ArchiveBoundarySmoke600',str(out/'archive')]),('admin-smoke',base+['org.securemail.ui.AdminIdentityRedirectSmoke600']),('recovery-guards',base+['org.securemail.ui.MailDeviceRecoveryAuthorizationSmoke600']),('recovery-form',base+['org.securemail.ui.MailRecoveryFormSmoke600',str(out/'recovery-form')])]
results=[]
for phase,cmd in commands:
 started=time.monotonic()
 with (out/(phase+'.log')).open('w') as log:
  try:result=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=180);code=result.returncode
  except subprocess.TimeoutExpired:code=124
 results.append({'phase':phase,'exitCode':code,'seconds':round(time.monotonic()-started,3)})
 print(phase,code,flush=True)
 if code:break
changed=[str(p.resolve()) for p in files if sha(p)!=before[str(p.resolve())]]
proof={'sourceCommit':subprocess.check_output(['git','-C',str(project),'rev-parse','HEAD'],text=True).strip(),'sourceDirty':bool(subprocess.check_output(['git','-C',str(project),'status','--porcelain'],text=True)),'releaseCommitProof':False,'pass':len(results)==len(commands) and all(r['exitCode']==0 for r in results) and not changed,'results':results,'inputHashes':before,'compiledRuntimeHashes':classhashes,'changedInputs':changed,'scope':'Actual local encrypted LocalStore/recovery/migration/JavaFX guards. UI admin RPC and live recovery challenge setup are explicit fixtures; native Windows/CachyOS, real Tor, final remote enrollment and endpoint isolation NOT_RUN here.'}
(out/'EXECUTION.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n');print(json.dumps({k:v for k,v in proof.items() if k not in ['inputHashes','compiledRuntimeHashes']},ensure_ascii=False,indent=2));sys.exit(0 if proof['pass'] else 1)
