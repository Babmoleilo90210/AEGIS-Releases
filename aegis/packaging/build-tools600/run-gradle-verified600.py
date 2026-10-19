#!/usr/bin/env python3
"""Capture immutable source and immediately CRC-check/copy JARs; outputs stay outside the repository."""
from pathlib import Path
import subprocess,sys,json,hashlib,zipfile,io,datetime,os
r=Path(__file__).resolve().parent
if len(sys.argv)<6 or '--project-dir' not in sys.argv[3:]:raise SystemExit('Usage: run-gradle-verified600.py LOG EVIDENCE --project-dir PROJECT tasks...')
log=Path(sys.argv[1]).resolve();out=Path(sys.argv[2]).resolve();args=sys.argv[3:];project=Path(args[args.index('--project-dir')+1]).resolve();out.mkdir(parents=True,exist_ok=True)
def git(*args):return subprocess.check_output(['git',*args],cwd=project,text=True).strip()
def digest(file):
 with file.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def source_snapshot():
 gitroot=Path(git('rev-parse','--show-toplevel'));files={};paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=gitroot).decode().split('\0')
 for name in paths:
  if not name:continue
  file=gitroot/name
  if file.is_symlink():files[name]={'symlink':os.readlink(file)}
  elif file.is_file():files[name]={'sha256':digest(file),'mode':file.stat().st_mode&0o777}
  else:files[name]={'missing':True}
 return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'dirtyTracked':bool(git('status','--porcelain','--untracked-files=no')),'workingTreeDirty':bool(git('status','--porcelain')),'files':files}
start=source_snapshot();(out/'SOURCE-BEFORE.json').write_text(json.dumps(start,indent=2)+'\n');command=[sys.executable,str(Path(__file__).with_name('run-gradle600.py')),str(log),*args];began=datetime.datetime.now(datetime.timezone.utc).isoformat();code=subprocess.call(command);jars=[]
for file in sorted(project.glob('*/build/libs/*.jar')):
 try:
  data=file.read_bytes()
  with zipfile.ZipFile(io.BytesIO(data)) as archive:assert archive.testzip() is None;entries=len(archive.infolist())
  target=out/'jars'/file.parent.parent.parent.name/file.name;target.parent.mkdir(parents=True,exist_ok=True);temporary=target.with_suffix('.tmp');temporary.write_bytes(data);temporary.replace(target);jars.append({'file':str(file.relative_to(project)),'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'entries':entries,'zipCRC':'PASS'})
 except Exception as error:jars.append({'file':str(file.relative_to(project)),'zipCRC':'FAIL','errorType':type(error).__name__})
end=source_snapshot();(out/'SOURCE-AFTER.json').write_text(json.dumps(end,indent=2)+'\n');unchanged=start==end
result={'startedAt':began,'finishedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':command,'gradleExitCode':code,'sourceUnchanged':unchanged,'sourceCommit':start['commit'],'sourceTree':start['tree'],'sourceDirtyAtStart':start['workingTreeDirty'],'jars':jars,'pass':code==0 and unchanged and all(x['zipCRC']=='PASS' for x in jars),'scope':'Local Gradle build/tests and immediate JAR/source integrity only; native/Tor/physical acceptance remains separate.'};(out/'GRADLE-VERIFICATION.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True);raise SystemExit(0 if result['pass'] else 1)
