#!/usr/bin/env python3
"""Bounded synthetic benchmark of actual SQLite and production community ACL/content.
Never connects to Tor, production Relay, external APIs or real user profiles.
"""
from __future__ import annotations
import argparse,datetime,hashlib,json,pathlib,subprocess,tempfile,time

def main():
 p=argparse.ArgumentParser();p.add_argument('--jdk',type=pathlib.Path,required=True);p.add_argument('--deps',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
 root=pathlib.Path(__file__).resolve().parents[1];jdk=a.jdk.resolve();deps=a.deps.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
 java=jdk/'bin/java';javac=jdk/'bin/javac';jars=[deps/name for name in ('sqlite-jdbc-3.53.4.0.jar','slf4j-api-2.0.17.jar','slf4j-nop-2.0.17.jar')]
 if not java.is_file() or not javac.is_file() or any(not x.is_file() for x in jars):raise SystemExit('Explicit trusted JDK/dependency files are required')
 version=subprocess.run([str(java),'-version'],capture_output=True,text=True,check=True,timeout=10)
 if 'version "21.' not in version.stderr+version.stdout:raise SystemExit('Java 21 required')
 sources=[]
 for package in ('core','access','content'):sources.extend(sorted((root/'community-server/src/main/java/org/securemail/community'/package).glob('*.java')))
 sources.append(root/'community-server/src/main/java/org/securemail/community/http/StrictJson.java')
 sources.append(root/'community-server/src/test/java/org/securemail/community/content/CommunityLoad500Smoke.java')
 inputs={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sources}
 inputs[str(pathlib.Path(__file__).resolve().relative_to(root))]=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
 started=datetime.datetime.now(datetime.timezone.utc).isoformat();wall=time.monotonic()
 with tempfile.TemporaryDirectory(prefix='aegis-community500-load-') as tmp:
  path=pathlib.Path(tmp);classes=path/'classes';classes.mkdir();separator=';' if __import__('os').name=='nt' else ':'
  compile_command=[str(javac),'-encoding','UTF-8','-Xlint:all','-d',str(classes),*[str(f) for f in sources]]
  compile_result=subprocess.run(compile_command,capture_output=True,text=True,timeout=60)
  (out/'compile.log').write_text(compile_result.stdout+compile_result.stderr)
  if compile_result.returncode:raise SystemExit('Benchmark compilation failed; see compile.log')
  command=[str(java),'-Xms64m','-Xmx384m','-cp',separator.join([str(classes),*[str(x) for x in jars]]),'org.securemail.community.content.CommunityLoad500Smoke',str(path/'data')]
  run=subprocess.run(command,capture_output=True,text=True,timeout=120)
  (out/'run.log').write_text(run.stderr+('\n'+run.stdout if run.returncode else ''))
  if run.returncode:raise SystemExit('Benchmark assertion failed; see run.log')
  report=json.loads(run.stdout);report.update({'startedUtc':started,'finishedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'wallSecondsIncludingCompile':time.monotonic()-wall,'javaVersionOutput':version.stderr.strip(),'sourceSha256':inputs,'dependencySha256':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in jars},'compilerSha256':hashlib.sha256(javac.read_bytes()).hexdigest(),'javaLauncherSha256':hashlib.sha256(java.read_bytes()).hexdigest(),'productionReady':False})
  (out/'RESULTS.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
  print(json.dumps({'datasets':[d['materials'] for d in report['datasets']],'assertionsPassed':True,'wallSeconds':report['wallSecondsIncludingCompile'],'report':str(out/'RESULTS.json')},ensure_ascii=False))
if __name__=='__main__':main()
