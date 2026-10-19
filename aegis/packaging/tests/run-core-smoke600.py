#!/usr/bin/env python3
"""Actual Core JavaFX/Monocle matrix plus public-consent owned-JVM lifecycle fixture.
This is a headless integration check, never native Tor/Windows/CachyOS acceptance.
"""
import argparse,hashlib,json,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for name in ('jdk','jars','dependencies','monocle','native-root','output'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();project=Path(__file__).resolve().parents[2];out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);classes=out/'classes';fixture=out/'fixture-classes';classes.mkdir();fixture.mkdir()
src=project/'client-ui/src/smoke/java/org/securemail/ui/CoreSmoke600.java';child=project/'client-ui/src/smokeFixtures600/java/org/securemail/ui/MailPairingEntrypoint600.java'
inputs=[*sorted(a.jars.resolve().glob('*/*.jar')),*sorted(a.dependencies.resolve().glob('*.jar')),a.monocle.resolve()]
inputs=[x for x in inputs if x.name not in ('slf4j-api-2.0.12.jar','slf4j-nop-2.0.12.jar') and not(x.name.startswith('javafx-') and x.name.endswith('-win.jar'))]
cp=':'.join(map(str,inputs));jdk=a.jdk.resolve()/'bin';fixturejar=out/'public-consent-fixture.jar'
commands=[('javac-smoke',[str(jdk/'javac'),'--release','21','-encoding','UTF-8','-cp',cp,'-d',str(classes),str(src)]),('javac-public-consent-fixture',[str(jdk/'javac'),'--release','21','-encoding','UTF-8','-cp',cp,'-d',str(fixture),str(child)]),('jar-public-consent-fixture',[str(jdk/'jar'),'--create','--file',str(fixturejar),'-C',str(fixture),'.'])]
for w,h in ((800,600),(1024,768),(1920,1080)):
 commands.append((f'smoke-{w}x{h}',[str(jdk/'java'),'-Daegis.native.root='+str(a.native_root.resolve()),'-Daegis.core600.consentFixtureJar='+str(fixturejar),'-Djava.awt.headless=true','-Dglass.platform=Monocle','-Dmonocle.platform=Headless','-Dheadless.geometry=1920x1080-32','-Dprism.order=sw','-cp',str(classes)+':'+cp,'org.securemail.ui.CoreSmoke600',str(out/f'{w}x{h}'),str(w),str(h)]))
def sha(file):return hashlib.file_digest(file.open('rb'),'sha256').hexdigest()
before={str(x):sha(x) for x in (src,child,*inputs)};results=[]
for phase,cmd in commands:
 started=time.monotonic()
 with (out/(phase+'.log')).open('w') as log:
  try:run=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=240);code=run.returncode
  except subprocess.TimeoutExpired:code=124
 errors=[x for x in ('BufferOverflowException','Too small int buffer') if x in (out/(phase+'.log')).read_text()]
 results.append({'phase':phase,'command':cmd,'exitCode':code,'seconds':round(time.monotonic()-started,3),'rendererErrors':errors})
 if code or errors:break
changed=[str(x) for x in (src,child,*inputs) if sha(x)!=before[str(x)]]
proof={'pass':len(results)==len(commands) and not changed and all(x['exitCode']==0 and not x['rendererErrors'] for x in results),'commands':results,'inputHashes':before,'changedInputs':changed,'scope':'Actual Monocle Core window + signed local Identity/Community HTTP/SQLite through explicit SOCKS/Tor/OS fixtures; separate test-only public-consent JVM uses real pipe/MAC IPC and production broker/Core lock. Native Windows/CachyOS/public Tor/Mail GUI/private-root/audio NOT_RUN.'}
(out/'EXECUTION.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps({k:v for k,v in proof.items() if k not in ('inputHashes','commands')},indent=2));raise SystemExit(0 if proof['pass'] else 1)
