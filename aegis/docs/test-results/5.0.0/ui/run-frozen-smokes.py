"""Repeat JavaFX checks using only immutable production JARs plus smoke-only classes."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,time,sys
outer=Path('/workspace/scratch/aa629f360927');repo=outer/'aegis/aegis';build=outer/'ui500-build';tag=sys.argv[1]if len(sys.argv)>1 else '';suffix=('-'+tag)if tag else '';frozen=build/('pinned-runtime'+suffix);classes=build/('frozen-smoke-classes'+suffix);output=build/('final'+suffix)
if frozen.exists() or classes.exists() or output.exists():raise SystemExit('Refusing to overwrite a pinned evidence run')
frozen.mkdir();classes.mkdir();output.mkdir()
modules=['common-protocol','client-core','client-ui','relay-server','community-server','news-worker']
for module in modules:shutil.copy2(repo/'build/local-java21'/f'{module}.jar',frozen/f'{module}.jar')
# Reuse byte-identical published third-party dependencies, excluding every previous AEGIS module.
for path in sorted((outer/'inputs250/squashfs-root/app').glob('*.jar')):
 if path.name.startswith(('client-core-','client-ui-','common-protocol-','commons-logging-')):continue
 shutil.copy2(path,frozen/path.name)
for path in sorted((outer/'inputs500/deps').glob('*.jar')):
 if path.name.startswith('junit-platform-'):continue
 shutil.copy2(path,frozen/path.name)
for path in sorted((outer/'inputs500/runtime-deps').glob('*.jar')):shutil.copy2(path,frozen/path.name)
cp=os.pathsep.join(map(str,[classes]+sorted(frozen.glob('*.jar'))));jdk=outer/'inputs500/jdk-21.0.12.1+1';smoke=repo/'client-ui/src/smoke/java/org/securemail/ui';sources=[smoke/x for x in ['Interface500Smoke.java','Community500FlowSmoke.java','ArchiveMenu500Smoke.java','Ui500RuntimeEvidence.java','Ui500GraphBoundsChecks.java']]
inputs={'createdAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'scope':'Frozen production JARs; only smoke classes compiled into separate test output. Monocle, not native acceptance.','productionJars':{str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(frozen.glob('*.jar'))},'smokeSources':{str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in sources}}
(output/'INPUTS.json').write_text(json.dumps(inputs,indent=2))
cmd=[str(jdk/'bin/javac'),'--release','21','-encoding','UTF-8','-cp',cp,'-d',str(classes)]+list(map(str,sources))
compile_result=subprocess.run(cmd,capture_output=True,text=True);(output/'compile.log').write_text(compile_result.stdout+compile_result.stderr)
if compile_result.returncode:raise SystemExit(compile_result.returncode)
assert not list((classes/'org/securemail/client').glob('**/*.class')),'Production Core classes entered smoke output'
results={}
for name,main,expected in [('archive','ArchiveMenu500Smoke','PASS_HEADLESS'),('interface','Interface500Smoke','PASS_HEADLESS'),('flow','Community500FlowSmoke','PASS_LOCAL_INTEGRATION')]:
 destination=output/name;destination.mkdir();command=[str(jdk/'bin/java'),'-Xmx1024m','-Dprism.order=sw','-Dglass.platform=Monocle','-Dmonocle.platform=Headless','-Dheadless.geometry=4096x2400-32','-Daegis.native.root='+str(outer/'inputs250/squashfs-root'),'-Daegis.ui500.output='+str(destination),'-cp',cp,'org.securemail.ui.'+main]
 (output/(name+'-command.json')).write_text(json.dumps(command,indent=2));print('RUN',name,flush=True)
 with(output/(name+'.log')).open('w')as log:run=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=300)
 log=(output/(name+'.log')).read_text();result=json.loads((destination/'RESULTS.json').read_text())if(destination/'RESULTS.json').exists()else{}
 if run.returncode or result.get('status')!=expected or result.get('runtimeEvidence',{}).get('productionClassCollocatedWithSmokeOutput') is not False or 'Exception in thread' in log or 'BufferOverflowException' in log:
  print(log[-8000:],flush=True);raise SystemExit(f'{name} failed; no claim of completed pass')
 results[name]={'exitCode':run.returncode,'status':result['status'],'screenshots':len(list(destination.glob('*.png'))),'productionClassCollocatedWithSmokeOutput':False}
 print('PASS',name,results[name],flush=True)
(output/'SUMMARY.json').write_text(json.dumps(results,indent=2))
