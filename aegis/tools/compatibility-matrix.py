#!/usr/bin/env python3
"""Bounded old released-client binary / independent relay subprocess compatibility."""
import argparse,pathlib,subprocess,os,shutil,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--jdk',required=True,type=pathlib.Path);p.add_argument('--baseline',required=True,type=pathlib.Path);p.add_argument('--base-app',required=True,type=pathlib.Path);p.add_argument('--deps',required=True,type=pathlib.Path);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];build=root/'build/local-java21';out=build/'compatibility';out.mkdir(exist_ok=True);jdk=a.jdk.resolve();base=a.baseline.resolve();app=a.base_app.resolve();deps=a.deps.resolve()
def run(cmd):subprocess.run(list(map(str,cmd)),check=True,timeout=120)
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
relaydeps=[x for x in deps.glob('*.jar') if x.name.startswith(('password4j-','sqlite-jdbc-','slf4j-'))]
old=out/'relay02/lib';old.mkdir(parents=True,exist_ok=True)
cp=list(relaydeps)
for module in ['common-protocol','relay-server']:
    classes=out/('old-'+module);classes.mkdir(exist_ok=True);source_list=out/(module+'.sources');source_list.write_text('\n'.join('"'+str(v)+'"' for v in sorted((base/module/'src/main/java').rglob('*.java')))+'\n')
    run([jdk/'bin/javac','--release','21','-encoding','UTF-8','-cp',os.pathsep.join(map(str,cp)),'-d',classes,'@'+str(source_list)])
    jar=old/(module+'.jar');run([jdk/'bin/jar','--create','--file',jar,'-C',classes,'.']);cp.append(jar)
new=out/'relay03/lib';new.mkdir(parents=True,exist_ok=True)
for destination in [old,new]:
    for dep in relaydeps:shutil.copy2(dep,destination/dep.name)
for module in ['common-protocol','relay-server']:shutil.copy2(build/(module+'.jar'),new/(module+'.jar'))
runtime=[jar for jar in (app/'app').glob('*.jar') if not jar.name.startswith(('relay-server-','client-ui-'))]+relaydeps
fresh=[jar for jar in runtime if not jar.name.startswith(('client-core-','common-protocol-'))]+[build/'client-core.jar',build/'common-protocol.jar']
smokes=root/'integration-tests/src/test/java/org/securemail/integration'
sources=[smokes/'SocksHarness.java',smokes/'Client10Relay02Smoke.java'];results=[]
for client,lib,cp in [('1.0.0','0.2.0',runtime),('1.0.0','0.3.0',runtime),('1.1.0','0.2.0',fresh)]:
    classes=out/('client-'+client);classes.mkdir(exist_ok=True);classpath=os.pathsep.join(map(str,cp+[classes]))
    run([jdk/'bin/javac','--release','21','-encoding','UTF-8','-cp',classpath,'-d',classes,*sources]);run([jdk/'bin/java','-Xmx768m','-Daegis.native.root='+str(app),'-cp',classpath,'org.securemail.integration.Client10Relay02Smoke',jdk/'bin/java',old if lib=='0.2.0' else new])
    results.append({'client':client,'relay':lib,'result':'PASS','transport':'synthetic SOCKS, not real Tor','relay02_provenance':'independently compiled verified 1.0.0 source archive; not downloaded production server binary'})
classes=out/'migration';classes.mkdir(exist_ok=True);classpath=os.pathsep.join(map(str,fresh+[classes]));run([jdk/'bin/javac','--release','21','-encoding','UTF-8','-cp',classpath,'-d',classes,smokes/'SocksHarness.java',smokes/'RelayMigrationSmoke.java']);run([jdk/'bin/java','-Xmx768m','-Daegis.native.root='+str(app),'-cp',classpath,'org.securemail.integration.RelayMigrationSmoke',jdk/'bin/java',old,new])
result={'oldReleasedClientJARs':{jar.name:sha(jar) for jar in runtime if jar.name.startswith(('client-core-','common-protocol-'))},'matrix':results,'SQLite02to03andBack':'PASS','nativeTorAcceptance':'NOT_RUN','productionChanges':False}
(build/'compatibility-matrix.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
