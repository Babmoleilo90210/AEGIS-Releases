#!/usr/bin/env python3
"""Offline Java 21 compiler/JUnit fallback for an explicitly supplied verified dependency set.

Gradle remains the normal build. This script never downloads dependencies and does not
mark a native platform acceptance successful. --deps may be repeated for runtime/test jars.
"""
import argparse, os, pathlib, subprocess, sys, shutil, json, time

parser=argparse.ArgumentParser()
parser.add_argument('--jdk',required=True,type=pathlib.Path)
parser.add_argument('--deps',required=True,action='append',type=pathlib.Path)
parser.add_argument('--native-root',required=True,type=pathlib.Path)
parser.add_argument('--skip-tests',action='store_true')
args=parser.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
jdk=args.jdk.resolve(); native=args.native_root.resolve()
deps=[]
for folder in args.deps:
    deps.extend(p.resolve() for p in folder.glob('*.jar')
                if not p.name.startswith(('client-core-','client-ui-','common-protocol-','relay-server-','community-server-','news-worker-')))
version=subprocess.run([str(jdk/'bin/javac'),'-version'],check=True,text=True,capture_output=True).stdout
if not all((native/'native'/name).is_file() for name in ['libsodium.so','libopus.so','libspeexdsp.so']):
    sys.exit('--native-root must be the reviewed bundle root containing native/*.so')
if not version.startswith('javac 21.'):
    sys.exit('Java 21 JDK is required, got '+version)
out=root/'build/local-java21';out.mkdir(parents=True,exist_ok=True)
classpath=list(deps)
for module in ['common-protocol','client-core','relay-server','community-server','news-worker','client-ui']:
    classes=out/module/'classes';shutil.rmtree(classes,ignore_errors=True);classes.mkdir(parents=True)
    sources=sorted((root/module/'src/main/java').rglob('*.java'))
    source_list=out/(module+'.sources')
    source_list.write_text('\n'.join('"'+str(p).replace('\\','\\\\').replace('"','\\"')+'"' for p in sources)+'\n')
    subprocess.run([str(jdk/'bin/javac'),'--release','21','-encoding','UTF-8','-Xlint:all',
                    '-parameters','-cp',os.pathsep.join(map(str,classpath)),'-d',str(classes),
                    '@'+str(source_list)],check=True,timeout=120)
    resources=root/module/'src/main/resources'
    jar=out/(module+'.jar')
    command=[str(jdk/'bin/jar'),'--create','--file',str(jar),'-C',str(classes),'.']
    if resources.is_dir():command+=['-C',str(resources),'.']
    subprocess.run(command,check=True,timeout=30)
    classpath.append(jar)
if not args.skip_tests:
    testclasses=out/'tests';shutil.rmtree(testclasses,ignore_errors=True);testclasses.mkdir()
    sources=sorted(p for module in ['common-protocol','client-core','relay-server','community-server','news-worker','integration-tests']
                   for p in (root/module/'src/test/java').rglob('*.java'))
    source_list=out/'tests.sources';source_list.write_text('\n'.join('"'+str(p)+'"' for p in sources)+'\n')
    subprocess.run([str(jdk/'bin/javac'),'--release','21','-encoding','UTF-8','-cp',
                    os.pathsep.join(map(str,classpath)),'-d',str(testclasses),'@'+str(source_list)],
                   check=True,timeout=120)
    console=next(p for p in deps if p.name.startswith('junit-platform-console-standalone-'))
    # Relay isolation must be checked in a JVM which never loads client crypto.
    runtimes={
      'common-protocol':([console,out/'common-protocol.jar'],'org.securemail.protocol'),
      'client-core':(deps+[out/'common-protocol.jar',out/'client-core.jar'],'org.securemail.client'),
      'relay-server':([p for p in deps if p.name.startswith(('password4j-','sqlite-jdbc-','slf4j-','junit-platform-console-'))]+[out/'common-protocol.jar',out/'relay-server.jar'],'org.securemail.relay'),
      'community-server':(deps+[out/'common-protocol.jar',out/'community-server.jar'],'org.securemail.community'),
      'news-worker':(deps+[out/'common-protocol.jar',out/'community-server.jar',out/'news-worker.jar'],'org.securemail.worker'),
      'integration-tests':(deps+[out/'common-protocol.jar',out/'client-core.jar',out/'relay-server.jar',out/'community-server.jar',out/'news-worker.jar'],'org.securemail.integration')}
    results=[]
    for module,(runtime,package) in runtimes.items():
      started=time.monotonic()
      result=subprocess.run([str(jdk/'bin/java'),'-Xmx768m','-Daegis.native.root='+str(native),
                      '-jar',str(console),'execute','--class-path',os.pathsep.join(map(str,runtime+[testclasses])),
                      '--select-package',package,'--reports-dir',str(out/'junit'/module),
                      '--details=summary'],check=False,timeout=1200)
      results.append({'module':module,'exitCode':result.returncode,'seconds':round(time.monotonic()-started,3)})
    (out/'TEST-EXECUTION.json').write_text(json.dumps({'scope':'actual JUnit; native acceptance is separate','modules':results},indent=2)+'\n')
    if any(r['exitCode'] for r in results):sys.exit('JUnit failures; see module XML and TEST-EXECUTION.json')
print('Java 21 build complete; native acceptance is separate.')
