#!/usr/bin/env python3
"""Actual local HTTP/TCP/SOCKS Relay6 tests, no Tor/native/production claim."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,xml.etree.ElementTree as ET
p=argparse.ArgumentParser();p.add_argument('--jdk',required=True,type=Path);p.add_argument('--deps',action='append',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args();root=Path(__file__).resolve().parents[2];a.out.mkdir(parents=True,exist_ok=True);classes=a.out/'classes';classes.mkdir(exist_ok=True);jars=sorted({f.resolve() for d in a.deps for f in d.glob('*.jar')});cp=os.pathsep.join(map(str,jars));sources=[]
for module in ['common-protocol','identity-server','relay-server']:sources+=list((root/module/'src/main/java').rglob('*.java'))
sources+=list((root/'client-core/src/main/java/org/securemail/client/crypto').glob('*.java'))
for name in ['storage/LocalStore.java','storage/AtomicFiles.java','storage/AvatarCodec.java','lifecycle/DeviceCapabilities.java','net/NetworkService.java','net/TorTransport.java','net/PacketAcceptor.java','net/RequestRejected.java','ecosystemauth/IdentityRelayCredentials600.java']:sources.append(root/'client-core/src/main/java/org/securemail/client'/name)
sources+=list((root/'relay-server/src/test/java').rglob('*.java'));sources.append(root/'integration-tests/src/test/java/org/securemail/relay/RelayIdentity600Test.java');sources=sorted(sources)
source_hashes={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sources}
r=subprocess.run([str(a.jdk/'bin/javac'),'-encoding','UTF-8','-g','-cp',cp,'-d',str(classes),*map(str,sources)],capture_output=True,text=True);(a.out/'javac.log').write_text(r.stdout+r.stderr);print(r.stdout+r.stderr,end='');report={'compileExit':r.returncode,'scope':'real local HTTP/SQL/Ed25519, no Tor/native/physical claim','sources':source_hashes}
if r.returncode:(a.out/'RESULTS.json').write_text(json.dumps(report,indent=2));raise SystemExit(r.returncode)
r=subprocess.run([str(a.jdk/'bin/java'),'-cp',str(classes)+os.pathsep+cp,'org.junit.platform.console.ConsoleLauncher','execute','--select-class','org.securemail.relay.RelayIdentity600Test','--select-class','org.securemail.relay.IdentityLoopback600Test','--select-class','org.securemail.relay.OpenRegistrationTest','--select-class','org.securemail.relay.RelayMain600Test','--disable-ansi-colors','--reports-dir',str(a.out/'junit')],capture_output=True,text=True);(a.out/'junit.log').write_text(r.stdout+r.stderr);print(r.stdout+r.stderr,end='');report['testExit']=r.returncode;xml=a.out/'junit/TEST-junit-jupiter.xml';suite=ET.parse(xml).getroot();report['tests']={k:suite.attrib[k] for k in ['tests','skipped','failures','errors','time','timestamp']};
# Enforce the original classloader-isolation assertion in its actual production dependency set.
iso=a.out/'isolated-runtime';iso.mkdir(exist_ok=True)
isojars=[j for j in jars if j.name.startswith(('gson-','sqlite-jdbc-','password4j-','slf4j-api-','slf4j-nop-','junit-platform-console-standalone-','apiguardian-api-'))]
isocp=os.pathsep.join(map(str,isojars));isosources=sorted([*(root/'common-protocol/src/main/java').rglob('*.java'),*(root/'relay-server/src/main/java').rglob('*.java'),root/'relay-server/src/test/java/org/securemail/relay/IsolationTest.java'])
ic=subprocess.run([str(a.jdk/'bin/javac'),'-encoding','UTF-8','-cp',isocp,'-d',str(iso),*map(str,isosources)],capture_output=True,text=True);(a.out/'isolation-javac.log').write_text(ic.stdout+ic.stderr)
if ic.returncode==0:
 ir=subprocess.run([str(a.jdk/'bin/java'),'-cp',str(iso)+os.pathsep+isocp,'org.junit.platform.console.ConsoleLauncher','execute','--select-class','org.securemail.relay.IsolationTest','--disable-ansi-colors','--reports-dir',str(a.out/'isolation-junit')],capture_output=True,text=True);(a.out/'isolation-junit.log').write_text(ir.stdout+ir.stderr);report['isolationExit']=ir.returncode
else:report['isolationExit']=ic.returncode
report['isolationRuntimeJars']=[j.name for j in isojars];report['testExit']=r.returncode or report['isolationExit']
report['sourceStable']=source_hashes=={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sources};report['status']='PASS_LOCAL' if report['testExit']==0 and report['sourceStable'] else 'SOURCE_CHANGED' if not report['sourceStable'] else 'FAIL';(a.out/'RESULTS.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');raise SystemExit(report['testExit'] or (0 if report['sourceStable'] else 2))
