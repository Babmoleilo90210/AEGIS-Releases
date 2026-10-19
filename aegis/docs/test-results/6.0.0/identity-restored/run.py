from pathlib import Path
import subprocess,hashlib,json,sys,xml.etree.ElementTree as ET
root=Path('/workspace/scratch/aa629f360927/aegis600/aegis');out=Path(__file__).resolve().parent;classes=out/'classes';classes.mkdir(exist_ok=True)
deps=root.parents[1]/'inputs600/maven-deps';jdk=root.parents[1]/'inputs600/toolchain/jdk-21.0.12.1+1/bin';junit=deps/'junit-platform-console-standalone-1.13.4.jar'
cp=':'.join(map(str,[classes,deps/'gson-2.14.0.jar',deps/'sqlite-jdbc-3.53.4.0.jar',deps/'slf4j-api-2.0.17.jar',deps/'slf4j-nop-2.0.17.jar',junit]))
files=list(root.glob('common-protocol/src/main/java/**/*.java'))+list(root.glob('identity-server/src/main/java/**/*.java'))
for name in ['net/TorTransport','community/CommunityJson','ecosystem/ComponentId','ecosystem/ComponentLease','ecosystem/SessionAuthority','ecosystemauth/DeviceCredentials600','ecosystemauth/DeviceApproval600','ecosystemauth/IdentityClient600','ecosystemauth/CoreAccountSession600','ecosystemauth/OwnerTransferFlow600','ecosystemauth/IdentityAdministrationFlow600']:
 files.append(root/('client-core/src/main/java/org/securemail/client/'+name+'.java'))
tests=list(root.glob('identity-server/src/test/java/**/*.java'))+[root/'client-core/src/test/java/org/securemail/client/ecosystemauth/IdentityAdministrationFlow600Test.java']
manifest={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files+tests};(out/'tested-sources.json').write_text(json.dumps(manifest,indent=2))
result={'scope':'actual Identity HTTP/SQLite and proof-of-possession administration; no native/Tor acceptance','sources':manifest}
for label,sources in [('main',files),('tests',tests)]:
 r=subprocess.run([str(jdk/'javac'),'--release','21','-encoding','UTF-8','-cp',cp,'-d',str(classes),*map(str,sources)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);(out/f'compile-{label}.log').write_text(r.stdout);print(r.stdout);print(label+'_COMPILE_EXIT',r.returncode)
 if r.returncode:result.update(exitCode=r.returncode,stage=label);(out/'RESULT.json').write_text(json.dumps(result,indent=2));sys.exit(r.returncode)
r=subprocess.run([str(jdk/'java'),'-jar',str(junit),'execute','--class-path',cp,'--select-package','org.securemail.identity','--select-class','org.securemail.client.ecosystemauth.IdentityAdministrationFlow600Test','--reports-dir',str(out/'junit'),'--details','summary','--disable-ansi-colors'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'test.log').write_text(r.stdout);print(r.stdout)
totals={k:0 for k in ['tests','failures','errors','skipped']}
for p in (out/'junit').glob('TEST-*.xml'):
 e=ET.parse(p).getroot()
 for k in totals:totals[k]+=int(e.attrib.get(k,'0'))
result.update(exitCode=r.returncode,sourceStable=all((root/p).exists() and hashlib.sha256((root/p).read_bytes()).hexdigest()==sha for p,sha in manifest.items()),totals=totals);(out/'RESULT.json').write_text(json.dumps(result,indent=2));print(json.dumps({k:v for k,v in result.items() if k!='sources'}));sys.exit(r.returncode)
