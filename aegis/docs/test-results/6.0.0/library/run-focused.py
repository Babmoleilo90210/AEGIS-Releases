from pathlib import Path
import subprocess,json,hashlib,datetime
base=Path('/workspace/scratch/aa629f360927');root=base/'aegis600/aegis';out=base/'audit600/library/actual-tests';out.mkdir(exist_ok=True)
jdk=base/'inputs600/toolchain/jdk-21.0.12.1+1/bin'
cp=':'.join(str(p) for p in list((base/'audit600/library/test-deps').glob('*.jar'))+list((base/'inputs600/linux500/squashfs-root/app').glob('*.jar'))+[base/'inputs600/test-deps/junit-platform-console-standalone-1.13.4.jar'])
src=[]
for module in ['client-core','community-server']:
 for kind in ['main','test']:src+=list((root/module/'src'/kind/'java').glob('org/securemail/**/library600/*.java'))
src += [root/'common-protocol/src/main/java/org/securemail/ecosystem/protocol/IdentityProtocol.java',root/'common-protocol/src/main/java/org/securemail/library/protocol600/LibraryWire600.java',root/'client-core/src/main/java/org/securemail/client/net/TorTransport.java',root/'client-core/src/main/java/org/securemail/client/community/CommunityJson.java']
src += list((root/'identity-server/src/main/java').rglob('*.java'))
src += [root/'client-core/src/main/java/org/securemail/client/maintenance600/RuntimeLease600.java']
src += [root/'community-server/src/main/java/org/securemail/community/access/AccessControl.java',root/'community-server/src/main/java/org/securemail/community/core/CommunityStore.java',root/'community-server/src/main/java/org/securemail/community/gateway600/TrustedContext600.java',root/'client-core/src/main/java/org/securemail/client/safeweb/ObsidianWindowsBoundary600.java']
source_hashes={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in src}
commands=[]
cmd=[str(jdk/'javac'),'--release','21','-cp',cp,'-d',str(out/'classes')]+[str(p) for p in src]
commands.append(cmd);r=subprocess.run(cmd,capture_output=True,text=True);(out/'compile.log').write_text(r.stdout+r.stderr);print('compile',r.returncode,flush=True)
if r.returncode:print(r.stdout+r.stderr);raise SystemExit(r.returncode)
cmd=[str(jdk/'java'),'-cp',str(out/'classes')+':'+cp,'org.junit.platform.console.ConsoleLauncher','execute','--scan-classpath='+str(out/'classes'),'--include-package','org.securemail.client.library600','--include-package','org.securemail.community.library600','--include-package','org.securemail.client.safeweb','--reports-dir',str(out/'xml'),'--details','tree']
commands.append(cmd);r=subprocess.run(cmd,capture_output=True,text=True,timeout=120);(out/'junit.log').write_text(r.stdout+r.stderr);print(r.stdout+r.stderr,flush=True)
proof={'when':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exitCode':r.returncode,'scope':'Real Identity and Library HTTP services, JCA proof/signature, SQLite/content ACL, production TorTransport via SOCKS loopback fixture, filesystem projection. Unit Authority fixture separate. NOT real Tor, Syncthing process, native Obsidian or Android.','commands':commands,'sources':source_hashes,'dependencySha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (base/'audit600/library/test-deps').glob('*.jar')}}
assert source_hashes=={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in src}, 'Source changed during tests'
(out/'RESULTS.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n');raise SystemExit(r.returncode)
