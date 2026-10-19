from pathlib import Path
import subprocess,json,hashlib,os
b=Path('/workspace/scratch/aa629f360927');root=b/'aegis600/aegis';out=b/'audit600/library/ui';out.mkdir(exist_ok=True)
cp=':'.join([str(b/'audit600/library/actual-tests/classes')]+[str(p)for p in (b/'audit600/library/test-deps').glob('*.jar')]+[str(p)for p in (b/'inputs600/linux500/squashfs-root/app').glob('*.jar')])
sources=[root/'client-ui/src/main/java/org/securemail/ui/LibraryLauncherView600.java',root/'client-ui/src/smoke/java/org/securemail/ui/LibraryLauncherSmoke600.java',root/'client-core/src/main/java/org/securemail/client/ecosystemauth/IdentityClient600.java'];hashes={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sources}
cmd=[str(b/'inputs600/toolchain/jdk-21.0.12.1+1/bin/javac'),'--release','21','-cp',cp,'-d',str(out/'classes')]+[str(p)for p in sources];r=subprocess.run(cmd,capture_output=True,text=True);(out/'compile.log').write_text(r.stdout+r.stderr);(out/'COMPILE.json').write_text(json.dumps({'command':cmd,'exitCode':r.returncode,'sources':hashes},indent=2));print('compile',r.returncode,flush=True)
if r.returncode:print(r.stdout+r.stderr);raise SystemExit(r.returncode)
cmd=[str(b/'inputs600/toolchain/jdk-21.0.12.1+1/bin/java'),'-Dprism.order=sw','-Dglass.platform=Monocle','-Dmonocle.platform=Headless','-Dheadless.geometry=1280x900-32','-Daegis.library600.output='+str(out/'screenshots'),'-cp',str(out/'classes')+':'+cp+':'+str(b/'inputs600/test-deps/openjfx-monocle-21.0.2.jar'),'org.securemail.ui.LibraryLauncherSmoke600']
r=subprocess.run(cmd,capture_output=True,text=True,timeout=120);(out/'run.log').write_text(r.stdout+r.stderr);print(r.returncode);print(r.stdout+r.stderr)
assert hashes=={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sources},'Source changed during UI run'
(out/'RUN.json').write_text(json.dumps({'command':cmd,'exitCode':r.returncode,'sources':hashes},indent=2));raise SystemExit(r.returncode)
