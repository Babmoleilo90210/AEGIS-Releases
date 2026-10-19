#!/usr/bin/env python3
"""Real local Identity/signaling/controller/TLS/Opus integration; routing and hardware remain fixtures."""
import argparse,hashlib,json,os,pathlib,subprocess,tempfile
HERE=pathlib.Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--jdk',type=pathlib.Path,required=True);p.add_argument('--deps',type=pathlib.Path,required=True);p.add_argument('--sdk',type=pathlib.Path,required=True);p.add_argument('--android-work',type=pathlib.Path,required=True);p.add_argument('--audio',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();root=HERE.parent;out=a.out.resolve();out.mkdir(parents=True,exist_ok=True);work=pathlib.Path(tempfile.mkdtemp(prefix='compile-',dir=out));classes=work/'classes';classes.mkdir();
 deps=sorted(a.deps.resolve().glob('*.jar'))+[a.sdk.resolve()/'bctls-jdk18on-1.86.jar'];support=root/'client-core/build/classes/java/main';android=a.android_work.resolve();cp=os.pathsep.join(map(str,[classes,android/'test-classes',android/'classes',support]+deps))
 sources=[]
 for module in ['common-protocol','identity-server']:sources+=sorted((root/module/'src/main/java').rglob('*.java'))
 sources += [root/'attachment-service/src/main/java/org/securemail/attachments/IdentityRemoteAuthority.java',root/'attachment-service/src/main/java/org/securemail/attachments/AttachmentStore.java',root/'glas-signaling/src/main/java/org/securemail/glas/signaling/GlasRegistry600.java',root/'glas-signaling/src/main/java/org/securemail/glas/signaling/GlasSignalingHttp600.java']
 names=['VoiceCallService','VoiceLocalStore600','VoiceHistory','VoiceCallPolicy','VoiceOrganizationAuthorizer','VoiceTls','VoiceFrames'];sources += [root/'client-core/src/main/java/org/securemail/client/voice'/(n+'.java')for n in names]
 sources += [HERE/'integration-test/org/securemail/client/voice/AndroidGlasCallIntegration.java']
 inputs=sources+[pathlib.Path(__file__).resolve()]+sorted((android/'classes').rglob('*.class'))+sorted((android/'test-classes').rglob('*.class'))+sorted(support.rglob('*.class'));before={str(f):sha(f)for f in inputs};native=a.audio.resolve()/'host/libaegis_audio.so';native_sha=sha(native);env=os.environ.copy()
 command=[str(a.jdk/'bin/javac'),'-encoding','UTF-8','-cp',cp,'-d',str(classes),*map(str,sources)];r=subprocess.run(command,capture_output=True,text=True,timeout=120);(out/'compile.log').write_text(r.stdout+r.stderr)
 if r.returncode:print(r.stdout+r.stderr);raise SystemExit(r.returncode)
 command=[str(a.jdk/'bin/java'),'-Djava.library.path='+str(a.audio.resolve()/'host'),'-cp',cp,'org.securemail.client.voice.AndroidGlasCallIntegration'];r=subprocess.run(command,capture_output=True,text=True,timeout=120,env=env);(out/'test.log').write_text(r.stdout+r.stderr);stable=before=={str(f):sha(f)for f in inputs}and native_sha==sha(native);result={'status':'PASS_LOCAL'if r.returncode==0 and stable else'FAIL','exit':r.returncode,'sourceStable':stable,'inputSha256':before,'nativeAudioHostSha256':native_sha,'scope':'actual Identity SQL/HTTP + signaling SQL/HTTP + Android adapted existing controller + original desktop controller/TLS + real JNI Opus/Speex. Onion route/SOCKS and PCM devices are explicit fixtures. Android/live Tor NOT_RUN'};(out/'RESULTS.json').write_text(json.dumps(result,indent=2)+'\n');print(r.stdout+r.stderr);raise SystemExit(r.returncode or(0 if stable else 2))
if __name__=='__main__':main()
