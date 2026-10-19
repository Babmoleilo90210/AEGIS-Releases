#!/usr/bin/env python3
"""Pinned SDK tools build four useful, incomplete Android security candidates, not Stable.

No Gradle root change, Android Studio, Firebase, or owner key is needed. Native source is verified separately.
"""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, sys, zipfile, tempfile

HERE=pathlib.Path(__file__).resolve().parent
PINNED={
    'annotation-1.1.0.jar':'d38d63edb30f1467818d50aaf05f8a692dea8b31392a049bfa991b159ad5b692',
    'tor-android-0.4.9.14-sources.jar':'095118a41782a91b9002038461c4c6a65f5c41bc6f5a37323362eceaf0088a2b',
    'tor-android-0.4.9.14.aar':'28ff2bb6d4d42eabe57183dedd7a97fce77e8ce4b6f5af6fa03993b3ca054edd',
    'jtorctl-0.4.5.7.jar':'51bbed22de9fe0028095223ceeb4694d8731eda2fc01edee07b8c0c8a46681c3',
    'localbroadcastmanager-1.1.0.aar':'a22b94a77789f3b34becd24082231300524011ccc83f026142c49ad60131379b',
    'platform-36_r02.zip':'37607369a28c5b640b3a7998868d45898ebcb777565a0e85f9acf36f29631d2e',
    'build-tools_r36.1_linux.zip':'a7b5889e4a79fcf3b0976bef40d401f4240fb1eed891d9d91169da1111e11d78',
    'apksig-9.4.1.jar':'7ae2e5980c77d853e3513074ee7c822bbdcdcde1668889d17faa7fe8bc8aa821',
    'gson-2.14.0.jar':'2cbd119bf1961c28788310963dc80ba65f58cdeec1dd139c8bdb1240faa2c36f',
    'bcprov-jdk18on-1.86.jar':'2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f',
    'tink-1.23.0.jar':'5bcdc8798ce106f5145acb4a0e993c5e5861337b1e75ca88ceb6ab9da10fa512',
    'protobuf-java-4.33.6.jar':'c24b2464ecfe9ac1d44e3a8fe281fca09e6ad2ca73dbd689dd7d6d719df987b5',
    'bctls-jdk18on-1.86.jar':'418e46d6ffd27c3226268533b6321daec899129b1ec8ede35331c7d78e11e535',
    'bcutil-jdk18on-1.86.jar':'1c268e15f785aafb1e4670d8d6e5f856f69475e96c162dadcd1ff9b350e9139f',
    'zip4j-2.11.6.jar':'5f1eb1e9d67cfee200a695e4079751b49e73a226b154193e13f7c602efbe72fb',
}
APPS=[('Core','org.aegis.core','АЕГИС'),('Mail','org.aegis.mail','Почта'),('Glas','org.aegis.glas','Глас'),('Strazh','org.aegis.strazh','Страж')]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(cmd,env,cwd=None,check=True):
    r=subprocess.run([str(x) for x in cmd],cwd=cwd,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    print(r.stdout,end='',flush=True)
    if check and r.returncode:raise RuntimeError('Build command failed: '+str(cmd[0]))
    return r
def write(path,text):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text,encoding='utf-8')
def manifest(package,label):
    extra=''
    if package=='org.aegis.core':extra='''<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED"/><uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE"/>
    <permission android:name="org.aegis.permission.ECOSYSTEM" android:protectionLevel="signature"/>'''
    if package=='org.aegis.glas':extra='''<uses-permission android:name="android.permission.INTERNET"/><uses-permission android:name="android.permission.RECORD_AUDIO"/><uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS"/>'''
    if package=='org.aegis.mail':extra='<uses-permission android:name="android.permission.INTERNET"/>'
    core=package=='org.aegis.core'
    activityPermission='' if core else 'android:permission="org.aegis.permission.ECOSYSTEM"'
    filters='''<intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>''' if core else ''
    service='''<service android:name="org.aegis.android.CoreTorService" android:process=":tor" android:exported="false" android:foregroundServiceType="specialUse"><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="User-initiated Tor onion transport for secure AEGIS applications"/></service><service android:name="org.aegis.android.CoreBrokerService" android:exported="true" android:permission="org.aegis.permission.ECOSYSTEM"/><receiver android:name="org.aegis.android.InstallResultReceiver" android:exported="false"/><service android:name="org.aegis.android.NetworkVpnService" android:exported="true" android:permission="android.permission.BIND_VPN_SERVICE" android:foregroundServiceType="systemExempted"><intent-filter><action android:name="android.net.VpnService"/></intent-filter><meta-data android:name="android.net.VpnService.SUPPORTS_ALWAYS_ON" android:value="false"/></service>''' if core else ''
    return f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}" android:versionCode="60000" android:versionName="6.0.0-test">
    <uses-sdk android:minSdkVersion="33" android:targetSdkVersion="36"/>
    <uses-permission android:name="org.aegis.permission.ECOSYSTEM"/><uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS"/><uses-permission android:name="android.permission.USE_BIOMETRIC"/>{extra}
    <queries><package android:name="org.aegis.core"/><package android:name="org.aegis.mail"/><package android:name="org.aegis.glas"/><package android:name="org.aegis.strazh"/></queries>
    <application android:label="{label}" android:theme="@style/AegisTheme" android:icon="@drawable/aegis_icon" android:allowBackup="false" android:fullBackupContent="false" android:usesCleartextTraffic="false" android:debuggable="false" android:extractNativeLibs="false" android:requestLegacyExternalStorage="false" android:enableOnBackInvokedCallback="true">
    <activity android:name="org.aegis.android.MainActivity" android:exported="true" {activityPermission}>{filters}</activity>{service}
    </application></manifest>'''
def main():
    p=argparse.ArgumentParser();p.add_argument('--sdk',required=True,type=pathlib.Path);p.add_argument('--jdk',required=True,type=pathlib.Path);p.add_argument('--out',type=pathlib.Path,default=HERE/'build'/'artifacts');p.add_argument('--expected-commit');p.add_argument('--native',required=True,type=pathlib.Path);p.add_argument('--tun',required=True,type=pathlib.Path);p.add_argument('--audio',required=True,type=pathlib.Path);a=p.parse_args();sdk=a.sdk.resolve();jdk=a.jdk.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
    git=subprocess.run(['git','-C',str(HERE.parent),'rev-parse','HEAD'],text=True,capture_output=True);commit=git.stdout.strip() if git.returncode==0 else None
    state=subprocess.run(['git','-C',str(HERE.parent),'status','--porcelain'],text=True,capture_output=True);dirty=bool(state.stdout.strip())
    if a.expected_commit and (commit!=a.expected_commit or dirty):raise SystemExit('Expected clean frozen source commit is not available')
    for name,expected in PINNED.items():
        path=sdk/name
        if not path.is_file() or sha(path)!=expected:raise SystemExit('Pinned SDK input mismatch: '+name)
    tools=sdk/'build-tools'/'36.1.0';android=sdk/'platforms'/'android-36'/'android.jar';apksig=sdk/'apksig-9.4.1.jar';gson=sdk/'gson-2.14.0.jar';work=pathlib.Path(tempfile.mkdtemp(prefix='aegis-android-build-',dir=out.parent))
    native=a.native.resolve();nativeReport=json.loads((native/'NATIVE-PROVENANCE.json').read_text());nativeLibrary=native/'lib/arm64-v8a/libaegis_sodium.so';assert sha(nativeLibrary)==nativeReport['arm64LibrarySha256'];assert nativeReport['sourceSha256']=='0a7f69b065b82afdb1470375ffa1cee4ecb066180cca05a71e44e3268cd8470d';assert nativeReport['jniSourceSha256']==sha(HERE/'native/aegis_sodium.c');assert nativeReport['hostLibrarySha256']==sha(native/'host/libaegis_sodium.so')
    tun=a.tun.resolve();tunReport=json.loads((tun/'TUN-PROVENANCE.json').read_text());tunLibrary=tun/'lib/arm64-v8a/libhev-socks5-tunnel.so';assert sha(tunLibrary)==tunReport['librarySha256'];assert tunReport['bridgeSha256']==sha(HERE/'native/aegis_tun_bridge.c')
    audio=a.audio.resolve();audioReport=json.loads((audio/'AUDIO-PROVENANCE.json').read_text());audioLibrary=audio/'lib/arm64-v8a/libaegis_audio.so';assert sha(audioLibrary)==audioReport['arm64LibrarySha256'];assert audioReport['jniSourceSha256']==sha(HERE/'native/aegis_audio.c');assert audioReport['hostLibrarySha256']==sha(audio/'host/libaegis_audio.so')
    bc=sdk/'bcprov-jdk18on-1.86.jar';zip4j=sdk/'zip4j-2.11.6.jar';deps=[apksig,gson,bc,zip4j,sdk/'bctls-jdk18on-1.86.jar',sdk/'bcutil-jdk18on-1.86.jar',sdk/'tink-1.23.0.jar',sdk/'protobuf-java-4.33.6.jar']
    torSources=[]
    for artifact in ['tor-android-0.4.9.14','localbroadcastmanager-1.1.0']:

        with zipfile.ZipFile(sdk/(artifact+'.aar'))as z:
            jar=work/(artifact+'-classes.jar');jar.write_bytes(z.read('classes.jar'))
            if not artifact.startswith('tor-'):deps.append(jar)
            if artifact.startswith('tor-'):
                torLibrary=work/'libtor.so';torLibrary.write_bytes(z.read('jni/arm64-v8a/libtor.so'))
                with zipfile.ZipFile(jar)as classesJar:
                    for name in classesJar.namelist():
                        if name.endswith('.class')and (b'kotlin/'in classesJar.read(name)or b'kotlin.'in classesJar.read(name)):raise RuntimeError('Unexpected Kotlin runtime dependency in pinned Tor AAR')
    # The signed upstream AAR uses Java24 class files; recompile its separately
    # OpenPGP-verified exact source unchanged for API33/D8 instead of lowering class headers.
    with zipfile.ZipFile(sdk/'tor-android-0.4.9.14-sources.jar')as sourcesJar:
        for name in ['org/torproject/jni/TorService.java','org/torproject/jni/BuildConfig.java']:
            target=work/'tor-source'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(sourcesJar.read(name));torSources.append(target)
    deps +=[sdk/'jtorctl-0.4.5.7.jar',sdk/'annotation-1.1.0.jar']
    env=os.environ.copy();env['JAVA_HOME']=str(jdk);env['PATH']=str(jdk/'bin')+os.pathsep+env.get('PATH','')
    shared=HERE.parent/'common-protocol/src/main/java/org/securemail/ecosystem/protocol/IdentityProtocol.java'
    reused=[HERE.parent/'client-core/src/main/java'/f for f in ['org/securemail/client/ecosystemauth/IdentityClient600.java','org/securemail/client/net/TorTransport.java','org/securemail/client/community/CommunityJson.java']]+[HERE.parent/'common-protocol/src/main/java/org/securemail/protocol/Limits.java']
    protocol=sorted((HERE.parent/'common-protocol/src/main/java/org/securemail/protocol').glob('*.java'));reused=[x for x in reused if x.name!='Limits.java']+protocol
    cryptoRoot=HERE.parent/'client-core/src/main/java/org/securemail/client';originals=[cryptoRoot/'crypto'/x for x in ['Identity.java','PlainMessage.java','AutomaticEncryption.java','MailContext.java','Secrets.java','LetterEnvelope.java','LetterKdf.java']]+[cryptoRoot/'storage/AtomicFiles.java']+[cryptoRoot/'voice/GlasAudioSession.java',cryptoRoot/'voice/GlasJitterBuffer.java',cryptoRoot/'voice600/GlasGrant600.java']+[cryptoRoot/'attachments600'/n for n in ['AttachmentManifest600.java','StreamingAttachmentCipher.java','AttachmentClient600.java']]
    generated=[]
    for original in originals:
        # Mechanical Java API compatibility only; no field/wire/cipher changes.
        text=original.read_text().replace('HexFormat.of()','org.aegis.android.AndroidHex.INSTANCE').replace('.getFirst()','.get(0)').replace('.toList()','.collect(java.util.stream.Collectors.toList())')
        target=work/'compat'/original.relative_to(cryptoRoot.parent.parent.parent);write(target,text);generated.append(target)
    tlsOriginal=cryptoRoot/'voice/VoiceTls.java';tlsTarget=work/'compat/org/securemail/client/voice/AndroidVoiceTls.java';run([sys.executable,HERE/'voice-tls-adapter.py',tlsOriginal,tlsTarget],env);generated.append(tlsTarget)
    glasProtocol=HERE.parent/'common-protocol/src/main/java/org/securemail/glas/protocol600/GlasProtocol600.java';reused.append(glasProtocol);reused.append(HERE.parent/'common-protocol/src/main/java/org/securemail/attachments/protocol/AttachmentProtocol.java')
    controllerNames=['VoiceCallService','VoiceLocalStore600','VoiceHistory','VoiceCallPolicy','VoiceOrganizationAuthorizer'];controllerInputs=[cryptoRoot/'voice'/(name+'.java')for name in controllerNames]+[cryptoRoot/'voice600/GlasSignalingClient600.java',cryptoRoot/'voice600/GlasOnionTransport600.java'];run([sys.executable,HERE/'voice-controller-adapter.py',HERE.parent,work/'controller-compat'],env);generated+=sorted((work/'controller-compat').rglob('*.java'));reused.append(cryptoRoot/'voice/VoiceFrames.java')
    def input_inventory():return [HERE.parent/'common-protocol/src/main/java/org/securemail/ecosystem/protocol/MailSessionProtocol600.java']+sorted((HERE/'src').rglob('*.java'))+sorted((HERE/'compat').rglob('*.java'))+[shared]+reused+originals+sorted(x for x in (HERE/'native').rglob('*')if x.is_file())+sorted(x for x in (HERE/'test').rglob('*')if x.is_file())+sorted((HERE/'third-party').glob('*'))+controllerInputs+[tlsOriginal,HERE/'voice-controller-adapter.py',HERE/'voice-tls-adapter.py',HERE/'build-native.py',HERE/'build-tun.py',HERE/'build-audio.py',HERE/'test-mail-relay.py',HERE/'test-glas.py']+sorted((HERE/'integration-test').rglob('*.java'))+sorted((HERE/'host-test').rglob('*.java'))
    sourceInputs=input_inventory()
    sharedMail=HERE.parent/'common-protocol/src/main/java/org/securemail/ecosystem/protocol/MailSessionProtocol600.java'
    reused.append(sharedMail)
    source=sorted((HERE/'src').rglob('*.java'))+sorted((HERE/'compat').rglob('*.java'))+[shared]+reused+generated+torSources
    before={str(f.relative_to(HERE.parent)):sha(f)for f in sourceInputs};before['android/build.py']=sha(pathlib.Path(__file__))
    classes=work/'classes';classes.mkdir(exist_ok=True)
    run([jdk/'bin/javac','--release','17','-encoding','UTF-8','-Xlint:all','-classpath',os.pathsep.join(str(x)for x in [android]+deps),'-d',classes,*source],env)
    prodjar=work/'android-code.jar';run([jdk/'bin/jar','--create','--date=1980-01-01T00:00:02Z','--file',prodjar,'-C',classes,'.'],env)
    dex=work/'dex';dex.mkdir(exist_ok=True)
    run([tools/'d8','--release','--min-api','33','--lib',android,'--output',dex,prodjar,*deps],env)
    testClasses=work/'test-classes';testClasses.mkdir(exist_ok=True)
    testSources=[shared,HERE/'src/org/securemail/client/voice600/AndroidGlasState.java']+[HERE/'src/org/aegis/android'/x for x in ['AndroidPolicy.java','ApkSafety.java','AppGrantProposal.java','AndroidHex.java','MailBackup.java','DomainRules.java','NetworkGateway.java','NativeTun.java','VoiceHandoff.java','VoiceEndpointProof.java','TorRuntimePolicy.java','BrokerLease.java','MicrophonePermissionGate.java']]+[x for x in sorted((HERE/'compat').rglob('*.java')) if x.name not in ['GlasAudioDevices.java','AndroidAudioSetup.java']]+reused+generated+sorted((HERE/'test').rglob('*.java'))+sorted((HERE/'host-test').rglob('*.java'))+[tlsOriginal]
    testcp=os.pathsep.join(str(x)for x in [testClasses]+deps)
    run([jdk/'bin/javac','--release','17','-encoding','UTF-8','-cp',os.pathsep.join(str(x)for x in deps),'-d',testClasses,*testSources],env)
    testLog='';testenv=env.copy();testenv['LD_LIBRARY_PATH']=str(tun/'host')+os.pathsep+testenv.get('LD_LIBRARY_PATH','')
    for test in ['AndroidPolicyTest','AppGrantProposalTest','OnionTransportTest','MailCryptoTest','NetworkGatewayTest','TunEngineHostTest','VoiceHandoffTest','TorRuntimePolicyTest','AndroidLifecyclePolicyTest','org.securemail.client.voice.AndroidAudioHostTest','org.securemail.client.voice.AndroidTlsInteropHostTest']:
        tests=run([jdk/'bin/java','-Djava.library.path='+str(native/'host')+os.pathsep+str(tun/'host')+os.pathsep+str(audio/'host'),'-cp',testcp,test if '.'in test else 'org.aegis.android.'+test],testenv);testLog+=tests.stdout
    write(out/'ANDROID-JVM-TESTS-6.0.0.log',testLog)
    cert=HERE/'build'/'TEST-ONLY.jks'
    if not cert.exists():run([jdk/'bin/keytool','-genkeypair','-keystore',cert,'-storepass','android','-keypass','android','-alias','aegis-test-only','-keyalg','RSA','-keysize','3072','-validity','365','-dname','CN=AEGIS TEST ONLY DO NOT TRUST,OU=Development,O=AEGIS'],env)
    outputs=[];verification={}
    for name,package,label in APPS:
        app=work/name;app.mkdir(exist_ok=True);res=app/'res';write(res/'values/styles.xml','''<resources><style name="AegisTheme" parent="android:style/Theme.Material.NoActionBar"><item name="android:fontFamily">sans</item><item name="android:colorAccent">#86B9E8</item><item name="android:windowLightStatusBar">false</item><item name="android:statusBarColor">#101C31</item><item name="android:navigationBarColor">#101C31</item><item name="android:windowBackground">#101C31</item></style></resources>''')
        write(res/'drawable/aegis_icon.xml','''<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="24dp" android:height="24dp" android:viewportWidth="24" android:viewportHeight="24"><path android:fillColor="#101C31" android:pathData="M0,0h24v24h-24z"/><path android:fillColor="#00000000" android:strokeColor="#D8E8F8" android:strokeWidth="1.5" android:pathData="M12,3L20,6L19,14Q17,19 12,22Q7,19 5,14L4,6Z M8,13L11,16L17,9"/></vector>''')
        mf=app/'AndroidManifest.xml';write(mf,manifest(package,label));flat=app/'resources.zip';linked=app/'linked.apk'
        run([tools/'aapt2','compile','--dir',res,'-o',flat],env)
        run([tools/'aapt2','link','-o',linked,'--manifest',mf,'-I',android,flat],env)
        unaligned=app/'unaligned.apk'
        with zipfile.ZipFile(linked)as z,zipfile.ZipFile(unaligned,'w',zipfile.ZIP_DEFLATED,compresslevel=9)as dest:
            def member(name,data,stored=False):
                entry=zipfile.ZipInfo(name,(1980,1,1,0,0,2));entry.compress_type=zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED;entry.external_attr=0o100644<<16;dest.writestr(entry,data)
            for item in z.infolist():member(item.filename,z.read(item.filename))
            for item in sorted(dex.glob('classes*.dex')):member(item.name,item.read_bytes())
            with zipfile.ZipFile(apksig)as lib:member('assets/licenses/APKSIG-APACHE-2.0.txt',lib.read('LICENSE'))
            member('assets/licenses/GSON-LICENSE.txt',(HERE/'third-party/GSON-LICENSE.txt').read_bytes())
            for license in ['LIBSODIUM-LICENSE.txt','BCPROV-LICENSE.md','ZIP4J-LICENSE.txt','OPUS-LICENSE.txt','SPEEXDSP-LICENSE.txt','TINK-LICENSE.txt','PROTOBUF-LICENSE.txt']:member('assets/licenses/'+license,(HERE/'third-party'/license).read_bytes())
            if name=='Core':
                member('lib/arm64-v8a/libhev-socks5-tunnel.so',tunLibrary.read_bytes(),True)
                member('lib/arm64-v8a/libtor.so',torLibrary.read_bytes(),True)
            member('assets/licenses/ANDROID-TOR-NOTICES.txt',(HERE/'third-party/ANDROID-TOR-NOTICES.txt').read_bytes())
            for license in ['HEV','HEV-CORE','HEV-TASK','LWIP','YAML']:member('assets/licenses/'+license+'-LICENSE.txt',(HERE/'third-party'/(license+'-LICENSE.txt')).read_bytes())
            if name=='Mail':member('lib/arm64-v8a/libaegis_sodium.so',nativeLibrary.read_bytes(),True)
            if name=='Glas':member('lib/arm64-v8a/libaegis_audio.so',audioLibrary.read_bytes(),True)
            member('assets/licenses/DEPENDENCIES.json',(HERE/'third-party/DEPENDENCIES.json').read_bytes())
            member('assets/AEGIS-STATUS.json',json.dumps({'productionReady':False,'app':name,'identityRpcImplemented':True,'legacyE2eeRelayMailImplemented':name=='Mail','localTcpDnsFilterImplemented':name=='Core','localOpusAudioPipelineImplemented':name=='Glas','delegatedBcJsseTlsAdapterImplemented':name=='Glas','mixedPerAppTorVpnImplemented':False,'fullMailVoiceVpnImplemented':False,'nativeAcceptance':'NOT_RUN','signing':'OWNER REQUIRED; TEST APK USES SEPARATE TEST KEY'},ensure_ascii=False))
        unsigned=out/f'AEGIS-{name}-6.0.0-unsigned.apk';run([tools/'zipalign','-f','-P','16','4',unaligned,unsigned],env)
        signed=out/f'AEGIS-{name}-6.0.0-TEST.apk';run([tools/'apksigner','sign','--ks',cert,'--ks-key-alias','aegis-test-only','--ks-pass','pass:android','--key-pass','pass:android','--v1-signing-enabled','false','--v2-signing-enabled','true','--v3-signing-enabled','true','--v4-signing-enabled','false','--out',signed,unsigned],env)
        result=run([tools/'apksigner','verify','--verbose','--print-certs','--min-sdk-version','33','-Werr',signed],env);write(out/f'{name}-APK-SIGNATURE.log',result.stdout)
        embedded=run([jdk/'bin/java','-cp',testcp,'org.aegis.android.ApkLibraryProbe',signed,'true'],env);write(out/f'{name}-EMBEDDED-APKSIG-9.4.1.log',embedded.stdout)
        badging=run([tools/'aapt2','dump','badging',signed],env);write(out/f'{name}-APK-BADGING.log',badging.stdout)
        run([tools/'zipalign','-c','-P','16','4',signed],env)
        certline=[line for line in result.stdout.splitlines() if 'certificate SHA-256 digest:'in line];verification[name]={'signatureVerified':True,'certificate':certline,'badging':badging.stdout.splitlines()[:4],'deviceInstalled':False}
        outputs +=[{'file':f.name,'bytes':f.stat().st_size,'sha256':sha(f),'testOnly':f==signed,'signed':f==signed}for f in [unsigned,signed]]
    fingerprints={v['certificate'][0]for v in verification.values()};assert len(fingerprints)==1,'APKs have different test signing certificates'
    # Actual tamper-negative check on built APK, rather than a mock cryptography result.
    original=out/'AEGIS-Core-6.0.0-TEST.apk';corrupt=work/'tampered.apk';data=bytearray(original.read_bytes())
    with zipfile.ZipFile(original)as z:item=z.getinfo('classes.dex');offset=item.header_offset+30+len(item.filename.encode())+len(item.extra);data[offset+10]^=1
    corrupt.write_bytes(data);negative=run([tools/'apksigner','verify','--min-sdk-version','33',corrupt],env,check=False);assert negative.returncode!=0,'Tampered APK accepted';write(out/'TAMPER-NEGATIVE.log',negative.stdout);embedded_negative=run([jdk/'bin/java','-cp',testcp,'org.aegis.android.ApkLibraryProbe',corrupt,'false'],env);write(out/'EMBEDDED-APKSIG-TAMPER-NEGATIVE.log',embedded_negative.stdout);corrupt.unlink()
    if set(input_inventory())!=set(sourceInputs):raise SystemExit('Source inventory changed during build; discard and rebuild')
    hashes={str(f.relative_to(HERE.parent)):sha(f)for f in sourceInputs};hashes['android/build.py']=sha(pathlib.Path(__file__))
    if hashes!=before:raise SystemExit('A source input changed while Android compilation was running; discard this attempt and rebuild')
    report={'schemaVersion':1,'productionReady':False,'sourceCommit':commit,'workingTreeDirty':dirty,'isolatedBuildWork':str(work),'sdkInputsSha256':PINNED,'sourceSha256':hashes,'testCertificate':next(iter(fingerprints)),'artifacts':outputs,'verification':verification,'actualTamperedApkRejected':True,'nativeProvenance':nativeReport,'tunProvenance':tunReport,'audioProvenance':audioReport,'apkContent':'Core: ARM64 hev/lwIP; Mail: ARM64 libsodium JNI; Glas: ARM64 Opus/SpeexDSP JNI; Strazh: DEX. ARM64 device acceptance NOT_RUN','blocked':['Android device installation','Binder platform spoof tests','FLAG_SECURE/overlay device tests','Tor/VPN/DNS','native real Tor mail/device acceptance','full mail formats/archive/P2P Android','real voice transport','Doze/background delivery','legacy identity migration','owner production APK signing']}
    write(out/'ANDROID-BUILD-PROVENANCE-6.0.0.json',json.dumps(report,ensure_ascii=False,indent=2)+'\n');write(out/'SHA256SUMS',''.join(f"{x['sha256']}  {x['file']}\n"for x in outputs));print(json.dumps({'builtApks':len(outputs),'productionReady':False,'artifacts':str(out)}))
if __name__=='__main__':main()
