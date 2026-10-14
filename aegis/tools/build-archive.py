#!/usr/bin/env python3
"""Rebuild candidate binaries from source and SHA-pinned released 1.2.0 package inputs.

Explicit networked build command, never called by the installed client. No publication,
owner-key signing, VPS deployment, production manifest write, or user profiles involved.
"""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, sys, urllib.request, zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
RELEASE = 'https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.2.0/'
INPUTS = {
    'AEGIS-1.2.0-Windows-x64.zip': '00addcba5b79828342e81f2a64eb9f21237b6b1297796fdf37c11edd95e6d4a9',
    'AEGIS-1.2.0-CachyOS-x86_64.AppImage': '118487525eb2bcd7692535fd629b5068489ff6ba50dff1ab0302c70f5ac768e9',
    'AEGIS-1.2.0-client-source.zip': '93c816760d3f688214a3a37e67483e9ec89233e5f671d28bb8f5b49f7f370324',
}
MAVEN = {
    'org/junit/platform/junit-platform-console-standalone/1.13.4/junit-platform-console-standalone-1.13.4.jar': '3fdfc37e29744a9a67dd5365e81467e26fbde0b7aa204e6f8bbe79eeaa7ae892',
    'org/testfx/openjfx-monocle/21.0.2/openjfx-monocle-21.0.2.jar': '3d0b0c186a9f495aa4e3d058c612b2a9cf44a97ffbcecd75d441aed8263fac50',
    'com/password4j/password4j/1.8.4/password4j-1.8.4.jar': 'd1406a158533b65bda7c20cebf7bf2a9a0626f8931fd1dc3d39243af5849edf5',
    'org/xerial/sqlite-jdbc/3.53.4.0/sqlite-jdbc-3.53.4.0.jar': 'bcb1f51e36f940867e83342f9efbf5968ac44a6bef4d397bb4af7b17b45cd2fb',
    'org/slf4j/slf4j-api/2.0.17/slf4j-api-2.0.17.jar': '7b751d952061954d5abfed7181c1f645d336091b679891591d63329c622eb832',
    'org/slf4j/slf4j-nop/2.0.17/slf4j-nop-2.0.17.jar': '3716f83649ec66161a2edefd4f49df34d1dd1c51cdcf941996c6987260f0a829',
    'org/apache/pdfbox/pdfbox/3.0.8/pdfbox-3.0.8.jar': '97647cfbde61ebcfc06b4cf8c9b0ffcaaee073396eceb4a7f6836a9b9128903c',
    'org/apache/pdfbox/pdfbox-io/3.0.8/pdfbox-io-3.0.8.jar': '36a0e04001010b4c764857817412b96339930b19755e728959805cc0352061b2',
    'org/apache/pdfbox/fontbox/3.0.8/fontbox-3.0.8.jar': 'a1915c24e3edbe0ecec93896dfbf6d41427810b663ade97bd4e8bae86ec3fdab',
    'commons-logging/commons-logging/1.3.5/commons-logging-1.3.5.jar': '6d7a744e4027649fbb50895df9497d109f98c766a637062fe8d2eabbb3140ba4',
}

def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()

def download(url, target, digest):
    if not target.exists():
        candidate = target.with_suffix(target.suffix + '.part')
        with urllib.request.urlopen(url, timeout=60) as response, candidate.open('wb') as out:
            shutil.copyfileobj(response, out)
        if sha(candidate) != digest: raise ValueError('Input SHA256 mismatch: ' + target.name)
        candidate.replace(target)
    if target.is_symlink() or sha(target) != digest: raise ValueError('Input SHA256 mismatch: ' + target.name)

def run(command, *, timeout=240, log=None, cwd=ROOT):
    if log:
        try:
            with log.open('w') as stream: subprocess.run(list(map(str, command)), check=True, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        except (subprocess.CalledProcessError,subprocess.TimeoutExpired):
            print(log.read_text(errors='replace')[-12000:],file=sys.stderr)
            raise
    else: subprocess.run(list(map(str, command)), check=True, cwd=cwd, timeout=timeout)

def unzip(path, destination):
    with zipfile.ZipFile(path) as archive:
        if archive.testzip(): raise ValueError('Input CRC mismatch')
        for entry in archive.infolist():
            p=pathlib.PurePosixPath(entry.filename)
            if p.is_absolute() or '..' in p.parts or '\\' in entry.filename or ((entry.external_attr >> 16) & 0o170000)==0o120000:
                raise ValueError('Unsafe input archive path')
        archive.extractall(destination)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jdk',required=True,type=pathlib.Path)
    parser.add_argument('--work',required=True,type=pathlib.Path)
    parser.add_argument('--out',required=True,type=pathlib.Path)
    parser.add_argument('--refresh-gradle-locks',action='store_true',help='Explicit developer dependency resolution; never executed by installed app')
    args=parser.parse_args();jdk=args.jdk.resolve();work=args.work.resolve();out=args.out.resolve()
    work.mkdir(parents=True,exist_ok=True);out.mkdir(parents=True,exist_ok=True);evidence=out/'evidence';evidence.mkdir(exist_ok=True)
    for name,digest in INPUTS.items():download(RELEASE+name,work/name,digest)
    # The SHA-verified 1.2.0 source already includes the five licensed Cyrillic families.
    oldimage=work/'AEGIS-1.2.0-CachyOS-x86_64.AppImage';oldimage.chmod(0o755)
    run([oldimage,'--appimage-extract'],cwd=work,log=evidence/'input-appimage-extract.log',timeout=120)
    linux=work/'squashfs-root';windows=work/'windows';unzip(work/'AEGIS-1.2.0-Windows-x64.zip',windows)
    (linux/'tor/pluggable_transports/lyrebird').chmod(0o755)
    if args.refresh_gradle_locks:
        (ROOT/'gradlew').chmod(0o755)
        run([ROOT/'gradlew','--no-daemon','--write-locks','--write-verification-metadata','sha256',':client-core:compileJava',':client-ui:compileJava',':integration-tests:compileTestJava'],timeout=600,log=evidence/'gradle-locks-compile.log')
    baseline=work/'baseline';unzip(work/'AEGIS-1.2.0-client-source.zip',baseline)
    # Published 1.1.5 source includes staging Relay 0.3.0, not the legacy 0.2.0.
    legacy=work/'AEGIS-1.0.0-client-source.zip'
    download('https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.0.0/'+legacy.name,legacy,'3745572f1261392a88b4ea4cfad7763d54e3fb9efb9a9d5a674eaa74abc5e2ee')
    relaybaseline=work/'relay02-source';unzip(legacy,relaybaseline)
    deps=work/'deps';deps.mkdir(exist_ok=True)
    for coordinate,digest in MAVEN.items():download('https://repo.maven.apache.org/maven2/'+coordinate,deps/pathlib.PurePosixPath(coordinate).name,digest)
    common=[sys.executable,ROOT/'tools/build-local.py','--jdk',jdk,'--deps',linux/'app','--deps',deps,'--native-root',linux]
    run(common,timeout=600,log=evidence/'java21-build-tests.log')
    build=ROOT/'build/local-java21'
    jars=[jar for jar in (linux/'app').glob('*.jar') if not jar.name.startswith(('client-core-','client-ui-','common-protocol-','relay-server-'))]+list(deps.glob('*.jar'))+list(build.glob('*.jar'))
    run([jdk/'bin/java','-Xmx256m','-cp',os.pathsep.join(map(str,jars+[build/'tests'])),'org.securemail.client.TorProcessSmoke',linux],timeout=60,log=evidence/'TorProcessSmoke.log')
    run([sys.executable,'-m','unittest','-v','test_release_manifest'],cwd=ROOT/'tools',log=evidence/'release-security-tests.log')
    ui=[sys.executable,ROOT/'tools/run-ui-regression.py','--jdk',jdk,'--deps',linux/'app','--deps',deps,'--native-root',linux]
    for test in ['SingleWindowSmoke','MessengerSmoke','Appearance115Smoke','AppearancePerformanceSmoke','Lifecycle120Smoke','Archive150Smoke']:
        run(ui+['--test',test],log=evidence/(test+'.log'))
    run([jdk/'bin/java','-Xmx256m','-Daegis.native.root='+str(linux),'-cp',os.pathsep.join(map(str,jars+[build/'tests'])),'org.securemail.client.archive.ArchivePerformanceMain'],timeout=90,log=evidence/'archive-performance.json')
    # Compare the same JavaFX workload against the exact released 1.1.5 JARs.
    perfcp=os.pathsep.join(map(str,[linux/'app'/'*',deps/'*',build/'ui-tests']))
    run([jdk/'bin/java','-Xmx768m','-Daegis.native.root='+str(linux),'-Dprism.order=sw','-Dglass.platform=Monocle','-Dmonocle.platform=Headless','-Dheadless.geometry=1600x1200-32','-cp',perfcp,'org.securemail.ui.AppearancePerformanceSmoke'],timeout=180,log=evidence/'baseline120-performance.log')
    shutil.copytree(ROOT/'build/ui115-screenshots',out/'screenshots/appearance',dirs_exist_ok=True)
    shutil.copytree(ROOT/'build/ui150-screenshots',out/'screenshots/archive',dirs_exist_ok=True)
    shutil.copytree(build/'junit',evidence/'junit',dirs_exist_ok=True)
    if (ROOT/'tools/compatibility-matrix.py').exists():
        run([sys.executable,ROOT/'tools/compatibility-matrix.py','--jdk',jdk,'--baseline',relaybaseline/'aegis','--base-app',linux,'--deps',deps,'--previous-client-version','1.2.0','--candidate-client-version','1.5.0'],log=evidence/'compatibility-matrix.log',timeout=360)
    for platform,base in [('linux',linux),('win',windows/'AEGIS')]:
        target=ROOT/'client-ui/build/stage'/platform
        if target.exists():shutil.rmtree(target)
        target.mkdir(parents=True)
        for jar in (base/'app').glob('*.jar'):
            if not jar.name.startswith(('client-ui-','client-core-','common-protocol-','relay-server-')):shutil.copy2(jar,target/jar.name)
        for dep in deps.glob('*.jar'):
            if dep.name.startswith(('pdfbox-','fontbox-','commons-logging-')):shutil.copy2(dep,target/dep.name)
        for module,version in [('client-ui','1.5.0'),('client-core','1.5.0'),('common-protocol','0.2.0')]:shutil.copy2(build/(module+'.jar'),target/(module+'-'+version+'.jar'))
    offset=int(subprocess.check_output([oldimage,'--appimage-offset'],timeout=30));runtime=work/'runtime-x86_64'
    with oldimage.open('rb') as source,runtime.open('wb') as destination:destination.write(source.read(offset))
    run([sys.executable,ROOT/'packaging/package-clients.py','--linux-base',linux,'--windows-base',windows/'AEGIS','--mingw','/usr/bin','--makensis','/usr/bin/makensis','--mksquashfs','/usr/bin/mksquashfs','--appimage-runtime',runtime,'--out',out],timeout=360,log=evidence/'packaging.log')
    run([sys.executable,ROOT/'packaging/verify_client_release.py',out],timeout=180,log=out/'ARTIFACT-VERIFICATION.json')
    run([sys.executable,ROOT/'packaging/archive-clients.py',out],timeout=90)
    run([sys.executable,ROOT/'tools/package-native150.py','--jdk',jdk,'--artifacts',out,'--staging-deps',deps],timeout=180,log=evidence/'native-kit-build.log')
    shutil.copytree(build/'junit',evidence/'junit',dirs_exist_ok=True)
    for name in ['README.md','README-WINDOWS.md','README-CACHYOS.md','CHANGELOG-1.5.0.md','TEST-REPORT-1.5.0.md','NATIVE-ACCEPTANCE-1.5.0.md','ARCHIVE-1.5.0.md','MIGRATION-1.2.0-TO-1.5.0.md','BUILD-1.5.0.md','SECURITY.md','ARCHIVE-THREAT-MODEL-1.5.0.md','RELEASE-GATES-1.5.0.json','OWNER-OFFLINE-SIGNING-1.5.0.md','AUDIT-1.5.0-RU.md','P2P-VERIFICATION-1.5.0.md','IMPLEMENTATION-REPORT-1.5.0-RU.md']:
        if (ROOT/name).is_file():shutil.copy2(ROOT/name,out/name)

    if (build/'compatibility-matrix.json').exists():shutil.copy2(build/'compatibility-matrix.json',evidence/'compatibility-matrix.json')
    provenance={'version':'1.5.0','productionReady':False,'sourceCommit':os.environ.get('GITHUB_SHA','local-uncommitted'),'nativeAcceptance':'NOT_RUN','JDK':subprocess.check_output([jdk/'bin/java','-version'],stderr=subprocess.STDOUT,text=True,timeout=15).strip(),'baseReleaseInputs':INPUTS,'testAndRelayDependencies':MAVEN,'runtimeConnectionsAdded':['account-signed peer onion virtual port 81 through existing mail SOCKS; relay protocol unchanged'],'ownerPrivateKeyUsed':False,'productionDeploymentOrPublication':False,'baseline':'1.2.0 Stable','newJavaDependencies':['PDFBox3.0.8 (Apache2): isolated local PDF renderer; no network'],'licensedFontsAdded':True,'lifecycleFeatures':'CLIENT_ONLY_SIGNED_E2EE; NATIVE_ACCEPTANCE_PENDING; CONSERVATIVE_EXPIRY_ON_OS_REBOOT','relay02SourceInputSha256':'3745572f1261392a88b4ea4cfad7763d54e3fb9efb9a9d5a674eaa74abc5e2ee'}
    (out/'BUILD-PROVENANCE.json').write_text(json.dumps(provenance,indent=2)+'\n')
    files=sorted(p for p in out.iterdir() if p.is_file() and p.name!='SHA256SUMS')
    (out/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in files))
    run([sys.executable,ROOT/'tools/archive-release.py','--artifacts',out],timeout=30)
    print('Candidate artifacts rebuilt and structurally verified. Native acceptance NOT_RUN; no signature/publication.')

if __name__=='__main__':main()
