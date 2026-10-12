#!/usr/bin/env python3
"""Rebuild candidate binaries from source and SHA-pinned released 1.1.5 package inputs.

Explicit networked build command, never called by the installed client. No publication,
owner-key signing, VPS deployment, production manifest write, or user profiles involved.
"""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, sys, urllib.request, zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
RELEASE = 'https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.1.5/'
INPUTS = {
    'AEGIS-1.1.5-Windows-x64.zip': '33937bad1c81117880731799523c8e368d019f85e003bb470d1df359e7f5af36',
    'AEGIS-1.1.5-CachyOS-x86_64.AppImage': '62680457178e59d24188ac7f25f1c9d178ae16aa64c5a4e972565f44a62edbdf',
    'AEGIS-1.1.5-client-source.zip': '9a564f5bb0638a55d1378d2601e5f8949012a725409a19792c6dd7630c74efd9',
}
MAVEN = {
    'org/junit/platform/junit-platform-console-standalone/1.13.4/junit-platform-console-standalone-1.13.4.jar': '3fdfc37e29744a9a67dd5365e81467e26fbde0b7aa204e6f8bbe79eeaa7ae892',
    'org/testfx/openjfx-monocle/21.0.2/openjfx-monocle-21.0.2.jar': '3d0b0c186a9f495aa4e3d058c612b2a9cf44a97ffbcecd75d441aed8263fac50',
    'com/password4j/password4j/1.8.4/password4j-1.8.4.jar': 'd1406a158533b65bda7c20cebf7bf2a9a0626f8931fd1dc3d39243af5849edf5',
    'org/xerial/sqlite-jdbc/3.53.4.0/sqlite-jdbc-3.53.4.0.jar': 'bcb1f51e36f940867e83342f9efbf5968ac44a6bef4d397bb4af7b17b45cd2fb',
    'org/slf4j/slf4j-api/2.0.17/slf4j-api-2.0.17.jar': '7b751d952061954d5abfed7181c1f645d336091b679891591d63329c622eb832',
    'org/slf4j/slf4j-nop/2.0.17/slf4j-nop-2.0.17.jar': '3716f83649ec66161a2edefd4f49df34d1dd1c51cdcf941996c6987260f0a829',
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
    args=parser.parse_args();jdk=args.jdk.resolve();work=args.work.resolve();out=args.out.resolve()
    work.mkdir(parents=True,exist_ok=True);out.mkdir(parents=True,exist_ok=True);evidence=out/'evidence';evidence.mkdir(exist_ok=True)
    for name,digest in INPUTS.items():download(RELEASE+name,work/name,digest)
    run([sys.executable,ROOT/'tools/fetch-fonts.py'],timeout=360,log=evidence/'official-fonts.log')
    oldimage=work/'AEGIS-1.1.5-CachyOS-x86_64.AppImage';oldimage.chmod(0o755)
    run([oldimage,'--appimage-extract'],cwd=work,log=evidence/'input-appimage-extract.log',timeout=120)
    linux=work/'squashfs-root';windows=work/'windows';unzip(work/'AEGIS-1.1.5-Windows-x64.zip',windows)
    (linux/'tor/pluggable_transports/lyrebird').chmod(0o755)
    baseline=work/'baseline';unzip(work/'AEGIS-1.1.5-client-source.zip',baseline)
    deps=work/'deps';deps.mkdir(exist_ok=True)
    for coordinate,digest in MAVEN.items():download('https://repo.maven.apache.org/maven2/'+coordinate,deps/pathlib.PurePosixPath(coordinate).name,digest)
    common=[sys.executable,ROOT/'tools/build-local.py','--jdk',jdk,'--deps',linux/'app','--deps',deps,'--native-root',linux]
    run(common,timeout=600,log=evidence/'java21-build-tests.log')
    build=ROOT/'build/local-java21'
    jars=[jar for jar in (linux/'app').glob('*.jar') if not jar.name.startswith(('client-core-','client-ui-','common-protocol-','relay-server-'))]+list(deps.glob('*.jar'))+list(build.glob('*.jar'))
    run([jdk/'bin/java','-Xmx256m','-cp',os.pathsep.join(map(str,jars+[build/'tests'])),'org.securemail.client.TorProcessSmoke',linux],timeout=60,log=evidence/'TorProcessSmoke.log')
    run([sys.executable,'-m','unittest','-v','test_release_manifest'],cwd=ROOT/'tools',log=evidence/'release-security-tests.log')
    ui=[sys.executable,ROOT/'tools/run-ui-regression.py','--jdk',jdk,'--deps',linux/'app','--deps',deps,'--native-root',linux]
    for test in ['ClientUiRegressionSmoke','Aegis11UiSmoke','SingleWindowSmoke','DarkGreenThemeSmoke','MessengerSmoke','Appearance115Smoke','AppearancePerformanceSmoke','Stability120Smoke']:
        run(ui+['--test',test],log=evidence/(test+'.log'))
    # Compare the same JavaFX workload against the exact released 1.1.5 JARs.
    perfcp=os.pathsep.join(map(str,[linux/'app'/'*',deps/'*',build/'ui-tests']))
    run([jdk/'bin/java','-Xmx768m','-Daegis.native.root='+str(linux),'-Dprism.order=sw','-Dglass.platform=Monocle','-Dmonocle.platform=Headless','-Dheadless.geometry=1600x1200-32','-cp',perfcp,'org.securemail.ui.AppearancePerformanceSmoke'],timeout=180,log=evidence/'baseline115-performance.log')
    shutil.copytree(ROOT/'build/ui115-screenshots',out/'screenshots',dirs_exist_ok=True)
    shutil.copytree(build/'junit',evidence/'junit',dirs_exist_ok=True)
    if (ROOT/'tools/compatibility-matrix.py').exists():
        run([sys.executable,ROOT/'tools/compatibility-matrix.py','--jdk',jdk,'--baseline',baseline/'aegis','--base-app',linux,'--deps',deps],log=evidence/'compatibility-matrix.log',timeout=360)
    for platform,base in [('linux',linux),('win',windows/'AEGIS')]:
        target=ROOT/'client-ui/build/stage'/platform
        if target.exists():shutil.rmtree(target)
        target.mkdir(parents=True)
        for jar in (base/'app').glob('*.jar'):
            if not jar.name.startswith(('client-ui-','client-core-','common-protocol-','relay-server-')):shutil.copy2(jar,target/jar.name)
        for module,version in [('client-ui','1.2.0'),('client-core','1.2.0'),('common-protocol','0.2.0')]:shutil.copy2(build/(module+'.jar'),target/(module+'-'+version+'.jar'))
    offset=int(subprocess.check_output([oldimage,'--appimage-offset'],timeout=30));runtime=work/'runtime-x86_64'
    with oldimage.open('rb') as source,runtime.open('wb') as destination:destination.write(source.read(offset))
    run([sys.executable,ROOT/'packaging/package-clients.py','--linux-base',linux,'--windows-base',windows/'AEGIS','--mingw','/usr/bin','--makensis','/usr/bin/makensis','--mksquashfs','/usr/bin/mksquashfs','--appimage-runtime',runtime,'--out',out],timeout=360,log=evidence/'packaging.log')
    run([sys.executable,ROOT/'packaging/verify_client_release.py',out],timeout=180,log=out/'ARTIFACT-VERIFICATION.json')
    run([sys.executable,ROOT/'packaging/archive-clients.py',out],timeout=90)
    run([sys.executable,ROOT/'tools/package-native120.py','--jdk',jdk,'--artifacts',out],timeout=180,log=evidence/'native-kit-build.log')
    shutil.copytree(build/'junit',evidence/'junit',dirs_exist_ok=True)
    for name in ['README-WINDOWS.md','README-CACHYOS.md','CHANGELOG-1.2.0.md','TEST-REPORT-1.2.0.md','NATIVE-ACCEPTANCE-1.2.0.md','APPEARANCE-1.2.0.md','MIGRATION-1.1.5-TO-1.2.0.md','BUILD-1.2.0.md','SECURITY.md','RELEASE-GATES-1.2.0.json','PERFORMANCE-1.2.0.json','NATIVE-RESULTS-1.2.0.csv','AUTO-TEST-MATRIX-1.2.0.json','AUDIT-1.2.0-RU.md','RELAY-LIFECYCLE-PROPOSAL-1.2.0.md','OWNER-OFFLINE-SIGNING-1.2.0.md','PROTECTED-COMPONENTS-1.2.0.json']:
        shutil.copy2(ROOT/name,out/name)
    if (build/'compatibility-matrix.json').exists():shutil.copy2(build/'compatibility-matrix.json',evidence/'compatibility-matrix.json')
    provenance={'version':'1.2.0','productionReady':False,'sourceCommit':os.environ.get('GITHUB_SHA','local-uncommitted'),'nativeAcceptance':'NOT_RUN','JDK':subprocess.check_output([jdk/'bin/java','-version'],stderr=subprocess.STDOUT,text=True,timeout=15).strip(),'baseReleaseInputs':INPUTS,'testAndRelayDependencies':MAVEN,'runtimeConnectionsAdded':False,'ownerPrivateKeyUsed':False,'productionDeploymentOrPublication':False,'baseline':'1.1.5 Stable','newJavaDependencies':False,'licensedFontsAdded':True,'lifecycleFeatures':'BLOCKED_ARCHITECTURE_APPROVAL'}
    (out/'BUILD-PROVENANCE.json').write_text(json.dumps(provenance,indent=2)+'\n')
    files=sorted(p for p in out.iterdir() if p.is_file() and p.name!='SHA256SUMS')
    (out/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in files))
    run([sys.executable,ROOT/'tools/stability-release.py','--artifacts',out],timeout=30)
    print('Candidate artifacts rebuilt and structurally verified. Native acceptance NOT_RUN; no signature/publication.')

if __name__=='__main__':main()
