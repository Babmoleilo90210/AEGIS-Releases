#!/usr/bin/env python3
"""Rebuild candidate binaries from source and SHA-pinned 1.0.0 native inputs.

Explicit networked build command, never called by the installed client. No publication,
owner-key signing, VPS deployment, production manifest write, or user profiles involved.
"""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, sys, urllib.request, zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
RELEASE = 'https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.0.0/'
INPUTS = {
    'AEGIS-1.0.0-Windows-x64.zip': 'f8dd50b1365388a662df1ae9be30a3c14f9de3ce67db34fe53f179648e614205',
    'AEGIS-1.0.0-CachyOS-x86_64.AppImage': '1e7b22de4ba40baef552093561d99171be1e95e8d89019008ad446fd3eefc7a3',
    'AEGIS-1.0.0-client-source.zip': '3745572f1261392a88b4ea4cfad7763d54e3fb9efb9a9d5a674eaa74abc5e2ee',
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
    published=work/'published-1.1.1-source.zip'
    download('https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.1.1/AEGIS-1.1.1-client-source.zip',published,'c6148e46d30cfa277483810fbfe64ac7f7ddcec06b13c544f4c921716c7a8a6a')
    run([sys.executable,ROOT/'tools/verify-visual-scope.py','--baseline',published,'--report',evidence/'visual-scope.json'],timeout=30,log=evidence/'visual-scope.log')
    oldimage=work/'AEGIS-1.0.0-CachyOS-x86_64.AppImage';oldimage.chmod(0o755)
    run([oldimage,'--appimage-extract'],cwd=work,log=evidence/'input-appimage-extract.log',timeout=120)
    linux=work/'squashfs-root';windows=work/'windows';unzip(work/'AEGIS-1.0.0-Windows-x64.zip',windows)
    (linux/'tor/pluggable_transports/lyrebird').chmod(0o755)
    baseline=work/'baseline';unzip(work/'AEGIS-1.0.0-client-source.zip',baseline)
    deps=work/'deps';deps.mkdir(exist_ok=True)
    for coordinate,digest in MAVEN.items():download('https://repo.maven.apache.org/maven2/'+coordinate,deps/pathlib.PurePosixPath(coordinate).name,digest)
    common=[sys.executable,ROOT/'tools/build-local.py','--jdk',jdk,'--deps',linux/'app','--deps',deps,'--native-root',linux]
    run(common,timeout=600,log=evidence/'java21-build-tests.log')
    build=ROOT/'build/local-java21'
    jars=[jar for jar in (linux/'app').glob('*.jar') if not jar.name.startswith(('client-core-','client-ui-','common-protocol-','relay-server-'))]+list(deps.glob('*.jar'))+list(build.glob('*.jar'))
    run([jdk/'bin/java','-Xmx256m','-cp',os.pathsep.join(map(str,jars+[build/'tests'])),'org.securemail.client.TorProcessSmoke',linux],timeout=60,log=evidence/'TorProcessSmoke.log')
    run([sys.executable,'-m','unittest','-v','test_release_manifest'],cwd=ROOT/'tools',log=evidence/'release-security-tests.log')
    ui=[sys.executable,ROOT/'tools/run-ui-regression.py','--jdk',jdk,'--deps',linux/'app','--deps',deps,'--native-root',linux]
    for test in ['ClientUiRegressionSmoke','Aegis11UiSmoke','SingleWindowSmoke','DarkGreenThemeSmoke','MessengerSmoke','Appearance115Smoke','AppearancePerformanceSmoke']:
        run(ui+['--test',test],log=evidence/(test+'.log'))
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
        for module,version in [('client-ui','1.1.5'),('client-core','1.1.5'),('common-protocol','0.2.0')]:shutil.copy2(build/(module+'.jar'),target/(module+'-'+version+'.jar'))
    offset=int(subprocess.check_output([oldimage,'--appimage-offset'],timeout=30));runtime=work/'runtime-x86_64'
    with oldimage.open('rb') as source,runtime.open('wb') as destination:destination.write(source.read(offset))
    run([sys.executable,ROOT/'packaging/package-clients.py','--linux-base',linux,'--windows-base',windows/'AEGIS','--mingw','/usr/bin','--makensis','/usr/bin/makensis','--mksquashfs','/usr/bin/mksquashfs','--appimage-runtime',runtime,'--out',out],timeout=360,log=evidence/'packaging.log')
    run([sys.executable,ROOT/'packaging/verify_client_release.py',out],timeout=180,log=out/'ARTIFACT-VERIFICATION.json')
    run([sys.executable,ROOT/'packaging/archive-clients.py',out],timeout=90)
    shutil.copytree(build/'junit',evidence/'junit',dirs_exist_ok=True)
    for name in ['README-WINDOWS.md','README-CACHYOS.md','CHANGELOG-1.1.5.md','TEST-REPORT-1.1.5.md','NATIVE-ACCEPTANCE-1.1.5.md','APPEARANCE-1.1.5.md','MIGRATION-1.1.1-TO-1.1.5.md','BUILD-1.1.5.md','SECURITY.md','RELEASE-GATES-1.1.5.json','PERFORMANCE-1.1.5.json','NATIVE-RESULTS-1.1.5.csv','AUTO-TEST-MATRIX-1.1.5.json']:
        shutil.copy2(ROOT/name,out/name)
    if (build/'compatibility-matrix.json').exists():shutil.copy2(build/'compatibility-matrix.json',evidence/'compatibility-matrix.json')
    provenance={'version':'1.1.5','productionReady':False,'sourceCommit':os.environ.get('GITHUB_SHA','local-uncommitted'),'nativeAcceptance':'NOT_RUN','JDK':subprocess.check_output([jdk/'bin/java','-version'],stderr=subprocess.STDOUT,text=True,timeout=15).strip(),'baseReleaseInputs':INPUTS,'testAndRelayDependencies':MAVEN,'runtimeConnectionsAdded':False,'ownerPrivateKeyUsed':False,'productionDeploymentOrPublication':False,'baseline':'1.1.1 Beta Demo','newDependencies':False}
    (out/'BUILD-PROVENANCE.json').write_text(json.dumps(provenance,indent=2)+'\n')
    files=sorted(p for p in out.iterdir() if p.is_file() and p.name!='SHA256SUMS')
    (out/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in files))
    run([sys.executable,ROOT/'tools/visual-release.py','--artifacts',out],timeout=30)
    print('Candidate artifacts rebuilt and structurally verified. Native acceptance NOT_RUN; no signature/publication.')

if __name__=='__main__':main()
