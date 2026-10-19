#!/usr/bin/env python3
"""Verified official libsodium Android ARM64 JNI build; ARM execution is NOT_RUN."""
import argparse,base64,hashlib,json,os,pathlib,re,shutil,subprocess,tarfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
HERE=pathlib.Path(__file__).resolve().parent
SODIUM_SHA='c44f62b9919e4cce5963e74c67a43b8818ed523bd2eded506266d8797d103baf'
NDK_SHA='4abbbcdc842f3d4879206e9695d52709603e52dd68d3c1fff04b3b5e7a308ecf'
PUB='RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--sdk',required=True,type=pathlib.Path);p.add_argument('--jdk',required=True,type=pathlib.Path);p.add_argument('--source',required=True,type=pathlib.Path);p.add_argument('--signature',required=True,type=pathlib.Path);p.add_argument('--out',required=True,type=pathlib.Path);p.add_argument('--resume',action='store_true');a=p.parse_args();a.sdk=a.sdk.resolve();a.jdk=a.jdk.resolve();a.out=a.out.resolve();a.source=a.source.resolve();a.signature=a.signature.resolve();a.out.mkdir(parents=True,exist_ok=True)
 if sha(a.source)!=SODIUM_SHA or sha(a.sdk/'android-ndk-r29-linux.zip')!=NDK_SHA:raise SystemExit('Pinned native source/toolchain mismatch')
 pub=base64.b64decode(PUB);lines=a.signature.read_text().splitlines();sig=base64.b64decode(lines[1]);assert sig[:2]==b'ED' and sig[2:10]==pub[2:10];k=Ed25519PublicKey.from_public_bytes(pub[10:]);k.verify(sig[10:],hashlib.blake2b(a.source.read_bytes(),digest_size=64).digest());k.verify(base64.b64decode(lines[3]),sig[10:]+lines[2].removeprefix('trusted comment: ').encode())
 ndk=a.sdk/'android-ndk-r29';bin=ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin';work=HERE/'build/native-work';
 if not a.resume:shutil.rmtree(work,ignore_errors=True)
 work.mkdir(parents=True,exist_ok=True)
 log=(a.out/'NATIVE-BUILD.log').open('w');env=os.environ.copy();env['SOURCE_DATE_EPOCH']='1792280091';commands=[]
 def run(cmd,cwd=None,e=None):
  commands.append([str(x)for x in cmd]);log.write('$ '+' '.join(commands[-1])+'\n');log.flush();r=subprocess.run(commands[-1],cwd=cwd,env=e or env,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise SystemExit('Native build failed; see '+str(a.out/'NATIVE-BUILD.log'))
 def extract(name):
  d=work/name;d.mkdir(exist_ok=True)
  with tarfile.open(a.source)as t:
   if a.resume:
    for member in t:
     if member.isfile():
      if hashlib.sha256(t.extractfile(member).read()).digest()!=hashlib.sha256((d/member.name).read_bytes()).digest():raise SystemExit('Native cached source changed: '+member.name)
   else:t.extractall(d,filter='data')
  return d/'libsodium-stable'
 arm=extract('arm64');prefix=work/'arm64-install';armenv=env.copy();armenv.update(CC=str(bin/'aarch64-linux-android33-clang'),AR=str(bin/'llvm-ar'),RANLIB=str(bin/'llvm-ranlib'),STRIP=str(bin/'llvm-strip'),CFLAGS='-O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fvisibility=hidden -ffile-prefix-map='+str(work)+'=/aegis-native',LDFLAGS='-Wl,-z,max-page-size=16384 -Wl,-z,relro,-z,now')
 
 if not a.resume:run(['./configure','--host=aarch64-linux-android','--disable-shared','--enable-static','--with-pic','--prefix='+str(prefix)],arm,armenv)
 run(['make','-j4'],arm,armenv);run(['make','install'],arm,armenv)
 target=a.out/'lib/arm64-v8a/libaegis_sodium.so';target.parent.mkdir(parents=True,exist_ok=True)
 run([bin/'aarch64-linux-android33-clang','-shared','-O2','-fPIC','-fstack-protector-strong','-D_FORTIFY_SOURCE=2','-fvisibility=hidden','-Werror','-Wall','-Wextra','-I'+str(prefix/'include'),HERE/'native/aegis_sodium.c',prefix/'lib/libsodium.a','-Wl,--exclude-libs,ALL','-Wl,--build-id=sha1','-Wl,-z,max-page-size=16384','-Wl,-z,relro,-z,now','-Wl,-soname,libaegis_sodium.so','-o',target]);run([bin/'llvm-strip','--strip-unneeded',target])
 headers=subprocess.check_output([str(bin/'llvm-readelf'),'-h','-l','-d',str(target)],text=True);(a.out/'ARM64-ELF.txt').write_text(headers);assert 'AArch64'in headers
 for line in headers.splitlines():
  if line.strip().startswith('LOAD'):assert int(line.split()[-1],16)>=16384,line
 host=extract('host');hp=work/'host-install';
 if not a.resume:run(['./configure','--disable-shared','--enable-static','--with-pic','--prefix='+str(hp)],host)
 run(['make','-j4'],host)
 # Build the exact generated upstream test-program list before executing it.
 text=(host/'test/default/Makefile').read_text().replace('\\\n',' ');variables=dict(line.split(' = ',1)for line in text.splitlines()if ' = 'in line and not line.startswith('\t'));value=variables['check_PROGRAMS']
 for unused in range(8):value=re.sub(r'\$\(([^)]+)\)',lambda m:variables.get(m.group(1),''),value)
 programs=value.split();assert programs and all(name.replace('_','').isalnum()for name in programs)
 run(['make','-C','test/default','-j4',*programs],host)
 for name in programs:
  f=host/'test/default'/name
  if f.read_bytes().startswith(b'\x7fELF'):f.chmod(f.stat().st_mode|0o100)
 try:run(['make','check','-j4'],host)
 except SystemExit:
  result=(host/'test/default/test-suite.log').read_text()
  if 'Permission denied'not in result or '(exit status: 126)'not in result:raise
  # The workspace may materialize a newly linked test without execute permission.
  # Repair only compiled ELF test-program modes, then rerun every upstream test.
  for name in programs:
   f=host/'test/default'/name
   if f.read_bytes().startswith(b'\x7fELF'):f.chmod(f.stat().st_mode|0o100)
  run(['make','check','-j2'],host)
 run(['make','install'],host)
 ht=a.out/'host/libaegis_sodium.so';ht.parent.mkdir(exist_ok=True);run(['gcc','-shared','-O2','-fPIC','-fstack-protector-strong','-D_FORTIFY_SOURCE=2','-Werror','-Wall','-Wextra','-I'+str(a.jdk/'include'),'-I'+str(a.jdk/'include/linux'),'-I'+str(hp/'include'),HERE/'native/aegis_sodium.c',hp/'lib/libsodium.a','-Wl,--exclude-libs,ALL','-Wl,-z,relro,-z,now','-o',ht])
 shutil.copy2(arm/'LICENSE',HERE/'third-party/LIBSODIUM-LICENSE.txt');shutil.copy2(a.signature,HERE/'third-party/libsodium-1.0.22-stable.minisig');shutil.copy2(host/'test/default/test-suite.log',a.out/'LIBSODIUM-HOST-TEST-SUITE.log')
 report={'schemaVersion':1,'productionReady':False,'libsodiumVersion':'1.0.22 stable 2026-10-19 signed snapshot','sourceSha256':SODIUM_SHA,'sourceUrl':'https://download.libsodium.org/libsodium/releases/libsodium-1.0.22-stable.tar.gz','officialSigningKey':PUB,'officialKeyDocumentation':'https://doc.libsodium.org/installation','minisignPayloadAndCommentVerified':True,'ndkRevision':'29.0.14206865','ndkArchiveSha256':NDK_SHA,'jniSourceSha256':sha(HERE/'native/aegis_sodium.c'),'arm64LibrarySha256':sha(target),'hostLibrarySha256':sha(ht),'androidMinApi':33,'elfLoadSegmentAlignment':16384,'hostLibsodiumTests':'PASS','arm64Execution':'NOT_RUN','androidDeviceAcceptance':'NOT_RUN','commands':commands}
 (a.out/'NATIVE-PROVENANCE.json').write_text(json.dumps(report,indent=2)+'\n');log.close();print(json.dumps(report,indent=2))
if __name__=='__main__':main()
