#!/usr/bin/env python3
"""Official pinned Opus/SpeexDSP, static ARM64 Android JNI and host validation build."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tarfile,tempfile
HERE=pathlib.Path(__file__).resolve().parent
SOURCES={
 'opus':('1.6.1','6ffcb593207be92584df15b32466ed64bbec99109f007c82205f0194572411a1','https://downloads.xiph.org/releases/opus/opus-1.6.1.tar.gz'),
 'speexdsp':('1.2.1','8c777343e4a6399569c72abc38a95b24db56882c83dbdb6c6424a5f4aeb54d3d','https://downloads.xiph.org/releases/speex/speexdsp-1.2.1.tar.gz')}
NDK_SHA='4abbbcdc842f3d4879206e9695d52709603e52dd68d3c1fff04b3b5e7a308ecf'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--sdk',required=True,type=pathlib.Path);p.add_argument('--jdk',required=True,type=pathlib.Path);p.add_argument('--sources',required=True,type=pathlib.Path);p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args();a.sdk=a.sdk.resolve();a.jdk=a.jdk.resolve();a.sources=a.sources.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
 if sha(a.sdk/'android-ndk-r29-linux.zip')!=NDK_SHA:raise SystemExit('Pinned NDK mismatch')
 for name,(version,digest,url)in SOURCES.items():
  if sha(a.sources/(name+'-'+version+'.tar.gz'))!=digest:raise SystemExit('Pinned audio source mismatch: '+name)
 (HERE/'build').mkdir(exist_ok=True)
 work=pathlib.Path(tempfile.mkdtemp(prefix='audio-work-',dir=HERE/'build'));ndkbin=a.sdk/'android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin';commands=[];env=os.environ.copy();env['SOURCE_DATE_EPOCH']='1792280091';log=(out/'AUDIO-BUILD.log').open('w')
 def run(cmd,cwd=None,e=None):
  command=[str(x)for x in cmd];commands.append(command);log.write('$ '+' '.join(command)+'\n');log.flush();r=subprocess.run(command,cwd=cwd,env=e or env,stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:raise SystemExit('Audio build failed; see '+str(out/'AUDIO-BUILD.log'))
 for arch in ['arm64','host']:
  prefix=work/(arch+'-install');e=env.copy()
  e['CFLAGS']='-O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fvisibility=hidden -ffile-prefix-map='+str(work)+'=/aegis-audio'
  if arch=='arm64':e.update(CC=str(ndkbin/'aarch64-linux-android33-clang'),AR=str(ndkbin/'llvm-ar'),RANLIB=str(ndkbin/'llvm-ranlib'),STRIP=str(ndkbin/'llvm-strip'),LDFLAGS='-Wl,-z,max-page-size=16384 -Wl,-z,relro,-z,now')
  for name,(version,digest,url)in SOURCES.items():
   folder=work/(arch+'-'+name);folder.mkdir()
   with tarfile.open(a.sources/(name+'-'+version+'.tar.gz'))as archive:archive.extractall(folder,filter='data')
   source=folder/(name+'-'+version);args=['./configure','--disable-shared','--enable-static','--with-pic','--prefix='+str(prefix)]
   if arch=='arm64':args+=['--host=aarch64-linux-android']
   args+=['--disable-extra-programs'if arch=='arm64'else'--enable-extra-programs','--disable-doc','--disable-deep-plc','--disable-dred','--disable-osce']if name=='opus'else['--disable-examples']
   run(args,source,e);run(['make','-j4'],source,e);run(['make','install'],source,e)
   # Native Android execution is not claimed. Run the real upstream suites on host.
   if arch=='host':
    run(['make','check','-j2'],source,e)
    for report in source.rglob('test-suite.log'):shutil.copy2(report,out/(name+'-'+str(report.relative_to(source)).replace('/','-')))
   shutil.copy2(source/'COPYING',HERE/'third-party'/(name.upper()+'-LICENSE.txt'))
  target=out/('lib/arm64-v8a/libaegis_audio.so'if arch=='arm64'else'host/libaegis_audio.so');target.parent.mkdir(parents=True,exist_ok=True)
  compiler=ndkbin/'aarch64-linux-android33-clang'if arch=='arm64'else'gcc'
  cmd=[compiler,'-shared','-O2','-fPIC','-fstack-protector-strong','-D_FORTIFY_SOURCE=2','-fvisibility=hidden','-Werror','-Wall','-Wextra','-I'+str(prefix/'include')]
  if arch=='host':cmd+=['-I'+str(a.jdk/'include'),'-I'+str(a.jdk/'include/linux')]
  cmd += [HERE/'native/aegis_audio.c',prefix/'lib/libopus.a',prefix/'lib/libspeexdsp.a','-lm','-pthread','-Wl,--exclude-libs,ALL','-Wl,-z,relro,-z,now']
  if arch=='arm64':cmd+=['-Wl,-z,max-page-size=16384','-Wl,-soname,libaegis_audio.so']
  run(cmd+['-o',target])
  if arch=='arm64':run([ndkbin/'llvm-strip','--strip-unneeded',target])
 elf=subprocess.check_output([str(ndkbin/'llvm-readelf'),'-h','-l','-d',str(out/'lib/arm64-v8a/libaegis_audio.so')],text=True);assert 'AArch64'in elf
 for line in elf.splitlines():
  if line.strip().startswith('LOAD'):assert int(line.split()[-1],16)>=16384
 (out/'AUDIO-ARM64-ELF.txt').write_text(elf)
 report={'schemaVersion':1,'productionReady':False,'sources':{name:{'version':v,'sourceSha256':s,'sourceUrl':u,'license':'BSD-3-Clause','authentication':'Official HTTPS archive + exact existing project SHA256; no upstream signature claimed'}for name,(v,s,u)in SOURCES.items()},'ndkRevision':'29.0.14206865','ndkArchiveSha256':NDK_SHA,'jniSourceSha256':sha(HERE/'native/aegis_audio.c'),'arm64LibrarySha256':sha(out/'lib/arm64-v8a/libaegis_audio.so'),'hostLibrarySha256':sha(out/'host/libaegis_audio.so'),'minimumApi':33,'loadSegmentAlignment':16384,'hostUpstreamSuites':{'opus':'See copied actual nonzero upstream test-suite.log','speexdsp':'make check exits zero but no automated test suite provided; not counted as tests'},'androidAudioRecordTrack':'NOT_RUN','nativeARM64Execution':'NOT_RUN','commands':commands}
 (out/'AUDIO-PROVENANCE.json').write_text(json.dumps(report,indent=2)+'\n');log.close();print(json.dumps(report,indent=2))
if __name__=='__main__':main()
