#!/usr/bin/env python3
"""Build client-only distributions, never server/config.
Fresh --inputs: verified prepare-inputs output, jlink from Linux/Windows jmods.
--linux-base/--windows-base: reuse identical audited 0.2 runtime/Tor native files.
"""
import argparse,pathlib,shutil,subprocess,os,zipfile,json,tempfile
from verify_appimage import verify
root=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser()
p.add_argument('--inputs',type=pathlib.Path);p.add_argument('--linux-base',type=pathlib.Path);p.add_argument('--windows-base',type=pathlib.Path)
p.add_argument('--mingw',type=pathlib.Path,required=True);p.add_argument('--makensis',type=pathlib.Path,required=True)
p.add_argument('--appimagetool',type=pathlib.Path);p.add_argument('--appimage-runtime',type=pathlib.Path,required=True);p.add_argument('--mksquashfs',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path,required=True)
a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True);stage=out/'stage';stage.mkdir(exist_ok=True)
def run(args,**kw):subprocess.run([str(v) for v in args],check=True,**kw)
def copy(src,dst):shutil.copytree(src,dst,dirs_exist_ok=True)
def fresh(target,platform):
 assets=a.inputs.resolve()/'assets';jdk=next((assets/'jdk-linux').glob('*'));mods=next((assets/('jdk-win' if platform=='win' else 'jdk-linux')).glob('*'))/'jmods'
 run([jdk/'bin/jlink','--module-path',mods,'--add-modules','java.base,java.desktop,java.logging,java.management,java.naming,java.sql,jdk.crypto.ec,jdk.unsupported,jdk.charsets','--strip-debug','--no-header-files','--no-man-pages','--compress=zip-6','--output',target/'runtime'])
 torroot=assets/('tor-win' if platform=='win' else 'tor-linux')
 copy(torroot/'tor',target/'tor');copy(torroot/'data',target/'tor/data')
 for unused in ['tor-gencert','tor-gencert.exe']:(target/'tor'/unused).unlink(missing_ok=True)
 for unused in (target/'tor/pluggable_transports').iterdir():
  if unused.name not in ['lyrebird','lyrebird.exe','pt_config.json']:
   if unused.is_dir():shutil.rmtree(unused)
   else:unused.unlink()
 if (torroot/'docs').exists():copy(torroot/'docs',target/'tor/licenses')
 import json
 bridges=json.loads((target/'tor/pluggable_transports/pt_config.json').read_text())['bridges']['snowflake']
 (target/'tor/snowflake-bridges.txt').write_text('\n'.join(bridges)+'\n')
 (target/'native').mkdir(exist_ok=True)
 sodium=assets/'sodium-win/libsodium-win64/bin/libsodium-26.dll' if platform=='win' else assets/'sodium-install/lib/libsodium.so'
 shutil.copy2(sodium,target/'native'/('libsodium.dll' if platform=='win' else 'libsodium.so'))
 (target/'licenses').mkdir(exist_ok=True);shutil.copy2(assets/'sodium-src/libsodium-stable/LICENSE',target/'licenses/libsodium-LICENSE')
 shutil.copy2(a.inputs/'manifest.json',target/'BUILD-INPUTS.json')
def docs(target):
 for name in ['README-WINDOWS.md','README-CACHYOS.md','README.md','BUILD-CLIENTS.md','CRYPTO-1.0.0.md','MIGRATION-1.0-TO-1.1.md','BUILD-1.1.5.md','APPEARANCE-1.1.5.md','MIGRATION-1.1.1-TO-1.1.5.md','NATIVE-ACCEPTANCE-1.1.5.md','SECURITY.md','THREAT_MODEL.md','PRIVACY.md','PROTOCOL.md','CHANGELOG-1.1.5.md','TEST-REPORT-1.1.5.md','RELEASE-GATES-1.1.5.json']:
  if (root/name).is_file():shutil.copy2(root/name,target/name)
 if (root/'docs').is_dir():copy(root/'docs',target/'docs')
 copy(root/'resources',target/'resources')
def prepare(name,platform,base):
 target=stage/name
 if target.exists():shutil.rmtree(target)
 target.mkdir()
 if base:
  base=base.resolve()
  for folder in ['runtime','tor','native','licenses']:copy(base/folder,target/folder)
  if (base/'BUILD-INPUTS.json').exists():shutil.copy2(base/'BUILD-INPUTS.json',target/'BUILD-INPUTS.json')
 else:fresh(target,platform)
 manifest=target/'BUILD-INPUTS.json'
 if base and manifest.exists():
  original=json.loads(manifest.read_text())
  if isinstance(original,dict):original=original.get('reused_0_2_0_manifest',original)
  manifest.write_text(json.dumps({'client_version':'1.1.5','runtime_tor_sodium':'verified released AEGIS 1.0.0 assets; unchanged Java 21/Tor/libsodium; Linux PT mode is 0755','reused_0_2_0_manifest':original,'client_build_tools':{'Java':'21; exact JDK recorded separately','packaging':'native launchers rebuilt; NSIS; Type 2 SquashFS runtime','nativeAcceptance':'NOT_RUN'}},indent=2))
 copy(root/'client-ui/build/stage'/platform,target/'app');docs(target)
 return target
win=prepare('AEGIS','win',a.windows_base);mingw=a.mingw.resolve();res=stage/'launcher.res'
compiler=mingw/'x86_64-w64-mingw32-clang'
if not compiler.exists():compiler=mingw/'x86_64-w64-mingw32-gcc'
run([mingw/'x86_64-w64-mingw32-windres','launcher.rc','-O','coff','-o',res],cwd=root/'packaging/windows')
run([compiler,'-Os','-municode','-mwindows',root/'packaging/windows/launcher.c',res,'-Wl,--dynamicbase,--nxcompat,--high-entropy-va','-luser32','-o',win/'AEGIS.exe'])
run([compiler,'-Os','-municode','-mwindows',root/'packaging/windows/maintenance.c',res,'-Wl,--dynamicbase,--nxcompat,--high-entropy-va','-luser32','-lshell32','-ladvapi32','-o',win/'AEGIS-Maintenance.exe'])
run([compiler,'-Os','-municode','-mwindows',root/'packaging/windows/updater.c',res,'-Wl,--dynamicbase,--nxcompat,--high-entropy-va','-luser32','-lshell32','-o',win/'AEGIS-Updater.exe'])
res.unlink();shutil.copy2(root/'packaging/windows/CreateShortcuts.ps1',win/'CreateShortcuts.ps1')
with zipfile.ZipFile(out/'AEGIS-1.1.5-Windows-x64.zip','w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for file in sorted(win.rglob('*')):
  if file.is_file():z.write(file,pathlib.Path('AEGIS')/file.relative_to(win))
run([a.makensis.resolve(),'-V2','-DPAYLOAD='+str(win),'-DOUTFILE='+str(out/'AEGIS-Setup-1.1.5-x64.exe'),'installer.nsi'],cwd=root/'packaging/windows')
linux=prepare('AEGIS.AppDir','linux',a.linux_base)
(linux/'tor/pluggable_transports/lyrebird').chmod(0o755)
(linux/'tor/tor').chmod(0o755)
for name in ['AppRun','aegis.desktop']:shutil.copy2(root/'packaging/linux'/name,linux/name)
(linux/'AppRun').chmod(0o755)
for name in ['aegis.png','.DirIcon']:shutil.copy2(root/'resources/aegis.png',linux/name)
env=os.environ.copy();env['ARCH']='x86_64';env['SOURCE_DATE_EPOCH']='1791201600';env['APPIMAGE_EXTRACT_AND_RUN']='1'
image=out/'AEGIS-1.1.5-CachyOS-x86_64.AppImage'
# Always build into a fresh file. Repeated in-place packaging produced a truncated
# image in the build environment despite a successful appimagetool exit status.
# Keep the previous release until the new runtime and complete payload pass checks.
with tempfile.TemporaryDirectory(prefix='.appimage-build-',dir=out) as directory:
 candidate=pathlib.Path(directory)/image.name
 if a.mksquashfs:
  squash=pathlib.Path(directory)/'payload.squashfs'
  # The verified Type 2 runtime supports zlib/zstd, not xz. Validate by actual extraction.
  run([a.mksquashfs.resolve(),linux,squash,'-noappend','-comp','zstd','-b','131072','-all-root','-no-xattrs','-mkfs-time',env['SOURCE_DATE_EPOCH'],'-all-time',env['SOURCE_DATE_EPOCH']])
  with candidate.open('wb') as output:
   for part in [a.appimage_runtime.resolve(),squash]:
    with part.open('rb') as input:shutil.copyfileobj(input,output)
  candidate.chmod(0o755)
 else:
  if not a.appimagetool:raise ValueError('AppImageTool or mksquashfs is required')
  run([a.appimagetool.resolve(),'--no-appstream','--runtime-file',a.appimage_runtime.resolve(),linux,candidate],env=env)
 verify(candidate,linux)
 with candidate.open('rb') as stream:os.fsync(stream.fileno())
 os.replace(candidate,image)
print('Created Windows ZIP, native Setup EXE and CachyOS AppImage. No server artifacts.')
