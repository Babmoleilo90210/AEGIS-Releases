#!/usr/bin/env python3
"""Build client-only distributions, never server/config.
Fresh --inputs: verified prepare-inputs output, jlink from Linux/Windows jmods.
--linux-base/--windows-base: reuse identical audited 0.2 runtime/Tor native files.
"""
import argparse,pathlib,shutil,subprocess,os,zipfile,json,tempfile
from verify_appimage import verify
from client_runtime import sha256, verify_safe_web_runtime, verify_voice_native
from java_runtime import verify_java_runtime
root=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser()
p.add_argument('--java-linux',type=pathlib.Path,required=True);p.add_argument('--java-windows',type=pathlib.Path,required=True)
p.add_argument('--voice-linux',type=pathlib.Path,required=True);p.add_argument('--voice-windows',type=pathlib.Path,required=True);p.add_argument('--inputs',type=pathlib.Path);p.add_argument('--linux-base',type=pathlib.Path);p.add_argument('--windows-base',type=pathlib.Path)
p.add_argument('--mingw',type=pathlib.Path,required=True);p.add_argument('--makensis',type=pathlib.Path,required=True)
p.add_argument('--appimagetool',type=pathlib.Path);p.add_argument('--appimage-runtime',type=pathlib.Path,required=True);p.add_argument('--mksquashfs',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path,required=True)
a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True);stage=out/'stage';stage.mkdir(exist_ok=True)
def run(args,**kw):subprocess.run([str(v) for v in args],check=True,**kw)
def copy(src,dst):shutil.copytree(src,dst,dirs_exist_ok=True)
def fresh(target,platform):
 assets=a.inputs.resolve()/'assets'
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
 for name in ['README-WINDOWS.md','README-CACHYOS.md','README.md','BUILD-CLIENTS.md','CRYPTO-1.0.0.md','MIGRATION-1.0-TO-1.1.md','BUILD-2.5.0.md','ARCHIVE-1.5.0.md','MIGRATION-1.5.0-TO-2.5.0.md','NATIVE-ACCEPTANCE-2.5.0.md','SECURITY.md','THREAT_MODEL.md','PRIVACY.md','PROTOCOL.md','ARCHIVE-THREAT-MODEL-2.5.0.md','P2P-VERIFICATION-2.5.0.md','OWNER-OFFLINE-SIGNING-2.5.0.md','CHANGELOG-2.5.0.md','TEST-REPORT-2.5.0.md','RELEASE-GATES-2.5.0.json']:
  if (root/name).is_file():shutil.copy2(root/name,target/name)
 for extra in ['SAFE-WEB-DISTRIBUTION-AUTH-2.5.0.md','SOURCE-PROVENANCE-2.5.0.json','SAFE-WEB-2.5.0.md','SAFE-WEB-THREAT-MODEL-2.5.0.md','INTERFACE-REFINEMENT-2.5.0.md','PROFILE-SYNC-2.5.0.md','RELAY-PROFILE-NICKNAME-PROPOSAL-2.5.0.md','IMPLEMENTATION-REPORT-2.5.0-RU.md','FINAL-VERIFICATION-2.5.0.json']:
  if (root/extra).exists():shutil.copy2(root/extra,target/extra)
 if (root/'docs').is_dir():copy(root/'docs',target/'docs')
 for extra in root.glob('*2.5.0*.md'):shutil.copy2(extra,target/extra.name)
 for extra in root.glob('*2.5.0*.json'):shutil.copy2(extra,target/extra.name)
 copy(root/'resources',target/'resources')
def prepare(name,platform,base):
 target=stage/name
 if target.exists():shutil.rmtree(target)
 target.mkdir()
 if base:
  base=base.resolve()
  for folder in ['tor','native','licenses']:copy(base/folder,target/folder)
  if (base/'BUILD-INPUTS.json').exists():shutil.copy2(base/'BUILD-INPUTS.json',target/'BUILD-INPUTS.json')
 else:fresh(target,platform)
 manifest=target/'BUILD-INPUTS.json'
 if base and manifest.exists():
  original=json.loads(manifest.read_text())
  if isinstance(original,dict):original=original.get('reused_0_2_0_manifest',original)
  manifest.write_text(json.dumps({'client_version':'2.5.0','tor_sodium':'SHA-256 verified published AEGIS 2.0.0 Beta Tor/libsodium; Linux PT mode is 0755','java_runtime':'Explicit reviewed Java 21 input with jdk.localedata; see JAVA-RUNTIME-2.5.0.json','reused_0_2_0_manifest':original,'client_build_tools':{'Java':'21; exact JDK recorded separately','packaging':'native launchers rebuilt; NSIS; Type 2 SquashFS runtime','nativeAcceptance':'NOT_RUN'}},indent=2))
 java=(a.java_windows if platform=='win' else a.java_linux).resolve()
 java_info=verify_java_runtime(java,platform)
 copy(java,target/'runtime');verify_java_runtime(target/'runtime',platform)
 (target/'JAVA-RUNTIME-2.5.0.json').write_text(json.dumps(java_info,indent=2)+'\n')
 voice=(a.voice_windows if platform=='win' else a.voice_linux).resolve()
 verify_voice_native(voice,platform)
 copy(voice/'native',target/'native');copy(voice/'licenses',target/'licenses')
 copy(root/'client-ui/build/stage'/platform,target/'app');runtime_pins=verify_safe_web_runtime(target/'app');docs(target)
 (target/'RUNTIME-DEPENDENCIES-2.5.0.json').write_text(json.dumps({'version':'2.5.0','platform':platform,'scope':'offline copied dependency hashes; no native acceptance claim','safeWebRuntimePins':runtime_pins,'runtimeJars':{jar.name:sha256(jar) for jar in sorted((target/'app').glob('*.jar'))}},indent=2)+'\n')
 import zipfile
 for jar in (target/'app').glob('*.jar'):
  with zipfile.ZipFile(jar) as archive:
   for name in archive.namelist():
    leaf=pathlib.PurePosixPath(name).name
    if not name.endswith('/') and name.startswith('META-INF/') and leaf.upper().startswith(('LICENSE','NOTICE','COPYING')):
     if archive.getinfo(name).file_size>262144:raise ValueError('Unexpectedly large dependency license: '+jar.name)
     (target/'licenses'/(jar.stem+'-'+leaf)).write_bytes(archive.read(name))
 return target
win=prepare('AEGIS','win',a.windows_base);mingw=a.mingw.resolve();res=stage/'launcher.res'
compiler=mingw/'x86_64-w64-mingw32-clang'
if not compiler.exists():compiler=mingw/'x86_64-w64-mingw32-gcc'
if not compiler.exists():compiler=mingw/'x86_64-w64-mingw32-gcc-win32'
run([mingw/'x86_64-w64-mingw32-windres','launcher.rc','-O','coff','-o',res],cwd=root/'packaging/windows')
run([compiler,'-Os','-municode','-mwindows',root/'packaging/windows/launcher.c',res,'-Wl,--dynamicbase,--nxcompat,--high-entropy-va','-luser32','-o',win/'AEGIS.exe'])
run([compiler,'-Os','-municode','-mwindows',root/'packaging/windows/maintenance.c',res,'-Wl,--dynamicbase,--nxcompat,--high-entropy-va','-luser32','-lshell32','-ladvapi32','-o',win/'AEGIS-Maintenance.exe'])
run([compiler,'-Os','-municode','-mwindows',root/'packaging/windows/updater.c',res,'-Wl,--dynamicbase,--nxcompat,--high-entropy-va','-luser32','-lshell32','-o',win/'AEGIS-Updater.exe'])
res.unlink();shutil.copy2(root/'packaging/windows/CreateShortcuts.ps1',win/'CreateShortcuts.ps1')
with zipfile.ZipFile(out/'AEGIS-2.5.0-Windows-x64.zip','w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for file in sorted(win.rglob('*')):
  if file.is_file():z.write(file,pathlib.Path('AEGIS')/file.relative_to(win))
run([a.makensis.resolve(),'-V2','-DPAYLOAD='+str(win),'-DOUTFILE='+str(out/'AEGIS-Setup-2.5.0-x64.exe'),'installer.nsi'],cwd=root/'packaging/windows')
linux=prepare('AEGIS.AppDir','linux',a.linux_base)
(linux/'tor/pluggable_transports/lyrebird').chmod(0o755)
(linux/'tor/tor').chmod(0o755)
for name in ['AppRun','aegis.desktop']:shutil.copy2(root/'packaging/linux'/name,linux/name)
(linux/'AppRun').chmod(0o755)
for name in ['aegis.png','.DirIcon']:shutil.copy2(root/'resources/aegis.png',linux/name)
env=os.environ.copy();env['ARCH']='x86_64';env['SOURCE_DATE_EPOCH']='1791201600';env['APPIMAGE_EXTRACT_AND_RUN']='1'
image=out/'AEGIS-2.5.0-CachyOS-x86_64.AppImage'
# Always build into a fresh file. Repeated in-place packaging produced a truncated
# image in the build environment despite a successful appimagetool exit status.
# Keep the previous release until the new runtime and complete payload pass checks.
with tempfile.TemporaryDirectory(prefix='.appimage-build-',dir=out) as directory:
 candidate=pathlib.Path(directory)/image.name
 if a.mksquashfs:
  squash=pathlib.Path(directory)/'payload.squashfs'
  # The verified Type 2 runtime supports zlib/zstd, not xz. Validate by actual extraction.
  run([a.mksquashfs.resolve(),linux,squash,'-noappend','-processors','2','-comp','zstd','-b','131072','-all-root','-no-xattrs','-mkfs-time',env['SOURCE_DATE_EPOCH'],'-all-time',env['SOURCE_DATE_EPOCH']])
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
