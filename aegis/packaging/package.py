#!/usr/bin/env python3
"""Create real native launchers, jlink runtimes and distributions from tested Gradle outputs.
Usage: python3 packaging/package.py /absolute/build-inputs /absolute/output [appimagetool-AppRun]
"""
import pathlib,subprocess,shutil,sys,json,os,zipfile
root=pathlib.Path(__file__).resolve().parents[1];inputs=pathlib.Path(sys.argv[1]).resolve();assets=inputs/'assets';out=pathlib.Path(sys.argv[2]).resolve();out.mkdir(parents=True,exist_ok=True)
stage=out/'stage';stage.mkdir(exist_ok=True);jdk=next((assets/'jdk-linux').glob('*'));winjdk=next((assets/'jdk-win').glob('*'));mingw=next((assets/'mingw').glob('*'))/'bin'
def run(args,**kw):print('RUN',pathlib.Path(str(args[0])).name,flush=True);subprocess.run([str(a) for a in args],check=True,**kw)
def runtime(target,jmods,server=False):
 if target.exists():return
 modules='java.base,java.logging,java.management,java.naming,java.sql,jdk.crypto.ec,jdk.unsupported,jdk.charsets'
 if not server:modules+=',java.desktop'
 run([jdk/'bin/jlink','--module-path',jmods,'--add-modules',modules,'--strip-debug','--no-header-files','--no-man-pages','--compress=zip-6','--output',target])
def copytree(src,dst):shutil.copytree(src,dst,dirs_exist_ok=True)
def tor(platform,target):
 src=assets/('tor-win' if platform=='win' else 'tor-linux');copytree(src/'tor',target)
 for name in ['tor-gencert.exe','tor-gencert']:(target/name).unlink(missing_ok=True)
 pt=target/'pluggable_transports'
 for p in list(pt.iterdir()):
  if p.name not in ['lyrebird','lyrebird.exe','pt_config.json']:
   if p.is_dir():shutil.rmtree(p)
   else:p.unlink()
 copytree(src/'data',target/'data')
 bridge=json.loads((pt/'pt_config.json').read_text())['bridges']['snowflake'];assert all('front=' not in s or ',' not in next((x[6:] for x in s.split() if x.startswith('front=')),'') for s in bridge)
 (target/'snowflake-bridges.txt').write_text('\n'.join(bridge)+'\n')
 (target/'torrc').write_text('# AEGIS generates its private torrc in the user profile. This file is documentation only.\n')
 # Complete Tor bundle license notices are kept, including third-party notices.
 if (src/'docs').exists():copytree(src/'docs',target/'licenses')
def docs(target):
 for name in ['README-WINDOWS.md','README-CACHYOS.md','README-SERVER.md','README.md','SECURITY.md','THREAT_MODEL.md','PRIVACY.md','CRYPTO.md','PROTOCOL.md','CHANGELOG.md','TEST-REPORT.md','BUILD.md','DEPENDENCIES.md','FIREWALL.md']:
  if (root/name).is_file():shutil.copy2(root/name,target/name)
 copytree(root/'resources',target/'resources')
 if (inputs/'manifest.json').exists():shutil.copy2(inputs/'manifest.json',target/'BUILD-INPUTS.json')
def zipdir(folder,path):
 with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
  for p in sorted(folder.rglob('*')):
   if p.is_file():z.write(p,pathlib.Path(folder.name)/p.relative_to(folder))
win=stage/'AEGIS';win.mkdir(exist_ok=True);runtime(win/'runtime',winjdk/'jmods');copytree(root/'client-ui/build/stage/win',win/'app');tor('win',win/'tor');(win/'native').mkdir(exist_ok=True);shutil.copy2(assets/'sodium-win/libsodium-win64/bin/libsodium-26.dll',win/'native/libsodium.dll')
res=root/'packaging/windows/launcher.res';run([mingw/'x86_64-w64-mingw32-windres','launcher.rc','-O','coff','-o',res],cwd=root/'packaging/windows');run([mingw/'x86_64-w64-mingw32-clang','-Os','-municode','-mwindows',root/'packaging/windows/launcher.c',res,'-Wl,--dynamicbase,--nxcompat,--high-entropy-va','-luser32','-o',win/'AEGIS.exe']);res.unlink();docs(win)
if (root/'packaging/windows/CreateShortcuts.ps1').exists():shutil.copy2(root/'packaging/windows/CreateShortcuts.ps1',win/'CreateShortcuts.ps1')
linux=stage/'AEGIS.AppDir';linux.mkdir(exist_ok=True);runtime(linux/'runtime',jdk/'jmods');copytree(root/'client-ui/build/stage/linux',linux/'app');tor('linux',linux/'tor');(linux/'native').mkdir(exist_ok=True);shutil.copy2(assets/'sodium-install/lib/libsodium.so',linux/'native/libsodium.so');shutil.copy2(root/'packaging/linux/AppRun',linux/'AppRun');(linux/'AppRun').chmod(0o755);shutil.copy2(root/'packaging/linux/aegis.desktop',linux/'aegis.desktop');shutil.copy2(root/'resources/aegis.png',linux/'aegis.png');shutil.copy2(root/'resources/aegis.png',linux/'.DirIcon');docs(linux)
server=stage/'AEGIS-server';server.mkdir(exist_ok=True);copytree(root/'packaging/server',server);copytree(root/'relay-server/build/install/relay-server/lib',server/'relay/lib');runtime(server/'relay/runtime',jdk/'jmods',True);(server/'relay/bin').mkdir(exist_ok=True)
(server/'relay/bin/relay-server').write_text('''#!/bin/sh
set -eu
app_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
unset JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS
exec "$app_dir/runtime/bin/java" -Xms32m -Xmx256m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -XX:ErrorFile=/dev/null -cp "$app_dir/lib/*" org.securemail.relay.RelayMain "$@"
''');(server/'relay/bin/relay-server').chmod(0o755);shutil.copy2(root/'config/relay.properties',server/'relay.properties');(server/'tor').mkdir(exist_ok=True);shutil.copy2(linux/'tor/pluggable_transports/lyrebird',server/'tor/lyrebird');shutil.copy2(linux/'tor/snowflake-bridges.txt',server/'tor/snowflake-bridges.txt');copytree(linux/'tor/licenses',server/'tor/licenses');docs(server)
for target in [win,linux,server]:
 (target/'licenses').mkdir(exist_ok=True);shutil.copy2(assets/'sodium-src/libsodium-stable/LICENSE',target/'licenses/libsodium-LICENSE')
 for p in target.rglob('__pycache__'):shutil.rmtree(p)
zipdir(win,out/'AEGIS-0.2.0-Windows-x64.zip');zipdir(server,out/'AEGIS-0.2.0-server-debian13.zip')
if len(sys.argv)>3:
 tool=pathlib.Path(sys.argv[3]).resolve();env=os.environ.copy();env['ARCH']='x86_64';env['SOURCE_DATE_EPOCH']='1790899200';env['APPIMAGE_EXTRACT_AND_RUN']='1'
 run([tool,'--no-appstream','--runtime-file',inputs/'runtime-x86_64',linux,out/'AEGIS-0.2.0-CachyOS-x86_64.AppImage'],env=env)
print('Distributions created',flush=True)
