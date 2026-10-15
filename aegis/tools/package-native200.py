#!/usr/bin/env python3
"""Build a separate owner-side 2.0.0 native acceptance kit from final source/client ZIPs.
No network, publication, signing, production profile edits, or production classpath changes.
"""
import argparse,hashlib,json,pathlib,shutil,subprocess,tempfile,zipfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--jdk',required=True,type=pathlib.Path);p.add_argument('--artifacts',required=True,type=pathlib.Path);p.add_argument('--staging-deps',type=pathlib.Path);a=p.parse_args()
r=a.artifacts.resolve();jdk=a.jdk.resolve();version='2.0.0'
def sha(file):
 with file.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def extract(file,dest):
 with zipfile.ZipFile(file) as z:
  assert z.testzip() is None
  for info in z.infolist():
   x=pathlib.PurePosixPath(info.filename);assert not x.is_absolute() and '..' not in x.parts and '\\' not in info.filename
   assert (info.external_attr>>16)&0o170000!=0o120000
  z.extractall(dest)
kit=r/'native-acceptance';kit.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='aegis200-native-kit-build-') as temp:
 temp=pathlib.Path(temp);extract(r/f'AEGIS-{version}-client-source.zip',temp/'source');source=temp/'source/aegis'
 extract(r/f'AEGIS-{version}-Windows-x64.zip',temp/'client');app=temp/'client/AEGIS'
 native=source/'client-core/src/test/java/org/securemail/client/security';ui=source/'client-ui/src/smoke/java'
 classes=temp/'classes';classes.mkdir();sources=[native/'NativeAcceptanceMain.java',native/'NativeCredentialStoreSmoke.java',*sorted(ui.rglob('*.java'))]
 wrapper=temp/'AppearanceNativeLauncher.java'
 wrapper.write_text('''package org.securemail.ui;
/** Owner-only synthetic fixtures; never installed in the application. */
public final class AppearanceNativeLauncher {
 public static void main(String[] args)throws Exception {
  if(args.length<1||args.length>2)throw new IllegalArgumentException("Specify app directory and optional responsive mode");
  System.setProperty("aegis.home",java.nio.file.Path.of(args[0]).toAbsolutePath().toString());
  org.securemail.client.net.TorTransport.requireAvailability(()->false);
  if(args.length==2&&args[1].equals("safeweb"))SafeWeb200Smoke.main(new String[0]);
  else if(args.length==2&&args[1].equals("responsive"))SettingsResponsive200Smoke.main(new String[0]);
  else Interface200Smoke.main(new String[0]);
 }
}
''');sources.append(wrapper);(kit/'AppearanceNativeLauncher.java').write_text(wrapper.read_text())
 source_list=temp/'sources';source_list.write_text('\n'.join('"'+str(f).replace('\\','\\\\')+'"' for f in sources)+'\n')
 javac=jdk/'bin/javac';jar=jdk/'bin/jar';suffix='.exe' if (jdk/'bin/javac.exe').exists() else ''
 subprocess.run([str(javac)+suffix,'--release','21','-encoding','UTF-8','-cp',str(app/'app/*'),'-d',str(classes),'@'+str(source_list)],check=True,timeout=120)
 # Classes are deliberately separate from app/*.jar and never replace the pinned verifier.
 native_classes=temp/'native-classes';ui_classes=temp/'ui-classes';native_classes.mkdir();ui_classes.mkdir()
 for f in classes.rglob('*.class'):
  rel=f.relative_to(classes);target=(native_classes if 'security' in rel.parts else ui_classes)/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(f,target)
 for name,folder in [('aegis-native-tests.jar',native_classes),('aegis-ui-tests.jar',ui_classes)]:
  subprocess.run([str(jar)+suffix,'--create','--file',str(kit/name),'-C',str(folder),'.'],check=True,timeout=30)
 for name in ['Run-Windows.cmd','Run-CachyOS.sh']:
  text=(source/'packaging/native-kit'/name).read_text().replace('1.0.0',version).replace('aegis-native-tests.jar;', 'aegis-native-tests.jar;%aegis_test_kit%aegis-ui-tests.jar;').replace('aegis-native-tests.jar:', 'aegis-native-tests.jar:$aegis_test_kit/aegis-ui-tests.jar:')
  (kit/name).write_bytes((text.replace('\r\n','\n').replace('\n','\r\n') if name.endswith('.cmd') else text).encode('utf-8'))
 (kit/'Run-CachyOS.sh').chmod(0o755)
 hashes={f.name:sha(f) for f in (app/'app').glob('*.jar') if f.name.startswith(('client-core-','client-ui-','common-protocol-'))}
 metadata={'version':version,'productionReady':False,'applicationJarSha256':hashes,'sourceZipSha256':sha(r/f'AEGIS-{version}-client-source.zip'),'productionClientClasspathModified':False,'signatureFixture':'EPHEMERAL_TEST_KEY_ONLY'}
 (kit/'TESTED-ARTIFACTS.json').write_text(json.dumps(metadata,indent=2)+'\n')
 if a.staging_deps:
  staging=kit/'staging';staging.mkdir(exist_ok=True)
  relay=pathlib.Path(__file__).resolve().parents[1]/'build/local-java21/compatibility/relay02/lib/relay-server.jar';shutil.copy2(relay,staging/relay.name)
  for dep in a.staging_deps.glob('*.jar'):
   if dep.name.startswith(('password4j-','sqlite-jdbc-','slf4j-')):shutil.copy2(dep,staging/dep.name)
  main=source/'integration-tests/src/test/java/org/securemail/integration/LifecycleTorProbe.java'
  import os
  cp=str(app/'app/*')+os.pathsep+str(staging/'*')
  stageclasses=temp/'stageclasses';stageclasses.mkdir()
  subprocess.run([str(javac)+suffix,'--release','21','-encoding','UTF-8','-cp',cp,'-d',str(stageclasses),str(main)],check=True,timeout=90)
  subprocess.run([str(jar)+suffix,'--create','--file',str(staging/'lifecycle-tor-tests.jar'),'-C',str(stageclasses),'.'],check=True,timeout=30)
  (staging/'README.md').write_text('Disposable staging Relay 0.2.0 (independently compiled SHA-verified published 1.0.0 source) and test-only dependencies. Never add these JARs to app/*.jar. Linux-only: the existing Debian Relay uses POSIX filesystem permissions. The real-Tor lifecycle probe generates two throwaway identities/accounts and three ephemeral onion services, on this device only. Production relay/feed/keys are not touched. Cross-network Windows11/KDE acceptance remains separate.\n')

 # Separate current-Relay profile probe; legacy lifecycle compatibility probe above
 # is retained independently and cannot exercise public-profile capability.
 if a.staging_deps:
  profile_stage=kit/'staging-profile';profile_stage.mkdir(exist_ok=True)
  current_relay=pathlib.Path(__file__).resolve().parents[1]/'build/local-java21/relay-server.jar'
  shutil.copy2(current_relay,profile_stage/'relay-server.jar')
  for dep in a.staging_deps.glob('*.jar'):
   if dep.name.startswith(('password4j-','sqlite-jdbc-','slf4j-')):shutil.copy2(dep,profile_stage/dep.name)
  profileclasses=temp/'profileclasses';profileclasses.mkdir()
  cp=str(app/'app/*')+os.pathsep+str(profile_stage/'*')
  subprocess.run([str(javac)+suffix,'--release','21','-encoding','UTF-8','-cp',cp,'-d',str(profileclasses),str(source/'integration-tests/src/test/java/org/securemail/integration/PublicProfileTorProbe.java')],check=True,timeout=90)
  subprocess.run([str(jar)+suffix,'--create','--file',str(profile_stage/'public-profile-tor-tests.jar'),'-C',str(profileclasses),'.'],check=True,timeout=30)
  (profile_stage/'README.md').write_text('Current candidate staging Relay and public-profile operator probe. Uses disposable accounts/database/onion and real bundled Tor. A SOCKS harness is not used. Does not access production endpoints or change production client classpath. The Linux run below is not Windows11/KDE/cross-network acceptance. Tor bootstrap failure leaves all profile cases NOT_RUN.\n')
  (kit/'Run-Public-Profiles-CachyOS.sh').write_text('''#!/usr/bin/env bash
set -euo pipefail
umask 077
aegis_probe_kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
aegis_probe_image=$(realpath -- "${1:?Укажите AppImage первым аргументом}")
aegis_probe_temp=$(mktemp -d -t aegis200-profile-probe-XXXXXXXX)
trap 'rm -rf -- "$aegis_probe_temp"' EXIT
(cd -- "$aegis_probe_temp" && "$aegis_probe_image" --appimage-extract >/dev/null)
aegis_probe_app="$aegis_probe_temp/squashfs-root"
unset JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS CLASSPATH
"$aegis_probe_app/runtime/bin/java" -Xmx768m -Daegis.native.root="$aegis_probe_app" -cp "$aegis_probe_app/app/*:$aegis_probe_kit/staging-profile/*" org.securemail.integration.PublicProfileTorProbe "$aegis_probe_app" "$aegis_probe_kit/public-profile-results" snowflake
''')
  (kit/'Run-Public-Profiles-CachyOS.sh').chmod(0o755)

 (kit/'Run-Appearance-Windows.cmd').write_bytes('''@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
set "aegis_test_app=%~1"
if not defined aegis_test_app set "aegis_test_app=%~dp0..\\AEGIS"
if not exist "%aegis_test_app%\\runtime\\bin\\java.exe" (
 echo Передайте каталог portable АЕГИС первым аргументом.
 pause
 exit /b 2
)
set "JAVA_TOOL_OPTIONS="
set "_JAVA_OPTIONS="
set "JDK_JAVA_OPTIONS="
set "CLASSPATH="
cd /d "%~dp0"
"%aegis_test_app%\\runtime\\bin\\java.exe" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "%~dp0aegis-native-tests.jar;%~dp0aegis-ui-tests.jar;%aegis_test_app%\\app\\*" org.securemail.ui.AppearanceNativeLauncher "%aegis_test_app%"
set "aegis_status=%ERRORLEVEL%"
if not "%aegis_status%"=="0" goto aegis_finish
"%aegis_test_app%\\runtime\\bin\\java.exe" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "%~dp0aegis-native-tests.jar;%~dp0aegis-ui-tests.jar;%aegis_test_app%\\app\\*" org.securemail.ui.AppearanceNativeLauncher "%aegis_test_app%" responsive
set "aegis_status=%ERRORLEVEL%"
if not "%aegis_status%"=="0" goto aegis_finish
"%aegis_test_app%\\runtime\\bin\\java.exe" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "%~dp0aegis-native-tests.jar;%~dp0aegis-ui-tests.jar;%aegis_test_app%\\app\\*" org.securemail.ui.AppearanceNativeLauncher "%aegis_test_app%" safeweb
set "aegis_status=%ERRORLEVEL%"
:aegis_finish
echo Синтетические снимки: build\\ui200-screenshots. Это не production profile.
pause
exit /b %aegis_status%
'''.replace('\n','\r\n').encode('utf-8'))
 (kit/'Run-Appearance-CachyOS.sh').write_text('''#!/usr/bin/env bash
set -euo pipefail
umask 077
aegis_test_kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
aegis_test_image=$(realpath -- "${1:?Укажите AppImage первым аргументом}")
aegis_test_temp=$(mktemp -d -t aegis200-appearance-XXXXXXXX)
trap 'rm -rf -- "$aegis_test_temp"' EXIT
(cd -- "$aegis_test_temp" && "$aegis_test_image" --appimage-extract >/dev/null)
aegis_test_app="$aegis_test_temp/squashfs-root"
unset JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS CLASSPATH
cd -- "$aegis_test_kit"
"$aegis_test_app/runtime/bin/java" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "$aegis_test_kit/aegis-native-tests.jar:$aegis_test_kit/aegis-ui-tests.jar:$aegis_test_app/app/*" org.securemail.ui.AppearanceNativeLauncher "$aegis_test_app"
"$aegis_test_app/runtime/bin/java" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "$aegis_test_kit/aegis-native-tests.jar:$aegis_test_kit/aegis-ui-tests.jar:$aegis_test_app/app/*" org.securemail.ui.AppearanceNativeLauncher "$aegis_test_app" responsive
"$aegis_test_app/runtime/bin/java" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "$aegis_test_kit/aegis-native-tests.jar:$aegis_test_kit/aegis-ui-tests.jar:$aegis_test_app/app/*" org.securemail.ui.AppearanceNativeLauncher "$aegis_test_app" safeweb
printf '%s\\n' 'Синтетические снимки: build/ui200-screenshots. Это не production profile.'
''');(kit/'Run-Appearance-CachyOS.sh').chmod(0o755)
 (kit/'README.md').write_text('''# Native acceptance kit АЕГИС 2.0.0

Это отдельный тестовый комплект, не часть production classpath. Сборка комплекта сама по себе не является native PASS.

Распакуйте portable Windows ZIP рядом с native-acceptance и запустите Run-Windows.cmd. Он использует встроенный Java21, проверяет реальные JAR hashes, криптографию, vault, DPAPI, JavaFX и синтетические GUI сцены. Для установленного клиента можно передать каталог первым аргументом. Затем Run-Appearance-Windows.cmd <каталог AEGIS> запускает 16 пресетов, архив, навигацию, пять групп настроек, logical scale 100/125/150/200 и одну Scene. Системное письмо в этой проверке подписано временным тестовым ключом; production ключ не используется. К сети тест не подключается.

На CachyOS выполните bash Run-CachyOS.sh <AppImage>, затем bash Run-Appearance-CachyOS.sh <AppImage>. Python/JDK/Gradle для запуска не нужны. Повторите в KDE Wayland и X11. Система DPI не меняется: запускайте отдельно при разных настройках дисплея. Не открывайте production key и не отключайте Defender/firewall.

Тесты не меняют реальный профиль, создают искусственные данные. NativeAcceptanceMain сохраняет JSON результатов без паролей/ключей. Дополнительная проверка оформления пишет synthetic screenshots в build/ui200-screenshots. В NativeAcceptanceMain добавлена реальная проверка пяти JavaFX шрифтов с кириллицей, карточки подключения и встроенного просмотра аватара. Friends/receipts/исчезновение реализованы client-only и требуют двух реальных клиентов для native PASS. В каталоге staging есть отдельный тест реальных onion services с disposable Relay 0.2.0; не добавляйте staging JARs в app/. Его PASS не заменяет Windows11/KDE/cross-network acceptance. Полная приёмка через обычный интерфейс, cross-platform Relay, миграция, reboot и подписанный updater выполняются дополнительно по NATIVE-ACCEPTANCE-2.0.0.md. FAIL_OR_UNAVAILABLE не равен PASS. productionReady остаётся false до всех обязательных проверок.

Состав тестов пересобирается package-native200.py из exact source/client ZIP текущего кандидата и явно переданного JDK21. Все классы fixture/wrapper остаются только в этом комплекте. Приложение не загружает эти JAR.
''',encoding='utf-8')
shutil.copy2(pathlib.Path(__file__),kit/'package-native200.py')
(kit/'SHA256SUMS').write_text(''.join(sha(f)+'  '+f.relative_to(kit).as_posix()+'\n' for f in sorted(kit.rglob('*')) if f.is_file() and f.name!='SHA256SUMS'))
archive=r/f'AEGIS-{version}-native-acceptance.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for f in sorted(kit.rglob('*')):
  if f.is_file():z.write(f,'native-acceptance/'+f.relative_to(kit).as_posix())
with zipfile.ZipFile(archive) as z:assert z.testzip() is None
print(json.dumps({'file':archive.name,'sha256':sha(archive),'nativeAcceptanceExecuted':False}))
