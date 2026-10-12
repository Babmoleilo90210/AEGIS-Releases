#!/usr/bin/env python3
"""Build a separate owner-side 1.2.0 native acceptance kit from final source/client ZIPs.
No network, publication, signing, production profile edits, or production classpath changes.
"""
import argparse,hashlib,json,pathlib,shutil,subprocess,tempfile,zipfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--jdk',required=True,type=pathlib.Path);p.add_argument('--artifacts',required=True,type=pathlib.Path);a=p.parse_args()
r=a.artifacts.resolve();jdk=a.jdk.resolve();version='1.2.0'
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
with tempfile.TemporaryDirectory(prefix='aegis120-native-kit-build-') as temp:
 temp=pathlib.Path(temp);extract(r/f'AEGIS-{version}-client-source.zip',temp/'source');source=temp/'source/aegis'
 extract(r/f'AEGIS-{version}-Windows-x64.zip',temp/'client');app=temp/'client/AEGIS'
 native=source/'client-core/src/test/java/org/securemail/client/security';ui=source/'client-ui/src/smoke/java'
 classes=temp/'classes';classes.mkdir();sources=[native/'NativeAcceptanceMain.java',native/'NativeCredentialStoreSmoke.java',*sorted(ui.rglob('*.java'))]
 wrapper=temp/'AppearanceNativeLauncher.java'
 wrapper.write_text('''package org.securemail.ui;
/** Owner-only synthetic fixtures; never installed in the application. */
public final class AppearanceNativeLauncher {
 public static void main(String[] args)throws Exception {
  if(args.length!=1)throw new IllegalArgumentException("Specify app directory");
  System.setProperty("aegis.home",java.nio.file.Path.of(args[0]).toAbsolutePath().toString());
  org.securemail.client.net.TorTransport.requireAvailability(()->false);
  Appearance115Smoke.main(new String[0]);
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
echo Синтетические снимки: build\\ui115-screenshots. Это не production profile.
pause
exit /b %aegis_status%
'''.replace('\n','\r\n').encode('utf-8'))
 (kit/'Run-Appearance-CachyOS.sh').write_text('''#!/usr/bin/env bash
set -euo pipefail
umask 077
aegis_test_kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
aegis_test_image=$(realpath -- "${1:?Укажите AppImage первым аргументом}")
aegis_test_temp=$(mktemp -d -t aegis120-appearance-XXXXXXXX)
trap 'rm -rf -- "$aegis_test_temp"' EXIT
(cd -- "$aegis_test_temp" && "$aegis_test_image" --appimage-extract >/dev/null)
aegis_test_app="$aegis_test_temp/squashfs-root"
unset JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS CLASSPATH
cd -- "$aegis_test_kit"
"$aegis_test_app/runtime/bin/java" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "$aegis_test_kit/aegis-native-tests.jar:$aegis_test_kit/aegis-ui-tests.jar:$aegis_test_app/app/*" org.securemail.ui.AppearanceNativeLauncher "$aegis_test_app"
printf '%s\\n' 'Синтетические снимки: build/ui115-screenshots. Это не production profile.'
''');(kit/'Run-Appearance-CachyOS.sh').chmod(0o755)
 (kit/'README.md').write_text('''# Native acceptance kit АЕГИС 1.2.0

Это отдельный тестовый комплект, не часть production classpath. Сборка комплекта сама по себе не является native PASS.

Распакуйте portable Windows ZIP рядом с native-acceptance и запустите Run-Windows.cmd. Он использует встроенный Java21, проверяет реальные JAR hashes, криптографию, vault, DPAPI, JavaFX и синтетические GUI сцены. Для установленного клиента можно передать каталог первым аргументом. Затем Run-Appearance-Windows.cmd <каталог AEGIS> запускает все 22 оформления, logical scale, page/drawer, навигацию, safe recovery и одну Scene. Системное письмо в этой проверке подписано временным тестовым ключом; production ключ не используется. К сети тест не подключается.

На CachyOS выполните bash Run-CachyOS.sh <AppImage>, затем bash Run-Appearance-CachyOS.sh <AppImage>. Python/JDK/Gradle для запуска не нужны. Повторите в KDE Wayland и X11. Система DPI не меняется: запускайте отдельно при разных настройках дисплея. Не открывайте production key и не отключайте Defender/firewall.

Тесты не меняют реальный профиль, создают искусственные данные. NativeAcceptanceMain сохраняет JSON результатов без паролей/ключей. Дополнительная проверка оформления пишет synthetic screenshots в build/ui115-screenshots. В NativeAcceptanceMain добавлена реальная проверка пяти JavaFX шрифтов с кириллицей, карточки подключения и встроенного просмотра аватара. Friends/receipts/исчезновение ожидают отдельного согласования; не объявляются PASS. Полная приёмка через обычный интерфейс, cross-platform Relay, миграция, reboot и подписанный updater выполняются дополнительно по NATIVE-ACCEPTANCE-1.2.0.md. FAIL_OR_UNAVAILABLE не равен PASS. productionReady остаётся false до всех обязательных проверок.

Состав тестов пересобирается package-native120.py из exact source/client ZIP текущего кандидата и явно переданного JDK21. Все классы fixture/wrapper остаются только в этом комплекте. Приложение не загружает эти JAR.
''',encoding='utf-8')
shutil.copy2(pathlib.Path(__file__),kit/'package-native120.py')
(kit/'SHA256SUMS').write_text(''.join(sha(f)+'  '+f.name+'\n' for f in sorted(kit.iterdir()) if f.is_file() and f.name!='SHA256SUMS'))
archive=r/f'AEGIS-{version}-native-acceptance.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for f in sorted(kit.iterdir()):
  if f.is_file():z.write(f,'native-acceptance/'+f.name)
with zipfile.ZipFile(archive) as z:assert z.testzip() is None
print(json.dumps({'file':archive.name,'sha256':sha(archive),'nativeAcceptanceExecuted':False}))
