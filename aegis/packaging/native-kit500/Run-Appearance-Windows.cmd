@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
set "aegis_test_kit=%~dp0"
set "aegis_test_app=%~1"
if not defined aegis_test_app set "aegis_test_app=%~dp0..\AEGIS"
if not exist "%aegis_test_app%\runtime\bin\java.exe" (
 echo Укажите каталог распакованного или установленного АЕГИС 5.0.0 первым аргументом.
 exit /b 2
)
set "JAVA_TOOL_OPTIONS="
set "_JAVA_OPTIONS="
set "JDK_JAVA_OPTIONS="
set "CLASSPATH="
cd /d "%aegis_test_kit%"
set "aegis_test_cp=%aegis_test_kit%aegis-native-tests.jar;%aegis_test_kit%aegis-ui-tests.jar;%aegis_test_app%\app\*"
"%aegis_test_app%\runtime\bin\java.exe" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "%aegis_test_cp%" org.securemail.ui.AppearanceNativeLauncher500 "%aegis_test_app%" interface
if errorlevel 1 exit /b %ERRORLEVEL%
"%aegis_test_app%\runtime\bin\java.exe" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "%aegis_test_cp%" org.securemail.ui.AppearanceNativeLauncher500 "%aegis_test_app%" archive
if errorlevel 1 exit /b %ERRORLEVEL%
"%aegis_test_app%\runtime\bin\java.exe" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "%aegis_test_cp%" org.securemail.ui.AppearanceNativeLauncher500 "%aegis_test_app%" vzor-glas
if errorlevel 1 exit /b %ERRORLEVEL%
echo Синтетические снимки: build\ui500-screenshots и build\archive-menu500.
echo Это UI fixtures, а не реальная проверка браузера или звука.
exit /b 0
