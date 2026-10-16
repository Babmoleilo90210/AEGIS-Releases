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
if not "%~3"=="" goto aegis_bad_voice_argument
if "%~2"=="--test-microphone" goto aegis_microphone
if not "%~2"=="" goto aegis_bad_voice_argument
"%aegis_test_app%\runtime\bin\java.exe" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "%aegis_test_cp%" org.securemail.client.security.VoiceNativeAcceptanceMain "%aegis_test_app%"
exit /b %ERRORLEVEL%
:aegis_microphone
echo Явно запрошена локальная проверка уровня микрофона до 15 секунд. Записи, воспроизведения и передачи нет.
"%aegis_test_app%\runtime\bin\java.exe" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "%aegis_test_cp%" org.securemail.client.security.VoiceNativeAcceptanceMain "%aegis_test_app%" --test-microphone
exit /b %ERRORLEVEL%
:aegis_bad_voice_argument
echo Usage: Run-Voice-Windows.cmd APP_DIRECTORY [--test-microphone]
exit /b 2
