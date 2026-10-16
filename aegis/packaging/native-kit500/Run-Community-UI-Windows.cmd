@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
set "aegis_test_kit=%~dp0"
set "aegis_test_app=%~1"
set "aegis_test_jdk=%~2"
if not exist "%aegis_test_app%\runtime\bin\java.exe" exit /b 2
if not exist "%aegis_test_jdk%\bin\java.exe" exit /b 2
set "JAVA_TOOL_OPTIONS="
set "_JAVA_OPTIONS="
set "JDK_JAVA_OPTIONS="
set "CLASSPATH="
cd /d "%aegis_test_kit%"
"%aegis_test_jdk%\bin\java.exe" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -Daegis.home="%aegis_test_app%" -cp "%aegis_test_app%\app\*;%aegis_test_kit%staging\*;%aegis_test_kit%aegis-ui-tests.jar" org.securemail.ui.AppearanceNativeLauncher500 "%aegis_test_app%" community-flow
exit /b %ERRORLEVEL%
