@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
set "aegis_test_kit=%~dp0"
set "aegis_test_app=%~1"
set "aegis_test_jdk=%~2"
if not exist "%aegis_test_app%\runtime\bin\java.exe" exit /b 2
if not exist "%aegis_test_jdk%\bin\java.exe" (
 echo Usage: Run-Community-Windows.cmd APP_DIRECTORY JDK21_DIRECTORY
 exit /b 2
)
set "JAVA_TOOL_OPTIONS="
set "_JAVA_OPTIONS="
set "JDK_JAVA_OPTIONS="
set "CLASSPATH="
cd /d "%aegis_test_kit%"
echo Локальные JUnit: SQLite, ACL, подписанный loopback HTTP. Это не Tor/native E2E.
"%aegis_test_jdk%\bin\java.exe" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -Daegis.native.root="%aegis_test_app%" -cp "%aegis_test_app%\app\*;%aegis_test_kit%staging\*;%aegis_test_kit%aegis-community-tests.jar" org.junit.platform.console.ConsoleLauncher execute --select-package org.securemail.community --select-package org.securemail.worker --select-package org.securemail.client.community --select-class org.securemail.integration.CommunityIntegration500Test --reports-dir "%aegis_test_kit%results-local-community" --disable-banner
exit /b %ERRORLEVEL%
