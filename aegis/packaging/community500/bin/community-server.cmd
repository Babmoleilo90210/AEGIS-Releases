@echo off
setlocal
if not "%JAVA_HOME%"=="" (set "AEGIS_OPERATOR_JAVA=%JAVA_HOME%\bin\java.exe") else (set "AEGIS_OPERATOR_JAVA=java")
"%AEGIS_OPERATOR_JAVA%" -Xms32m -Xmx384m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "%~dp0..\lib\*" org.securemail.community.CommunityMain %*
exit /b %errorlevel%
