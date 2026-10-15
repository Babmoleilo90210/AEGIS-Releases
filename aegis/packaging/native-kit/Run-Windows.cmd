@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
set "aegis_test_kit=%~dp0"
set "aegis_test_app=%~1"
if not defined aegis_test_app set "aegis_test_app=%~dp0..\AEGIS"
if not exist "%aegis_test_app%\runtime\bin\java.exe" set "aegis_test_app=%LOCALAPPDATA%\Programs\AEGIS"
if not exist "%aegis_test_app%\runtime\bin\java.exe" (
  echo Укажите каталог распакованного или установленного АЕГИС.
  set /p "aegis_test_app=Каталог: "
)
set "aegis_test_app=%aegis_test_app:"=%"
if not exist "%aegis_test_app%\runtime\bin\java.exe" (
  echo Не найден встроенный Java runtime АЕГИС. Установка Java не требуется.
  pause
  exit /b 2
)
set "JAVA_TOOL_OPTIONS="
set "_JAVA_OPTIONS="
set "JDK_JAVA_OPTIONS="
set "CLASSPATH="
cd /d "%aegis_test_kit%"
echo Проверка АЕГИС на Windows. Будут открываться тестовые окна.
"%aegis_test_app%\runtime\bin\java.exe" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "%aegis_test_kit%aegis-native-tests.jar;%aegis_test_app%\app\*" org.securemail.client.security.NativeAcceptanceMain "%aegis_test_app%" "%aegis_test_kit%" --gui
set "aegis_test_status=%ERRORLEVEL%"
echo.
echo Отчёт AEGIS-native-Windows-*.json сохранён рядом с этим файлом.
echo Отчёт не содержит паролей и ключей. Автоматической отправки нет.
pause
exit /b %aegis_test_status%
