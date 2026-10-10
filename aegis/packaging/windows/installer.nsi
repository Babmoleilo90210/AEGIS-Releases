Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!ifndef PAYLOAD
 !error "Pass /DPAYLOAD=absolute AEGIS folder"
!endif
!ifndef OUTFILE
 !define OUTFILE "AEGIS-Setup-1.1.1-x64.exe"
!endif
Name "АЕГИС"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\AEGIS"
InstallDirRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "InstallLocation"
RequestExecutionLevel user
SetCompressor /SOLID lzma
BrandingText "АЕГИС 1.1.1"
VIProductVersion "1.1.1.0"
VIAddVersionKey /LANG=1033 "ProductName" "AEGIS"
VIAddVersionKey /LANG=1033 "ProductVersion" "1.1.1"
VIAddVersionKey /LANG=1033 "FileVersion" "1.1.1"
VIAddVersionKey /LANG=1033 "FileDescription" "AEGIS Demo Installer"
VIAddVersionKey /LANG=1033 "LegalCopyright" "AEGIS contributors"
Icon "..\..\resources\icon.ico"
UninstallIcon "..\..\resources\icon.ico"
Var ExistingVersion
Var Result
!define MUI_ABORTWARNING
!define MUI_ICON "..\..\resources\icon.ico"
!define MUI_UNICON "..\..\resources\icon.ico"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\AEGIS.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить АЕГИС"
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "English"
Function .onInit
 ${IfNot} ${RunningX64}
  MessageBox MB_ICONSTOP "Требуется Windows 10/11 x64."
  Abort
 ${EndIf}
 ReadRegStr $ExistingVersion HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "DisplayVersion"
 ${If} $ExistingVersion != ""
  MessageBox MB_OKCANCEL|MB_ICONINFORMATION "AEGIS $ExistingVersion найден.$\r$\nОбновить до 1.1.1? Аккаунт и локальные данные сохраняются." IDOK continue
  Abort
  continue:
 ${EndIf}
FunctionEnd
Section "АЕГИС (обязательно)" Main
 SectionIn RO
 SetShellVarContext current
 InitPluginsDir
 SetOutPath "$PLUGINSDIR\AEGIS"
 File /r "${PAYLOAD}\*"
 nsExec::ExecToStack '"$PLUGINSDIR\AEGIS\AEGIS-Maintenance.exe" "$INSTDIR"'
 Pop $Result
 Pop $0
 ${If} $Result != 0
  MessageBox MB_ICONSTOP "Закройте старый АЕГИС и повторите обновление. Другие процессы Tor не затрагиваются."
  Abort
 ${EndIf}
 ; New bundled runtime works even on a Windows account with no global Java.
 nsExec::ExecToStack '"$PLUGINSDIR\AEGIS\runtime\bin\java.exe" -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "$PLUGINSDIR\AEGIS\app\*" org.securemail.client.MaintenanceMain backup'
 Pop $Result
 Pop $0
 ${If} $Result != 0
  MessageBox MB_ICONSTOP "Не удалось создать резервную копию. Установка остановлена; текущие данные сохранены."
  Abort
 ${EndIf}
 ; Preserve the previous program folder until the replacement is complete.
 IfFileExists "$INSTDIR\AEGIS.exe" 0 no_old
 IfFileExists "$INSTDIR.rollback-1.1.1\AEGIS.exe" 0 keep_old
  MessageBox MB_ICONSTOP "Существует предыдущая копия программы для отката. Завершите или отмените прежнее обновление перед повторной установкой."
  Abort
 keep_old:
 ClearErrors
 Rename "$INSTDIR" "$INSTDIR.rollback-1.1.1"
 ${If} ${Errors}
  MessageBox MB_ICONSTOP "Не удалось заменить программу. Проверьте, что АЕГИС закрыт."
  Abort
 ${EndIf}
 no_old:
 ClearErrors
 CreateDirectory "$INSTDIR"
 CopyFiles /SILENT "$PLUGINSDIR\AEGIS\*.*" "$INSTDIR"
 ${If} ${Errors}
  RMDir /r "$INSTDIR"
  Rename "$INSTDIR.rollback-1.1.1" "$INSTDIR"
  MessageBox MB_ICONSTOP "Обновление не удалось. Предыдущая программа восстановлена."
  Abort
 ${EndIf}
 WriteUninstaller "$INSTDIR\Uninstall.exe"
 CreateDirectory "$SMPROGRAMS\АЕГИС"
 CreateShortCut "$SMPROGRAMS\АЕГИС\АЕГИС.lnk" "$INSTDIR\AEGIS.exe" "" "$INSTDIR\AEGIS.exe" 0
 CreateShortCut "$SMPROGRAMS\АЕГИС\Удалить.lnk" "$INSTDIR\Uninstall.exe"
 IfFileExists "$DESKTOP\АЕГИС.lnk" 0 +2
  CreateShortCut "$DESKTOP\АЕГИС.lnk" "$INSTDIR\AEGIS.exe" "" "$INSTDIR\AEGIS.exe" 0
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "DisplayName" "АЕГИС"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "RollbackVersion" "$ExistingVersion"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "DisplayVersion" "1.1.1"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "InstallLocation" "$INSTDIR"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "DisplayIcon" "$INSTDIR\AEGIS.exe"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "UninstallString" '"$INSTDIR\Uninstall.exe"'
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "NoModify" 1
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "NoRepair" 1
SectionEnd
Section /o "Ярлык на рабочем столе"
 SetShellVarContext current
 CreateShortCut "$DESKTOP\АЕГИС.lnk" "$INSTDIR\AEGIS.exe" "" "$INSTDIR\AEGIS.exe" 0
SectionEnd
Section "Uninstall"
 SetShellVarContext current
 Delete "$DESKTOP\АЕГИС.lnk"
 Delete "$SMPROGRAMS\АЕГИС\АЕГИС.lnk"
 Delete "$SMPROGRAMS\АЕГИС\Удалить.lnk"
 RMDir "$SMPROGRAMS\АЕГИС"
 DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS"
 ; LOCALAPPDATA\AEGIS and the encrypted pre-update backups are never removed.
 RMDir /r "$INSTDIR\runtime"
 RMDir /r "$INSTDIR\tor"
 RMDir /r "$INSTDIR\app"
 RMDir /r "$INSTDIR\native"
 RMDir /r "$INSTDIR\resources"
 RMDir /r "$INSTDIR\licenses"
 Delete "$INSTDIR\AEGIS.exe"
 Delete "$INSTDIR\AEGIS-Maintenance.exe"
 Delete "$INSTDIR\AEGIS-Updater.exe"
 Delete "$INSTDIR\CreateShortcuts.ps1"
 Delete "$INSTDIR\*.md"
 Delete "$INSTDIR\BUILD-INPUTS.json"
 Delete "$INSTDIR\Uninstall.exe"
 RMDir "$INSTDIR"
SectionEnd
