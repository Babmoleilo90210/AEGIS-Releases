Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!ifndef PAYLOAD
 !error "Pass /DPAYLOAD=absolute AEGIS folder"
!endif
!ifndef OUTFILE
 !define OUTFILE "AEGIS-Setup-6.0.0-x64.exe"
!endif
Name "АЕГИС"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\AEGIS"
InstallDirRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "InstallLocation"
RequestExecutionLevel user
SetCompressor /SOLID lzma
BrandingText "АЕГИС 6.0.0"
VIProductVersion "6.0.0.0"
VIAddVersionKey /LANG=1049 "ProductName" "АЕГИС"
VIAddVersionKey /LANG=1049 "ProductVersion" "6.0.0"
VIAddVersionKey /LANG=1049 "FileVersion" "6.0.0"
VIAddVersionKey /LANG=1049 "FileDescription" "Установка АЕГИС"
VIAddVersionKey /LANG=1049 "LegalCopyright" "Разработчики АЕГИС"
Icon "..\..\resources\icon.ico"
UninstallIcon "..\..\resources\icon.ico"
Var ExistingVersion
Var Result
Var RuntimeGuard
Var GuardLibrary
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

; Explicit LoadLibrary reference keeps the x86 guard DLL and its exclusive handle
; alive through the whole install section. Crash/cancel releases kernel locks.
Function AcquireRuntimeGuard
 System::Call 'kernel32::LoadLibraryW(w "$PLUGINSDIR\AEGIS\AEGIS-RuntimeGuard.dll") p.r0'
 StrCpy $GuardLibrary $0
 ${If} $GuardLibrary == 0
  MessageBox MB_ICONSTOP "Не удалось проверить блокировку компонентов. Установка остановлена."
  Abort
 ${EndIf}
 System::Call 'kernel32::GetProcAddress(p $GuardLibrary, m "acquire") p.r0'
 ${If} $0 == 0
  Call ReleaseRuntimeGuard
  Abort
 ${EndIf}
 System::Call '::$0(i 1) p.r1 ? c'
 StrCpy $RuntimeGuard $1
 ${If} $RuntimeGuard == -1
 ${OrIf} $RuntimeGuard == 0
  MessageBox MB_ICONSTOP "Обновление заблокировано. Закройте АЕГИС, Письма, Глас, Взор и личную библиотеку и повторите установку. Приложения не завершаются автоматически."
  Call ReleaseRuntimeGuard
  Abort
 ${EndIf}
FunctionEnd
Function ReleaseRuntimeGuard
 ${If} $GuardLibrary != 0
  ${If} $RuntimeGuard != 0
  ${AndIf} $RuntimeGuard != -1
   System::Call 'kernel32::GetProcAddress(p $GuardLibrary, m "release") p.r0'
   ${If} $0 != 0
    System::Call '::$0(p $RuntimeGuard) ? c'
   ${Else}
    System::Call 'kernel32::CloseHandle(p $RuntimeGuard)'
   ${EndIf}
  ${EndIf}
  StrCpy $RuntimeGuard 0
  System::Call 'kernel32::FreeLibrary(p $GuardLibrary)'
  StrCpy $GuardLibrary 0
 ${EndIf}
FunctionEnd
Function .onGUIEnd
 Call ReleaseRuntimeGuard
FunctionEnd

Function .onInit
 ${IfNot} ${RunningX64}
  MessageBox MB_ICONSTOP "Требуется Windows 11 x64."
  Abort
 ${EndIf}
 SetRegView 64
 ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentBuildNumber"
 IntCmp $0 22000 windows_11 windows_unsupported windows_11
 windows_unsupported:
  MessageBox MB_ICONSTOP "Требуется Windows 11 x64. Пользовательские данные не изменялись."
  Abort
 windows_11:
 ReadRegStr $ExistingVersion HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "DisplayVersion"
 ${If} $ExistingVersion != ""
  MessageBox MB_OKCANCEL|MB_ICONINFORMATION "АЕГИС $ExistingVersion найден.$\r$\nОбновить до 6.0.0? Аккаунт и локальные данные сохраняются." IDOK continue
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
 Call AcquireRuntimeGuard
 ; New bundled runtime works even on a Windows account with no global Java.
 nsExec::ExecToStack '"$PLUGINSDIR\AEGIS\runtime\bin\java.exe" -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "$PLUGINSDIR\AEGIS\app\*" org.securemail.client.maintenance600.MaintenanceMain600 backup'
 Pop $Result
 Pop $0
 ${If} $Result != 0
  MessageBox MB_ICONSTOP "Не удалось создать резервную копию. Установка остановлена; текущие данные сохранены."
  Abort
 ${EndIf}
 ; Preserve the previous program folder until the replacement is complete.
 IfFileExists "$INSTDIR\AEGIS.exe" 0 no_old
 IfFileExists "$INSTDIR.rollback-6.0.0\AEGIS.exe" 0 keep_old
  MessageBox MB_ICONSTOP "Существует предыдущая копия программы для отката. Завершите или отмените прежнее обновление перед повторной установкой."
  Abort
 keep_old:
 ClearErrors
 Rename "$INSTDIR" "$INSTDIR.rollback-6.0.0"
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
  Rename "$INSTDIR.rollback-6.0.0" "$INSTDIR"
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
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "DisplayVersion" "6.0.0"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "InstallLocation" "$INSTDIR"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "DisplayIcon" "$INSTDIR\AEGIS.exe"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "UninstallString" '"$INSTDIR\Uninstall.exe"'
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "NoModify" 1
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS" "NoRepair" 1
 Call ReleaseRuntimeGuard
SectionEnd
Section /o "Ярлык на рабочем столе"
 SetShellVarContext current
 CreateShortCut "$DESKTOP\АЕГИС.lnk" "$INSTDIR\AEGIS.exe" "" "$INSTDIR\AEGIS.exe" 0
SectionEnd
Section "Uninstall"
 SetShellVarContext current
 InitPluginsDir
 ClearErrors
 CopyFiles /SILENT "$INSTDIR\AEGIS-RuntimeGuard.dll" "$PLUGINSDIR\AEGIS-RuntimeGuard.dll"
 ${If} ${Errors}
  MessageBox MB_ICONSTOP "Не удалось подготовить безопасное удаление. Файлы сохранены."
  Abort
 ${EndIf}
 System::Call 'kernel32::LoadLibraryW(w "$PLUGINSDIR\AEGIS-RuntimeGuard.dll") p.r0'
 StrCpy $GuardLibrary $0
 ${If} $GuardLibrary == 0
  MessageBox MB_ICONSTOP "Не удалось проверить блокировку. Удаление остановлено."
  Abort
 ${EndIf}
 System::Call 'kernel32::GetProcAddress(p $GuardLibrary, m "acquire") p.r0'
 ${If} $0 == 0
  Abort
 ${EndIf}
 System::Call '::$0(i 1) p.r1 ? c'
 StrCpy $RuntimeGuard $1
 ${If} $RuntimeGuard == 0
 ${OrIf} $RuntimeGuard == -1
  MessageBox MB_ICONSTOP "Закройте все компоненты АЕГИС, Взор и личную библиотеку перед удалением."
  Abort
 ${EndIf}
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
 Delete "$INSTDIR\AEGIS-RuntimeGuard.dll"
 Delete "$INSTDIR\AEGIS-Updater.exe"
 Delete "$INSTDIR\CreateShortcuts.ps1"
 Delete "$INSTDIR\*.md"
 Delete "$INSTDIR\BUILD-INPUTS.json"
 Delete "$INSTDIR\Uninstall.exe"
 RMDir "$INSTDIR"
SectionEnd
