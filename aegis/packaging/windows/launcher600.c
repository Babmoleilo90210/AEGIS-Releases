#include "runtimeguard600.h"
#include <shellapi.h>
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE previous,LPWSTR tail,int show){
 (void)instance;(void)previous;(void)tail;(void)show;
 int argc=0;LPWSTR *args=CommandLineToArgvW(GetCommandLineW(),&argc);if(!args||argc!=1){if(args)LocalFree(args);return 2;}LocalFree(args);
 wchar_t home[32768],java[32768],command[32768];DWORD length=GetModuleFileNameW(NULL,home,32768);
 if(!length||length>=32768)return 1;
 wchar_t *slash=wcsrchr(home,L'\\');if(!slash)return 1;*slash=0;
 HANDLE guard=aegis_runtime_guard600(FALSE);if(guard==INVALID_HANDLE_VALUE){MessageBoxW(NULL,L"Запуск заблокирован обновлением или недоступной личной блокировкой. Завершите установку и повторите запуск.",L"АЕГИС",MB_OK|MB_ICONERROR);return 1;}
 if(swprintf(java,32768,L"%ls\\runtime\\bin\\javaw.exe",home)<0||swprintf(command,32768,L"\"%ls\" -Xmx1024m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -XX:ErrorFile=NUL -Dfile.encoding=UTF-8 \"-Daegis.home=%ls\" -cp \"%ls\\app\\*\" org.securemail.ui.Launcher",java,home,home)<0){aegis_runtime_release600(guard);return 1;}
 SetEnvironmentVariableW(L"JAVA_TOOL_OPTIONS",NULL);SetEnvironmentVariableW(L"_JAVA_OPTIONS",NULL);SetEnvironmentVariableW(L"JDK_JAVA_OPTIONS",NULL);
 STARTUPINFOW startup={0};startup.cb=sizeof(startup);PROCESS_INFORMATION process={0};
 if(!CreateProcessW(java,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,home,&startup,&process)){MessageBoxW(NULL,L"Не удалось запустить АЕГИС. Распакуйте полный ZIP с runtime и app.",L"АЕГИС",MB_OK|MB_ICONERROR);aegis_runtime_release600(guard);return 1;}
 // Deliberately no kill-on-job-close: detached Взор and personal library survive Core exit.
 CloseHandle(process.hThread);WaitForSingleObject(process.hProcess,INFINITE);DWORD code=1;GetExitCodeProcess(process.hProcess,&code);CloseHandle(process.hProcess);aegis_runtime_release600(guard);return (int)code;
}
