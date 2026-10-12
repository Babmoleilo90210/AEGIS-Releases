#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <wchar.h>
#include <stdio.h>
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){
 (void)a;(void)b;(void)c;(void)d;int count=0;LPWSTR *args=CommandLineToArgvW(GetCommandLineW(),&count);
 if(!args||count!=3||wcscmp(args[1],L"--job")||wcschr(args[2],L'\"')||wcschr(args[2],L'\n')||wcschr(args[2],L'\r'))return 1;
 wchar_t home[32768],java[32768],command[32768];DWORD n=GetModuleFileNameW(NULL,home,32768);if(!n||n>=32768)return 1;wchar_t *slash=wcsrchr(home,L'\\');if(!slash)return 1;*slash=0;
 if(swprintf(java,32768,L"%ls\\runtime\\bin\\javaw.exe",home)<0)return 1;
 if(swprintf(command,32768,L"\"%ls\" -Xmx256m -Djava.awt.headless=true -Daegis.process.role=updater -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -XX:ErrorFile=NUL -cp \"%ls\\app\\*\" org.securemail.client.update.UpdaterMain --job \"%ls\"",java,home,args[2])<0)return 1;
 SetEnvironmentVariableW(L"JAVA_TOOL_OPTIONS",NULL);SetEnvironmentVariableW(L"_JAVA_OPTIONS",NULL);SetEnvironmentVariableW(L"JDK_JAVA_OPTIONS",NULL);
 STARTUPINFOW start={0};start.cb=sizeof(start);PROCESS_INFORMATION p={0};if(!CreateProcessW(java,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,home,&start,&p))return 1;
 CloseHandle(p.hThread);WaitForSingleObject(p.hProcess,INFINITE);DWORD code=1;GetExitCodeProcess(p.hProcess,&code);CloseHandle(p.hProcess);LocalFree(args);return (int)code;
}
