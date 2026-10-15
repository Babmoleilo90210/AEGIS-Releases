#define UNICODE
#define _UNICODE
#include <windows.h>
#include <wchar.h>
#include <stdio.h>
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE previous,LPWSTR tail,int show) {
 (void)instance;(void)previous;(void)tail;(void)show;
 wchar_t home[32768],java[32768],command[32768];DWORD length=GetModuleFileNameW(NULL,home,32768);
 if(!length||length>=32768)return 1;wchar_t *slash=wcsrchr(home,L'\\');if(!slash)return 1;*slash=0;
 if(swprintf(java,32768,L"%ls\\runtime\\bin\\javaw.exe",home)<0)return 1;
 if(swprintf(command,32768,L"\"%ls\" -Xmx1024m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -XX:ErrorFile=NUL -Dfile.encoding=UTF-8 \"-Daegis.home=%ls\" -cp \"%ls\\app\\*\" org.securemail.ui.Launcher",java,home,home)<0)return 1;
 SetEnvironmentVariableW(L"JAVA_TOOL_OPTIONS",NULL);SetEnvironmentVariableW(L"_JAVA_OPTIONS",NULL);SetEnvironmentVariableW(L"JDK_JAVA_OPTIONS",NULL);
 HANDLE job=CreateJobObjectW(NULL,NULL);if(!job)return 1;
 JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_BREAKAWAY_OK;
 if(!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))){CloseHandle(job);return 1;}
 STARTUPINFOW startup={0};startup.cb=sizeof(startup);PROCESS_INFORMATION process={0};
 if(!CreateProcessW(java,command,NULL,NULL,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,NULL,home,&startup,&process)){
  MessageBoxW(NULL,L"Не удалось запустить АЕГИС. Распакуйте полный ZIP, включая runtime и app.",L"АЕГИС",MB_OK|MB_ICONERROR);CloseHandle(job);return 1;
 }
 if(!AssignProcessToJobObject(job,process.hProcess)){TerminateProcess(process.hProcess,1);CloseHandle(process.hThread);CloseHandle(process.hProcess);CloseHandle(job);return 1;}
 ResumeThread(process.hThread);CloseHandle(process.hThread);WaitForSingleObject(process.hProcess,INFINITE);DWORD code=1;GetExitCodeProcess(process.hProcess,&code);CloseHandle(process.hProcess);CloseHandle(job);return (int)code;
}
