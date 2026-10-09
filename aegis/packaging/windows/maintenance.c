#define UNICODE
#define _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <shellapi.h>
static DWORD owned_pid;
static BOOL CALLBACK close_window(HWND window,LPARAM unused){(void)unused;DWORD pid=0;GetWindowThreadProcessId(window,&pid);if(pid==owned_pid)PostMessageW(window,WM_CLOSE,0,0);return TRUE;}
static HANDLE owned(DWORD pid,const wchar_t *expected){HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);if(!process)return NULL;wchar_t image[32768];DWORD length=32768;if(!QueryFullProcessImageNameW(process,0,image,&length)||_wcsicmp(image,expected)!=0){CloseHandle(process);return NULL;}return process;}
static int rollback(LPWSTR *args){
 wchar_t java[32768],launcher[32768],old[32768],failed[32768],command[32768];
 if(swprintf(java,32768,L"%ls\\runtime\\bin\\javaw.exe",args[2])<0||swprintf(launcher,32768,L"%ls\\AEGIS.exe",args[2])<0||swprintf(old,32768,L"%ls.rollback-1.1.0",args[2])<0||swprintf(failed,32768,L"%ls.failed-1.1.0-%llu",args[2],(unsigned long long)GetTickCount64())<0)return 2;
 HANDLE client=owned(wcstoul(args[3],NULL,10),java),parent=owned(wcstoul(args[4],NULL,10),launcher);if(!client||!parent){if(client)CloseHandle(client);if(parent)CloseHandle(parent);return 2;}
 DWORD done=WaitForSingleObject(client,30000);CloseHandle(client);if(done!=WAIT_OBJECT_0){CloseHandle(parent);return 1;}done=WaitForSingleObject(parent,30000);CloseHandle(parent);if(done!=WAIT_OBJECT_0)return 1;
 if(!MoveFileExW(args[2],failed,MOVEFILE_WRITE_THROUGH))return 1;
 if(!MoveFileExW(old,args[2],MOVEFILE_WRITE_THROUGH)){MoveFileExW(failed,args[2],MOVEFILE_WRITE_THROUGH);return 1;}
 HKEY key;if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AEGIS",0,KEY_QUERY_VALUE|KEY_SET_VALUE,&key)==ERROR_SUCCESS){wchar_t version[128];DWORD bytes=sizeof(version),type=0;if(RegQueryValueExW(key,L"RollbackVersion",NULL,&type,(LPBYTE)version,&bytes)==ERROR_SUCCESS&&type==REG_SZ)RegSetValueExW(key,L"DisplayVersion",0,REG_SZ,(const BYTE*)version,bytes);RegCloseKey(key);}
 swprintf(command,32768,L"\"%ls\"",launcher);STARTUPINFOW startup={0};startup.cb=sizeof(startup);PROCESS_INFORMATION process={0};if(!CreateProcessW(launcher,command,NULL,NULL,FALSE,0,NULL,args[2],&startup,&process))return 1;CloseHandle(process.hThread);CloseHandle(process.hProcess);return 0;
}
static int prepare_rollback(LPWSTR *args){
 wchar_t exe[32768],command[32768];DWORD size=GetModuleFileNameW(NULL,exe,32768);if(!size||size>=32768)return 2;
 if(swprintf(command,32768,L"\"%ls\" --rollback \"%ls\" %ls %ls",exe,args[2],args[3],args[4])<0)return 2;
 STARTUPINFOW startup={0};startup.cb=sizeof(startup);PROCESS_INFORMATION process={0};
 if(!CreateProcessW(exe,command,NULL,NULL,FALSE,CREATE_BREAKAWAY_FROM_JOB|CREATE_NO_WINDOW,NULL,NULL,&startup,&process))return 1;
 CloseHandle(process.hThread);CloseHandle(process.hProcess);return 0;
}
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){
 (void)a;(void)b;(void)c;(void)d;int argc=0;LPWSTR *args=CommandLineToArgvW(GetCommandLineW(),&argc);if(!args)return 2;
 if(argc==5&&wcscmp(args[1],L"--prepare-rollback")==0){int result=prepare_rollback(args);LocalFree(args);return result;}
 if(argc==5&&wcscmp(args[1],L"--rollback")==0){int result=rollback(args);if(result)MessageBoxW(NULL,L"Автоматический откат программы не завершён. Предыдущая программа и резервная копия данных сохранены.",L"АЕГИС",MB_OK|MB_ICONERROR);LocalFree(args);return result;}
 if(argc!=2){LocalFree(args);return 2;}wchar_t expected[32768];if(swprintf(expected,32768,L"%ls\\runtime\\bin\\javaw.exe",args[1])<0){LocalFree(args);return 2;}LocalFree(args);
 HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if(snapshot==INVALID_HANDLE_VALUE)return 2;PROCESSENTRY32W entry={0};entry.dwSize=sizeof(entry);int code=0;
 if(Process32FirstW(snapshot,&entry))do{HANDLE process=owned(entry.th32ProcessID,expected);if(!process)continue;owned_pid=entry.th32ProcessID;EnumWindows(close_window,0);if(WaitForSingleObject(process,30000)!=WAIT_OBJECT_0)code=1;CloseHandle(process);}while(Process32NextW(snapshot,&entry));CloseHandle(snapshot);return code;
}
