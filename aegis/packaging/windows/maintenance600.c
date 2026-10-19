#include "runtimeguard600.h"
#include <wchar.h>
#include <shellapi.h>
static HANDLE owned(DWORD pid,const wchar_t *expected){HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);if(!process)return NULL;wchar_t image[32768];DWORD length=32768;if(!QueryFullProcessImageNameW(process,0,image,&length)||_wcsicmp(image,expected)!=0){CloseHandle(process);return NULL;}return process;}
/* The copied executable and cwd both stay outside the tree being renamed. */
static BOOL outside_directory(const wchar_t *program,wchar_t directory[32768]){
 DWORD size=GetModuleFileNameW(NULL,directory,32768);if(!size||size>=32768)return FALSE;
 wchar_t *separator=wcsrchr(directory,L'\\');if(!separator)return FALSE;separator[1]=0;
 size_t length=wcslen(program);while(length>3&&(program[length-1]==L'\\'||program[length-1]==L'/'))length--;
 if(_wcsnicmp(directory,program,length)==0&&(directory[length]==0||directory[length]==L'\\'||directory[length]==L'/'))return FALSE;
 return SetCurrentDirectoryW(directory);
}
static int rollback(LPWSTR *args){
 wchar_t outside[32768];if(!outside_directory(args[2],outside))return 2;
 wchar_t java[32768],launcher[32768],old[32768],failed[32768],command[32768];
 if(swprintf(java,32768,L"%ls\\runtime\\bin\\javaw.exe",args[2])<0||swprintf(launcher,32768,L"%ls\\AEGIS.exe",args[2])<0||swprintf(old,32768,L"%ls.rollback-6.0.0",args[2])<0||swprintf(failed,32768,L"%ls.failed-6.0.0-%llu",args[2],(unsigned long long)GetTickCount64())<0)return 2;
 HANDLE client=owned(wcstoul(args[3],NULL,10),java),parent=owned(wcstoul(args[4],NULL,10),launcher);if(!client||!parent){if(client)CloseHandle(client);if(parent)CloseHandle(parent);return 2;}
 DWORD done=WaitForSingleObject(client,30000);CloseHandle(client);if(done!=WAIT_OBJECT_0){CloseHandle(parent);return 1;}done=WaitForSingleObject(parent,30000);CloseHandle(parent);if(done!=WAIT_OBJECT_0)return 1;
 HANDLE guard=aegis_runtime_guard600(TRUE);if(guard==INVALID_HANDLE_VALUE)return 1;
 if(!MoveFileExW(args[2],failed,MOVEFILE_WRITE_THROUGH)){aegis_runtime_release600(guard);return 1;}
 if(!MoveFileExW(old,args[2],MOVEFILE_WRITE_THROUGH)){MoveFileExW(failed,args[2],MOVEFILE_WRITE_THROUGH);aegis_runtime_release600(guard);return 1;}
 HKEY key;if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AEGIS",0,KEY_QUERY_VALUE|KEY_SET_VALUE,&key)==ERROR_SUCCESS){wchar_t version[128];DWORD bytes=sizeof(version),type=0;if(RegQueryValueExW(key,L"RollbackVersion",NULL,&type,(LPBYTE)version,&bytes)==ERROR_SUCCESS&&type==REG_SZ)RegSetValueExW(key,L"DisplayVersion",0,REG_SZ,(const BYTE*)version,bytes);RegCloseKey(key);}
 aegis_runtime_release600(guard);
 swprintf(command,32768,L"\"%ls\"",launcher);STARTUPINFOW startup={0};startup.cb=sizeof(startup);PROCESS_INFORMATION process={0};if(!CreateProcessW(launcher,command,NULL,NULL,FALSE,0,NULL,args[2],&startup,&process))return 1;CloseHandle(process.hThread);CloseHandle(process.hProcess);return 0;
}
static int prepare_rollback(LPWSTR *args){
 wchar_t exe[32768],command[32768],outside[32768];if(!outside_directory(args[2],outside))return 2;DWORD size=GetModuleFileNameW(NULL,exe,32768);if(!size||size>=32768)return 2;
 if(swprintf(command,32768,L"\"%ls\" --rollback \"%ls\" %ls %ls",exe,args[2],args[3],args[4])<0)return 2;
 STARTUPINFOW startup={0};startup.cb=sizeof(startup);PROCESS_INFORMATION process={0};
 if(!CreateProcessW(exe,command,NULL,NULL,FALSE,CREATE_BREAKAWAY_FROM_JOB|CREATE_NO_WINDOW,NULL,outside,&startup,&process))return 1;
 CloseHandle(process.hThread);CloseHandle(process.hProcess);return 0;
}
int WINAPI wWinMain(HINSTANCE a,HINSTANCE b,LPWSTR c,int d){
 (void)a;(void)b;(void)c;(void)d;int argc=0;LPWSTR *args=CommandLineToArgvW(GetCommandLineW(),&argc);if(!args)return 2;
 if(argc==5&&wcscmp(args[1],L"--prepare-rollback")==0){int result=prepare_rollback(args);LocalFree(args);return result;}
 if(argc==5&&wcscmp(args[1],L"--rollback")==0){int result=rollback(args);if(result)MessageBoxW(NULL,L"Автоматический откат программы не завершён. Предыдущая программа и резервная копия данных сохранены.",L"АЕГИС",MB_OK|MB_ICONERROR);LocalFree(args);return result;}
 // Legacy prepare command is a read-only availability check. NSIS retains its own
 // exclusive native guard across actual backup/copy; this helper never closes apps.
 if(argc!=2){LocalFree(args);return 2;}LocalFree(args);
 HANDLE guard=aegis_runtime_guard600(TRUE);if(guard==INVALID_HANDLE_VALUE)return 1;aegis_runtime_release600(guard);return 0;
}
