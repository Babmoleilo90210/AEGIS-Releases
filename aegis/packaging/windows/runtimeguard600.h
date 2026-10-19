#ifndef AEGIS_RUNTIME_GUARD_600
#define AEGIS_RUNTIME_GUARD_600
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <sddl.h>
#include <wchar.h>
#include <stdio.h>
/* Same path and byte range as RuntimeLease600. No process enumeration or signals. */
static HANDLE aegis_runtime_guard600(BOOL exclusive){
 wchar_t base[32768],directory[32768],path[32768];DWORD length=GetEnvironmentVariableW(L"LOCALAPPDATA",base,32768);
 if(!length||length>=32768||length<3||base[1]!=L':'||base[2]!=L'\\')return INVALID_HANDLE_VALUE;
 // Match the Java guard's refusal to traverse linked ancestors. Ordinary drive
 // roots are supported; redirected/UNC application-data setups fail closed.
 for(DWORD i=3;i<=length;i++)if(base[i]==L'\\'||base[i]==0){wchar_t saved=base[i];base[i]=0;DWORD attributes=GetFileAttributesW(base);base[i]=saved;if(attributes==INVALID_FILE_ATTRIBUTES||(attributes&FILE_ATTRIBUTE_REPARSE_POINT))return INVALID_HANDLE_VALUE;}
 if(swprintf(directory,32768,L"%ls\\AEGIS-Runtime600-Guard",base)<0||swprintf(path,32768,L"%ls\\installation.lock",directory)<0)return INVALID_HANDLE_VALUE;
 HANDLE token=NULL;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return INVALID_HANDLE_VALUE;
 DWORD bytes=0;GetTokenInformation(token,TokenUser,NULL,0,&bytes);PTOKEN_USER user=LocalAlloc(LPTR,bytes);LPWSTR sid=NULL;PSECURITY_DESCRIPTOR descriptor=NULL;
 if(!user||!GetTokenInformation(token,TokenUser,user,bytes,&bytes)||!ConvertSidToStringSidW(user->User.Sid,&sid)){if(user)LocalFree(user);CloseHandle(token);return INVALID_HANDLE_VALUE;}
 wchar_t sddl[512];BOOL valid=swprintf(sddl,512,L"D:P(A;OICI;FA;;;%ls)",sid)>=0&&ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,SDDL_REVISION_1,&descriptor,NULL);
 LocalFree(sid);LocalFree(user);CloseHandle(token);if(!valid)return INVALID_HANDLE_VALUE;
 SECURITY_ATTRIBUTES attributes={sizeof(attributes),descriptor,FALSE};BOOL made=CreateDirectoryW(directory,&attributes);DWORD error=GetLastError();
 if(!made&&error!=ERROR_ALREADY_EXISTS){LocalFree(descriptor);return INVALID_HANDLE_VALUE;}
 DWORD flags=GetFileAttributesW(directory);if(flags==INVALID_FILE_ATTRIBUTES||(flags&FILE_ATTRIBUTE_REPARSE_POINT)||!(flags&FILE_ATTRIBUTE_DIRECTORY)){LocalFree(descriptor);return INVALID_HANDLE_VALUE;}
 HANDLE file=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&attributes,OPEN_ALWAYS,FILE_FLAG_OPEN_REPARSE_POINT,NULL);LocalFree(descriptor);
 if(file==INVALID_HANDLE_VALUE)return file;
 BY_HANDLE_FILE_INFORMATION info;LARGE_INTEGER size;OVERLAPPED overlap={0};
 if(!GetFileInformationByHandle(file,&info)||(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))||info.nNumberOfLinks!=1||!GetFileSizeEx(file,&size)||size.QuadPart!=0||!LockFileEx(file,LOCKFILE_FAIL_IMMEDIATELY|(exclusive?LOCKFILE_EXCLUSIVE_LOCK:0),0,0xffffffffUL,0x7fffffffUL,&overlap)){CloseHandle(file);return INVALID_HANDLE_VALUE;}
 return file;
}
static void aegis_runtime_release600(HANDLE file){if(file!=INVALID_HANDLE_VALUE&&file!=NULL){OVERLAPPED overlap={0};UnlockFileEx(file,0,0xffffffffUL,0x7fffffffUL,&overlap);CloseHandle(file);}}
#endif
