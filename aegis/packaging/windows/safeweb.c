/* AEGIS Safe Web launcher. Build: x86_64-w64-mingw32-gcc -std=c11 -Os
 * -Wall -Wextra -Werror -municode -static -o AEGIS-SafeWeb.exe safeweb.c
 * -luserenv -ladvapi32 -lshell32 -lole32 -lbcrypt -luuid -lws2_32
 *
 * Security boundary: Windows AppContainer + a private Job Object, not a Tor-only
 * kernel firewall. internetClient is needed by the bundle's own Tor. Tor-only
 * browsing remains the unmodified official Tor Browser's responsibility.
 * No shell, external command, Firefox host profile, inherited application
 * environment, inherited application handle, or messenger Tor is used.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define _WIN32_WINNT 0x0602
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <userenv.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <wchar.h>
#include <wctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PATH_CAP 32768
#define URL_CAP 4096
#define TREE_LIMIT 40000
#define TREE_DEPTH 40
#define SHUTDOWN_MS 8000
enum { OK=0, BAD_ARGUMENT=2, UNSAFE_PATH=3, SANDBOX_FAILED=4,
       ALREADY_RUNNING=5, BROWSER_FAILED=6, SELFTEST_FAILED=7,
       CLEANUP_FAILED=8 };

typedef struct {
  PSID user_sid;
  PSID app_sid;
  wchar_t *user_text;
  wchar_t *app_text;
  wchar_t container_name[64];
  wchar_t local[PATH_CAP];
  wchar_t root[PATH_CAP];
  wchar_t control[PATH_CAP];
  wchar_t package_dir[PATH_CAP];
  wchar_t home[PATH_CAP];
  wchar_t temp[PATH_CAP];
  PSECURITY_DESCRIPTOR private_sd;
  PSECURITY_DESCRIPTOR app_sd;
  HANDLE lock;
} Context;

static void status(const char *state, const char *detail, DWORD number) {
  /* Only compile-time ASCII identifiers and numeric errors, never URLs, paths,
   * environment variables, browser stdout, or user data. Always bounded. */
  printf("{\"state\":\"%s\",\"detail\":\"%s\",\"code\":%lu}\n",
         state,detail,(unsigned long)number); fflush(stdout);
}
static int fail(int code,const char *detail) {
  status("ERROR",detail,GetLastError()); return code;
}
static BOOL path_join(wchar_t *out,const wchar_t *base,const wchar_t *tail) {
  return swprintf(out,PATH_CAP,L"%ls\\%ls",base,tail)>0 && wcslen(out)<PATH_CAP-1;
}
static BOOL simple_component(const wchar_t *s) {
  size_t n=wcslen(s); if(!n||n>100||s[0]==L'.')return FALSE;
  for(size_t i=0;i<n;i++)if(!((s[i]>=L'a'&&s[i]<=L'z')||
    (s[i]>=L'A'&&s[i]<=L'Z')||(s[i]>=L'0'&&s[i]<=L'9')||
    s[i]==L'-'||s[i]==L'_'))return FALSE;
  return TRUE;
}
static BOOL no_reparse_ancestors(const wchar_t *path) {
  wchar_t *copy=_wcsdup(path); if(!copy)return FALSE;
  BOOL ok=TRUE;size_t n=wcslen(copy);
  for(size_t i=3;i<=n;i++)if(copy[i]==L'\\'||copy[i]==0) {
    wchar_t save=copy[i];copy[i]=0;
    DWORD attrs=GetFileAttributesW(copy);
    if(attrs==INVALID_FILE_ATTRIBUTES||(attrs&FILE_ATTRIBUTE_REPARSE_POINT))ok=FALSE;
    copy[i]=save;if(!ok)break;
  }
  free(copy);return ok;
}
static BOOL regular_object(const wchar_t *path,BOOL directory) {
  DWORD attrs=GetFileAttributesW(path);
  return attrs!=INVALID_FILE_ATTRIBUTES && !(attrs&FILE_ATTRIBUTE_REPARSE_POINT) &&
         (!!(attrs&FILE_ATTRIBUTE_DIRECTORY)==!!directory);
}
static BOOL user_context(Context *c) {
  HANDLE token=NULL;DWORD size=0;
  if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return FALSE;
  TOKEN_ELEVATION elevation={0};DWORD bytes=0;
  if(!GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&bytes)||
     elevation.TokenIsElevated){CloseHandle(token);SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
  GetTokenInformation(token,TokenUser,NULL,0,&size);
  TOKEN_USER *user=malloc(size);
  if(!user){CloseHandle(token);return FALSE;}
  BOOL ok=GetTokenInformation(token,TokenUser,user,size,&size);
  if(ok){DWORD length=GetLengthSid(user->User.Sid);c->user_sid=malloc(length);
    ok=c->user_sid&&CopySid(length,c->user_sid,user->User.Sid)&&
       ConvertSidToStringSidW(c->user_sid,&c->user_text);}
  free(user);CloseHandle(token);
  PWSTR local=NULL;
  if(ok)ok=SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_LocalAppData,KF_FLAG_DEFAULT,NULL,&local));
  if(ok){DWORD n=GetFullPathNameW(local,PATH_CAP,c->local,NULL);ok=n>0&&n<PATH_CAP;}
  if(local)CoTaskMemFree(local);
  if(!ok)return FALSE;
  /* Reject UNC, redirected devices, junctions and filesystems without persistent
   * ACLs. The ordinary local Windows profile is the supported deployment. */
  if(wcslen(c->local)<3||c->local[1]!=L':'||c->local[2]!=L'\\'||
     !no_reparse_ancestors(c->local)){SetLastError(ERROR_NOT_SUPPORTED);return FALSE;}
  wchar_t volume[4]={c->local[0],L':',L'\\',0},fs[32];DWORD flags=0;
  if(!GetVolumeInformationW(volume,NULL,0,NULL,NULL,&flags,fs,32)||
     !(flags&FS_PERSISTENT_ACLS)){SetLastError(ERROR_NOT_SUPPORTED);return FALSE;}
  return path_join(c->root,c->local,L"AEGIS-SafeWeb")&&
         path_join(c->control,c->root,L"control");
}
static BOOL make_sd(Context *c,BOOL grant_app,PSECURITY_DESCRIPTOR *out) {
  wchar_t text[1024];
  int n=grant_app ? swprintf(text,1024,
    L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%ls)(A;OICI;FA;;;%ls)S:(ML;OICI;NW;;;LW)",
    c->user_text,c->app_text) : swprintf(text,1024,
    L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%ls)",c->user_text);
  return n>0&&ConvertStringSecurityDescriptorToSecurityDescriptorW(text,SDDL_REVISION_1,out,NULL);
}
static BOOL apply_sd(const wchar_t *path,PSECURITY_DESCRIPTOR sd) {
  HANDLE object=CreateFileW(path,READ_CONTROL|WRITE_DAC|WRITE_OWNER|FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
  if(object==INVALID_HANDLE_VALUE)return FALSE;
  BY_HANDLE_FILE_INFORMATION info;BOOL ok=GetFileInformationByHandle(object,&info);
  if(ok && ((info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||
       (!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&info.nNumberOfLinks!=1))) {
    ok=FALSE;SetLastError(ERROR_ACCESS_DENIED);
  }
  PACL dacl=NULL,sacl=NULL;BOOL present=FALSE,defaulted=FALSE;
  if(ok)ok=GetSecurityDescriptorDacl(sd,&present,&dacl,&defaulted)&&present;
  if(ok){DWORD result=SetSecurityInfo(object,SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,NULL,NULL,dacl,NULL);
    ok=result==ERROR_SUCCESS;if(!ok)SetLastError(result);}
  if(ok&&GetSecurityDescriptorSacl(sd,&present,&sacl,&defaulted)&&present) {
    DWORD result=SetSecurityInfo(object,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,
      NULL,NULL,NULL,sacl);ok=result==ERROR_SUCCESS;if(!ok)SetLastError(result);
  }
  CloseHandle(object);return ok;
}
static BOOL mkdir_private(const wchar_t *path,Context *c) {
  SECURITY_ATTRIBUTES sa={sizeof(sa),c->private_sd,FALSE};
  if(!CreateDirectoryW(path,&sa)&&GetLastError()!=ERROR_ALREADY_EXISTS)return FALSE;
  return regular_object(path,TRUE)&&apply_sd(path,c->private_sd);
}
static BOOL acl_tree(const wchar_t *path,Context *c,unsigned depth,DWORD *count) {
  if(depth>TREE_DEPTH||++*count>TREE_LIMIT){SetLastError(ERROR_BUFFER_OVERFLOW);return FALSE;}
  if(!apply_sd(path,c->app_sd))return FALSE;
  if(!regular_object(path,TRUE))return TRUE;
  wchar_t *pattern=malloc(PATH_CAP*sizeof(wchar_t)),*child=malloc(PATH_CAP*sizeof(wchar_t));
  if(!pattern||!child){free(pattern);free(child);return FALSE;}
  if(!path_join(pattern,path,L"*")){free(pattern);free(child);return FALSE;}
  WIN32_FIND_DATAW entry;HANDLE find=FindFirstFileW(pattern,&entry);BOOL ok=TRUE;
  if(find==INVALID_HANDLE_VALUE){DWORD error=GetLastError();free(pattern);free(child);
    return error==ERROR_FILE_NOT_FOUND;}
  do {
    if(!wcscmp(entry.cFileName,L".")||!wcscmp(entry.cFileName,L".."))continue;
    if((entry.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||
       !path_join(child,path,entry.cFileName)||!acl_tree(child,c,depth+1,count)){ok=FALSE;break;}
  }while(FindNextFileW(find,&entry));
  if(ok&&GetLastError()!=ERROR_NO_MORE_FILES)ok=FALSE;
  FindClose(find);free(pattern);free(child);return ok;
}
static BOOL random_name(wchar_t *out,size_t cap,const wchar_t *prefix) {
  unsigned char bytes[16];if(BCryptGenRandom(NULL,bytes,sizeof(bytes),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0)return FALSE;
  size_t used=wcslen(prefix);if(cap<used+33)return FALSE;wcscpy(out,prefix);
  for(size_t i=0;i<16;i++)swprintf(out+used+2*i,cap-used-2*i,L"%02x",bytes[i]);
  return TRUE;
}
static BOOL create_container(Context *c) {
  if(!random_name(c->container_name,64,L"AEGIS.SafeWeb."))return FALSE;
  HRESULT result=CreateAppContainerProfile(c->container_name,L"AEGIS Safe Web",
    L"Isolated official Tor Browser session",NULL,0,&c->app_sid);
  if(FAILED(result)){SetLastError((DWORD)result);return FALSE;}
  if(!ConvertSidToStringSidW(c->app_sid,&c->app_text))return FALSE;
  PWSTR folder=NULL;
  result=GetAppContainerFolderPath(c->app_text,&folder);
  if(FAILED(result)){SetLastError((DWORD)result);return FALSE;}
  BOOL ok=wcslen(folder)<PATH_CAP-32;
  if(ok)wcscpy(c->package_dir,folder);
  CoTaskMemFree(folder);
  return ok&&make_sd(c,TRUE,&c->app_sd);
}
static BOOL is_container(HANDLE process,PSID expected) {
  HANDLE token=NULL;if(!OpenProcessToken(process,TOKEN_QUERY,&token))return FALSE;
  DWORD yes=0,n=0;BOOL ok=GetTokenInformation(token,TokenIsAppContainer,&yes,sizeof(yes),&n)&&yes;
  unsigned char buffer[SECURITY_MAX_SID_SIZE+sizeof(TOKEN_APPCONTAINER_INFORMATION)];
  if(ok&&expected){ok=GetTokenInformation(token,TokenAppContainerSid,buffer,sizeof(buffer),&n);
    if(ok)ok=EqualSid(((TOKEN_APPCONTAINER_INFORMATION*)buffer)->TokenAppContainer,expected);}
  CloseHandle(token);return ok;
}
static BOOL valid_url(const wchar_t *url) {
  size_t n=wcslen(url);if(!n||n>URL_CAP)return FALSE;
  /* URL is ASCII URI from Java; reject controls, shell/argument quoting, local
   * schemes, backslashes, user-info and malformed host/port. No network lookup. */
  for(size_t i=0;i<n;i++)if(url[i]<=32||url[i]>126||url[i]==L'"'||url[i]==L'\\')return FALSE;
  size_t scheme=!_wcsnicmp(url,L"https://",8)?8:(!_wcsnicmp(url,L"http://",7)?7:0);
  if(!scheme)return FALSE;
  const wchar_t *host=url+scheme,*end=host;
  while(*end&&*end!=L'/'&&*end!=L'?'&&*end!=L'#')end++;
  if(end==host||end-host>259)return FALSE;
  const wchar_t *colon=NULL;
  for(const wchar_t *p=host;p<end;p++){
    if(*p==L':'){if(colon)return FALSE;colon=p;continue;}
    if(!((*p>=L'a'&&*p<=L'z')||(*p>=L'A'&&*p<=L'Z')||
       (*p>=L'0'&&*p<=L'9')||*p==L'.'||*p==L'-'))return FALSE;
  }
  const wchar_t *host_end=colon?colon:end;
  if(host_end==host||host[0]==L'.'||host[0]==L'-'||host_end[-1]==L'.'||host_end[-1]==L'-')return FALSE;
  size_t host_size=(size_t)(host_end-host);BOOL has_dot=FALSE,only_numeric=TRUE;
  for(const wchar_t *p=host;p<host_end;p++){
    if(*p==L'.')has_dot=TRUE;
    else if(*p<L'0'||*p>L'9')only_numeric=FALSE;
  }
  if(!has_dot||only_numeric||(host_size>=10&&!_wcsnicmp(host_end-10,L".localhost",10)))return FALSE;
  if(colon){unsigned port=0;if(colon+1==end)return FALSE;
    for(const wchar_t *p=colon+1;p<end;p++){if(*p<L'0'||*p>L'9')return FALSE;
      port=port*10+(unsigned)(*p-L'0');if(port>65535)return FALSE;}if(!port)return FALSE;}
  BOOL onion=host_size>=62&&!_wcsnicmp(host_end-6,L".onion",6);
  if(onion){
    const wchar_t *label=host_end-62;
    if(label>host&&label[-1]!=L'.')return FALSE;
    for(const wchar_t *p=label;p<host_end-6;p++)
      if(!((*p>=L'a'&&*p<=L'z')||(*p>=L'A'&&*p<=L'Z')||(*p>=L'2'&&*p<=L'7')))return FALSE;
  }else if(host_size>=6&&!_wcsnicmp(host_end-6,L".onion",6))return FALSE;
  if(scheme==7&&!onion)return FALSE;
  return TRUE;
}
/* Windows CRT argument quoting, including terminal backslashes. No cmd.exe. */
static BOOL quote_arg(wchar_t *out,size_t cap,size_t *used,const wchar_t *arg) {
  if(*used+3>=cap)return FALSE;
  out[(*used)++]=L'"';size_t slashes=0;
  for(const wchar_t *p=arg;;p++){
    if(*p==L'\\'){slashes++;continue;}
    size_t copies=(*p==L'"'||!*p)?slashes*2:slashes;
    if(*used+copies+3>=cap)return FALSE;
    while(copies--)out[(*used)++]=L'\\';
    slashes=0;
    if(!*p)break;
    if(*p==L'"')out[(*used)++]=L'\\';
    out[(*used)++]=*p;
  }
  out[(*used)++]=L'"';out[*used]=0;return TRUE;
}
static BOOL add_arg(wchar_t *out,size_t *used,const wchar_t *arg) {
  if(*used){if(*used+1>=PATH_CAP)return FALSE;out[(*used)++]=L' ';}
  return quote_arg(out,PATH_CAP,used,arg);
}
static wchar_t *minimal_environment(Context *c) {
  wchar_t windows[PATH_CAP],system[PATH_CAP],appdata[PATH_CAP];
  if(!GetWindowsDirectoryW(windows,PATH_CAP)||!path_join(system,windows,L"System32")||
    !path_join(appdata,c->home,L"AppData")||(!CreateDirectoryW(appdata,NULL)&&GetLastError()!=ERROR_ALREADY_EXISTS))return NULL;
  if(!path_join(appdata,c->home,L"AppData\\Roaming")||
    (!CreateDirectoryW(appdata,NULL)&&GetLastError()!=ERROR_ALREADY_EXISTS))return NULL;
  wchar_t *env=calloc(8*PATH_CAP,sizeof(wchar_t));if(!env)return NULL;
  /* Alphabetic environment block; every value is OS-derived or private. */
  const wchar_t *names[]={L"APPDATA",L"LOCALAPPDATA",L"PATH",L"SystemRoot",L"TEMP",L"TMP",L"USERPROFILE",L"windir"};
  const wchar_t *values[]={appdata,c->package_dir,system,windows,c->temp,c->temp,c->home,windows};
  size_t used=0;
  for(size_t i=0;i<8;i++){
    size_t need=wcslen(names[i])+wcslen(values[i])+2;
    if(used+need+1>=8*PATH_CAP){free(env);return NULL;}
    swprintf(env+used,8*PATH_CAP-used,L"%ls=%ls",names[i],values[i]);used+=need;
  }
  env[used]=0;return env;
}
static HANDLE private_job(void) {
  HANDLE job=CreateJobObjectW(NULL,NULL);if(!job)return NULL;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};
  limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  limits.BasicLimitInformation.ActiveProcessLimit=256;
  JOBOBJECT_BASIC_UI_RESTRICTIONS ui={JOB_OBJECT_UILIMIT_READCLIPBOARD|
    JOB_OBJECT_UILIMIT_WRITECLIPBOARD|JOB_OBJECT_UILIMIT_DESKTOP|
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS|JOB_OBJECT_UILIMIT_DISPLAYSETTINGS|JOB_OBJECT_UILIMIT_EXITWINDOWS};
  if(!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))||
     !SetInformationJobObject(job,JobObjectBasicUIRestrictions,&ui,sizeof(ui))){CloseHandle(job);return NULL;}
  return job;
}
static BOOL launch(Context *c,const wchar_t *exe,wchar_t *command,const wchar_t *cwd,
                   HANDLE job,BOOL network,PROCESS_INFORMATION *pi) {
  STARTUPINFOEXW si={0};si.StartupInfo.cb=sizeof(si);
  si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
  SECURITY_ATTRIBUTES inherit={sizeof(inherit),NULL,TRUE};
  HANDLE nullin=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&inherit,OPEN_EXISTING,0,NULL);
  HANDLE nullout=CreateFileW(L"NUL",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&inherit,OPEN_EXISTING,0,NULL);
  if(nullin==INVALID_HANDLE_VALUE||nullout==INVALID_HANDLE_VALUE){
    if(nullin!=INVALID_HANDLE_VALUE)CloseHandle(nullin);
    if(nullout!=INVALID_HANDLE_VALUE)CloseHandle(nullout);
    return FALSE;}
  si.StartupInfo.hStdInput=nullin;si.StartupInfo.hStdOutput=nullout;si.StartupInfo.hStdError=nullout;
  HANDLE handles[2]={nullin,nullout};SIZE_T length=0;
  InitializeProcThreadAttributeList(NULL,2,0,&length);
  si.lpAttributeList=malloc(length);
  BOOL initialized=si.lpAttributeList&&InitializeProcThreadAttributeList(si.lpAttributeList,2,0,&length);
  SECURITY_CAPABILITIES capabilities={0};capabilities.AppContainerSid=c->app_sid;
  unsigned char internet_sid[SECURITY_MAX_SID_SIZE];DWORD sid_size=sizeof(internet_sid);
  SID_AND_ATTRIBUTES internet={internet_sid,SE_GROUP_ENABLED};
  BOOL ok=initialized;
  if(ok&&network){ok=CreateWellKnownSid(WinCapabilityInternetClientSid,NULL,internet_sid,&sid_size);
    capabilities.Capabilities=&internet;capabilities.CapabilityCount=1;}
  if(ok)ok=UpdateProcThreadAttribute(si.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    &capabilities,sizeof(capabilities),NULL,NULL)&&UpdateProcThreadAttribute(si.lpAttributeList,0,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,handles,sizeof(handles),NULL,NULL);
  wchar_t *env=ok?minimal_environment(c):NULL;ok=ok&&env;
  if(ok)ok=CreateProcessW(exe,command,NULL,NULL,TRUE,
    EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW,
    env,cwd,&si.StartupInfo,pi);
  DWORD error=GetLastError();free(env);
  if(initialized)DeleteProcThreadAttributeList(si.lpAttributeList);
  free(si.lpAttributeList);CloseHandle(nullin);CloseHandle(nullout);
  if(!ok){SetLastError(error);return FALSE;}
  /* Child cannot execute a single instruction before both containment checks. */
  if(!is_container(pi->hProcess,c->app_sid)||!AssignProcessToJobObject(job,pi->hProcess)||
    ResumeThread(pi->hThread)==(DWORD)-1){
    error=GetLastError();TerminateProcess(pi->hProcess,SANDBOX_FAILED);
    CloseHandle(pi->hThread);CloseHandle(pi->hProcess);memset(pi,0,sizeof(*pi));SetLastError(error);return FALSE;}
  CloseHandle(pi->hThread);pi->hThread=NULL;return TRUE;
}
static DWORD job_count(HANDLE job) {
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
  if(!QueryInformationJobObject(job,JobObjectBasicAccountingInformation,&info,sizeof(info),NULL))return MAXDWORD;
  return info.ActiveProcesses;
}
static BOOL CALLBACK close_owned_window(HWND window,LPARAM parameter) {
  HANDLE job=(HANDLE)parameter;DWORD pid=0;GetWindowThreadProcessId(window,&pid);
  HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);BOOL owned=FALSE;
  if(process){if(IsProcessInJob(process,job,&owned)&&owned)PostMessageW(window,WM_CLOSE,0,0);CloseHandle(process);}
  return TRUE;
}
static void stop_job(HANDLE job) {
  EnumWindows(close_owned_window,(LPARAM)job);ULONGLONG until=GetTickCount64()+SHUTDOWN_MS;
  while(job_count(job)>0&&GetTickCount64()<until)Sleep(50);
  if(job_count(job)>0)TerminateJobObject(job,OK);
}
static BOOL write_sentinel(const wchar_t *path,PSECURITY_DESCRIPTOR sd) {
  SECURITY_ATTRIBUTES sa={sizeof(sa),sd,FALSE};
  HANDLE file=CreateFileW(path,GENERIC_WRITE,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
  if(file==INVALID_HANDLE_VALUE)return FALSE;
  DWORD written=0;
  BOOL ok=WriteFile(file,"AEGIS_SAFEWEB_PROBE",18,&written,NULL)&&written==18;CloseHandle(file);return ok;
}
static int loopback_child(const wchar_t *port_text,const wchar_t *sid_text) {
  PSID expected=NULL;if(!ConvertStringSidToSidW(sid_text,&expected))return SELFTEST_FAILED;
  BOOL ok=is_container(GetCurrentProcess(),expected);LocalFree(expected);
  if(!ok)return SELFTEST_FAILED;
  wchar_t *end=NULL;unsigned long port=wcstoul(port_text,&end,10);
  if(!end||*end||!port||port>65535)return SELFTEST_FAILED;
  WSADATA data;if(WSAStartup(MAKEWORD(2,2),&data))return SELFTEST_FAILED;
  SOCKET connection=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
  struct sockaddr_in address={0};address.sin_family=AF_INET;
  address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons((u_short)port);
  ok=connection!=INVALID_SOCKET&&connect(connection,(struct sockaddr*)&address,sizeof(address))==0&&
     send(connection,"T",1,0)==1;
  if(connection!=INVALID_SOCKET)closesocket(connection);
  WSACleanup();return ok?OK:SELFTEST_FAILED;
}
static BOOL loopback_probe(const wchar_t *sid_text) {
  WSADATA data;if(WSAStartup(MAKEWORD(2,2),&data))return FALSE;
  SOCKET listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP),connection=INVALID_SOCKET;
  struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  int size=sizeof(address);BOOL ok=FALSE;PROCESS_INFORMATION pi={0};
  wchar_t *self=calloc(PATH_CAP,sizeof(wchar_t)),*command=calloc(PATH_CAP,sizeof(wchar_t));
  if(listener==INVALID_SOCKET||!self||!command||bind(listener,(struct sockaddr*)&address,sizeof(address))||
     listen(listener,1)||getsockname(listener,(struct sockaddr*)&address,&size))goto done;
  if(!GetModuleFileNameW(NULL,self,PATH_CAP))goto done;
  wchar_t port[16];swprintf(port,16,L"%u",(unsigned)ntohs(address.sin_port));size_t used=0;
  if(!add_arg(command,&used,self)||!add_arg(command,&used,L"--loopback-internal")||
     !add_arg(command,&used,port)||!add_arg(command,&used,sid_text))goto done;
  STARTUPINFOW si={0};si.cb=sizeof(si);
  /* This child inherits its AppContainer token, capability and job from the
   * contained probe. It does not inherit handles or use any shell. */
  if(!CreateProcessW(self,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi))goto done;
  CloseHandle(pi.hThread);pi.hThread=NULL;
  fd_set ready;FD_ZERO(&ready);FD_SET(listener,&ready);struct timeval timeout={5,0};
  if(select(0,&ready,NULL,NULL,&timeout)!=1)goto done;
  connection=accept(listener,NULL,NULL);if(connection==INVALID_SOCKET)goto done;
  DWORD receive_timeout=3000;setsockopt(connection,SOL_SOCKET,SO_RCVTIMEO,(const char*)&receive_timeout,sizeof(receive_timeout));
  char received=0;if(recv(connection,&received,1,0)!=1||received!='T')goto done;
  if(WaitForSingleObject(pi.hProcess,5000)==WAIT_OBJECT_0){DWORD code=SELFTEST_FAILED;
    ok=GetExitCodeProcess(pi.hProcess,&code)&&code==OK;}
done:
  if(pi.hProcess){if(!ok)TerminateProcess(pi.hProcess,SELFTEST_FAILED);CloseHandle(pi.hProcess);}
  if(listener!=INVALID_SOCKET)closesocket(listener);
  if(connection!=INVALID_SOCKET)closesocket(connection);
  free(self);free(command);WSACleanup();return ok;
}
static int probe_child(const wchar_t *own,const wchar_t *outside,const wchar_t *sid_text) {
  PSID expected=NULL;if(!ConvertStringSidToSidW(sid_text,&expected))return SELFTEST_FAILED;
  BOOL ok=is_container(GetCurrentProcess(),expected);LocalFree(expected);if(!ok)return SELFTEST_FAILED;
  HANDLE file=CreateFileW(own,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
  if(file==INVALID_HANDLE_VALUE)return SELFTEST_FAILED;
  char buffer[18];DWORD read=0;ok=ReadFile(file,buffer,sizeof(buffer),&read,NULL)&&read==18&&
    !memcmp(buffer,"AEGIS_SAFEWEB_PROBE",18);CloseHandle(file);if(!ok)return SELFTEST_FAILED;
  file=CreateFileW(outside,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
  if(file!=INVALID_HANDLE_VALUE){CloseHandle(file);return SELFTEST_FAILED;}
  if(GetLastError()!=ERROR_ACCESS_DENIED)return SELFTEST_FAILED;
  file=CreateFileW(outside,GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
  if(file!=INVALID_HANDLE_VALUE){CloseHandle(file);return SELFTEST_FAILED;}
  if(GetLastError()!=ERROR_ACCESS_DENIED)return SELFTEST_FAILED;
  /* Reading and writing the host clipboard must be disabled for the entire job. */
  JOBOBJECT_BASIC_UI_RESTRICTIONS ui={0};
  if(!QueryInformationJobObject(NULL,JobObjectBasicUIRestrictions,&ui,sizeof(ui),NULL)||
    (ui.UIRestrictionsClass&(JOB_OBJECT_UILIMIT_READCLIPBOARD|JOB_OBJECT_UILIMIT_WRITECLIPBOARD))!=
    (JOB_OBJECT_UILIMIT_READCLIPBOARD|JOB_OBJECT_UILIMIT_WRITECLIPBOARD))return SELFTEST_FAILED;
  return loopback_probe(sid_text)?OK:SELFTEST_FAILED;
}
static BOOL filesystem_probe(Context *c,const wchar_t *inside) {
  wchar_t name[64],*exe=calloc(PATH_CAP,sizeof(wchar_t)),*own=calloc(PATH_CAP,sizeof(wchar_t));
  wchar_t *outside=calloc(PATH_CAP,sizeof(wchar_t)),*source=calloc(PATH_CAP,sizeof(wchar_t));
  wchar_t *command=malloc(PATH_CAP*sizeof(wchar_t));HANDLE job=NULL;BOOL ok=FALSE;PROCESS_INFORMATION pi={0};
  if(!exe||!own||!outside||!source||!command||!random_name(name,64,L"probe-"))goto done;
  wchar_t tail[90];swprintf(tail,90,L"%ls.exe",name);if(!path_join(exe,inside,tail))goto done;
  swprintf(tail,90,L"%ls-own.txt",name);if(!path_join(own,inside,tail))goto done;
  swprintf(tail,90,L"%ls-outside.txt",name);if(!path_join(outside,c->control,tail))goto done;
  if(!GetModuleFileNameW(NULL,source,PATH_CAP)||!CopyFileW(source,exe,TRUE)||
    !apply_sd(exe,c->app_sd)||!write_sentinel(own,c->app_sd)||
    !write_sentinel(outside,c->private_sd))goto done;
  size_t used=0;
  if(!add_arg(command,&used,exe)||!add_arg(command,&used,L"--probe-internal")||
    !add_arg(command,&used,own)||!add_arg(command,&used,outside)||!add_arg(command,&used,c->app_text))goto done;
  job=private_job();if(!job||!launch(c,exe,command,inside,job,TRUE,&pi))goto done;
  if(WaitForSingleObject(pi.hProcess,20000)==WAIT_OBJECT_0){DWORD exit_code=SELFTEST_FAILED;
    ok=GetExitCodeProcess(pi.hProcess,&exit_code)&&exit_code==OK;}
done:
  if(job){TerminateJobObject(job,OK);CloseHandle(job);}if(pi.hProcess)CloseHandle(pi.hProcess);
  if(exe&&*exe)DeleteFileW(exe);
  if(own&&*own)DeleteFileW(own);
  if(outside&&*outside)DeleteFileW(outside);
  free(exe);free(own);free(outside);free(source);free(command);return ok;
}
static BOOL bundle_path(Context *c,const wchar_t *arg,wchar_t *bundle) {
  wchar_t *parent=malloc(PATH_CAP*sizeof(wchar_t));if(!parent)return FALSE;
  BOOL ok=path_join(parent,c->root,L"bundles");DWORD n=GetFullPathNameW(arg,PATH_CAP,bundle,NULL);
  size_t base=wcslen(parent);
  if(!ok||!n||n>=PATH_CAP||_wcsnicmp(bundle,parent,base)||bundle[base]!=L'\\'||
    !simple_component(bundle+base+1)||!regular_object(bundle,TRUE)||!no_reparse_ancestors(bundle))ok=FALSE;
  free(parent);return ok;
}
static BOOL acquire_lock(Context *c,const wchar_t *bundle) {
  uint64_t hash=UINT64_C(1469598103934665603);
  for(const wchar_t *p=c->user_text;*p;p++)hash=(hash^(uint16_t)*p)*UINT64_C(1099511628211);
  for(const wchar_t *p=bundle;*p;p++)hash=(hash^(uint16_t)towlower(*p))*UINT64_C(1099511628211);
  wchar_t name[100];swprintf(name,100,L"Local\\AEGIS.SafeWeb.%016llx",(unsigned long long)hash);
  SECURITY_ATTRIBUTES sa={sizeof(sa),c->private_sd,FALSE};
  c->lock=CreateMutexW(&sa,TRUE,name);if(!c->lock)return FALSE;
  if(GetLastError()==ERROR_ALREADY_EXISTS){CloseHandle(c->lock);c->lock=NULL;SetLastError(ERROR_ALREADY_EXISTS);return FALSE;}
  return TRUE;
}
static BOOL setup_dirs(Context *c,const wchar_t *bundle) {
  wchar_t *path=malloc(PATH_CAP*sizeof(wchar_t));if(!path)return FALSE;
  BOOL ok=path_join(c->home,bundle,L"Browser\\TorBrowser\\Data\\aegis-home")&&
    (CreateDirectoryW(c->home,NULL)||GetLastError()==ERROR_ALREADY_EXISTS)&&regular_object(c->home,TRUE);
  /* Apply the AppContainer SID only inside its own bundle/profile, never to the
   * user's profile, AEGIS, LocalAppData, control records or verified templates. */
  if(ok)ok=path_join(path,bundle,L"aegis-downloads")&&
    (CreateDirectoryW(path,NULL)||GetLastError()==ERROR_ALREADY_EXISTS)&&regular_object(path,TRUE);
  if(ok)ok=path_join(path,c->home,L"Downloads")&&
    (CreateDirectoryW(path,NULL)||GetLastError()==ERROR_ALREADY_EXISTS)&&regular_object(path,TRUE);
  if(ok)ok=path_join(c->temp,c->package_dir,L"Temp")&&
    (CreateDirectoryW(c->temp,NULL)||GetLastError()==ERROR_ALREADY_EXISTS)&&regular_object(c->temp,TRUE);
  free(path);return ok;
}
static int run_browser(Context *c,const wchar_t *bundle,const wchar_t *url) {
  wchar_t *exe=malloc(PATH_CAP*sizeof(wchar_t)),*profile=malloc(PATH_CAP*sizeof(wchar_t));
  wchar_t *command=malloc(PATH_CAP*sizeof(wchar_t));int result=SANDBOX_FAILED;
  HANDLE job=NULL;PROCESS_INFORMATION pi={0};
  if(!exe||!profile||!command)goto done;
  if(!path_join(exe,bundle,L"Browser\\firefox.exe")||!regular_object(exe,FALSE)||
    !path_join(profile,bundle,L"Browser\\TorBrowser\\Data\\Browser\\profile.default")||
    !regular_object(profile,TRUE)){result=fail(UNSAFE_PATH,"OFFICIAL_BUNDLE_LAYOUT_REQUIRED");goto done;}
  if(!acquire_lock(c,bundle)){result=fail(ALREADY_RUNNING,"BUNDLE_IN_USE");goto done;}
  if(!create_container(c)||!setup_dirs(c,bundle)) {result=fail(SANDBOX_FAILED,"CONTAINER_CREATE_FAILED");goto done;}
  DWORD count=0;
  if(!acl_tree(bundle,c,0,&count)||!filesystem_probe(c,bundle)){
    result=fail(SANDBOX_FAILED,"FILESYSTEM_PROBE_FAILED");goto done;}
  size_t used=0;
  if(!add_arg(command,&used,exe)||!add_arg(command,&used,L"-no-remote")||
    !add_arg(command,&used,L"-profile")||!add_arg(command,&used,profile)||
    !add_arg(command,&used,L"-new-window")||!add_arg(command,&used,url)){
    result=fail(BAD_ARGUMENT,"COMMAND_TOO_LONG");goto done;}
  job=private_job();
  if(!job||!launch(c,exe,command,bundle,job,TRUE,&pi)){
    result=fail(SANDBOX_FAILED,"CONTAINED_LAUNCH_FAILED");goto done;}
  ULONGLONG launched_at=GetTickCount64();
  printf("{\"state\":\"PROCESS_CREATED\",\"isolation\":\"APPCONTAINER\",\"networkPolicy\":\"STOCK_TOR_BROWSER\",\"pid\":%lu}\n",(unsigned long)pi.dwProcessId);fflush(stdout);
  /* Java must retain the stdin pipe. EOF, CLOSE\n, malformed input or a broken
   * controller pipe stops only this job. Browser children never inherit it. */
  HANDLE input=GetStdHandle(STD_INPUT_HANDLE);char control[16];size_t used_control=0;BOOL close=FALSE;
  if(GetFileType(input)!=FILE_TYPE_PIPE){result=fail(BAD_ARGUMENT,"CONTROLLER_PIPE_REQUIRED");goto done;}
  for(;;){
    DWORD active=job_count(job);if(active==0){DWORD exit_code=0;
      if(!GetExitCodeProcess(pi.hProcess,&exit_code)||exit_code!=0||GetTickCount64()-launched_at<3000)
        result=fail(BROWSER_FAILED,"BROWSER_EARLY_EXIT_OR_CRASH");
      else result=OK;
      break;}
    if(active==MAXDWORD){result=fail(SANDBOX_FAILED,"JOB_QUERY_FAILED");break;}
    DWORD available=0;
    if(!PeekNamedPipe(input,NULL,0,NULL,&available,NULL)){close=TRUE;break;}
    if(available){DWORD received=0;char chunk[16];DWORD take=available<sizeof(chunk)?available:(DWORD)sizeof(chunk);
      if(!ReadFile(input,chunk,take,&received,NULL)||!received){close=TRUE;break;}
      for(DWORD i=0;i<received;i++){
        if(used_control+1>=sizeof(control)){close=TRUE;break;}
        control[used_control++]=chunk[i];
        if(chunk[i]=='\n'){control[used_control]=0;close=TRUE;break;}
      }
      if(close)break;
    }
    Sleep(100);
  }
  if(close){stop_job(job);result=OK;}
  status("CLOSED","OWNED_JOB_STOPPED",0);
done:
  if(job){TerminateJobObject(job,OK);CloseHandle(job);}
  if(pi.hProcess)CloseHandle(pi.hProcess);
  free(exe);free(profile);free(command);return result;
}
static int selftest(Context *c) {
  wchar_t *inside=calloc(PATH_CAP,sizeof(wchar_t));if(!inside)return SELFTEST_FAILED;
  wchar_t name[64];BOOL ok=random_name(name,64,L"selftest-")&&path_join(inside,c->root,name)&&mkdir_private(inside,c);
  /* Self-test has no Browser tree, so its private home is the scaffold itself. */
  if(ok)ok=create_container(c)&&path_join(c->temp,c->package_dir,L"Temp")&&
    (CreateDirectoryW(c->temp,NULL)||GetLastError()==ERROR_ALREADY_EXISTS);
  if(ok){wcscpy(c->home,inside);ok=apply_sd(inside,c->app_sd)&&filesystem_probe(c,inside);}
  status(ok?"SELFTEST_PASS":"SELFTEST_FAIL","TOKEN_FS_DENY_LOOPBACK_JOB_POLICY",0);
  /* Remove only our empty sentinel scaffold; persistent session bundles are
   * never deleted by this helper. Windows owns AppContainer profile cleanup. */
  if(*inside){wchar_t path[PATH_CAP];
    if(path_join(path,inside,L"AppData\\Roaming"))RemoveDirectoryW(path);
    if(path_join(path,inside,L"AppData"))RemoveDirectoryW(path);
    RemoveDirectoryW(inside);}
  free(inside);return ok?OK:SELFTEST_FAILED;
}
static int cleanup(Context *c,int result) {
  if(c->container_name[0]) {
    HRESULT hr=DeleteAppContainerProfile(c->container_name);
    if(FAILED(hr)){status("WARNING","CONTAINER_PROFILE_CLEANUP_FAILED",(DWORD)hr);if(result==OK)result=CLEANUP_FAILED;}
  }
  if(c->lock){ReleaseMutex(c->lock);CloseHandle(c->lock);}
  if(c->app_sid)FreeSid(c->app_sid);
  free(c->user_sid);
  if(c->app_text)LocalFree(c->app_text);
  if(c->user_text)LocalFree(c->user_text);
  if(c->private_sd)LocalFree(c->private_sd);
  if(c->app_sd)LocalFree(c->app_sd);
  return result;
}
int wmain(int argc,wchar_t **argv) {
  SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
  /* Trusted internal probe is inert without an AppContainer token. */
  if(argc==5&&!wcscmp(argv[1],L"--probe-internal"))return probe_child(argv[2],argv[3],argv[4]);
  if(argc==4&&!wcscmp(argv[1],L"--loopback-internal"))return loopback_child(argv[2],argv[3]);
  BOOL testing=argc==2&&!wcscmp(argv[1],L"--self-test");
  if(!testing&&(argc!=5||wcscmp(argv[1],L"--bundle")||wcscmp(argv[3],L"--url")||!valid_url(argv[4])))
    return fail(BAD_ARGUMENT,"EXPECTED_BUNDLE_URL_OR_SELFTEST");
  Context *c=calloc(1,sizeof(Context));if(!c)return fail(SANDBOX_FAILED,"NO_MEMORY");
  int result=SANDBOX_FAILED;
  if(!user_context(c)||!make_sd(c,FALSE,&c->private_sd)||!mkdir_private(c->root,c)||!mkdir_private(c->control,c))
    result=fail(SANDBOX_FAILED,"PRIVATE_USER_CONTEXT_REQUIRED");
  else if(testing)result=selftest(c);
  else {
    wchar_t *bundle=calloc(PATH_CAP,sizeof(wchar_t));
    if(!bundle||!bundle_path(c,argv[2],bundle))result=fail(UNSAFE_PATH,"DEDICATED_LOCAL_BUNDLE_REQUIRED");
    else result=run_browser(c,bundle,argv[4]);
    free(bundle);
  }
  result=cleanup(c,result);free(c);return result;
}
