#define _POSIX_C_SOURCE 200809L
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* fcntl, not flock: interoperable with Java FileChannel on Linux. Parent retains lease. */
static int guard(void){
 const char *base=getenv("XDG_DATA_HOME");char fallback[PATH_MAX],path[PATH_MAX];
 if(!base||!*base){
  // Match the JVM's operating-system user.home, not a substituted shell HOME.
  struct passwd user,*found=NULL;char buffer[65536];
  if(getpwuid_r(getuid(),&user,buffer,sizeof buffer,&found)||!found||!user.pw_dir||*user.pw_dir!='/')return -1;
  if(snprintf(fallback,sizeof fallback,"%s/.local/share",user.pw_dir)>=(int)sizeof fallback)return -1;
  base=fallback;
 }
 if(*base!='/'||snprintf(path,sizeof path,"%s/aegis-runtime600-guard",base)>=(int)sizeof path)return -1;
 // Walk every parent through directory FDs with O_NOFOLLOW; no shell/path substitution.
 int directory=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(directory<0)return -1;char copy[PATH_MAX];strcpy(copy,path);char *save=NULL;
 for(char *part=strtok_r(copy,"/",&save);part;part=strtok_r(NULL,"/",&save)){
  if(!strcmp(part,".")||!strcmp(part,"..")){close(directory);return -1;}
  if(mkdirat(directory,part,0700)&&errno!=EEXIST){close(directory);return -1;}
  int next=openat(directory,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(directory);if(next<0)return -1;directory=next;
 }
 struct stat info;if(fstat(directory,&info)||info.st_uid!=getuid()||fchmod(directory,0700)){close(directory);return -1;}
 int file=openat(directory,"installation.lock",O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC,0600);close(directory);if(file<0)return -1;
 if(fstat(file,&info)||!S_ISREG(info.st_mode)||info.st_uid!=getuid()||info.st_nlink!=1||info.st_size!=0){close(file);return -1;}
 struct flock lock={.l_type=F_RDLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=0x7fffffffffffffffLL};if(fcntl(file,F_SETLK,&lock)){close(file);return -1;}return file;
}
int main(int argc,char **argv){
 if(argc<2||argv[1][0]!='/')return 2;
 int lease=guard();if(lease<0){fputs("АЕГИС: запуск заблокирован обновлением или недоступной личной блокировкой.\n",stderr);return 1;}
 pid_t child=fork();if(child<0){close(lease);return 1;}if(child==0){close(lease);execv(argv[1],argv+1);_exit(127);}
 int status;while(waitpid(child,&status,0)<0){if(errno!=EINTR){close(lease);return 1;}}close(lease);return WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);
}
