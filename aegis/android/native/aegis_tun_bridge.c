/* Lifecycle/policy JNI glue only. Upstream hev + lwIP implements all TCP/IP. */
#include <jni.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "hev-main.h"
#include "aegis_tun_bridge.h"
static JavaVM *vm;static jobject protector;static jmethodID protect_method;static char *rules;static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;static int running;
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *v,void *unused){(void)unused;vm=v;return JNI_VERSION_1_6;}
/* hev tasks run on alternate stacks. JNI calls are dispatched to a normal attached
 * pthread rather than invoking ART/JVM from a coroutine stack. One engine, one request. */
static pthread_mutex_t protect_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t protect_cond=PTHREAD_COND_INITIALIZER;
static pthread_t protect_thread;static int protect_started,protect_stop,request_fd=-1,request_result;
static void *protect_worker(void *unused){(void)unused;JNIEnv *env=NULL;
#ifdef __ANDROID__
int ok=(*vm)->AttachCurrentThread(vm,&env,NULL)==JNI_OK;
#else
int ok=(*vm)->AttachCurrentThread(vm,(void**)&env,NULL)==JNI_OK;
#endif
pthread_mutex_lock(&protect_lock);while(!protect_stop){while(request_fd<0&&!protect_stop)pthread_cond_wait(&protect_cond,&protect_lock);if(protect_stop)break;int fd=request_fd;pthread_mutex_unlock(&protect_lock);int verdict=0;if(ok&&protector&&protect_method){verdict=(*env)->CallBooleanMethod(env,protector,protect_method,fd);if((*env)->ExceptionCheck(env)){(*env)->ExceptionClear(env);verdict=0;}}pthread_mutex_lock(&protect_lock);request_result=verdict?1:0;request_fd=-1;pthread_cond_broadcast(&protect_cond);}pthread_mutex_unlock(&protect_lock);if(ok)(*vm)->DetachCurrentThread(vm);return NULL;}
int aegis_protect_fd(int fd){pthread_mutex_lock(&protect_lock);if(!protect_started||protect_stop){pthread_mutex_unlock(&protect_lock);return 0;}request_fd=fd;request_result=0;pthread_cond_broadcast(&protect_cond);while(request_fd>=0&&!protect_stop)pthread_cond_wait(&protect_cond,&protect_lock);int verdict=request_result;pthread_mutex_unlock(&protect_lock);return verdict;}
int aegis_domain_allowed(const char *domain){size_t n=strnlen(domain,254);if(n<3||n>253)return 0;char lower[254];size_t label=0;for(size_t i=0;i<n;i++){unsigned char c=(unsigned char)domain[i];if(c=='.'){if(label<1||label>63)return 0;label=0;}else{if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'))return 0;label++;}lower[i]=(char)tolower(c);}if(label<1||label>63)return 0;lower[n]=0;if(rules){const char *p=rules;while(*p){const char *end=strchr(p,'\n');size_t len=end?(size_t)(end-p):strlen(p);if(len<=n&&!memcmp(lower+n-len,p,len)&&(len==n||lower[n-len-1]=='.'))return 0;if(!end)break;p=end+1;}}return 1;}
JNIEXPORT jint JNICALL Java_org_aegis_android_NativeTun_run(JNIEnv *e,jclass cls,jbyteArray config,jint fd,jstring deny,jobject callback){(void)cls;int result=-1,owned=-1;unsigned char *parameters=NULL;jsize parameters_len=0;const char *text=NULL;pthread_mutex_lock(&lock);if(running){pthread_mutex_unlock(&lock);return -1;}running=1;pthread_mutex_unlock(&lock);if(!config)goto done;parameters_len=(*e)->GetArrayLength(e,config);if(parameters_len<1||parameters_len>16384)goto done;parameters=malloc(parameters_len);if(!parameters)goto done;(*e)->GetByteArrayRegion(e,config,0,parameters_len,(jbyte*)parameters);if((*e)->ExceptionCheck(e))goto done;text=(*e)->GetStringUTFChars(e,deny,NULL);if(!text||strlen(text)>65536||!callback)goto done;rules=strdup(text);if(!rules)goto done;protector=(*e)->NewGlobalRef(e,callback);jclass c=(*e)->GetObjectClass(e,callback);protect_method=(*e)->GetMethodID(e,c,"protectDescriptor","(I)Z");(*e)->DeleteLocalRef(e,c);if(!protector||!protect_method||(*e)->ExceptionCheck(e))goto done;protect_stop=0;request_fd=-1;request_result=0;if(pthread_create(&protect_thread,NULL,protect_worker,NULL)!=0)goto done;protect_started=1;owned=dup(fd);if(owned<0)goto done;result=hev_socks5_tunnel_main_from_str(parameters,parameters_len,owned);
 done:if(owned>=0)close(owned);if(protect_started){pthread_mutex_lock(&protect_lock);protect_stop=1;pthread_cond_broadcast(&protect_cond);pthread_mutex_unlock(&protect_lock);pthread_join(protect_thread,NULL);protect_started=0;}if(parameters){volatile unsigned char *wipe=parameters;for(jsize i=0;i<parameters_len;i++)wipe[i]=0;free(parameters);}if(text)(*e)->ReleaseStringUTFChars(e,deny,text);if(protector)(*e)->DeleteGlobalRef(e,protector);protector=NULL;protect_method=NULL;if(rules){memset(rules,0,strlen(rules));free(rules);rules=NULL;}pthread_mutex_lock(&lock);running=0;pthread_mutex_unlock(&lock);return result;}
JNIEXPORT void JNICALL Java_org_aegis_android_NativeTun_quit(JNIEnv *e,jclass cls){(void)e;(void)cls;hev_socks5_tunnel_quit();}
