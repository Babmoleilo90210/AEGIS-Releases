/* Host-only socketpair fixture. This file is never compiled into Android APKs. */
#include <jni.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
JNIEXPORT jintArray JNICALL Java_org_aegis_android_TunEngineHostTest_pair(JNIEnv *e,jclass c){(void)c;int fds[2];if(socketpair(AF_UNIX,SOCK_DGRAM,0,fds))return NULL;jintArray r=(*e)->NewIntArray(e,2);if(r)(*e)->SetIntArrayRegion(e,r,0,2,fds);return r;}
JNIEXPORT void JNICALL Java_org_aegis_android_TunEngineHostTest_write(JNIEnv *e,jclass c,jint fd,jbyteArray a){(void)c;jsize n=(*e)->GetArrayLength(e,a);if(n<1||n>4096)return;char b[4096];(*e)->GetByteArrayRegion(e,a,0,n,(jbyte*)b);send(fd,b,n,MSG_NOSIGNAL);}
JNIEXPORT jbyteArray JNICALL Java_org_aegis_android_TunEngineHostTest_read(JNIEnv *e,jclass c,jint fd,jint wait){(void)c;struct pollfd p={.fd=fd,.events=POLLIN};if(poll(&p,1,wait)<=0)return NULL;char b[4096];ssize_t n=recv(fd,b,sizeof b,0);if(n<1)return NULL;jbyteArray a=(*e)->NewByteArray(e,n);if(a)(*e)->SetByteArrayRegion(e,a,0,n,(jbyte*)b);return a;}
JNIEXPORT void JNICALL Java_org_aegis_android_TunEngineHostTest_closeFd(JNIEnv *e,jclass c,jint fd){(void)e;(void)c;close(fd);}
