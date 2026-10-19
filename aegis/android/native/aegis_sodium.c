/* Thin JNI binding only. Algorithms implemented by official libsodium 1.0.22. */
#include <jni.h>
#include <sodium.h>
#include <stdint.h>
static void fail(JNIEnv *e,const char *message){jclass c=(*e)->FindClass(e,"java/security/GeneralSecurityException");if(c)(*e)->ThrowNew(e,c,message);}
static int read_exact(JNIEnv *e,jbyteArray a,unsigned char *out,jsize n){if(!a||(*e)->GetArrayLength(e,a)!=n){fail(e,"Invalid native crypto input length");return 0;}(*e)->GetByteArrayRegion(e,a,0,n,(jbyte*)out);return !(*e)->ExceptionCheck(e);}
static jbyteArray result(JNIEnv *e,const unsigned char *b,jsize n){jbyteArray a=(*e)->NewByteArray(e,n);if(a)(*e)->SetByteArrayRegion(e,a,0,n,(const jbyte*)b);return a;}
JNIEXPORT jint JNICALL Java_org_securemail_client_crypto_SodiumBox_initialize(JNIEnv *e,jclass c){(void)e;(void)c;return sodium_init();}
JNIEXPORT jbyteArray JNICALL Java_org_securemail_client_crypto_SodiumBox_nativeSeal(JNIEnv *e,jclass c,jbyteArray key,jbyteArray pub){
 (void)c;unsigned char k[32]={0},ed[32]={0},x[32]={0},out[80]={0};jbyteArray r=NULL;
 if(!read_exact(e,key,k,32)||!read_exact(e,pub,ed,32))goto done;
 if(crypto_sign_ed25519_pk_to_curve25519(x,ed)!=0||crypto_box_seal(out,k,32,x)!=0){fail(e,"Sealed message key failed");goto done;}r=result(e,out,80);
 done:sodium_memzero(k,sizeof k);sodium_memzero(ed,sizeof ed);sodium_memzero(x,sizeof x);sodium_memzero(out,sizeof out);return r;
}
JNIEXPORT jbyteArray JNICALL Java_org_securemail_client_crypto_SodiumBox_nativeOpen(JNIEnv *e,jclass c,jbyteArray sealed,jbyteArray pub,jbyteArray seed){
 (void)c;unsigned char box[80]={0},edpub[32]={0},s[32]={0},derived[32]={0},edsecret[64]={0},xp[32]={0},xs[32]={0},out[32]={0};jbyteArray r=NULL;
 if(!read_exact(e,sealed,box,80)||!read_exact(e,pub,edpub,32)||!read_exact(e,seed,s,32))goto done;
 if(crypto_sign_seed_keypair(derived,edsecret,s)!=0||sodium_memcmp(derived,edpub,32)!=0||crypto_sign_ed25519_pk_to_curve25519(xp,edpub)!=0||crypto_sign_ed25519_sk_to_curve25519(xs,edsecret)!=0||crypto_box_seal_open(out,box,80,xp,xs)!=0){fail(e,"Cannot open authenticated message key");goto done;}r=result(e,out,32);
 done:sodium_memzero(box,sizeof box);sodium_memzero(edpub,sizeof edpub);sodium_memzero(s,sizeof s);sodium_memzero(derived,sizeof derived);sodium_memzero(edsecret,sizeof edsecret);sodium_memzero(xp,sizeof xp);sodium_memzero(xs,sizeof xs);sodium_memzero(out,sizeof out);return r;
}
