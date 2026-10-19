#include <jni.h>
#include <opus/opus.h>
#include <speex/speex_echo.h>
#include <speex/speex_preprocess.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* No raw pointer is accepted from Java: bounded generation-stamped handle table. */
#define SAMPLES 960
#define RATE 48000
#define MAX_PACKET 1275
#define MAX_CONTEXTS 4
typedef struct {uint64_t id;OpusEncoder*encoder;OpusDecoder*decoder;SpeexEchoState*echo;SpeexPreprocessState*pre;int echo_started;} Audio;
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static Audio contexts[MAX_CONTEXTS];
static uint64_t next_id=1;
static void wipe(void*p,size_t n){volatile unsigned char*x=p;while(n--)*x++=0;}
static void error(JNIEnv*e,const char*s){jclass c=(*e)->FindClass(e,"java/io/IOException");if(c)(*e)->ThrowNew(e,c,s);}
static Audio*get(JNIEnv*e,jlong id){for(int i=0;i<MAX_CONTEXTS;i++)if(contexts[i].id!=0&&contexts[i].id==(uint64_t)id)return &contexts[i];error(e,"Аудиосессия закрыта");return NULL;}
static void release(Audio*a){
 if(a->encoder){wipe(a->encoder,(size_t)opus_encoder_get_size(1));opus_encoder_destroy(a->encoder);}
 if(a->decoder){wipe(a->decoder,(size_t)opus_decoder_get_size(1));opus_decoder_destroy(a->decoder);}
 if(a->pre)speex_preprocess_state_destroy(a->pre);
 if(a->echo)speex_echo_state_destroy(a->echo);
 wipe(a,sizeof(*a));
}
static int processing(Audio*a,int echo,int noise){
 int n=noise?1:0,agc=0,suppress=-20,rate=RATE;
 if(speex_preprocess_ctl(a->pre,SPEEX_PREPROCESS_SET_DENOISE,&n)||speex_preprocess_ctl(a->pre,SPEEX_PREPROCESS_SET_AGC,&agc)||speex_preprocess_ctl(a->pre,SPEEX_PREPROCESS_SET_NOISE_SUPPRESS,&suppress))return 0;
 if(echo&&!a->echo){
  SpeexEchoState*next=speex_echo_state_init(SAMPLES,RATE/5);if(!next)return 0;
  if(speex_echo_ctl(next,SPEEX_ECHO_SET_SAMPLING_RATE,&rate)||speex_preprocess_ctl(a->pre,SPEEX_PREPROCESS_SET_ECHO_STATE,next)){speex_echo_state_destroy(next);return 0;}
  a->echo=next;a->echo_started=0;
 }else if(!echo&&a->echo){
  if(speex_preprocess_ctl(a->pre,SPEEX_PREPROCESS_SET_ECHO_STATE,NULL))return 0;
  speex_echo_state_destroy(a->echo);a->echo=NULL;a->echo_started=0;
 }
 return 1;
}
JNIEXPORT jlong JNICALL Java_org_securemail_client_voice_GlasNativeAudio_create(JNIEnv*e,jclass c,jboolean echo,jboolean noise){
 (void)c;pthread_mutex_lock(&mutex);Audio*a=NULL;int code=0;
 for(int i=0;i<MAX_CONTEXTS;i++)if(!contexts[i].id){a=&contexts[i];break;}
 if(!a||next_id==0||strcmp(opus_get_version_string(),"libopus 1.6.1")){error(e,"Лимит или версия аудиокодека");pthread_mutex_unlock(&mutex);return 0;}
 a->encoder=opus_encoder_create(RATE,1,OPUS_APPLICATION_VOIP,&code);
 if(!a->encoder||code)goto fail;
 a->decoder=opus_decoder_create(RATE,1,&code);if(!a->decoder||code)goto fail;
 if(opus_encoder_ctl(a->encoder,OPUS_SET_BITRATE(24000))||opus_encoder_ctl(a->encoder,OPUS_SET_VBR(1))||opus_encoder_ctl(a->encoder,OPUS_SET_COMPLEXITY(5))||opus_encoder_ctl(a->encoder,OPUS_SET_DTX(1))||opus_encoder_ctl(a->encoder,OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE)))goto fail;
 a->pre=speex_preprocess_state_init(SAMPLES,RATE);if(!a->pre||!processing(a,echo,noise))goto fail;
 a->id=next_id++;jlong result=(jlong)a->id;pthread_mutex_unlock(&mutex);return result;
 fail:release(a);error(e,"Не удалось создать обработку звука");pthread_mutex_unlock(&mutex);return 0;
}
JNIEXPORT void JNICALL Java_org_securemail_client_voice_GlasNativeAudio_destroy(JNIEnv*e,jclass c,jlong id){
 (void)e;(void)c;pthread_mutex_lock(&mutex);for(int i=0;i<MAX_CONTEXTS;i++)if(contexts[i].id&&(uint64_t)id==contexts[i].id){release(&contexts[i]);break;}pthread_mutex_unlock(&mutex);
}
JNIEXPORT void JNICALL Java_org_securemail_client_voice_GlasNativeAudio_setBitrate(JNIEnv*e,jclass c,jlong id,jint rate){
 (void)c;pthread_mutex_lock(&mutex);Audio*a=get(e,id);if(a&&(rate<12000||rate>32000||opus_encoder_ctl(a->encoder,OPUS_SET_BITRATE(rate))))error(e,"Неверный битрейт");pthread_mutex_unlock(&mutex);
}
static int read_pcm(JNIEnv*e,jshortArray src,short*pcm){if(!src||(*e)->GetArrayLength(e,src)!=SAMPLES){error(e,"Неверный аудиобуфер");return 0;}(*e)->GetShortArrayRegion(e,src,0,SAMPLES,pcm);return !(*e)->ExceptionCheck(e);}
JNIEXPORT jbyteArray JNICALL Java_org_securemail_client_voice_GlasNativeAudio_encodeFrame(JNIEnv*e,jclass c,jlong id,jshortArray src){
 (void)c;short pcm[SAMPLES]={0};unsigned char packet[MAX_PACKET]={0};jbyteArray result=NULL;pthread_mutex_lock(&mutex);Audio*a=get(e,id);
 if(a&&read_pcm(e,src,pcm)){int n=opus_encode(a->encoder,pcm,SAMPLES,packet,MAX_PACKET);if(n<=0||n>MAX_PACKET)error(e,"Ошибка кодирования звука");else{result=(*e)->NewByteArray(e,n);if(result)(*e)->SetByteArrayRegion(e,result,0,n,(jbyte*)packet);}}
 wipe(pcm,sizeof(pcm));wipe(packet,sizeof(packet));pthread_mutex_unlock(&mutex);return result;
}
JNIEXPORT jshortArray JNICALL Java_org_securemail_client_voice_GlasNativeAudio_decodeFrame(JNIEnv*e,jclass c,jlong id,jbyteArray src){
 (void)c;short pcm[SAMPLES]={0};unsigned char packet[MAX_PACKET]={0};jshortArray result=NULL;pthread_mutex_lock(&mutex);Audio*a=get(e,id);int n=src?(*e)->GetArrayLength(e,src):0;
 if(a){if(src&&(n<=0||n>MAX_PACKET))error(e,"Неверный аудиокадр");else{
  if(src)(*e)->GetByteArrayRegion(e,src,0,n,(jbyte*)packet);
  if(!(*e)->ExceptionCheck(e)){
   if(src&&(opus_packet_get_nb_samples(packet,n,RATE)!=SAMPLES||opus_packet_get_nb_channels(packet)!=1))error(e,"Неверные параметры Opus");
   else if(opus_decode(a->decoder,src?packet:NULL,n,pcm,SAMPLES,0)!=SAMPLES)error(e,"Ошибка декодирования звука");
   else{result=(*e)->NewShortArray(e,SAMPLES);if(result)(*e)->SetShortArrayRegion(e,result,0,SAMPLES,pcm);}
  }
 }}wipe(pcm,sizeof(pcm));wipe(packet,sizeof(packet));pthread_mutex_unlock(&mutex);return result;
}
JNIEXPORT void JNICALL Java_org_securemail_client_voice_GlasNativeAudio_processFrame(JNIEnv*e,jclass c,jlong id,jshortArray src){
 (void)c;short pcm[SAMPLES]={0},clean[SAMPLES]={0};pthread_mutex_lock(&mutex);Audio*a=get(e,id);
 if(a&&read_pcm(e,src,pcm)){if(a->echo){speex_echo_capture(a->echo,pcm,clean);memcpy(pcm,clean,sizeof(pcm));a->echo_started=1;}speex_preprocess_run(a->pre,pcm);(*e)->SetShortArrayRegion(e,src,0,SAMPLES,pcm);}
 wipe(pcm,sizeof(pcm));wipe(clean,sizeof(clean));pthread_mutex_unlock(&mutex);
}
JNIEXPORT void JNICALL Java_org_securemail_client_voice_GlasNativeAudio_playedFrame(JNIEnv*e,jclass c,jlong id,jshortArray src){
 (void)c;short pcm[SAMPLES]={0};pthread_mutex_lock(&mutex);Audio*a=get(e,id);if(a&&read_pcm(e,src,pcm)&&a->echo&&a->echo_started)speex_echo_playback(a->echo,pcm);wipe(pcm,sizeof(pcm));pthread_mutex_unlock(&mutex);
}
JNIEXPORT void JNICALL Java_org_securemail_client_voice_GlasNativeAudio_setProcessing(JNIEnv*e,jclass c,jlong id,jboolean echo,jboolean noise){
 (void)c;pthread_mutex_lock(&mutex);Audio*a=get(e,id);if(a&&!processing(a,echo,noise))error(e,"Ошибка настройки обработки звука");pthread_mutex_unlock(&mutex);
}
JNIEXPORT void JNICALL Java_org_securemail_client_voice_GlasNativeAudio_reset(JNIEnv*e,jclass c,jlong id){
 (void)c;pthread_mutex_lock(&mutex);Audio*a=get(e,id);if(a&&a->echo){speex_echo_state_reset(a->echo);a->echo_started=0;}pthread_mutex_unlock(&mutex);
}
