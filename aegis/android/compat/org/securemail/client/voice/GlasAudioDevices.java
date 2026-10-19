package org.securemail.client.voice;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.media.*;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;

/** Bounded Android device adapter; no audio file, socket, background capture or shared UID. */
final class GlasAudioDevices {
    private static volatile Context context;
    private static final int FRAME_BYTES=1920,MAX_BUFFER=38400;
    static void initialize(Context value){if(!"org.aegis.glas".equals(value.getPackageName()))throw new SecurityException("Аудио разрешено только Гласу");context=value.getApplicationContext();}
    private static AudioManager manager()throws IOException {Context c=context;if(c==null)throw new IOException("Аудиоконтекст не подготовлен");return (AudioManager)c.getSystemService(Context.AUDIO_SERVICE);}
    private static AudioDeviceInfo device(String id,boolean input)throws IOException {
        if(id==null||id.isEmpty())return null;
        if(!id.matches("[1-9][0-9]{0,9}"))throw new IOException("Неверный идентификатор аудиоустройства");
        for(AudioDeviceInfo d:manager().getDevices(input?AudioManager.GET_DEVICES_INPUTS:AudioManager.GET_DEVICES_OUTPUTS))if(Integer.toString(d.getId()).equals(id))return d;
        throw new IOException("Выбранное аудиоустройство отключено");
    }
    static List<GlasAudioSession.Device> devices(boolean input){
        List<GlasAudioSession.Device> result=new ArrayList<>();
        try{for(AudioDeviceInfo d:manager().getDevices(input?AudioManager.GET_DEVICES_INPUTS:AudioManager.GET_DEVICES_OUTPUTS)){
            if(result.size()==128)break;String label=String.valueOf(d.getProductName());if(label.length()>128)label=label.substring(0,128);
            result.add(new GlasAudioSession.Device(Integer.toString(d.getId()),label,input));
        }}catch(IOException|SecurityException ignored){/* No device is invented when permission/device access is unavailable. */}
        return Collections.unmodifiableList(result);
    }
    interface Input extends AutoCloseable {int read(byte[] pcm,int offset,int length)throws IOException;void close();}
    interface Output extends AutoCloseable {int write(byte[] pcm,int offset,int length)throws IOException;void close();}
    interface Provider {Input input(String id)throws IOException;Output output(String id)throws IOException;}
    private static void bounds(byte[] pcm,int offset,int length){if(pcm==null||offset<0||length<=0||length>FRAME_BYTES||offset>pcm.length-length||(length&1)!=0)throw new IllegalArgumentException("PCM bounds");}
    static final Provider SYSTEM=new Provider(){
        public Input input(String id)throws IOException {
            Context c=context;if(c==null||c.checkSelfPermission(Manifest.permission.RECORD_AUDIO)!=PackageManager.PERMISSION_GRANTED)throw new IOException("Доступ к микрофону не предоставлен");
            int min=AudioRecord.getMinBufferSize(48000,AudioFormat.CHANNEL_IN_MONO,AudioFormat.ENCODING_PCM_16BIT);
            if(min<=0||min>MAX_BUFFER)throw new IOException("Неподдерживаемый аудиобуфер микрофона");
            AudioRecord record=null;
            try{
                AudioDeviceInfo preferred=device(id,true);
                record=new AudioRecord.Builder().setAudioSource(MediaRecorder.AudioSource.VOICE_RECOGNITION).setAudioFormat(new AudioFormat.Builder().setSampleRate(48000).setChannelMask(AudioFormat.CHANNEL_IN_MONO).setEncoding(AudioFormat.ENCODING_PCM_16BIT).build()).setBufferSizeInBytes(Math.max(min,FRAME_BYTES*4)).build();
                if(record.getState()!=AudioRecord.STATE_INITIALIZED||(preferred!=null&&!record.setPreferredDevice(preferred)))throw new IOException("Не удалось выбрать микрофон");
                record.startRecording();if(record.getRecordingState()!=AudioRecord.RECORDSTATE_RECORDING)throw new IOException("Микрофон не запустился");
                AudioRecord owned=record;AtomicBoolean closed=new AtomicBoolean();
                return new Input(){
                    public int read(byte[] pcm,int offset,int length)throws IOException {bounds(pcm,offset,length);long end=System.nanoTime()+250_000_000L;while(!closed.get()){
                        int n=owned.read(pcm,offset,length,AudioRecord.READ_NON_BLOCKING);if(n>0)return n;if(n<0)throw new IOException("Микрофон отключён или недоступен");if(System.nanoTime()>=end)throw new IOException("Микрофон не передаёт звук");LockSupport.parkNanos(2_000_000L);
                    }throw new IOException("Микрофон закрыт");}
                    public void close(){if(closed.compareAndSet(false,true)){try{owned.stop();}catch(IllegalStateException ignored){}finally{owned.release();}}}
                };
            }catch(IllegalArgumentException|IllegalStateException|SecurityException e){if(record!=null)record.release();throw new IOException("Микрофон недоступен",e);}catch(IOException e){if(record!=null)record.release();throw e;}
        }
        public Output output(String id)throws IOException {
            int min=AudioTrack.getMinBufferSize(48000,AudioFormat.CHANNEL_OUT_MONO,AudioFormat.ENCODING_PCM_16BIT);
            if(min<=0||min>MAX_BUFFER)throw new IOException("Неподдерживаемый аудиобуфер вывода");
            AudioTrack track=null;
            try{
                AudioDeviceInfo preferred=device(id,false);
                track=new AudioTrack.Builder().setAudioAttributes(new AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION).setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build()).setAudioFormat(new AudioFormat.Builder().setSampleRate(48000).setChannelMask(AudioFormat.CHANNEL_OUT_MONO).setEncoding(AudioFormat.ENCODING_PCM_16BIT).build()).setTransferMode(AudioTrack.MODE_STREAM).setBufferSizeInBytes(Math.max(min,FRAME_BYTES*4)).build();
                if(track.getState()!=AudioTrack.STATE_INITIALIZED||(preferred!=null&&!track.setPreferredDevice(preferred)))throw new IOException("Не удалось выбрать устройство вывода");
                track.play();AudioTrack owned=track;AtomicBoolean closed=new AtomicBoolean();
                return new Output(){
                    public int write(byte[] pcm,int offset,int length)throws IOException {bounds(pcm,offset,length);long end=System.nanoTime()+250_000_000L;while(!closed.get()){
                        int n=owned.write(pcm,offset,length,AudioTrack.WRITE_NON_BLOCKING);if(n>0)return n;if(n<0)throw new IOException("Устройство вывода отключено");if(System.nanoTime()>=end)throw new IOException("Устройство вывода не принимает звук");LockSupport.parkNanos(2_000_000L);
                    }throw new IOException("Воспроизведение закрыто");}
                    public void close(){if(closed.compareAndSet(false,true)){try{owned.pause();owned.flush();owned.stop();}catch(IllegalStateException ignored){}finally{owned.release();}}}
                };
            }catch(IllegalArgumentException|IllegalStateException|SecurityException e){if(track!=null)track.release();throw new IOException("Воспроизведение недоступно",e);}catch(IOException e){if(track!=null)track.release();throw e;}
        }
    };
}
