package org.securemail.client.security;

import com.google.gson.GsonBuilder;
import java.io.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.*;
import org.securemail.client.voice.GlasAudioSession;

/** Owner-invoked local diagnostics only, excluded from the production JAR.
 * Default execution does not open audio lines, profiles or network sockets.
 */
public final class VoiceNativeAcceptanceMain {
  @FunctionalInterface private interface Check {Object run()throws Exception;}
  private final Map<String,Object> report=new LinkedHashMap<>();
  private final List<Map<String,Object>> checks=new ArrayList<>();
  private boolean localChecksPassed=true;
  private static String safe(String value){if(value==null)return "unknown";String clean=value.replaceAll("[\\p{Cntrl}]","");return clean.length()>256?clean.substring(0,256):clean;}
  private void check(String name,Check action){
    Map<String,Object> result=new LinkedHashMap<>();result.put("name",name);long begin=System.nanoTime();
    try{result.put("evidence",action.run());result.put("result","PASS");}
    catch(Exception|LinkageError failure){Throwable detail=failure;while(detail instanceof InvocationTargetException reflected&&reflected.getCause()!=null)detail=reflected.getCause();result.put("result","FAIL_OR_UNAVAILABLE");result.put("technicalErrorType",detail.getClass().getSimpleName());localChecksPassed=false;}
    result.put("elapsedMillis",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-begin));checks.add(result);System.out.println(result.get("result")+" "+name);
  }
  private static Method accessible(Class<?> type,String name,Class<?>...parameters)throws NoSuchMethodException {Method method=type.getDeclaredMethod(name,parameters);method.setAccessible(true);return method;}
  private static Object codecFixture()throws Exception {
    // Test-only access uses exactly the production verified loader and codec.
    // No public runtime switch or alternate library source is added.
    Class<?> type=Class.forName("org.securemail.client.voice.GlasNativeAudio");Constructor<?> constructor=type.getDeclaredConstructor(boolean.class,boolean.class);constructor.setAccessible(true);Object codec=constructor.newInstance(false,true);
    short[] pcm=new short[960],decoded=null;byte[] packet=null;int encodedBytes=0;
    try{
      Method process=accessible(type,"process",short[].class),encode=accessible(type,"encode",short[].class),decode=accessible(type,"decode",byte[].class);
      for(int frame=0;frame<16;frame++){
        for(int sample=0;sample<pcm.length;sample++)pcm[sample]=(short)Math.round(6000*Math.sin(2*Math.PI*440*(frame*960+sample)/48000.0));
        process.invoke(codec,(Object)pcm);packet=(byte[])encode.invoke(codec,(Object)pcm);if(packet.length<1||packet.length>1275)throw new IOException("Codec packet bounds");encodedBytes+=packet.length;
        decoded=(short[])decode.invoke(codec,(Object)packet);if(decoded.length!=960)throw new IOException("Codec frame bounds");Arrays.fill(packet,(byte)0);packet=null;Arrays.fill(decoded,(short)0);decoded=null;
      }
      return Map.of("syntheticFrames",16,"sampleRate",48000,"channels",1,"frameMillis",20,"encodedBytes",encodedBytes,"physicalAudioOpened",false,"acousticEchoQuality","NOT_RUN");
    }finally{Arrays.fill(pcm,(short)0);if(packet!=null)Arrays.fill(packet,(byte)0);if(decoded!=null)Arrays.fill(decoded,(short)0);accessible(type,"close").invoke(codec);}
  }
  private static Object pins(Path app)throws Exception {
    String arch=System.getProperty("os.arch","").toLowerCase(Locale.ROOT);if(!Set.of("amd64","x86_64").contains(arch))throw new IOException("Unsupported architecture");boolean windows=System.getProperty("os.name","").startsWith("Windows");String platform=windows?"windows-x86_64":"linux-x86_64";if(!windows&&!System.getProperty("os.name","").equals("Linux"))throw new IOException("Unsupported OS");
    Class<?> loader=Class.forName("org.securemail.client.voice.GlasAudioLibraries");Method verified=accessible(loader,"verified",Path.class,String.class,String.class);var hashes=new LinkedHashMap<String,String>();
    for(String filename:windows?List.of("opus.dll","speexdsp.dll"):List.of("libopus.so","libspeexdsp.so")){
      byte[] bytes=(byte[])verified.invoke(null,app.resolve("native").resolve(filename),filename,platform);try{hashes.put(filename,HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));}finally{Arrays.fill(bytes,(byte)0);}
    }
    return Map.of("compiledRegistryVerified",true,"platform",platform,"sha256",hashes);
  }
  private static Object devices(){
    var input=GlasAudioSession.inputDevices();var output=GlasAudioSession.outputDevices();List<Map<String,String>> values=new ArrayList<>();
    for(var device:input)values.add(Map.of("id",safe(device.id()),"name",safe(device.name()),"direction","input"));
    for(var device:output)values.add(Map.of("id",safe(device.id()),"name",safe(device.name()),"direction","output"));
    return Map.of("inputs",input.size(),"outputs",output.size(),"devices",values,"captureOpened",false,"playbackOpened",false,"note","Enumeration success does not prove a physical device works");
  }
  private static Object microphone(String deviceId)throws Exception {
    AtomicLong levels=new AtomicLong(),peakBits=new AtomicLong(Double.doubleToLongBits(0));long begin=System.nanoTime();
    try(var test=GlasAudioSession.testMicrophone(deviceId,level->{levels.incrementAndGet();peakBits.accumulateAndGet(Double.doubleToLongBits(level),(previous,next)->Double.longBitsToDouble(next)>Double.longBitsToDouble(previous)?next:previous);})){
      long deadline=begin+TimeUnit.SECONDS.toNanos(16);while(test.running()&&System.nanoTime()<deadline)Thread.sleep(50);
    }
    if(levels.get()==0)throw new IOException("No local microphone levels");
    return Map.of("levelSamples",levels.get(),"peakLevel",Double.longBitsToDouble(peakBits.get()),"elapsedMillis",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-begin),"audioRecorded",false,"audioTransmitted",false,"playbackOpened",false,"osMicrophoneIndicatorClosure","NOT_RUN");
  }
  private void run(Path app,boolean testMicrophone,String deviceId){
    report.put("schemaVersion",1);report.put("applicationVersion","2.5.0");report.put("recordedAtUtc",Instant.now().toString());
    report.put("osName",safe(System.getProperty("os.name")));report.put("osVersion",safe(System.getProperty("os.version")));report.put("architecture",safe(System.getProperty("os.arch")));report.put("javaVersion",safe(System.getProperty("java.version")));
    String session=System.getenv("XDG_SESSION_TYPE");report.put("sessionType",Set.of("x11","wayland").contains(Objects.toString(session,""))?session:System.getProperty("os.name","").startsWith("Windows")?"windows":"unknown");
    if(Files.isRegularFile(Path.of("/etc/os-release")))try{
      byte[] bytes;try(var input=Files.newInputStream(Path.of("/etc/os-release"))){bytes=input.readNBytes(16385);}if(bytes.length<=16384){Map<String,String> distribution=new LinkedHashMap<>();for(String line:new String(bytes,java.nio.charset.StandardCharsets.UTF_8).split("\\R")){int at=line.indexOf('=');if(at>0&&Set.of("ID","NAME","VERSION_ID").contains(line.substring(0,at)))distribution.put(line.substring(0,at),safe(line.substring(at+1).replace("\"","")));}report.put("linuxDistribution",distribution);}
    }catch(IOException ignored){report.put("linuxDistribution","UNAVAILABLE");}
    check("compiled_audio_pins",()->pins(app));check("audio_device_enumeration",VoiceNativeAcceptanceMain::devices);check("synthetic_native_Opus_Speex_fixture",VoiceNativeAcceptanceMain::codecFixture);
    if(testMicrophone){System.out.println("Explicit local microphone level test, up to 15 seconds. No recording, playback or transmission.");check("explicit_microphone_level_sample",()->microphone(deviceId));}else report.put("physicalMicrophoneCapture","NOT_RUN");
    report.put("checks",checks);report.put("allRequestedLocalChecksPassed",localChecksPassed);report.put("nativeVoiceAcceptance","NOT_RUN");report.put("twoPhysicalMachinesOnDifferentNetworks","NOT_RUN");report.put("sixtyMinuteOnionCall","NOT_RUN");report.put("physicalPlaybackAndSpeechQuality","NOT_RUN");report.put("productionReady",false);report.put("networkConnectionsInitiated",false);report.put("productionProfilesRead",false);report.put("audioFilesWritten",false);report.put("secretsOrConversationContentIncluded",false);report.put("hardwareDeviceNamesIncluded",true);
  }
  public static void main(String[] args)throws Exception {
    if(args.length<1)throw new IllegalArgumentException("Usage: VoiceNativeAcceptanceMain APP_DIRECTORY [--test-microphone] [--microphone-id DEVICE_ID] [--output REPORT.json]");
    Path app=Path.of(args[0]).toAbsolutePath().normalize(),output=Path.of("AEGIS-voice-local-"+System.currentTimeMillis()+".json").toAbsolutePath();boolean microphone=false;String device="";
    for(int index=1;index<args.length;index++)switch(args[index]){case "--test-microphone"->{if(microphone)throw new IllegalArgumentException("Duplicate microphone flag");microphone=true;}case "--microphone-id"->{if(++index==args.length)throw new IllegalArgumentException("Missing device ID");device=args[index];}case "--output"->{if(++index==args.length)throw new IllegalArgumentException("Missing report path");output=Path.of(args[index]).toAbsolutePath().normalize();}default->throw new IllegalArgumentException("Unknown argument");}
    if(!microphone&&!device.isEmpty())throw new IllegalArgumentException("Device selection requires explicit --test-microphone");
    if(!Files.isDirectory(app.resolve("native"),LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("APP_DIRECTORY must contain native audio libraries");
    if(Files.exists(output,LinkOption.NOFOLLOW_LINKS))throw new IOException("Report already exists");
    boolean passed=false;Path temporary=Files.createTempDirectory("aegis-voice-local-");try{try{Files.setPosixFilePermissions(temporary,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));}catch(UnsupportedOperationException ignored){}
      System.setProperty("aegis.home",app.toString());System.setProperty("jna.tmpdir",temporary.toString());System.setProperty("java.io.tmpdir",temporary.toString());
      var runner=new VoiceNativeAcceptanceMain();runner.run(app,microphone,device);Files.writeString(output,new GsonBuilder().setPrettyPrinting().create().toJson(runner.report)+"\n",StandardOpenOption.CREATE_NEW);System.out.println("Local report written. Native voice acceptance remains NOT_RUN.");passed=runner.localChecksPassed;
    }finally{try(var paths=Files.walk(temporary)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())try{Files.deleteIfExists(path);}catch(IOException ignored){}}}
    if(!passed)System.exit(1);
  }
}
