package org.securemail.client.update;

import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import org.securemail.client.storage.AtomicFiles;

/** Local updater events. This type is never accepted by the Relay/mail wire decoder. */
public final class UpdateEvents {
  public enum Kind { AVAILABLE, DOWNLOADED, VERIFIED, INSTALLED, RESTARTED, FAILED, ROLLBACK }
  public record Event(String id,String version,String channel,Kind kind,Instant time,String code,SignedManifest release) {
    public boolean systemLetter(){return release!=null&&(kind==Kind.AVAILABLE||kind==Kind.INSTALLED);}
    public String title(){return switch(kind){case AVAILABLE->"Доступна АЕГИС "+version;case INSTALLED->"Установлена АЕГИС "+version;default->kind+" · "+version;};}
  }
  private final Path updates,root;private final UpdateService.Verifier verifier;
  UpdateEvents(Path updates,UpdateService.Verifier verifier)throws IOException{this.updates=updates;this.root=updates.resolve("events");this.verifier=verifier;AtomicFiles.directory(root);}
  static String id(String version,String channel,Kind kind){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest((version+"|"+channel+"|"+kind).getBytes(StandardCharsets.US_ASCII)));}catch(GeneralSecurityException e){throw new IllegalStateException(e);}}
  synchronized void record(SignedManifest manifest,Kind kind,String channel,String code)throws IOException {
    String version=manifest==null?"0.0.0":manifest.version();SemVersion.parse(version);
    if(!Set.of("stable","beta").contains(channel)||code==null||!code.matches("[A-Z0-9_]{0,64}"))throw new IOException("Invalid update event");
    if(manifest==null&&kind!=Kind.FAILED)throw new IOException("Unauthenticated update event");
    String identity=id(version,channel,kind);Path target=root.resolve(identity+".json");if(Files.exists(target,LinkOption.NOFOLLOW_LINKS))return;
    try(var files=Files.list(root)){if(files.limit(1025).count()>=1024)throw new IOException("Update history limit");}
    JsonObject o=new JsonObject();o.addProperty("schema",1);o.addProperty("id",identity);o.addProperty("version",version);o.addProperty("channel",channel);o.addProperty("kind",kind.name());o.addProperty("time",Instant.now().toString());o.addProperty("code",code);AtomicFiles.write(target,JsonData.encode(o));
  }
  synchronized void migrateLegacy()throws IOException {
    for(String channel:List.of("stable","beta")){Path floor=updates.resolve(channel+".floor");if(!Files.isRegularFile(floor,LinkOption.NOFOLLOW_LINKS))continue;
      try{SemVersion highest=SemVersion.parse(new String(AtomicFiles.read(floor,100),StandardCharsets.US_ASCII).trim());try(var files=Files.newDirectoryStream(updates,channel+"-*.json")){int n=0;for(Path path:files){if(++n>256)break;try{String name=path.getFileName().toString();SignedManifest m=verifier.verify(AtomicFiles.read(path,SignedManifest.MAX_BYTES),AtomicFiles.read(updates.resolve(name.substring(0,name.length()-5)+".sig"),64),channel,"0.0.0","0.0.0");if(m.announcement().showAsLetter()&&SemVersion.parse(m.version()).compareTo(highest)<=0)record(m,Kind.AVAILABLE,channel,"");}catch(IOException|GeneralSecurityException|RuntimeException invalid){}}}}
      catch(IOException|RuntimeException invalid){/* Preserve old metadata; an invalid floor is not a trusted event. */}
    }
  }
  /** A startup ACK alone is not an installation receipt: the helper must commit too. */
  synchronized void reconcile()throws IOException {
    try(var dirs=Files.newDirectoryStream(updates,"install-*")){int count=0;for(Path dir:dirs){if(++count>256)break;if(Files.isSymbolicLink(dir)||!Files.isDirectory(dir,LinkOption.NOFOLLOW_LINKS))continue;
      try {JsonObject job=JsonData.object(AtomicFiles.read(dir.resolve("job.json"),16384),16384);String channel=JsonData.text(job,"channel",8),version=JsonData.text(job,"version",100);
        SignedManifest m=verifier.verify(AtomicFiles.read(dir.resolve("manifest.json"),SignedManifest.MAX_BYTES),AtomicFiles.read(dir.resolve("manifest.sig"),64),channel,"0.0.0","0.0.0");if(!m.version().equals(version))continue;
        // Retain authenticated metadata independently of helper/package retention.
        Path json=updates.resolve(channel+"-"+version+".json"),sig=updates.resolve(channel+"-"+version+".sig");if(!Files.exists(json)){AtomicFiles.write(sig,AtomicFiles.read(dir.resolve("manifest.sig"),64));AtomicFiles.write(json,AtomicFiles.read(dir.resolve("manifest.json"),SignedManifest.MAX_BYTES));}
        if(committed(dir,job,m)){record(m,Kind.RESTARTED,channel,"");record(m,Kind.INSTALLED,channel,"");}
        if(Files.isRegularFile(dir.resolve("failed"),LinkOption.NOFOLLOW_LINKS))record(m,Kind.FAILED,channel,"INSTALL_FAILED");
        if(Files.isRegularFile(dir.resolve("rolled-back"),LinkOption.NOFOLLOW_LINKS))record(m,Kind.ROLLBACK,channel,"ROLLED_BACK");
      }catch(IOException|GeneralSecurityException|RuntimeException invalid){/* Invalid receipts cannot create trusted system letters. */}
    }}
  }
  private static boolean committed(Path dir,JsonObject job,SignedManifest m)throws IOException {
    if(!Files.isRegularFile(dir.resolve("installed"),LinkOption.NOFOLLOW_LINKS)||!Files.isRegularFile(dir.resolve("confirmed"),LinkOption.NOFOLLOW_LINKS)||Files.exists(dir.resolve("failed"))||Files.exists(dir.resolve("rolled-back")))return false;
    String token=JsonData.text(job,"token",36);return token.matches("[a-f0-9-]{36}")&&new String(AtomicFiles.read(dir.resolve("confirmed"),100),StandardCharsets.US_ASCII).trim().equals(token)&&new String(AtomicFiles.read(dir.resolve("installed"),100),StandardCharsets.US_ASCII).trim().equals(m.version());
  }
  public synchronized List<Event> history()throws IOException {
    reconcile();List<Event> events=new ArrayList<>();try(var files=Files.newDirectoryStream(root,"*.json")){int count=0;for(Path path:files){if(++count>1024)break;try{
      JsonObject o=JsonData.object(AtomicFiles.read(path,2048),2048);JsonData.fields(o,"schema","id","version","channel","kind","time","code");if(JsonData.number(o,"schema")!=1)continue;
      String version=JsonData.text(o,"version",100),channel=JsonData.text(o,"channel",8),identity=JsonData.text(o,"id",64),code=JsonData.text(o,"code",64);Kind kind=Kind.valueOf(JsonData.text(o,"kind",20));Instant time=Instant.parse(JsonData.text(o,"time",40));SemVersion.parse(version);
      if(!Set.of("stable","beta").contains(channel)||!identity.equals(id(version,channel,kind))||!path.getFileName().toString().equals(identity+".json")||!code.matches("[A-Z0-9_]{0,64}"))continue;
      SignedManifest m=null;if(!version.equals("0.0.0")){try{m=verifier.verify(AtomicFiles.read(updates.resolve(channel+"-"+version+".json"),SignedManifest.MAX_BYTES),AtomicFiles.read(updates.resolve(channel+"-"+version+".sig"),64),channel,"0.0.0","0.0.0");}catch(GeneralSecurityException invalid){continue;}if(!version.equals(m.version()))continue;}
      if(m==null&&kind!=Kind.FAILED)continue;
      if(kind==Kind.INSTALLED||kind==Kind.RESTARTED){boolean proof=false;try(var dirs=Files.newDirectoryStream(updates,"install-*")){int n=0;for(Path dir:dirs){if(++n>256)break;if(Files.isSymbolicLink(dir))continue;try{JsonObject job=JsonData.object(AtomicFiles.read(dir.resolve("job.json"),16384),16384);if(channel.equals(JsonData.text(job,"channel",8))&&version.equals(JsonData.text(job,"version",100))&&committed(dir,job,m)){proof=true;break;}}catch(IOException ignored){}}}if(!proof)continue;}
      events.add(new Event(identity,version,channel,kind,time,code,m));
    }catch(IOException|RuntimeException bad){/* Isolated malformed history does not block mailbox delivery. */}}}
    events.sort(Comparator.comparing(Event::time).reversed());return List.copyOf(events);
  }
}
