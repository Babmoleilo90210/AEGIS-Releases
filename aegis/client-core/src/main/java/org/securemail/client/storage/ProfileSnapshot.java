package org.securemail.client.storage;

import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.securemail.client.*;

/** Complete ciphertext/settings snapshot. Caller holds the app lock with vault and Tor closed. */
public final class ProfileSnapshot {
  private ProfileSnapshot(){}
  private static boolean updateMetadata(String name){return name.matches("(?:stable|beta)\\.floor|lastAnnouncementVersion-(?:stable|beta)|(?:stable|beta)-[A-Za-z0-9.-]{1,100}\\.(?:json|sig)");}
  private static Map<String,Path> sources(ClientConfig config)throws IOException{
    var result=new LinkedHashMap<String,Path>();
    result.put("vault",config.storagePath());result.put("client-config",AppPaths.config());
    Path profile=config.storagePath().toAbsolutePath().normalize();String prefix=profile.getFileName().toString();
    result.put("personal-archives/main",profile.resolveSibling(prefix+".personal-archive"));
    if(Files.isDirectory(profile.getParent()))try(var siblings=Files.list(profile.getParent())){
      for(Path p:siblings.toList())if(p.getFileName().toString().matches(java.util.regex.Pattern.quote(prefix)+"\\.archive-(?:restored|diagnostic)-[a-f0-9-]{36}"))result.put("personal-archives/"+p.getFileName(),p);
    }
    for(String name:List.of("ui-preferences.json","theme.txt","appearance","updates/events","mail-mode.txt","tor-mode.txt","update-preferences.json","session","glas600","tor/state","tor/transport-state"))
      result.put("app/"+name,AppPaths.root().resolve(name));
    // Persistent Core credentials/settings only: no live Tor cookie, cache, socket or runtime guard.
    for(String name:List.of("device.vault","navigation.json","notification-preferences.json","identity.properties","community.properties","library.properties","glas600.properties","relay600.properties","management.properties","attachments600.properties","tor-mode.txt","obsidian-control/linux-distribution.json"))
      result.put("app/core600/"+name,AppPaths.root().resolve("core600").resolve(name));
    for(String name:List.of("migration.properties","migration.mac"))
      result.put("app/mail600/migrated-profile6/"+name,AppPaths.root().resolve("mail600/migrated-profile6").resolve(name));
    Path updates=AppPaths.root().resolve("updates");
    if(Files.isSymbolicLink(updates))throw new IOException("Snapshot symlink rejected");
    if(Files.isDirectory(updates))try(var files=Files.list(updates)){
      for(Path file:files.toList())if(updateMetadata(file.getFileName().toString()))result.put("app/updates/"+file.getFileName(),file);
    }
    return result;
  }
  public static Path create(ClientConfig config,Path backups)throws IOException{return create(config,backups,true);}
  /** Mail migration owns only legacy Mail sources, never Core/Glas device credentials. */
  public static Path createMailMigration600(ClientConfig config,Path backups)throws IOException{return create(config,backups,false);}
  private static Path create(ClientConfig config,Path backups,boolean ecosystem)throws IOException{
    ClientUpgrade.recover(config.storagePath());AtomicFiles.directory(backups);
    Path snapshot=backups.resolve("pre-update-"+System.currentTimeMillis()+"-"+UUID.randomUUID());AtomicFiles.directory(snapshot);
    var inventory=new Properties();inventory.setProperty("schema","1");inventory.setProperty("storage",config.storagePath().toAbsolutePath().normalize().toString());
    try{
      for(var entry:sources(config).entrySet()){
        if(!ecosystem&&newState600(entry.getKey()))continue;
        Path source=entry.getValue().toAbsolutePath().normalize();
        if(snapshot.toAbsolutePath().normalize().startsWith(source))throw new IOException("Backup overlaps source");
        if(newState600(entry.getKey()))inventory.setProperty("managed/"+entry.getKey(),"true");
        if(!Files.exists(source,LinkOption.NOFOLLOW_LINKS))continue;
        copy(source,snapshot.resolve(entry.getKey()));inventory.setProperty("present/"+entry.getKey(),"true");
      }
      inventory.setProperty("sha256",treeDigest(snapshot));var data=new ByteArrayOutputStream();inventory.store(data,"AEGIS full profile snapshot; ciphertext only");
      AtomicFiles.write(snapshot.resolve("snapshot.properties"),data.toByteArray());AtomicFiles.syncDirectory(snapshot);return snapshot;
    }catch(IOException failure){
      // Keep an incomplete snapshot for diagnosis; it cannot be restored without its verified inventory.
      AtomicFiles.write(snapshot.resolve("incomplete"),new byte[]{1});throw failure;
    }
  }
  public static void verify(Path snapshot,ClientConfig config)throws IOException{
    if(Files.isSymbolicLink(snapshot)||!Files.isDirectory(snapshot,LinkOption.NOFOLLOW_LINKS)||Files.exists(snapshot.resolve("incomplete")))throw new IOException("Incomplete profile backup");
    var p=new Properties();try(var input=new ByteArrayInputStream(AtomicFiles.read(snapshot.resolve("snapshot.properties"),32768))){p.load(input);}
    if(!"1".equals(p.getProperty("schema"))||!config.storagePath().toAbsolutePath().normalize().toString().equals(p.getProperty("storage"))||!treeDigest(snapshot).equals(p.getProperty("sha256")))throw new IOException("Profile backup verification failed");
  }
  /** Previous failed state is preserved by rename; no existing identity is destroyed. */
  public static void restore(Path snapshot,ClientConfig config)throws IOException{
    verify(snapshot,config);var p=new Properties();try(var input=Files.newInputStream(snapshot.resolve("snapshot.properties"))){p.load(input);}
    var targets=sources(config);
    for(String key:p.stringPropertyNames())if(key.startsWith("present/app/updates/")){
      String name=key.substring("present/app/updates/".length());if(name.equals("events"))continue;if(!updateMetadata(name))throw new IOException("Invalid update metadata backup");targets.put("app/updates/"+name,AppPaths.root().resolve("updates").resolve(name));
    }
    String archivePrefix=config.storagePath().getFileName().toString();
    for(String key:p.stringPropertyNames())if(key.startsWith("present/personal-archives/")){
      String name=key.substring("present/personal-archives/".length());
      if(name.equals("main"))targets.put("personal-archives/main",config.storagePath().resolveSibling(archivePrefix+".personal-archive"));
      else if(name.matches(java.util.regex.Pattern.quote(archivePrefix)+"\\.archive-(?:restored|diagnostic)-[a-f0-9-]{36}"))targets.put("personal-archives/"+name,config.storagePath().resolveSibling(name));
      else throw new IOException("Invalid managed archive backup");
    }
    for(var target:targets.values()){Path parent=target.toAbsolutePath().normalize();while(parent!=null){if(Files.isSymbolicLink(parent))throw new IOException("Profile restore symlink rejected");parent=parent.getParent();}}
    for(var entry:targets.entrySet()){
      // A pre-6 snapshot never owned Core/Glas state; restoring it must not remove a newly paired identity.
      if((newState600(entry.getKey()))&&!p.containsKey("managed/"+entry.getKey())&&!p.containsKey("present/"+entry.getKey()))continue;
      Path target=entry.getValue().toAbsolutePath().normalize();boolean present="true".equals(p.getProperty("present/"+entry.getKey()));
      if(!present&&!Files.exists(target,LinkOption.NOFOLLOW_LINKS))continue;
      AtomicFiles.directory(target.getParent());Path candidate=target.resolveSibling(target.getFileName()+".restore-"+UUID.randomUUID());
      if(present)copy(snapshot.resolve(entry.getKey()),candidate);
      if(Files.exists(target,LinkOption.NOFOLLOW_LINKS)){
        if(Files.isSymbolicLink(target))throw new IOException("Profile restore symlink rejected");
        Files.move(target,target.resolveSibling(target.getFileName()+".failed-update-"+UUID.randomUUID()),StandardCopyOption.ATOMIC_MOVE);
      }
      if(present)Files.move(candidate,target,StandardCopyOption.ATOMIC_MOVE);AtomicFiles.syncDirectory(target.getParent());
    }
  }
  private static boolean newState600(String key){return key.startsWith("app/core600/")||key.equals("app/glas600")||key.startsWith("app/mail600/migrated-profile6/");}
  private static boolean excluded(Path p){String n=p.getFileName().toString();return n.endsWith(".lock")||n.startsWith(".atomic-")||n.equals("control_auth_cookie")||n.equals("lock")||n.equals("library-cache")||n.startsWith(".verify-identity-");}
  private static void copy(Path source,Path target)throws IOException{
    if(Files.isSymbolicLink(source))throw new IOException("Snapshot symlink rejected");
    if(Files.isDirectory(source,LinkOption.NOFOLLOW_LINKS)){
      AtomicFiles.directory(target);try(var files=Files.list(source)){for(Path p:files.toList())if(!excluded(p))copy(p,target.resolve(p.getFileName()));}AtomicFiles.syncDirectory(target);
    }else if(Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS)){
      AtomicFiles.directory(target.getParent());Files.copy(source,target,StandardCopyOption.COPY_ATTRIBUTES);
      try(var ch=FileChannel.open(target,StandardOpenOption.WRITE)){ch.force(true);}
    }else throw new IOException("Non-regular profile file rejected");
  }
  private static String treeDigest(Path snapshot)throws IOException{
    try{
      var digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[65536];
      try(var paths=Files.walk(snapshot)){
        for(Path file:paths.sorted().toList()){
          if(Files.isSymbolicLink(file))throw new IOException("Snapshot symlink rejected");
          String relative=snapshot.relativize(file).toString().replace('\\','/');if(relative.equals("snapshot.properties")||relative.equals("incomplete"))continue;
          digest.update(relative.getBytes(java.nio.charset.StandardCharsets.UTF_8));digest.update((byte)0);
          digest.update((byte)(Files.isDirectory(file)?1:2));
          if(Files.isRegularFile(file))try(var input=Files.newInputStream(file)){int n;while((n=input.read(buffer))>=0)digest.update(buffer,0,n);}
          digest.update((byte)0);
        }
      }return HexFormat.of().formatHex(digest.digest());
    }catch(GeneralSecurityException impossible){throw new IOException(impossible);}
  }
}
