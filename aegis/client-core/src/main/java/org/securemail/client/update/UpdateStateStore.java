package org.securemail.client.update;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.securemail.client.storage.AtomicFiles;

/** Only public authenticated release metadata is persisted; no mailbox or credentials. */
public final class UpdateStateStore {
  private final Path root;
  public UpdateStateStore(Path profile)throws IOException {root=profile.resolve("updates");AtomicFiles.directory(root);}
  public Path root(){return root;}
  public synchronized String highest(String channel)throws IOException {
    Path p=root.resolve(channel+".floor");return Files.exists(p)?new String(AtomicFiles.read(p,100),java.nio.charset.StandardCharsets.US_ASCII).trim():SignedManifest.CURRENT;
  }
  public synchronized boolean remember(SignedManifest manifest,byte[] exact,byte[] signature)throws IOException,GeneralSecurityException {
    String channel=manifest.channel(),high=highest(channel);if(SemVersion.parse(manifest.version()).compareTo(SemVersion.parse(high))<0)throw new IOException("Release rollback");
    Path json=root.resolve(channel+"-"+manifest.version()+".json"),sig=root.resolve(channel+"-"+manifest.version()+".sig");
    if(Files.exists(json)&&!MessageDigest.isEqual(AtomicFiles.read(json,SignedManifest.MAX_BYTES),exact))throw new IOException("Release version was replaced");
    AtomicFiles.write(sig,signature);AtomicFiles.write(json,exact);AtomicFiles.write(root.resolve(channel+".floor"),(manifest.version()+"\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    Path marker=root.resolve("lastAnnouncementVersion-"+channel);String old=Files.exists(marker)?new String(AtomicFiles.read(marker,100),java.nio.charset.StandardCharsets.US_ASCII).trim():"";
    return manifest.announcement().showAsLetter()&&manifest.newerThan(SignedManifest.CURRENT)&&!old.equals(manifest.version());
  }
  public synchronized void announcementShown(SignedManifest manifest)throws IOException {AtomicFiles.write(root.resolve("lastAnnouncementVersion-"+manifest.channel()),manifest.version().getBytes(java.nio.charset.StandardCharsets.US_ASCII));}
  public synchronized List<SignedManifest> history(String channel)throws IOException {
    List<SignedManifest> values=new ArrayList<>();try(var files=Files.newDirectoryStream(root,channel+"-*.json")){for(Path p:files){String name=p.getFileName().toString();try{values.add(SignedManifest.verify(AtomicFiles.read(p,SignedManifest.MAX_BYTES),AtomicFiles.read(root.resolve(name.substring(0,name.length()-5)+".sig"),64),channel,"0.0.0","0.0.0"));}catch(GeneralSecurityException|IOException|RuntimeException invalid){/* Unauthenticated local records are not shown as trusted letters. */}}}
    values.sort((a,b)->SemVersion.parse(b.version()).compareTo(SemVersion.parse(a.version())));return List.copyOf(values);
  }
}
