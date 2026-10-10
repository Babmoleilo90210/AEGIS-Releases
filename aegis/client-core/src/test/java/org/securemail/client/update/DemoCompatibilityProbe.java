package org.securemail.client.update;

import com.google.gson.*;
import java.io.*;
import java.net.URI;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

/** Run against the unmodified, published 1.1.0 JARs. The ephemeral in-memory
 * test key exercises the old verifier's schema/state machine only. Production
 * verification must reject that key; this is not an owner-signed E2E test.
 */
public final class DemoCompatibilityProbe {
  public static void main(String[] args)throws Exception {
    if(!SignedManifest.CURRENT.equals("1.1.0"))throw new AssertionError("Use the published 1.1.0 classpath");
    byte[] json=Files.readAllBytes(Path.of(args[0]));Path windows=Path.of(args[1]),linux=Path.of(args[2]);
    var key=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();Signature signer=Signature.getInstance("Ed25519");signer.initSign(key.getPrivate());signer.update(json);byte[] signature=signer.sign();
    SignedManifest manifest=SignedManifest.verifyWithKey(json,signature,"beta","1.1.0","1.1.0",key.getPublic());
    if(!manifest.version().equals("1.1.1")||manifest.requiredFor("1.1.0"))throw new AssertionError("Demo update policy mismatch");
    manifest.requireInstallable("1.1.0","1.1.0");
    try{SignedManifest.verify(json,signature,"beta","1.1.0","1.1.0");throw new AssertionError("Test key replaced production trust");}catch(SignatureException expected){}
    if(!Base64.getEncoder().encodeToString(SignedManifest.embeddedPublicKey()).equals("MCowBQYDK2VwAyEAswWYCFStSEhQdrgqUJFF3x12ltmfUA0PvQtlh684B2g="))throw new AssertionError("Pinned key changed");
    for(var pair:List.of(Map.entry(windows,manifest.clientAsset(true)),Map.entry(linux,manifest.clientAsset(false)))) {
      UpdateService.verifyFile(pair.getKey(),pair.getValue());PackageSanity.check(pair.getKey(),pair.getValue(),manifest.version());
    }
    Path profile=Files.createTempDirectory("AEGIS demo old updater ");List<UpdateService.Snapshot> events=new CopyOnWriteArrayList<>();
    var files=new UpdateService.Downloads(){
      public byte[] bytes(URI uri,int max)throws IOException{if(!uri.toString().endsWith("/main/updates/beta.json")&&!uri.toString().endsWith("/main/updates/beta.json.sig"))throw new IOException("Wrong channel endpoint");return uri.toString().endsWith(".sig")?signature:json;}
      public void file(SignedManifest.Asset asset,Path target,java.util.function.BooleanSupplier cancelled,UpdateService.Progress progress)throws IOException {
        try(var in=Files.newInputStream(windows);var out=Files.newOutputStream(target)){byte[] buffer=new byte[65536];long n=0;int count;while((count=in.read(buffer))!=-1){if(cancelled.getAsBoolean())throw new InterruptedIOException();out.write(buffer,0,count);n+=count;progress.accept(n,asset.size());}}
      }
    };
    try(var service=new UpdateService(files,new UpdateStateStore(profile),true,(data,sig,channel,current,highest)->SignedManifest.verifyWithKeyForCheck(data,sig,channel,current,key.getPublic()))) {
      service.channel("beta");service.listener(events::add);service.check(true);
      long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(45);
      while(System.nanoTime()<end&&service.snapshot().state()!=UpdateService.State.READY_TO_INSTALL&&service.snapshot().state()!=UpdateService.State.FAILED)Thread.sleep(10);
      if(service.snapshot().state()!=UpdateService.State.READY_TO_INSTALL)throw new AssertionError("Old updater rejected exact demo package: "+service.snapshot().state());
      if(events.stream().noneMatch(s->s.state()==UpdateService.State.DOWNLOADING&&s.downloaded()>0&&s.downloaded()<s.total()))throw new AssertionError("No actual byte progress");
      if(events.stream().filter(UpdateService.Snapshot::announcement).count()!=1)throw new AssertionError("Announcement was not deduplicated");
    }
    System.out.println("Published 1.1.0 compatibility PASS: beta endpoint, 1.1.1 schema, actual ZIP/AppImage hash and package checks, byte progress, READY_TO_INSTALL, unchanged pinned key rejects ephemeral key. Fixture transport/signature; owner-signed native install NOT_RUN.");
  }
}
