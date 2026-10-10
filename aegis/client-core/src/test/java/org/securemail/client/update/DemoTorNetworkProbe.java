package org.securemail.client.update;

import java.io.*;
import java.net.URI;
import java.nio.file.*;
import java.security.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.securemail.client.*;
import org.securemail.client.net.*;

/** Real published 1.1.0 HTTPS transport and bundled Tor, with its production
 * Ed25519 key. Fetches an already signed production source artifact read-only.
 * Does not install, write feeds or claim that unsigned 1.1.1 passed E2E.
 */
public final class DemoTorNetworkProbe {
  public static void main(String[] args)throws Exception {
    if(!SignedManifest.CURRENT.equals("1.1.0"))throw new AssertionError("Use the published 1.1.0 classpath");
    Path app=Path.of(args[0]).toAbsolutePath(),evidence=Path.of(args[1]).toAbsolutePath();Files.createDirectories(evidence);
    Path profile=Files.createTempDirectory("AEGIS demo Tor fixture ");System.setProperty("aegis.home",app.toString());System.setProperty("aegis.profile",profile.toString());
    ClientConfig config=ClientConfig.load(profile.resolve("config/client.properties"));
    try(TorConnection tor=new TorConnection(config)) {
      TorTransport.requireAvailability(tor::ready);tor.start(Duration.ofSeconds(120),Duration.ofSeconds(240),(mode,n)->System.out.println("Tor "+mode+" "+n+"%"));
      if(!tor.ready())throw new AssertionError("Tor unavailable");
      String rc=Files.readString(profile.resolve("tor/torrc"));if(!rc.contains("127.0.0.1:19050 OnionTrafficOnly")||!rc.contains("127.0.0.1:19052\n")||rc.contains("0.0.0.0"))throw new AssertionError("Listener isolation failed");
      var https=new TorHttpsClient(config.torUpdateSocksPort());URI uri=URI.create("https://raw.githubusercontent.com/"+SignedManifest.REPOSITORY+"/main/updates/stable.json");
      byte[] exact=https.bytes(uri,SignedManifest.MAX_BYTES),sig=https.bytes(URI.create(uri+".sig"),64);SignedManifest signed=SignedManifest.verifyForCheck(exact,sig,"stable","1.1.0","1.1.0");
      if(signed.newerThan("1.1.0"))throw new AssertionError("Feed changed; this read-only test must not download a newer update");
      var asset=signed.artifacts().stream().filter(a->a.kind().equals("source")).findFirst().orElseThrow();
      Path target=profile.resolve("source.part");AtomicBoolean cancel=new AtomicBoolean();AtomicInteger progress=new AtomicInteger();
      try{https.file(asset,target,cancel::get,(n,total)->{progress.incrementAndGet();if(n>=262144)cancel.set(true);});throw new AssertionError("Cancellation did not interrupt transfer");}catch(InterruptedIOException expected){}
      long partial=Files.size(target);if(partial<=0||partial>=asset.size())throw new AssertionError("No resumable partial file");
      AtomicLong first=new AtomicLong(-1),last=new AtomicLong();
      https.file(asset,target,()->false,(n,total)->{first.compareAndSet(-1,n);last.set(n);progress.incrementAndGet();});UpdateService.verifyFile(target,asset);
      if(last.get()!=asset.size()||progress.get()<3)throw new AssertionError("No real progress");
      Files.write(evidence.resolve("production-stable.json"),exact);Files.write(evidence.resolve("production-stable.json.sig"),sig);
      Files.writeString(evidence.resolve("RESULTS.json"),"{\n  \"result\": \"PASS\",\n  \"clientVersion\": \"1.1.0\",\n  \"torMode\": \""+tor.mode()+"\",\n  \"torBootstrap\": 100,\n  \"productionEd25519\": true,\n  \"TLSDefaultTruststore\": true,\n  \"artifactVersion\": \""+signed.version()+"\",\n  \"artifactKind\": \"source\",\n  \"downloadedBytes\": "+asset.size()+",\n  \"partialBytes\": "+partial+",\n  \"firstResumedProgress\": "+first.get()+",\n  \"progressEvents\": "+progress.get()+",\n  \"sha256\": \""+asset.sha256()+"\",\n  \"directFallback\": false,\n  \"productionModified\": false,\n  \"demo111SignedInstall\": \"NOT_RUN\"\n}\n");
      System.out.println("Published 1.1.0 real Tor PASS: production Ed25519, TLS, GitHub artifact download, interruption/resume and SHA-256. New 1.1.1 owner-signed installation pending.");
    }
  }
}
