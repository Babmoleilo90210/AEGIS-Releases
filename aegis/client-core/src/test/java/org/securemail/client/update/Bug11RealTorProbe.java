package org.securemail.client.update;

import java.net.URI;
import java.nio.file.*;
import java.security.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.*;
import org.securemail.client.net.*;

/** Read-only production-feed acceptance using the exact packaged Tor, TLS and pinned key.
 * Evidence contains public manifest/signature bytes only; no test profile or Tor state is exported.
 * Run separately from JUnit. Compatible with the pre-fix jar to demonstrate the same failure.
 */
public final class Bug11RealTorProbe {
  public static void main(String[] args)throws Exception {
    Path app=Path.of(args[0]).toAbsolutePath(),evidence=Path.of(args[1]).toAbsolutePath();
    boolean before=args.length>2&&args[2].equals("--before");
    Files.createDirectories(evidence);Path profile=Files.createTempDirectory("AEGIS BUG11 own profile ");
    System.setProperty("aegis.home",app.toString());System.setProperty("aegis.profile",profile.toString());
    ClientConfig config=ClientConfig.load(profile.resolve("config/client.properties"));
    CountDownLatch done=new CountDownLatch(1);List<UpdateService.Snapshot> states=new CopyOnWriteArrayList<>();
    try(TorConnection tor=new TorConnection(config)) {
      TorTransport.requireAvailability(tor::ready);
      tor.start(Duration.ofSeconds(120),Duration.ofSeconds(240),(mode,n)->System.out.println("Tor "+mode+" "+n+"%"));
      if(!tor.ready())throw new AssertionError("Tor did not bootstrap");
      String rc=Files.readString(profile.resolve("tor/torrc"));
      if(!rc.contains("127.0.0.1:19050 OnionTrafficOnly")||!rc.contains("127.0.0.1:19052\n")||rc.contains("0.0.0.0"))throw new AssertionError("Unexpected SOCKS listeners");
      var https=new TorHttpsClient(config.torUpdateSocksPort());
      URI feed=URI.create("https://raw.githubusercontent.com/"+SignedManifest.REPOSITORY+"/main/updates/stable.json");
      byte[] json=https.bytes(feed,SignedManifest.MAX_BYTES),sig=https.bytes(URI.create(feed+".sig"),64);
      // Strict verification with the feed's deployed client version also checks the full old schema.
      SignedManifest deployed=SignedManifest.verify(json,sig,"stable","1.0.0","1.0.0");
      Files.write(evidence.resolve("production-stable.json"),json);Files.write(evidence.resolve("production-stable.json.sig"),sig);
      String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(json));
      System.out.println("TLS and production pinned Ed25519 PASS; manifest="+deployed.version()+" SHA256="+hash+" signatureBytes="+sig.length);
      if(deployed.newerThan(SignedManifest.CURRENT))throw new AssertionError("Feed changed: this probe needs an older or equal version");
      try(UpdateService service=new UpdateService(profile,config.torUpdateSocksPort())) {
        service.listener(s->{states.add(s);if(s.state()!=UpdateService.State.CHECKING)done.countDown();});
        service.check(true);if(!done.await(120,TimeUnit.SECONDS))throw new AssertionError("Updater check timed out");
        var result=service.snapshot();String expected=before?"FAILED":"UP_TO_DATE";
        if(!result.state().name().equals(expected))throw new AssertionError("Expected "+expected+", received "+result.state());
        if(result.manifest()!=null||result.announcement()||states.stream().anyMatch(s->s.state()==UpdateService.State.DOWNLOADING))throw new AssertionError("Old feed reached installation/announcement");
        if(Files.exists(profile.resolve("updates/stable.floor")))throw new AssertionError("Old feed persisted a rollback floor");
        String diagnostic="pre-fix generic error";
        try{Object d=result.getClass().getMethod("diagnostic").invoke(result);if(d!=null)diagnostic=d.toString();}catch(NoSuchMethodException expectedOldJar){}
        String report="{\n  \"result\": \"PASS\",\n  \"mode\": \""+(before?"BEFORE_REPRODUCED":"AFTER_FIXED")+"\",\n  \"clientVersion\": \""+SignedManifest.CURRENT+"\",\n  \"feedVersion\": \""+deployed.version()+"\",\n  \"manifestSha256\": \""+hash+"\",\n  \"torMode\": \""+tor.mode()+"\",\n  \"torBootstrap\": 100,\n  \"tlsDefaultTruststore\": true,\n  \"pinnedEd25519Verified\": true,\n  \"updateState\": \""+result.state()+"\",\n  \"directFallback\": false,\n  \"productionModified\": false\n}\n";
        Files.writeString(evidence.resolve(before?"BEFORE.json":"AFTER.json"),report);
        System.out.println("BUG11 "+(before?"reproduced":"fixed")+": "+result.state()+" / "+diagnostic);
      }
    }finally{TorTransport.requireAvailability(()->true);}
    // Verify owned child cleanup without killing unrelated processes.
    for(int port:new int[]{19050,19051,19052})try(var socket=new java.net.ServerSocket()){socket.bind(new java.net.InetSocketAddress("127.0.0.1",port));}
    System.out.println("Owned Tor stopped; all three loopback ports released. No production write or release signing.");
  }
}
