package org.securemail.client.security600;

import com.google.gson.JsonObject;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.securemail.client.ClientConfig;
import org.securemail.client.net.*;
import org.securemail.client.update.*;

/** Explicit network acceptance utility, NOT an automatically passing JUnit/mock/native test.
 * Uses a fresh test profile, only owned Tor processes and public read-only endpoints.
 * Never prints real/exit IP addresses, control cookies or account material.
 * Onion source: https://onion.torproject.org/ (aus1 entry, checked 2026-10-18).
 */
public final class LiveTorTransport600 {
  private LiveTorTransport600(){}
  public static void main(String[] args)throws Exception {
    if(args.length!=2)throw new IllegalArgumentException("bundle directory and result JSON required");
    Path profile=Files.createTempDirectory("aegis600-live-tor-");System.setProperty("aegis.profile",profile.toString());System.setProperty("aegis.home",Path.of(args[0]).toAbsolutePath().toString());
    ClientConfig config=new ClientConfig("127.0.0.1",29450,29451,profile.resolve("tor/control_auth_cookie"),29460,1800,"",80,profile.resolve("data"),16777216,268435456,604800000);
    JsonObject result=new JsonObject();result.addProperty("scope","Real bundled Tor on Work Linux container; no browser/native target/DNS packet capture/voice or two-device acceptance");result.addProperty("nativeTargetAcceptance",false);AtomicInteger last=new AtomicInteger(-1);String phase="BOOTSTRAP";
    ScheduledExecutorService deadline=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"aegis-live-tor-total-deadline");t.setDaemon(true);return t;});
    try(TorConnection connection=new TorConnection(config)){
      TorTransport.requireAvailability(connection::ready);deadline.schedule(connection::close,210,TimeUnit.SECONDS);
      try {
        connection.start(Duration.ofSeconds(60),Duration.ofSeconds(90),(mode,percent)->{if(last.getAndSet(percent)!=percent)System.out.println("TOR "+mode+" "+percent);});result.addProperty("bootstrap","PASS");result.addProperty("transportMode",connection.mode().name());
        phase="HTTPS";TorHttpsClient https=new TorHttpsClient(29452);URI feed=URI.create("https://raw.githubusercontent.com/"+SignedManifest.REPOSITORY+"/main/updates/beta.json");byte[] manifest=https.bytes(feed,SignedManifest.MAX_BYTES);result.addProperty("https","PASS");phase="SIGNED_PUBLIC_FEED";byte[] signature=https.bytes(URI.create(feed+".sig"),64);SignedManifest release=SignedManifest.verifyForCheck(manifest,signature,"beta",SignedManifest.CURRENT,"0.0.0");result.addProperty("signedPublicFeed","PASS");result.addProperty("feedVersion",release.version());
        phase="ONION";String onion="ot3ivcdxmalbsbponeeq5222hftpf3pqil24q3s5ejwo5t52l65qusid.onion";
        try(var socket=new TorTransport("127.0.0.1",29450).connectPeer(onion,80)){socket.setSoTimeout(20000);socket.getOutputStream().write(("GET /torbrowser/update_3/release/download-linux-x86_64.json HTTP/1.1\r\nHost: "+onion+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));socket.getOutputStream().flush();ByteArrayOutputStream status=new ByteArrayOutputStream();for(int n=0;n<1024;n++){int b=socket.getInputStream().read();if(b<0)throw new EOFException();if(b=='\n')break;if(b!='\r')status.write(b);}if(!status.toString(StandardCharsets.US_ASCII).matches("HTTP/1\\.[01] (?:200|301|302)(?: .*)?"))throw new IOException("Unexpected public onion HTTP status");result.addProperty("onion","PASS");}
      }catch(Exception unavailable){result.addProperty("blockedPhase",phase);result.addProperty("observedBootstrapPercent",last.get());result.addProperty("exceptionType",unavailable.getClass().getSimpleName());result.addProperty("networkAcceptance","BLOCKED");}
    }finally{deadline.shutdownNow();}
    for(String name:new String[]{"bootstrap","https","signedPublicFeed","onion"})if(!result.has(name))result.addProperty(name,"NOT_RUN");if(!result.has("networkAcceptance"))result.addProperty("networkAcceptance","PASS_FOR_EXPLICIT_TRANSPORT_CHECKS_ONLY");
    Path output=Path.of(args[1]).toAbsolutePath();Files.createDirectories(output.getParent());Files.writeString(output,result.toString()+"\n",StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW);System.out.println(result);
  }
}
