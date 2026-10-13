package org.securemail.integration;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.securemail.client.*;
import org.securemail.client.crypto.*;
import org.securemail.client.lifecycle.*;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;
import org.securemail.relay.*;

/** Owner/CI-only real onion transport with a disposable staging relay and two random accounts.
 * One OS and one Tor process: this is deliberately not Windows11/KDE cross-network acceptance.
 * No production relay, account, update feed or release key is touched. */
public final class LifecycleTorProbe {
  @FunctionalInterface private interface Refresh {void run()throws Exception;}
  private static DeviceCapabilities warmProbe(NetworkService network,UserInfo peer,Refresh refresh)throws Exception {
    java.io.IOException last=null;
    for(int attempt=1;attempt<=3;attempt++){refresh.run();try{var value=network.probe(peer);if(value!=null)return value;last=new java.io.IOException("Signed peer route not yet available");}catch(java.io.IOException notReady){last=notReady;}System.out.println("Staging signed capability attempt "+attempt+" not ready");}
    throw new java.io.IOException("Onion descriptor did not become available within three bounded probes",last);
  }
  public static void main(String[] args)throws Exception {
    Path app=Path.of(args[0]).toAbsolutePath(),output=Path.of(args[1]).toAbsolutePath();Files.createDirectories(output);
    Path root=Files.createTempDirectory("AEGIS lifecycle onion staging ");System.setProperty("aegis.home",app.toString());System.setProperty("aegis.profile",root.toString());
    ClientConfig config=ClientConfig.load(root.resolve("config/client.properties"));Clock clock=Clock.systemUTC();char[] password=Base64.getEncoder().encodeToString(Secrets.random(24)).toCharArray();
    RelayConfig relayConfig=new RelayConfig(root.resolve("relay/relay.db"),"127.0.0.1",0,604800000,2_000_000,32_000_000,256,3,true,Set.of("raven","blackfox"));
    try(var tor=new TorConnection(config);var rs=new RelayStore(relayConfig,clock);var server=new RelayServer(relayConfig,rs,clock);var a=new LocalStore(root.resolve("a"),password,clock,2_000_000,32_000_000);var b=new LocalStore(root.resolve("b"),password,clock,2_000_000,32_000_000)){
      TorTransport.requireAvailability(tor::ready);tor.start(Duration.ofSeconds(150),Duration.ofSeconds(300),(mode,n)->System.out.println("Staging Tor "+mode+" "+n+"%"));if(!tor.ready())throw new AssertionError("Tor unavailable");server.start();
      try(var relayControl=new TorControl(config.torControlPort(),config.torCookiePath());var ac=new TorControl(config.torControlPort(),config.torCookiePath());var bc=new TorControl(config.torControlPort(),config.torCookiePath())){
        String relayOnion=relayControl.publish(server.port());var na=new NetworkService(new TorTransport("127.0.0.1",config.torSocksPort()),relayOnion,80,a,2_000_000);var nb=new NetworkService(new TorTransport("127.0.0.1",config.torSocksPort()),relayOnion,80,b,2_000_000);
        na.authenticate("raven",password,true);nb.authenticate("blackfox",password,true);UserInfo au=nb.find("raven"),bu=na.find("blackfox");a.trust(bu);b.trust(au);var af=new LocalFeatures(a);var bf=new LocalFeatures(b);
        try(var al=new LifecycleService(a,af,2_000_000);var bl=new LifecycleService(b,bf,2_000_000);var pa=new PeerServer(0,a,2_000_000,al::accept,al::capabilities);var pb=new PeerServer(0,b,2_000_000,bl::accept,bl::capabilities)){
          na.packetAcceptor(al::accept);nb.packetAcceptor(bl::accept);al.network(na);bl.network(nb);pa.start();pb.start();String ao=ac.publish(pa.port()),bo=bc.publish(pb.port());na.publish(a.identity().route(ao,81,a.now()+90_000));nb.publish(b.identity().route(bo,81,b.now()+90_000));
          var advertised=warmProbe(na,bu,()->nb.publish(b.identity().route(bo,81,b.now()+90_000)));if(advertised==null)throw new AssertionError("Real signed onion capability unavailable");al.learn(bu,advertised);var reverse=warmProbe(nb,au,()->na.publish(a.identity().route(ao,81,a.now()+90_000)));if(reverse==null)throw new AssertionError("Reverse signed capability unavailable");bl.learn(au,reverse);
          al.sync(bu);bl.sync(au);na.fetchAndAcknowledge();nb.fetchAndAcknowledge();al.retry();bl.retry();if(!af.friend(bu.userId())||!bf.friend(au.userId()))throw new AssertionError("Real onion mutual friendship missing");
          na.publish(a.identity().route(ao,81,a.now()+90_000));nb.publish(b.identity().route(bo,81,b.now()+90_000));String text="Synthetic real Tor lifecycle fixture";EncryptedPacket p;try(var plain=PlainMessage.text(text)){p=new AutomaticEncryption(clock).encrypt(plain,86400,86400000,a.identity(),"raven",bu);}
          var result=al.send(p,bu);if(result.delivery()!=NetworkService.Delivery.P2P_CONFIRMED)throw new AssertionError("Real onion P2P was not used");
          try(var opened=bl.open(bl.loadHistory(p.messageId(),false),200000,false)){if(!opened.text().equals(text))throw new AssertionError("Body mismatch");bl.displayed(p.messageId());}bl.retry();na.fetchAndAcknowledge();if(!al.status(p.messageId(),"").equals("Прочитано"))throw new AssertionError("Signed read receipt missing");
          pb.close();EncryptedPacket offline;try(var plain=PlainMessage.text("Offline ciphertext fixture")){offline=new AutomaticEncryption(clock).encrypt(plain,86400,86400000,a.identity(),"raven",bu);}if(al.send(offline,bu).delivery()!=NetworkService.Delivery.RELAY_QUEUED)throw new AssertionError("Offline relay fallback missing");nb.fetchAndAcknowledge();try(var opened=bl.open(bl.loadHistory(offline.messageId(),false),200000,false)){if(!opened.text().equals("Offline ciphertext fixture"))throw new AssertionError("Offline body mismatch");}
          String dataMarker="ARCHIVE-FIXTURE-PRIVATE";EncryptedPacket timed;try(var plain=new PlainMessage("Expiring file fixture".getBytes(java.nio.charset.StandardCharsets.UTF_8),"fixture.txt",dataMarker.getBytes(java.nio.charset.StandardCharsets.UTF_8))){timed=al.encryptExpiring(plain,bu,60,86400000);al.send(timed,bu);}nb.fetchAndAcknowledge();try(var opened=bl.open(bl.loadHistory(timed.messageId(),false),200000,true)){byte[] file=opened.attachmentBytes("fixture.txt");try{if(!new String(file,java.nio.charset.StandardCharsets.UTF_8).equals(dataMarker))throw new AssertionError("File mismatch");}finally{Arrays.fill(file,(byte)0);}bl.displayed(timed.messageId());}
          Thread.sleep(30_000);Thread.sleep(31_000);bl.cleanup();if(!bl.expired(timed.messageId())||Files.exists(b.root().resolve("lifecycle/mail-"+timed.messageId()+".enc")))throw new AssertionError("Real expiry did not remove ciphertext");
          af.consent(bu.userId(),false);a.removeContact("blackfox");al.sync(null);nb.fetchAndAcknowledge();if(bf.friend(au.userId()))throw new AssertionError("Signed revocation missing");
          String database=new String(Files.readAllBytes(relayConfig.databasePath()),java.nio.charset.StandardCharsets.ISO_8859_1);if(database.contains(text)||database.contains(dataMarker))throw new AssertionError("Relay plaintext leak");
          Files.writeString(output.resolve("RESULTS.json"),"{\"result\":\"PASS\",\"transport\":\"actual bundled Tor onion services\",\"torBootstrap\":100,\"capabilitySignature\":true,\"friends\":true,\"P2P\":true,\"offlineRelay\":true,\"readReceipt\":true,\"file\":true,\"real60SecondExpiry\":true,\"revocation\":true,\"relayPlaintext\":false,\"protocol\":1,\"productionModified\":false,\"multiplePhysicalNetworks\":false,\"nativeWindows11CachyOS\":\"NOT_RUN\"}\n");System.out.println("LifecycleTorProbe PASS: real signed onion capabilities, Friends, P2P, offline Relay, read receipt, attachment, elapsed expiry, revoke; disposable staging only.");
        }
      }
    }finally{Arrays.fill(password,'\0');}
  }
}
