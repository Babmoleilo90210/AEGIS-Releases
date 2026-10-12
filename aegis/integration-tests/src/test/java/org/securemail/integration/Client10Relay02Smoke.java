package org.securemail.integration;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.securemail.client.crypto.*;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

/** Runs an independently packaged relay process. SOCKS is local test routing, not real Tor. */
public final class Client10Relay02Smoke {
  private static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
  public static void main(String[] args)throws Exception{
    Path temp=Files.createTempDirectory("aegis-process-test-");int port;
    try(var probe=new ServerSocket(0,16,InetAddress.getLoopbackAddress())){port=probe.getLocalPort();}
    Path db=temp.resolve("server/relay.db"),config=temp.resolve("relay.properties");
    Files.writeString(config,"databasePath="+db+"\nlistenAddress=127.0.0.1\nlistenPort="+port+"\nregistrationMode=open\nallowRegistration=true\nallowedNicknames=raven,blackfox\nmaxUsers=3\nmaxFileSize=8388608\n");
    Process process=new ProcessBuilder(args[0],"-Xmx256m","-cp",Path.of(args[1]).resolve("*").toString(),"org.securemail.relay.RelayMain","serve",config.toString()).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    try{
      boolean listening=false;
      for(int n=0;n<100&&process.isAlive();n++){try(var probe=new Socket("127.0.0.1",port)){listening=true;break;}catch(java.io.IOException e){Thread.sleep(50);}}
      check(listening,"Packaged relay did not start");
      Clock clock=Clock.systemUTC();char[] vault="local vault test passphrase".toCharArray(),account="separate account passphrase".toCharArray();
      try(var socks=new SocksHarness();var a=new LocalStore(temp.resolve("a"),vault,clock,9_000_000,30_000_000);var b=new LocalStore(temp.resolve("b"),vault,clock,9_000_000,30_000_000)){
        socks.destinations.put(SocksHarness.RELAY,port);
        var na=new NetworkService(new TorTransport("127.0.0.1",socks.port()),SocksHarness.RELAY,80,a,9_000_000);
        var nb=new NetworkService(new TorTransport("127.0.0.1",socks.port()),SocksHarness.RELAY,80,b,9_000_000);
        na.authenticate("raven",account,true);nb.authenticate("blackfox",account,true);
        a.trust(na.find("blackfox"));b.trust(nb.find("raven"));
        String marker="RELEASE-PLAINTEXT-MUST-STAY-LOCAL-"+UUID.randomUUID();
        byte[] data=Secrets.random(2*1024*1024);System.arraycopy(marker.getBytes(StandardCharsets.UTF_8),0,data,50,marker.length());
        Path file=temp.resolve("example.zip");Files.write(file,data);List<Path> files=new ArrayList<>(List.of(file));for(String name:List.of("test.txt","document.pdf","photo.jpg","spreadsheet.xlsx","video.mp4","random.bin")){Path extra=temp.resolve(name);Files.write(extra,new byte[]{1,2,3,4});files.add(extra);}var crypto=new AutomaticEncryption(clock);EncryptedPacket packet;
        try(var plain=PlainMessage.letterWithAttachments("V4 subject",LetterEnvelope.seal(marker,"Frost-8134".toCharArray(),"Raven-821".toCharArray()),files,8_388_608)){packet=crypto.encrypt(plain,3,60_000,a.identity(),"raven",na.find("blackfox"));}
        check(na.deliver(packet)==NetworkService.Delivery.RELAY_QUEUED,"Offline packet not queued");check(b.inbox().isEmpty(),"Unexpected delivery");
        process.destroy();if(!process.waitFor(5,TimeUnit.SECONDS))process.destroyForcibly();
        process=new ProcessBuilder(args[0],"-Xmx256m","-cp",Path.of(args[1]).resolve("*").toString(),"org.securemail.relay.RelayMain","serve",config.toString()).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        boolean restarted=false;for(int n=0;n<100&&process.isAlive();n++){try(var probe=new Socket("127.0.0.1",port)){restarted=true;break;}catch(java.io.IOException e){Thread.sleep(50);}}
        check(restarted,"Relay process failed to restart");na.authenticate("raven",account,false);nb.authenticate("blackfox",account,false);
        Thread.sleep(1500);check(nb.fetchAndAcknowledge()==1,"Missing delivery");
        check(b.inbox().getFirst().receivedAt()>packet.createdAt()+1000,"TTL started before delivery");
        try(var plain=crypto.decrypt(b.load(packet.messageId()),b.identity(),8_388_608)){
          try(var opened=LetterEnvelope.open(plain.letterEnvelope(),"Frost-8134".toCharArray())){check(opened.candidate("Raven-821".toCharArray()).equals(marker),"Protected text mismatch");}Path received=temp.resolve("received.zip");plain.exportEncryptedZip(received,"Frost-8134".toCharArray(),()->true);check(plain.files().size()==7,"Multiple attachments lost");try(var archive=new net.lingala.zip4j.ZipFile(received.toFile(),"Frost-8134".toCharArray());var in=archive.getInputStream(archive.getFileHeader("example.zip"))){check(Arrays.equals(data,in.readAllBytes()),"Encrypted ZIP file mismatch");}
        }
        check(nb.fetchAndAcknowledge()==0,"ACK did not remove packet");na.deliver(packet);check(nb.fetchAndAcknowledge()==0,"Replay reappeared");
        synchronized(socks.relayBytes){String wire=socks.relayBytes.toString(StandardCharsets.ISO_8859_1);check(!wire.contains(marker),"Plaintext reached relay transport");check(!wire.contains(new String(a.identity().privateKey(),StandardCharsets.ISO_8859_1)),"Private key reached relay transport");}
        EncryptedPacket reply;
        try(var letter=PlainMessage.letter("Reply",LetterEnvelope.seal("Ответ АЕГИС 🦊","second-password".toCharArray(),"Code-4829".toCharArray()),null,8_388_608)){
          reply=crypto.encrypt(letter,60,60000,b.identity(),"blackfox",nb.find("raven"));
        }
        check(nb.deliver(reply)==NetworkService.Delivery.RELAY_QUEUED,"Reply not queued");check(na.fetchAndAcknowledge()==1,"Reply not delivered");
        try(var letter=crypto.decrypt(a.load(reply.messageId()),a.identity(),8_388_608);var opened=LetterEnvelope.open(letter.letterEnvelope(),"second-password".toCharArray())){check(opened.candidate("Code-4829".toCharArray()).equals("Ответ АЕГИС 🦊"),"Reply mismatch");}
        a.exportIdentity(temp.resolve("a-backup.aegis-backup"));
        Thread.sleep(3200);b.cleanup();check(b.inbox().isEmpty(),"TTL did not remove packet");
        String stored=new String(Files.readAllBytes(db),StandardCharsets.ISO_8859_1);check(!stored.contains(marker),"Plaintext in relay DB");check(!stored.contains(new String(a.identity().privateKey(),StandardCharsets.ISO_8859_1)),"Private key in relay DB");
      }
      try(var a=new LocalStore(temp.resolve("a"),"local vault test passphrase".toCharArray(),Clock.systemUTC(),9_000_000,30_000_000);var b=new LocalStore(temp.resolve("b"),"local vault test passphrase".toCharArray(),Clock.systemUTC(),9_000_000,30_000_000)){
        check(a.nickname().equals("raven")&&b.nickname().equals("blackfox"),"Restart lost account binding");
        check(a.contact("blackfox")!=null&&b.contact("raven")!=null,"Restart lost contacts");
        var packet=a.load(a.inbox().getFirst().messageId());
        try(var plain=new AutomaticEncryption(Clock.systemUTC()).decrypt(packet,a.identity(),8_388_608);var opened=LetterEnvelope.open(plain.letterEnvelope(),"second-password".toCharArray())){check(opened.candidate("Code-4829".toCharArray()).equals("Ответ АЕГИС 🦊"),"Restart lost letter/identity");}
        check(b.inbox().isEmpty(),"Expired packet survived reopen");
      }
      System.out.println("Protocol-1 independent relay/client compatibility passed (exact versions in matrix): bidirectional FF1 + AES letters, relay process restart, client vault reopen, offline, E2EE, seven file types, AES ZIP, 2 MiB file, ACK, deduplication, TTL, no plaintext/private key on relay transport");
    }finally{process.destroy();if(!process.waitFor(5,TimeUnit.SECONDS))process.destroyForcibly();}
  }
}
