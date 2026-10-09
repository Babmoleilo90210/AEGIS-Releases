package org.securemail.integration;

import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.securemail.client.crypto.*;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

/** Real old/new relay subprocesses and the same SQLite file; synthetic local SOCKS, not Tor. */
public final class RelayMigrationSmoke {
  private static void check(boolean value,String what){if(!value)throw new AssertionError(what);}
  private static Process start(String java,Path lib,Path config,int port)throws Exception{
    Process process=new ProcessBuilder(java,"-Xmx256m","-cp",lib.resolve("*").toString(),"org.securemail.relay.RelayMain","serve",config.toString()).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    try{for(int n=0;n<100&&process.isAlive();n++){try(var socket=new Socket("127.0.0.1",port)){return process;}catch(java.io.IOException pending){Thread.sleep(50);}}throw new AssertionError("Relay did not listen");}
    catch(Exception|Error failure){stop(process);throw failure;}
  }
  private static void stop(Process process)throws Exception{if(process==null)return;process.destroy();if(!process.waitFor(5,TimeUnit.SECONDS)){process.destroyForcibly();process.waitFor(5,TimeUnit.SECONDS);}}
  private static Map<String,String> rows(Path path)throws Exception{
    var result=new LinkedHashMap<String,String>();
    try(var db=DriverManager.getConnection("jdbc:sqlite:"+path)){
      for(String table:List.of("users","mailbox","receipts")){
        var digest=MessageDigest.getInstance("SHA-256");try(var query=db.createStatement();var rs=query.executeQuery("SELECT * FROM "+table+" ORDER BY 1")){
          int count=rs.getMetaData().getColumnCount();while(rs.next())for(int n=1;n<=count;n++){byte[] value=rs.getBytes(n);if(value==null)digest.update((byte)0);else{digest.update(java.nio.ByteBuffer.allocate(4).putInt(value.length).array());digest.update(value);}}
        }result.put(table,HexFormat.of().formatHex(digest.digest()));
      }
    }return result;
  }
  public static void main(String[] args)throws Exception{
    Path temp=Files.createTempDirectory("aegis-relay-migration-");int port;try(var socket=new ServerSocket(0,16,InetAddress.getLoopbackAddress())){port=socket.getLocalPort();}
    Path db=temp.resolve("relay.db"),config=temp.resolve("relay.properties");Files.writeString(config,"databasePath="+db+"\nlistenAddress=127.0.0.1\nlistenPort="+port+"\nregistrationMode=open\nallowRegistration=true\nmaxUsers=4\nmaxFileSize=1000000\n");
    Process process=null;char[] password="migration test passphrase".toCharArray();Clock clock=Clock.systemUTC();
    try(var socks=new SocksHarness();var a=new LocalStore(temp.resolve("a"),password,clock,1000000,8000000);var b=new LocalStore(temp.resolve("b"),password,clock,1000000,8000000)){
      socks.destinations.put(SocksHarness.RELAY,port);process=start(args[0],Path.of(args[1]),config,port);
      var na=new NetworkService(new TorTransport("127.0.0.1",socks.port()),SocksHarness.RELAY,80,a,1000000);var nb=new NetworkService(new TorTransport("127.0.0.1",socks.port()),SocksHarness.RELAY,80,b,1000000);
      na.authenticate("raven",password,true);nb.authenticate("blackfox",password,true);var recipient=na.find("blackfox");a.trust(recipient);b.trust(nb.find("raven"));
      check(na.capabilities()==0,"Old relay capabilities must degrade to zero");check(na.profile("blackfox")==null,"Old relay profile must be unavailable");check(na.relationship(recipient).ours()==null,"Old relay friendship unavailable");check(na.loggedIn(),"Capability discovery cleared authentication");
      var crypto=new AutomaticEncryption(clock);EncryptedPacket acknowledged,queued;
      try(var plain=PlainMessage.text("acknowledged fixture")){acknowledged=crypto.encrypt(plain,300,3600000,a.identity(),"raven",recipient);}na.deliver(acknowledged);check(nb.fetchAndAcknowledge()==1,"Old relay ACK failed");
      try(var plain=PlainMessage.text("queued before migration")){queued=crypto.encrypt(plain,300,3600000,a.identity(),"raven",recipient);}na.deliver(queued);
      stop(process);process=null;var before=rows(db);process=start(args[0],Path.of(args[2]),config,port);stop(process);process=null;
      check(before.equals(rows(db)),"Additive migration changed account hashes, identity keys, mailbox, TTL, or receipts");
      try(var connection=DriverManager.getConnection("jdbc:sqlite:"+db);var statement=connection.createStatement();var rs=statement.executeQuery("SELECT COUNT(*) FROM schema_migrations WHERE version='public-data-v1'")){check(rs.next()&&rs.getInt(1)==1,"Migration marker missing");}
      process=start(args[0],Path.of(args[2]),config,port);na.authenticate("raven",password,false);nb.authenticate("blackfox",password,false);check(na.capabilities()==3,"New relay features missing");check(nb.fetchAndAcknowledge()==1,"Old queued ciphertext lost");
      try(var opened=crypto.decrypt(b.load(queued.messageId()),b.identity(),1000000)){check(opened.text().equals("queued before migration"),"Queued mail or client identity changed");}
      stop(process);process=null;process=start(args[0],Path.of(args[1]),config,port);na.authenticate("raven",password,false);nb.authenticate("blackfox",password,false);check(na.capabilities()==0,"Old relay cannot reopen migrated SQLite");
      EncryptedPacket after;try(var plain=PlainMessage.text("mail after old relay rollback")){after=crypto.encrypt(plain,300,3600000,a.identity(),"raven",recipient);}na.deliver(after);check(nb.fetchAndAcknowledge()==1,"Basic mail after relay rollback failed");
      System.out.println("PASS: client 1.1 on relay 0.2 fallback; real SQLite 0.2 -> 0.3 migration preserves users/password hashes/public keys/queued ciphertext/TTLs/receipts; old relay reopens migrated DB and delivers mail. Synthetic local SOCKS; no native Tor/VPS acceptance.");
    }finally{stop(process);Arrays.fill(password,'\0');}
  }
}
