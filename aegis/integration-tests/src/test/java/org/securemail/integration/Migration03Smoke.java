package org.securemail.integration;
import java.net.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.securemail.client.*;
import org.securemail.client.crypto.*;
import org.securemail.client.storage.*;
import org.securemail.client.net.*;
public final class Migration03Smoke {
 static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);}
 public static void main(String[] args)throws Exception{
  Path temp=Files.createTempDirectory("aegis-030-to-100-");System.setProperty("aegis.profile",temp.toString());int port;try(var s=new ServerSocket(0,16,InetAddress.getLoopbackAddress())){port=s.getLocalPort();}
  Path relayConfig=temp.resolve("relay.properties");Files.writeString(relayConfig,"databasePath="+temp.resolve("relay.db")+"\nlistenAddress=127.0.0.1\nlistenPort="+port+"\nregistrationMode=open\nmaxUsers=32\n");
  Process relay=new ProcessBuilder(args[0],"-cp",Path.of(args[1]).resolve("*").toString(),"org.securemail.relay.RelayMain","serve",relayConfig.toString()).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
  try(var socks=new SocksHarness()){
   socks.destinations.put(SocksHarness.RELAY,port);boolean alive=false;for(int n=0;n<100&&relay.isAlive();n++)try(var s=new Socket("127.0.0.1",port)){alive=true;break;}catch(java.io.IOException e){Thread.sleep(50);}check(alive,"Old packaged relay failed to start");
   Path bundle=Path.of(args[2]);String cp=bundle.resolve("app/*")+java.io.File.pathSeparator+args[3];
   Process fixture=new ProcessBuilder(bundle.resolve("runtime/bin/java").toString(),"-Daegis.native.root="+bundle,"-cp",cp,Profile03Fixture.class.getName(),temp.toString(),Integer.toString(socks.port())).inheritIO().start();check(fixture.waitFor()==0,"Actual 0.3.0 fixture failed");
   ClientConfig config=ClientConfig.load(AppPaths.config());byte[] configBefore=Files.readAllBytes(AppPaths.config()),vaultBefore=Files.readAllBytes(config.storagePath().resolve("state.vault"));String id=Files.readString(temp.resolve("expected-id"));
   char[] account="account-password-1000".toCharArray(),old="separate-vault-password-0300".toCharArray();
   try{AccountLogin.open(config,"blackfox",account,null);throw new AssertionError("Missing one-time old password request");}catch(AccountLogin.OldPasswordRequired expected){}
   check(Arrays.equals(vaultBefore,Files.readAllBytes(config.storagePath().resolve("state.vault"))),"Wrong password changed old profile");
   Path backup;try(var files=Files.list(temp.resolve("backups"))){backup=files.filter(Files::isDirectory).findFirst().orElseThrow();}check(Arrays.equals(vaultBefore,Files.readAllBytes(backup.resolve("vault/state.vault"))),"Backup was not made before open");
   try{AccountLogin.open(config,"blackfox","wrong-account-password".toCharArray(),old);throw new AssertionError("Wrong account accepted");}catch(RequestRejected expected){}
   check(!LocalStore.modernVault(config.storagePath()),"Unauthenticated password migrated vault");
   try(var session=AccountLogin.open(config,"blackfox",account,old)){
    check(session.local().identity().userId().equals(id),"Identity changed");check(session.local().contacts().size()==11,"Contacts lost");check(session.local().inbox().size()==1,"Inbox lost");check(session.local().mailboxIndex(true).size()==1,"Sent lost");
    var item=session.local().inbox().getFirst();try(var plain=new AutomaticEncryption(Clock.systemUTC()).decrypt(session.local().load(item.messageId()),session.local().identity(),config.maxFileSize());var opened=LetterEnvelope.open(plain.letterEnvelope(),"letter-password-0300".toCharArray())){check(opened.candidate("code-0300".toCharArray()).equals("Письмо 0.3.0"),"Old letter unreadable");check(plain.files().size()==1&&plain.fileSize()==4,"Old attachment lost");}
   }
   check(LocalStore.modernVault(config.storagePath()),"KDF migration not committed");check(Arrays.equals(configBefore,Files.readAllBytes(AppPaths.config())),"Onion/config changed");
   try(var reopened=AccountLogin.open(config,"blackfox",account,null)){check(reopened.local().identity().userId().equals(id),"Single-password restart failed");check(reopened.local().contacts().size()==11,"Restart lost contacts");}
   check(Files.readString(AppPaths.config()).contains(SocksHarness.RELAY),"Saved onion lost");
   System.out.println("Actual 0.3.0 profile -> 1.0.0 passed: unchanged relay 0.2.0, account, identity, 11 contacts, inbox, sent, attachment, onion/config, full encrypted backup, one-time old-password migration, subsequent single-password login, rejected wrong account cannot migrate");
  }finally{relay.destroy();if(!relay.waitFor(5,TimeUnit.SECONDS))relay.destroyForcibly();}
 }
}
