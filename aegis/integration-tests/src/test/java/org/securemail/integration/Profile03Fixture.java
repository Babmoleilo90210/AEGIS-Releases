package org.securemail.integration;
import java.nio.file.*;
import java.time.Clock;
import org.securemail.client.*;
import org.securemail.client.crypto.*;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;
/** Executed with actual released 0.3.0 JARs, not the new LocalStore. */
public final class Profile03Fixture {
 public static void main(String[] args)throws Exception{
  Path root=Path.of(args[0]),profile=root.resolve("data");System.setProperty("aegis.profile",root.toString());
  ClientConfig c=ClientConfig.load(root.resolve("empty.properties"));c=new ClientConfig("127.0.0.1",Integer.parseInt(args[1]),19051,c.torCookiePath(),19120,1800,SocksHarness.RELAY,80,profile,16*1024*1024,32*1024*1024,604800000);c.save(AppPaths.config());
  char[] old="separate-vault-password-0300".toCharArray(),account="account-password-1000".toCharArray();
  try(var local=new LocalStore(profile,old,Clock.systemUTC(),c.maxCiphertext(),c.maxLocalStorage())){
   var network=new NetworkService(new TorTransport("127.0.0.1",c.torSocksPort()),SocksHarness.RELAY,80,local,c.maxCiphertext());network.authenticate("blackfox",account,true);
   Identity raven=Identity.create();local.trust(new UserInfo(raven.userId(),"raven",raven.publicKey(),null));
   for(int i=1;i<=10;i++){Identity contact=Identity.create();local.trust(new UserInfo(contact.userId(),String.format("contact%02d",i),contact.publicKey(),null));}
   Path file=root.resolve("old-file.zip");Files.write(file,new byte[]{1,3,5,7});var crypto=new AutomaticEncryption(Clock.systemUTC());
   try(var plain=PlainMessage.letter("Old inbox",LetterEnvelope.seal("Письмо 0.3.0","letter-password-0300".toCharArray(),"code-0300".toCharArray()),file,c.maxFileSize())){var packet=crypto.encrypt(plain,604800,604800000,raven,"raven",new UserInfo(local.identity().userId(),"blackfox",local.identity().publicKey(),null));local.accept(packet);}
   try(var plain=PlainMessage.letter("Old sent",LetterEnvelope.seal("Sent 0.3.0","letter-password-0300".toCharArray(),"code-0300".toCharArray()),file,c.maxFileSize())){var packet=crypto.encrypt(plain,604800,604800000,local.identity(),"blackfox",new UserInfo(raven.userId(),"raven",raven.publicKey(),null));local.saveSent(packet,"raven",System.currentTimeMillis());}
   Files.writeString(root.resolve("expected-id"),local.identity().userId());network.forgetSession();
  }
 }
}
