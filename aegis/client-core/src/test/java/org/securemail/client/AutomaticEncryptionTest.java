package org.securemail.client;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.client.storage.*;
import org.securemail.client.net.*;
import org.securemail.protocol.*;
class AutomaticEncryptionTest {
 @TempDir Path temp;
 @Test void recipientSenderWrongIdentityTamperAndNonce()throws Exception{
  var a=Identity.create();var b=Identity.create();var c=Identity.create();var service=new AutomaticEncryption(Clock.systemUTC());var user=new UserInfo(b.userId(),"blackfox",b.publicKey(),null);EncryptedPacket p,q;
  try(var text=PlainMessage.text("PRIVATE-E2EE-TEXT-539712")){p=service.encrypt(text,60,86400000,a,"raven",user);q=service.encrypt(text,60,86400000,a,"raven",user);}
  assertFalse(Arrays.equals(p.nonce(),q.nonce()));assertFalse(Arrays.equals(p.ciphertext(),q.ciphertext()));
  for(var identity:List.of(a,b))try(var plain=service.decrypt(p,identity,1_000_000)){assertEquals("PRIVATE-E2EE-TEXT-539712",plain.text());}
  assertThrows(java.security.GeneralSecurityException.class,()->service.decrypt(p,c,1_000_000));
  assertFalse(new String(PacketCodec.encode(p),StandardCharsets.ISO_8859_1).contains("PRIVATE-E2EE-TEXT-539712"));
  byte[] changed=p.ciphertext();changed[changed.length-1]^=1;
  var tampered=a.signPacket(new EncryptedPacket(p.messageId(),p.senderId(),p.senderNickname(),p.recipientId(),p.createdAt(),p.deliveryDeadline(),p.ttlAfterDelivery(),p.algorithm(),p.salt(),p.nonce(),changed,p.senderPublicKey(),new byte[0]));
  assertThrows(java.security.GeneralSecurityException.class,()->service.decrypt(tampered,b,1_000_000));
 }
 @Test void encryptedHistoryBackupRestoresOriginalIdentityAndPassword()throws Exception{
  char[] pwd="different vault password 246".toCharArray();Path root=temp.resolve("profile"),backup=temp.resolve("identity.aegis-backup");String original;
  try(var store=new LocalStore(root,pwd,Clock.systemUTC(),200000,1000000)){
   original=store.identity().userId();store.bindNickname("raven");var other=Identity.create();var contact=new UserInfo(other.userId(),"blackfox",other.publicKey(),null);store.trust(contact);
   try(var text=PlainMessage.text("NEVER-PERSIST-PLAINTEXT-1199")){var p=new AutomaticEncryption(Clock.systemUTC()).encrypt(text,60,60000,store.identity(),"raven",contact);store.saveSent(p,"blackfox",System.currentTimeMillis());assertEquals(1,store.history("blackfox").size());}
   store.exportIdentity(backup);
   try(var files=Files.walk(root)){for(var p:files.filter(Files::isRegularFile).toList())assertFalse(new String(Files.readAllBytes(p),StandardCharsets.ISO_8859_1).contains("NEVER-PERSIST-PLAINTEXT-1199"));}
  }
  Path target=temp.resolve("restore");LocalStore.restoreIdentity(backup,target,pwd,200000,1000000);
  try(var store=new LocalStore(target,pwd,Clock.systemUTC(),200000,1000000)){assertEquals(original,store.identity().userId());assertEquals("raven",store.nickname());assertNotNull(store.contact("blackfox"));}
  assertThrows(java.security.GeneralSecurityException.class,()->LocalStore.restoreIdentity(backup,temp.resolve("wrong"),"wrong password".toCharArray(),200000,1000000));
 }
 @Test void rejectsAmbiguousSnowflakeFront()throws Exception{Path f=temp.resolve("bridges");Files.writeString(f,"snowflake 192.0.2.3:80 front=example.com,example.org\n");assertThrows(java.io.IOException.class,()->EmbeddedTor.bridges(f));Files.writeString(f,"snowflake 192.0.2.3:80 fronts=example.com,example.org\n");assertEquals(1,EmbeddedTor.bridges(f).size());}
 @Test void torUnavailableFailClosedBeforeSocket()throws Exception{TorTransport.requireAvailability(()->false);try{assertThrows(java.io.IOException.class,()->new TorTransport("127.0.0.1",19050).connect("a".repeat(56)+".onion",80));}finally{TorTransport.requireAvailability(()->true);}}
 @Test void rejectsWindowsTraversalAndDevices(){for(String n:List.of("CON.txt","NUL.zip","A.txt:stream","../a.zip","a.zip ","LPT1.zip"))assertThrows(IllegalArgumentException.class,()->PlainMessage.validateFilename(n));}
}
