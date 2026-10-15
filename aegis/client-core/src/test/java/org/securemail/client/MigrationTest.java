package org.securemail.client;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.storage.*;
import org.securemail.client.crypto.*;
import org.securemail.protocol.*;
class MigrationTest {
 @TempDir Path root;
 @Test void distinctVaultKeyAndVerifiedFullRekey()throws Exception{
  char[] before="old-vault-password-1000".toCharArray(),account="new-account-password-1000".toCharArray();byte[] salt=Secrets.random(16);assertFalse(Arrays.equals(Secrets.derive(account,salt),Secrets.deriveVault(account,salt)));
  Path profile=root.resolve("profile"),next=root.resolve("profile.migration-1000");String id;EncryptedPacket packet;
  try(var store=new LocalStore(profile,before,Clock.systemUTC(),200000,1000000)){
   id=store.identity().userId();store.bindNickname("blackfox");Identity contact=Identity.create();UserInfo raven=new UserInfo(contact.userId(),"raven",contact.publicKey(),null);store.trust(raven);
   try(var text=PlainMessage.letter("Subject",LetterEnvelope.seal("Preserve me","letter-password".toCharArray(),"code".toCharArray()),null,10000)){packet=new AutomaticEncryption(Clock.systemUTC()).encrypt(text,86400,604800000,contact,"raven",new UserInfo(store.identity().userId(),"blackfox",store.identity().publicKey(),null));}
   store.accept(packet);try(var text=PlainMessage.text("Sent legacy")){var outgoing=new AutomaticEncryption(Clock.systemUTC()).encrypt(text,86400,604800000,store.identity(),"blackfox",raven);store.saveSent(outgoing,"raven",System.currentTimeMillis());}
   store.rekeyCopy(next,account);
  }
  ClientUpgrade.commit(profile,next);
  try(var store=new LocalStore(profile,account,Clock.systemUTC(),200000,1000000)){assertEquals(id,store.identity().userId());assertEquals("blackfox",store.nickname());assertNotNull(store.contact("raven"));assertEquals(1,store.inbox().size());assertEquals(1,store.mailboxIndex(true).size());assertArrayEquals(Identity.digest(packet),Identity.digest(store.load(packet.messageId())));}
  assertThrows(javax.crypto.AEADBadTagException.class,()->new LocalStore(profile,before,Clock.systemUTC(),200000,1000000));
 }
 @Test void crashBetweenRenamesRestoresOldProfile()throws Exception{
  Path profile=root.resolve("profile"),old=root.resolve("profile.pre-migration-test");Files.createDirectory(old);Files.writeString(old.resolve("state.vault"),"sealed-old");Files.writeString(root.resolve("profile.migration-journal"),old.getFileName()+"\nprofile.migration-stage\n");
  ClientUpgrade.recover(profile);assertEquals("sealed-old",Files.readString(profile.resolve("state.vault")));assertFalse(Files.exists(root.resolve("profile.migration-journal")));
 }
 @Test void malformedJournalCannotMoveOutsideProfile()throws Exception{
  Path profile=root.resolve("profile");Files.createDirectory(profile);Files.writeString(profile.resolve("state.vault"),"old");Files.writeString(root.resolve("profile.migration-journal"),"../outside\nprofile.migration-stage\n");assertThrows(java.io.IOException.class,()->ClientUpgrade.recover(profile));assertEquals("old",Files.readString(profile.resolve("state.vault")));
 }
}
