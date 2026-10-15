package org.securemail.client;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.*;
import org.securemail.client.crypto.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;
class LetterTest {
 @TempDir Path temp;
 private static final char[] PASSWORD="Frost-8134".toCharArray(), CODE="Raven-821".toCharArray();
 @Test void nistFf1KnownVector(){
   byte[] digits={0,1,2,3,4,5,6,7,8,9},result=new byte[10];
   var engine=new FPEFF1Engine();
   engine.init(true,new FPEParameters(new KeyParameter(HexFormat.of().parseHex("2B7E151628AED2A6ABF7158809CF4F3C")),10,new byte[0]));
   engine.processBlock(digits,0,10,result,0);
   assertArrayEquals(new byte[]{2,4,3,3,4,7,7,4,8,4},result);
 }
 @Test void unicodeShortAndEmptyRoundTrip()throws Exception{
   for(String text:List.of("Письмо 🦊\n雪 العربية e\u0301","Я","","x")){
     byte[] packet=LetterEnvelope.seal(text,PASSWORD,CODE);
     try(var opened=LetterEnvelope.open(packet,PASSWORD)){assertEquals(text,opened.candidate(CODE));}
   }
 }
 @Test void outerAuthenticationBeforeInnerAndFreshParameters()throws Exception{
   byte[] a=LetterEnvelope.seal("secret",PASSWORD,CODE),b=LetterEnvelope.seal("secret",PASSWORD,CODE);
   assertFalse(Arrays.equals(a,b));
   assertThrows(AEADBadTagException.class,()->LetterEnvelope.open(a,"wrong-password".toCharArray()));
   a[a.length-1]^=1;assertThrows(AEADBadTagException.class,()->LetterEnvelope.open(a,PASSWORD));
   try(var x=new DataInputStream(new ByteArrayInputStream(b))){
     x.readInt();x.readInt();assertEquals(16,Binary.bytes(x,16).length);assertEquals(12,Binary.bytes(x,12).length);
   }
 }
 @Test void everyCodeComputesCandidateWithoutInnerVerifier()throws Exception{
   byte[] a=LetterEnvelope.seal("Секретный текст с несколькими строками\nHello",PASSWORD,CODE);
   try(var opened=LetterEnvelope.open(a,PASSWORD)){
     var candidates=new HashSet<String>();
     for(String code:List.of("R","Ra","Rav","Rave","wrong","Raven-821"))candidates.add(assertDoesNotThrow(()->opened.candidate(code.toCharArray())));
     assertEquals(6,candidates.size());assertEquals("Секретный текст с несколькими строками\nHello",opened.candidate(CODE));
     opened.close();assertThrows(IllegalStateException.class,opened::ciphertext);
   }
 }
 @Test void protectedContentInsideUnchangedE2eeAndAttachmentAndOldContent()throws Exception{
   var sender=Identity.create();var receiver=Identity.create();var user=new UserInfo(receiver.userId(),"blackfox",receiver.publicKey(),null);
   var crypto=new AutomaticEncryption(Clock.systemUTC());String marker="V3-LOCAL-ONLY-"+UUID.randomUUID();
   Path file=temp.resolve("archive.zip");byte[] contents=(marker+"-file").getBytes(StandardCharsets.UTF_8);Files.write(file,contents);
   byte[] letter=LetterEnvelope.seal(marker,PASSWORD,CODE);EncryptedPacket packet;
   try(var message=PlainMessage.letter("Тема",letter,file,10000)){packet=crypto.encrypt(message,60,60000,sender,"raven",user);}
   for(var identity:List.of(sender,receiver))try(var message=crypto.decrypt(packet,identity,10000)){
     assertTrue(message.protectedLetter());assertEquals("Тема",message.subject());
     try(var opened=LetterEnvelope.open(message.letterEnvelope(),PASSWORD)){assertEquals(marker,opened.candidate(CODE));}
     Path saved=temp.resolve(identity.userId()+".zip");message.exportTo(saved);assertArrayEquals(contents,Files.readAllBytes(saved));
   }
   String wire=new String(PacketCodec.encode(packet),StandardCharsets.ISO_8859_1);
   assertFalse(wire.contains(marker));assertFalse(wire.contains(new String(PASSWORD)));assertFalse(wire.contains(new String(CODE)));
   try(var old=PlainMessage.text("Old 0.2 content");var decoded=PlainMessage.decode(old.encode(),10000)){assertFalse(decoded.protectedLetter());assertEquals("Old 0.2 content",decoded.text());}
 }
 @Test void modernIdentityBackupPreservesKdf()throws Exception{
   Path profile=temp.resolve("existing");String id;char[] password="existing-account-password".toCharArray();Path saved=temp.resolve("identity.aegis-backup");
   try(var store=new LocalStore(profile,password,Clock.systemUTC(),200000,1000000)){id=store.identity().userId();store.bindNickname("raven");store.exportIdentity(saved);}
   assertTrue(LocalStore.modernVault(profile));LocalStore.restoreIdentity(saved,temp.resolve("restored"),password,200000,1000000);
   try(var store=new LocalStore(temp.resolve("restored"),password,Clock.systemUTC(),200000,1000000)){assertEquals(id,store.identity().userId());assertEquals("raven",store.nickname());assertTrue(LocalStore.modernVault(temp.resolve("restored")));}
 }
}
