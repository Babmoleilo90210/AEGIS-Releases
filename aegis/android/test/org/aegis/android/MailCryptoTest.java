package org.aegis.android;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Clock;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.securemail.client.crypto.*;
import org.securemail.client.crypto.Identity;
import org.securemail.protocol.*;

/** Actual host JNI/libsodium/AEGIS wire crypto, not ARM64 or Tor acceptance. */
public final class MailCryptoTest {
    static int count;interface Checked{void run()throws Exception;}
    static void test(String name,Checked t)throws Exception{t.run();System.out.println("PASS "+name);count++;}
    static void require(boolean b){if(!b)throw new AssertionError();}
    static void reject(Checked t)throws Exception{try{t.run();}catch(Exception expected){return;}throw new AssertionError("Accepted invalid input");}
    static byte[] backup(Identity a,Identity b,boolean modern,char[] password)throws Exception {
        byte[] salt=Secrets.random(16),state=Binary.encode(out->{out.writeInt(1);Binary.bytes(out,a.publicKey());Binary.bytes(out,a.privateKey());Binary.text(out,"alice");out.writeLong(System.currentTimeMillis());out.writeInt(1);new UserInfo(b.userId(),"bob",b.publicKey(),null).write(out);out.writeInt(0);});byte[] key=modern?Secrets.deriveVault(password,salt):Secrets.derive(password,salt);byte[] nonce=Secrets.random(12);try{Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD("state/v1".getBytes(StandardCharsets.US_ASCII));byte[] encrypted=c.doFinal(state),sealed=new byte[12+encrypted.length];System.arraycopy(nonce,0,sealed,0,12);System.arraycopy(encrypted,0,sealed,12,encrypted.length);return Binary.encode(out->{out.writeInt(modern?0x41454232:0x41454231);Binary.bytes(out,salt);Binary.bytes(out,sealed);});}finally{Arrays.fill(key,(byte)0);Arrays.fill(state,(byte)0);}
    }
    public static void main(String[]args)throws Exception {
        Identity a=Identity.create(),b=Identity.create(),c=Identity.create();UserInfo recipient=new UserInfo(b.userId(),"bob",b.publicKey(),null);AutomaticEncryption crypto=new AutomaticEncryption(Clock.systemUTC());EncryptedPacket packet;try(PlainMessage message=PlainMessage.text("Проверка реального E2EE · Android JNI")){packet=crypto.encrypt(message,3600,3600000,a,"alice",recipient);}
        test("actual JNI/libsodium recipient decrypt",()->{try(PlainMessage m=crypto.decrypt(packet,b,128*1024)){require(m.text().equals("Проверка реального E2EE · Android JNI"));}});
        test("actual JNI/libsodium sender copy decrypt",()->{try(PlainMessage m=crypto.decrypt(packet,a,128*1024)){require(m.text().contains("E2EE"));}});
        test("unrelated identity cannot decrypt",()->reject(()->crypto.decrypt(packet,c,128*1024)));
        test("existing packet codec wire roundtrip",()->{byte[] wire=PacketCodec.encode(packet);require(Arrays.equals(wire,PacketCodec.encode(PacketCodec.decode(wire,192*1024))));require(Identity.verifyPacket(PacketCodec.decode(wire,192*1024)));});
        test("AEGIS02A marker retained",()->require(AutomaticEncryption.supports(packet)&&packet.ciphertext().length>=180));
        test("ciphertext mutation signature rejected",()->{byte[] cipher=packet.ciphertext();cipher[cipher.length-1]^=1;EncryptedPacket altered=new EncryptedPacket(packet.messageId(),packet.senderId(),packet.senderNickname(),packet.recipientId(),packet.createdAt(),packet.deliveryDeadline(),packet.ttlAfterDelivery(),packet.algorithm(),packet.salt(),packet.nonce(),cipher,packet.senderPublicKey(),packet.signature());reject(()->crypto.decrypt(altered,b,128*1024));});
        test("authenticated invalid sealed box fails closed",()->{byte[] cipher=packet.ciphertext();cipher[20]^=1;EncryptedPacket altered=a.signPacket(new EncryptedPacket(packet.messageId(),packet.senderId(),packet.senderNickname(),packet.recipientId(),packet.createdAt(),packet.deliveryDeadline(),packet.ttlAfterDelivery(),packet.algorithm(),packet.salt(),packet.nonce(),cipher,packet.senderPublicKey(),new byte[0]));reject(()->crypto.decrypt(altered,b,128*1024));});
        test("invalid Ed25519 recipient point rejected by libsodium",()->{byte[] publicKey=b.publicKey();Arrays.fill(publicKey,12,44,(byte)0);UserInfo bad=new UserInfo(Identity.id(publicKey),"bad",publicKey,null);try(PlainMessage m=PlainMessage.text("test")){reject(()->crypto.encrypt(m,60,60000,a,"alice",bad));}});
        test("fresh keys and nonce for independent messages",()->{try(PlainMessage m=PlainMessage.text("same")){EncryptedPacket p=crypto.encrypt(m,60,60000,a,"alice",recipient);require(!Arrays.equals(p.nonce(),packet.nonce())&&!Arrays.equals(p.ciphertext(),packet.ciphertext())&&!p.messageId().equals(packet.messageId()));}});
        test("PlainMessage v1 unchanged wire body",()->{try(PlainMessage m=PlainMessage.text("abc")){byte[] expected=Binary.encode(out->{out.writeInt(1);Binary.bytes(out,"abc".getBytes(StandardCharsets.UTF_8));Binary.text(out,"");Binary.bytes(out,new byte[0]);});require(Arrays.equals(expected,m.encode()));}});
        byte[] protectedEnvelope=LetterEnvelope.seal("Защищённое письмо Android/ПК", "test-letter-password".toCharArray(),"code-FF1-test".toCharArray());
        test("existing password and FF1 protected envelope roundtrip",()->{try(var opened=LetterEnvelope.open(protectedEnvelope,"test-letter-password".toCharArray())){require(opened.candidate("code-FF1-test".toCharArray()).equals("Защищённое письмо Android/ПК"));}});
        test("wrong letter password fails authenticated outer layer",()->reject(()->LetterEnvelope.open(protectedEnvelope,"wrong-letter-password".toCharArray())));
        test("wrong FF1 code computes candidate without validation oracle",()->{try(var opened=LetterEnvelope.open(protectedEnvelope,"test-letter-password".toCharArray())){String candidate=opened.candidate("another-FF1-code".toCharArray());require(candidate!=null&&!candidate.equals("Защищённое письмо Android/ПК"));}});
        test("protected letter remains inside unchanged signed E2EE packet",()->{try(PlainMessage message=PlainMessage.letter("Тема",protectedEnvelope,null,0)){EncryptedPacket protectedPacket=crypto.encrypt(message,60,60000,a,"alice",recipient);try(PlainMessage clear=crypto.decrypt(protectedPacket,b,128*1024)){require(clear.protectedLetter()&&clear.subject().equals("Тема"));byte[] bytes=clear.letterEnvelope();try(var opened=LetterEnvelope.open(bytes,"test-letter-password".toCharArray())){require(opened.candidate("code-FF1-test".toCharArray()).equals("Защищённое письмо Android/ПК"));}finally{Arrays.fill(bytes,(byte)0);}}}});
        Arrays.fill(protectedEnvelope,(byte)0);
        char[] password="aegis-test-password-only".toCharArray();byte[] modern=backup(a,b,true,password),legacy=backup(a,b,false,password);
        test("AEB2 exact protected identity and contact import",()->{char[] pass=password.clone();try(MailBackup m=MailBackup.read(new ByteArrayInputStream(modern),pass,a.userId())){require(m.identity.userId().equals(a.userId())&&m.contacts.size()==1&&m.contacts.get(0).userId().equals(b.userId()));}for(char ch:pass)require(ch==0);});
        test("AEB1 existing legacy KDF import",()->{try(MailBackup m=MailBackup.read(new ByteArrayInputStream(legacy),password.clone(),a.userId())){require(m.identity.userId().equals(a.userId()));}});
        test("AEB2 wrong password rejected",()->reject(()->MailBackup.read(new ByteArrayInputStream(modern),"wrong-password-only".toCharArray(),a.userId())));
        test("cross-account root import forbidden",()->reject(()->MailBackup.read(new ByteArrayInputStream(modern),password.clone(),b.userId())));
        test("modified encrypted backup rejected",()->{byte[] corrupt=modern.clone();corrupt[corrupt.length-1]^=1;reject(()->MailBackup.read(new ByteArrayInputStream(corrupt),password.clone(),a.userId()));});
        test("backup trailing data rejected",()->reject(()->MailBackup.read(new ByteArrayInputStream(Arrays.copyOf(modern,modern.length+1)),password.clone(),a.userId())));
        test("backup stream bound enforced",()->reject(()->MailBackup.read(new ByteArrayInputStream(new byte[2*1024*1024+129]),password.clone(),a.userId())));
        test("hex API33 formatting matches existing SHA256 identity",()->require(AndroidHex.INSTANCE.formatHex(MessageDigest.getInstance("SHA-256").digest(a.publicKey())).equals(a.userId())));
        Arrays.fill(password,'\0');Arrays.fill(modern,(byte)0);Arrays.fill(legacy,(byte)0);System.out.println("MailCryptoTest: "+count+" actual host tests PASS; Android ARM64/device/Tor NOT_RUN");
    }
}
