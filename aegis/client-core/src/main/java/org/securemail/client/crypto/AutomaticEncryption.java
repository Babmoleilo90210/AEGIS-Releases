package org.securemail.client.crypto;
import java.io.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.securemail.protocol.*;
/** E2EE content extension carried unchanged by protocol-1 relays. AES key wrapped by libsodium sealed boxes. */
public final class AutomaticEncryption {
  private static final byte[] MARKER="AEGIS02A".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
  private final Clock clock;
  public AutomaticEncryption(Clock clock){this.clock=clock;}
  public static boolean supports(EncryptedPacket packet){return packet.algorithm()==Algorithm.AES_256_GCM&&packet.salt().length==16&&Arrays.equals(Arrays.copyOf(packet.salt(),8),MARKER);}
  public EncryptedPacket encrypt(PlainMessage message,long ttl,long delivery,Identity sender,String nick,UserInfo recipient) throws Exception {
    if(!Identity.id(recipient.publicKey()).equals(recipient.userId()))throw new GeneralSecurityException("Invalid recipient");
    byte[] key=Secrets.random(32),salt=Secrets.random(16),nonce=Secrets.random(12),plain=null;
    System.arraycopy(MARKER,0,salt,0,8);long now=clock.millis();
    var p=new EncryptedPacket(UUID.randomUUID().toString(),sender.userId(),nick,recipient.userId(),now,Math.addExact(now,delivery),ttl,Algorithm.AES_256_GCM,salt,nonce,new byte[16],sender.publicKey(),new byte[0]);
    try{
      byte[] forRecipient=SodiumBox.seal(key,recipient.publicKey()),forSender=SodiumBox.seal(key,sender.publicKey());
      plain=message.encode();var cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(PacketCodec.associatedData(p));byte[] ciphertext=cipher.doFinal(plain);
      byte[] payload=Binary.encode(out->{out.writeInt(0x4145324b);out.write(forRecipient);out.write(forSender);out.write(ciphertext);});
      return sender.signPacket(new EncryptedPacket(p.messageId(),p.senderId(),nick,p.recipientId(),now,p.deliveryDeadline(),ttl,p.algorithm(),salt,nonce,payload,sender.publicKey(),new byte[0]));
    }finally{Arrays.fill(key,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);}
  }
  public PlainMessage decrypt(EncryptedPacket p,Identity identity,int maxFile) throws Exception {
    if(!supports(p)||!Identity.verifyPacket(p))throw new GeneralSecurityException("Неверная подпись сообщения");
    boolean recipient=p.recipientId().equals(identity.userId());if(!recipient&&!p.senderId().equals(identity.userId()))throw new GeneralSecurityException("Другой получатель");
    byte[] key=null,plain=null;
    try(var input=new DataInputStream(new ByteArrayInputStream(p.ciphertext()))){
      if(input.readInt()!=0x4145324b)throw new GeneralSecurityException("Неверный формат E2EE");
      byte[] toRecipient=new byte[80],toSender=new byte[80];input.readFully(toRecipient);input.readFully(toSender);
      key=SodiumBox.open(recipient?toRecipient:toSender,identity);var cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,p.nonce()));cipher.updateAAD(PacketCodec.associatedData(p));plain=cipher.doFinal(input.readAllBytes());return PlainMessage.decode(plain,maxFile);
    }finally{if(key!=null)Arrays.fill(key,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);}
  }
}
