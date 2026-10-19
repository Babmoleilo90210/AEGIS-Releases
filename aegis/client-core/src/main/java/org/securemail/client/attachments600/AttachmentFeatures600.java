package org.securemail.client.attachments600;

import java.io.*;
import java.security.*;
import java.util.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.net.NetworkService;
import org.securemail.protocol.*;

/** New typed operation; legacy operation100/schema1 and Relay protocol1 stay unchanged. */
public record AttachmentFeatures600(String accountId,byte[] rootPublic,String serviceAudience,long maximumBytes,long expiresAt,byte[] challenge,byte[] signature) {
  public static final int OPERATION=102;
  public AttachmentFeatures600 {Limits.userId(accountId);if(rootPublic.length!=44||!serviceAudience.matches("[a-f0-9]{64}")||maximumBytes<1||maximumBytes>StreamingAttachmentCipher.MAX_PLAINTEXT||expiresAt<1||challenge.length!=32||signature.length!=0&&signature.length!=64)throw new IllegalArgumentException("Возможности вложений");rootPublic=rootPublic.clone();challenge=challenge.clone();signature=signature.clone();}
  public byte[] rootPublic(){return rootPublic.clone();}public byte[] challenge(){return challenge.clone();}public byte[] signature(){return signature.clone();}
  private void unsigned(DataOutput out)throws IOException{Binary.text(out,accountId);Binary.bytes(out,rootPublic);Binary.text(out,serviceAudience);out.writeLong(maximumBytes);out.writeLong(expiresAt);Binary.bytes(out,challenge);}
  public byte[] signingBytes()throws IOException{return Binary.encode(o->{Binary.text(o,"AEGIS-ATTACHMENT-FEATURES/v1");unsigned(o);});}
  public void write(DataOutput o)throws IOException{o.writeInt(1);unsigned(o);Binary.bytes(o,signature);}
  public static AttachmentFeatures600 read(DataInput i)throws IOException{if(i.readInt()!=1)throw new IOException("Версия возможностей вложений");try{return new AttachmentFeatures600(Binary.text(i,64),Binary.bytes(i,44),Binary.text(i,64),i.readLong(),i.readLong(),Binary.bytes(i,32),Binary.bytes(i,64));}catch(IllegalArgumentException e){throw new IOException("Возможности вложений",e);}}
  public static AttachmentFeatures600 sign(Identity root,String audience,byte[] challenge,long now)throws IOException,GeneralSecurityException{var unsigned=new AttachmentFeatures600(root.userId(),root.publicKey(),audience,StreamingAttachmentCipher.MAX_PLAINTEXT,now+60000,challenge,new byte[0]);return new AttachmentFeatures600(unsigned.accountId,unsigned.rootPublic,audience,unsigned.maximumBytes,unsigned.expiresAt,challenge,root.sign(unsigned.signingBytes()));}
  public void verify(UserInfo pinned,String audience,byte[] expected,long now)throws IOException,GeneralSecurityException {if(!accountId.equals(pinned.userId())||!Identity.id(rootPublic).equals(accountId)||!MessageDigest.isEqual(rootPublic,pinned.publicKey())||!serviceAudience.equals(audience)||expiresAt<=now||expiresAt>now+120000||!MessageDigest.isEqual(challenge,expected)||!Identity.verify(rootPublic,signingBytes(),signature))throw new GeneralSecurityException("Получатель не подтвердил потоковые вложения 6.0");}
  public static AttachmentFeatures600 probe(NetworkService network,UserInfo contact,String audience,long now)throws IOException,GeneralSecurityException {
    byte[] challenge=org.securemail.client.crypto.Secrets.random(32);
    try(var socket=network.connectVoice(contact);var in=new DataInputStream(new BufferedInputStream(socket.getInputStream()));var out=new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))){socket.setSoTimeout(20000);Binary.header(out);out.writeByte(OPERATION);Binary.text(out,"");Binary.bytes(out,challenge);out.flush();Binary.header(in);if(in.readInt()!=0)throw new IOException("Получатель должен открыть Почту АЕГИС 6.0 с настроенным сервером вложений");var answer=read(in);answer.verify(contact,audience,challenge,now);return answer;}catch(IOException unavailable){throw new IOException("Потоковые вложения недоступны: получатель должен открыть Почту АЕГИС 6.0 с тем же доверенным сервером вложений.",unavailable);}
  }
}
