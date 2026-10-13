package org.securemail.client.lifecycle;

import java.io.*;
import java.security.*;
import java.util.*;
import org.securemail.client.crypto.*;
import org.securemail.client.crypto.Identity;
import org.securemail.protocol.*;

/** Ciphertext nested in the unchanged version-1 E2EE payload. Legacy clients only see instructions.
 * The actual content is sealed to one advertised device, not every account backup/device. */
public record ExpiringEnvelope(long seconds,String deviceId,EncryptedPacket inner) {
  public static final String MARKER="AEGIS-EXPIRING-DEVICE-v1",FILENAME="aegis-expiring-ciphertext.txt";
  public ExpiringEnvelope {if(seconds<60||seconds>30L*86400)throw new IllegalArgumentException("Expiry duration");Limits.userId(deviceId);if(!inner.recipientId().equals(deviceId))throw new IllegalArgumentException("Expiry device");}
  public byte[] encode()throws IOException{return Binary.encode(o->{o.writeInt(1);o.writeLong(seconds);Binary.text(o,deviceId);PacketCodec.write(o,inner);});}
  public PlainMessage carrier()throws IOException {return new PlainMessage((MARKER+"\nИсчезающее письмо. Откройте его в АЕГИС 1.2.0 на выбранном устройстве.").getBytes(java.nio.charset.StandardCharsets.UTF_8),FILENAME,encode());}
  public static boolean isCarrier(PlainMessage plain){return plain.text().startsWith(MARKER+"\n")&&plain.files().size()==1&&plain.filename().equals(FILENAME);}
  public static ExpiringEnvelope read(PlainMessage plain,int max)throws IOException {
    if(!isCarrier(plain))return null;byte[] bytes=plain.attachmentBytes(FILENAME);
    try(var in=new DataInputStream(new ByteArrayInputStream(bytes))){if(in.readInt()!=1)throw new IOException("Expiry schema");var result=new ExpiringEnvelope(in.readLong(),Binary.text(in,64),PacketCodec.read(in,max));Binary.end(in);return result;}catch(IllegalArgumentException bad){throw new IOException("Expiry fields",bad);}finally{Arrays.fill(bytes,(byte)0);}
  }
  public void verify(EncryptedPacket outer)throws IOException,GeneralSecurityException {if(!inner.senderId().equals(outer.senderId())||!inner.senderNickname().equals(outer.senderNickname())||!MessageDigest.isEqual(inner.senderPublicKey(),outer.senderPublicKey())||!Identity.verifyPacket(inner)||!AutomaticEncryption.supports(inner)||inner.createdAt()>outer.createdAt()||outer.createdAt()-inner.createdAt()>300_000)throw new GeneralSecurityException("Expiry envelope origin");}
}
