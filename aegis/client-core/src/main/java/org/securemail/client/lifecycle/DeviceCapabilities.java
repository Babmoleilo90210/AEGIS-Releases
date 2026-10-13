package org.securemail.client.lifecycle;

import java.io.*;
import java.security.*;
import java.util.*;
import org.securemail.client.crypto.Identity;
import org.securemail.protocol.*;

/** Account-signed, challenge-bound advertisement of client-only lifecycle support.
 * Virtual onion port 81 is advertised in the existing signed Route. Port 80 remains usable. */
public record DeviceCapabilities(String ownerId,byte[] rootKey,byte[] deviceKey,long expiresAt,int flags,byte[] challenge,byte[] signature) {
  public static final int ONION_PORT=81,OPERATION=100,FRIENDS=1,RECEIPTS=2,EXPIRING=4;
  public DeviceCapabilities {
    Limits.userId(ownerId);if(rootKey.length!=44||deviceKey.length!=44||expiresAt<1||(flags&~7)!=0||challenge.length!=32||signature.length!=0&&signature.length!=64)throw new IllegalArgumentException("Capability fields");
    rootKey=rootKey.clone();deviceKey=deviceKey.clone();challenge=challenge.clone();signature=signature.clone();
  }
  public byte[] rootKey(){return rootKey.clone();}public byte[] deviceKey(){return deviceKey.clone();}public byte[] challenge(){return challenge.clone();}public byte[] signature(){return signature.clone();}
  private void unsigned(DataOutput o)throws IOException {Binary.text(o,ownerId);Binary.bytes(o,rootKey);Binary.bytes(o,deviceKey);o.writeLong(expiresAt);o.writeInt(flags);Binary.bytes(o,challenge);}
  public byte[] signingBytes()throws IOException{return Binary.encode(o->{Binary.text(o,"AEGIS-CLIENT-CAPABILITIES-v1");unsigned(o);});}
  public static DeviceCapabilities create(Identity root,Identity device,long expires,int flags,byte[] challenge)throws IOException,GeneralSecurityException {
    var p=new DeviceCapabilities(root.userId(),root.publicKey(),device.publicKey(),expires,flags,challenge,new byte[0]);return new DeviceCapabilities(p.ownerId,p.rootKey,p.deviceKey,expires,flags,challenge,root.sign(p.signingBytes()));
  }
  public void verify(UserInfo owner,byte[] expectedChallenge,long now)throws IOException,GeneralSecurityException {
    if(!owner.userId().equals(ownerId)||!Identity.id(rootKey).equals(ownerId)||!MessageDigest.isEqual(owner.publicKey(),rootKey)||expiresAt<=now||expiresAt>now+31L*86400_000||expectedChallenge!=null&&!MessageDigest.isEqual(challenge,expectedChallenge)||!Identity.verify(rootKey,signingBytes(),signature))throw new GeneralSecurityException("Unverified client capabilities");
  }
  public boolean supports(int capability){return (flags&capability)==capability;}
  public void write(DataOutput o)throws IOException{o.writeInt(1);unsigned(o);Binary.bytes(o,signature);}
  public static DeviceCapabilities read(DataInput i)throws IOException {if(i.readInt()!=1)throw new IOException("Capability schema");try{return new DeviceCapabilities(Binary.text(i,64),Binary.bytes(i,44),Binary.bytes(i,44),i.readLong(),i.readInt(),Binary.bytes(i,32),Binary.bytes(i,64));}catch(IllegalArgumentException bad){throw new IOException("Capability fields",bad);}}
}
