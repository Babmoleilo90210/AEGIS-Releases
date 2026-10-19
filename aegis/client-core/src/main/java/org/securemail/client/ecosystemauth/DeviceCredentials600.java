package org.securemail.client.ecosystemauth;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Only the device private key is owned by Core. The account and recovery keys here are PUBLIC. */
public final class DeviceCredentials600 implements AutoCloseable {
  private final byte[] accountPublic,devicePublic,recoveryPublic,devicePrivate;
  private boolean closed;
  public DeviceCredentials600(byte[] accountPublic,KeyPair device,byte[] recoveryPublic) {
    this(accountPublic,device.getPublic().getEncoded(),device.getPrivate().getEncoded(),recoveryPublic);
  }
  private DeviceCredentials600(byte[] account,byte[] device,byte[] secret,byte[] recovery) {
    IdentityProtocol.publicKey(account);IdentityProtocol.publicKey(device);IdentityProtocol.publicKey(recovery);
    if(Arrays.equals(account,device)||Arrays.equals(account,recovery)||Arrays.equals(device,recovery)||secret.length<40||secret.length>128)throw new IllegalArgumentException("Ключи аккаунта, устройства и восстановления должны различаться");
    this.accountPublic=account.clone();this.devicePublic=device.clone();this.devicePrivate=secret.clone();this.recoveryPublic=recovery.clone();
    byte[] challenge=new byte[32];new SecureRandom().nextBytes(challenge);
    if(!IdentityProtocol.verify(device,challenge,sign(challenge))){close();throw new IllegalArgumentException("Ключ устройства не соответствует открытому ключу");}
  }
  public String accountId(){return IdentityProtocol.id(accountPublic);}
  public String deviceId(){return IdentityProtocol.id(devicePublic);}
  public byte[] accountPublic(){return accountPublic.clone();}
  public byte[] devicePublic(){return devicePublic.clone();}
  public byte[] recoveryPublic(){return recoveryPublic.clone();}
  synchronized DeviceCredentials600 withRecoveryPublic(byte[] recovery){if(closed)throw new IllegalStateException("Ключ устройства заблокирован");return new DeviceCredentials600(accountPublic,devicePublic,devicePrivate,recovery);}
  synchronized byte[] sign(byte[] typedPayload) {
    if(closed)throw new IllegalStateException("Ключ устройства заблокирован");
    try{return IdentityProtocol.sign(KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(devicePrivate)),typedPayload);}
    catch(GeneralSecurityException invalid){throw new IllegalArgumentException("Некорректный ключ устройства",invalid);}
  }
  synchronized byte[] encode()throws IOException {
    if(closed)throw new IOException("Ключ устройства заблокирован");
    ByteArrayOutputStream buffer=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(buffer)){out.writeUTF("AEGIS-CORE-DEVICE/v1");out.write(accountPublic);out.write(devicePublic);out.write(recoveryPublic);out.writeInt(devicePrivate.length);out.write(devicePrivate);}return buffer.toByteArray();
  }
  static DeviceCredentials600 decode(byte[] plain)throws IOException {
    try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(plain))){
      if(plain.length>512||!in.readUTF().equals("AEGIS-CORE-DEVICE/v1"))throw new IOException("Некорректное хранилище устройства");
      byte[] account=in.readNBytes(44),device=in.readNBytes(44),recovery=in.readNBytes(44);int size=in.readInt();
      if(size<40||size>128)throw new IOException("Некорректный ключ устройства");byte[] secret=in.readNBytes(size);
      try{if(secret.length!=size||in.read()!=-1)throw new IOException("Некорректное хранилище устройства");return new DeviceCredentials600(account,device,secret,recovery);}
      finally{Arrays.fill(secret,(byte)0);}
    }catch(IllegalArgumentException invalid){throw new IOException("Не удалось проверить хранилище устройства",invalid);}
  }
  @Override public synchronized void close(){closed=true;Arrays.fill(devicePrivate,(byte)0);}
  @Override public String toString(){return "DeviceCredentials600[private key redacted]";}
}
