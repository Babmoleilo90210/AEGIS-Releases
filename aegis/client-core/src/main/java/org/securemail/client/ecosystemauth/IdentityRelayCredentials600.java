package org.securemail.client.ecosystemauth;

import java.io.*;
import java.security.*;
import org.securemail.ecosystem.protocol.*;
import org.securemail.protocol.Binary;

/** Mail's narrow proof key, not its account root key. There is no legacy fallback when configured. */
public final class IdentityRelayCredentials600 {
  private final byte[] serviceKey,identityKey;private final String wire;private final PrivateKey proof;private final IdentityProtocol.Capability cap;
  public IdentityRelayCredentials600(byte[] relayServicePublicKey,byte[] identityPublicKey,String capabilityWire,PrivateKey appProof) {
    IdentityProtocol.publicKey(relayServicePublicKey);IdentityProtocol.publicKey(identityPublicKey);cap=IdentityProtocol.decodeCapability(capabilityWire);
    if(!IdentityProtocol.verifyCapability(cap,identityPublicKey,System.currentTimeMillis())||cap.appId!=IdentityProtocol.App.MAIL||!cap.capabilities.contains(IdentityProtocol.Scope.MAIL_READ))throw new IllegalArgumentException("Недействительное разрешение Почты");
    byte[] challenge=IdentityProtocol.digest(capabilityWire.getBytes(java.nio.charset.StandardCharsets.US_ASCII));if(!IdentityProtocol.verify(cap.proofKey,challenge,IdentityProtocol.sign(appProof,challenge)))throw new IllegalArgumentException("Ключ приложения не соответствует разрешению Почты");
    serviceKey=relayServicePublicKey.clone();identityKey=identityPublicKey.clone();wire=capabilityWire;proof=appProof;
  }
  public void requireCurrent(String accountId)throws IOException {if(!cap.accountId.equals(accountId)||!IdentityProtocol.verifyCapability(cap,identityKey,System.currentTimeMillis()))throw new IOException("Вход Почты требует действующего разрешения АЕГИС");}
  public void writeProof(DataOutputStream out,String accountId,String nickname,byte[] passwordUtf8)throws IOException {
    write(out,accountId,nickname,passwordUtf8,null);
  }
  public void writeRegistrationProof(DataOutputStream out,String accountId,String nickname,byte[] passwordUtf8,byte[] accountPublicKey)throws IOException {
    if(!cap.capabilities.contains(IdentityProtocol.Scope.MAIL_SEND))throw new IOException("Регистрация требует разрешения MAIL_SEND");write(out,accountId,nickname,passwordUtf8,accountPublicKey);
  }
  private void write(DataOutputStream out,String accountId,String nickname,byte[] passwordUtf8,byte[] accountPublicKey)throws IOException {
    requireCurrent(accountId);long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] body=accountPublicKey==null?MailSessionProtocol600.login(IdentityProtocol.id(serviceKey),accountId,nickname,passwordUtf8):MailSessionProtocol600.registration(IdentityProtocol.id(serviceKey),accountId,nickname,passwordUtf8,accountPublicKey);String action=accountPublicKey==null?"mail.read":"mail.send";
    byte[] signature=IdentityProtocol.sign(proof,IdentityProtocol.requestDigest(cap,action,IdentityProtocol.digest(body),time,nonce));
    Binary.text(out,wire);out.writeLong(time);Binary.text(out,nonce);Binary.bytes(out,signature);
  }
  @Override public String toString(){return "IdentityRelayCredentials600[credentials redacted]";}
}
