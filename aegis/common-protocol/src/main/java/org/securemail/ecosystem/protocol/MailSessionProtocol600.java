package org.securemail.ecosystem.protocol;

import java.io.*;
import java.nio.charset.StandardCharsets;

/** Fixed login binding: service, account, nickname, password digest. No password is serialized here. */
public final class MailSessionProtocol600 {
  private MailSessionProtocol600(){}
  public static byte[] registration(String relayAudience,String accountId,String nickname,byte[] passwordUtf8,byte[] accountPublicKey) {
    IdentityProtocol.publicKey(accountPublicKey);if(!IdentityProtocol.id(accountPublicKey).equals(accountId))throw new IllegalArgumentException("Ключ аккаунта");
    return encode("AEGIS-MAIL-REGISTER/v1",relayAudience,accountId,nickname,passwordUtf8,accountPublicKey);
  }
  public static byte[] login(String relayAudience,String accountId,String nickname,byte[] passwordUtf8) {
    return encode("AEGIS-MAIL-LOGIN/v1",relayAudience,accountId,nickname,passwordUtf8,null);
  }
  private static byte[] encode(String domain,String relayAudience,String accountId,String nickname,byte[] passwordUtf8,byte[] accountPublicKey) {
    IdentityProtocol.idValue(relayAudience);IdentityProtocol.idValue(accountId);
    if(nickname==null||!nickname.matches("[A-Za-z0-9_]{3,32}")||passwordUtf8==null||passwordUtf8.length<12||passwordUtf8.length>4096)throw new IllegalArgumentException("Некорректный вход Почты");
    try {ByteArrayOutputStream buffer=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(buffer);out.writeUTF(domain);out.writeUTF(relayAudience);out.writeUTF(accountId);out.writeUTF(nickname);out.write(IdentityProtocol.digest(passwordUtf8));if(accountPublicKey!=null)out.write(accountPublicKey);return buffer.toByteArray();}
    catch(IOException impossible){throw new IllegalStateException(impossible);}
  }
}
