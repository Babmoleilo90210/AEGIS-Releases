package org.securemail.client.ecosystemauth;

import com.google.gson.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Set;
import org.securemail.client.community.CommunityJson;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Public, short-lived device pairing request. Contains no private key/password/token. */
public record DeviceApproval600(String audience,String accountId,String challenge,byte[] devicePublic,long expiresAt){
  public DeviceApproval600 {
    IdentityProtocol.idValue(audience);IdentityProtocol.idValue(accountId);IdentityProtocol.nonceValue(challenge);IdentityProtocol.publicKey(devicePublic);devicePublic=devicePublic.clone();if(expiresAt<1)throw new IllegalArgumentException("Недопустимый срок подтверждения");
  }
  @Override public byte[] devicePublic(){return devicePublic.clone();}
  public String fingerprint(){return IdentityProtocol.id(devicePublic);}
  /** New device proves possession of its own key; it cannot grant itself trust. */
  public static DeviceApproval600 request(IdentityClient600 identity,DeviceCredentials600 credentials)throws IOException {
    long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();JsonObject args=new JsonObject();args.addProperty("accountId",credentials.accountId());args.addProperty("deviceKey",IdentityProtocol.b64(credentials.devicePublic()));args.addProperty("time",time);args.addProperty("nonce",nonce);args.addProperty("proof",IdentityProtocol.b64(credentials.sign(IdentityProtocol.login(identity.audience(),credentials.accountId(),credentials.deviceId(),time,nonce))));return fromResponse(identity.rpc("challengeDevice",args),identity.audience(),credentials);
  }
  public void verifyTarget(String expectedAudience,String expectedAccount,long now)throws IOException {if(!audience.equals(expectedAudience)||!accountId.equals(expectedAccount)||expiresAt<=now||expiresAt-now>300_000)throw new IOException("Запрос другого аккаунта или срок подтверждения истёк");}
  public String encode(){JsonObject j=new JsonObject();j.addProperty("schema",1);j.addProperty("audience",audience);j.addProperty("accountId",accountId);j.addProperty("challenge",challenge);j.addProperty("deviceKey",IdentityProtocol.b64(devicePublic));j.addProperty("expiresAt",expiresAt);return j.toString();}
  public static DeviceApproval600 parse(String encoded)throws IOException {
    if(encoded==null||encoded.length()>2048)throw new IOException("Запрос устройства слишком велик");try{JsonObject j=CommunityJson.parse(encoded.getBytes(StandardCharsets.UTF_8));if(!j.keySet().equals(Set.of("schema","audience","accountId","challenge","deviceKey","expiresAt"))||number(j,"schema")!=1)throw new IOException("Неизвестный формат запроса устройства");return new DeviceApproval600(text(j,"audience"),text(j,"accountId"),text(j,"challenge"),IdentityProtocol.unb64(text(j,"deviceKey"),44),number(j,"expiresAt"));}catch(IllegalArgumentException|IllegalStateException|ArithmeticException invalid){throw new IOException("Повреждён запрос устройства",invalid);}
  }
  static DeviceApproval600 fromResponse(JsonObject response,String audience,DeviceCredentials600 credentials)throws IOException {
    try{DeviceApproval600 value=new DeviceApproval600(audience,text(response,"accountId"),text(response,"challenge"),IdentityProtocol.unb64(text(response,"deviceKey"),44),number(response,"expiresAt"));value.verifyTarget(audience,credentials.accountId(),System.currentTimeMillis());if(!MessageDigest.isEqual(value.devicePublic(),credentials.devicePublic()))throw new IOException("Сервер вернул другое устройство");return value;}catch(IllegalArgumentException|IllegalStateException|ArithmeticException invalid){throw new IOException("Некорректный ответ подтверждения устройства",invalid);}
  }
  private static String text(JsonObject j,String key)throws IOException {JsonElement e=j.get(key);if(e==null||!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isString())throw new IOException("Повреждён запрос устройства");return e.getAsString();}
  private static long number(JsonObject j,String key)throws IOException {JsonElement e=j.get(key);if(e==null||!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isNumber()||!e.getAsString().matches("[0-9]{1,19}"))throw new IOException("Повреждён срок запроса устройства");try{return e.getAsBigDecimal().longValueExact();}catch(ArithmeticException invalid){throw new IOException("Повреждён срок запроса устройства",invalid);}}
}
