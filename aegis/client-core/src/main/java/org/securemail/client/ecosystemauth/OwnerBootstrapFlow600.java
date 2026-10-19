package org.securemail.client.ecosystemauth;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import static org.securemail.client.ecosystemauth.OwnerTransferFlow600.*;

/** The client can inspect and produce a Mail-signed public proof. Only the operator CLI completes bootstrap. */
public final class OwnerBootstrapFlow600 {
  private final IdentityClient600 client;private final CoreAccountSession600 session;
  public OwnerBootstrapFlow600(IdentityClient600 client,CoreAccountSession600 session){this.client=Objects.requireNonNull(client);this.session=Objects.requireNonNull(session);}
  public static OwnerBootstrap parse(String code)throws IOException{
    if(code==null||code.length()>8192)throw new IOException("Слишком большой публичный запрос");try{
      // The operator challenge document also contains human-readable/public CLI fields. Extract via a strict allowlist.
      JsonObject o=parseObject(code,8192,Set.of("type","audience","accountId","challenge","expiresAt","proofBytes","bootstrap"));if(!string(o,"type").equals("AEGIS-OWNER-BOOTSTRAP/v1"))throw new IOException("Неподдерживаемая версия запроса");OwnerBootstrap b=IdentityProtocol.decodeOwnerBootstrap(IdentityProtocol.unb64(string(o,"bootstrap"),1024));
      if(!b.audience.equals(string(o,"audience"))||!b.accountId.equals(string(o,"accountId"))||!b.challenge.equals(string(o,"challenge"))||b.expiresAt!=positive(o,"expiresAt")||!MessageDigest.isEqual(IdentityProtocol.ownerBootstrapBytes(b),IdentityProtocol.unb64(string(o,"proofBytes"),1024)))throw new IOException("Публичные поля запроса противоречат друг другу");return b;
    }catch(IllegalArgumentException|IllegalStateException invalid){throw new IOException("Некорректный запрос первоначального назначения",invalid);}
  }
  public OwnerBootstrap inspect(OwnerBootstrap expected)throws IOException{
    live();long now=System.currentTimeMillis();if(!expected.audience.equals(client.audience())||!expected.accountId.equals(session.accountId())||expected.expiresAt<=now||expected.expiresAt>now+600_000)throw new IOException("Запрос относится к другому аккаунту или истёк");var grant=session.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ));String nonce=IdentityProtocol.nonce();byte[] body=IdentityProtocol.ownerBootstrapInspection(client.audience(),expected.challenge,now,nonce);JsonObject response=client.rpc("ownerBootstrapInspect",signed(grant,"account.read",body,now,nonce,json("challenge",expected.challenge)));OwnerBootstrap actual;try{actual=IdentityProtocol.decodeOwnerBootstrap(IdentityProtocol.unb64(string(response,"bootstrap"),1024));}catch(IllegalArgumentException invalid){throw new IOException("Некорректное подтверждение сервера",invalid);}if(!MessageDigest.isEqual(IdentityProtocol.ownerBootstrapBytes(actual),IdentityProtocol.ownerBootstrapBytes(expected)))throw new IOException("Запрос первоначального назначения изменён");live();return actual;
  }
  public String publicCliProof(OwnerBootstrap bootstrap,byte[] rootProof)throws IOException{
    inspect(bootstrap);if(!IdentityProtocol.verify(session.accountPublic(),IdentityProtocol.ownerBootstrapBytes(bootstrap),rootProof))throw new IOException("Почта не подтвердила первоначальное назначение");return json("audience",bootstrap.audience,"accountId",bootstrap.accountId,"challenge",bootstrap.challenge,"signature",IdentityProtocol.b64(rootProof)).toString();
  }
  private void live()throws IOException{if(session.locked())throw new IOException("Сессия АЕГИС заблокирована");session.coreGrant();}
}
