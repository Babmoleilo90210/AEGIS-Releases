package org.securemail.client.ecosystemauth;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Objects;
import java.util.Set;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import org.securemail.ecosystem.protocol.IdentityAdministrationProtocol600;
import org.securemail.ecosystem.protocol.IdentityAdministrationProtocol600.Operation;
import static org.securemail.client.ecosystemauth.OwnerTransferFlow600.*;

/** Three fixed Identity administration actions. Root keys never enter Core. */
public final class IdentityAdministrationFlow600 {
  private final IdentityClient600 client;private final CoreAccountSession600 session;
  public IdentityAdministrationFlow600(IdentityClient600 client,CoreAccountSession600 session){this.client=Objects.requireNonNull(client);this.session=Objects.requireNonNull(session);}
  public record Permit(String audience,String initiatorAccountId,Operation operation,String targetAccountId,String roleName,String requestId,long expiresAt,String payloadSha256){
    public Permit{IdentityProtocol.idValue(audience);IdentityProtocol.idValue(initiatorAccountId);IdentityProtocol.idValue(targetAccountId);IdentityProtocol.nonceValue(requestId);if(expiresAt<1)throw new IllegalArgumentException("Permit expiry");byte[] payload=IdentityAdministrationProtocol600.payload(operation,targetAccountId,roleName);if(!MessageDigest.isEqual(IdentityProtocol.unb64(payloadSha256,32),IdentityProtocol.digest(payload)))throw new IllegalArgumentException("Permit payload binding");}
    public byte[] payload(){return IdentityAdministrationProtocol600.payload(operation,targetAccountId,roleName);}
    public String encode(){return json("schema",1,"audience",audience,"initiatorAccountId",initiatorAccountId,"operation",operation.name(),"targetAccountId",targetAccountId,"roleName",roleName,"requestId",requestId,"expiresAt",expiresAt,"payloadSha256",payloadSha256).toString();}
    public static Permit parse(String code)throws IOException{try{JsonObject o=parseObject(code,4096,Set.of("schema","audience","initiatorAccountId","operation","targetAccountId","roleName","requestId","expiresAt","payloadSha256"));if(!schema(o))throw new IOException("Неподдерживаемый публичный код");return new Permit(string(o,"audience"),string(o,"initiatorAccountId"),Operation.valueOf(string(o,"operation")),string(o,"targetAccountId"),string(o,"roleName"),string(o,"requestId"),positive(o,"expiresAt"),string(o,"payloadSha256"));}catch(IllegalArgumentException bad){throw new IOException("Некорректный публичный запрос полномочий",bad);}}
  }
  /** A fresh Mail step-up is required by the caller and independently enforced by Identity. */
  public Permit prepare(Operation operation,String target,String roleName)throws IOException{
    live();byte[] payload=IdentityAdministrationProtocol600.payload(operation,target,roleName);var grant=admin();long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] body=IdentityProtocol.criticalApproval(client.audience(),session.accountId(),operation.wire,nonce,payload,time+300_000);
    JsonObject result=client.rpc("criticalRequest",signed(grant,"admin.execute",body,time,nonce,json("operation",operation.wire,"payload",IdentityProtocol.b64(payload))));
    if(!operation.wire.equals(string(result,"operation"))||!MessageDigest.isEqual(IdentityProtocol.unb64(string(result,"payloadSha256"),32),IdentityProtocol.digest(payload)))throw new IOException("Сервер вернул другую операцию");
    Permit permit=new Permit(client.audience(),session.accountId(),operation,target,roleName,string(result,"requestId"),positive(result,"expiresAt"),string(result,"payloadSha256"));inspect(permit);return permit;
  }
  /** Read the live, persisted permit under a separate ADMIN PoP domain before any approval. */
  public void inspect(Permit permit)throws IOException{
    valid(permit);var grant=admin();long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] body=IdentityAdministrationProtocol600.criticalInspection(client.audience(),permit.requestId,time,nonce);
    JsonObject result=client.rpc("criticalInspect",signed(grant,"admin.execute",body,time,nonce,json("requestId",permit.requestId)));
    if(!permit.audience.equals(string(result,"audience"))||!permit.initiatorAccountId.equals(string(result,"initiatorAccountId"))||!permit.requestId.equals(string(result,"requestId"))||!permit.operation.wire.equals(string(result,"operation"))||permit.expiresAt!=positive(result,"expiresAt")||!permit.payloadSha256.equals(string(result,"payloadSha256")))throw new IOException("Публичный запрос не совпадает с действующей серверной операцией");live();
  }
  public void approve(Permit permit)throws IOException{
    inspect(permit);if(session.accountId().equals(permit.initiatorAccountId))throw new IOException("Необходимо подтверждение независимого администратора");var grant=admin();long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] body=approval(permit);
    if(!bool(client.rpc("criticalApprove",signed(grant,"admin.execute",body,time,nonce,json("requestId",permit.requestId))),"approved"))throw new IOException("Подтверждение отклонено");live();
  }
  public void execute(Permit permit)throws IOException{
    inspect(permit);if(!session.accountId().equals(permit.initiatorAccountId))throw new IOException("Завершить операцию может только её инициатор");var grant=admin();long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();JsonObject args=json("requestId",permit.requestId,"targetAccountId",permit.targetAccountId);if(permit.operation==Operation.ASSIGN)args.addProperty("roleName",permit.roleName);
    if(!bool(client.rpc(permit.operation.rpc,signed(grant,"admin.execute",approval(permit),time,nonce,args)),permit.operation.result))throw new IOException("Операция не подтверждена");live();
  }
  private byte[] approval(Permit permit){return IdentityProtocol.criticalApproval(client.audience(),session.accountId(),permit.operation.wire,permit.requestId,permit.payload(),permit.expiresAt);}
  private CoreAccountSession600.AppGrant admin()throws IOException{return session.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ,Scope.ADMIN));}
  private void valid(Permit permit)throws IOException{Objects.requireNonNull(permit);live();long now=System.currentTimeMillis();if(!permit.audience.equals(client.audience())||permit.expiresAt<=now||permit.expiresAt>now+300_000)throw new IOException("Срок публичного запроса истёк");}
  private void live()throws IOException{if(session.locked())throw new IOException("Сессия АЕГИС заблокирована");session.coreGrant();}
}
