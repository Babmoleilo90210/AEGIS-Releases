package org.securemail.client.ecosystemauth;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import static org.securemail.client.ecosystemauth.OwnerTransferFlow600.*;

/** One-time quorum creation. All four root/device proofs are typed and independently checked. */
public final class FirstDelegationFlow600 {
  private final IdentityClient600 client;private final CoreAccountSession600 session;
  public FirstDelegationFlow600(IdentityClient600 client,CoreAccountSession600 session){this.client=Objects.requireNonNull(client);this.session=Objects.requireNonNull(session);}
  public record Request(FirstDelegation delegation){
    public Request{Objects.requireNonNull(delegation);}
    public String encode(){return json("schema",1,"delegation",IdentityProtocol.b64(IdentityProtocol.firstDelegationBytes(delegation))).toString();}
    public static Request parse(String code)throws IOException{try{JsonObject o=parseObject(code,4096,Set.of("schema","delegation"));if(!schema(o))throw new IOException("Неподдерживаемый формат делегирования");return new Request(IdentityProtocol.decodeFirstDelegation(IdentityProtocol.unb64(string(o,"delegation"),2048)));}catch(IllegalArgumentException|IllegalStateException invalid){throw new IOException("Некорректный публичный запрос делегирования",invalid);}}
  }
  public record Consent(Request request,FirstDelegateRole role,byte[] rootPublic,byte[] devicePublic,byte[] rootProof,byte[] deviceProof){
    public Consent{Objects.requireNonNull(request);Objects.requireNonNull(role);rootPublic=rootPublic.clone();devicePublic=devicePublic.clone();rootProof=rootProof.clone();deviceProof=deviceProof.clone();IdentityProtocol.publicKey(rootPublic);IdentityProtocol.publicKey(devicePublic);FirstDelegation t=request.delegation;boolean owner=role==FirstDelegateRole.OWNER_APPROVE;byte[] payload=IdentityProtocol.firstDelegationBytes(t);if(!IdentityProtocol.id(rootPublic).equals(owner?t.ownerAccountId:t.targetAccountId)||!IdentityProtocol.id(devicePublic).equals(owner?t.ownerDeviceId:t.targetDeviceId)||!IdentityProtocol.verify(rootPublic,payload,rootProof)||!IdentityProtocol.verify(devicePublic,payload,deviceProof))throw new IllegalArgumentException("Delegation consent binding");}
    @Override public byte[] rootPublic(){return rootPublic.clone();}@Override public byte[] devicePublic(){return devicePublic.clone();}@Override public byte[] rootProof(){return rootProof.clone();}@Override public byte[] deviceProof(){return deviceProof.clone();}
    public String encode(){return json("schema",1,"request",request.encode(),"role",role.name(),"rootPublic",IdentityProtocol.b64(rootPublic),"devicePublic",IdentityProtocol.b64(devicePublic),"rootProof",IdentityProtocol.b64(rootProof),"deviceProof",IdentityProtocol.b64(deviceProof)).toString();}
    public static Consent parse(String code)throws IOException{try{JsonObject o=parseObject(code,8192,Set.of("schema","request","role","rootPublic","devicePublic","rootProof","deviceProof"));if(!schema(o))throw new IOException("Неподдерживаемое подтверждение");return new Consent(Request.parse(string(o,"request")),FirstDelegateRole.valueOf(string(o,"role")),IdentityProtocol.unb64(string(o,"rootPublic"),44),IdentityProtocol.unb64(string(o,"devicePublic"),44),IdentityProtocol.unb64(string(o,"rootProof"),64),IdentityProtocol.unb64(string(o,"deviceProof"),64));}catch(IllegalArgumentException|IllegalStateException invalid){throw new IOException("Некорректное публичное подтверждение делегирования",invalid);}}
  }
  public Request prepare(String target,String roleName)throws IOException{
    live();var grant=session.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ,Scope.ADMIN));long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] proposal=IdentityProtocol.firstDelegateProposal(client.audience(),session.accountId(),target,roleName,time,nonce);JsonObject response=client.rpc("firstDelegateChallenge",signed(grant,"admin.execute",proposal,time,nonce,json("targetAccountId",target,"roleName",roleName)));FirstDelegation t=decode(response);if(!t.ownerAccountId.equals(session.accountId())||!t.targetAccountId.equals(target)||!t.roleName.equals(roleName))throw new IOException("Сервер вернул другое делегирование");live();return new Request(t);
  }
  public FirstDelegation inspect(Request request)throws IOException{
    valid(request);var grant=session.grant(App.AEGIS,Set.of(Scope.ACCOUNT_READ));long time=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] body=IdentityProtocol.firstDelegationInspection(client.audience(),request.delegation.challenge,time,nonce);FirstDelegation t=decode(client.rpc("firstDelegateInspect",signed(grant,"account.read",body,time,nonce,json("challenge",request.delegation.challenge))));if(!MessageDigest.isEqual(IdentityProtocol.firstDelegationBytes(t),IdentityProtocol.firstDelegationBytes(request.delegation)))throw new IOException("Публичный запрос делегирования изменён");live();return t;
  }
  public Consent consent(Request request,FirstDelegateRole role,byte[] rootProof)throws IOException{inspect(request);try{return new Consent(request,role,session.accountPublic(),session.devicePublic(),rootProof,session.signFirstDelegationConsent(request.delegation,role));}catch(IllegalArgumentException invalid){throw new IOException("Почта не подтвердила делегирование",invalid);}}
  public void complete(Consent owner,Consent delegate)throws IOException{
    valid(owner.request);if(owner.role!=FirstDelegateRole.OWNER_APPROVE||delegate.role!=FirstDelegateRole.DELEGATE_ACCEPT||!owner.request.encode().equals(delegate.request.encode())||!session.accountId().equals(owner.request.delegation.ownerAccountId))throw new IOException("Подтверждения относятся к разным участникам");inspect(owner.request);JsonObject response=client.rpc("firstDelegateComplete",json("challenge",owner.request.delegation.challenge,"ownerRootProof",IdentityProtocol.b64(owner.rootProof),"ownerDeviceProof",IdentityProtocol.b64(owner.deviceProof),"targetRootProof",IdentityProtocol.b64(delegate.rootProof),"targetDeviceProof",IdentityProtocol.b64(delegate.deviceProof)));if(!bool(response,"delegated"))throw new IOException("Первое делегирование не подтверждено");live();
  }
  private FirstDelegation decode(JsonObject response)throws IOException{try{FirstDelegation d=IdentityProtocol.decodeFirstDelegation(IdentityProtocol.unb64(string(response,response.has("delegation")?"delegation":"proofBytes"),2048));valid(new Request(d));return d;}catch(IllegalArgumentException invalid){throw new IOException("Некорректное делегирование сервера",invalid);}}
  private void valid(Request request)throws IOException{live();var d=request.delegation;long now=System.currentTimeMillis();if(!d.audience.equals(client.audience())||d.expiresAt<=now||d.expiresAt>now+120_000)throw new IOException("Запрос делегирования истёк");}
  private void live()throws IOException{if(session.locked())throw new IOException("Сессия АЕГИС заблокирована");session.coreGrant();}
}
