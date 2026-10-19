package org.securemail.client.ecosystemauth;

import com.google.gson.JsonObject;
import java.io.IOException;import java.security.*;import java.util.*;import java.util.function.BooleanSupplier;
import org.securemail.client.ecosystem.MailPairing600;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import static org.securemail.client.ecosystemauth.OwnerTransferFlow600.*;

/** Unknown-device recovery owns only the new device key. Both registered root signatures come from Mail. */
public final class DeviceRecoveryClient600 implements AutoCloseable {
 public record Inspection(DeviceRecovery recovery,long time,String nonce,byte[] proof){public Inspection{proof=proof.clone();}@Override public byte[] proof(){return proof.clone();}}
 private final IdentityClient600 identity;private final DeviceCredentialStore600 store;private final String account;private final BooleanSupplier cancelled;private final DeviceCredentials600 existing;private final KeyPair fresh;private final long anchorWall=System.currentTimeMillis(),anchorNano=System.nanoTime();private DeviceRecovery challenge;private boolean closed,completed;
 public DeviceRecoveryClient600(IdentityClient600 identity,DeviceCredentialStore600 store,String account,char[] devicePassword)throws IOException{this(identity,store,account,devicePassword,()->false);}
 public DeviceRecoveryClient600(IdentityClient600 identity,DeviceCredentialStore600 store,String account,char[] devicePassword,BooleanSupplier cancelled)throws IOException{
  if(devicePassword==null||devicePassword.length<12)throw new IOException("Пароль ключа устройства: не менее 12 символов");this.cancelled=Objects.requireNonNull(cancelled);this.identity=Objects.requireNonNull(identity);this.store=Objects.requireNonNull(store);this.account=IdentityProtocol.idValue(account);
  if(store.exists()){existing=store.unlock(devicePassword);fresh=null;if(!existing.accountId().equals(account)){existing.close();throw new IOException("Ключ устройства относится к другому аккаунту");}}
  else{existing=null;try{fresh=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}catch(GeneralSecurityException failure){throw new IOException("Не удалось создать отдельный ключ устройства",failure);}}
 }
 public DeviceRecovery begin()throws IOException{
  live();long time=now();String nonce=IdentityProtocol.nonce();byte[] key=publicDevice(),request=IdentityProtocol.login(identity.audience(),account,IdentityProtocol.id(key),time,nonce);JsonObject response=identity.rpc("challengeDevice",json("accountId",account,"deviceKey",IdentityProtocol.b64(key),"time",time,"nonce",nonce,"proof",IdentityProtocol.b64(sign(request))));
  try{DeviceRecovery next=new DeviceRecovery(identity.audience(),string(response,"accountId"),IdentityProtocol.unb64(string(response,"deviceKey"),44),string(response,"challenge"),positive(response,"expiresAt"));if(!account.equals(next.accountId)||!MessageDigest.isEqual(key,next.newDevicePublic())||next.expiresAt<=now()||next.expiresAt>now()+300_000)throw new IOException("Сервер вернул другое устройство");live();challenge=next;inspect();return next;}catch(IllegalArgumentException invalid){throw new IOException("Некорректный запрос восстановления устройства",invalid);}
 }
 /** Each independent Mail inspection receives a fresh proof, not a reusable capability. */
 public Inspection inspection()throws IOException{live();if(challenge==null||challenge.expiresAt<=now())throw new IOException("Запрос восстановления истёк");long time=now();String nonce=IdentityProtocol.nonce();return new Inspection(challenge,time,nonce,sign(IdentityProtocol.deviceRecoveryInspection(challenge,time,nonce)));}
 public void inspect()throws IOException{Inspection request=inspection();JsonObject response=identity.rpc("deviceRecoveryInspect",json("recovery",IdentityProtocol.b64(IdentityProtocol.deviceRecoveryBytes(request.recovery)),"time",request.time,"nonce",request.nonce,"proof",IdentityProtocol.b64(request.proof)));try{var actual=IdentityProtocol.decodeDeviceRecovery(IdentityProtocol.unb64(string(response,"recovery"),1024));if(!MessageDigest.isEqual(IdentityProtocol.deviceRecoveryBytes(actual),IdentityProtocol.deviceRecoveryBytes(challenge)))throw new IOException("Запрос восстановления изменён");live();}catch(IllegalArgumentException invalid){throw new IOException("Некорректное подтверждение восстановления",invalid);}}
 public void recover(MailPairing600.DeviceRecoveryResult result,char[] devicePassword)throws IOException{
  live();inspect();byte[] body=IdentityProtocol.deviceRecoveryBytes(challenge);
  if(!MessageDigest.isEqual(body,IdentityProtocol.deviceRecoveryBytes(result.recovery()))||!IdentityProtocol.id(result.accountPublic()).equals(account)||!IdentityProtocol.verify(result.accountPublic(),body,result.accountProof())||!IdentityProtocol.verify(result.recoveryPublic(),body,result.recoveryProof()))throw new IOException("Почта не подтвердила оба ключа восстановления");
  // Persist the new device before server trust changes, so interruption cannot silently lose that key.
  if(existing==null){try(var credentials=new DeviceCredentials600(result.accountPublic(),fresh,result.recoveryPublic())){store.create(credentials,devicePassword);}}
  else if(!MessageDigest.isEqual(existing.accountPublic(),result.accountPublic()))throw new IOException("Почта относится к другому аккаунту");
  live();JsonObject response=identity.rpc("recoverDevice",json("accountId",account,"challenge",challenge.challenge,"accountProof",IdentityProtocol.b64(result.accountProof()),"recoveryProof",IdentityProtocol.b64(result.recoveryProof())));
  if(!bool(response,"approved")||!bool(response,"sensitiveRecoveryPending"))throw new IOException("Сервер не подтвердил восстановление устройства");live();
  store.updateRecoveryPublic(account,IdentityProtocol.id(publicDevice()),result.recoveryPublic(),devicePassword);completed=true;
 }
 public boolean completed(){return completed;}
 private byte[] publicDevice(){return existing==null?fresh.getPublic().getEncoded():existing.devicePublic();}
 private byte[] sign(byte[] body){return existing==null?IdentityProtocol.sign(fresh.getPrivate(),body):existing.sign(body);}
 private long now()throws IOException{long wall=System.currentTimeMillis(),elapsed=System.nanoTime()-anchorNano;if(elapsed<0||wall<anchorWall-1000)throw new IOException("Время изменилось: повторите восстановление");return Math.max(wall,anchorWall+elapsed/1_000_000);}
 private void live()throws IOException{if(closed||completed||cancelled.getAsBoolean())throw new IOException("Восстановление закрыто или уже завершено");now();}
 @Override public void close(){closed=true;if(existing!=null)existing.close();if(fresh!=null)try{fresh.getPrivate().destroy();}catch(Exception ignored){}challenge=null;}
}
