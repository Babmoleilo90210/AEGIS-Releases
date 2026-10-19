package org.securemail.client.library600;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;
import java.util.function.LongSupplier;

/** Per-material RAM snapshot permit, distinct from a general Identity capability.
 * Issued only from a fresh signed read.authorize response. No disk restoration. */
public final class LibraryReadPermit600 {
 public static final class SnapshotChanged extends IOException {public SnapshotChanged(){super("Снимок или полномочия материала изменены");}}
 private final String id,sha,account,device;private final long revision,generation,epoch;private final boolean offline;private final LibraryLease600 lease;private final LongSupplier nanoClock;private final long checkedNano,onlineWindowMillis;
 private LibraryReadPermit600(String id,long revision,String sha,String account,String device,long generation,long epoch,boolean offline,LibraryLease600 lease,LongSupplier nanoClock,long transit){this.id=id;this.revision=revision;this.sha=sha;this.account=account;this.device=device;this.generation=generation;this.epoch=epoch;this.offline=offline;this.lease=lease;this.nanoClock=nanoClock;checkedNano=nanoClock.getAsLong();onlineWindowMillis=Math.max(1,60000-transit);}
 public static LibraryReadPermit600 acceptVerified(String expectedId,long expectedRevision,String displayedBody,Map<String,Object>response,Clock clock,LongSupplier nano)throws Exception {
  String digest=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(displayedBody.getBytes(StandardCharsets.UTF_8)));return accept(expectedId,expectedRevision,digest,response,clock,nano);
 }
 private static LibraryReadPermit600 accept(String id,long revision,String sha,Map<String,Object>response,Clock clock,LongSupplier nano)throws Exception {
  if(!(response.get("data")instanceof Map<?,?>d)||!id.equals(d.get("id"))||revision!=number(d,"revision")||!sha.equals(d.get("sha256"))||!(d.get("offlineAllowed")instanceof Boolean offline))throw new SnapshotChanged();
  String account=(String)response.get("accountId"),device=(String)response.get("deviceId");long gen=number(response,"generation"),epoch=number(response,"aclEpoch");long transit=response.containsKey("_localRoundTripMillis600")?number(response,"_localRoundTripMillis600"):0;
  // RAM may be shown online without EXPORT. The separate offline flag is checked
  // on every uncertain/offline use and is never an export/vault permission.
  LibraryLease600 lease=LibraryLease600.acceptVerified(account,device,gen,epoch,number(response,"serverNow"),number(response,"leaseUntil"),true,clock,nano,transit);
  return new LibraryReadPermit600(id,revision,sha,account,device,gen,epoch,offline,lease,nano,transit);
 }
 public LibraryReadPermit600 renewVerified(Map<String,Object>response,Clock clock,LongSupplier nano)throws Exception {
  try{if(!account.equals(response.get("accountId"))||!device.equals(response.get("deviceId"))||generation!=number(response,"generation")||epoch!=number(response,"aclEpoch"))throw new SnapshotChanged();return accept(id,revision,sha,response,clock,nano);}catch(Exception invalid){throw new SnapshotChanged();}
 }
 public String materialId(){return id;}
 public void requireCurrent()throws IOException {lease.require(account,device,generation,epoch);long elapsed=nanoClock.getAsLong()-checkedNano;if(!offline&&(elapsed<0||elapsed/1000000L>=onlineWindowMillis))throw new IOException("Нужна повторная онлайн-проверка чтения");}
 public void requireOffline()throws IOException {requireCurrent();if(!offline)throw new IOException("Офлайн-просмотр материала не разрешён");}
 public void revoke(){lease.revoke();}
 private static long number(Map<?,?>m,String key)throws IOException {if(!(m.get(key)instanceof Number n))throw new IOException("Поле допуска материала");try{return new java.math.BigDecimal(n.toString()).longValueExact();}catch(RuntimeException bad){throw new IOException("Некорректный допуск материала");}}
}
