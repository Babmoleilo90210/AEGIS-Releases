package org.securemail.client.library600;

import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class LibraryReadPermit600Test {
 final String id=UUID.randomUUID().toString(),account="a".repeat(64),device="device";final AtomicLong wall=new AtomicLong(100000),nano=new AtomicLong();
 final Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId zone){return this;}public Instant instant(){return Instant.ofEpochMilli(wall.get());}public long millis(){return wall.get();}};
 Map<String,Object> envelope(boolean offline)throws Exception{return new HashMap<>(Map.of("data",Map.of("id",id,"revision",3L,"sha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest("body".getBytes(StandardCharsets.UTF_8))),"offlineAllowed",offline),"accountId",account,"deviceId",device,"generation",2L,"aclEpoch",5L,"serverNow",100000L,"leaseUntil",220000L));}
 LibraryReadPermit600 accept(Map<String,Object> env)throws Exception{return LibraryReadPermit600.acceptVerified(id,3,"body",env,clock,nano::get);}
 @Test void onlineReadNeedsNoExportButCannotUseOfflineAndRequiresRefreshWithinMinute()throws Exception {var permit=accept(envelope(false));permit.requireCurrent();assertThrows(IOException.class,permit::requireOffline);nano.set(60_000_000_000L);assertThrows(IOException.class,permit::requireCurrent);}
 @Test void explicitlyPermittedOfflineSnapshotRemainsMonotonicallyBounded()throws Exception {var permit=accept(envelope(true));nano.set(61_000_000_000L);permit.requireOffline();nano.set(120_000_000_000L);assertThrows(IOException.class,permit::requireOffline);}
 @Test void revisionBodyEpochAndIdentityChangesInvalidateDisplayedSnapshot()throws Exception {var original=envelope(true);var permit=accept(original);for(String field:List.of("accountId","deviceId","generation","aclEpoch")){var changed=new HashMap<>(original);changed.put(field,field.equals("accountId")?"b".repeat(64):field.equals("deviceId")?"other":99L);assertThrows(LibraryReadPermit600.SnapshotChanged.class,()->permit.renewVerified(changed,clock,nano::get));}assertThrows(LibraryReadPermit600.SnapshotChanged.class,()->LibraryReadPermit600.acceptVerified(id,4,"body",original,clock,nano::get));assertThrows(LibraryReadPermit600.SnapshotChanged.class,()->LibraryReadPermit600.acceptVerified(id,3,"changed",original,clock,nano::get));}
 @Test void renewalCannotTurnPreviouslyPermittedCopyIntoUnboundedOfflineAccess()throws Exception {var permit=accept(envelope(true));nano.set(50_000_000_000L);var renewed=permit.renewVerified(envelope(false),clock,nano::get);renewed.requireCurrent();assertThrows(IOException.class,renewed::requireOffline);renewed.revoke();assertThrows(IOException.class,renewed::requireCurrent);}
 @Test void measuredRoundTripAndLocalSignedExpiryAreSubtracted()throws Exception {var env=envelope(true);env.put("_localRoundTripMillis600",10000L);var permit=accept(env);nano.set(110_000_000_000L);assertThrows(IOException.class,permit::requireCurrent);nano.set(0);wall.set(219999);var almostExpired=accept(envelope(true));nano.set(1_000_000L);assertThrows(IOException.class,almostExpired::requireCurrent);}
 @Test void rollbackAndUnreasonableTransitFailClosed()throws Exception {var permit=accept(envelope(true));wall.decrementAndGet();assertThrows(IOException.class,permit::requireCurrent);wall.set(100000);var env=envelope(true);env.put("_localRoundTripMillis600",120001L);assertThrows(IOException.class,()->accept(env));}
}
