package org.securemail.client.library600;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;

class LibraryConnector600Test {
    @TempDir Path dir;
    String account="a".repeat(64),device="device",id=UUID.randomUUID().toString();
    AtomicLong nano=new AtomicLong();Map<String,Object>response;
    VaultProjection600 projection;LibraryConnector600 connector;
    @BeforeEach void setup()throws Exception {
        response=new HashMap<>(Map.of("accountId",account,"deviceId",device,"generation",1,"aclEpoch",2,"serverNow",1000,"leaseUntil",11000,"data",Map.of("id",id,"revision",1,"markdown","# Test","offlineAllowed",true)));
        projection=new VaultProjection600(dir.resolve("projection"));connector=new LibraryConnector600((a,d)->{assertEquals("library600.project",a);assertEquals(id,d.get("id"));return response;},projection,account,device,1,Clock.fixed(Instant.ofEpochMilli(1000),ZoneOffset.UTC),nano::get);
    }
    @AfterEach void close()throws Exception{connector.close();}
    @Test void validProjectionAndIdenticalRetryRenewOnlyFreshVerifiedLease()throws Exception {
        Path file=connector.project(id);assertEquals("# Test",Files.readString(file));assertEquals(file,connector.project(id));nano.set(10_000_000_000L);connector.maintain();assertFalse(Files.exists(file));
    }
    @Test void wrongIdentityDeviceOrGenerationClearsPriorPlaintext()throws Exception {
        Path file=connector.project(id);response.put("generation",2);assertThrows(IOException.class,()->connector.project(id));assertFalse(Files.exists(file));
    }
    @Test void staleEpochAndInvalidIntegerRejectRatherThanRound()throws Exception {
        Path file=connector.project(id);response.put("aclEpoch",1);assertThrows(IOException.class,()->connector.project(id));assertFalse(Files.exists(file));response.put("aclEpoch",2);response.put("generation",1.5);assertThrows(IOException.class,()->connector.project(id));
    }
    @Test void missingOfflineGrantFailsClosedAndNoFileIsWritten()throws Exception {
        response.put("data",Map.of("id",id,"revision",1,"markdown","secret","offlineAllowed",false));assertThrows(IOException.class,()->connector.project(id));assertFalse(Files.exists(dir.resolve("projection").resolve(id+".md")));
    }
    @Test void epochChangeClearsPreviouslyProjectedMaterials()throws Exception {
        Path first=connector.project(id);String second=UUID.randomUUID().toString();
        var lease=LibraryLease600.acceptVerified(account,device,1,2,1000,11000,true,Clock.fixed(Instant.ofEpochMilli(1000),ZoneOffset.UTC),nano::get);
        Path stale=projection.publish(second,1,"old epoch",lease,new VaultProjection600.Context(account,device,1,2));assertTrue(Files.exists(stale));
        response.put("aclEpoch",3);connector.project(id);assertFalse(Files.exists(stale));assertEquals("# Test",Files.readString(first));
    }
    @Test void revokeAndCloseStopProjection()throws Exception {
        Path file=connector.project(id);connector.revoke();assertFalse(Files.exists(file));assertThrows(IOException.class,()->connector.project(id));connector.close();assertThrows(IOException.class,()->connector.project(id));
    }
    @Test void stalledRpcDoesNotPreventExpiryOrRevocationMaintenance()throws Exception {
        var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);var calls=new AtomicInteger();
        var pool=java.util.concurrent.Executors.newFixedThreadPool(2);
        try(var independentProjection=new VaultProjection600(dir.resolve("concurrent"));var c=new LibraryConnector600((a,d)->{if(calls.incrementAndGet()>1){entered.countDown();release.await(5,java.util.concurrent.TimeUnit.SECONDS);}return response;},independentProjection,account,device,1,Clock.fixed(Instant.ofEpochMilli(1000),ZoneOffset.UTC),nano::get)) {
            Path file=c.project(id);var request=pool.submit(()->{try{c.project(id);return false;}catch(IOException closed){return true;}catch(Exception failure){throw new RuntimeException(failure);}});
            assertTrue(entered.await(2,java.util.concurrent.TimeUnit.SECONDS));nano.set(10_000_000_000L);
            pool.submit(()->{c.maintain();return true;}).get(2,java.util.concurrent.TimeUnit.SECONDS);assertFalse(Files.exists(file));
            c.revoke();release.countDown();assertTrue(request.get(2,java.util.concurrent.TimeUnit.SECONDS));
        }finally{release.countDown();pool.shutdownNow();}
    }

}
