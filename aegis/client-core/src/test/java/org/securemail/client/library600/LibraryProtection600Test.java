package org.securemail.client.library600;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class LibraryProtection600Test {
    @TempDir Path dir;
    String account="a".repeat(64),device="device_1",id=UUID.randomUUID().toString();
    AtomicLong wall=new AtomicLong(100000),nano=new AtomicLong(0);
    Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochMilli(wall.get());}public long millis(){return wall.get();}};
    LibraryLease600 lease()throws Exception{return LibraryLease600.acceptVerified(account,device,1,5,100000,110000,true,clock,nano::get);}
    VaultProjection600.Context context(){return new VaultProjection600.Context(account,device,1,5);}
    @Test void leaseRejectsOnlineOnlyAndOver24hours()throws Exception {
        assertThrows(IOException.class,()->LibraryLease600.acceptVerified(account,device,1,5,100000,110000,false,clock,nano::get));
        assertThrows(IOException.class,()->LibraryLease600.acceptVerified(account,device,1,5,1,LibraryLease600.MAX_OFFLINE_MILLIS+2,true,clock,nano::get));
    }
    @Test void monotonicExpiryCannotBeExtendedByWallClock()throws Exception {
        var lease=lease();nano.set(10_000_000_000L);assertThrows(IOException.class,()->lease.require(account,device,1,5));
    }
    @Test void wallRollbackAndForwardJumpFailClosed()throws Exception {
        var first=lease();wall.decrementAndGet();assertThrows(IOException.class,()->first.require(account,device,1,5));
        wall.set(100000);var target=lease();wall.set(110000);assertThrows(IOException.class,()->target.require(account,device,1,5));
    }
    @Test void generationDeviceEpochAndRevocationBound()throws Exception {
        var lease=lease();lease.require(account,device,1,5);
        assertThrows(IOException.class,()->lease.require(account,device,2,5));assertThrows(IOException.class,()->lease.require(account,"other",1,5));assertThrows(IOException.class,()->lease.require(account,device,1,6));lease.revoke();assertThrows(IOException.class,()->lease.require(account,device,1,5));
    }
    @Test void nanoTimeWrapRemainsBounded()throws Exception {
        nano.set(Long.MAX_VALUE-1_000_000_000L);var lease=lease();nano.set(Long.MIN_VALUE+1_000_000_000L);lease.require(account,device,1,5);nano.set(Long.MIN_VALUE+11_000_000_000L);assertThrows(IOException.class,()->lease.require(account,device,1,5));
    }
    @Test void writesOnlyUuidAtomicallyAndPreservesPreviousOnFailure()throws Exception {
        try(var vault=new VaultProjection600(dir.resolve("projection"))){Path file=vault.publish(id,1,"# Русский текст",lease(),context());assertEquals("# Русский текст",Files.readString(file));assertThrows(IOException.class,()->vault.publish(id,1,"old",lease(),context()));assertThrows(IOException.class,()->vault.publish("../../escape",2,"bad",lease(),context()));assertThrows(IOException.class,()->vault.publish(id,2,"x".repeat(1024*1024+1),lease(),context()));assertEquals("# Русский текст",Files.readString(file));assertFalse(Files.exists(dir.resolve("escape.md")));}
    }
    @Test void expiryPrunesAndCloseClearsPlaintext()throws Exception {
        var vault=new VaultProjection600(dir.resolve("projection"));Path file=vault.publish(id,1,"body",lease(),context());nano.set(10_000_000_000L);vault.prune();assertFalse(Files.exists(file));nano.set(0);file=vault.publish(id,2,"body",lease(),context());vault.close();assertFalse(Files.exists(file));assertThrows(IOException.class,()->vault.publish(id,3,"body",lease(),context()));
    }
    @Test void restartClearsOnlyOwnedProjectionAndNeedsFreshPermit()throws Exception {
        Path root=dir.resolve("projection");var first=new VaultProjection600(root);Path file=first.publish(id,1,"body",lease(),context());try(var restarted=new VaultProjection600(root)){assertFalse(Files.exists(file));assertEquals(1,Files.list(root).count());}first.close();
    }
    @Test void existingUserDirectoryNeverAdopted()throws Exception {
        Path root=Files.createDirectory(dir.resolve("personal"));Files.writeString(root.resolve("my-note.md"),"personal");assertThrows(IOException.class,()->new VaultProjection600(root));assertEquals("personal",Files.readString(root.resolve("my-note.md")));
    }
    @Test void symlinkTargetAndAncestorRejected()throws Exception {
        Path outside=Files.writeString(dir.resolve("outside"),"untouched");try(var vault=new VaultProjection600(dir.resolve("projection"))){Files.createSymbolicLink(dir.resolve("projection").resolve(id+".md"),outside);assertThrows(IOException.class,()->vault.publish(id,1,"bad",lease(),context()));assertEquals("untouched",Files.readString(outside));}
        Files.createSymbolicLink(dir.resolve("alias"),dir);assertThrows(IOException.class,()->new VaultProjection600(dir.resolve("alias/other")));
    }
    @Test void remoteEmbedsAndMalformedUnicodeRejected()throws Exception {
        try(var vault=new VaultProjection600(dir.resolve("projection"))){assertThrows(IOException.class,()->vault.publish(id,1,"![secret](https://evil.example/pixel)",lease(),context()));assertThrows(IOException.class,()->vault.publish(id,1,"bad\ud800",lease(),context()));assertThrows(IOException.class,()->vault.publish(id,1,"<img src=\"https://evil.example/pixel\">",lease(),context()));assertThrows(IOException.class,()->vault.publish(id,1,"![[../../private]]",lease(),context()));}
    }
    @Test void syncthingPolicyHasNoProxyFallbackOrDiscovery()throws Exception {
        var env=SyncthingPolicy600.environment(19050);assertEquals("1",env.get("ALL_PROXY_NO_FALLBACK"));assertEquals("socks5://127.0.0.1:19050",env.get("ALL_PROXY"));
        var process=new ProcessBuilder("syncthing");process.environment().put("https_proxy","http://direct.example");process.environment().put("NO_PROXY","*");SyncthingPolicy600.applyEnvironment(process,19050);assertFalse(process.environment().containsKey("https_proxy"));assertFalse(process.environment().containsKey("NO_PROXY"));assertEquals("1",process.environment().get("ALL_PROXY_NO_FALLBACK"));
        String config=SyncthingPolicy600.config("AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA","a".repeat(56)+".onion",22000,"f".repeat(32),"/private/vault & notes");
        assertTrue(config.contains("type=\"receiveonly\""));for(String field:List.of("globalAnnounceEnabled","localAnnounceEnabled","relaysEnabled","natEnabled"))assertTrue(config.contains("<"+field+">false</"+field+">"));assertFalse(config.contains("quic://"));assertTrue(config.contains("&amp;"));assertThrows(IllegalArgumentException.class,()->SyncthingPolicy600.config("untrusted","x",22000,"f".repeat(32),"/x"));
    }
    String sha(Path p)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)));}
    @Test void protectedProfilePinsExecutableAndRefusesUnexpectedPlugins()throws Exception {
        Path exe=Files.writeString(dir.resolve("obsidian"),"test-fixture-not-official-app"),vault=Files.createDirectory(dir.resolve("vault")),config=Files.createDirectory(dir.resolve("config"));
        var plan=ObsidianProfile600.validate(ObsidianProfile600.Mode.PROTECTED,exe,sha(exe),vault,config,Map.of());assertTrue(plan.requiresOsIsolation());assertThrows(IOException.class,()->ObsidianProfile600.validate(ObsidianProfile600.Mode.PROTECTED,exe,"0".repeat(64),vault,config,Map.of()));
        Path plugin=Files.createDirectories(vault.resolve(".obsidian/plugins/evil"));Files.writeString(plugin.resolve("main.js"),"evil");assertThrows(IOException.class,()->ObsidianProfile600.validate(ObsidianProfile600.Mode.PROTECTED,exe,sha(exe),vault,config,Map.of()));
    }
    @Test void approvedScriptChangedOrExtraCodeFailsProfileCheck()throws Exception {
        Path exe=Files.writeString(dir.resolve("obsidian"),"fixture"),vault=Files.createDirectory(dir.resolve("vault")),config=Files.createDirectory(dir.resolve("config")),plugin=Files.createDirectories(vault.resolve(".obsidian/plugins/approved")),script=Files.writeString(plugin.resolve("main.js"),"audited");
        var approved=Map.of("approved",sha(script));ObsidianProfile600.validate(ObsidianProfile600.Mode.PROTECTED,exe,sha(exe),vault,config,approved);
        Files.writeString(script,"changed");assertThrows(IOException.class,()->ObsidianProfile600.validate(ObsidianProfile600.Mode.PROTECTED,exe,sha(exe),vault,config,approved));Files.writeString(script,"audited");Files.writeString(plugin.resolve("extra.js"),"evil");assertThrows(IOException.class,()->ObsidianProfile600.validate(ObsidianProfile600.Mode.PROTECTED,exe,sha(exe),vault,config,approved));
    }
}
