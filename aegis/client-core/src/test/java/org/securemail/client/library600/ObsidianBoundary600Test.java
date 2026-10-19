package org.securemail.client.library600;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.apache.commons.compress.archivers.tar.*;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Distribution/parser/process-policy fixtures. NOT an official Obsidian/native sandbox acceptance. */
class ObsidianBoundary600Test {
    @TempDir Path dir;
    Path archive()throws Exception {
        Path file=dir.resolve(UUID.randomUUID()+".tar.gz");try(var tar=new TarArchiveOutputStream(new GzipCompressorOutputStream(Files.newOutputStream(file)))){
            entry(tar,"obsidian-1.14.4/obsidian","#!/bin/sh\nexit 0\n",0700);entry(tar,"obsidian-1.14.4/resources/app.asar","fixture only",0600);
        }return file;
    }
    static void entry(TarArchiveOutputStream tar,String path,String body,int mode)throws Exception{byte[]bytes=body.getBytes(StandardCharsets.UTF_8);var e=new TarArchiveEntry(path);e.setSize(bytes.length);e.setMode(mode);tar.putArchiveEntry(e);tar.write(bytes);tar.closeArchiveEntry();}
    ObsidianDistribution600.Release release(Path archive)throws Exception{return new ObsidianDistribution600.Release("1.14.4",URI.create("https://github.com/obsidianmd/obsidian-releases/releases/download/v1.14.4/obsidian-1.14.4.tar.gz"),Files.size(archive),ObsidianDistribution600.hash(archive));}
    ObsidianDistribution600 install(Path archive,Path dest)throws Exception{return ObsidianDistribution600.install(release(archive),dest,()->false,(r,target,cancel)->Files.copy(archive,target));}
    @Test void reviewedPackageIsAtomicAndEveryExecutableResourceIsReverified()throws Exception {
        Path source=archive();var d=install(source,dir.resolve("installed"));d.verify();assertEquals("1.14.4",d.version());
        ObsidianDistribution600.reopenLinux(d.root(),release(source),d.receiptSha256()).verify();
        assertThrows(IOException.class,()->ObsidianDistribution600.reopenLinux(d.root(),release(source),"0".repeat(64)));
        Files.writeString(d.root().resolve("resources/app.asar"),"substituted");assertThrows(IOException.class,d::verify);
        assertThrows(IOException.class,()->install(source,d.root()));assertEquals("substituted",Files.readString(d.root().resolve("resources/app.asar")));
        try(var children=Files.list(dir)){assertTrue(children.noneMatch(p->p.getFileName().toString().startsWith(".obsidian-install-")));}
    }
    @Test void wrongPinAndCancelledPreparationNeverPublishBundle()throws Exception {
        Path source=archive(),target=dir.resolve("missing");var r=release(source);var bad=new ObsidianDistribution600.Release(r.version(),r.source(),r.size(),"f".repeat(64));
        assertThrows(IOException.class,()->ObsidianDistribution600.install(bad,target,()->false,(v,p,c)->Files.copy(source,p)));assertFalse(Files.exists(target));
        assertThrows(InterruptedIOException.class,()->ObsidianDistribution600.install(r,target,()->true,(v,p,c)->Files.copy(source,p)));assertFalse(Files.exists(target));
    }
    @Test void traversalSymlinksAndDuplicateArchiveNamesAreRejectedBeforePublication()throws Exception {
        for(int mode=0;mode<3;mode++) {Path source=dir.resolve("bad"+mode+".tar.gz");try(var tar=new TarArchiveOutputStream(new GzipCompressorOutputStream(Files.newOutputStream(source)))){
            if(mode==0)entry(tar,"../outside","bad",0600);
            else if(mode==1){var e=new TarArchiveEntry("bundle/link",TarConstants.LF_SYMLINK);e.setLinkName("../../outside");tar.putArchiveEntry(e);tar.closeArchiveEntry();}
            else{entry(tar,"same","first",0600);entry(tar,"same","second",0600);}
        }Path target=dir.resolve("denied"+mode);assertThrows(IOException.class,()->install(source,target));assertFalse(Files.exists(target));assertFalse(Files.exists(dir.resolve("outside")));}
    }
    @Test void officialSourceAndEveryRedirectAreNarrowlyBound()throws Exception {
        Path source=archive();var r=release(source);
        assertThrows(IllegalArgumentException.class,()->new ObsidianDistribution600.Release(r.version(),URI.create(r.source().toString().replace("obsidianmd","attacker")),r.size(),r.sha256()));
        ObsidianHttps600.validate(r.source(),r.source(),true);ObsidianHttps600.validate(URI.create("https://release-assets.githubusercontent.com/github-production-release-asset/123/abc?token=signed"),r.source(),false);
        for(String url:List.of("https://github.com/attacker/release","https://raw.githubusercontent.com/obsidianmd/obsidian-releases/file","http://github.com/obsidianmd","https://release-assets.githubusercontent.com/anything","https://user:pass@release-assets.githubusercontent.com/github-production-release-asset/1/x"))assertThrows(IOException.class,()->ObsidianHttps600.validate(URI.create(url),r.source(),false));
    }
    @Test void protectedCommandHasNoNetworkHostIpcOrChromiumSandboxBypass() {
        var args=LinuxObsidianBoundary600.command(dir.resolve("bundle"),dir.resolve("projection"),dir.resolve("settings"),dir.resolve("auth"),Path.of("/tmp/.X11-unix/X123"),123);
        assertTrue(args.contains("--unshare-all"));assertTrue(args.contains("--new-session"));assertTrue(args.contains("--die-with-parent"));assertFalse(args.contains("--share-net"));assertFalse(args.contains("--no-sandbox"));assertFalse(args.contains("--disable-setuid-sandbox"));assertFalse(args.contains("--bind"));assertFalse(args.contains("/run/user"));assertFalse(args.contains("/dev/snd"));assertFalse(args.contains("slirp4netns"));
        assertTrue(args.contains("/home/library/vault/projection"));assertEquals("/opt/obsidian/obsidian",args.get(args.indexOf("--")+1));
    }
    @Test void personalProcessGetsOnlyItsOwnWritableVaultAndConfigurationInSeparateNetworkNamespace(){
        Path vault=dir.resolve("personal-vault"),config=dir.resolve("personal-profile");var args=LinuxObsidianBoundary600.personalCommand(dir.resolve("bundle"),vault,config,dir.resolve("runtime/auth"),Path.of("/tmp/.X11-unix/X123"),123);
        assertTrue(args.contains("--unshare-all"));assertFalse(args.contains("--share-net"));assertFalse(args.contains("--no-sandbox"));assertTrue(args.contains("--info-fd"));assertTrue(args.contains("--block-fd"));
        List<String>rw=new ArrayList<>();for(int n=0;n<args.size();n++)if(args.get(n).equals("--bind"))rw.add(args.get(n+1));assertEquals(List.of(vault.toString(),config.toString()),rw);assertFalse(args.contains("/home/library/vault/.obsidian"));assertTrue(args.contains("/etc/resolv.conf"));
    }
    @Test void protectedSettingsCopyOnlyPinnedCodeAndCannotEnableUnapprovedPlugins()throws Exception {
        Path source=archive();var d=install(source,dir.resolve("bundle"));Path vault=Files.createDirectory(dir.resolve("vault")),config=Files.createDirectory(dir.resolve("config"));Path plugin=Files.createDirectories(vault.resolve(".obsidian/plugins/approved"));Files.writeString(plugin.resolve("main.js"),"module.exports={};");Files.writeString(plugin.resolve("manifest.json"),"{\"id\":\"approved\"}");
        var plan=ObsidianProfile600.validate(ObsidianProfile600.Mode.PROTECTED,d.binary(),ObsidianDistribution600.hash(d.binary()),vault,config,Map.of("approved",ObsidianDistribution600.hash(plugin.resolve("main.js"))));
        Path settings=LinuxObsidianBoundary600.prepareSettings(Files.createDirectory(dir.resolve("run")),plan);assertEquals("[\"approved\"]",Files.readString(settings.resolve("community-plugins.json")));assertFalse(Files.exists(settings.resolve("app.json")));assertFalse(Files.readString(settings.resolve("core-plugins.json")).contains("sync"));
        Files.writeString(plugin.resolve("main.js"),"changed");assertThrows(IOException.class,()->LinuxObsidianBoundary600.prepareSettings(Files.createDirectory(dir.resolve("run2")),plan));
    }
}
