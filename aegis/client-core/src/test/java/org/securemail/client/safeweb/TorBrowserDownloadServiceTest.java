package org.securemail.client.safeweb;

import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.apache.commons.compress.archivers.tar.*;
import org.tukaani.xz.*;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Real HTTP parser + real disposable OpenPGP signature + real bounded XZ/TAR.
 * No fixture is an official browser; no external network or production key is used. */
class TorBrowserDownloadServiceTest {
    @TempDir Path root;
    static PGPKeyPair key;static byte[] publicKey;static String pin;
    static final Instant NOW=Instant.now();
    @BeforeAll static void keys()throws Exception {
        var generator=new RSAKeyPairGenerator();generator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537),new SecureRandom(),3072,80));
        key=new BcPGPKeyPair(4,PublicKeyAlgorithmTags.RSA_GENERAL,generator.generateKeyPair(),Date.from(NOW.minusSeconds(3600)));
        var packets=packets(NOW.minusSeconds(3600));packets.setKeyFlags(false,KeyFlags.CERTIFY_OTHER|KeyFlags.SIGN_DATA);
        var ring=new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,key,"Disposable AEGIS download fixture <fixture.invalid>",new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),packets.generate(),null,signer(),null);
        publicKey=ring.generatePublicKeyRing().getEncoded();pin=HexFormat.of().withUpperCase().formatHex(key.getPublicKey().getFingerprint());
    }
    static PGPSignatureSubpacketGenerator packets(Instant time){var p=new PGPSignatureSubpacketGenerator();p.setSignatureCreationTime(true,Date.from(time));p.setIssuerFingerprint(false,key.getPublicKey());return p;}
    static BcPGPContentSignerBuilder signer(){return new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL,HashAlgorithmTags.SHA256);}
    static byte[] signature(byte[] bytes)throws Exception {var sign=new PGPSignatureGenerator(signer(),key.getPublicKey());sign.init(PGPSignature.BINARY_DOCUMENT,key.getPrivateKey());sign.setHashedSubpackets(packets(NOW.minusSeconds(30)).generate());sign.update(bytes);return sign.generate().getEncoded();}
    static byte[] version(String v,String arch){return ("{\"version\":\""+v+"\",\"architecture\":\""+arch+"\",\"channel\":\"release\"}").getBytes(StandardCharsets.UTF_8);}
    static byte[] archive(String v)throws Exception {
        var bytes=new ByteArrayOutputStream();try(var xz=new XZOutputStream(bytes,new LZMA2Options());var tar=new TarArchiveOutputStream(xz)) {
            byte[] value=version(v,"linux-x86_64");var entry=new TarArchiveEntry("tor-browser/Browser/tbb_version.json");entry.setSize(value.length);tar.putArchiveEntry(entry);tar.write(value);tar.closeArchiveEntry();
        }return bytes.toByteArray();
    }
    static byte[] metadata(String v,TorBrowserDownloadService.Platform p){String url="https://dist.torproject.org/torbrowser/"+v+"/tor-browser-"+p.packagePlatform+"-"+v+p.extension;return ("{\"binary\":\""+url+"\",\"git_tag\":\"tbb-"+v+"-build2\",\"sig\":\""+url+".asc\",\"version\":\""+v+"\"}").getBytes(StandardCharsets.UTF_8);}
    TorBrowserDownloadService service(String offered,byte[] archive,boolean alter,AtomicInteger calls)throws Exception {
        byte[] asc=signature(archive),sent=archive.clone();if(alter)sent[sent.length/2]^=1;
        return new TorBrowserDownloadService(()->true,(uri,out,limit,cancel,progress)->{
            calls.incrementAndGet();byte[] body=uri.getHost().startsWith("aus1")?metadata(offered,TorBrowserDownloadService.Platform.LINUX_X64):uri.getPath().endsWith(".asc")?asc:sent;
            byte[] head=("HTTP/1.1 200 OK\r\nContent-Length: "+body.length+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
            TorBrowserHttps.readResponse(new SequenceInputStream(new ByteArrayInputStream(head),new ByteArrayInputStream(body)),uri,out,limit,cancel,progress);
        },(a,s)->TorBrowserSignature.verifyTrusted(a,s,new ByteArrayInputStream(publicKey),pin,Clock.systemUTC()));
    }
    @Test void authenticatesRealFixtureBytesAndSignedInternalVersionBeforeReady()throws Exception {
        var progress=new ArrayList<TorBrowserDownloadService.Progress>();var calls=new AtomicInteger();Path download=root.resolve("download");
        Path archive;
        try(var pkg=service("15.0.25",archive("15.0.25"),false,calls).downloadLatest(TorBrowserDownloadService.Platform.LINUX_X64,download,progress::add,new TorBrowserDownloadService.Cancellation())){
            archive=pkg.archive();assertTrue(Files.isRegularFile(archive));assertTrue(Files.isRegularFile(pkg.signature()));assertEquals(pin,pkg.verification().primaryFingerprint());assertEquals("15.0.25",pkg.release().version());assertEquals(3,calls.get());
            assertEquals(TorBrowserDownloadService.Stage.READY,progress.getLast().stage());assertTrue(Files.list(archive.getParent()).noneMatch(p->p.toString().endsWith(".part")));
            if(Files.getFileStore(archive).supportsFileAttributeView("posix"))assertEquals("rw-------",java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(archive)));
        }
        assertFalse(Files.exists(archive));assertEquals("15.0.25",Files.readString(download.resolve("minimum-downloaded-linux-x86_64.txt")).strip());
    }
    @Test void alteredPayloadCannotReachReadyAndTemporaryFilesAreRemoved()throws Exception {
        var events=new ArrayList<TorBrowserDownloadService.Progress>();Path download=root.resolve("download");
        assertThrows(IOException.class,()->service("15.0.25",archive("15.0.25"),true,new AtomicInteger()).downloadLatest(TorBrowserDownloadService.Platform.LINUX_X64,download,events::add,new TorBrowserDownloadService.Cancellation()));
        assertTrue(Files.list(download).findAny().isEmpty());assertEquals(TorBrowserDownloadService.Stage.FAILED,events.getLast().stage());
    }
    @Test void signedOlderArchiveRenamedAsNewerDoesNotPoisonVersionFloor()throws Exception {
        Path download=root.resolve("download");assertThrows(IOException.class,()->service("99.0.0",archive("15.0.25"),false,new AtomicInteger()).downloadLatest(TorBrowserDownloadService.Platform.LINUX_X64,download,p->{},new TorBrowserDownloadService.Cancellation()));assertTrue(Files.list(download).findAny().isEmpty());
    }
    @Test void previouslyAuthenticatedNewerVersionPreventsRollbackBeforeBinaryFetch()throws Exception {
        Path download=root.resolve("download");try(var pkg=service("15.0.25",archive("15.0.25"),false,new AtomicInteger()).downloadLatest(TorBrowserDownloadService.Platform.LINUX_X64,download,p->{},new TorBrowserDownloadService.Cancellation())){assertNotNull(pkg.archive());}
        var calls=new AtomicInteger();assertThrows(IOException.class,()->service("15.0.24",archive("15.0.24"),false,calls).downloadLatest(TorBrowserDownloadService.Platform.LINUX_X64,download,p->{},new TorBrowserDownloadService.Cancellation()));assertEquals(1,calls.get());assertEquals("15.0.25",Files.readString(download.resolve("minimum-downloaded-linux-x86_64.txt")).strip());
    }
    @Test void offlineTorHasNoFetchNoFilesystemMutationAndNoFallback()throws Exception {
        var calls=new AtomicInteger();var events=new ArrayList<TorBrowserDownloadService.Progress>();var service=new TorBrowserDownloadService(()->false,(u,o,l,c,p)->calls.incrementAndGet(),(a,s)->{throw new AssertionError();});
        assertThrows(TorBrowserDownloadService.TorRequiredException.class,()->service.downloadLatest(TorBrowserDownloadService.Platform.LINUX_X64,root.resolve("absent"),events::add,new TorBrowserDownloadService.Cancellation()));assertEquals(0,calls.get());assertFalse(Files.exists(root.resolve("absent")));assertEquals(TorBrowserDownloadService.Stage.WAITING_FOR_TOR,events.getLast().stage());
    }
    @Test void cancellationDuringBodyClosesOwnedResourceAndRemovesPartial()throws Exception {
        var token=new TorBrowserDownloadService.Cancellation();var closed=new AtomicBoolean();var events=new ArrayList<TorBrowserDownloadService.Progress>();
        var service=new TorBrowserDownloadService(()->true,(uri,out,limit,cancel,progress)->{
            if(uri.getHost().startsWith("aus1")){out.write(metadata("15.0.25",TorBrowserDownloadService.Platform.LINUX_X64));return;}
            Closeable resource=()->closed.set(true);cancel.attach(resource);out.write(new byte[31]);cancel.cancel();cancel.check();
        },(a,s)->{throw new AssertionError("verification must not run");});
        assertThrows(InterruptedIOException.class,()->service.downloadLatest(TorBrowserDownloadService.Platform.LINUX_X64,root.resolve("download"),events::add,token));assertTrue(closed.get());assertTrue(Files.list(root.resolve("download")).findAny().isEmpty());assertEquals(TorBrowserDownloadService.Stage.CANCELLED,events.getLast().stage());
    }
    @Test void refusesSymlinkDownloadRootAndPreservesOutsideSentinel()throws Exception {
        Path outside=Files.createDirectory(root.resolve("outside"));Files.writeString(outside.resolve("keep"),"keep");Files.createSymbolicLink(root.resolve("link"),outside);
        assertThrows(IOException.class,()->service("15.0.25",archive("15.0.25"),false,new AtomicInteger()).downloadLatest(TorBrowserDownloadService.Platform.LINUX_X64,root.resolve("link"),p->{},new TorBrowserDownloadService.Cancellation()));assertEquals("keep",Files.readString(outside.resolve("keep")));
    }
    @Test void discoveryMetadataIsStrictAndBoundToExactPlatformVersionSignatureAndOrigin()throws Exception {
        for(var platform:TorBrowserDownloadService.Platform.values()){var data=metadata("15.0.25",platform);assertEquals("15.0.25",TorBrowserDownloadService.parseMetadata(data,platform).version());}
        String good=new String(metadata("15.0.25",TorBrowserDownloadService.Platform.LINUX_X64),StandardCharsets.UTF_8);
        for(String bad:List.of(good.replace("\"version\":","\"unknown\":\"x\",\"version\":"),good.replace("\"version\":\"15.0.25\"","\"version\":\"15.0.25\",\"version\":\"15.0.25\""),good+"{}",good.replace("https:","http:"),good.replace("dist.torproject.org","dist.torproject.org.evil"),good.replace("linux-x86_64","windows-x86_64-portable"),good.replace(".asc\"",".exe\""),good.replace("15.0.25","15.0a2"),good.replace("build2","build0")))assertThrows(IOException.class,()->TorBrowserDownloadService.parseMetadata(bad.getBytes(StandardCharsets.UTF_8),TorBrowserDownloadService.Platform.LINUX_X64),bad);
        assertThrows(IOException.class,()->TorBrowserDownloadService.parseMetadata(new byte[]{(byte)0xff},TorBrowserDownloadService.Platform.LINUX_X64));
    }
    @Test void supportedArchitectureAndNumericVersionOrdering()throws Exception {
        assertEquals(TorBrowserDownloadService.Platform.WINDOWS_X64,TorBrowserDownloadService.Platform.detect("Windows 11","amd64"));assertEquals(TorBrowserDownloadService.Platform.LINUX_X64,TorBrowserDownloadService.Platform.detect("Linux","x86_64"));
        assertThrows(IOException.class,()->TorBrowserDownloadService.Platform.detect("Linux","aarch64"));assertThrows(IOException.class,()->TorBrowserDownloadService.Platform.detect("Mac OS X","x86_64"));assertTrue(TorBrowserDownloadService.compareVersions("15.0.25","15.0.9")>0);assertEquals(0,TorBrowserDownloadService.compareVersions("15.0","15.0.0"));
    }
}
