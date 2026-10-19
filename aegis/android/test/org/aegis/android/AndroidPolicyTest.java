package org.aegis.android;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.zip.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** JVM tests for production policy code; these are not Android/native IPC tests. */
public final class AndroidPolicyTest {
    private static int passed;
    private interface Check {void run()throws Exception;}
    private static void test(String name,Check c)throws Exception{c.run();passed++;System.out.println("PASS "+name);}
    private static void check(boolean value){if(!value)throw new AssertionError();}
    private static void denied(Check c)throws Exception{try{c.run();}catch(SecurityException|IllegalArgumentException|IOException expected){return;}throw new AssertionError("Expected denial");}
    public static void main(String[] args)throws Exception{
        test("package-to-app-fixed",()->check(AndroidPolicy.app(AndroidPolicy.MAIL)==IdentityProtocol.App.MAIL));
        test("unknown-package-denied",()->denied(()->AndroidPolicy.app("org.aegis.evil")));
        test("caller-all-checks-positive",()->check(AndroidPolicy.callerMatches(10001,10001,new String[]{AndroidPolicy.MAIL},AndroidPolicy.MAIL,true)));
        test("caller-uid-mismatch",()->check(!AndroidPolicy.callerMatches(10002,10001,new String[]{AndroidPolicy.MAIL},AndroidPolicy.MAIL,true)));
        test("caller-package-mismatch",()->check(!AndroidPolicy.callerMatches(10001,10001,new String[]{AndroidPolicy.STRAZH},AndroidPolicy.MAIL,true)));
        test("caller-certificate-mismatch",()->check(!AndroidPolicy.callerMatches(10001,10001,new String[]{AndroidPolicy.MAIL},AndroidPolicy.MAIL,false)));
        test("shared-uid-denied",()->check(!AndroidPolicy.callerMatches(10001,10001,new String[]{AndroidPolicy.MAIL,AndroidPolicy.STRAZH},AndroidPolicy.MAIL,true)));
        test("badge-bounds",()->check(AndroidPolicy.badge(0).isEmpty()&&AndroidPolicy.badge(-1).isEmpty()&&AndroidPolicy.badge(99).equals("99")&&AndroidPolicy.badge(100).equals("99+")));
        AndroidPolicy.LeaseClock clock=new AndroidPolicy.LeaseClock(1_000_000,500,7,60_500);
        test("monotonic-valid",()->check(clock.valid(1_001_000,1500,7)));
        test("expiry-denied",()->check(!clock.valid(1_060_000,60_500,7)));
        test("clock-rollback-denied",()->check(!clock.valid(999_999,1500,7)));
        test("reboot-denied",()->check(!clock.valid(1_001_000,1500,8)));
        test("elapsed-rollback-denied",()->check(!clock.valid(1_001_000,499,7)));
        test("future-clock-jump-denied",()->check(!clock.valid(2_000_000,1500,7)));
        test("offline-over-24-hours-denied",()->denied(()->new AndroidPolicy.LeaseClock(1,1,1,86_400_002)));
        test("generation-forward-accepted",()->AndroidPolicy.requireGeneration(7,6,5));
        test("generation-rollback-rejected",()->denied(()->AndroidPolicy.requireGeneration(5,6,0)));
        test("logout-generation-reimport-rejected",()->denied(()->AndroidPolicy.requireGeneration(6,6,6)));
        KeyPairGenerator generator=KeyPairGenerator.getInstance("Ed25519");KeyPair server=generator.generateKeyPair(),app=generator.generateKeyPair(),other=generator.generateKeyPair();long now=System.currentTimeMillis();
        IdentityProtocol.Capability cap=new IdentityProtocol.Capability(IdentityProtocol.id(server.getPublic().getEncoded()),IdentityProtocol.id(other.getPublic().getEncoded()),IdentityProtocol.id(app.getPublic().getEncoded()),IdentityProtocol.App.MAIL,3,IdentityProtocol.nonce(),now-1000,now+60_000,now+30_000,app.getPublic().getEncoded(),EnumSet.of(IdentityProtocol.Scope.MAIL_READ),new byte[0]);cap=cap.signed(IdentityProtocol.sign(server.getPrivate(),IdentityProtocol.capabilityBytes(cap)));final IdentityProtocol.Capability valid=cap;
        test("actual-shared-server-capability-verifies",()->AndroidPolicy.validateCapability(valid,server.getPublic().getEncoded(),AndroidPolicy.MAIL,app.getPublic().getEncoded(),now));
        test("cross-app-capability-denied",()->denied(()->AndroidPolicy.validateCapability(valid,server.getPublic().getEncoded(),AndroidPolicy.GLAS,app.getPublic().getEncoded(),now)));
        test("wrong-proof-key-denied",()->denied(()->AndroidPolicy.validateCapability(valid,server.getPublic().getEncoded(),AndroidPolicy.MAIL,other.getPublic().getEncoded(),now)));
        test("wrong-authority-denied",()->denied(()->AndroidPolicy.validateCapability(valid,other.getPublic().getEncoded(),AndroidPolicy.MAIL,app.getPublic().getEncoded(),now)));
        test("expired-offline-grant-denied",()->denied(()->AndroidPolicy.validateCapability(valid,server.getPublic().getEncoded(),AndroidPolicy.MAIL,app.getPublic().getEncoded(),now+31_000)));
        test("binder-proof-domain-and-package-bound",()->{String nonce=IdentityProtocol.nonce();byte[] p=AndroidPolicy.proof(AndroidPolicy.MAIL,nonce,app.getPublic().getEncoded(),2);byte[] sig=IdentityProtocol.sign(app.getPrivate(),p);check(IdentityProtocol.verify(app.getPublic().getEncoded(),p,sig));check(!IdentityProtocol.verify(app.getPublic().getEncoded(),AndroidPolicy.proof(AndroidPolicy.GLAS,nonce,app.getPublic().getEncoded(),2),sig));check(!IdentityProtocol.verify(app.getPublic().getEncoded(),AndroidPolicy.proof(AndroidPolicy.MAIL,nonce,app.getPublic().getEncoded(),4),sig));});
        Path tmp=Files.createTempDirectory("aegis-apk-policy ");try{
            test("valid-structural-fixture-only",()->{File f=zip(tmp,"valid.zip",Map.of("AndroidManifest.xml",new byte[20],"classes.dex",new byte[20]));ApkSafety a=ApkSafety.inspect(f);check(!a.hasNative&&a.entries==2&&a.sha256.length()==64);});
            test("zip-traversal-denied",()->denied(()->ApkSafety.inspect(zip(tmp,"traversal.zip",Map.of("../secret",new byte[20],"AndroidManifest.xml",new byte[20],"classes.dex",new byte[20])))));
            test("backslash-path-denied",()->denied(()->ApkSafety.inspect(zip(tmp,"slash.zip",Map.of("x\\secret",new byte[20],"AndroidManifest.xml",new byte[20],"classes.dex",new byte[20])))));
            test("zip-bomb-ratio-denied",()->denied(()->ApkSafety.inspect(zip(tmp,"bomb.zip",Map.of("assets/bomb",new byte[2_000_000],"AndroidManifest.xml",new byte[20],"classes.dex",new byte[20])))));
            test("missing-dex-denied",()->denied(()->ApkSafety.inspect(zip(tmp,"nodex.zip",Map.of("AndroidManifest.xml",new byte[20])))));
            test("copy-stream-limit-and-partial-removal",()->{File f=tmp.resolve("partial.apk").toFile();InputStream huge=new InputStream(){long left=ApkSafety.MAX_APK+1;public int read(){return left-->0?0:-1;}public int read(byte[] b,int off,int len){if(left<=0)return -1;int n=(int)Math.min(left,len);Arrays.fill(b,off,off+n,(byte)0);left-=n;return n;}};denied(()->ApkSafety.copyBounded(huge,f));check(!f.exists());});
            test("arm64-detected-without-claiming-elf-validation",()->{File f=zip(tmp,"native.zip",Map.of("AndroidManifest.xml",new byte[20],"classes.dex",new byte[20],"lib/arm64-v8a/libexample.so",new byte[20]));ApkSafety a=ApkSafety.inspect(f);check(a.arm64&&a.hasNative);});
        }finally{try(java.util.stream.Stream<Path> walk=Files.walk(tmp)){for(Path p:walk.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
        System.out.println("RESULT "+passed+" PASS; Android device/IPC/window/VPN/audio tests NOT_RUN");
    }
    private static File zip(Path directory,String name,Map<String,byte[]> entries)throws IOException{File f=directory.resolve(name).toFile();try(ZipOutputStream out=new ZipOutputStream(new FileOutputStream(f))){for(Map.Entry<String,byte[]> e:entries.entrySet()){out.putNextEntry(new ZipEntry(e.getKey()));out.write(e.getValue());out.closeEntry();}}return f;}
}
