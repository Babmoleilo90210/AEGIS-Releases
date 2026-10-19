package org.aegis.android;

import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Pure policy used by the real Binder boundary and independently tested on a JVM. */
public final class AndroidPolicy {
    public static final String CORE="org.aegis.core", MAIL="org.aegis.mail", GLAS="org.aegis.glas", STRAZH="org.aegis.strazh";
    public static final String PERMISSION="org.aegis.permission.ECOSYSTEM";
    public static final long LOCK_AFTER=600_000L, LOCAL_LEASE=60_000L;
    private AndroidPolicy() { }
    public static IdentityProtocol.App app(String pkg) {
        if(CORE.equals(pkg))return IdentityProtocol.App.AEGIS;
        if(MAIL.equals(pkg))return IdentityProtocol.App.MAIL;
        if(GLAS.equals(pkg))return IdentityProtocol.App.GLAS;
        if(STRAZH.equals(pkg))return IdentityProtocol.App.STRAZH;
        throw new SecurityException("Неизвестное приложение");
    }
    public static String badge(int count) {return count<=0?"":count>99?"99+":Integer.toString(count);}
    public static boolean callerMatches(int uid,int expectedUid,String[] packages,String expectedPackage,boolean signatureMatches) {
        return uid==expectedUid && uid>=0 && signatureMatches && packages!=null && packages.length==1 && expectedPackage.equals(packages[0]);
    }
    public static byte[] proof(String pkg,String nonce,byte[] publicKey,int operation) {
        app(pkg);IdentityProtocol.nonceValue(nonce);IdentityProtocol.publicKey(publicKey);
        if(operation<1||operation>15)throw new IllegalArgumentException("Операция Binder");
        try {java.io.ByteArrayOutputStream bytes=new java.io.ByteArrayOutputStream();java.io.DataOutputStream out=new java.io.DataOutputStream(bytes);
            out.writeUTF("AEGIS-ANDROID-BINDER/v1");out.writeUTF(pkg);out.writeInt(operation);out.writeUTF(nonce);out.write(publicKey);out.close();return bytes.toByteArray();
        }catch(java.io.IOException impossible){throw new IllegalStateException(impossible);}
    }
    public static void requireGeneration(long generation,long highest,long revoked){if(generation<1||generation<highest||generation<=revoked)throw new SecurityException("Поколение сессии отозвано или понижено");}
    public static final class LeaseClock {
        public final long wall,elapsed,boot,deadline;
        public LeaseClock(long wall,long elapsed,long boot,long deadline) {
            if(wall<0||elapsed<0||boot<0||deadline<=elapsed||deadline-elapsed>IdentityProtocol.MAX_LEASE_MILLIS)throw new IllegalArgumentException("Интервал допуска");
            this.wall=wall;this.elapsed=elapsed;this.boot=boot;this.deadline=deadline;
        }
        public boolean valid(long nowWall,long nowElapsed,long nowBoot) {
            if(nowBoot!=boot||nowElapsed<elapsed||nowElapsed>=deadline)return false;
            long expected=wall+(nowElapsed-elapsed);
            return expected>=wall&&nowWall>=wall&&Math.abs(nowWall-expected)<=120_000L;
        }
    }
    public static void validateCapability(IdentityProtocol.Capability c,byte[] serverKey,String pkg,byte[] proofKey,long now) {
        if(c.appId!=app(pkg)||!IdentityProtocol.verifyCapability(c,serverKey,now)
                ||!java.security.MessageDigest.isEqual(c.proofKey,proofKey)||c.offlineUntil<=now)
            throw new SecurityException("Допуск недействителен или не разрешает автономную работу");
    }
}
