package org.aegis.android;

import com.android.apksig.ApkVerifier;
import java.io.File;

/** Exercises exactly the Google apksig version embedded in our APKs, on the host only. */
public final class ApkLibraryProbe {
    public static void main(String[] args)throws Exception {
        boolean expected=Boolean.parseBoolean(args[1]);ApkVerifier.Result r=new ApkVerifier.Builder(new File(args[0])).setMinCheckedPlatformVersion(33).build().verify();
        if(r.isVerified()!=expected)throw new AssertionError("Unexpected APK signature result");
        System.out.println(expected?"PASS exact embedded apksig 9.4.1 verified actual APK":"PASS exact embedded apksig 9.4.1 rejected actual modified APK");
    }
}
