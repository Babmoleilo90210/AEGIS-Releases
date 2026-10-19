package org.aegis.android;

import android.content.*;
import android.content.pm.*;
import android.os.Binder;
import java.security.*;

final class PackageTrust {
    static String caller(Context context){
        context.enforceCallingPermission(AndroidPolicy.PERMISSION,"Требуется подпись АЕГИС");
        int uid=Binder.getCallingUid();PackageManager pm=context.getPackageManager();String[] packages=pm.getPackagesForUid(uid);
        if(packages==null||packages.length!=1)throw new SecurityException("Неизвестный UID");String pkg=packages[0];AndroidPolicy.app(pkg);
        try {
            int expected=pm.getApplicationInfo(pkg,0).uid;
            if(!AndroidPolicy.callerMatches(uid,expected,packages,pkg,pm.checkSignatures(uid,android.os.Process.myUid())==PackageManager.SIGNATURE_MATCH))throw new SecurityException("Подпись или UID не совпадает");
            PackageInfo own=pm.getPackageInfo(context.getPackageName(),PackageManager.GET_SIGNING_CERTIFICATES);
            if(own.signingInfo==null||own.signingInfo.hasMultipleSigners())throw new SecurityException("Неоднозначная подпись");
            android.content.pm.Signature[] certs=own.signingInfo.getApkContentsSigners();if(certs.length!=1||!pm.hasSigningCertificate(pkg,MessageDigest.getInstance("SHA-256").digest(certs[0].toByteArray()),PackageManager.CERT_INPUT_SHA256))throw new SecurityException("Недоверенная цепочка подписи");
            return pkg;
        }catch(PackageManager.NameNotFoundException|GeneralSecurityException failure){throw new SecurityException("Не удалось подтвердить пакет",failure);}
    }
    static void verifyInstalled(Context c,String pkg)throws Exception {
        AndroidPolicy.app(pkg);PackageManager pm=c.getPackageManager();PackageInfo target=pm.getPackageInfo(pkg,PackageManager.GET_SIGNING_CERTIFICATES);
        if(target.applicationInfo==null||pm.checkSignatures(c.getPackageName(),pkg)!=PackageManager.SIGNATURE_MATCH||target.signingInfo==null||target.signingInfo.hasMultipleSigners())throw new SecurityException("Подпись установленного приложения не совпадает");
    }
}
