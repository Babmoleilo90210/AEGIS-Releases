package org.aegis.android;

import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.net.Uri;
import android.provider.Settings;
import java.io.*;
import java.security.MessageDigest;

final class OwnApkInstaller {
    static void install(Activity activity,File file,ApkInspection verified)throws Exception {
        if(!AndroidPolicy.CORE.equals(activity.getPackageName()))throw new SecurityException("Установщик доступен в главном приложении");
        AndroidPolicy.app(verified.info.packageName);
        if(verified.info.applicationInfo.minSdkVersion<33||verified.info.applicationInfo.minSdkVersion>android.os.Build.VERSION.SDK_INT||verified.structure.hasNative&&!verified.structure.arm64)throw new SecurityException("APK несовместим с Android 13+ ARM64");
        PackageInfo own=activity.getPackageManager().getPackageInfo(activity.getPackageName(),PackageManager.GET_SIGNING_CERTIFICATES);
        if(own.signingInfo==null||own.signingInfo.hasMultipleSigners()||own.signingInfo.getApkContentsSigners().length!=1||!MessageDigest.isEqual(own.signingInfo.getApkContentsSigners()[0].toByteArray(),verified.certificate))throw new SecurityException("Сертификат APK отличается от установленного АЕГИС");
        try{PackageInfo old=activity.getPackageManager().getPackageInfo(verified.info.packageName,0);if(verified.info.getLongVersionCode()<=old.getLongVersionCode())throw new SecurityException("Повторная установка и понижение версии запрещены");}catch(PackageManager.NameNotFoundException firstInstall){/* legitimate first installation */}
        if(!ApkSafety.inspect(file).sha256.equals(verified.structure.sha256))throw new SecurityException("APK изменился после проверки");
        if(!activity.getPackageManager().canRequestPackageInstalls()){activity.startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,Uri.parse("package:"+activity.getPackageName())));throw new SecurityException("Разрешите установку из АЕГИС в системном окне, затем повторите действие");}
        PackageInstaller installer=activity.getPackageManager().getPackageInstaller();PackageInstaller.SessionParams params=new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);params.setAppPackageName(verified.info.packageName);params.setSize(file.length());params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED);int id=installer.createSession(params);boolean committed=false;
        try(PackageInstaller.Session session=installer.openSession(id)){try(InputStream in=new FileInputStream(file);OutputStream out=session.openWrite("base.apk",0,file.length())){byte[] buffer=new byte[65536];for(int n;(n=in.read(buffer))!=-1;)out.write(buffer,0,n);session.fsync(out);}Intent result=new Intent(activity,InstallResultReceiver.class).setAction(activity.getPackageName()+".INSTALL_RESULT");PendingIntent pending=PendingIntent.getBroadcast(activity,id,result,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_MUTABLE);session.commit(pending.getIntentSender());committed=true;}
        finally{if(!committed)installer.abandonSession(id);}
    }
}
