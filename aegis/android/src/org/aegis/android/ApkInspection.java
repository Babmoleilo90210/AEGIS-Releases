package org.aegis.android;

import android.content.Context;
import android.content.pm.*;
import com.android.apksig.ApkVerifier;
import java.io.*;
import java.security.*;
import java.util.*;

/** Actual v2/v3 signature and digest validation using Google's Apache-2.0 apksig library. */
final class ApkInspection {
    final ApkSafety structure;final PackageInfo info;final byte[] certificate;final String certificateSha256;final List<String> risks;
    private ApkInspection(ApkSafety safety,PackageInfo info,byte[] cert,String hash,List<String> risks){structure=safety;this.info=info;certificate=cert;certificateSha256=hash;this.risks=Collections.unmodifiableList(risks);}
    static ApkInspection inspect(Context c,File file)throws Exception {
        ApkSafety structural=ApkSafety.inspect(file);
        ApkVerifier.Result result=new ApkVerifier.Builder(file).setMinCheckedPlatformVersion(33).build().verify();
        if(!result.isVerified()||(!result.isVerifiedUsingV2Scheme()&&!result.isVerifiedUsingV3Scheme())||result.getSignerCertificates().size()!=1)throw new SecurityException("Подпись APK v2/v3 не подтверждена или подписант неоднозначен");
        byte[] certificate=result.getSignerCertificates().get(0).getEncoded();String certHash=hex(MessageDigest.getInstance("SHA-256").digest(certificate));
        PackageInfo info=c.getPackageManager().getPackageArchiveInfo(file.getAbsolutePath(),PackageManager.GET_PERMISSIONS|PackageManager.GET_SIGNING_CERTIFICATES);
        if(info==null||info.applicationInfo==null||info.signingInfo==null||info.signingInfo.hasMultipleSigners())throw new SecurityException("Android не распознал подписанный APK");
        android.content.pm.Signature[] systemCerts=info.signingInfo.getApkContentsSigners();if(systemCerts.length!=1||!MessageDigest.isEqual(certificate,systemCerts[0].toByteArray()))throw new SecurityException("Проверки сертификата APK не совпадают");
        List<String> risks=new ArrayList<>();Set<String> permissions=new TreeSet<>();if(info.requestedPermissions!=null)permissions.addAll(Arrays.asList(info.requestedPermissions));
        Map<String,String> flags=new LinkedHashMap<>();flags.put("android.permission.RECORD_AUDIO","Доступ к микрофону");flags.put("android.permission.CAMERA","Доступ к камере");flags.put("android.permission.READ_SMS","Чтение SMS");flags.put("android.permission.READ_CONTACTS","Чтение системных контактов");flags.put("android.permission.ACCESS_FINE_LOCATION","Точное местоположение");flags.put("android.permission.SYSTEM_ALERT_WINDOW","Наложения поверх других приложений");flags.put("android.permission.REQUEST_INSTALL_PACKAGES","Предложение установки APK");flags.put("android.permission.QUERY_ALL_PACKAGES","Просмотр установленных пакетов");flags.put("android.permission.MANAGE_EXTERNAL_STORAGE","Широкий доступ к файлам");
        for(Map.Entry<String,String> e:flags.entrySet())if(permissions.contains(e.getKey()))risks.add(e.getValue());
        if((info.applicationInfo.flags&ApplicationInfo.FLAG_DEBUGGABLE)!=0)risks.add("Разрешена отладка приложения");
        if(info.applicationInfo.targetSdkVersion<33)risks.add("Устаревший targetSdk ниже Android 13");
        if(structural.hasNative&&!structural.arm64)risks.add("Нет собственной библиотеки arm64-v8a");
        return new ApkInspection(structural,info,certificate,certHash,risks);
    }
    String summary(){return "Пакет: "+info.packageName+"\nВерсия: "+info.versionName+" ("+info.getLongVersionCode()+")\nSHA-256: "+structure.sha256+"\nСертификат SHA-256: "+certificateSha256+"\nПодпись v2/v3 и содержимое APK проверены\n"+(risks.isEmpty()?"Опасные разрешения из локального списка не обнаружены":String.join("\n",risks))+"\n\nПроверка не доказывает отсутствие вредоносного кода. Подписанная база угроз и root/spyware-анализ ещё не реализованы. Файл никуда не отправлялся.";}
    static String hex(byte[] b){StringBuilder out=new StringBuilder();for(byte value:b)out.append(String.format(Locale.ROOT,"%02x",value&255));return out.toString();}
}
