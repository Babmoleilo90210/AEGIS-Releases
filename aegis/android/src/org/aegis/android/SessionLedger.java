package org.aegis.android;

import android.content.Context;
import android.os.SystemClock;
import android.provider.Settings;
import org.json.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Offline signed grants only. There is no fabricated online Identity/Tor connection. */
final class SessionLedger {
    private static SessionLedger instance;
    static synchronized SessionLedger get(Context c){if(instance==null)instance=new SessionLedger(c.getApplicationContext());return instance;}
    private final Context context;private final PrivateVault vault;private final Map<String,String> tokens=new HashMap<>();
    private AndroidPolicy.LeaseClock clock;private byte[] serviceKey;private long generation,highestGeneration,revokedGeneration,lastActivity;private String account="",device="";private boolean locked=true;private long revision;
    private SessionLedger(Context c){context=c;vault=new PrivateVault(c);try{restore();}catch(Exception damaged){tokens.clear();locked=true;}}
    private long boot(){return Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT,-1);}
    synchronized long revision(){return revision;}
    synchronized void install(String base64Key,String lines,long expectedRevision)throws Exception {if(revision!=expectedRevision)throw new SecurityException("Ответ входа получен после блокировки или выхода");install(base64Key,lines);}
    synchronized void install(String base64Key,String lines)throws Exception {
        byte[] pin=IdentityProtocol.unb64(base64Key.trim(),44);IdentityProtocol.publicKey(pin);Map<String,String> parsed=new HashMap<>();long now=System.currentTimeMillis();String a=null,d=null;long g=-1,expiry=Long.MAX_VALUE;
        if(lines.length()>24576)throw new SecurityException("Слишком большой набор допусков");
        for(String line:lines.split("\\r?\\n")){line=line.trim();if(line.isEmpty())continue;IdentityProtocol.Capability cap=IdentityProtocol.decodeCapability(line);
            if(!IdentityProtocol.verifyCapability(cap,pin,now)||cap.offlineUntil<=now)throw new SecurityException("Подпись или срок допуска недействительны");
            String pkg=packageFor(cap.appId);if(parsed.put(pkg,line)!=null)throw new SecurityException("Дубликат приложения");
            if(a==null){a=cap.accountId;d=cap.deviceId;g=cap.generation;}else if(!a.equals(cap.accountId)||!d.equals(cap.deviceId)||g!=cap.generation)throw new SecurityException("Допуски разных сессий");
            expiry=Math.min(expiry,cap.offlineUntil);
        }
        String core=parsed.get(AndroidPolicy.CORE);if(core==null)throw new SecurityException("Отсутствует допуск главного приложения");IdentityProtocol.Capability c=IdentityProtocol.decodeCapability(core);
        AndroidPolicy.validateCapability(c,pin,AndroidPolicy.CORE,vault.appPublicKey(),now);
        if(!account.isEmpty()&&!account.equals(a))throw new SecurityException("Смена локального аккаунта требует отдельного безопасного переноса; он пока не реализован");AndroidPolicy.requireGeneration(g,highestGeneration,revokedGeneration);
        if(serviceKey!=null&&!java.security.MessageDigest.isEqual(serviceKey,pin))throw new SecurityException("Изменение закреплённого ключа требует отдельной процедуры доверия");
        revision++;locked=true;long elapsed=SystemClock.elapsedRealtime();clock=new AndroidPolicy.LeaseClock(now,elapsed,boot(),Math.addExact(elapsed,expiry-now));tokens.clear();tokens.putAll(parsed);if(!account.equals(a)){highestGeneration=0;revokedGeneration=0;}account=a;device=d;generation=g;highestGeneration=Math.max(highestGeneration,g);serviceKey=pin;lastActivity=elapsed;save();locked=false;
    }
    static String packageFor(IdentityProtocol.App app){switch(app){case AEGIS:return AndroidPolicy.CORE;case MAIL:return AndroidPolicy.MAIL;case GLAS:return AndroidPolicy.GLAS;case STRAZH:return AndroidPolicy.STRAZH;default:throw new SecurityException("Этот Android компонент не поддерживается");}}
    synchronized boolean active(){if(locked||clock==null||!clock.valid(System.currentTimeMillis(),SystemClock.elapsedRealtime(),boot())||SystemClock.elapsedRealtime()-lastActivity>=AndroidPolicy.LOCK_AFTER){locked=true;return false;}return true;}
    synchronized String lease(String pkg,byte[] proofKey)throws Exception {
        if(!active())throw new SecurityException("Сессия заблокирована");String token=tokens.get(pkg);if(token==null)throw new SecurityException("Допуск приложения отсутствует");IdentityProtocol.Capability c=IdentityProtocol.decodeCapability(token);AndroidPolicy.validateCapability(c,serviceKey,pkg,proofKey,System.currentTimeMillis());if(c.generation!=generation||!c.accountId.equals(account)||!c.deviceId.equals(device))throw new SecurityException("Поколение сессии отозвано");return token;
    }
    synchronized String publicPin(){if(serviceKey==null)throw new SecurityException("Серверный ключ не задан");return IdentityProtocol.b64(serviceKey);}
    synchronized String coreToken(){if(!active())throw new SecurityException("Сессия заблокирована");String wire=tokens.get(AndroidPolicy.CORE);if(wire==null)throw new SecurityException("Главный допуск отсутствует");return wire;}
    synchronized String tokenForLogout(){String wire=tokens.get(AndroidPolicy.CORE);if(wire==null)throw new SecurityException("Нет допуска для серверного выхода");return wire;}
    synchronized void requireSameAccount(String id){if(!account.isEmpty()&&!account.equals(id))throw new SecurityException("Смена аккаунта без защищённого переноса не разрешена");}
    synchronized void addCapability(String pkg,String wire)throws Exception {if(!active())throw new SecurityException("Сессия заблокирована");IdentityProtocol.Capability c=IdentityProtocol.decodeCapability(wire);if(!IdentityProtocol.verifyCapability(c,serviceKey,System.currentTimeMillis())||!c.accountId.equals(account)||!c.deviceId.equals(device)||c.generation!=generation||c.appId!=AndroidPolicy.app(pkg)||c.offlineUntil<=System.currentTimeMillis())throw new SecurityException("Допуск другой сессии");tokens.put(pkg,wire);try{save();}catch(Exception fail){tokens.remove(pkg);throw fail;}}
    synchronized void touch(){if(active())lastActivity=SystemClock.elapsedRealtime();}
    synchronized void lock(){locked=true;revision++;}
    synchronized void logout()throws Exception {locked=true;revision++;revokedGeneration=Math.max(revokedGeneration,generation);tokens.clear();clock=null;generation=0;save();}
    synchronized String status(){return active()?"Подписанный допуск действителен · сетевой статус смотрите в Identity":"Сессия заблокирована · войдите через Identity или импортируйте допуск";}
    private void save()throws Exception {JSONObject json=new JSONObject();json.put("pin",serviceKey==null?"":IdentityProtocol.b64(serviceKey));json.put("account",account);json.put("device",device);json.put("generation",generation);json.put("highestGeneration",highestGeneration);json.put("revokedGeneration",revokedGeneration);JSONObject t=new JSONObject();for(Map.Entry<String,String> e:tokens.entrySet())t.put(e.getKey(),e.getValue());json.put("tokens",t);if(clock!=null){json.put("wall",clock.wall);json.put("elapsed",clock.elapsed);json.put("boot",clock.boot);json.put("deadline",clock.deadline);}byte[] b=json.toString().getBytes(StandardCharsets.UTF_8);try{vault.put("session-ledger",b);}finally{Arrays.fill(b,(byte)0);}}
    private void restore()throws Exception {byte[] b=vault.get("session-ledger");if(b==null)return;try{JSONObject j=new JSONObject(new String(b,StandardCharsets.UTF_8));String pin=j.getString("pin");serviceKey=pin.isEmpty()?null:IdentityProtocol.unb64(pin,44);account=j.getString("account");device=j.getString("device");highestGeneration=j.getLong("highestGeneration");revokedGeneration=j.optLong("revokedGeneration",0);/* Process restart never silently unlocks old capabilities. */locked=true;}finally{Arrays.fill(b,(byte)0);}}
}
