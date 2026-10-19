package org.aegis.android;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.glas.protocol600.GlasProtocol600;
import org.securemail.client.voice600.GlasGrant600;

/** One-use, in-memory, typed public grant carrier. Never accepts a signing payload or secret. */
final class VoiceHandoff {
    private String requestId,wire;private long started,until;private IdentityProtocol.Capability glas;private byte[] delivered;
    static final long TTL=60_000;
    static void sameSession(IdentityProtocol.Capability first,IdentityProtocol.Capability second){if(!first.accountId.equals(second.accountId)||!first.deviceId.equals(second.deviceId)||first.generation!=second.generation||!first.audience.equals(second.audience))throw new SecurityException("Допуски разных сессий");}
    private static void valid(IdentityProtocol.Capability cap,byte[] server,long now){if(!IdentityProtocol.verifyCapability(cap,server,now)||cap.offlineUntil<=now)throw new SecurityException("Допуск отозван или истёк");}
    static IdentityProtocol.Capability voiceCapability(String wire,IdentityProtocol.Capability current,byte[] server,long now){if(wire==null||wire.length()>4096)throw new SecurityException("Размер допуска Гласа");IdentityProtocol.Capability cap=IdentityProtocol.decodeCapability(wire);valid(cap,server,now);valid(current,server,now);sameSession(cap,current);if(cap.appId!=IdentityProtocol.App.GLAS||!cap.capabilities.contains(IdentityProtocol.Scope.VOICE_CALL))throw new SecurityException("Нужен допуск Гласа");return cap;}
    synchronized String stage(String capability,IdentityProtocol.Capability current,byte[] server,long wall,long elapsed){IdentityProtocol.Capability cap=voiceCapability(capability,current,server,wall);if(glas!=null&&elapsed>=started&&elapsed<until)throw new SecurityException("Запрос Гласа уже ожидает подтверждения");clear();glas=cap;wire=capability;requestId=IdentityProtocol.nonce();started=elapsed;until=Math.addExact(elapsed,TTL);return requestId;}
    private void alive(IdentityProtocol.Capability current,byte[] server,long wall,long elapsed){if(glas==null||elapsed<started||elapsed>=until){clear();throw new SecurityException("Запрос Гласа отсутствует или истёк");}valid(current,server,wall);valid(glas,server,wall);sameSession(glas,current);}
    private static void mail(IdentityProtocol.Capability current){if(current.appId!=IdentityProtocol.App.MAIL||!current.capabilities.containsAll(java.util.EnumSet.of(IdentityProtocol.Scope.MAIL_READ,IdentityProtocol.Scope.MAIL_SEND,IdentityProtocol.Scope.CONTACTS_READ)))throw new SecurityException("Нужен полный узкий допуск Почты");}
    synchronized String pending(IdentityProtocol.Capability current,byte[] server,long wall,long elapsed){alive(current,server,wall,elapsed);mail(current);if(delivered!=null)throw new SecurityException("Допуск уже подтверждён");return requestId+"\n"+wire;}
    static GlasGrant600 validateGrant(byte[] encoded,IdentityProtocol.Capability cap,byte[] server,String request,long now)throws IOException {if(encoded==null||encoded.length>65536||encoded.length<1)throw new SecurityException("Размер допуска Гласа");valid(cap,server,now);GlasGrant600 grant=GlasGrant600.decode(encoded);GlasProtocol600.Delegation d=grant.delegation();if(cap.appId!=IdentityProtocol.App.GLAS||!cap.capabilities.contains(IdentityProtocol.Scope.VOICE_CALL)||!grant.verify(d.accountPublic(),cap.audience,now)||!d.accountId().equals(cap.accountId)||!d.deviceId.equals(cap.deviceId)||d.generation!=cap.generation||!MessageDigest.isEqual(d.appPublic(),cap.proofKey)||d.expiresAt>cap.expiresAt||d.expiresAt>cap.offlineUntil||d.issuedAt<cap.issuedAt-30_000||(request!=null&&!request.equals(d.nonce)))throw new SecurityException("Публичный допуск не соответствует текущему Гласу");return grant;}
    synchronized void deliver(String request,byte[] grant,IdentityProtocol.Capability current,byte[] server,long wall,long elapsed)throws IOException {alive(current,server,wall,elapsed);mail(current);if(delivered!=null||!requestId.equals(request))throw new SecurityException("Повторное или чужое подтверждение");validateGrant(grant,glas,server,requestId,wall);delivered=grant.clone();}
    synchronized byte[] receive(IdentityProtocol.Capability current,byte[] server,long wall,long elapsed)throws IOException {alive(current,server,wall,elapsed);if(current.appId!=IdentityProtocol.App.GLAS||!current.tokenId.equals(glas.tokenId)||delivered==null)throw new SecurityException("Подтверждённый допуск недоступен");validateGrant(delivered,current,server,requestId,wall);byte[] result=delivered.clone();clear();return result;}
    synchronized void expire(long elapsed){if(glas!=null&&(elapsed<started||elapsed>=until))clear();}
    synchronized void clear(){requestId=null;wire=null;glas=null;started=until=0;if(delivered!=null)Arrays.fill(delivered,(byte)0);delivered=null;}
}
