package org.aegis.android;

import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import org.securemail.client.community.CommunityJson;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Reconstructs a single fixed capability-request domain; never signs arbitrary Core bytes. */
final class AppGrantProposal {
    final String nonce;final byte[] bytes;
    AppGrantProposal(String pkg,byte[] appKey,String wire,byte[] expectedServiceKey,long now)throws Exception {
        if(wire==null||wire.length()>8192)throw new SecurityException("Предложение слишком велико");JsonObject j=CommunityJson.parse(wire.getBytes(StandardCharsets.UTF_8));
        Set<String> exact=Set.of("accountId","deviceId","generation","appId","proofKey","capabilities","ttl","time","nonce","audience");if(!j.keySet().equals(exact))throw new SecurityException("Некорректные поля предложения");
        String account=IdentityProtocol.idValue(text(j,"accountId")),device=IdentityProtocol.idValue(text(j,"deviceId")),audience=IdentityProtocol.idValue(text(j,"audience"));nonce=IdentityProtocol.nonceValue(text(j,"nonce"));
        if(!audience.equals(IdentityProtocol.id(expectedServiceKey))||!AndroidPolicy.app(pkg).name().equals(text(j,"appId"))||!MessageDigest.isEqual(appKey,IdentityProtocol.unb64(text(j,"proofKey"),44)))throw new SecurityException("Предложение адресовано другому приложению");
        long generation=number(j,"generation"),time=number(j,"time"),ttl=number(j,"ttl");if(generation<1||ttl<1||ttl>3_600_000L||time>now+30_000||time<now-60_000)throw new SecurityException("Неверный срок предложения");
        JsonElement list=j.get("capabilities");if(!list.isJsonArray())throw new SecurityException("Полномочия отсутствуют");EnumSet<IdentityProtocol.Scope> scopes=EnumSet.noneOf(IdentityProtocol.Scope.class);for(JsonElement value:list.getAsJsonArray()){if(!value.isJsonPrimitive()||!value.getAsJsonPrimitive().isString()||!scopes.add(IdentityProtocol.Scope.valueOf(value.getAsString())))throw new SecurityException("Неоднозначные полномочия");}
        if(scopes.isEmpty()||!IdentityProtocol.allowed(AndroidPolicy.app(pkg)).containsAll(scopes))throw new SecurityException("Расширение полномочий запрещено");
        bytes=IdentityProtocol.capabilityRequest(audience,account,device,generation,AndroidPolicy.app(pkg),appKey,scopes,ttl,time,nonce);
    }
    private static String text(JsonObject j,String name){JsonElement e=j.get(name);if(e==null||!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isString()||e.getAsString().length()>256)throw new SecurityException("Неверное предложение");return e.getAsString();}
    private static long number(JsonObject j,String name){JsonElement e=j.get(name);if(e==null||!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isNumber()||!e.getAsString().matches("[0-9]{1,19}"))throw new SecurityException("Неверное число предложения");return Long.parseLong(e.getAsString());}
}
