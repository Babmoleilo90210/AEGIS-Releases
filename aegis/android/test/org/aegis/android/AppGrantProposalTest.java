package org.aegis.android;

import com.google.gson.*;
import java.security.*;
import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Real production typed proposal parser, JVM-only; not an Android Binder acceptance test. */
public final class AppGrantProposalTest {
    interface Run {void run()throws Exception;}static int pass;
    static void test(String name,Run r)throws Exception{r.run();pass++;System.out.println("PASS "+name);}
    static void deny(Run r)throws Exception{try{r.run();}catch(SecurityException|IllegalArgumentException|java.io.IOException ok){return;}throw new AssertionError("Accepted hostile proposal");}
    public static void main(String[] args)throws Exception{
        KeyPairGenerator g=KeyPairGenerator.getInstance("Ed25519");byte[] service=g.generateKeyPair().getPublic().getEncoded(),app=g.generateKeyPair().getPublic().getEncoded(),other=g.generateKeyPair().getPublic().getEncoded();long now=System.currentTimeMillis();JsonObject valid=new JsonObject();valid.addProperty("accountId",IdentityProtocol.id(other));valid.addProperty("deviceId",IdentityProtocol.id(app));valid.addProperty("generation",3);valid.addProperty("appId","MAIL");valid.addProperty("proofKey",IdentityProtocol.b64(app));valid.addProperty("ttl",3600000);valid.addProperty("time",now);String nonce=IdentityProtocol.nonce();valid.addProperty("nonce",nonce);valid.addProperty("audience",IdentityProtocol.id(service));JsonArray scopes=new JsonArray();scopes.add("MAIL_READ");scopes.add("MAIL_SEND");valid.add("capabilities",scopes);
        test("typed-canonical-capability-request",()->{AppGrantProposal p=new AppGrantProposal(AndroidPolicy.MAIL,app,valid.toString(),service,now);byte[] expected=IdentityProtocol.capabilityRequest(IdentityProtocol.id(service),IdentityProtocol.id(other),IdentityProtocol.id(app),3,IdentityProtocol.App.MAIL,app,EnumSet.of(IdentityProtocol.Scope.MAIL_READ,IdentityProtocol.Scope.MAIL_SEND),3600000,now,nonce);if(!MessageDigest.isEqual(p.bytes,expected))throw new AssertionError();});
        test("other-app-proposal-denied",()->deny(()->new AppGrantProposal(AndroidPolicy.GLAS,app,valid.toString(),service,now)));
        test("other-authority-denied",()->deny(()->new AppGrantProposal(AndroidPolicy.MAIL,app,valid.toString(),other,now)));
        test("other-app-key-denied",()->deny(()->new AppGrantProposal(AndroidPolicy.MAIL,other,valid.toString(),service,now)));
        test("stale-proposal-denied",()->deny(()->new AppGrantProposal(AndroidPolicy.MAIL,app,valid.toString(),service,now+61000)));
        test("future-proposal-denied",()->deny(()->new AppGrantProposal(AndroidPolicy.MAIL,app,valid.toString(),service,now-31000)));
        for(String field:List.of("ttl","generation")){JsonObject changed=valid.deepCopy();changed.addProperty(field,field.equals("ttl")?86400000:0);test("invalid-"+field+"-denied",()->deny(()->new AppGrantProposal(AndroidPolicy.MAIL,app,changed.toString(),service,now)));}
        JsonObject admin=valid.deepCopy();admin.getAsJsonArray("capabilities").add("ADMIN");test("administrative-escalation-denied",()->deny(()->new AppGrantProposal(AndroidPolicy.MAIL,app,admin.toString(),service,now)));
        JsonObject duplicate=valid.deepCopy();duplicate.getAsJsonArray("capabilities").add("MAIL_READ");test("duplicate-permission-denied",()->deny(()->new AppGrantProposal(AndroidPolicy.MAIL,app,duplicate.toString(),service,now)));
        JsonObject generic=valid.deepCopy();generic.addProperty("proofBytes","do not sign");test("generic-signature-payload-denied",()->deny(()->new AppGrantProposal(AndroidPolicy.MAIL,app,generic.toString(),service,now)));
        String dup=valid.toString().replaceFirst("\\{","{\"appId\":\"AEGIS\",");test("duplicate-json-field-denied",()->deny(()->new AppGrantProposal(AndroidPolicy.MAIL,app,dup,service,now)));
        JsonObject fractional=valid.deepCopy();fractional.addProperty("generation",new java.math.BigDecimal("3.0"));test("ambiguous-number-denied",()->deny(()->new AppGrantProposal(AndroidPolicy.MAIL,app,fractional.toString(),service,now)));
        System.out.println("RESULT "+pass+" PASS; platform Binder tests NOT_RUN");
    }
}
