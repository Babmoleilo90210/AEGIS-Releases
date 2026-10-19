package org.securemail.ecosystem.protocol;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/** Dependency-free fixed-domain Ed25519 identity protocol. Compatible with Java 8 source syntax.
 * Legacy account private keys are never contained in these values. No JSON canonicalization.
 */
public final class IdentityProtocol {
    public static final long MAX_LEASE_MILLIS=86_400_000L;
    public static final int MAX_BODY=65_536;
    public enum App { AEGIS, MAIL, GLAS, LIBRARY, STRAZH, NETWORK }
    public enum Scope { ACCOUNT_READ, DEVICE_MANAGE, SESSION_MANAGE, ADMIN, MAIL_READ, MAIL_SEND, CONTACTS_READ, VOICE_CALL, LIBRARY_READ, LIBRARY_WRITE, THREAT_SCAN, NETWORK_CONTROL }
    private IdentityProtocol() { }
    public static final class Capability {
        public final String audience,accountId,deviceId,tokenId;
        public final App appId;
        public final long generation,issuedAt,expiresAt,offlineUntil;
        public final byte[] proofKey,serverSignature;
        public final Set<Scope> capabilities;
        public Capability(String audience,String accountId,String deviceId,App appId,long generation,String tokenId,long issuedAt,long expiresAt,long offlineUntil,byte[] proofKey,Set<Scope> capabilities,byte[] serverSignature) {
            this.audience=idValue(audience);this.accountId=idValue(accountId);this.deviceId=idValue(deviceId);this.appId=Objects.requireNonNull(appId);this.generation=generation;this.tokenId=nonceValue(tokenId);this.issuedAt=issuedAt;this.expiresAt=expiresAt;this.offlineUntil=offlineUntil;
            if(generation<1||issuedAt<0||expiresAt<=issuedAt||expiresAt-issuedAt>MAX_LEASE_MILLIS||offlineUntil<issuedAt||offlineUntil>expiresAt)throw new IllegalArgumentException("Capability interval");
            publicKey(proofKey);this.proofKey=proofKey.clone();this.serverSignature=serverSignature.clone();if(serverSignature.length!=0&&serverSignature.length!=64)throw new IllegalArgumentException("Signature length");
            EnumSet<Scope> scopes=capabilities.isEmpty()?EnumSet.noneOf(Scope.class):EnumSet.copyOf(capabilities);if(scopes.isEmpty()||!allowed(appId).containsAll(scopes))throw new IllegalArgumentException("Application scope");this.capabilities=Collections.unmodifiableSet(scopes);
        }
        public Capability signed(byte[] signature) {return new Capability(audience,accountId,deviceId,appId,generation,tokenId,issuedAt,expiresAt,offlineUntil,proofKey,capabilities,signature);}
    }
    public static final class VerifiedContext {
        public final String accountId,deviceId;public final App appId;public final long generation,leaseUntil;public final Set<Scope> capabilities;
        public VerifiedContext(Capability c) {accountId=c.accountId;deviceId=c.deviceId;appId=c.appId;generation=c.generation;leaseUntil=c.expiresAt;capabilities=c.capabilities;}
    }
    public static Set<Scope> allowed(App app) {
        switch(app) {
            case AEGIS:return EnumSet.of(Scope.ACCOUNT_READ,Scope.DEVICE_MANAGE,Scope.SESSION_MANAGE,Scope.ADMIN);
            case MAIL:return EnumSet.of(Scope.MAIL_READ,Scope.MAIL_SEND,Scope.CONTACTS_READ);
            case GLAS:return EnumSet.of(Scope.VOICE_CALL,Scope.CONTACTS_READ);
            case LIBRARY:return EnumSet.of(Scope.LIBRARY_READ,Scope.LIBRARY_WRITE);
            case STRAZH:return EnumSet.of(Scope.THREAT_SCAN);
            case NETWORK:return EnumSet.of(Scope.NETWORK_CONTROL);
            default:throw new IllegalArgumentException("Application");
        }
    }
    public static byte[] capabilityBytes(Capability c) {
        return bytes(out->{out.writeUTF("AEGIS-CAPABILITY/v1");out.writeUTF(c.audience);out.writeUTF(c.accountId);out.writeUTF(c.deviceId);out.writeUTF(c.appId.name());out.writeLong(c.generation);out.writeUTF(c.tokenId);out.writeLong(c.issuedAt);out.writeLong(c.expiresAt);out.writeLong(c.offlineUntil);out.write(c.proofKey);writeScopes(out,c.capabilities);});
    }
    public static String encodeCapability(Capability c) {if(c.serverSignature.length!=64)throw new IllegalArgumentException("Unsigned capability");return b64(capabilityBytes(c))+"."+b64(c.serverSignature);}
    public static Capability decodeCapability(String wire) {
        if(wire==null||wire.length()>4096)throw new IllegalArgumentException("Capability size");String[] parts=wire.split("\\.",-1);if(parts.length!=2)throw new IllegalArgumentException("Capability framing");byte[] payload=unb64(parts[0],2048),sig=unb64(parts[1],64);
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(payload))) {
            if(!in.readUTF().equals("AEGIS-CAPABILITY/v1"))throw new IOException("Domain");String audience=in.readUTF(),account=in.readUTF(),device=in.readUTF();App app=App.valueOf(in.readUTF());long gen=in.readLong();String token=in.readUTF();long issued=in.readLong(),expires=in.readLong(),offline=in.readLong();byte[] key=new byte[44];in.readFully(key);int n=in.readUnsignedByte();if(n<1||n>Scope.values().length)throw new IOException("Scopes");EnumSet<Scope> scopes=EnumSet.noneOf(Scope.class);String prior="";for(int i=0;i<n;i++){String s=in.readUTF();if(s.compareTo(prior)<=0)throw new IOException("Scope order");scopes.add(Scope.valueOf(s));prior=s;}if(in.read()!=-1)throw new IOException("Trailing data");Capability c=new Capability(audience,account,device,app,gen,token,issued,expires,offline,key,scopes,sig);if(!MessageDigest.isEqual(payload,capabilityBytes(c)))throw new IOException("Noncanonical token");return c;
        }catch(IOException|RuntimeException e){throw new IllegalArgumentException("Invalid capability",e);}
    }
    public static boolean verifyCapability(Capability c,byte[] serviceKey,long now) {return id(serviceKey).equals(c.audience)&&now>=c.issuedAt&&now<c.expiresAt&&verify(serviceKey,capabilityBytes(c),c.serverSignature);}
    public static byte[] registration(String audience,byte[] accountKey,byte[] deviceKey,byte[] recoveryKey,String nickname,long time,String nonce) {
        publicKey(accountKey);publicKey(deviceKey);publicKey(recoveryKey);if(Arrays.equals(accountKey,deviceKey)||Arrays.equals(accountKey,recoveryKey)||Arrays.equals(deviceKey,recoveryKey))throw new IllegalArgumentException("Separate account/device/recovery keys required");if(nickname==null||nickname.length()<1||nickname.length()>80||nickname.codePoints().anyMatch(Character::isISOControl))throw new IllegalArgumentException("Nickname");return typed("REGISTER",audience,time,nonce,out->{out.write(accountKey);out.write(deviceKey);out.write(recoveryKey);out.writeUTF(nickname);});
    }
    public static byte[] login(String audience,String account,String device,long time,String nonce) {return typed("LOGIN",audience,time,nonce,out->{out.writeUTF(idValue(account));out.writeUTF(idValue(device));});}
    public static byte[] deviceApproval(String audience,String account,String approvingDevice,String challenge,byte[] newKey,long expires) {publicKey(newKey);return typed("DEVICE-APPROVAL",audience,expires,challenge,out->{out.writeUTF(idValue(account));out.writeUTF(idValue(approvingDevice));out.write(newKey);});}
    public static final class DeviceRecovery {
        public final String audience,accountId,challenge;public final long expiresAt;private final byte[] newDevicePublic;
        public DeviceRecovery(String audience,String accountId,byte[] newDevicePublic,String challenge,long expiresAt){this.audience=idValue(audience);this.accountId=idValue(accountId);this.challenge=nonceValue(challenge);publicKey(newDevicePublic);this.newDevicePublic=newDevicePublic.clone();if(expiresAt<1)throw new IllegalArgumentException("Recovery expiry");this.expiresAt=expiresAt;}
        public byte[] newDevicePublic(){return newDevicePublic.clone();}
    }
    public static byte[] deviceRecoveryBytes(DeviceRecovery r){return recovery(r.audience,r.accountId,r.challenge,r.newDevicePublic(),r.expiresAt);}
    public static byte[] deviceRecoveryInspection(DeviceRecovery r,long time,String nonce){return typed("DEVICE-RECOVERY-INSPECTION",r.audience,time,nonce,out->{out.writeUTF(r.accountId);out.writeUTF(r.challenge);out.write(r.newDevicePublic());out.writeLong(r.expiresAt);});}
    public static DeviceRecovery decodeDeviceRecovery(byte[] bytes){if(bytes==null||bytes.length<1||bytes.length>1024)throw new IllegalArgumentException("Device recovery size");try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes))){if(!in.readUTF().equals("AEGIS-IDENTITY-DEVICE-RECOVERY/v1"))throw new IOException("Recovery domain");String audience=in.readUTF();long expires=in.readLong();String challenge=in.readUTF(),account=in.readUTF();byte[] key=new byte[44];in.readFully(key);DeviceRecovery r=new DeviceRecovery(audience,account,key,challenge,expires);if(in.read()!=-1||!MessageDigest.isEqual(bytes,deviceRecoveryBytes(r)))throw new IOException("Recovery canonicality");return r;}catch(IOException invalid){throw new IllegalArgumentException("Invalid device recovery",invalid);}}
    public static byte[] recovery(String audience,String account,String challenge,byte[] newKey,long expires) {publicKey(newKey);return typed("DEVICE-RECOVERY",audience,expires,challenge,out->{out.writeUTF(idValue(account));out.write(newKey);});}
    public static byte[] stepUp(String audience,String account,String device,String challenge,long expires) {return typed("STEP-UP",audience,expires,challenge,out->{out.writeUTF(idValue(account));out.writeUTF(idValue(device));});}
    public static byte[] capabilityRequest(String audience,String account,String device,long generation,App app,byte[] key,Set<Scope> scopes,long ttl,long time,String nonce) {publicKey(key);if(generation<1||ttl<1||ttl>MAX_LEASE_MILLIS||!allowed(app).containsAll(scopes)||scopes.isEmpty())throw new IllegalArgumentException("Scope request");return typed("ISSUE-CAPABILITY",audience,time,nonce,out->{out.writeUTF(idValue(account));out.writeUTF(idValue(device));out.writeLong(generation);out.writeUTF(app.name());out.write(key);writeScopes(out,scopes);out.writeLong(ttl);});}
    public static byte[] request(Capability c,String action,byte[] body,long time,String nonce) {if(action==null||!action.matches("[a-z][a-z0-9_.]{0,95}")||body==null||body.length>MAX_BODY)throw new IllegalArgumentException("Request size/action");return typed("APPLICATION-REQUEST",c.audience,time,nonce,out->{out.writeUTF(c.accountId);out.writeUTF(c.deviceId);out.writeUTF(c.appId.name());out.writeLong(c.generation);out.writeUTF(c.tokenId);out.writeUTF(action);out.writeInt(body.length);out.write(digest(body));});}
    /** Exact operation digest is calculated independently by the receiving service; never trust a client digest without matching bytes. */
    public static byte[] requestDigest(Capability c,String action,byte[] operationSha256,long time,String nonce) {if(action==null||!action.matches("[a-z][a-z0-9_.]{0,95}")||operationSha256==null||operationSha256.length!=32)throw new IllegalArgumentException("Request digest/action");return typed("APPLICATION-REQUEST-DIGEST",c.audience,time,nonce,out->{out.writeUTF(c.accountId);out.writeUTF(c.deviceId);out.writeUTF(c.appId.name());out.writeLong(c.generation);out.writeUTF(c.tokenId);out.writeUTF(action);out.write(operationSha256);});}
    /** Operator-pinned Relay service proof, not an account/app signature or public membership lookup. */
    public static byte[] managedAccountQuery(String audience,String serviceId,String accountId,long time,String nonce) {return typed("RELAY-MANAGED-ACCOUNT",audience,time,nonce,out->{out.writeUTF(idValue(serviceId));out.writeUTF(idValue(accountId));});}
    public enum OwnerTransferRole { OWNER_APPROVE, SUCCESSOR_ACCEPT }
    /** Exact fixed-domain transfer, no arbitrary document-to-sign. Shared Java8-compatible value. */
    public static final class OwnerTransfer {
        public final String audience,challenge,ownerAccountId,ownerDeviceId,targetAccountId,targetDeviceId;
        public final long ownerGeneration,targetGeneration,authorityEpoch,expiresAt;
        public OwnerTransfer(String audience,String challenge,String ownerAccountId,String ownerDeviceId,long ownerGeneration,String targetAccountId,String targetDeviceId,long targetGeneration,long authorityEpoch,long expiresAt) {
            this.audience=idValue(audience);this.challenge=nonceValue(challenge);this.ownerAccountId=idValue(ownerAccountId);this.ownerDeviceId=idValue(ownerDeviceId);this.targetAccountId=idValue(targetAccountId);this.targetDeviceId=idValue(targetDeviceId);
            if(ownerAccountId.equals(targetAccountId)||ownerDeviceId.equals(targetDeviceId)||ownerGeneration<1||targetGeneration<1||authorityEpoch<0||expiresAt<1)throw new IllegalArgumentException("Independent owner transfer participants");
            this.ownerGeneration=ownerGeneration;this.targetGeneration=targetGeneration;this.authorityEpoch=authorityEpoch;this.expiresAt=expiresAt;
        }
    }
    public static byte[] ownerTransferProposal(String audience,String owner,String target,long time,String nonce) {if(owner.equals(target))throw new IllegalArgumentException("Independent accounts required");return typed("OWNER-TRANSFER-PROPOSAL",audience,time,nonce,out->{out.writeUTF(idValue(owner));out.writeUTF(idValue(target));});}
    public static byte[] ownerTransferInspection(String audience,String challenge,long time,String nonce) {return typed("OWNER-TRANSFER-INSPECTION",audience,time,nonce,out->out.writeUTF(nonceValue(challenge)));}
    public static byte[] ownerTransferBytes(OwnerTransfer t) {return typed("OWNER-TRANSFER",t.audience,t.expiresAt,t.challenge,out->{out.writeUTF(t.ownerAccountId);out.writeUTF(t.ownerDeviceId);out.writeLong(t.ownerGeneration);out.writeUTF(t.targetAccountId);out.writeUTF(t.targetDeviceId);out.writeLong(t.targetGeneration);out.writeLong(t.authorityEpoch);});}
    public static byte[] ownerTransferConsent(OwnerTransfer t,OwnerTransferRole role) {Objects.requireNonNull(role);return typed("OWNER-TRANSFER-CONSENT",t.audience,t.expiresAt,t.challenge,out->{out.writeUTF(role.name());out.write(digest(ownerTransferBytes(t)));});}
    public static OwnerTransfer decodeOwnerTransfer(byte[] bytes) {
        if(bytes==null||bytes.length<1||bytes.length>2048)throw new IllegalArgumentException("Owner transfer size");
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes))){if(!in.readUTF().equals("AEGIS-IDENTITY-OWNER-TRANSFER/v1"))throw new IOException("Owner transfer domain");String audience=in.readUTF();long expires=in.readLong();String challenge=in.readUTF();OwnerTransfer t=new OwnerTransfer(audience,challenge,in.readUTF(),in.readUTF(),in.readLong(),in.readUTF(),in.readUTF(),in.readLong(),in.readLong(),expires);if(in.read()!=-1||!MessageDigest.isEqual(bytes,ownerTransferBytes(t)))throw new IOException("Owner transfer canonicality");return t;}catch(IOException e){throw new IllegalArgumentException("Invalid owner transfer",e);}
    }
    public static final class OwnerBootstrap {
        public final String audience,accountId,challenge;public final long expiresAt;
        public OwnerBootstrap(String audience,String accountId,String challenge,long expiresAt){this.audience=idValue(audience);this.accountId=idValue(accountId);this.challenge=nonceValue(challenge);if(expiresAt<1)throw new IllegalArgumentException("Bootstrap expiry");this.expiresAt=expiresAt;}
    }
    public static byte[] ownerBootstrapBytes(OwnerBootstrap b){return ownerBootstrap(b.audience,b.accountId,b.challenge,b.expiresAt);}
    public static byte[] ownerBootstrapInspection(String audience,String challenge,long time,String nonce){return typed("OWNER-BOOTSTRAP-INSPECTION",audience,time,nonce,out->out.writeUTF(nonceValue(challenge)));}
    public static OwnerBootstrap decodeOwnerBootstrap(byte[] bytes){if(bytes==null||bytes.length<1||bytes.length>1024)throw new IllegalArgumentException("Owner bootstrap size");try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes))){if(!in.readUTF().equals("AEGIS-IDENTITY-OWNER-BOOTSTRAP/v1"))throw new IOException("Bootstrap domain");String audience=in.readUTF();long expires=in.readLong();String challenge=in.readUTF();OwnerBootstrap b=new OwnerBootstrap(audience,in.readUTF(),challenge,expires);if(in.read()!=-1||!MessageDigest.isEqual(bytes,ownerBootstrapBytes(b)))throw new IOException("Bootstrap canonicality");return b;}catch(IOException invalid){throw new IllegalArgumentException("Invalid Owner bootstrap",invalid);}}
    public static byte[] ownerBootstrap(String audience,String account,String challenge,long expires) {return typed("OWNER-BOOTSTRAP",audience,expires,challenge,out->out.writeUTF(idValue(account)));}
    public enum FirstDelegateRole { OWNER_APPROVE, DELEGATE_ACCEPT }
    public static final class FirstDelegation {
        public final String audience,ownerAccountId,ownerDeviceId,targetAccountId,targetDeviceId,roleName,challenge;
        public final long ownerGeneration,targetGeneration,expiresAt;
        public FirstDelegation(String audience,String ownerAccountId,String ownerDeviceId,long ownerGeneration,String targetAccountId,String targetDeviceId,long targetGeneration,String roleName,String challenge,long expiresAt) {
            this.audience=idValue(audience);this.ownerAccountId=idValue(ownerAccountId);this.ownerDeviceId=idValue(ownerDeviceId);this.targetAccountId=idValue(targetAccountId);this.targetDeviceId=idValue(targetDeviceId);this.challenge=nonceValue(challenge);roleName(roleName);this.roleName=roleName;if(ownerAccountId.equals(targetAccountId)||ownerDeviceId.equals(targetDeviceId)||ownerGeneration<1||targetGeneration<1||expiresAt<1)throw new IllegalArgumentException("Independent delegation participants");this.ownerGeneration=ownerGeneration;this.targetGeneration=targetGeneration;this.expiresAt=expiresAt;
        }
    }
    public static byte[] firstDelegationBytes(FirstDelegation t) {return firstDelegateConsent(t.audience,t.ownerAccountId,t.ownerDeviceId,t.ownerGeneration,t.targetAccountId,t.targetDeviceId,t.targetGeneration,t.roleName,t.challenge,t.expiresAt);}
    public static byte[] firstDelegationInspection(String audience,String challenge,long time,String nonce) {return typed("FIRST-DELEGATE-INSPECTION",audience,time,nonce,out->out.writeUTF(nonceValue(challenge)));}
    public static FirstDelegation decodeFirstDelegation(byte[] bytes) {
        if(bytes==null||bytes.length<1||bytes.length>2048)throw new IllegalArgumentException("First delegation size");
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes))){if(!in.readUTF().equals("AEGIS-IDENTITY-FIRST-DELEGATE-CONSENT/v1"))throw new IOException("Delegation domain");String audience=in.readUTF();long expires=in.readLong();String challenge=in.readUTF();FirstDelegation t=new FirstDelegation(audience,in.readUTF(),in.readUTF(),in.readLong(),in.readUTF(),in.readUTF(),in.readLong(),in.readUTF(),challenge,expires);if(in.read()!=-1||!MessageDigest.isEqual(bytes,firstDelegationBytes(t)))throw new IOException("Delegation canonicality");return t;}catch(IOException e){throw new IllegalArgumentException("Invalid first delegation",e);}
    }
    public static byte[] firstDelegateProposal(String audience,String owner,String target,String roleName,long time,String nonce) {roleName(roleName);return typed("FIRST-DELEGATE-PROPOSAL",audience,time,nonce,out->{out.writeUTF(idValue(owner));out.writeUTF(idValue(target));out.writeUTF(roleName);});}
    public static byte[] firstDelegateConsent(String audience,String owner,String ownerDevice,long ownerGeneration,String target,String targetDevice,long targetGeneration,String roleName,String challenge,long expires) {roleName(roleName);if(ownerGeneration<1||targetGeneration<1||owner.equals(target))throw new IllegalArgumentException("Independent accounts required");return typed("FIRST-DELEGATE-CONSENT",audience,expires,challenge,out->{out.writeUTF(idValue(owner));out.writeUTF(idValue(ownerDevice));out.writeLong(ownerGeneration);out.writeUTF(idValue(target));out.writeUTF(idValue(targetDevice));out.writeLong(targetGeneration);out.writeUTF(roleName);});}
    public static byte[] administratorAssignment(String target,String roleName) {roleName(roleName);return bytes(out->{out.writeUTF("AEGIS-ADMINISTRATOR-ASSIGNMENT/v1");out.writeUTF(idValue(target));out.writeUTF(roleName);});}
    public static byte[] administratorRevocation(String target) {return bytes(out->{out.writeUTF("AEGIS-ADMINISTRATOR-REVOCATION/v1");out.writeUTF(idValue(target));});}
    public static byte[] accountRecoveryApproval(String target) {return bytes(out->{out.writeUTF("AEGIS-SENSITIVE-RECOVERY-APPROVAL/v1");out.writeUTF(idValue(target));});}
    private static void roleName(String name) {if(name==null||name.length()<1||name.length()>80||!name.equals(name.trim())||name.codePoints().anyMatch(Character::isISOControl))throw new IllegalArgumentException("Role name");}
    public static byte[] criticalApproval(String audience,String account,String operation,String challenge,byte[] payload,long expires) {if(operation==null||!operation.matches("[a-z][a-z0-9_.]{0,63}")||payload.length>MAX_BODY)throw new IllegalArgumentException("Critical operation");return typed("CRITICAL-APPROVAL",audience,expires,challenge,out->{out.writeUTF(idValue(account));out.writeUTF(operation);out.write(digest(payload));});}
    public static byte[] response(String audience,String nonce,byte[] request,byte[] response) {if(request.length>MAX_BODY||response.length>MAX_BODY)throw new IllegalArgumentException("Response size");return typed("HTTP-RESPONSE",audience,0,nonce,out->{out.write(digest(request));out.writeInt(response.length);out.write(digest(response));});}
    private interface Writer {void write(DataOutputStream out)throws IOException;}
    private static byte[] typed(String domain,String audience,long time,String nonce,Writer writer) {idValue(audience);nonceValue(nonce);if(time<0)throw new IllegalArgumentException("Time");return bytes(out->{out.writeUTF("AEGIS-IDENTITY-"+domain+"/v1");out.writeUTF(audience);out.writeLong(time);out.writeUTF(nonce);writer.write(out);});}
    private static byte[] bytes(Writer writer) {try{ByteArrayOutputStream buffer=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(buffer)){writer.write(out);}return buffer.toByteArray();}catch(IOException impossible){throw new IllegalStateException(impossible);}}
    private static void writeScopes(DataOutputStream out,Set<Scope> scopes)throws IOException {List<String> sorted=new ArrayList<>();for(Scope s:scopes)sorted.add(s.name());Collections.sort(sorted);out.writeByte(sorted.size());for(String s:sorted)out.writeUTF(s);}
    public static PublicKey publicKey(byte[] encoded) {try{if(encoded==null||encoded.length!=44)throw new GeneralSecurityException("Key length");PublicKey key=KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));if(!MessageDigest.isEqual(encoded,key.getEncoded()))throw new GeneralSecurityException("Key canonicality");return key;}catch(GeneralSecurityException e){throw new IllegalArgumentException("Invalid Ed25519 public key",e);}}
    public static byte[] sign(PrivateKey key,byte[] payload) {try{Signature s=Signature.getInstance("Ed25519");s.initSign(key);s.update(payload);return s.sign();}catch(GeneralSecurityException e){throw new IllegalArgumentException("Signing failed",e);}}
    public static boolean verify(byte[] key,byte[] payload,byte[] signature) {try{if(signature==null||signature.length!=64)return false;Signature s=Signature.getInstance("Ed25519");s.initVerify(publicKey(key));s.update(payload);return s.verify(signature);}catch(GeneralSecurityException|RuntimeException e){return false;}}
    public static byte[] digest(byte[] bytes) {try{return MessageDigest.getInstance("SHA-256").digest(bytes);}catch(GeneralSecurityException e){throw new IllegalStateException(e);}}
    public static String id(byte[] encoded) {byte[] hash=digest(encoded);StringBuilder s=new StringBuilder(64);for(byte b:hash)s.append(String.format(Locale.ROOT,"%02x",b&255));return s.toString();}
    public static String idValue(String s) {if(s==null||!s.matches("[a-f0-9]{64}"))throw new IllegalArgumentException("Identifier");return s;}
    public static String nonce() {byte[] b=new byte[32];new SecureRandom().nextBytes(b);return b64(b);}
    public static String nonceValue(String s) {if(s==null||!s.matches("[A-Za-z0-9_-]{43}")||unb64(s,32).length!=32)throw new IllegalArgumentException("Nonce");return s;}
    public static String b64(byte[] bytes) {return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    public static byte[] unb64(String text,int max) {if(text==null||text.length()>((max+2)/3)*4)throw new IllegalArgumentException("Encoding limit");byte[] bytes=Base64.getUrlDecoder().decode(text);if(bytes.length>max||!b64(bytes).equals(text))throw new IllegalArgumentException("Encoding canonicality");return bytes;}
}
