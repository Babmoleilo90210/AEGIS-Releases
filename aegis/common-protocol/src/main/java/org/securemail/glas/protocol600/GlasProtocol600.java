package org.securemail.glas.protocol600;

import java.io.*;
import java.security.*;
import java.util.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;

/** Public, fixed-domain delegation/endpoint values. Contains no account/app private key or audio. */
public final class GlasProtocol600 {
  public static final long MAX_DELEGATION_MILLIS = 86_400_000L, MAX_ENDPOINT_MILLIS = 120_000L;
  public static final int MAX_REQUEST = 48 * 1024, MAX_CONTACTS = 256;
  private GlasProtocol600() {}
  public enum Command { REGISTER, LOOKUP, UNREGISTER }
  public static final class Delegation {
    public final String audience, deviceId, nonce;
    public final long generation, issuedAt, expiresAt;
    private final byte[] accountPublic, appPublic, signature;
    public Delegation(String audience, byte[] accountPublic, String deviceId, long generation, byte[] appPublic, long issuedAt, long expiresAt, String nonce, byte[] signature) {
      this.audience=IdentityProtocol.idValue(audience);this.deviceId=IdentityProtocol.idValue(deviceId);this.nonce=IdentityProtocol.nonceValue(nonce);
      IdentityProtocol.publicKey(accountPublic);IdentityProtocol.publicKey(appPublic);
      if(generation<1||issuedAt<0||expiresAt<=issuedAt||expiresAt-issuedAt>MAX_DELEGATION_MILLIS||signature==null||signature.length!=64||MessageDigest.isEqual(accountPublic,appPublic))throw new IllegalArgumentException("Допуск Гласа");
      this.accountPublic=accountPublic.clone();this.appPublic=appPublic.clone();this.signature=signature.clone();this.generation=generation;this.issuedAt=issuedAt;this.expiresAt=expiresAt;
    }
    public byte[] accountPublic(){return accountPublic.clone();} public byte[] appPublic(){return appPublic.clone();} public byte[] signature(){return signature.clone();}
    public String accountId(){return IdentityProtocol.id(accountPublic);}
    public byte[] signingBytes(){return bytes(out->{out.writeUTF("AEGIS-GLAS-DELEGATION/v1");out.writeUTF(audience);out.write(accountPublic);out.writeUTF(deviceId);out.writeLong(generation);out.write(appPublic);out.writeLong(issuedAt);out.writeLong(expiresAt);out.writeUTF(nonce);});}
    public byte[] encode(){return join(signingBytes(),signature);}
    public Delegation signed(byte[] rootSignature){return new Delegation(audience,accountPublic,deviceId,generation,appPublic,issuedAt,expiresAt,nonce,rootSignature);}
    public boolean verify(String expectedAudience,long now){return audience.equals(expectedAudience)&&issuedAt<=now+30_000&&expiresAt>now&&IdentityProtocol.verify(accountPublic,signingBytes(),signature);}
  }
  public static Delegation decodeDelegation(byte[] wire)throws IOException {
    if(wire==null||wire.length>1024)throw invalid();
    try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(wire))){
      if(!in.readUTF().equals("AEGIS-GLAS-DELEGATION/v1"))throw invalid();String audience=in.readUTF();byte[] root=read(in,44);String device=in.readUTF();long gen=in.readLong();byte[] app=read(in,44);long issued=in.readLong(),until=in.readLong();String nonce=in.readUTF();Delegation d=new Delegation(audience,root,device,gen,app,issued,until,nonce,read(in,64));if(in.read()!=-1||!MessageDigest.isEqual(wire,d.encode()))throw invalid();return d;
    }catch(RuntimeException failure){throw invalid();}
  }
  public static byte[] delegationSigningBytes(Delegation delegation){return delegation.signingBytes();}
  public static byte[] sha256Delegation(Delegation delegation){return IdentityProtocol.digest(delegation.encode());}
  /** Server registration binding, independently checked against the authenticated current capability. */
  public static boolean verifyDelegation(Delegation d,IdentityProtocol.Capability c,byte[] pinnedIdentityPublic,long now){
    return IdentityProtocol.verifyCapability(c,pinnedIdentityPublic,now)&&c.appId==IdentityProtocol.App.GLAS&&c.capabilities.contains(IdentityProtocol.Scope.VOICE_CALL)
      &&d.verify(IdentityProtocol.id(pinnedIdentityPublic),now)&&d.accountId().equals(c.accountId)&&d.deviceId.equals(c.deviceId)&&d.generation==c.generation
      &&MessageDigest.isEqual(d.appPublic(),c.proofKey)&&d.expiresAt<=c.expiresAt&&d.issuedAt>=c.issuedAt-30_000;
  }
  /** Peer trust always starts from the existing pinned contact root, never nickname or supplied certificate alone. */
  public static boolean verifyDelegation(Delegation d,byte[] pinnedContactRoot,String pinnedIdentityAudience,long now){
    return MessageDigest.isEqual(d.accountPublic(),pinnedContactRoot)&&d.verify(pinnedIdentityAudience,now);
  }
  public static final class Endpoint {
    public final String serviceAudience,onion,nonce;
    public final int port;
    public final long issuedAt,expiresAt;
    private final byte[] delegationSha256,signature;
    public Endpoint(String serviceAudience,byte[] delegationSha256,String onion,int port,long issuedAt,long expiresAt,String nonce,byte[] signature){
      this.serviceAudience=IdentityProtocol.idValue(serviceAudience);this.nonce=IdentityProtocol.nonceValue(nonce);
      if(delegationSha256==null||delegationSha256.length!=32||!validOnion(onion)||port<1||port>65535||issuedAt<0||expiresAt<=issuedAt||expiresAt-issuedAt>MAX_ENDPOINT_MILLIS||signature==null||signature.length!=64)throw new IllegalArgumentException("Адрес Гласа");
      this.delegationSha256=delegationSha256.clone();this.signature=signature.clone();this.onion=onion;this.port=port;this.issuedAt=issuedAt;this.expiresAt=expiresAt;
    }
    public byte[] signature(){return signature.clone();} public byte[] delegationSha256(){return delegationSha256.clone();}
    public byte[] signingBytes(){return bytes(out->{out.writeUTF("AEGIS-GLAS-ENDPOINT/v1");out.writeUTF(serviceAudience);out.write(delegationSha256);out.writeUTF(onion);out.writeInt(port);out.writeLong(issuedAt);out.writeLong(expiresAt);out.writeUTF(nonce);});}
    public byte[] encode(){return join(signingBytes(),signature);}
    public Endpoint signed(byte[] appSignature){return new Endpoint(serviceAudience,delegationSha256,onion,port,issuedAt,expiresAt,nonce,appSignature);}
    public boolean verify(String expectedService,Delegation delegation,long now){return serviceAudience.equals(expectedService)&&MessageDigest.isEqual(delegationSha256,IdentityProtocol.digest(delegation.encode()))&&issuedAt<=now+30_000&&issuedAt>=delegation.issuedAt&&expiresAt>now&&expiresAt<=delegation.expiresAt&&IdentityProtocol.verify(delegation.appPublic(),signingBytes(),signature);}
  }
  public static Endpoint decodeEndpoint(byte[] wire)throws IOException {
    if(wire==null||wire.length>1024)throw invalid();
    try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(wire))){if(!in.readUTF().equals("AEGIS-GLAS-ENDPOINT/v1"))throw invalid();Endpoint e=new Endpoint(in.readUTF(),read(in,32),in.readUTF(),in.readInt(),in.readLong(),in.readLong(),in.readUTF(),read(in,64));if(in.read()!=-1||!MessageDigest.isEqual(wire,e.encode()))throw invalid();return e;}catch(RuntimeException failure){throw invalid();}
  }
  public static final class Request {
    public final Command command;public final Delegation delegation;public final Endpoint endpoint;public final Set<String> incoming,outgoing;public final String targetId;public final boolean lookupIncoming;private final byte[] targetRoot;
    private Request(Command command,Delegation d,Endpoint e,Set<String> incoming,Set<String> outgoing,String target,byte[] root,boolean lookupIncoming){this.command=command;delegation=d;endpoint=e;this.incoming=contacts(incoming);this.outgoing=contacts(outgoing);targetId=target;targetRoot=root==null?new byte[0]:root.clone();this.lookupIncoming=lookupIncoming;}
    public static Request register(Delegation d,Endpoint e,Set<String> incoming,Set<String> outgoing){return new Request(Command.REGISTER,Objects.requireNonNull(d),Objects.requireNonNull(e),incoming,outgoing,"",null,false);}
    public static Request lookup(byte[] pinnedRoot){return lookup(pinnedRoot,false);}
    public static Request lookup(byte[] pinnedRoot,boolean incoming){IdentityProtocol.publicKey(pinnedRoot);return new Request(Command.LOOKUP,null,null,Set.of(),Set.of(),IdentityProtocol.id(pinnedRoot),pinnedRoot,incoming);}
    public static Request unregister(){return new Request(Command.UNREGISTER,null,null,Set.of(),Set.of(),"",null,false);}
    public byte[] targetRoot(){return targetRoot.clone();}
    public byte[] encode(){return bytes(out->{out.writeUTF("AEGIS-GLAS-REQUEST/v1");out.writeUTF(command.name());if(command==Command.REGISTER){write(out,delegation.encode());write(out,endpoint.encode());writeContacts(out,incoming);writeContacts(out,outgoing);}else if(command==Command.LOOKUP){out.writeUTF(targetId);out.write(targetRoot);out.writeBoolean(lookupIncoming);}});}
  }
  public static Request decode(byte[] wire)throws IOException {
    if(wire==null||wire.length<1||wire.length>MAX_REQUEST)throw invalid();
    try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(wire))){if(!in.readUTF().equals("AEGIS-GLAS-REQUEST/v1"))throw invalid();Command c=Command.valueOf(in.readUTF());Request r;if(c==Command.REGISTER)r=Request.register(decodeDelegation(readSized(in,1024)),decodeEndpoint(readSized(in,1024)),readContacts(in),readContacts(in));else if(c==Command.LOOKUP){String id=in.readUTF();byte[] root=read(in,44);r=Request.lookup(root,in.readBoolean());if(!r.targetId.equals(id))throw invalid();}else r=Request.unregister();if(in.read()!=-1||!MessageDigest.isEqual(wire,r.encode()))throw invalid();return r;}catch(RuntimeException failure){throw invalid();}
  }
  private static Set<String> contacts(Set<String> values){if(values==null||values.size()>MAX_CONTACTS)throw new IllegalArgumentException("Список контактов");TreeSet<String>s=new TreeSet<>();for(String id:values)s.add(IdentityProtocol.idValue(id));return Collections.unmodifiableSet(s);}
  private static void writeContacts(DataOutputStream out,Set<String>s)throws IOException{out.writeInt(s.size());for(String id:s)out.writeUTF(id);}
  private static Set<String> readContacts(DataInputStream in)throws IOException{int n=in.readInt();if(n<0||n>MAX_CONTACTS)throw invalid();Set<String>s=new TreeSet<>();String prior="";for(int i=0;i<n;i++){String id=in.readUTF();if(id.compareTo(prior)<=0||!s.add(IdentityProtocol.idValue(id)))throw invalid();prior=id;}return s;}
  private interface Writer{void write(DataOutputStream out)throws IOException;}
  /** Tor address-spec: base32(public key | SHA3 checksum[:2] | version 3). Reachability is not asserted. */
  public static boolean validOnion(String host){
    if(host==null||!host.matches("[a-z2-7]{56}\\.onion"))return false;
    byte[] raw=new byte[35];int bits=0,value=0,index=0;String alphabet="abcdefghijklmnopqrstuvwxyz234567";
    for(int i=0;i<56;i++){value=(value<<5)|alphabet.indexOf(host.charAt(i));bits+=5;if(bits>=8){bits-=8;raw[index++]=(byte)(value>>>bits);}}
    if(index!=35||raw[34]!=3)return false;byte[] hash=onionChecksum(Arrays.copyOf(raw,32));return raw[32]==hash[0]&&raw[33]==hash[1];
  }
  public static String onionFromPublicKey(byte[] ed25519Public){IdentityProtocol.publicKey(ed25519Public);byte[] raw=new byte[35],key=Arrays.copyOfRange(ed25519Public,12,44);System.arraycopy(key,0,raw,0,32);byte[] hash=onionChecksum(key);raw[32]=hash[0];raw[33]=hash[1];raw[34]=3;StringBuilder result=new StringBuilder(62);String alphabet="abcdefghijklmnopqrstuvwxyz234567";int value=0,bits=0;for(byte b:raw){value=(value<<8)|(b&255);bits+=8;while(bits>=5){bits-=5;result.append(alphabet.charAt((value>>>bits)&31));}}return result+".onion";}
  private static byte[] onionChecksum(byte[] rawPublic){try{MessageDigest sha=MessageDigest.getInstance("SHA3-256");sha.update(".onion checksum".getBytes(java.nio.charset.StandardCharsets.US_ASCII));sha.update(rawPublic);sha.update((byte)3);return sha.digest();}catch(GeneralSecurityException missing){throw new IllegalStateException("SHA3-256 недоступен",missing);}}
  private static byte[] bytes(Writer writer){try{ByteArrayOutputStream b=new ByteArrayOutputStream();try(DataOutputStream out=new DataOutputStream(b)){writer.write(out);}return b.toByteArray();}catch(IOException impossible){throw new IllegalStateException(impossible);}}
  private static byte[] join(byte[] a,byte[] b){byte[] result=Arrays.copyOf(a,a.length+b.length);System.arraycopy(b,0,result,a.length,b.length);return result;}
  private static void write(DataOutputStream out,byte[] b)throws IOException{out.writeInt(b.length);out.write(b);}
  private static byte[] read(DataInputStream in,int n)throws IOException{byte[] b=new byte[n];in.readFully(b);return b;}
  private static byte[] readSized(DataInputStream in,int max)throws IOException{int n=in.readInt();if(n<1||n>max)throw invalid();return read(in,n);}
  private static IOException invalid(){return new IOException("Данные Гласа недоступны");}
}
