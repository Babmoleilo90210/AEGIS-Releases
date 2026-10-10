package org.securemail.client.update;

import com.google.gson.*;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

/** Immutable authenticated release metadata. The runtime trust key is compiled in. */
public record SignedManifest(String version,String channel,String minimumSupported,String updatePolicy,
    Announcement announcement,Notes releaseNotes,List<Asset> artifacts,Asset checksums,Asset changelog) {
  public static final String REPOSITORY="Babmoleilo90210/AEGIS-Releases",CURRENT="1.1.5";
  public static final int MAX_BYTES=65536;
  private static final byte[] ROOT_KEY=Base64.getDecoder().decode("MCowBQYDK2VwAyEAswWYCFStSEhQdrgqUJFF3x12ltmfUA0PvQtlh684B2g=");
  public record Announcement(String title,String summary,boolean showAsLetter){}
  public record Notes(String publishedAt,String type,String text){}
  public record Asset(String fileName,long size,String sha256,URI url,String platform,String kind){}
  public SignedManifest{artifacts=List.copyOf(artifacts);}
  public static SignedManifest verify(byte[] exact,byte[] signature,String channel,String current,String highest)throws GeneralSecurityException,IOException {
    return verifyWithKey(exact,signature,channel,current,highest,KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(ROOT_KEY)));
  }
  /** Authenticated feed reading may observe a release older than the installed client. */
  public static SignedManifest verifyForCheck(byte[] exact,byte[] signature,String channel,String current,String highest)throws GeneralSecurityException,IOException {
    return verifyWithKeyForCheck(exact,signature,channel,current,KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(ROOT_KEY)));
  }
  static SignedManifest verifyWithKeyForCheck(byte[] exact,byte[] signature,String channel,String current,PublicKey key)throws GeneralSecurityException,IOException {
    return verifyWithKey(exact,signature,channel,current,"0.0.0",key,false);
  }
  // Package-private injection is confined to same-package tests. No CLI/config key override.
  static SignedManifest verifyWithKey(byte[] exact,byte[] signature,String expectedChannel,String current,String highest,PublicKey key)throws GeneralSecurityException,IOException {
    return verifyWithKey(exact,signature,expectedChannel,current,highest,key,true);
  }
  private static SignedManifest verifyWithKey(byte[] exact,byte[] signature,String expectedChannel,String current,String highest,PublicKey key,boolean strictPolicy)throws GeneralSecurityException,IOException {
    if(exact.length==0||exact.length>MAX_BYTES||signature.length!=64)throw new SignatureException("Invalid manifest/signature length");
    Signature verifier=Signature.getInstance("Ed25519");verifier.initVerify(key);verifier.update(exact);
    if(!verifier.verify(signature))throw new SignatureException("Release signature rejected");
    // No JSON parsing, URI handling, announcement or policy is performed before this point.
    JsonObject o=JsonData.object(exact,MAX_BYTES);
    JsonData.fields(o,"schemaVersion","application","channel","version","tag","repository","protocolVersion","relayCompatibility","artifacts","checksums","changelog","minimumSupported","updatePolicy","announcement","releaseNotes");
    String version=JsonData.text(o,"version",100),channel=JsonData.text(o,"channel",8),minimum=JsonData.text(o,"minimumSupported",100),policy=JsonData.text(o,"updatePolicy",10);
    try {
      SemVersion v=SemVersion.parse(version),installed=SemVersion.parse(current),floor=SemVersion.parse(highest),min=SemVersion.parse(minimum);
      if(JsonData.number(o,"schemaVersion")!=1||JsonData.number(o,"protocolVersion")!=1||!JsonData.text(o,"application",8).equals("AEGIS")||!JsonData.text(o,"repository",100).equals(REPOSITORY)||!JsonData.text(o,"tag",101).equals("v"+version))throw new IOException("Release schema rejected");
      if(!Set.of("stable","beta").contains(channel)||!channel.equals(expectedChannel)||channel.equals("stable")&&!v.prerelease().isEmpty())throw new IOException("Update channel rejected");
      if(min.compareTo(v)>0)throw new IOException("Invalid minimum version");
      if(strictPolicy&&(v.compareTo(installed)<0||v.compareTo(floor)<0))throw new UpdateDiagnostic.Failure(UpdateDiagnostic.Category.POLICY,"VERSION_ROLLBACK");
      if(!o.get("relayCompatibility").isJsonArray()||!o.getAsJsonArray("relayCompatibility").equals(JsonParser.parseString("[\"0.2.0\"]")))throw new IOException("Relay compatibility rejected");
      if(!Set.of("optional","required").contains(policy))throw new IOException("Invalid update policy");
      JsonObject a=o.getAsJsonObject("announcement");JsonData.fields(a,"title","summary","showAsLetter");Announcement announcement=new Announcement(JsonData.text(a,"title",140),JsonData.text(a,"summary",1500),JsonData.bool(a,"showAsLetter"));
      JsonObject n=o.getAsJsonObject("releaseNotes");JsonData.fields(n,"publishedAt","type","text");Notes notes=new Notes(JsonData.text(n,"publishedAt",40),JsonData.text(n,"type",12),JsonData.text(n,"text",12000));Instant.parse(notes.publishedAt());
      if(!Set.of("Feature","Fix","Security").contains(notes.type())||policy.equals("required")&&!notes.type().equals("Security")&&min.compareTo(installed)<=0)throw new IOException("Unsupported mandatory update");
      Map<String,String> expected=Map.of("AEGIS-Setup-"+version+"-x64.exe","windows-x64/installer","AEGIS-"+version+"-Windows-x64.zip","windows-x64/portable","AEGIS-"+version+"-CachyOS-x86_64.AppImage","cachyos-x86_64/appimage","AEGIS-"+version+"-client-source.zip","source/source");
      JsonArray files=o.getAsJsonArray("artifacts");if(files.size()!=4)throw new IOException("Wrong artifact count");Set<String> seen=new HashSet<>();List<Asset> assets=new ArrayList<>();
      for(JsonElement e:files){Asset asset=asset(e.getAsJsonObject(),version,true);if(!seen.add(asset.fileName())||!Objects.equals(expected.get(asset.fileName()),asset.platform()+"/"+asset.kind()))throw new IOException("Wrong release asset");assets.add(asset);}
      Asset sums=asset(o.getAsJsonObject("checksums"),version,false),log=asset(o.getAsJsonObject("changelog"),version,false);
      if(!sums.fileName().equals("SHA256SUMS")||!log.fileName().equals("CHANGELOG-"+version+".md"))throw new IOException("Invalid auxiliary release asset");
      return new SignedManifest(version,channel,minimum,policy,announcement,notes,assets,sums,log);
    }catch(IllegalArgumentException|IllegalStateException|NullPointerException|java.time.DateTimeException e){throw new IOException("Invalid signed release metadata",e);}
  }
  private static Asset asset(JsonObject o,String version,boolean platform)throws IOException {
    if(platform)JsonData.fields(o,"fileName","size","sha256","url","platform","kind");else JsonData.fields(o,"fileName","size","sha256","url");
    String name=JsonData.text(o,"fileName",180),hash=JsonData.text(o,"sha256",64),url=JsonData.text(o,"url",500);long size=JsonData.number(o,"size");
    if(!name.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,179}")||!hash.matches("[a-f0-9]{64}")||size<1||size>512L*1024*1024||!url.equals("https://github.com/"+REPOSITORY+"/releases/download/v"+version+"/"+name))throw new IOException("Unsafe release asset");
    return new Asset(name,size,hash,URI.create(url),platform?JsonData.text(o,"platform",32):"",platform?JsonData.text(o,"kind",20):"");
  }
  public Asset clientAsset(boolean windows){return artifacts.stream().filter(a->a.platform().equals(windows?"windows-x64":"cachyos-x86_64")&&a.kind().equals(windows?"portable":"appimage")).findFirst().orElseThrow();}
  public boolean newerThan(String current){return SemVersion.parse(version).compareTo(SemVersion.parse(current))>0;}
  public void requireInstallable(String current,String highest)throws IOException {
    if(!newerThan(current)||SemVersion.parse(version).compareTo(SemVersion.parse(highest))<0)
      throw new UpdateDiagnostic.Failure(UpdateDiagnostic.Category.POLICY,"VERSION_ROLLBACK");
  }
  public boolean requiredFor(String current){return updatePolicy.equals("required")||SemVersion.parse(current).compareTo(SemVersion.parse(minimumSupported))<0;}
  public static byte[] embeddedPublicKey(){return ROOT_KEY.clone();}
}
