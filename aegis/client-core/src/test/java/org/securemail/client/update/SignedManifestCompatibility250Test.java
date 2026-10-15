package org.securemail.client.update;

import static org.junit.jupiter.api.Assertions.*;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Real unsigned generator + frozen historical parsing; test-only in-memory Ed25519 key.
 * This does not claim an owner signature, native install/restart/rollback, or updater E2E.
 */
class SignedManifestCompatibility250Test {
  @TempDir static Path scratch;
  private static final String PREFIX="org.securemail.client.update.";
  private static final List<Frozen> historical=new ArrayList<>();
  private static KeyPair testKey;
  private record Frozen(String label,URLClassLoader loader,Class<?> manifest){}
  private record Generated(byte[] exact,Path artifacts){}

  @BeforeAll static void freezeAndCompileHistoricalSources()throws Exception {
    testKey=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var compiler=ToolProvider.getSystemJavaCompiler();assertNotNull(compiler,"Java 21 JDK is required for the historical parser check");
    JsonObject provenance=JsonParser.parseString(new String(resource("PROVENANCE.json"),StandardCharsets.UTF_8)).getAsJsonObject().getAsJsonObject("snapshots");
    for(String label:List.of("v150","v200")){
      Path folder=Files.createDirectories(scratch.resolve(label)),classes=Files.createDirectories(folder.resolve("classes"));
      List<String> args=new ArrayList<>(List.of("--release","21","-encoding","UTF-8","-cp",Path.of(Gson.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString(),"-d",classes.toString()));
      JsonObject description=provenance.getAsJsonObject(label);
      for(String file:List.of("SignedManifest.java","JsonData.java","SemVersion.java","UpdateDiagnostic.java")){
        byte[] source=resource(label+"/"+file);String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(source));
        assertEquals(description.getAsJsonObject("files").getAsJsonObject(file).get("sha256").getAsString(),hash,"Frozen Git source changed: "+label+"/"+file);
        Path output=folder.resolve(file);Files.write(output,source);args.add(output.toString());
      }
      ByteArrayOutputStream diagnostics=new ByteArrayOutputStream();
      assertEquals(0,compiler.run(null,diagnostics,diagnostics,args.toArray(String[]::new)),diagnostics.toString(StandardCharsets.UTF_8));
      URLClassLoader loader=new URLClassLoader(new URL[]{classes.toUri().toURL()},Gson.class.getClassLoader()){
        @Override protected synchronized Class<?> loadClass(String name,boolean resolve)throws ClassNotFoundException {
          if(name.startsWith(PREFIX)){
            Class<?> result=findLoadedClass(name);
            if(result==null)try{result=findClass(name);}catch(ClassNotFoundException absent){return super.loadClass(name,resolve);}
            if(resolve)resolveClass(result);return result;
          }
          return super.loadClass(name,resolve);
        }
      };
      Class<?> manifest=loader.loadClass(PREFIX+"SignedManifest");
      assertEquals(description.get("clientVersion").getAsString(),manifest.getField("CURRENT").get(null));
      assertArrayEquals(SignedManifest.embeddedPublicKey(),(byte[])manifest.getMethod("embeddedPublicKey").invoke(null));
      historical.add(new Frozen(label,loader,manifest));
    }
  }

  @AfterAll static void closeLoaders()throws Exception {for(Frozen parser:historical)parser.loader().close();}

  private static byte[] resource(String name)throws IOException {
    try(InputStream input=SignedManifestCompatibility250Test.class.getResourceAsStream("/org/securemail/client/update/frozen/"+name)){
      // The offline javac fallback does not copy test resources; read the same frozen
      // repository fixture there. Gradle resolves the packaged test resource above.
      if(input==null)return Files.readAllBytes(repository().resolve("client-core/src/test/resources/org/securemail/client/update/frozen").resolve(name));return input.readAllBytes();
    }
  }
  private static Path repository()throws IOException {
    Path current=Path.of("").toAbsolutePath();
    for(int i=0;i<5&&current!=null;i++,current=current.getParent())if(Files.isRegularFile(current.resolve("tools/generate-release-manifest.py")))return current;
    throw new IOException("Run compatibility test from the AEGIS repository");
  }
  private Generated generate(String version,String channel)throws Exception {
    Path folder=Files.createDirectories(scratch.resolve("assets-"+UUID.randomUUID()));
    Map<String,String> files=new LinkedHashMap<>();
    for(String name:List.of("AEGIS-Setup-"+version+"-x64.exe","AEGIS-"+version+"-Windows-x64.zip","AEGIS-"+version+"-CachyOS-x86_64.AppImage","AEGIS-"+version+"-client-source.zip"))files.put(name,"Measured compatibility fixture "+name);
    files.put("CHANGELOG-"+version+".md","# АЕГИС "+version+"\nПроверка совместимости manifest.\n");
    StringBuilder sums=new StringBuilder();
    for(var entry:files.entrySet()){
      byte[] bytes=entry.getValue().getBytes(StandardCharsets.UTF_8);Files.write(folder.resolve(entry.getKey()),bytes);
      sums.append(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))).append("  ").append(entry.getKey()).append('\n');
    }
    Files.writeString(folder.resolve("SHA256SUMS"),sums,StandardCharsets.US_ASCII);
    Path output=folder.resolve("AEGIS-"+version+"-"+channel+".UNSIGNED.json");
    Process process=new ProcessBuilder("python3",repository().resolve("tools/generate-release-manifest.py").toString(),"--artifacts",folder.toString(),"--version",version,"--channel",channel,"--output",output.toString(),"--published-at","2026-10-15T09:00:00Z").redirectErrorStream(true).start();
    String diagnostics=new String(process.getInputStream().readAllBytes(),StandardCharsets.UTF_8);assertEquals(0,process.waitFor(),diagnostics);assertTrue(diagnostics.contains("UNSIGNED"));
    assertFalse(Files.exists(output.resolveSibling(output.getFileName()+".sig")));
    return new Generated(Files.readAllBytes(output),folder);
  }
  private static byte[] sign(byte[] exact)throws Exception {Signature signature=Signature.getInstance("Ed25519");signature.initSign(testKey.getPrivate());signature.update(exact);return signature.sign();}
  private static Object call(Method method,Object... arguments)throws Exception {
    try{return method.invoke(null,arguments);}catch(InvocationTargetException wrapped){if(wrapped.getCause()instanceof Exception cause)throw cause;if(wrapped.getCause()instanceof Error cause)throw cause;throw wrapped;}
  }
  private static Object oldVerify(Frozen parser,byte[] exact,byte[] signature,String channel,String current,String floor)throws Exception {
    Method verify=parser.manifest().getDeclaredMethod("verifyWithKey",byte[].class,byte[].class,String.class,String.class,String.class,PublicKey.class);verify.setAccessible(true);
    return call(verify,exact,signature,channel,current,floor,testKey.getPublic());
  }
  private static void acceptedEverywhere(byte[] exact,String channel,String installed)throws Exception {
    byte[] signature=sign(exact);String version=JsonData.object(exact,65536).get("version").getAsString();
    assertEquals(version,SignedManifest.verifyWithKey(exact,signature,channel,installed,installed,testKey.getPublic()).version());
    for(Frozen parser:historical){Object old=oldVerify(parser,exact,signature,channel,installed,installed);assertEquals(version,old.getClass().getMethod("version").invoke(old));}
  }
  private static void rejectedEverywhere(byte[] exact,byte[] signature,String channel,String installed,String floor,Class<? extends Exception> reason)throws Exception {
    assertThrows(reason,()->SignedManifest.verifyWithKey(exact,signature,channel,installed,floor,testKey.getPublic()));
    for(Frozen parser:historical)assertThrows(reason,()->oldVerify(parser,exact,signature,channel,installed,floor),parser.label());
  }

  @Test void generated250StableAndBetaManifestsAreAcceptedForInstalled150And200()throws Exception {
    for(String channel:List.of("stable","beta")){
      byte[] exact=generate("2.5.0",channel).exact();JsonObject doc=JsonData.object(exact,65536);assertEquals("v2.5.0",doc.get("tag").getAsString());
      for(String installed:List.of("1.5.0","2.0.0"))acceptedEverywhere(exact,channel,installed);
    }
  }
  @Test void explicitPrereleaseRetainsItsExactTagAndCannotEnterStableChannel()throws Exception {
    byte[] exact=generate("2.5.0-beta.1","beta").exact();assertEquals("v2.5.0-beta.1",JsonData.object(exact,65536).get("tag").getAsString());acceptedEverywhere(exact,"beta","2.0.0");
    rejectedEverywhere(exact,sign(exact),"stable","2.0.0","2.0.0",IOException.class);
  }
  @Test void historical200BetaTagErrorIsRejectedEvenWithAValidTestSignature()throws Exception {
    JsonObject doc=JsonData.object(generate("2.0.0","beta").exact(),65536);doc.addProperty("tag","v2.0.0-beta.1");
    for(var file:doc.getAsJsonArray("artifacts")){JsonObject asset=file.getAsJsonObject();asset.addProperty("url",asset.get("url").getAsString().replace("/v2.0.0/","/v2.0.0-beta.1/"));}
    byte[] wrong=JsonData.encode(doc);rejectedEverywhere(wrong,sign(wrong),"beta","1.5.0","1.5.0",IOException.class);
  }
  @Test void signatureFirstPinnedKeyShaFormatAndRollbackRemainStrict()throws Exception {
    byte[] exact=generate("2.5.0","stable").exact(),signature=sign(exact),changed=exact.clone();changed[0]^=1;
    rejectedEverywhere(changed,signature,"stable","2.0.0","2.0.0",GeneralSecurityException.class);
    rejectedEverywhere(exact,signature,"stable","2.0.0","2.5.1",IOException.class);
    JsonObject doc=JsonData.object(exact,65536);doc.getAsJsonArray("artifacts").get(0).getAsJsonObject().addProperty("sha256","G".repeat(64));byte[] badHash=JsonData.encode(doc);
    rejectedEverywhere(badHash,sign(badHash),"stable","2.0.0","2.0.0",IOException.class);
    assertThrows(GeneralSecurityException.class,()->SignedManifest.verify(exact,signature,"stable","2.0.0","2.0.0"));
    for(Frozen parser:historical){Method pinned=parser.manifest().getMethod("verify",byte[].class,byte[].class,String.class,String.class,String.class);assertThrows(GeneralSecurityException.class,()->call(pinned,exact,signature,"stable","2.0.0","2.0.0"));}
  }
  @Test void generatedHashesDescribeActualFilesAndChangedSameSizeDownloadIsRejected()throws Exception {
    Generated generated=generate("2.5.0","stable");SignedManifest parsed=SignedManifest.verifyWithKey(generated.exact(),sign(generated.exact()),"stable","2.0.0","2.0.0",testKey.getPublic());
    for(SignedManifest.Asset asset:parsed.artifacts())UpdateService.verifyFile(generated.artifacts().resolve(asset.fileName()),asset);
    UpdateService.verifyFile(generated.artifacts().resolve("SHA256SUMS"),parsed.checksums());UpdateService.verifyFile(generated.artifacts().resolve("CHANGELOG-2.5.0.md"),parsed.changelog());
    SignedManifest.Asset asset=parsed.clientAsset(true);Path downloaded=generated.artifacts().resolve(asset.fileName());byte[] changed=Files.readAllBytes(downloaded);changed[0]^=1;Files.write(downloaded,changed);
    assertThrows(GeneralSecurityException.class,()->UpdateService.verifyFile(downloaded,asset));
  }
}
