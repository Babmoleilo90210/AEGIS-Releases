package org.securemail.client.security;

import com.google.gson.GsonBuilder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.securemail.client.crypto.*;
import org.securemail.client.crypto.Identity;
import org.securemail.client.net.TorTransport;
import org.securemail.client.storage.LocalStore;
import org.securemail.client.update.SignedManifest;
import org.securemail.protocol.*;

/** Owner-side test runner. It is never placed on the application's production classpath. */
public final class NativeAcceptanceMain {
  @FunctionalInterface private interface Check { void run() throws Exception; }
  private final Map<String,Object> report = new LinkedHashMap<>();
  private final List<Map<String,Object>> checks = new ArrayList<>();
  private final Path app, kit, temporary;
  private NativeAcceptanceMain(Path app, Path kit, Path temporary) {
    this.app = app; this.kit = kit; this.temporary = temporary;
  }
  private static void require(boolean value, String message) {
    if (!value) throw new AssertionError(message);
  }
  private static String sha256(Path file) throws Exception {
    var digest = MessageDigest.getInstance("SHA-256");
    try (var input = Files.newInputStream(file)) { byte[] b = new byte[65536]; for (int n; (n = input.read(b)) != -1;) digest.update(b,0,n); }
    return HexFormat.of().formatHex(digest.digest());
  }
  private boolean check(String name, Check action) {
    long start = System.nanoTime();
    Map<String,Object> item = new LinkedHashMap<>(); item.put("name", name);
    boolean passed;
    try { action.run(); item.put("result","PASS"); passed = true; }
    catch (Throwable error) {
      item.put("result","FAIL_OR_UNAVAILABLE");
      // Error type only: no exception text, credential values or stack trace in the report.
      item.put("technicalErrorType",error.getClass().getSimpleName()); passed = false;
    }
    item.put("elapsedMillis",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start));
    checks.add(item); System.out.println(item.get("result") + " " + name);
    return passed;
  }
  private void child(String main, int seconds, String... arguments) throws Exception {
    Path working = temporary.resolve("child-" + checks.size()); Files.createDirectory(working);
    var command = new ArrayList<String>(List.of(app.resolve("runtime/bin/java" + (isWindows()?".exe":"")).toString(),
        "-Xmx768m","-XX:+DisableAttachMechanism","-XX:-HeapDumpOnOutOfMemoryError",
        "-Daegis.home="+app,"-Daegis.secret.test.isolated=true","-Djava.io.tmpdir="+temporary,
        "-cp",kit.resolve("aegis-native-tests.jar") + File.pathSeparator + kit.resolve("aegis-ui-tests.jar") + File.pathSeparator + app.resolve("app") + File.separator + "*", main));
    command.addAll(List.of(arguments));
    Path log = working.resolve("technical-test.log");
    ProcessBuilder builder = new ProcessBuilder(command).directory(working.toFile()).redirectErrorStream(true).redirectOutput(log.toFile());
    for (String name : List.of("JAVA_TOOL_OPTIONS","_JAVA_OPTIONS","JDK_JAVA_OPTIONS","CLASSPATH")) builder.environment().remove(name);
    Process process = builder.start();
    try {
      boolean finished = process.waitFor(seconds,TimeUnit.SECONDS);
      require(finished && process.exitValue()==0,"Native test process did not pass");
      if (main.endsWith("NativeScreenProbe")) {
        String text = Files.readString(log);
        for (String line : text.split("\\R")) if (line.startsWith("AEGIS_SCREEN "))
          report.put("nativeScreen",com.google.gson.JsonParser.parseString(line.substring(13)));
      }
    } finally {
      // Only this test's owned processes are stopped; never system Tor/keyring or another AEGIS.
      List<ProcessHandle> children = process.descendants().toList();
      if (process.isAlive()) process.destroy();
      for (ProcessHandle owned : children) if (owned.isAlive()) owned.destroy();
      if (!process.waitFor(5,TimeUnit.SECONDS)) process.destroyForcibly();
      for (ProcessHandle owned : children) if (owned.isAlive()) owned.destroyForcibly();
    }
  }
  private static boolean isWindows() { return System.getProperty("os.name").startsWith("Windows"); }
  private void run(boolean gui) throws Exception {
    report.put("schemaVersion",1); report.put("applicationVersion",SignedManifest.CURRENT); report.put("checkedAtUtc",Instant.now().toString());
    report.put("osName",System.getProperty("os.name")); report.put("osVersion",System.getProperty("os.version"));
    report.put("architecture",System.getProperty("os.arch")); report.put("javaVersion",System.getProperty("java.version"));
    report.put("glassPlatformOverride",System.getProperty("glass.platform","none"));
    report.put("desktopSession",Objects.toString(System.getenv("XDG_SESSION_TYPE"),isWindows()?"windows":"unknown"));
    if (!isWindows() && Files.isRegularFile(Path.of("/etc/os-release"))) {
      Map<String,String> distribution = new LinkedHashMap<>();
      for (String line : Files.readAllLines(Path.of("/etc/os-release"))) {
        int at=line.indexOf('='); if(at>0 && Set.of("ID","ID_LIKE","VERSION_ID","NAME").contains(line.substring(0,at)))
          distribution.put(line.substring(0,at),line.substring(at+1).replace("\"",""));
      }
      report.put("linuxDistribution",distribution);
    }
    Map<String,String> jars = new LinkedHashMap<>();
    check("packaged_java21_and_common_client_JARs",()->{
      require(Runtime.version().feature()==21,"Java21 required");
      for(String name:List.of("client-core-"+SignedManifest.CURRENT+".jar","client-ui-"+SignedManifest.CURRENT+".jar","common-protocol-0.2.0.jar")) jars.put(name,sha256(app.resolve("app").resolve(name)));
      Path metadata=kit.resolve("TESTED-ARTIFACTS.json");
      require(Files.size(metadata)<65536,"Oversized acceptance metadata");
      var expected=com.google.gson.JsonParser.parseString(Files.readString(metadata)).getAsJsonObject().getAsJsonObject("applicationJarSha256");
      for(var entry:jars.entrySet())require(entry.getValue().equals(expected.get(entry.getKey()).getAsString()),"Different application JAR");
      require(!Files.exists(app.resolve("app/relay-server-0.2.0.jar")),"Relay in client");
    });
    report.put("applicationJarSha256",jars);
    check("embedded_owner_key_and_unsigned_manifest_rejection",()->{
      require(Base64.getEncoder().encodeToString(SignedManifest.embeddedPublicKey()).equals("MCowBQYDK2VwAyEAswWYCFStSEhQdrgqUJFF3x12ltmfUA0PvQtlh684B2g="),"Wrong root key");
      boolean rejected=false;try{SignedManifest.verify("{}".getBytes(StandardCharsets.UTF_8),new byte[64],"stable","1.0.0","1.0.0");}catch(GeneralSecurityException expected){rejected=true;}
      require(rejected,"Unsigned metadata accepted");
    });
    check("modern_ciphers_roundtrip_wrong_password_and_nonce",()->{
      Identity sender=Identity.create(),recipient=Identity.create();var crypto=new EncryptionService(Clock.systemUTC());
      char[] password=Base64.getEncoder().encodeToString(Secrets.random(24)).toCharArray();
      char[] wrong=Base64.getEncoder().encodeToString(Secrets.random(24)).toCharArray();
      try {
        for(Algorithm algorithm:List.of(Algorithm.AES_256_GCM,Algorithm.XCHACHA20_POLY1305,Algorithm.CHACHA20_POLY1305,Algorithm.CAMELLIA_256_GCM))
          try(var plaintext=PlainMessage.text("Synthetic AEGIS native acceptance fixture")) {
            var packet=crypto.encrypt(plaintext,password,algorithm,300,86400000,sender,"raven",recipient.userId());
            var second=crypto.encrypt(plaintext,password,algorithm,300,86400000,sender,"raven",recipient.userId());
            require(!Arrays.equals(packet.nonce(),second.nonce()),"Nonce repeated");
            try(var opened=crypto.decrypt(packet,password,100000)){require(opened.text().equals(plaintext.text()),"Cipher roundtrip failed");}
            boolean rejected=false;try(var ignored=crypto.decrypt(packet,wrong,100000)){}catch(GeneralSecurityException expected){rejected=true;}
            require(rejected,"Wrong message password accepted");
          }
      } finally {Arrays.fill(password,'\0');Arrays.fill(wrong,'\0');}
    });
    check("bundled_libsodium_E2EE_and_identity_binding",()->{
      Identity sender=Identity.create(),recipient=Identity.create(),stranger=Identity.create();var crypto=new AutomaticEncryption(Clock.systemUTC());
      try(var plaintext=PlainMessage.text("Synthetic native libsodium fixture")) {
        var packet=crypto.encrypt(plaintext,300,86400000,sender,"raven",new UserInfo(recipient.userId(),"wolf",recipient.publicKey(),null));
        try(var opened=crypto.decrypt(packet,recipient,100000)){require(opened.text().equals(plaintext.text()),"Native recipient unwrap failed");}
        try(var opened=crypto.decrypt(packet,sender,100000)){require(opened.text().equals(plaintext.text()),"Native sender unwrap failed");}
        boolean rejected=false;try(var ignored=crypto.decrypt(packet,stranger,100000)){}catch(GeneralSecurityException expected){rejected=true;}
        require(rejected,"Different identity accepted");
      }
    });
    check("encrypted_vault_reopen_on_native_filesystem",()->{
      Path data=temporary.resolve("vault");char[] password=Base64.getEncoder().encodeToString(Secrets.random(24)).toCharArray();String identity;
      try {
        try(var store=new LocalStore(data,password,Clock.systemUTC(),100000,1000000)){store.bindNickname("raven");identity=store.identity().userId();}
        try(var store=new LocalStore(data,password,Clock.systemUTC(),100000,1000000)){require(store.identity().userId().equals(identity)&&store.nickname().equals("raven"),"Vault identity changed");}
      } finally {Arrays.fill(password,'\0');}
    });
    check("Tor_unavailable_fails_closed",()->{
      TorTransport.requireAvailability(()->false);
      try { boolean rejected=false;try(var ignored=new TorTransport("127.0.0.1",19050).connectUpdate("github.com")){}catch(IOException expected){rejected=true;}require(rejected,"Direct fallback permitted"); }
      finally {TorTransport.requireAvailability(()->true);}
    });
    check(isWindows()?"native_DPAPI_CurrentUser_resume_restart_expiry_tamper":"native_SecretService_resume_restart_expiry_tamper",
      ()->child(NativeCredentialStoreSmoke.class.getName(),100,temporary.resolve("system-profile").toString()));
    if(gui) {
      if(check("native_JavaFX_screen",()->child("org.securemail.ui.NativeScreenProbe",30))) {
        check("native_contact_and_TTL_popups",()->child("org.securemail.ui.NativeGuiSmokeLauncher",150,"picker"));
        check("native_selectors_themes_presets_and_update_progress",()->child("org.securemail.ui.NativeGuiSmokeLauncher",150,"selectors"));
        check("native_messenger_password_FF1_preview_TTL",()->child("org.securemail.ui.NativeGuiSmokeLauncher",150,"messenger"));
        check("native_profile_scale_and_draft",()->child("org.securemail.ui.NativeGuiSmokeLauncher",150,"aegis11"));
        check("native_single_window_navigation",()->child("org.securemail.ui.NativeGuiSmokeLauncher",150,"single-window"));
      }
    } else report.put("nativeGUI","NOT_REQUESTED");
    report.put("checks",checks);
    report.put("allExecutedChecksPassed",checks.stream().allMatch(item->item.get("result").equals("PASS")));
    report.put("productionReady",false);
    report.put("stillRequires",List.of("Real client launch/installer, all Windows DPI settings and native reboot acceptance",
        "Real Tor100% and Windows-to-CachyOS exchange/offline/files/TTL through the owner's relay",
        "Explicit decision for frozen relay12h/auth compatibility constraints", "Owner-only offline manifest signature"));
    report.put("secretsOrPasswordsIncluded",false);report.put("automaticUpload",false);report.put("networkConnectionsInitiated",false);
  }
  public static void main(String[] args) throws Exception {
    if(args.length<2 || args.length>3)throw new IllegalArgumentException("Usage: NativeAcceptanceMain APP_DIRECTORY KIT_DIRECTORY [--gui]");
    Path app=Path.of(args[0]).toAbsolutePath().normalize(),kit=Path.of(args[1]).toAbsolutePath().normalize();
    Path temporary=Files.createTempDirectory("aegis-native-acceptance-");
    boolean allPassed=false;
    try {
      try{Files.setPosixFilePermissions(temporary,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));}catch(UnsupportedOperationException ignored){}
      System.setProperty("aegis.home",app.toString());System.setProperty("aegis.profile",temporary.resolve("app-profile").toString());
      System.setProperty("java.io.tmpdir",temporary.toString());System.setProperty("jna.tmpdir",temporary.toString());
      var runner=new NativeAcceptanceMain(app,kit,temporary);runner.run(args.length==3&&args[2].equals("--gui"));
      Path output=Path.of("AEGIS-native-"+(isWindows()?"Windows":"Linux")+"-"+System.currentTimeMillis()+".json").toAbsolutePath();
      Files.writeString(output,new GsonBuilder().setPrettyPrinting().create().toJson(runner.report)+"\n",StandardOpenOption.CREATE_NEW);
      System.out.println("Report: "+output);System.out.println("This test report is not a production-readiness declaration.");
      allPassed=runner.checks.stream().allMatch(item->item.get("result").equals("PASS"));
    } finally {
      try(var paths=Files.walk(temporary)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())try{Files.deleteIfExists(path);}catch(IOException ignored){}}
    }
    if(!allPassed)System.exit(1);
  }
}
