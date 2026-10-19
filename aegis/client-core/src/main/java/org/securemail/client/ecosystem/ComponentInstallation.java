package org.securemail.client.ecosystem;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Installer-supplied fixed JVM and JAR inventory. No shell commands, user main classes or raw JVM options. */
public record ComponentInstallation(Path javaExecutable, String javaSha256, Map<Path, String> classpath) {
  public ComponentInstallation {
    javaExecutable = Objects.requireNonNull(javaExecutable).toAbsolutePath().normalize();
    if (!hex(javaSha256) || classpath == null || classpath.isEmpty() || classpath.size() > 96)
      throw new IllegalArgumentException("Некорректная установленная программа");
    var copy = new LinkedHashMap<Path, String>();
    for (var entry : classpath.entrySet()) {
      Path path = entry.getKey().toAbsolutePath().normalize();
      if (!path.getFileName().toString().endsWith(".jar") || !hex(entry.getValue()) || copy.put(path, entry.getValue()) != null)
        throw new IllegalArgumentException("Некорректный состав программы");
    }
    classpath = Collections.unmodifiableMap(copy);
  }
  private static boolean hex(String value) { return value != null && value.matches("[a-f0-9]{64}"); }
  public void verify() throws IOException {
    verifyFile(javaExecutable, javaSha256);
    for (var entry : classpath.entrySet()) verifyFile(entry.getKey(), entry.getValue());
  }
  private static void verifyFile(Path file, String expected) throws IOException {
    if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
      throw new IOException("Файл установленной программы отсутствует или подменён");
    Path parent=file.getParent();
    while (parent != null) { if (Files.isSymbolicLink(parent)) throw new IOException("Ссылка в пути программы запрещена"); parent=parent.getParent(); }
    if (!MessageDigest.isEqual(expected.getBytes(java.nio.charset.StandardCharsets.US_ASCII), sha256(file).getBytes(java.nio.charset.StandardCharsets.US_ASCII)))
      throw new IOException("Контрольная сумма установленной программы не совпадает");
  }
  public static String sha256(Path path) throws IOException {
    try {
      MessageDigest digest=MessageDigest.getInstance("SHA-256"); byte[] buffer=new byte[65536];
      try(InputStream in=Files.newInputStream(path)) { int size; while ((size=in.read(buffer)) != -1) digest.update(buffer,0,size); }
      return HexFormat.of().formatHex(digest.digest());
    } catch (GeneralSecurityException e) { throw new IOException("Недоступна проверка целостности",e); }
  }
  List<String> command(ComponentId component) {return commandFor("org.securemail.ui.ecosystem.ComponentEntrypoint",List.of(component.name()));}
  List<String> pairingCommand(){return commandFor("org.securemail.ui.MailPairingEntrypoint600",List.of());}
  private List<String> commandFor(String main,List<String> args) {
    Path appDirectory=classpath.keySet().iterator().next().getParent();
    Path bundle=System.getProperty("aegis.home")!=null?org.securemail.client.AppPaths.bundle():appDirectory.getFileName().toString().equals("app")?appDirectory.getParent():org.securemail.client.AppPaths.bundle();
    var result=new ArrayList<>(List.of(javaExecutable.toString(),"-Daegis.home="+bundle,"-Daegis.native.root="+bundle, "-Xmx768m", "-XX:+DisableAttachMechanism",
        "-XX:-HeapDumpOnOutOfMemoryError", "-cp", String.join(java.io.File.pathSeparator,
        classpath.keySet().stream().map(Path::toString).toList()),
        main));String explicitProfile=System.getProperty("aegis.profile");if(explicitProfile!=null)result.add(1,"-Daegis.profile="+org.securemail.client.AppPaths.root());result.addAll(args);return List.copyOf(result);
  }
}
