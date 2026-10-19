package org.securemail.ui;

import java.nio.file.*;
import org.securemail.client.ClientConfig;
import org.securemail.client.storage.LocalStore;

public final class Launcher {
  private Launcher() {}

  public static void main(String[] args) {
    try (org.securemail.client.maintenance600.RuntimeLease600.Lease runtime=org.securemail.client.maintenance600.RuntimeLease600.running()) {
      if (args.length > 0 && args[0].equals("--cleanup")) {
        Path c = args.length > 1 ? Path.of(args[1]) : AegisApp.defaultConfig();
        LocalStore.cleanupLockedFiles(
            ClientConfig.load(c).storagePath(), System.currentTimeMillis());
        return;
      }
      Path profile=org.securemail.client.AppPaths.root();
      org.securemail.client.storage.AtomicFiles.directory(profile);
      for(String name:new String[]{"tmp","native-cache"})org.securemail.client.storage.AtomicFiles.directory(profile.resolve(name));
      System.setProperty("java.io.tmpdir",profile.resolve("tmp").toString());
      System.setProperty("jna.tmpdir",profile.resolve("native-cache").toString());
      System.setProperty("javafx.cachedir",profile.resolve("native-cache").toString());
      javafx.application.Application.launch(CoreApp600.class, args);
    } catch (Exception e) {
      System.err.println("АЕГИС: запуск не завершён. Проверьте Java 21, графическое окружение и установленный комплект.");
      System.exit(1);
    }
  }
}
