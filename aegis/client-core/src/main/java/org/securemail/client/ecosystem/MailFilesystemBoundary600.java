package org.securemail.client.ecosystem;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import org.securemail.client.AppPaths;
import org.securemail.client.ClientConfig;
import org.securemail.client.safeweb600.VzorLaunch600;

/** Fail-closed, path-only preflight for Mail 6. No key, password or profile content enters the browser manager. */
public final class MailFilesystemBoundary600 {
  public static final class Violation extends IOException{private static final long serialVersionUID=1L;private Violation(IOException cause){super("Каталог Почты или архива нарушает изоляцию Взора. Выберите личную папку вне системных папок и каталогов браузера. Старые данные сохранены.",cause);}}
  private MailFilesystemBoundary600(){}
  private static void requirePaths(List<Path> paths)throws IOException{try{VzorLaunch600.requireHiddenData(paths);}catch(IOException unsafe){throw new Violation(unsafe);}}
  public static void require(ClientConfig config)throws IOException {
    Objects.requireNonNull(config,"config");
    Path storage=config.storagePath().toAbsolutePath().normalize();
    Path name=storage.getFileName();
    if(name==null)throw new IOException("Каталог Почты должен находиться отдельно от корня файловой системы");
    requirePaths(List.of(AppPaths.root(),AppPaths.config(),storage,
        storage.resolveSibling(name+".personal-archive"),AppPaths.root().resolveSibling("aegis-archive-guards")));
  }
  public static void requireArchive(Path archive)throws IOException {
    if(archive==null)throw new IOException("Не задан защищённый каталог архива");
    requirePaths(List.of(AppPaths.root(),AppPaths.config(),archive,
        AppPaths.root().resolveSibling("aegis-archive-guards")));
  }
}
