package org.securemail.client.storage;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import org.securemail.client.AppPaths;

/** Encrypted full-profile backup and recoverable directory commit. No plaintext staging. */
public final class ClientUpgrade {
  private ClientUpgrade() {}
  public static Path beforeOpen(Path profile,Path backups)throws IOException {
    recover(profile);
    if(!Files.exists(profile.resolve("state.vault")))return null;
    // A 1.0 Argon2 vault still needs a full first-1.1 snapshot before creating sidecars.
    Path marker=backups.resolve(LocalStore.modernVault(profile)?"upgrade-1.1-backup-location":"migration-backup-location");
    if(Files.exists(marker)){
      Path existing=Path.of(Files.readString(marker).strip());
      if(existing.getParent().equals(backups.toAbsolutePath())&&Files.exists(existing.resolve("snapshot.properties"))){ProfileSnapshot.verify(existing,org.securemail.client.ClientConfig.load(AppPaths.config()).withStorage(profile));return existing;}
      // A legacy identity-only/partial snapshot is retained but never accepted as a complete backup.
    }
    Path backup=ProfileSnapshot.create(org.securemail.client.ClientConfig.load(AppPaths.config()).withStorage(profile),backups).toAbsolutePath();
    ProfileSnapshot.verify(backup,org.securemail.client.ClientConfig.load(AppPaths.config()).withStorage(profile));
    AtomicFiles.write(marker,backup.toString().getBytes(StandardCharsets.UTF_8));return backup;
  }
  public static void snapshot(Path source,Path target)throws IOException {
    if(target.toAbsolutePath().normalize().startsWith(source.toAbsolutePath().normalize()))throw new IOException("Backup cannot be inside its source");
    if(!Files.isDirectory(source,LinkOption.NOFOLLOW_LINKS))throw new IOException("Profile missing");
    AtomicFiles.directory(target);
    try(var paths=Files.walk(source)){
      for(Path file:paths.toList()){
        if(file.equals(source))continue;if(Files.isSymbolicLink(file))throw new IOException("Symlink in profile");
        String name=file.getFileName().toString();if(name.endsWith(".lock")||name.startsWith(".atomic-"))continue;
        Path dest=target.resolve(source.relativize(file));if(Files.isDirectory(file))AtomicFiles.directory(dest);else {Files.copy(file,dest);try(var ch=java.nio.channels.FileChannel.open(dest,StandardOpenOption.WRITE)){ch.force(true);}}
      }
    }AtomicFiles.syncDirectory(target);
  }
  private static Path journal(Path profile){return profile.resolveSibling(profile.getFileName()+".migration-journal");}
  /** Caller closes the old LocalStore before commit; the global application lock is held. */
  public static void commit(Path profile,Path verified)throws IOException {
    profile=profile.toAbsolutePath();verified=verified.toAbsolutePath();
    if(!profile.getParent().equals(verified.getParent())||!Files.exists(verified.resolve("vault-kdf")))throw new IOException("Invalid migration staging");
    Path old=profile.resolveSibling(profile.getFileName()+".pre-migration-"+UUID.randomUUID()),journal=journal(profile);
    AtomicFiles.write(journal,(old.getFileName()+"\n"+verified.getFileName()+"\n").getBytes(StandardCharsets.UTF_8));
    try{Files.move(profile,old,StandardCopyOption.ATOMIC_MOVE);Files.move(verified,profile,StandardCopyOption.ATOMIC_MOVE);AtomicFiles.syncDirectory(profile.getParent());Files.delete(journal);AtomicFiles.syncDirectory(profile.getParent());}
    catch(IOException e){recover(profile);throw e;}
    // Keep the encrypted previous directory for rollback; also retained in the dated backup.
  }
  public static void recover(Path profile)throws IOException {
    profile=profile.toAbsolutePath();Path journal=journal(profile);if(!Files.exists(journal))return;
    List<String> lines=Files.readAllLines(journal,StandardCharsets.UTF_8);if(lines.size()!=2)throw new IOException("Migration journal damaged");
    for(String name:lines)if(name.contains("/")||name.contains("\\")||!name.startsWith(profile.getFileName()+"."))throw new IOException("Migration journal damaged");
    Path old=profile.resolveSibling(lines.getFirst());
    if(Files.exists(old)){
      if(Files.exists(profile))Files.move(profile,profile.resolveSibling(profile.getFileName()+".failed-migration-"+UUID.randomUUID()),StandardCopyOption.ATOMIC_MOVE);
      Files.move(old,profile,StandardCopyOption.ATOMIC_MOVE);AtomicFiles.syncDirectory(profile.getParent());
    }
    Files.delete(journal);AtomicFiles.syncDirectory(profile.getParent());
  }
}
