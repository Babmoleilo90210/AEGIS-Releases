package org.securemail.client.storage;

import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

public final class AtomicFiles {
  private AtomicFiles() {}

  public static void directory(Path p) throws IOException {
    Files.createDirectories(p);
    if (Files.isSymbolicLink(p)) throw new IOException("Symlink storage is not allowed");
    if(Files.getFileStore(p).supportsFileAttributeView("posix")) Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwx------"));
    else {
      var view=Files.getFileAttributeView(p,AclFileAttributeView.class,LinkOption.NOFOLLOW_LINKS);
      if(view==null)throw new IOException("Хранилище требует NTFS с ACL");
      var user=p.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
      view.setAcl(List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(user).setPermissions(EnumSet.allOf(AclEntryPermission.class)).setFlags(AclEntryFlag.FILE_INHERIT,AclEntryFlag.DIRECTORY_INHERIT).build()));
    }
  }

  public static void write(Path p, byte[] b) throws IOException {
    Path t =
        Files.createTempFile(
            p.getParent(),
            ".atomic-",
            ".tmp",
            attributes(p.getParent()));
    try {
      try (var ch = FileChannel.open(t, StandardOpenOption.WRITE)) {
        ByteBuffer data = ByteBuffer.wrap(b);
        while (data.hasRemaining()) ch.write(data);
        ch.force(true);
      }
      Files.move(t, p, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      syncDirectory(p.getParent());
    } finally {
      Files.deleteIfExists(t);
    }
  }

  public static FileAttribute<?>[] attributes(Path parent) throws IOException {
    if(Files.getFileStore(parent).supportsFileAttributeView("posix"))return new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))};
    var owner=parent.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
    List<AclEntry> acl=List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner).setPermissions(EnumSet.allOf(AclEntryPermission.class)).build());
    return new FileAttribute<?>[]{new FileAttribute<List<AclEntry>>(){public String name(){return "acl:acl";}public List<AclEntry> value(){return acl;}}};
  }
  /** Explicit exports may target exFAT; private application storage still requires ACL/POSIX. */
  public static FileAttribute<?>[] exportAttributes(Path parent) throws IOException {
    if(!Files.getFileStore(parent).supportsFileAttributeView("posix")&&!Files.getFileStore(parent).supportsFileAttributeView("acl"))return new FileAttribute<?>[0];
    return attributes(parent);
  }
  public static void syncDirectory(Path p) throws IOException {
    if(System.getProperty("os.name").startsWith("Windows"))return; // NIO Windows cannot fsync directories; files are forced before atomic rename.
    try (var ch = FileChannel.open(p, StandardOpenOption.READ)) {
      ch.force(true);
    }
  }

  public static byte[] read(Path p, int max) throws IOException {
    if (Files.isSymbolicLink(p) || Files.size(p) > max) throw new IOException("Invalid local file");
    try (var in = Files.newInputStream(p)) {
      byte[] b = in.readNBytes(max + 1);
      if (b.length > max) throw new IOException("Invalid local file");
      return b;
    }
  }
}
