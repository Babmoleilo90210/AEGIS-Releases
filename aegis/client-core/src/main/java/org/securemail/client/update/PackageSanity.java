package org.securemail.client.update;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import net.lingala.zip4j.model.FileHeader;

/** Package limits are checked after signature/hash validation, before extraction or execution. */
public final class PackageSanity {
  private PackageSanity(){}
  public static void check(Path file,SignedManifest.Asset asset,String version)throws IOException {
    if(Files.isSymbolicLink(file)||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)||Files.size(file)!=asset.size())throw new IOException("Invalid update package");
    if(asset.kind().equals("portable"))zip(file,version);else if(asset.kind().equals("appimage"))appimage(file);else throw new IOException("Unsupported update package");
  }
  private static String entry(String name)throws IOException {
    if(name.length()>500||name.startsWith("/")||name.contains("\\")||name.contains(":"))throw new IOException("Unsafe update path");
    String[] parts=name.split("/");if(parts.length<2||!parts[0].equals("AEGIS"))throw new IOException("Invalid package root");
    for(String p:parts)if(p.isEmpty()||p.equals(".")||p.equals("..")||p.endsWith(".")||p.endsWith(" ")||p.chars().anyMatch(c->c<32)||p.matches("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\\..*)?"))throw new IOException("Unsafe update filename");
    return String.join("/",Arrays.copyOfRange(parts,1,parts.length));
  }
  private static void zip(Path path,String version)throws IOException {
    List<FileHeader> headers=new net.lingala.zip4j.ZipFile(path.toFile()).getFileHeaders();if(headers.size()>10000)throw new IOException("Too many update files");long total=0;Set<String> names=new HashSet<>();
    for(FileHeader h:headers){String name=entry(h.getFileName());if(!names.add(name.toLowerCase(Locale.ROOT)))throw new IOException("Duplicate update path");byte[] a=h.getExternalFileAttributes();int mode=a.length>=4?(Byte.toUnsignedInt(a[3])<<8)|Byte.toUnsignedInt(a[2]):0;if((mode&0170000)==0120000||h.isEncrypted())throw new IOException("Unsafe update entry");long n=h.getUncompressedSize();if(n<0||n>256L*1024*1024||(total+=n)>768L*1024*1024)throw new IOException("Update expansion limit");}
    for(String required:List.of("AEGIS.exe","AEGIS-Updater.exe","runtime/bin/javaw.exe","tor/tor.exe","tor/pluggable_transports/lyrebird.exe","native/libsodium.dll","app/client-core-"+version+".jar","app/client-ui-"+version+".jar","app/common-protocol-0.2.0.jar"))if(!names.contains(required.toLowerCase(Locale.ROOT)))throw new IOException("Incomplete Windows update");
    try(ZipInputStream in=new ZipInputStream(Files.newInputStream(path))){byte[] b=new byte[65536];long count=0;int files=0;for(ZipEntry e;(e=in.getNextEntry())!=null;){entry(e.getName());if(++files>10000)throw new IOException("Too many update entries");while(true){int n=in.read(b);if(n<0)break;if((count+=n)>768L*1024*1024)throw new IOException("Update expansion limit");}in.closeEntry();}if(files!=headers.size())throw new IOException("ZIP directory mismatch");}
  }
  public static void extractWindows(Path archive,Path target)throws IOException {
    if(Files.exists(target))throw new IOException("Staging target exists");Files.createDirectory(target);
    try(ZipInputStream in=new ZipInputStream(Files.newInputStream(archive))){
      byte[] b=new byte[65536];long count=0;int files=0;
      for(ZipEntry e;(e=in.getNextEntry())!=null;){Path path=target.resolve(entry(e.getName())).normalize();if(!path.startsWith(target.toAbsolutePath())&&!path.toAbsolutePath().startsWith(target.toAbsolutePath()))throw new IOException("Path traversal");if(++files>10000)throw new IOException("Too many files");if(e.isDirectory())Files.createDirectories(path);else{Files.createDirectories(path.getParent());try(OutputStream out=Files.newOutputStream(path,StandardOpenOption.CREATE_NEW)){int n;while((n=in.read(b))!=-1){if((count+=n)>768L*1024*1024)throw new IOException("Expansion limit");out.write(b,0,n);}}try(var ch=FileChannel.open(path,StandardOpenOption.WRITE)){ch.force(true);}}in.closeEntry();}
    }
  }
  private static void appimage(Path file)throws IOException {
    try(var channel=FileChannel.open(file,StandardOpenOption.READ)){
      ByteBuffer b=ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);read(channel,b,0);byte[] h=b.array();
      if(h[0]!=127||h[1]!='E'||h[2]!='L'||h[3]!='F'||h[4]!=2||h[5]!=1||h[8]!='A'||h[9]!='I'||h[10]!=2||b.getShort(18)!=62)throw new IOException("Invalid x64 Type2 AppImage");
      long offset=b.getLong(40);int width=Short.toUnsignedInt(b.getShort(58)),count=Short.toUnsignedInt(b.getShort(60));if(width<64||width>128||count<1||count>1000||offset<64||offset+(long)width*count>channel.size())throw new IOException("Invalid ELF sections");
      long end=offset+(long)width*count;
      for(int i=0;i<count;i++){ByteBuffer section=ByteBuffer.allocate(width).order(ByteOrder.LITTLE_ENDIAN);read(channel,section,offset+(long)i*width);if(section.getInt(4)!=8){long at=section.getLong(24),size=section.getLong(32);if(at<0||size<0||at+size>channel.size())throw new IOException("Invalid ELF payload");end=Math.max(end,at+size);}}
      ByteBuffer magic=ByteBuffer.allocate(4);read(channel,magic,end);if(!Arrays.equals(magic.array(),new byte[]{'h','s','q','s'}))throw new IOException("Missing AppImage filesystem");
    }
  }
  private static void read(FileChannel channel,ByteBuffer buffer,long at)throws IOException {while(buffer.hasRemaining()){int n=channel.read(buffer,at);if(n<0)throw new EOFException("Truncated package");at+=n;}buffer.rewind();}
}
