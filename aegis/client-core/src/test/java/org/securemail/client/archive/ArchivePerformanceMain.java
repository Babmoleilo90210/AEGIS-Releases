package org.securemail.client.archive;
import java.io.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
/** Bounded measured workload, generated InputStream never stages a plaintext file. */
public final class ArchivePerformanceMain {
  public static void main(String[] args)throws Exception {
    Path root=Files.createTempDirectory("AEGIS-150-performance-");long bytes=32L*1024*1024,start=System.nanoTime(),cpu=ProcessHandle.current().info().totalCpuDuration().map(java.time.Duration::toNanos).orElse(-1L);long create,imported,search,backup,restored;
    char[] password="synthetic benchmark archive password".toCharArray();
    try(var a=EncryptedArchive.create(root.resolve("archive"),root.resolve("guards"),password,false,Clock.systemUTC()).archive()){
      create=System.nanoTime();InputStream synthetic=new InputStream(){long remaining=bytes;public int read(){if(remaining--<=0)return -1;return 0x41;}public int read(byte[] b,int off,int len){int n=(int)Math.min(remaining,len);if(n<=0)return -1;Arrays.fill(b,off,off+n,(byte)0x41);remaining-=n;return n;}};
      a.importStream("generated.bin","file",bytes,synthetic,"",List.of(),false,false,EncryptedArchive.QUIET,()->false);imported=System.nanoTime();
      a.importBytes("text.txt","text","Текст benchmark-token только в зашифрованном индексе".getBytes(java.nio.charset.StandardCharsets.UTF_8),"",false,EncryptedArchive.QUIET,()->false);if(a.search(new EncryptedArchive.Filter("benchmark-token","","",0,Long.MAX_VALUE,false,false,true),EncryptedArchive.QUIET,()->false).size()!=1)throw new AssertionError();search=System.nanoTime();
      a.backup(root.resolve("copy.aegis-archive"),null,EncryptedArchive.QUIET,()->false);backup=System.nanoTime();try(var b=ArchiveBackup.restore(root.resolve("copy.aegis-archive"),root.resolve("restored"),root.resolve("new-guards"),password,Clock.systemUTC(),EncryptedArchive.QUIET,()->false)){b.verifyAll(EncryptedArchive.QUIET,()->false);}restored=System.nanoTime();
      System.gc();long heap=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();System.out.println("{\"version\":\"1.5.0\",\"environment\":\"Linux headless JDK21\",\"bytes\":"+bytes+",\"createMs\":"+((create-start)/1000000)+",\"importMs\":"+((imported-create)/1000000)+",\"textImportAndSearchMs\":"+((search-imported)/1000000)+",\"backupMs\":"+((backup-search)/1000000)+",\"restoreAndVerifyMs\":"+((restored-backup)/1000000)+",\"cpuMs\":"+(cpu<0?-1:(ProcessHandle.current().info().totalCpuDuration().map(java.time.Duration::toNanos).orElse(cpu)-cpu)/1000000)+",\"heapAfterGcBytes\":"+heap+",\"plaintextFileStaging\":false,\"nativeAcceptance\":false}");
    }finally{Arrays.fill(password,'\0');}
  }
}
