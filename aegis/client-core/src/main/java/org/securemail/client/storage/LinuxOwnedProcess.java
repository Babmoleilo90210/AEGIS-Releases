package org.securemail.client.storage;
import com.sun.jna.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Kernel pidfd pins a proved process incarnation; works with a host-mounted /proc too.
 * No shell, process-name kill or PID reuse race. Linux >=5.3 / glibc >=2.36.
 */
final class LinuxOwnedProcess implements AutoCloseable {
  private interface LibC extends Library {
    int pidfd_open(int pid,int flags);int pidfd_send_signal(int fd,int signal,Pointer info,int flags);
    int poll(Pointer descriptors,NativeLong count,int timeout);int close(int fd);
  }
  private static final LibC LIB=Native.load("c",LibC.class);
  private final int fd;
  private LinuxOwnedProcess(int fd){this.fd=fd;}
  static LinuxOwnedProcess pin(ProcessHandle process)throws IOException {
    Path proc=Path.of("/proc",Long.toString(process.pid()));String before=birth(proc);
    int depth=namespaceIds(Path.of("/proc/self/status")).length;int[] ids=namespaceIds(proc.resolve("status"));
    if(ids.length<depth)throw new IOException("Process namespace mismatch");int pid=ids[depth-1];int fd;
    try{fd=LIB.pidfd_open(pid,0);}catch(UnsatisfiedLinkError e){throw new IOException("Закройте прежний АЕГИС перед обновлением: pidfd недоступен",e);}
    if(fd<0)throw new IOException("Не удалось закрепить процесс прежнего АЕГИС");
    LinuxOwnedProcess pinned=new LinuxOwnedProcess(fd);
    try{if(!pinned.alive()||!before.equals(birth(proc)))throw new IOException("Process changed during update");return pinned;}catch(IOException failure){pinned.close();throw failure;}
  }
  private static int[] namespaceIds(Path status)throws IOException {
    String text=new String(AtomicFiles.read(status,65536),StandardCharsets.US_ASCII);
    for(String line:text.split("\n"))if(line.startsWith("NSpid:")){
      try{return Arrays.stream(line.substring(6).strip().split("\\s+")).mapToInt(Integer::parseInt).toArray();}catch(NumberFormatException e){throw new IOException("Invalid process namespace",e);}
    }throw new IOException("Process namespace unavailable");
  }
  private static String birth(Path proc)throws IOException {String stat=new String(AtomicFiles.read(proc.resolve("stat"),8192),StandardCharsets.US_ASCII);int end=stat.lastIndexOf(')');String[] fields=stat.substring(end+1).strip().split("\\s+");if(fields.length<=19)throw new IOException("Invalid process stat");return fields[19];}
  boolean alive()throws IOException {
    try(Memory descriptor=new Memory(8)){descriptor.setInt(0,fd);descriptor.setShort(4,(short)1);descriptor.setShort(6,(short)0);int result=LIB.poll(descriptor,new NativeLong(1),0);if(result<0)throw new IOException("Process wait failed");if(result==0)return true;if((descriptor.getShort(6)&17)!=0)return false;throw new IOException("Invalid process descriptor event");}
  }
  void signal(int signal)throws IOException {if(alive()&&LIB.pidfd_send_signal(fd,signal,null,0)<0)throw new IOException("Не удалось закрыть прежний АЕГИС");}
  boolean await(long millis)throws IOException,InterruptedException {long until=System.nanoTime()+java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(millis);while(alive()&&System.nanoTime()<until)Thread.sleep(50);return !alive();}
  @Override public void close(){LIB.close(fd);}
}
