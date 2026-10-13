package org.securemail.client.lifecycle;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Ole32;
import com.sun.jna.platform.win32.COM.WbemcliUtil.WmiQuery;

/** OS boot identity and elapsed boot time, including suspend; never performs a network request. */
public interface BootClock {
  record Stamp(String boot,long elapsed){public Stamp{if(boot.isBlank()||boot.length()>128||elapsed<0)throw new IllegalArgumentException("Boot clock");}}
  Stamp stamp()throws IOException;
  static BootClock system(){
    if(System.getProperty("os.name").startsWith("Windows")){
      FutureTask<String> task=new FutureTask<>(()->{
        int result=Ole32.INSTANCE.CoInitializeEx(null,Ole32.COINIT_MULTITHREADED).intValue();if(result<0)throw new IOException("Local WMI unavailable");
        try{var values=new WmiQuery<>("Win32_OperatingSystem",BootProperty.class).execute(2500);if(values.getResultCount()!=1)throw new IOException("Boot identity unavailable");String id=(String)values.getValue(BootProperty.LASTBOOTUPTIME,0);if(id==null||!id.matches("[0-9]{14}\\.[0-9]{6}[+-][0-9]{3}"))throw new IOException("Boot identity invalid");return "windows-"+id;}finally{Ole32.INSTANCE.CoUninitialize();}
      });Thread worker=new Thread(task,"aegis-local-boot-identity");worker.setDaemon(true);worker.start();
      try{String boot=task.get(4,TimeUnit.SECONDS);return ()->new Stamp(boot,Kernel32.INSTANCE.GetTickCount64());}catch(Exception unavailable){task.cancel(true);return ()->{throw new IOException("Boot identity unavailable");};}
    }
    return ()->{
      String boot=bounded(Path.of("/proc/sys/kernel/random/boot_id"),64).trim();if(!boot.matches("[a-f0-9-]{36}"))throw new IOException("Boot identity unavailable");
      try{String uptime=bounded(Path.of("/proc/uptime"),128).split(" ",2)[0];return new Stamp("linux-"+boot,new java.math.BigDecimal(uptime).multiply(java.math.BigDecimal.valueOf(1000)).longValueExact());}catch(ArithmeticException|NumberFormatException bad){throw new IOException("Boot uptime invalid",bad);}
    };
  }
  private static String bounded(Path p,int max)throws IOException {try(var in=Files.newInputStream(p)){byte[] b=in.readNBytes(max+1);if(b.length>max)throw new IOException("Boot value size");return new String(b,java.nio.charset.StandardCharsets.US_ASCII);}}
  enum BootProperty {LASTBOOTUPTIME}
}
