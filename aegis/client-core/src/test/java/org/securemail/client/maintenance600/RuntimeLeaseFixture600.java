package org.securemail.client.maintenance600;
import java.io.*;
import java.nio.file.*;
/** Actual separate-JVM lock fixture, never a replacement for native installer acceptance. */
public final class RuntimeLeaseFixture600 {
  public static void main(String[] args)throws Exception{
    try(var lease=RuntimeLease600.acquire(Path.of(args[0]),args[1].equals("shared"))){System.out.println("HELD");System.out.flush();System.in.read();}
    catch(IOException busy){System.out.println("BLOCKED");System.out.flush();System.exit(3);}
  }
}
