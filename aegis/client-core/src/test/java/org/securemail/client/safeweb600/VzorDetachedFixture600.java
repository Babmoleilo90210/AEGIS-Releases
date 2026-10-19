package org.securemail.client.safeweb600;

import java.nio.file.*;
import java.time.Duration;
import java.util.*;

/** Real separate-JVM lifecycle fixture; deliberately no Tor/browser/audio/network implementation. */
public final class VzorDetachedFixture600 {
  private VzorDetachedFixture600(){}
  public static void main(String[] args)throws Exception{
    switch(args[0]){
      case "manager"->{
        try(var bootstrap=VzorBootstrap600.read(System.in,Duration.ofSeconds(3))){
          VzorState600 state;
          try{state=VzorState600.open(Path.of(args[1]),Path.of(args[1]+"-browser"));}
          catch(VzorFailure600 busy){bootstrap.acknowledge(System.out,VzorBootstrap600.Reply.ALREADY_RUNNING);return;}
          try(state){Files.writeString(Path.of(args[2]+"-trace"),"beforeACK\n");bootstrap.acknowledge(System.out,VzorBootstrap600.Reply.READY);Files.writeString(Path.of(args[2]+"-trace"),"afterACK\n",StandardOpenOption.APPEND);await(Path.of(args[2]));Files.writeString(Path.of(args[2]+"-trace"),"afterAwait\n",StandardOpenOption.APPEND);}
          Files.writeString(Path.of(args[2]+"-released"),"released");
        }
      }
      case "core"->{
        List<String> command=List.of(java(),"-cp",args[1],VzorDetachedFixture600.class.getName(),"manager",args[2],args[3]);
        var detached=VzorLaunch600.launch(command,"https://example.org/",Duration.ofSeconds(5),true);
        Files.writeString(Path.of(args[4]),Long.toString(detached.managerPid()));
        // Returning exits this JVM. No hold-open pipe or root/account session survives.
      }
      case "stalled"->{Files.writeString(Path.of(args[1]),Long.toString(ProcessHandle.current().pid()));Thread.sleep(30_000);}
      case "unrelated"->{Files.writeString(Path.of(args[2]),Long.toString(ProcessHandle.current().pid()));await(Path.of(args[1]));}
      case "bad-ack"->{try(var bootstrap=VzorBootstrap600.read(System.in,Duration.ofSeconds(3))){System.out.write(new byte[46]);System.out.flush();Thread.sleep(30_000);}}
      default->throw new IllegalArgumentException("Fixture mode");
    }
  }
  private static void await(Path marker)throws Exception{long end=System.nanoTime()+Duration.ofSeconds(30).toNanos();while(!Files.exists(marker)&&System.nanoTime()<end)Thread.sleep(20);}
  private static String java(){return Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java").toString();}
}
