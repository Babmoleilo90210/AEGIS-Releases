package org.securemail.ui.ecosystem;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import org.securemail.client.ecosystem.*;

/** Test-only separate JVM; never enters a production JAR. Identity validation is a local fixture, not a server proof. */
public final class ComponentEntrypoint {
  private ComponentEntrypoint() {}
  public static void main(String[] args) throws Exception {
    ComponentId component=ComponentId.valueOf(args[0]);
    try(var connection=LocalIpc.connectChild(System.in,component,lease->{if(!new String(lease.capability(),StandardCharsets.UTF_8).startsWith("fixture|"))throw new java.io.IOException("fixture invalid capability");})) {
      String[] config=new String(connection.lease().capability(),StandardCharsets.UTF_8).split("\\|",3);
      if(config[1].equals("no-ready")){Path receipt=Path.of(config[2]+".started");try(var file=java.nio.channels.FileChannel.open(receipt,StandardOpenOption.CREATE,StandardOpenOption.WRITE);var held=file.lock()){file.write(java.nio.ByteBuffer.wrap("owned-child-started".getBytes(StandardCharsets.US_ASCII)));file.force(true);Thread.sleep(30000);}return;}
      if(config[1].equals("crash")){connection.channel().send(LocalIpc.Packet.command(LocalIpc.Type.READY));return;}
      if(config[1].equals("silent")){connection.channel().send(LocalIpc.Packet.command(LocalIpc.Type.READY));Thread.sleep(30000);return;}
      Path queue=Path.of(config[2]);
      try(var runtime=new ComponentRuntime(connection,new ComponentRuntime.Callbacks(){
        public void lockProtectedData() throws Exception {Files.writeString(queue.resolveSibling(queue.getFileName()+".locked"),"locked");}
        public void persistQueuesAndStop() throws Exception {Files.writeString(queue,"flushed");}
        public void limitedIncomingCall(boolean accept)throws Exception{Files.writeString(queue.resolveSibling(queue.getFileName()+".call"),accept?"accepted":"rejected");}
      })) {runtime.notifications(101);runtime.run();}
    }
  }
}
