package org.securemail.client.ecosystem;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

class LocalIpcTest {
  private static ComponentLease lease(){return new ComponentLease(ComponentId.MAIL,"account-identity",9,new byte[]{1,2,3});}
  @Test void authenticatedWireRejectsAnExactPacketReplay()throws Exception {
    try(ServerSocket server=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"));var boot=new LocalIpc.Bootstrap(lease(),server.getLocalPort());var pool=Executors.newSingleThreadExecutor()) {
      Future<LocalIpc.Channel> accepted=pool.submit(()->LocalIpc.acceptParent(server.accept(),boot,1234));
      try(Socket attacker=new Socket("127.0.0.1",server.getLocalPort())) {
        DataOutputStream out=new DataOutputStream(attacker.getOutputStream());DataInputStream in=new DataInputStream(attacker.getInputStream());
        byte[] child=LocalIpc.random(32);out.writeInt(0x49504336);out.writeLong(1234);out.write(child);out.write(LocalIpc.hmac(boot.secret,LocalIpc.combine(boot.binding(),LocalIpc.longBytes(1234),child)));out.flush();
        byte[] parent=in.readNBytes(32);assertEquals(32,in.readNBytes(32).length);
        byte[] master=LocalIpc.hmac(boot.secret,LocalIpc.combine("channel".getBytes(StandardCharsets.US_ASCII),boot.binding(),child,parent));
        byte[] readKey=LocalIpc.hmac(master,"child-to-parent".getBytes(StandardCharsets.US_ASCII));
        var body=new ByteArrayOutputStream();var frame=new DataOutputStream(body);frame.writeLong(1);frame.writeByte(LocalIpc.Type.NOTIFICATION_COUNT.ordinal());frame.writeInt(4);frame.writeInt(3);byte[] bytes=body.toByteArray();
        byte[] mac=LocalIpc.hmac(readKey,bytes);out.writeInt(bytes.length+32);out.write(bytes);out.write(mac);out.flush();
        try(var channel=accepted.get(3,TimeUnit.SECONDS)) {
          assertEquals(3,java.nio.ByteBuffer.wrap(channel.receive().payload()).getInt());
          out.writeInt(bytes.length+32);out.write(bytes);out.write(mac);out.flush();assertThrows(IOException.class,channel::receive);
        }
      }
    }
  }
  @Test void forgedProofAndWrongPidAreRejectedBeforeReady()throws Exception {
    for(boolean wrongPid:List.of(false,true))try(ServerSocket server=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"));var boot=new LocalIpc.Bootstrap(lease(),server.getLocalPort());var pool=Executors.newSingleThreadExecutor()) {
      Future<LocalIpc.Channel> accepted=pool.submit(()->LocalIpc.acceptParent(server.accept(),boot,1234));
      try(Socket attacker=new Socket("127.0.0.1",server.getLocalPort())) {
        var out=new DataOutputStream(attacker.getOutputStream());byte[] random=LocalIpc.random(32);long pid=wrongPid?1235:1234;
        out.writeInt(0x49504336);out.writeLong(pid);out.write(random);out.write(wrongPid?LocalIpc.hmac(boot.secret,LocalIpc.combine(boot.binding(),LocalIpc.longBytes(pid),random)):new byte[32]);out.flush();
        assertThrows(ExecutionException.class,()->accepted.get(3,TimeUnit.SECONDS));
      }
    }
  }
  @Test void expiredOrAlreadyConsumedLaunchTicketCannotAuthenticateAnotherSocket()throws Exception {
    try(ServerSocket server=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"));
        var expired=new LocalIpc.Bootstrap(lease(),server.getLocalPort(),LocalIpc.random(32),LocalIpc.random(32),System.nanoTime()-TimeUnit.SECONDS.toNanos(11));
        var pool=Executors.newSingleThreadExecutor()) {
      Future<?> rejected=pool.submit(()->LocalIpc.acceptParent(server.accept(),expired,1234));
      try(Socket socket=new Socket("127.0.0.1",server.getLocalPort())){assertThrows(ExecutionException.class,()->rejected.get(1,TimeUnit.SECONDS));}
      try(var consumed=new LocalIpc.Bootstrap(lease(),server.getLocalPort())) {
        consumed.claimed.set(true);Future<?> replay=pool.submit(()->LocalIpc.acceptParent(server.accept(),consumed,1234));
        try(Socket socket=new Socket("127.0.0.1",server.getLocalPort())){assertThrows(ExecutionException.class,()->replay.get(1,TimeUnit.SECONDS));}
      }
    }
  }
  @Test void childMustIndependentlyAcceptIdentityCapabilityBeforeConnecting()throws Exception {
    try(ServerSocket server=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"));var boot=new LocalIpc.Bootstrap(lease(),server.getLocalPort())) {
      var bytes=new ByteArrayOutputStream();boot.write(bytes);
      assertThrows(IOException.class,()->LocalIpc.connectChild(new ByteArrayInputStream(bytes.toByteArray()),ComponentId.MAIL,l->{throw new IOException("wrong server signature");}));
      server.setSoTimeout(100);assertThrows(SocketTimeoutException.class,server::accept);
    }
  }
  @Test void bootstrapRejectsWrongComponentAndMalformedLengths()throws Exception {
    try(ServerSocket server=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"));var boot=new LocalIpc.Bootstrap(lease(),server.getLocalPort())) {
      var bytes=new ByteArrayOutputStream();boot.write(bytes);assertThrows(IOException.class,()->LocalIpc.connectChild(new ByteArrayInputStream(bytes.toByteArray()),ComponentId.GLAS,l->{}));
      byte[] truncated=Arrays.copyOf(bytes.toByteArray(),10);assertThrows(IOException.class,()->LocalIpc.connectChild(new ByteArrayInputStream(truncated),ComponentId.MAIL,l->{}));
    }
  }
  @Test void packetSchemaNeverAcceptsArbitraryCommandsOrStringPayloads() {
    assertThrows(IllegalArgumentException.class,()->new LocalIpc.Packet(LocalIpc.Type.LOCK,"rm -rf".getBytes(StandardCharsets.UTF_8)));
    assertThrows(IllegalArgumentException.class,()->LocalIpc.Packet.count(-1));
    assertThrows(IllegalArgumentException.class,()->new LocalIpc.Packet(LocalIpc.Type.NOTIFICATION_COUNT,new byte[8193]));
    ComponentLease narrow=lease();assertFalse(narrow.toString().contains("account-identity"));assertFalse(narrow.toString().contains("1, 2, 3"));
    byte[] capability=narrow.capability();capability[0]=99;assertEquals(1,narrow.capability()[0]);
  }
}
