package org.securemail.ui;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import org.securemail.client.AppPaths;
import org.securemail.client.ecosystem.*;

/** JDK-only smoke fixture, deliberately excluded from production and regular smoke source sets.
 * No Mail GUI, account vault, root key, Tor or audio is simulated as accepted here. */
public final class MailPairingEntrypoint600 {
  private MailPairingEntrypoint600(){}
  public static void main(String[] args)throws Exception {
    Path home=AppPaths.root().resolve("core600/smoke-consent");Files.createDirectories(home);
    try(var connection=LocalIpc.connectChild(System.in,ComponentId.MAIL,lease->{
      if(!lease.accountId().equals(MailPairing600.PURPOSE_REGISTER)||lease.generation()!=1||!(MailPairing600.decodeRequest(lease.capability()) instanceof MailPairing600.RegistrationRequest))throw new IOException("Only public registration consent is accepted by this smoke fixture");
    });var lockFile=FileChannel.open(home.resolve("started.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);var lock=lockFile.lock()){
      connection.channel().send(LocalIpc.Packet.command(LocalIpc.Type.READY));Files.writeString(home.resolve("ready"),"MAC-authenticated public registration request");
      while(true){var packet=connection.channel().receive();switch(packet.type()){
        case HEARTBEAT -> {connection.channel().send(LocalIpc.Packet.command(LocalIpc.Type.PONG));Files.writeString(home.resolve("heartbeat"),"Authenticated HEARTBEAT/PONG");}
        case SHUTDOWN -> {Files.writeString(home.resolve("shutdown"),"Authenticated SHUTDOWN");Thread.sleep(1200);return;}
        default -> throw new IOException("Unexpected fixture command");
      }}
    }
  }
}
