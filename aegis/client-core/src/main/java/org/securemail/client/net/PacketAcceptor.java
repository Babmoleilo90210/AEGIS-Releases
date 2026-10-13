package org.securemail.client.net;
import java.io.IOException;
import java.security.GeneralSecurityException;
import org.securemail.protocol.EncryptedPacket;
import org.securemail.protocol.Receipt;
/** ACK is returned only after the encrypted packet and required local state are durable. */
@FunctionalInterface
public interface PacketAcceptor {
  Receipt accept(EncryptedPacket packet) throws IOException, GeneralSecurityException;
}
