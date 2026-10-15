package org.securemail.relay;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class IsolationTest {
  @Test
  void relayRuntimeHasNoClientOrMessageCrypto() {
    for (String name :
        new String[] {
          "org.securemail.client.crypto.EncryptionService",
          "org.bouncycastle.crypto.engines.AESEngine",
          "com.google.crypto.tink.subtle.XChaCha20Poly1305"
        }) assertThrows(ClassNotFoundException.class, () -> Class.forName(name));
  }
}
