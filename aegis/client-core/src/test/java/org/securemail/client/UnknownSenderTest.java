package org.securemail.client;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.client.storage.*;
import org.securemail.protocol.*;

class UnknownSenderTest {
  @TempDir Path root;
  @Test void unknownValidSenderIsDurableAndNeverAutomaticallyTrusted()throws Exception {
    var sender=Identity.create();EncryptedPacket packet;long received;
    char[] password="local-vault-password".toCharArray();
    try(var local=new LocalStore(root,password,Clock.systemUTC(),200000,1000000)){
      try(var plain=PlainMessage.text("unknown signed message")){
        packet=new AutomaticEncryption(Clock.systemUTC()).encrypt(plain,60,86400000,sender,"raven",
          new UserInfo(local.identity().userId(),"blackfox",local.identity().publicKey(),null));
      }
      received=local.accept(packet).deliveredAt();assertEquals(received,local.accept(packet).deliveredAt());
      assertEquals(1,local.inbox().size());assertNull(local.contact("raven"));
      var assessment=local.assessSender(packet);assertTrue(assessment.signatureValid());assertFalse(assessment.inContacts());assertFalse(assessment.keyMatches());
      try(var plain=new AutomaticEncryption(Clock.systemUTC()).decrypt(local.load(packet.messageId()),local.identity(),1024)){assertEquals("unknown signed message",plain.text());}
    }
    try(var local=new LocalStore(root,password,Clock.systemUTC(),200000,1000000)){
      assertEquals(received,local.accept(packet).deliveredAt());assertEquals(1,local.inbox().size());assertTrue(local.contacts().isEmpty());
    }
  }
  @Test void contactsRemainPinnedAndForeignAvatarWriteIsRejected()throws Exception {
    var known=Identity.create();var impostor=Identity.create();
    try(var local=new LocalStore(root,"vault-password-example".toCharArray(),Clock.systemUTC(),200000,1000000)){
      local.bindNickname("blackfox");local.trust(new UserInfo(known.userId(),"raven",known.publicKey(),null));
      assertThrows(java.io.IOException.class,()->local.avatar("raven",new byte[]{1,2,3}));
      try(var plain=PlainMessage.text("signature is not nickname verification")){
        var packet=new AutomaticEncryption(Clock.systemUTC()).encrypt(plain,60,86400000,impostor,"raven",
          new UserInfo(local.identity().userId(),"blackfox",local.identity().publicKey(),null));
        local.accept(packet);var assessment=local.assessSender(packet);
        assertTrue(assessment.signatureValid());assertTrue(assessment.inContacts());assertFalse(assessment.keyMatches());
        assertEquals(known.userId(),local.contact("raven").userId());
      }
    }
  }
  @Test void signedButDamagedUnknownCiphertextDoesNotSuppressOtherInboxResults()throws Exception{
    var sender=Identity.create();var crypto=new AutomaticEncryption(Clock.systemUTC());
    try(var local=new LocalStore(root,"damaged mail test password".toCharArray(),Clock.systemUTC(),200000,1000000)){
      local.bindNickname("blackfox");var recipient=new UserInfo(local.identity().userId(),"blackfox",local.identity().publicKey(),null);EncryptedPacket bad,good;
      try(var plain=PlainMessage.text("damaged content")){var p=crypto.encrypt(plain,300,60000,sender,"raven",recipient);byte[] altered=p.ciphertext();altered[altered.length-1]^=1;
        bad=sender.signPacket(new EncryptedPacket(p.messageId(),p.senderId(),p.senderNickname(),p.recipientId(),p.createdAt(),p.deliveryDeadline(),p.ttlAfterDelivery(),p.algorithm(),p.salt(),p.nonce(),altered,p.senderPublicKey(),new byte[0]));}
      try(var plain=PlainMessage.text("good content")){good=crypto.encrypt(plain,300,60000,sender,"raven",recipient);}
      local.accept(bad);local.accept(good);var found=LocalMailSearch.find(local,new LocalFeatures(local),new LocalMailSearch.Query("","",0,Long.MAX_VALUE,LocalMailSearch.Scope.INBOX),100000);
      assertEquals(2,found.size());assertTrue(found.stream().anyMatch(r->r.item().id().equals(bad.messageId())&&r.subject().equals("Повреждённое письмо")&&r.signatureValid()));assertTrue(found.stream().anyMatch(r->r.item().id().equals(good.messageId())));
    }
  }
}
