package org.securemail.client.ecosystem;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.Identity;
import org.securemail.client.storage.LocalStore;
import org.securemail.ecosystem.protocol.IdentityProtocol;

class MailSecurity600Test {
  @TempDir Path root;
  private static final char[] PASSWORD="local Mail fixture password 600".toCharArray();
  @Test void rootAccountBindingRejectsAnotherUnlockedVaultBeforeMailUse()throws Exception {
    try(var mail=new LocalStore(root.resolve("mail"),PASSWORD,Clock.systemUTC(),100000,3000000)) {
      Identity other=Identity.create();var wrong=new MailComponentGate600(new ComponentLease(ComponentId.MAIL,other.userId(),5,new byte[]{1}),lease->{});
      assertThrows(IOException.class,()->wrong.verifyUnlockedVault(mail));
      var right=new MailComponentGate600(new ComponentLease(ComponentId.MAIL,mail.identity().userId(),5,new byte[]{1}),lease->{});right.verifyUnlockedVault(mail);right.lock();assertThrows(IOException.class,()->right.verifyUnlockedVault(mail));
      assertThrows(IOException.class,()->new MailComponentGate600(new ComponentLease(ComponentId.GLAS,mail.identity().userId(),5,new byte[]{1}),lease->{}));
    }
  }
  @Test void recoveryKeyExistsOnlyInEncryptedMailStateAndVerifiedEncryptedExport()throws Exception {
    String account;byte[] recoveryPublic;
    try(var mail=new LocalStore(root.resolve("mail"),PASSWORD,Clock.systemUTC(),100000,3000000);var recovery=MailRecoveryKey600.loadOrCreate(mail)) {
      account=mail.identity().userId();recoveryPublic=recovery.publicKey();assertNotEquals(account,IdentityProtocol.id(recoveryPublic));
      byte[] stored=Files.readAllBytes(root.resolve("mail/lifecycle/identity6-recovery-root-v1.enc"));assertFalse(contains(stored,recoveryPublic));
      Path exported=root.resolve("offline.aer6");char[] exportPass="separate encrypted recovery fixture".toCharArray();recovery.exportEncrypted(exported,exportPass,account);
      try(var imported=MailRecoveryKey600.importEncrypted(exported,exportPass,account)) {
        assertArrayEquals(recoveryPublic,imported.publicKey());KeyPair server=KeyPairGenerator.getInstance("Ed25519").generateKeyPair(),device=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();String audience=IdentityProtocol.id(server.getPublic().getEncoded()),challenge=IdentityProtocol.nonce();long expires=System.currentTimeMillis()+60000;
        byte[] approval=imported.approveRecovery(audience,account,challenge,device.getPublic().getEncoded(),expires);assertTrue(IdentityProtocol.verify(recoveryPublic,IdentityProtocol.recovery(audience,account,challenge,device.getPublic().getEncoded(),expires),approval));assertFalse(IdentityProtocol.verify(recoveryPublic,"arbitrary sign request".getBytes(java.nio.charset.StandardCharsets.UTF_8),approval));
      }
      assertThrows(GeneralSecurityException.class,()->MailRecoveryKey600.importEncrypted(exported,"wrong recovery export password".toCharArray(),account));
      assertThrows(IOException.class,()->MailRecoveryKey600.importEncrypted(exported,exportPass,Identity.create().userId()));
      byte[] damaged=Files.readAllBytes(exported);damaged[damaged.length-1]^=1;Files.write(exported,damaged);assertThrows(GeneralSecurityException.class,()->MailRecoveryKey600.importEncrypted(exported,exportPass,account));
    }
    try(var mail=new LocalStore(root.resolve("mail"),PASSWORD,Clock.systemUTC(),100000,3000000);var recovery=MailRecoveryKey600.loadOrCreate(mail)){assertArrayEquals(recoveryPublic,recovery.publicKey());assertEquals(account,mail.identity().userId());}
  }
  @Test void unreadDeduplicationAndRecoverySurviveRealVaultRekeyWithoutSharingMailKey()throws Exception {
    String one=UUID.randomUUID().toString(),two=UUID.randomUUID().toString();byte[] recoveryPublic;String account;char[] next="replacement Mail vault fixture 600".toCharArray();Path migrated=root.resolve("rekeyed");
    try(var mail=new LocalStore(root.resolve("mail"),PASSWORD,Clock.systemUTC(),100000,3000000);var recovery=MailRecoveryKey600.loadOrCreate(mail)) {
      account=mail.identity().userId();recoveryPublic=recovery.publicKey();var unread=new MailNotificationCounter600(mail);assertEquals(0,unread.count());assertEquals(2,unread.add(List.of(one,one,two)));assertEquals(1,unread.read(one));assertEquals(1,unread.read(one));mail.rekeyCopy(migrated,next);
    }
    try(var mail=new LocalStore(migrated,next,Clock.systemUTC(),100000,3000000);var recovery=MailRecoveryKey600.loadOrCreate(mail)){assertEquals(account,mail.identity().userId());assertArrayEquals(recoveryPublic,recovery.publicKey());var unread=new MailNotificationCounter600(mail);assertEquals(1,unread.count());assertEquals(0,unread.read(two));assertThrows(IllegalArgumentException.class,()->unread.add(List.of("../../bad")));}
  }
  @Test void pairingProtocolHasOnlyTypedRegistrationAndStepUpDomains()throws Exception {
    KeyPair rootKey=KeyPairGenerator.getInstance("Ed25519").generateKeyPair(),device=KeyPairGenerator.getInstance("Ed25519").generateKeyPair(),recovery=KeyPairGenerator.getInstance("Ed25519").generateKeyPair(),service=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var request=new MailPairing600.RegistrationRequest(device.getPublic().getEncoded());var decoded=(MailPairing600.RegistrationRequest)MailPairing600.decodeRequest(MailPairing600.requestBytes(request));assertArrayEquals(device.getPublic().getEncoded(),decoded.devicePublic());
    long now=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();byte[] typed=IdentityProtocol.registration(IdentityProtocol.id(service.getPublic().getEncoded()),rootKey.getPublic().getEncoded(),device.getPublic().getEncoded(),recovery.getPublic().getEncoded(),"raven",now,nonce);
    var result=new MailPairing600.RegistrationResult(rootKey.getPublic().getEncoded(),recovery.getPublic().getEncoded(),"raven",now,nonce,IdentityProtocol.sign(rootKey.getPrivate(),typed));byte[] encoded=MailPairing600.registrationResult(result);var roundtrip=MailPairing600.decodeRegistrationResult(encoded);assertTrue(IdentityProtocol.verify(roundtrip.accountPublic(),typed,roundtrip.accountProof()));
    assertThrows(IOException.class,()->MailPairing600.decodeStepUpResult(encoded));byte[] trailing=Arrays.copyOf(encoded,encoded.length+1);assertThrows(IOException.class,()->MailPairing600.decodeRegistrationResult(trailing));assertThrows(IOException.class,()->MailPairing600.decodeRequest("SIGN-ANYTHING".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    assertThrows(IllegalArgumentException.class,()->new MailPairing600.RegistrationResult(rootKey.getPublic().getEncoded(),rootKey.getPublic().getEncoded(),"raven",now,nonce,new byte[64]));
  }
  @Test void applicationProofSecretHasDefensiveCopiesAndIsWipedAtClose()throws Exception {
    KeyPair app=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();byte[] privateKey=app.getPrivate().getEncoded();var lease=new ComponentLease(ComponentId.MAIL,"bound-account",1,new byte[]{1},privateKey,app.getPublic().getEncoded());byte[] exposed=lease.proofPrivatePkcs8();exposed[0]^=1;assertArrayEquals(privateKey,lease.proofPrivatePkcs8());lease.close();assertArrayEquals(new byte[privateKey.length],lease.proofPrivatePkcs8());assertArrayEquals(privateKey,app.getPrivate().getEncoded());
  }
  private static boolean contains(byte[] source,byte[] value){outer:for(int i=0;i<=source.length-value.length;i++){for(int j=0;j<value.length;j++)if(source[i+j]!=value[j])continue outer;return true;}return false;}
}
