package org.securemail.client.storage;

import static org.junit.jupiter.api.Assertions.*;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Random;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.Identity;
import org.securemail.protocol.UserInfo;

/** Real encrypted-file boundaries; no Relay or Tor acceptance is implied. */
class AvatarPublication250Test {
  @TempDir Path root;
  private static final char[] PASSWORD="avatar-publication-250-password".toCharArray();
  private LocalStore open(Path folder,long quota)throws Exception {
    LocalStore local=new LocalStore(folder,PASSWORD,Clock.systemUTC(),1_000_000,quota);
    local.bindNickname("alice");return local;
  }
  private static byte[] avatar(int color,boolean noise)throws Exception {
    BufferedImage image=new BufferedImage(256,256,BufferedImage.TYPE_INT_RGB);Random random=new Random(250);
    try{for(int y=0;y<256;y++)for(int x=0;x<256;x++)image.setRGB(x,y,noise?random.nextInt():color);ByteArrayOutputStream out=new ByteArrayOutputStream();assertTrue(ImageIO.write(image,"png",out));return AvatarCodec.normalize(out.toByteArray());}finally{image.flush();}
  }
  private static void color(byte[] png,int expected)throws Exception {
    BufferedImage decoded=ImageIO.read(new ByteArrayInputStream(png));assertNotNull(decoded);
    try{assertEquals(expected|0xff000000,decoded.getRGB(128,128));}finally{decoded.flush();}
  }

  @Test void crashAfterAvatarCommitBeforeFeaturesDirtyWriteRetainsPendingAcrossRestart()throws Exception {
    Path folder=root.resolve("profile");String token;
    try(LocalStore local=open(folder,2_000_000)){
      LocalFeatures features=new LocalFeatures(local);features.profilePublished();assertFalse(features.profilePending());
      local.avatar("alice",avatar(0x335577,false)); // Deliberately do not call features.profileChanged().
      token=local.avatarPublicationToken();assertFalse(token.isEmpty());assertTrue(features.profilePending());
      byte[] marker=Files.readAllBytes(folder.resolve("own-avatar-publication-v1.vault"));
      assertFalse(new String(marker,StandardCharsets.ISO_8859_1).contains(token));
    }
    try(LocalStore local=open(folder,2_000_000)){
      LocalFeatures features=new LocalFeatures(local);assertTrue(features.profilePending());assertEquals(token,local.avatarPublicationToken());color(local.avatar("alice"),0x335577);
      features.profilePublished(features.profileState());assertFalse(features.profilePending());assertFalse(Files.exists(folder.resolve("own-avatar-publication-v1.vault")));
    }
    try(LocalStore local=open(folder,2_000_000)){assertFalse(new LocalFeatures(local).profilePending());}
  }

  @Test void acknowledgementOfOlderPixelsCannotConsumeANewerAvatarEdit()throws Exception {
    try(LocalStore local=open(root.resolve("profile"),2_000_000)){
      LocalFeatures features=new LocalFeatures(local);features.profilePublished();local.avatar("alice",avatar(0x335577,false));
      var sent=features.profileState();local.avatar("alice",avatar(0xaa4422,false));String current=local.avatarPublicationToken();
      assertNotEquals(sent.avatarToken(),current);features.profilePublished(sent);assertTrue(features.profilePending());assertEquals(current,local.avatarPublicationToken());color(local.avatar("alice"),0xaa4422);
      features.profilePublished(features.profileState());assertFalse(features.profilePending());
    }
  }

  @Test void deletionAndUnreadablePublicationMarkerRecoverConservatively()throws Exception {
    Path folder=root.resolve("profile");
    try(LocalStore local=open(folder,2_000_000)){
      LocalFeatures features=new LocalFeatures(local);local.avatar("alice",avatar(0x335577,false));features.profilePublished(features.profileState());
      local.avatar("alice",null);assertNull(local.avatar("alice"));
    }
    // A damaged small journal must request republishing, rather than prevent vault access or drop deletion.
    Files.write(folder.resolve("own-avatar-publication-v1.vault"),new byte[]{1,2,3});
    try(LocalStore local=open(folder,2_000_000)){
      LocalFeatures features=new LocalFeatures(local);assertTrue(features.profilePending());assertNull(local.avatar("alice"));features.profilePublished(features.profileState());assertFalse(features.profilePending());
    }
  }

  @Test void rekeyKeepsPendingAvatarAndTheOriginalIdentity()throws Exception {
    Path folder=root.resolve("profile"),target=root.resolve("rekeyed");String userId,token;
    try(LocalStore local=open(folder,2_000_000)){
      LocalFeatures features=new LocalFeatures(local);features.profilePublished();local.avatar("alice",avatar(0x335577,false));userId=local.identity().userId();token=local.avatarPublicationToken();local.rekeyCopy(target,PASSWORD);
    }
    try(LocalStore local=open(target,2_000_000)){
      assertEquals(userId,local.identity().userId());assertEquals(token,local.avatarPublicationToken());assertTrue(new LocalFeatures(local).profilePending());color(local.avatar("alice"),0x335577);
    }
  }

  @Test void aggregateAvatarAndProfileQuotaRejectsGrowthWithoutReplacingVerifiedContent()throws Exception {
    Path folder=root.resolve("profile");Identity bob=Identity.create();byte[] first=avatar(0x335577,false);long quota;
    try(LocalStore local=open(folder,2_000_000)){
      local.avatar("alice",first);local.trust(new UserInfo(bob.userId(),"bob",bob.publicKey(),null));local.cacheProfile(bob.profile("bob",1,true,"before",first));
      try(var files=Files.list(folder.resolve("avatars"))){quota=Files.size(files.findFirst().orElseThrow())+Files.size(folder.resolve("profiles").resolve(bob.userId()+".enc"))+10;}
    }
    try(LocalStore local=open(folder,quota)){
      String token=local.avatarPublicationToken();assertThrows(java.io.IOException.class,()->local.cacheProfile(bob.profile("bob",2,true,"x".repeat(300),first)));
      assertEquals(1,local.cachedProfile("bob").revision());assertEquals("before",local.cachedProfile("bob").about());
      assertThrows(java.io.IOException.class,()->local.avatar("alice",avatar(0,true)));assertEquals(token,local.avatarPublicationToken());color(local.avatar("alice"),0x335577);color(local.avatar("bob"),0x335577);
    }
  }

  @Test void removingContactDeletesItsProfileAndStartupPrunesLegacyOrphansOnly()throws Exception {
    Path folder=root.resolve("profile");Identity bob=Identity.create();byte[] stale;Path remote=folder.resolve("profiles").resolve(bob.userId()+".enc");String own;
    try(LocalStore local=open(folder,2_000_000)){
      own=local.identity().userId();local.cacheProfile(local.identity().profile("alice",1,true,"own",new byte[0]));
      local.trust(new UserInfo(bob.userId(),"bob",bob.publicKey(),null));local.cacheProfile(bob.profile("bob",1,true,"former contact",avatar(0x335577,false)));stale=Files.readAllBytes(remote);
      local.removeContact("bob");assertFalse(Files.exists(remote));assertNotNull(local.cachedProfile("alice"));
    }
    Files.write(remote,stale); // Simulate a cache orphan left by the old client or a crash after contact removal.
    try(LocalStore local=open(folder,2_000_000)){
      assertFalse(Files.exists(remote));assertTrue(Files.exists(folder.resolve("profiles").resolve(own+".enc")));assertNull(local.contact("bob"));assertEquals("own",local.cachedProfile("alice").about());
    }
  }
}
