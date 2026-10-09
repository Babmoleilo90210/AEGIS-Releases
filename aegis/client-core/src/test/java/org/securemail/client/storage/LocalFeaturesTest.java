package org.securemail.client.storage;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.protocol.*;

class LocalFeaturesTest {
  @TempDir Path root;
  @Test void mutualConsentRequiresBothPinnedSignaturesAndRevocationDoesNotRemoveContact()throws Exception{
    var peer=Identity.create();try(var local=new LocalStore(root,"feature-vault-password".toCharArray(),Clock.systemUTC(),100000,1000000)){
      local.bindNickname("raven");var user=new UserInfo(peer.userId(),"blackfox",peer.publicKey(),null);local.trust(user);var state=new LocalFeatures(local);
      long now=local.now();var ours=local.identity().consent(peer.userId(),now,true);var theirs=peer.consent(local.identity().userId(),now,true);
      state.friendship(user,ours,null);assertFalse(state.friend(peer.userId()));state.friendship(user,ours,theirs);assertTrue(state.friend(peer.userId()));
      var wrong=new ContactAssertion(theirs.ownerId(),theirs.targetId(),now+1,true,theirs.publicKey(),new byte[64]);assertThrows(java.security.GeneralSecurityException.class,()->state.friendship(user,ours,wrong));
      state.consent(peer.userId(),false);assertFalse(state.friend(peer.userId()));assertNotNull(local.contact("blackfox"));
      state.friendship(user,ours,theirs);assertFalse(state.friend(peer.userId()));
      assertThrows(java.security.GeneralSecurityException.class,()->state.friendship(user,ours,peer.consent(local.identity().userId(),now-1,true)));
    }
  }
  @Test void featureSidecarIsEncryptedSurvivesRekeyAndCannotAssignRemoteAvatar()throws Exception{
    String marker="PRIVATE-PROFILE-ABOUT-DO-NOT-PERSIST-PLAINTEXT";var peer=Identity.create();String id=java.util.UUID.randomUUID().toString();Path next=root.resolveSibling(root.getFileName()+"-rekey");
    try(var local=new LocalStore(root,"feature-vault-password".toCharArray(),Clock.systemUTC(),100000,1000000)){
      local.bindNickname("raven");local.trust(new UserInfo(peer.userId(),"blackfox",peer.publicKey(),null));var state=new LocalFeatures(local);
      state.profile(marker,false);state.blockMail(id,true);state.pin("pinnedMail",id,true);
      assertFalse(new String(Files.readAllBytes(root.resolve("features-v1.vault")),StandardCharsets.ISO_8859_1).contains(marker));
      var profile=peer.profile("blackfox",local.now(),false,"",new byte[0]);local.cacheProfile(profile);assertEquals(peer.userId(),local.cachedProfile("blackfox").userId());
      var stranger=Identity.create();assertThrows(java.security.GeneralSecurityException.class,()->local.cacheProfile(stranger.profile("blackfox",local.now()+1,false,"",new byte[0])));
      assertThrows(java.io.IOException.class,()->local.avatar("blackfox",new byte[]{1,2,3}));local.rekeyCopy(next,"new-feature-password".toCharArray());
    }
    try(var local=new LocalStore(next,"new-feature-password".toCharArray(),Clock.systemUTC(),100000,1000000)){
      var state=new LocalFeatures(local);assertEquals(marker,state.about());assertTrue(state.pinned("pinnedMail",id));assertEquals(peer.userId(),local.cachedProfile("blackfox").userId());
      state.purgeExpired(java.util.Set.of());assertFalse(state.pinned("pinnedMail",id));
    }
  }
}
