package org.securemail.client.voice;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;
import org.securemail.client.storage.LocalStore;
import org.securemail.client.storage.LocalFeatures;
import org.securemail.protocol.UserInfo;

/** Narrow voice state. A standalone Glas implementation never exposes or imports a Mail identity private key. */
public interface VoiceLocalStore600 {
  byte[] accountPublic();
  default String accountId(){return org.securemail.client.crypto.Identity.id(accountPublic());}
  long now();
  UserInfo contact(String nickname);
  List<UserInfo> contacts();
  boolean blocked(String accountId);
  byte[] readVoiceState() throws IOException,GeneralSecurityException;
  void writeVoiceState(byte[] state) throws IOException,GeneralSecurityException;
  VoiceTls.Pending createTls(UUID callId,VoiceTls.Role role,byte[] pinnedPeer) throws IOException,GeneralSecurityException;
  default String identityAudience(){return null;}
  default boolean sessionAuthorized(UserInfo contact){return true;}
  default void verifyRemote(VoiceTls.Offer offer,byte[] peer,UUID callId,VoiceTls.Role role)throws IOException,GeneralSecurityException {
    offer.verify(peer,accountPublic(),callId,role,now(),identityAudience());
  }
  static VoiceLocalStore600 legacy(LocalStore store,LocalFeatures features){
    Objects.requireNonNull(store);Objects.requireNonNull(features);
    return new VoiceLocalStore600(){
      public byte[] accountPublic(){return store.identity().publicKey();}
      public long now(){return store.now();}
      public UserInfo contact(String nickname){return store.contact(nickname);}
      public List<UserInfo> contacts(){return store.contacts();}
      public boolean blocked(String account){return features.blockedSender(account);}
      public byte[] readVoiceState()throws IOException,GeneralSecurityException{return store.readVoiceState();}
      public void writeVoiceState(byte[] state)throws IOException,GeneralSecurityException{store.writeVoiceState(state);}
      public VoiceTls.Pending createTls(UUID id,VoiceTls.Role role,byte[] peer)throws IOException,GeneralSecurityException{return VoiceTls.create(store.identity(),id,role,peer);}
    };
  }
}
