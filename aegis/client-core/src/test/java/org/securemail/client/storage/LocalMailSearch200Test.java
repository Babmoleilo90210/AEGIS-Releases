package org.securemail.client.storage;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;
import org.securemail.protocol.*;

/** Real encrypted local packets, never an index containing persisted plaintext. */
class LocalMailSearch200Test {
  @TempDir Path root;
  private static LocalMailSearch.Query query(String sender,String subject,LocalMailSearch.Scope scope,String text,LocalMailSearch.Kind kind){return new LocalMailSearch.Query(sender,subject,0,Long.MAX_VALUE,scope,text,kind);}
  @Test void bodySubjectSenderDirectionAndProtectionFiltersUseRealPackets()throws Exception{
    var peer=Identity.create();var crypto=new AutomaticEncryption(Clock.systemUTC());
    try(var local=new LocalStore(root,"search 200 vault password".toCharArray(),Clock.systemUTC(),300000,3000000)){
      local.bindNickname("blackfox");var other=new UserInfo(peer.userId(),"raven",peer.publicKey(),null);local.trust(other);var self=new UserInfo(local.identity().userId(),"blackfox",local.identity().publicKey(),null);
      String normalId,protectedId,sentId;
      try(var plain=PlainMessage.rich("Тема для поиска","Обычный текст содержит НУЖНЫЙМАРКЕР",new byte[0],List.of(),100000,null)){var packet=crypto.encrypt(plain,300,3600000,peer,"raven",self);normalId=packet.messageId();local.accept(packet);}
      byte[] envelope=LetterEnvelope.seal("СЕКРЕТНЫЙМАРКЕР", "new letter password 200".toCharArray(),"f3f4f5".toCharArray());
      try(var plain=PlainMessage.letter("Публичная метаинформация",envelope,null,100000)){var packet=crypto.encrypt(plain,300,3600000,peer,"raven",self);protectedId=packet.messageId();local.accept(packet);}finally{Arrays.fill(envelope,(byte)0);}
      try(var plain=PlainMessage.rich("Отчёт","Исходящий текст",new byte[0],List.of(),100000,null)){var packet=crypto.encrypt(plain,300,3600000,local.identity(),"blackfox",other);sentId=packet.messageId();local.saveSent(packet,"raven",local.now());}
      var features=new LocalFeatures(local);
      var ordinary=LocalMailSearch.find(local,features,query("","",LocalMailSearch.Scope.ALL,"нужныймаркер",LocalMailSearch.Kind.ALL),100000);
      assertEquals(List.of(normalId),ordinary.stream().map(r->r.item().id()).toList());assertTrue(ordinary.getFirst().snippet().contains("НУЖНЫЙМАРКЕР"));
      assertTrue(LocalMailSearch.find(local,features,query("","",LocalMailSearch.Scope.ALL,"секретныймаркер",LocalMailSearch.Kind.ALL),100000).isEmpty());
      var protectedRows=LocalMailSearch.find(local,features,query("","метаинформация",LocalMailSearch.Scope.INBOX,"",LocalMailSearch.Kind.PROTECTED),100000);
      assertEquals(List.of(protectedId),protectedRows.stream().map(r->r.item().id()).toList());assertEquals("",protectedRows.getFirst().snippet());
      var sent=LocalMailSearch.find(local,features,query("BLACKFOX","",LocalMailSearch.Scope.SENT,"",LocalMailSearch.Kind.ORDINARY),100000);assertEquals(List.of(sentId),sent.stream().map(r->r.item().id()).toList());
      assertTrue(LocalMailSearch.find(local,features,query("raven","",LocalMailSearch.Scope.SENT,"",LocalMailSearch.Kind.ALL),100000).isEmpty());
      assertEquals(2,LocalMailSearch.find(local,features,query("RAVEN","",LocalMailSearch.Scope.INBOX,"",LocalMailSearch.Kind.ALL),100000).size());
      var dated=new LocalMailSearch.Query("","",local.now()+60000,Long.MAX_VALUE,LocalMailSearch.Scope.ALL,"",LocalMailSearch.Kind.ALL);assertTrue(LocalMailSearch.find(local,features,dated,100000).isEmpty());
      // Running the search must not create any plaintext search index or files.
      try(var files=Files.walk(root)){for(Path file:files.filter(Files::isRegularFile).toList()){String stored=new String(Files.readAllBytes(file),StandardCharsets.UTF_8);assertFalse(stored.contains("НУЖНЫЙМАРКЕР"));assertFalse(stored.contains("СЕКРЕТНЫЙМАРКЕР"));}}
    }
  }
  @Test void queryRejectsNullFieldsAndInvalidDateRange(){
    assertThrows(IllegalArgumentException.class,()->query(null,"",LocalMailSearch.Scope.ALL,"",LocalMailSearch.Kind.ALL));
    assertThrows(IllegalArgumentException.class,()->query("",null,LocalMailSearch.Scope.ALL,"",LocalMailSearch.Kind.ALL));
    assertThrows(IllegalArgumentException.class,()->new LocalMailSearch.Query("","",100,99,LocalMailSearch.Scope.ALL));
  }
  @Test void publicationCompletingAfterAnEditCannotLoseThePendingEdit()throws Exception{
    try(var local=new LocalStore(root,"profile generation password".toCharArray(),Clock.systemUTC(),100000,1000000)){
      local.bindNickname("blackfox");var state=new LocalFeatures(local);assertTrue(state.visible());
      var first=state.profileState();state.profile("Новая версия",false);state.profilePublished(first.generation());assertTrue(state.profilePending());assertFalse(state.visible());
      var next=state.profileState();state.profilePublished(next.generation());assertFalse(state.profilePending());state.profileChanged();state.profilePublished(next.generation());assertTrue(state.profilePending());
      var reopened=new LocalFeatures(local);assertTrue(reopened.profilePending());assertEquals("Новая версия",reopened.about());assertFalse(reopened.visible());
    }
  }
}
