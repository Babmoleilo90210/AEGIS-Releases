package org.securemail.client;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.crypto.*;

class ReplyContentTest {
  @TempDir Path root;
  @Test void richContentRetainsReplyAndMultipleAttachmentsWhileLegacyContentStaysReadable()throws Exception{
    String parent=UUID.randomUUID().toString();var reference=new MailContext(parent,parent,"raven","Original",1000,5000,new byte[32],false);
    Path one=root.resolve("one.txt"),two=root.resolve("two.zip");Files.writeString(one,"one");Files.writeString(two,"two");
    try(var plain=PlainMessage.compose("Reply","Ordinary text",new byte[0],List.of(one,two),null,100000,reference,true);var opened=PlainMessage.decode(plain.encode(),100000)){
      assertFalse(opened.protectedLetter());assertEquals("Ordinary text",opened.text());assertEquals(parent,opened.context().parentId());assertEquals(2,opened.files().size());
      opened.exportTo(root.resolve("chosen.txt"),"one.txt");assertEquals("one",Files.readString(root.resolve("chosen.txt")));assertThrows(java.io.IOException.class,()->opened.exportTo(root.resolve("chosen.txt"),"one.txt"));
      try(var copied=opened.copyFiles();var forward=PlainMessage.compose("Fwd","Forwarded text",new byte[0],List.of(),copied,100000,new MailContext("",parent,"raven","Original",1000,5000,new byte[32],true),true)){assertTrue(forward.context().forwarded());assertEquals(2,forward.files().size());}
    }
    try(var plain=PlainMessage.compose("Legacy subject","Text",new byte[0],List.of(one),null,100000,reference,false);var opened=PlainMessage.decode(plain.encode(),100000)){assertNull(opened.context());assertEquals("Legacy subject\n\nText",opened.text());}
  }
  @Test void protectedReplyUsesNewIndependentManualSecretsAndFreshSaltNonce()throws Exception{
    byte[] first=LetterEnvelope.seal("First","first-letter-password".toCharArray(),"first-FF1-code".toCharArray());byte[] reply=LetterEnvelope.seal("Reply","second-letter-password".toCharArray(),"second-FF1-code".toCharArray());
    assertFalse(Arrays.equals(first,reply));assertThrows(javax.crypto.AEADBadTagException.class,()->LetterEnvelope.open(reply,"first-letter-password".toCharArray()));
    try(var opened=LetterEnvelope.open(reply,"second-letter-password".toCharArray())){assertEquals("Reply",opened.candidate("second-FF1-code".toCharArray()));assertNotEquals("Reply",opened.candidate("first-FF1-code".toCharArray()));}
    Arrays.fill(first,(byte)0);Arrays.fill(reply,(byte)0);
  }
}
