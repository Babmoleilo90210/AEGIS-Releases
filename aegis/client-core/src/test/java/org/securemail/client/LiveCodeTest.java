package org.securemail.client;
import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.securemail.client.crypto.LiveCode;
class LiveCodeTest {
 @Test void staleQueuedUiResultAndCloseAreSuppressed()throws Exception{
   var ui=new LinkedBlockingQueue<Runnable>();var shown=new ArrayList<String>();
   try(var live=new LiveCode(chars->new String(chars),ui::add,shown::add)){
     live.change("first".toCharArray(),"");Runnable stale=ui.poll(5,TimeUnit.SECONDS);assertNotNull(stale);
     live.change("latest".toCharArray(),"");Runnable current=ui.poll(5,TimeUnit.SECONDS);assertNotNull(current);
     stale.run();assertTrue(shown.isEmpty());current.run();assertEquals(List.of("latest"),shown);
     live.change(new char[0],"cipher");Runnable closing=ui.poll(5,TimeUnit.SECONDS);live.close();closing.run();assertEquals(1,shown.size());
   }
 }
 @Test void rapidTypingOnlyPublishesLatest()throws Exception{
   var result=new LinkedBlockingQueue<String>();
   try(var live=new LiveCode(chars->new String(chars),Runnable::run,result::add)){
     for(int i=0;i<100;i++)live.change(("code-"+i).toCharArray(),"");
     assertEquals("code-99",result.poll(5,TimeUnit.SECONDS));assertNull(result.poll(200,TimeUnit.MILLISECONDS));
   }
 }
}

