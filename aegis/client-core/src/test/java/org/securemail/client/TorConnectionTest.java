package org.securemail.client;
import static org.junit.jupiter.api.Assertions.*;
import java.time.Duration;
import java.util.*;
import java.util.function.IntConsumer;
import org.junit.jupiter.api.Test;
import org.securemail.client.net.*;
class TorConnectionTest {
 static final class Fake implements TorConnection.Attempt {
   final boolean timeout;boolean closed,ready;EmbeddedTor.Mode mode;
   Fake(boolean timeout){this.timeout=timeout;}
   public void start(EmbeddedTor.Mode mode,Duration duration,IntConsumer progress)throws Exception{
     this.mode=mode;progress.accept(10);progress.accept(45);
     if(timeout)throw new EmbeddedTor.BootstrapFailure();ready=true;progress.accept(100);
   }
   public boolean ready(){return ready&&!closed;}
   public void close(){closed=true;ready=false;}
 }
 @Test void stalledDirectAutomaticallyStartsFreshSnowflake(){
   Fake first=new Fake(true),second=new Fake(false);var attempts=new ArrayDeque<>(List.of(first,second));
   try(var connection=new TorConnection(()->{if(attempts.size()==1)assertTrue(first.closed);return attempts.removeFirst();})){
     assertDoesNotThrow(()->connection.start(Duration.ofSeconds(1),Duration.ofSeconds(2),(mode,n)->{}));
     assertEquals(EmbeddedTor.Mode.DIRECT,first.mode);assertEquals(EmbeddedTor.Mode.SNOWFLAKE,second.mode);assertTrue(connection.ready());
   }assertTrue(first.closed);assertTrue(second.closed);
 }
 @Test void bothAttemptsFailClosed(){
   var attempts=new ArrayDeque<>(List.of(new Fake(true),new Fake(true)));
   try(var connection=new TorConnection(attempts::removeFirst)){
     TorTransport.requireAvailability(connection::ready);
     assertThrows(EmbeddedTor.BootstrapFailure.class,()->connection.start(Duration.ZERO,Duration.ZERO,(mode,n)->{}));
     assertFalse(connection.ready());assertThrows(java.io.IOException.class,()->new TorTransport("127.0.0.1",19050).connect("a".repeat(56)+".onion",80));
   }finally{TorTransport.requireAvailability(()->true);}
 }
}

