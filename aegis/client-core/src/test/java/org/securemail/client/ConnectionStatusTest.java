package org.securemail.client;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.securemail.client.net.*;

class ConnectionStatusTest {
  @Test void fallbackIsStillConnectingAndNeverFailed(){
    var state=new ConnectionStatus();state.bootstrap(EmbeddedTor.Mode.DIRECT,10);assertTrue(state.snapshot().busy());
    state.offline();assertEquals(ConnectionStatus.State.BOOTSTRAPPING_DIRECT,state.snapshot().state());
    state.bootstrap(EmbeddedTor.Mode.SNOWFLAKE,0);assertTrue(state.snapshot().busy());assertEquals(ConnectionStatus.Failure.NONE,state.snapshot().failure());
    state.bootstrap(EmbeddedTor.Mode.SNOWFLAKE,100);state.torConnected();assertEquals(ConnectionStatus.State.TOR_CONNECTED,state.snapshot().state());
    state.relayConnecting();assertEquals(ConnectionStatus.State.RELAY_CONNECTING,state.snapshot().state());state.connected();assertFalse(state.snapshot().busy());
  }
  @Test void relaySuccessRequiresTorAndSeparateProbe(){
    var state=new ConnectionStatus();assertThrows(IllegalStateException.class,state::relayConnecting);assertThrows(IllegalStateException.class,state::connected);
    state.bootstrap(EmbeddedTor.Mode.DIRECT,100);state.torConnected();assertThrows(IllegalStateException.class,state::connected);
    state.relayConnecting();state.failed(ConnectionStatus.Failure.RELAY_UNAVAILABLE);assertEquals(ConnectionStatus.State.FAILED,state.snapshot().state());
    state.bootstrap(EmbeddedTor.Mode.DIRECT,1);assertEquals(ConnectionStatus.Failure.NONE,state.snapshot().failure());
  }
  @Test void duplicateStartsCannotCreateSecondAttempt()throws Exception{
    CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);AtomicInteger made=new AtomicInteger();
    TorConnection connection=new TorConnection(()->{made.incrementAndGet();return new TorConnection.Attempt(){
      public void start(EmbeddedTor.Mode m,Duration d,java.util.function.IntConsumer p)throws Exception{entered.countDown();if(!release.await(3,TimeUnit.SECONDS))throw new java.io.IOException("test timeout");}
      public boolean ready(){return true;}public void close(){}
    };});
    ExecutorService worker=Executors.newSingleThreadExecutor();
    try{Future<?> first=worker.submit(()->{try{connection.start(Duration.ofSeconds(1),Duration.ofSeconds(1),(m,p)->{});}catch(Exception e){throw new RuntimeException(e);}});
      assertTrue(entered.await(2,TimeUnit.SECONDS));assertThrows(java.io.IOException.class,()->connection.start(Duration.ofSeconds(1),Duration.ofSeconds(1),(m,p)->{}));assertEquals(1,made.get());release.countDown();first.get(2,TimeUnit.SECONDS);
    }finally{release.countDown();connection.close();worker.shutdownNow();}
  }
}
