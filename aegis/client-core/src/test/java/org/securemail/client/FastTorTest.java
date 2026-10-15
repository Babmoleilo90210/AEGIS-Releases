package org.securemail.client;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.client.net.*;
class FastTorTest {
 @TempDir Path root;
 @Test void rememberedSnowflakeFirstAndReverseFallback()throws Exception{
  Path saved=root.resolve("mode.txt");Files.writeString(saved,"snowflake\n");var first=new TorConnectionTest.Fake(true);var second=new TorConnectionTest.Fake(false);var attempts=new ArrayDeque<>(List.of(first,second));
  try(var connection=new TorConnection(()->{if(attempts.size()==1)assertTrue(first.closed);return attempts.removeFirst();},saved)){connection.start(Duration.ofSeconds(1),Duration.ofSeconds(2),(m,n)->{});assertEquals(EmbeddedTor.Mode.SNOWFLAKE,first.mode);assertEquals(EmbeddedTor.Mode.DIRECT,second.mode);assertEquals("direct\n",Files.readString(saved));}
 }
 @Test void stallMeasuredFromLastRealProgress(){
  var watch=new BootstrapWatch(Duration.ofSeconds(30),0);watch.progress(10,0);assertFalse(watch.stalled(Duration.ofSeconds(29).toNanos()));watch.progress(10,Duration.ofSeconds(29).toNanos());assertTrue(watch.stalled(Duration.ofSeconds(30).toNanos()));
  watch.progress(50,Duration.ofSeconds(31).toNanos());assertFalse(watch.stalled(Duration.ofSeconds(60).toNanos()));watch.progress(100,Duration.ofSeconds(61).toNanos());assertFalse(watch.stalled(Duration.ofDays(1).toNanos()));
 }
 @Test void rawTransportMessagesNeverEnterLogs(){
  assertEquals(TechnicalLog.Event.SNOWFLAKE_BROKER_ERROR,TransportDiagnostics.classify("LOG SEVERITY=error MESSAGE=broker failed password=SECRET 1.2.3.4"));assertEquals(TechnicalLog.Event.LYREBIRD_STATUS,TransportDiagnostics.classify("STATUS secret-control-cookie"));assertNull(TransportDiagnostics.classify("arbitrary-private-text"));
 }
}
