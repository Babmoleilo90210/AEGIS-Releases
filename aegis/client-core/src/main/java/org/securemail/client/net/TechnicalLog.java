package org.securemail.client.net;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import org.securemail.client.AppPaths;
import org.securemail.client.storage.AtomicFiles;

/** Local bounded allowlist: callers never pass a payload, secret or raw Tor line. */
public final class TechnicalLog {
  public enum Event { TOR_START, TOR_BOOTSTRAP, TOR_READY, TOR_EXIT, TOR_TIMEOUT,
    SNOWFLAKE_FALLBACK, TRANSPORT_STARTED, TRANSPORT_ERROR, NETWORK_ERROR, CONFIG_ERROR, RELAY_CONNECTED, TOR_DIRECT_START, TOR_SNOWFLAKE_START, TOR_DIRECT_STALLED, TOR_SNOWFLAKE_STALLED, TOR_FALLBACK, LYREBIRD_STARTED, LYREBIRD_STATUS, SNOWFLAKE_BROKER_ERROR, SNOWFLAKE_CONNECTED, RELAY_CONNECT, RELAY_FAILED }
  private TechnicalLog() {}
  public static synchronized void record(Event event, int number) {
    try {
      Path dir=AppPaths.root().resolve("logs"), file=dir.resolve("connection.log");
      AtomicFiles.directory(dir);
      if(!Files.exists(file) || Files.size(file)>1024*1024) AtomicFiles.write(file,new byte[0]);
      Files.writeString(file,Instant.now()+" "+event.name()+" "+number+"\n",StandardCharsets.UTF_8,StandardOpenOption.APPEND);
    } catch(IOException ignored) { /* Logging is not required to send or receive. */ }
  }
}

