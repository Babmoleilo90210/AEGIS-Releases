package org.securemail.client.net;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.securemail.client.AppPaths;
import org.securemail.client.storage.AtomicFiles;

/** Standard Tor PT-v1 managed transport, launched by ProcessBuilder with one absolute
 * executable argument. No torrc exec quoting, PATH lookup, shell or system transport.
 * Tor uses its announced loopback SOCKS5 endpoint; bridge options still come from Tor.
 */
final class SnowflakeProcess implements AutoCloseable {
  private volatile Process process;
  private volatile boolean closed;
  int start(Path executable,Path state)throws Exception {
    AtomicFiles.directory(state);
    var builder=new ProcessBuilder(executable.toAbsolutePath().toString())
        .directory(executable.toAbsolutePath().getParent().toFile())
        .redirectError(ProcessBuilder.Redirect.PIPE);
    var env=builder.environment();
    // Prevent unrelated managed-transport environment from overriding our own instance.
    env.keySet().removeIf(key->key.startsWith("TOR_PT_"));
    env.put("TOR_PT_MANAGED_TRANSPORT_VER","1");env.put("TOR_PT_CLIENT_TRANSPORTS","snowflake");
    env.put("TOR_PT_STATE_LOCATION",state.toAbsolutePath().toString());env.put("TOR_PT_EXIT_ON_STDIN_CLOSE","1");
    synchronized(this){if(closed)throw new IOException("Приложение закрывается");process=builder.start();}
    Process owned=process;TechnicalLog.record(TechnicalLog.Event.LYREBIRD_STARTED,0);
    Thread errors=new Thread(()->{try(var reader=new BufferedReader(new InputStreamReader(owned.getErrorStream(),StandardCharsets.UTF_8))){String line;while((line=reader.readLine())!=null)TransportDiagnostics.accept(line);}catch(IOException ignored){}},"aegis-snowflake-diagnostics");errors.setDaemon(true);errors.start();
    CompletableFuture<Integer> announced=new CompletableFuture<>();
    Thread reader=new Thread(()->{
      int port=0;boolean version=false;
      try(var in=new BufferedReader(new InputStreamReader(owned.getInputStream(),StandardCharsets.UTF_8))){
        String line;
        while((line=in.readLine())!=null){
          if(line.length()>4096)throw new IOException("Неверный ответ транспорта");
          if(line.equals("VERSION 1"))version=true;
          else if(line.startsWith("CMETHOD snowflake socks5 ")){
            String endpoint=line.substring("CMETHOD snowflake socks5 ".length());
            if(!endpoint.matches("127\\.0\\.0\\.1:[0-9]{1,5}"))throw new IOException("Небезопасный адрес транспорта");
            port=Integer.parseInt(endpoint.substring(endpoint.lastIndexOf(':')+1));
            if(port<1||port>65535)throw new IOException("Неверный порт транспорта");
          }else if(line.equals("CMETHODS DONE")){
            if(!version||port==0)throw new IOException("Транспорт не зарегистрирован");
            TechnicalLog.record(TechnicalLog.Event.TRANSPORT_STARTED,port);announced.complete(port);
          }else if(line.startsWith("ENV-ERROR")||line.startsWith("VERSION-ERROR")||line.startsWith("CMETHOD-ERROR")){
            TechnicalLog.record(TechnicalLog.Event.TRANSPORT_ERROR,0);throw new IOException("Транспорт не смог запуститься");
          }
          if(line.startsWith("STATUS ")||line.startsWith("LOG "))TransportDiagnostics.accept(line);
          // Raw lines, hosts and cookies are never retained.
        }
        announced.completeExceptionally(new IOException("Транспорт остановлен"));
      }catch(Exception error){announced.completeExceptionally(error);}
    },"aegis-snowflake-protocol");reader.setDaemon(true);reader.start();
    try{return announced.get(15,TimeUnit.SECONDS);}catch(Exception failure){close();throw new IOException("Не удалось запустить Snowflake",failure);}
  }
  boolean alive(){return !closed&&process!=null&&process.isAlive();}
  @Override public synchronized void close(){closed=true;if(process!=null){try{process.getOutputStream().close();}catch(IOException ignored){}EmbeddedTor.stopOwnedTree(process);process=null;}}
}

