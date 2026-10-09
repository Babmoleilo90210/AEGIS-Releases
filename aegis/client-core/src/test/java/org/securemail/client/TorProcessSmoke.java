package org.securemail.client;
import java.nio.file.*;
import java.time.Duration;
import java.util.concurrent.*;
import org.securemail.client.net.*;
/** Real Linux Tor and PT lifecycle test. Does NOT assert public Tor connectivity. */
public final class TorProcessSmoke {
 public static void main(String[] args)throws Exception{
   Path profile=Files.createTempDirectory("AEGIS profile with spaces ");
   System.setProperty("aegis.profile",profile.toString());System.setProperty("aegis.home",Path.of(args[0]).toAbsolutePath().toString());
   
   ClientConfig config=new ClientConfig("127.0.0.1",19050,19051,profile.resolve("tor/control_auth_cookie"),19120,1800,"",80,profile.resolve("data"),16777216,268435456,604800000);
   Path unrelatedData=profile.resolve("unrelated Tor state");Files.createDirectories(unrelatedData);
   Path unrelatedRc=profile.resolve("unrelated-torrc");Files.writeString(unrelatedRc,"");
   ProcessBuilder unrelatedBuilder=new ProcessBuilder(Path.of(args[0],"tor/tor").toString(),"--defaults-torrc",unrelatedRc.toString(),"-f",unrelatedRc.toString(),"--DataDirectory",unrelatedData.toString(),"--SocksPort","0","--ControlPort","0","--DisableNetwork","1").redirectError(ProcessBuilder.Redirect.DISCARD).redirectOutput(ProcessBuilder.Redirect.DISCARD);
   unrelatedBuilder.environment().put("LD_LIBRARY_PATH",Path.of(args[0],"tor").toAbsolutePath().toString());
   Process unrelated=unrelatedBuilder.start();
   Thread.sleep(500);if(!unrelated.isAlive())throw new AssertionError("Unrelated test Tor could not start, exit "+unrelated.exitValue());
   Path cached=config.torCookiePath().getParent().resolve("state/persistent-cache-fixture");Files.createDirectories(cached.getParent());Files.writeString(cached,"retain me");
   try(var connection=new TorConnection(config)){
     try { connection.start(Duration.ofSeconds(3),Duration.ofSeconds(12),(mode,n)->System.out.println(mode+" bootstrap "+n)); }
     catch(EmbeddedTor.BootstrapFailure expected){System.out.println("Public Tor bootstrap not completed in test timeout");}
     if(connection.mode()!=EmbeddedTor.Mode.SNOWFLAKE)throw new AssertionError("Automatic fallback missing");
   }finally{
     if(!unrelated.isAlive())throw new AssertionError("Unrelated Tor was terminated");
     unrelated.destroy();if(!unrelated.waitFor(3,TimeUnit.SECONDS))unrelated.destroyForcibly();
   }
   if(!Files.readString(cached).equals("retain me"))throw new AssertionError("Tor state was removed");
   String rc=Files.readString(profile.resolve("tor/torrc"));
   if(!rc.contains("SocksPort 127.0.0.1:19050 OnionTrafficOnly\n")||!rc.contains("SocksPort 127.0.0.1:19052\n")||rc.contains("0.0.0.0"))throw new AssertionError("Unsafe or missing mail/update listeners");
   String log=Files.readString(profile.resolve("logs/connection.log"));
   if(!log.contains("TOR_FALLBACK")||!log.contains("TRANSPORT_STARTED"))throw new AssertionError("Real PT not observed: "+log);
   if(log.contains("cookie")||log.contains("Bridge"))throw new AssertionError("Secret/raw configuration in logs");
   for(int port:new int[]{19050,19051,19052})try(var socket=new java.net.ServerSocket()){
     socket.bind(new java.net.InetSocketAddress("127.0.0.1",port));
   }
   System.out.println("Linux bundled Tor passed: own config with spaces, onion-only mail and separate update SOCKS, automatic fallback, actual Lyrebird child, unrelated process survives, all three owned ports released. Public Tor 100% NOT_RUN.");
   System.out.println("Test profile: "+profile);
 }
}

