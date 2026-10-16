package org.securemail.client.net;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.securemail.client.*;

/** Real patched binary and production config/builder/owned-stop methods.
 * DisableNetwork1 is added in this probe only. This never tests public bootstrap.
 */
public final class EmbeddedTorPatched500Probe {
 public static void main(String[] args)throws Exception{
  Path bundle=Path.of(args[0]).toAbsolutePath(),profile=Path.of(args[1]).toAbsolutePath();
  Files.createDirectories(profile.resolve("tor/state"));System.setProperty("aegis.home",bundle.toString());System.setProperty("aegis.profile",profile.toString());
  ClientConfig config=new ClientConfig("127.0.0.1",29050,29051,29052,profile.resolve("tor/control_auth_cookie"),29120,1800,"",80,profile.resolve("data"),16777216,268435456,604800000);
  EmbeddedTor manager=new EmbeddedTor(config);String rc=manager.baseConfiguration();
  if(!rc.contains("SocksPort 127.0.0.1:29050 OnionTrafficOnly\n")||!rc.contains("SocksPort 127.0.0.1:29052\n")||!rc.contains("CookieAuthentication 1\n")||!rc.contains("SafeLogging 1\n"))throw new AssertionError("Production Tor config invariant missing");
  Files.writeString(profile.resolve("tor/defaults-torrc"),"");Files.writeString(profile.resolve("tor/torrc"),rc+"DisableNetwork 1\n");
  var command=new ArrayList<>(List.of(bundle.resolve("tor/tor").toString(),"--defaults-torrc",profile.resolve("tor/defaults-torrc").toString(),"-f",profile.resolve("tor/torrc").toString(),"--SocksPort","0","--ControlPort","0"));
  Method builder=EmbeddedTor.class.getDeclaredMethod("builder",List.class);builder.setAccessible(true);
  var verification=new ArrayList<>(command);verification.add("--verify-config");Process check=((ProcessBuilder)builder.invoke(manager,verification)).start();
  if(!check.waitFor(15,TimeUnit.SECONDS)){EmbeddedTor.stopOwnedTree(check);throw new AssertionError("Config verification timeout");}if(check.exitValue()!=0)throw new AssertionError("Production-generated patched Tor config rejected");
  Path outputFile=profile.resolve("tor-process.log");
  Process process=((ProcessBuilder)builder.invoke(manager,command)).redirectErrorStream(true).redirectOutput(outputFile.toFile()).start();
  String output;
  try{
   Thread.sleep(600);if(!process.isAlive())throw new AssertionError("Patched Tor exited early");
  }finally{EmbeddedTor.stopOwnedTree(process);manager.close();output=Files.readString(outputFile,StandardCharsets.UTF_8);}
  if(process.isAlive()||process.exitValue()!=0||!output.contains("Tor 0.4.9.14")||!output.contains("OpenSSL 3.5.9")||!output.contains("DisableNetwork is set"))throw new AssertionError("Unexpected patched Tor lifecycle: "+output);
  System.out.println("PASS_PRODUCTION_CONFIG_VERIFY");System.out.println("PASS_PRODUCTION_BUILDER_LIBRARY_PATH_AND_OWNED_STOP");System.out.println("TOR_0.4.9.14_OPENSSL_3.5.9");System.out.println("DISABLE_NETWORK_1_SOCKS_0_CONTROL_0");System.out.println("PUBLIC_BOOTSTRAP_NOT_RUN");
 }
}
