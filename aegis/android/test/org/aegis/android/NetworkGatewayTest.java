package org.aegis.android;
import java.io.*;import java.net.*;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.concurrent.atomic.*;
/** Actual host sockets/forwarding fixture; Android protect/VPN/native engine not claimed. */
public final class NetworkGatewayTest {
 static int count;interface Checked{void run()throws Exception;}static void test(String n,Checked t)throws Exception{t.run();count++;System.out.println("PASS "+n);}static void require(boolean b){if(!b)throw new AssertionError();}static void reject(Checked t)throws Exception{try{t.run();}catch(Exception expected){return;}throw new AssertionError();}
 static Socket connect(NetworkGateway g,String password)throws Exception {Socket s=new Socket("127.0.0.1",g.port());s.setSoTimeout(3000);DataOutputStream o=new DataOutputStream(s.getOutputStream());DataInputStream i=new DataInputStream(s.getInputStream());o.write(new byte[]{5,1,2});o.flush();require(i.readUnsignedByte()==5&&i.readUnsignedByte()==2);byte[] user=g.user.getBytes(StandardCharsets.US_ASCII),pass=password.getBytes(StandardCharsets.US_ASCII);o.writeByte(1);o.writeByte(user.length);o.write(user);o.writeByte(pass.length);o.write(pass);o.flush();require(i.readUnsignedByte()==1);if(i.readUnsignedByte()!=0){s.close();throw new IOException("Denied auth");}return s;}
 static void destination(Socket s,int command,String domain,int port)throws Exception {DataOutputStream o=new DataOutputStream(s.getOutputStream());byte[] host=domain.getBytes(StandardCharsets.US_ASCII);o.write(new byte[]{5,(byte)command,0,3,(byte)host.length});o.write(host);o.writeShort(port);o.flush();}
 static void rejectedDestination(NetworkGateway gateway,int command,String domain,int port)throws Exception {
  long deniedBefore=gateway.denied.get();
  try(Socket socket=connect(gateway,gateway.password)){
   try{destination(socket,command,domain,port);require(socket.getInputStream().read()==-1);}
   catch(SocketException earlyClose){/* Rejection may close TCP before the fixture finishes its request bytes. */}
  }
  long deadline=System.nanoTime()+1_000_000_000L;
  while(gateway.denied.get()==deniedBefore&&System.nanoTime()<deadline)Thread.sleep(2);
  require(gateway.denied.get()>deniedBefore);
 }
 public static void main(String[]args)throws Exception {
  DomainRules rules=new DomainRules("tracker.example\nTelemetry.Example\ntracker.example");
  test("domain rules canonical bounded and deduplicated",()->require(rules.canonical.equals("telemetry.example\ntracker.example")));
  test("DNS exact block",()->require(!rules.allowed("tracker.example")));
  test("DNS subdomain and case block",()->require(!rules.allowed("CDN.TRACKER.example.")));
  test("domain suffix boundary no overblock",()->require(rules.allowed("nottracker.example")&&rules.allowed("tracker.example.org")));
  test("invalid Unicode and local domain refused",()->require(!rules.allowed("localhost")&&!rules.allowed("foo.local")&&!rules.allowed("пример.рф")&&!rules.allowed("foo..example")));
  test("oversized DNS label refused",()->reject(()->DomainRules.domain("a".repeat(64)+".example")));
  test("rule count quota",()->{StringBuilder b=new StringBuilder();for(int n=0;n<1025;n++)b.append("x").append(n).append(".example\n");reject(()->new DomainRules(b.toString()));});
  test("private IPv4 blocked",()->{for(byte[] ip:new byte[][]{{127,0,0,1},{10,1,2,3},{(byte)192,(byte)168,1,1},{100,64,0,1},{(byte)198,18,0,1}})require(!DomainRules.publicAddress(InetAddress.getByAddress(ip)));});
  test("private IPv6 blocked",()->{require(!DomainRules.publicAddress(InetAddress.getByAddress(new byte[16])));byte[] local=new byte[16];local[0]=(byte)0xfd;require(!DomainRules.publicAddress(InetAddress.getByAddress(local)));});
  AtomicInteger connected=new AtomicInteger();try(ServerSocket echo=new ServerSocket(0,2,InetAddress.getByAddress(new byte[]{127,0,0,1}));NetworkGateway gateway=new NetworkGateway(rules,(host,address,port)->{connected.incrementAndGet();if(!"normal.example".equals(host)||address!=null||port!=echo.getLocalPort())throw new IOException("Unexpected route");return new Socket("127.0.0.1",port);})){
   test("loopback gateway requires random credentials",()->reject(()->connect(gateway,"wrong-password")));
   test("blocked domain never reaches connector",()->{int before=connected.get();rejectedDestination(gateway,1,"tracker.example",443);require(connected.get()==before);});
   test("UDP associate never reaches connector",()->{int before=connected.get();rejectedDestination(gateway,3,"normal.example",443);require(connected.get()==before);});
   test("real bidirectional TCP payload forwarding",()->{Thread server=new Thread(()->{try(Socket remote=echo.accept()){byte[] bytes=remote.getInputStream().readNBytes(17);remote.getOutputStream().write(bytes);remote.getOutputStream().flush();}catch(IOException e){throw new RuntimeException(e);}});server.setDaemon(true);server.start();try(Socket s=connect(gateway,gateway.password)){destination(s,1,"normal.example",echo.getLocalPort());require(s.getInputStream().readNBytes(10)[1]==0);byte[] payload="real-forward-data".getBytes(StandardCharsets.US_ASCII);s.getOutputStream().write(payload);s.getOutputStream().flush();require(Arrays.equals(payload,s.getInputStream().readNBytes(payload.length)));}server.join(3000);require(!server.isAlive());long deadline=System.nanoTime()+1_000_000_000L;while(gateway.downloaded.get()<17&&System.nanoTime()<deadline)Thread.sleep(5);if(gateway.uploaded.get()<17||gateway.downloaded.get()<17)throw new AssertionError("Actual byte counters: "+gateway.uploaded.get()+"/"+gateway.downloaded.get());});
  }
  System.out.println("NetworkGatewayTest: "+count+" PASS; actual host sockets only, Android VPN/protect/native/DNS leak NOT_RUN");
 }
}
