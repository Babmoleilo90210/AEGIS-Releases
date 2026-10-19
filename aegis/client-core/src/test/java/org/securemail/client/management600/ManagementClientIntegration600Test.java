package org.securemail.client.management600;

import static org.junit.jupiter.api.Assertions.*;
import com.google.gson.JsonObject;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.attachments.*;
import org.securemail.client.net.TorTransport;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import org.securemail.identity.*;
import org.securemail.management.*;

/** Production HTTP/SOCKS client + Identity and Management SQL; systemctl is only a command recorder. */
class ManagementClientIntegration600Test {
  @TempDir Path home;
  static final String ONION="a".repeat(56)+".onion";
  IdentityStore identity;IdentityHttpServer http;IdentityRemoteAuthority remote;ManagementService management;
  KeyPair service,agentKey;Account owner,delegate;final List<List<String>> commands=new ArrayList<>();byte[] managementAudit;
  ManagementHttpServer600 agent;SocksFixture socks;ManagementClient600 client;
  record Account(KeyPair root, KeyPair device, KeyPair recovery, KeyPair app, IdentityStore.Session session, Capability cap) { Account with(Capability cap) { return new Account(root, device, recovery, app, session, cap); } }
  static KeyPair pair() throws Exception { return KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); }
  @BeforeEach void prepare() throws Exception {
    service = pair(); byte[] audit = new byte[32]; managementAudit = new byte[32]; new SecureRandom().nextBytes(audit); new SecureRandom().nextBytes(managementAudit);
    identity = new IdentityStore(home.resolve("identity/identity.sqlite"), service, audit, Clock.systemUTC()); owner = register(); delegate = register();
    var challenge = identity.ownerChallenge(owner.session().accountId()); identity.bootstrapOwner(owner.session().accountId(), challenge.challenge(), IdentityProtocol.sign(owner.root().getPrivate(), IdentityProtocol.ownerBootstrap(identity.audience(), owner.session().accountId(), challenge.challenge(), challenge.expiresAt())));
    step(owner); owner = owner.with(cap(owner));
    long now = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); byte[] proposal = IdentityProtocol.firstDelegateProposal(identity.audience(), owner.session().accountId(), delegate.session().accountId(), "Оператор восстановления", now, nonce);
    var delegation = identity.firstDelegateChallenge(owner.cap(), delegate.session().accountId(), "Оператор восстановления", now, nonce, IdentityProtocol.sign(owner.app().getPrivate(), IdentityProtocol.requestDigest(owner.cap(), "admin.execute", IdentityProtocol.digest(proposal), now, nonce)));
    byte[] consent = IdentityProtocol.unb64((String) delegation.get("proofBytes"), 4096); identity.completeFirstDelegation((String) delegation.get("challenge"), IdentityProtocol.sign(owner.root().getPrivate(), consent), IdentityProtocol.sign(owner.device().getPrivate(), consent), IdentityProtocol.sign(delegate.root().getPrivate(), consent), IdentityProtocol.sign(delegate.device().getPrivate(), consent)); delegate = delegate.with(cap(delegate));
    http = new IdentityHttpServer(new InetSocketAddress("127.0.0.1", 0), identity, service); http.start(); remote = new IdentityRemoteAuthority(URI.create("http://127.0.0.1:" + http.port() + "/identity/v1"), service.getPublic().getEncoded());
    management = new ManagementService(home.resolve("management.sqlite"), managementAudit, remote::authorize, args -> { commands.add(List.copyOf(args)); return new ManagementService.Result(0, args.contains("show") ? "ActiveState=active\nSubState=running\nMainPID=123\n" : "Системное задание поставлено в очередь; результат проверьте отдельно"); }, Clock.systemUTC());
    agentKey=pair();agent=new ManagementHttpServer600(new InetSocketAddress("127.0.0.1",0),agentKey,bytes->{var envelope=ManagementMain.decode(bytes);var result=management.execute(envelope.request(),envelope.proofs());JsonObject data=new JsonObject();data.addProperty("exitCode",result.exitCode());data.addProperty("output",result.safeOutput());return data;});agent.start();socks=new SocksFixture(ONION,()->agent.port());client=new ManagementClient600(new TorTransport("127.0.0.1",socks.port()),ONION,80,agentKey.getPublic().getEncoded(),service.getPublic().getEncoded());
  }
  @AfterEach void close() throws Exception { if(client!=null)client.close();if(socks!=null)socks.close();if(agent!=null)agent.close(); if (management != null) management.close(); if (http != null) http.close(); if (identity != null) identity.close(); if (managementAudit != null) Arrays.fill(managementAudit, (byte) 0); }
  Account register() throws Exception { KeyPair root = pair(), device = pair(), recovery = pair(), app = pair(); long now = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); byte[] body = IdentityProtocol.registration(identity.audience(), root.getPublic().getEncoded(), device.getPublic().getEncoded(), recovery.getPublic().getEncoded(), "Администратор", now, nonce); var session = identity.register(root.getPublic().getEncoded(), device.getPublic().getEncoded(), recovery.getPublic().getEncoded(), "Администратор", now, nonce, IdentityProtocol.sign(root.getPrivate(), body), IdentityProtocol.sign(device.getPrivate(), body)); return new Account(root, device, recovery, app, session, null); }
  void step(Account account) { var c = identity.stepUpChallenge(account.session().accountId(), account.session().deviceId(), account.session().generation()); byte[] body = IdentityProtocol.stepUp(identity.audience(), c.accountId(), c.deviceId(), c.challenge(), c.expiresAt()); identity.stepUp(c.accountId(), c.deviceId(), account.session().generation(), c.challenge(), IdentityProtocol.sign(account.root().getPrivate(), body), IdentityProtocol.sign(account.device().getPrivate(), body)); }
  Capability cap(Account account) { long now = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); Set<Scope> scopes = EnumSet.of(Scope.ADMIN,Scope.ACCOUNT_READ); byte[] request = IdentityProtocol.capabilityRequest(identity.audience(), account.session().accountId(), account.session().deviceId(), account.session().generation(), App.AEGIS, account.app().getPublic().getEncoded(), scopes, 600000, now, nonce); return identity.issueCapability(account.session().accountId(), account.session().deviceId(), account.session().generation(), App.AEGIS, account.app().getPublic().getEncoded(), scopes, 600000, now, nonce, IdentityProtocol.sign(account.device().getPrivate(), request), IdentityProtocol.sign(account.app().getPrivate(), request)); }
  ManagementClient600.Grant grant(Account a){return new ManagementClient600.Grant(IdentityProtocol.encodeCapability(a.cap()),a.app().getPrivate());}
  @Test void exactClientMetadataMatchesActualServerParserForEveryServiceAndAction()throws Exception {
    for(var service:ManagementClient600.Service.values())for(var action:List.of(ManagementClient600.Action.STATUS,ManagementClient600.Action.RESTART)){
      var request=new ManagementClient600.Request(UUID.randomUUID().toString(),action,service,"");var decoded=ManagementPolicy.decode(request.encode());assertEquals(action.name(),decoded.action().name());assertEquals(service.name(),decoded.service().name());assertArrayEquals(request.encode(),decoded.encode());
    }
    for(var request:List.of(ManagementClient600.Request.backup(),ManagementClient600.Request.restore("a".repeat(64))))assertArrayEquals(request.encode(),ManagementPolicy.decode(request.encode()).encode());
  }
  @Test void realClientStatusRestartAndAsyncBackupUseOnlyFixedCommands()throws Exception {
    var response=client.execute(ManagementClient600.Request.status(ManagementClient600.Service.IDENTITY),grant(owner));assertTrue(response.output().contains("ActiveState=active"));
    client.execute(ManagementClient600.Request.restart(ManagementClient600.Service.ATTACHMENTS),grant(owner));assertTrue(client.execute(ManagementClient600.Request.backup(),grant(owner)).queued());client.execute(ManagementClient600.Request.restart(ManagementClient600.Service.MAIL_RELAY),grant(owner));assertEquals(4,commands.size());assertEquals("aegis600-staging-mail-relay.service",commands.get(3).getLast());
    assertEquals(List.of("/usr/bin/systemctl","try-restart","--","aegis600-staging-attachments.service"),commands.get(1));assertTrue(commands.get(2).contains("aegis600-staging-backup.service"));
  }
  @Test void actualIdentityGenerationRevokeDeniesBeforeAnyCommand()throws Exception {
    long now=System.currentTimeMillis();String nonce=IdentityProtocol.nonce();identity.login(owner.session().accountId(),owner.session().deviceId(),now,nonce,IdentityProtocol.sign(owner.device().getPrivate(),IdentityProtocol.login(identity.audience(),owner.session().accountId(),owner.session().deviceId(),now,nonce)));
    assertThrows(ManagementClient600.Rejected.class,()->client.execute(ManagementClient600.Request.restart(ManagementClient600.Service.IDENTITY),grant(owner)));assertEquals(0,commands.size());
  }
  @Test void twoDistinctActualAdministratorsApproveExactlyOneImmutableRestore()throws Exception {
    var request=ManagementClient600.Request.restore("b".repeat(64));var approvals=List.of(client.approve(request,grant(owner)),client.approve(request,grant(delegate)));assertEquals(0,client.executeApproved(request,approvals).exitCode());assertEquals(1,commands.size());
    assertThrows(IOException.class,()->client.executeApproved(request,approvals));assertEquals(1,commands.size());assertTrue(management.verifyAudit());
  }
  @Test void metadataTamperDuplicateAdministratorAndWrongAppProofAreRejectedLocally()throws Exception {
    var request=ManagementClient600.Request.restore("b".repeat(64));var altered=new ManagementClient600.Request(request.id(),request.action(),null,"c".repeat(64));var proof=client.approve(request,grant(owner));
    assertThrows(IOException.class,()->client.executeApproved(altered,List.of(proof,client.approve(request,grant(delegate)))));assertThrows(IOException.class,()->client.executeApproved(request,List.of(proof,client.approve(request,grant(owner)))));
    assertThrows(IOException.class,()->client.approve(ManagementClient600.Request.backup(),new ManagementClient600.Grant(grant(owner).capability(),pair().getPrivate())));assertEquals(0,commands.size());
  }
  @Test void wrongServicePinAndMissingSocksNeverCauseDirectFallback()throws Exception {
    try(var wrong=new ManagementClient600(new TorTransport("127.0.0.1",socks.port()),ONION,80,pair().getPublic().getEncoded(),service.getPublic().getEncoded())){assertThrows(IOException.class,()->wrong.execute(ManagementClient600.Request.status(ManagementClient600.Service.IDENTITY),grant(owner)));}
    socks.close();assertThrows(IOException.class,()->client.execute(ManagementClient600.Request.status(ManagementClient600.Service.IDENTITY),grant(owner)));assertEquals(1,commands.size());
    assertThrows(IllegalArgumentException.class,()->new ManagementClient600(new TorTransport("127.0.0.1",1),"example.com",443,agentKey.getPublic().getEncoded(),service.getPublic().getEncoded()));
  }
  @Test void signedRateRefusalBindsRequestAndDoesNotRunThirtyFirstCommand()throws Exception {
    for(int i=0;i<30;i++)client.execute(ManagementClient600.Request.status(ManagementClient600.Service.IDENTITY),grant(owner));
    assertThrows(ManagementClient600.Busy.class,()->client.execute(ManagementClient600.Request.status(ManagementClient600.Service.IDENTITY),grant(owner)));assertEquals(30,commands.size());
  }
  @Test void publicConfigurationHasOnlyExactKeysAndNoSymlinkOrDuplicatePin()throws Exception {
    Path config=home.resolve("management.properties");String value="onion="+ONION+"\nport=80\npublicKey="+IdentityProtocol.b64(agentKey.getPublic().getEncoded())+"\n";Files.writeString(config,value);assertEquals(ONION,ManagementClient600.Config.load(config).onion());
    Files.writeString(config,value+"port=81\n");assertThrows(IOException.class,()->ManagementClient600.Config.load(config));Files.writeString(config,value+"command=whoami\n");assertThrows(IOException.class,()->ManagementClient600.Config.load(config));Files.writeString(config,value);Path link=home.resolve("alias");Files.createSymbolicLink(link,config);assertThrows(IOException.class,()->ManagementClient600.Config.load(link));
    assertFalse(grant(owner).toString().contains(grant(owner).capability()));assertFalse(client.approve(ManagementClient600.Request.backup(),grant(owner)).toString().contains(grant(owner).capability()));
  }
  /** Local SOCKS5 test fixture only. It validates the production client sent an onion name, never DNS/IP. */
  private static final class SocksFixture implements AutoCloseable {
    final ServerSocket listener = new ServerSocket(0, 8, InetAddress.getByAddress(new byte[]{127,0,0,1})); final ExecutorService pool = Executors.newFixedThreadPool(8); final Set<Socket> active = ConcurrentHashMap.newKeySet(); final Thread accept; final String onion; final java.util.function.IntSupplier origin; volatile boolean closed;
    SocksFixture(String onion, java.util.function.IntSupplier origin) throws IOException { this.onion = onion; this.origin = origin; accept = new Thread(() -> { while (!closed) try { Socket socket = listener.accept(); active.add(socket); pool.execute(() -> relay(socket)); } catch (IOException | RejectedExecutionException e) { if (!closed) throw new IllegalStateException(e); } }, "attachment-test-socks"); accept.setDaemon(true); accept.start(); }
    int port() { return listener.getLocalPort(); }
    void relay(Socket client) {
      Socket backend = null;
      try { client.setSoTimeout(60000); var in = new DataInputStream(client.getInputStream()); OutputStream out = client.getOutputStream(); if (in.readUnsignedByte() != 5 || in.readUnsignedByte() != 1 || in.readUnsignedByte() != 0) throw new IOException(); out.write(new byte[]{5,0}); out.flush(); if (in.readUnsignedByte() != 5 || in.readUnsignedByte() != 1 || in.readUnsignedByte() != 0 || in.readUnsignedByte() != 3) throw new IOException(); int n = in.readUnsignedByte(); String host = new String(in.readNBytes(n), StandardCharsets.US_ASCII); int port = in.readUnsignedShort(); if (!host.equals(onion) || port != 80) throw new IOException(); backend = new Socket(InetAddress.getByAddress(new byte[]{127,0,0,1}), origin.getAsInt()); active.add(backend); out.write(new byte[]{5,0,0,1,127,0,0,1,0,0}); out.flush(); Socket target = backend;
        pool.execute(() -> { try { target.getInputStream().transferTo(client.getOutputStream()); } catch (IOException ignored) {} finally { try { target.close(); client.close(); } catch (IOException ignored) {} active.remove(target); active.remove(client); } }); in.transferTo(backend.getOutputStream());
      } catch (IOException ignored) { try { client.close(); if (backend != null) backend.close(); } catch (IOException ignored2) {} }
    }
    @Override public void close() throws Exception { closed = true; listener.close(); for (Socket socket : active) socket.close(); pool.shutdownNow(); accept.join(1000); }
  }
}
