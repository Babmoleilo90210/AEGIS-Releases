package org.securemail.management;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.securemail.attachments.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import org.securemail.identity.*;

/** Real Identity HTTP/SQLite/bootstrap/delegation/PoP; command recorder is NOT native systemd acceptance. */
class ManagementIdentityIntegrationTest {
  @TempDir Path home;
  IdentityStore identity; IdentityHttpServer http; IdentityRemoteAuthority remote; ManagementService management;
  KeyPair service; Account owner, delegate; final List<List<String>> commands = new ArrayList<>(); byte[] managementAudit;
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
    management = new ManagementService(home.resolve("management.sqlite"), managementAudit, remote::authorize, args -> { commands.add(List.copyOf(args)); return new ManagementService.Result(0, "TEST_COMMAND_RECORDER_NOT_SYSTEMD"); }, Clock.systemUTC());
  }
  @AfterEach void close() throws Exception { if (management != null) management.close(); if (http != null) http.close(); if (identity != null) identity.close(); if (managementAudit != null) Arrays.fill(managementAudit, (byte) 0); }
  Account register() throws Exception { KeyPair root = pair(), device = pair(), recovery = pair(), app = pair(); long now = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); byte[] body = IdentityProtocol.registration(identity.audience(), root.getPublic().getEncoded(), device.getPublic().getEncoded(), recovery.getPublic().getEncoded(), "Администратор", now, nonce); var session = identity.register(root.getPublic().getEncoded(), device.getPublic().getEncoded(), recovery.getPublic().getEncoded(), "Администратор", now, nonce, IdentityProtocol.sign(root.getPrivate(), body), IdentityProtocol.sign(device.getPrivate(), body)); return new Account(root, device, recovery, app, session, null); }
  void step(Account account) { var c = identity.stepUpChallenge(account.session().accountId(), account.session().deviceId(), account.session().generation()); byte[] body = IdentityProtocol.stepUp(identity.audience(), c.accountId(), c.deviceId(), c.challenge(), c.expiresAt()); identity.stepUp(c.accountId(), c.deviceId(), account.session().generation(), c.challenge(), IdentityProtocol.sign(account.root().getPrivate(), body), IdentityProtocol.sign(account.device().getPrivate(), body)); }
  Capability cap(Account account) { long now = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); Set<Scope> scopes = EnumSet.of(Scope.ADMIN); byte[] request = IdentityProtocol.capabilityRequest(identity.audience(), account.session().accountId(), account.session().deviceId(), account.session().generation(), App.AEGIS, account.app().getPublic().getEncoded(), scopes, 600000, now, nonce); return identity.issueCapability(account.session().accountId(), account.session().deviceId(), account.session().generation(), App.AEGIS, account.app().getPublic().getEncoded(), scopes, 600000, now, nonce, IdentityProtocol.sign(account.device().getPrivate(), request), IdentityProtocol.sign(account.app().getPrivate(), request)); }
  IdentityRemoteAuthority.Proof proof(Account account, ManagementPolicy.Request request) { long now = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); byte[] signature = IdentityProtocol.sign(account.app().getPrivate(), IdentityProtocol.requestDigest(account.cap(), request.action().permission(), IdentityProtocol.digest(request.encode()), now, nonce)); return new IdentityRemoteAuthority.Proof(IdentityProtocol.encodeCapability(account.cap()), now, nonce, signature); }
  ManagementPolicy.Request restore() { return new ManagementPolicy.Request(UUID.randomUUID().toString(), ManagementPolicy.Action.BACKUP_RESTORE, null, "a".repeat(64)); }
  @Test void ordinaryOwnerOperationUsesFreshRealHttpAuthorityAndExactFixedUnit() throws Exception {
    var request = new ManagementPolicy.Request(UUID.randomUUID().toString(), ManagementPolicy.Action.RESTART, ManagementPolicy.Service.ATTACHMENTS, ""); assertEquals(0, management.execute(request, List.of(proof(owner, request))).exitCode());
    assertEquals(List.of("/usr/bin/systemctl", "try-restart", "--", "aegis600-staging-attachments.service"), commands.getFirst()); assertTrue(management.verifyAudit());
  }
  @Test void actualFourProofDelegatedSecondAdministratorApprovesCriticalRestoreExactlyOnce() throws Exception {
    assertEquals(true, identity.profile(delegate.session().accountId()).get("delegatedAdministrator")); assertEquals(false, identity.profile(delegate.session().accountId()).get("ownerBadge")); var request = restore(); management.execute(request, List.of(proof(owner, request), proof(delegate, request))); assertEquals(1, commands.size()); assertTrue(commands.getFirst().contains("aegis600-staging-restore@" + "a".repeat(64) + ".service"));
    assertThrows(IOException.class, () -> management.execute(request, List.of(proof(owner, request), proof(delegate, request)))); assertEquals(1, commands.size()); assertTrue(management.verifyAudit());
  }
  @Test void oneAdministratorCannotSupplyTwoProofsOrClientRoleFlags() throws Exception {
    var request = restore(); assertThrows(IOException.class, () -> management.execute(request, List.of(proof(owner, request)))); assertThrows(IOException.class, () -> management.execute(request, List.of(proof(owner, request), proof(owner, request)))); assertEquals(0, commands.size());
  }
  @Test void modifiedSnapshotAndSwappedActionCannotReuseApproval() throws Exception {
    var request = restore(); var other = new ManagementPolicy.Request(request.id(), ManagementPolicy.Action.BACKUP_RESTORE, null, "b".repeat(64)); assertThrows(IOException.class, () -> management.execute(other, List.of(proof(owner, request), proof(delegate, request)))); assertEquals(0, commands.size());
  }
  @Test void revokedGenerationAndWrongServicePinDenyBeforeCommand() throws Exception {
    var request = restore(); long now = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); identity.login(delegate.session().accountId(), delegate.session().deviceId(), now, nonce, IdentityProtocol.sign(delegate.device().getPrivate(), IdentityProtocol.login(identity.audience(), delegate.session().accountId(), delegate.session().deviceId(), now, nonce)));
    assertThrows(IOException.class, () -> management.execute(request, List.of(proof(owner, request), proof(delegate, request)))); assertEquals(0, commands.size());
    var wrong = new IdentityRemoteAuthority(URI.create("http://127.0.0.1:" + http.port() + "/identity/v1"), pair().getPublic().getEncoded()); var ordinary = new ManagementPolicy.Request(UUID.randomUUID().toString(), ManagementPolicy.Action.STATUS, ManagementPolicy.Service.IDENTITY, ""); assertThrows(IOException.class, () -> wrong.authorize(proof(owner, ordinary), ordinary.action().permission(), ordinary.encode()));
  }
  @Test void fixedCommandGrammarRejectsShellUnitPathAndNonCanonicalMetadata() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> new ManagementPolicy.Request(UUID.randomUUID().toString(), ManagementPolicy.Action.BACKUP_RESTORE, null, "../root"));
    for (var service : ManagementPolicy.Service.values()) for (var action : List.of(ManagementPolicy.Action.STATUS, ManagementPolicy.Action.RESTART)) {
      var request = new ManagementPolicy.Request(UUID.randomUUID().toString(), action, service, ""); assertEquals(request, ManagementPolicy.decode(request.encode())); List<String> command = ManagementPolicy.command(request); assertTrue(ManagementPolicy.allowsCommand(command)); assertEquals("/usr/bin/systemctl", command.getFirst()); assertTrue(command.getLast().startsWith("aegis600-staging-")); assertFalse(command.contains("sh")); assertFalse(command.contains("aegis-relay.service"));
    }
    assertTrue(ManagementPolicy.allowsCommand(ManagementPolicy.command(restore())));
    assertFalse(ManagementPolicy.allowsCommand(List.of("/usr/bin/systemctl", "start", "--", "aegis-relay.service")));
    assertFalse(ManagementPolicy.allowsCommand(List.of("/usr/bin/systemctl", "--no-block", "start", "--", "aegis600-staging-restore@../root.service")));
    assertFalse(ManagementPolicy.allowsCommand(List.of("/usr/bin/systemctl", "set-environment", "LD_PRELOAD=/tmp/evil")));
    assertThrows(IOException.class, () -> ManagementService.runFixedProcess(List.of("/usr/bin/systemctl", "start", "--", "aegis-relay.service")));
    var request = restore(); assertThrows(IOException.class, () -> ManagementPolicy.decode(Arrays.copyOf(request.encode(), request.encode().length + 1)));
  }
  @Test void auditTamperBlocksReopenAndFailedIntentCannotBeSilentlyRetried() throws Exception {
    var request = new ManagementPolicy.Request(UUID.randomUUID().toString(), ManagementPolicy.Action.STATUS, ManagementPolicy.Service.IDENTITY, ""); management.execute(request, List.of(proof(owner, request))); management.close();
    try (var sql = java.sql.DriverManager.getConnection("jdbc:sqlite:" + home.resolve("management.sqlite")); var s = sql.createStatement()) { s.executeUpdate("UPDATE audit SET stage='FORGED' WHERE seq=1"); }
    assertThrows(IOException.class, () -> new ManagementService(home.resolve("management.sqlite"), managementAudit, remote::authorize, args -> new ManagementService.Result(0, "TEST"), Clock.systemUTC())); management = null;
  }
}
