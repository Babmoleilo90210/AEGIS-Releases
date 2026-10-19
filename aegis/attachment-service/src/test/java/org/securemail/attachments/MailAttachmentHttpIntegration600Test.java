package org.securemail.attachments;

import static org.junit.jupiter.api.Assertions.*;
import com.google.gson.*;
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
import org.securemail.attachments.protocol.AttachmentProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.ecosystem.protocol.IdentityProtocol.*;
import org.securemail.identity.*;
import org.securemail.client.attachments600.*;
import org.securemail.client.net.TorTransport;
import org.securemail.client.storage.LocalStore;
import org.securemail.client.crypto.AutomaticEncryption;
import org.securemail.client.crypto.LetterEnvelope;
import org.securemail.client.crypto.PlainMessage;
import org.securemail.protocol.*;

/** Actual Mail streaming manager + existing E2EE + local SOCKS/HTTP services. No Relay/public Tor/native claim. */
class MailAttachmentHttpIntegration600Test {
  @TempDir Path home;
  IdentityStore identity;IdentityHttpServer identityHttp;AttachmentStore objects;AttachmentHttpServer attachmentHttp;IdentityRemoteAuthority authority;
  KeyPair identityKey,attachmentKey;Account sender,recipient;LocalStore senderLocal,recipientLocal;
  record Account(KeyPair root, KeyPair device, KeyPair recovery, KeyPair app, IdentityStore.Session session, Capability capability) {}
  record Reply(int status, JsonObject metadata, byte[] payload) {}
  static KeyPair pair() throws Exception { return KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); }
  @BeforeEach void setup() throws Exception {
    identityKey = pair(); attachmentKey = pair(); byte[] audit = new byte[32]; new SecureRandom().nextBytes(audit); identity = new IdentityStore(home.resolve("identity.sqlite"), identityKey, audit, Clock.systemUTC());
    senderLocal=new org.securemail.client.storage.LocalStore(home.resolve("sender-mail"),"synthetic-vault-password".toCharArray(),Clock.systemUTC(),Limits.HARD_FILE_BYTES,1024L*1024*1024);recipientLocal=new org.securemail.client.storage.LocalStore(home.resolve("recipient-mail"),"synthetic-vault-password".toCharArray(),Clock.systemUTC(),Limits.HARD_FILE_BYTES,1024L*1024*1024);sender = account(senderLocal); recipient = account(recipientLocal); identityHttp = new IdentityHttpServer(new InetSocketAddress("127.0.0.1", 0), identity, identityKey); identityHttp.start();
    authority = new IdentityRemoteAuthority(URI.create("http://127.0.0.1:" + identityHttp.port() + "/identity/v1"), identityKey.getPublic().getEncoded()); objects = new AttachmentStore(home.resolve("objects"), Clock.systemUTC(), AttachmentStore.Quotas.defaults());
    attachmentHttp = new AttachmentHttpServer(new InetSocketAddress("127.0.0.1", 0), objects, authority::authorize, attachmentKey); attachmentHttp.start();
  }
  @AfterEach void close() throws Exception { if (attachmentHttp != null) attachmentHttp.close(); if (objects != null) objects.close(); if (identityHttp != null) identityHttp.close(); if (identity != null) identity.close();if(senderLocal!=null)senderLocal.close();if(recipientLocal!=null)recipientLocal.close(); }
  Account account(org.securemail.client.storage.LocalStore local) throws Exception {
    var factory=KeyFactory.getInstance("Ed25519");KeyPair root=new KeyPair(factory.generatePublic(new java.security.spec.X509EncodedKeySpec(local.identity().publicKey())),factory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(local.identity().privateKey()))), device = pair(), recovery = pair(), app = pair(); long now = System.currentTimeMillis(); String nonce = IdentityProtocol.nonce(); byte[] registration = IdentityProtocol.registration(identity.audience(), root.getPublic().getEncoded(), device.getPublic().getEncoded(), recovery.getPublic().getEncoded(), "Тест", now, nonce);
    var session = identity.register(root.getPublic().getEncoded(), device.getPublic().getEncoded(), recovery.getPublic().getEncoded(), "Тест", now, nonce, IdentityProtocol.sign(root.getPrivate(), registration), IdentityProtocol.sign(device.getPrivate(), registration));
    Set<Scope> scopes = EnumSet.of(Scope.MAIL_READ, Scope.MAIL_SEND); now = System.currentTimeMillis(); nonce = IdentityProtocol.nonce(); byte[] request = IdentityProtocol.capabilityRequest(identity.audience(), session.accountId(), session.deviceId(), session.generation(), App.MAIL, app.getPublic().getEncoded(), scopes, 600000, now, nonce);
    Capability cap = identity.issueCapability(session.accountId(), session.deviceId(), session.generation(), App.MAIL, app.getPublic().getEncoded(), scopes, 600000, now, nonce, IdentityProtocol.sign(device.getPrivate(), request), IdentityProtocol.sign(app.getPrivate(), request)); return new Account(root, device, recovery, app, session, cap);
  }
  private AttachmentClient600 client(Account account,SocksFixture socks)throws Exception{return new AttachmentClient600(new TorTransport("127.0.0.1",socks.port()),"a".repeat(56)+".onion",80,attachmentKey.getPublic().getEncoded(),identityKey.getPublic().getEncoded(),IdentityProtocol.encodeCapability(account.capability()),account.app().getPrivate());}
  private static MailAttachmentManager600.Remote remote(AttachmentClient600 client){return new MailAttachmentManager600.Remote(){public void upload(Path path,AttachmentClient600.RemoteFile f,java.util.function.BooleanSupplier active,AttachmentClient600.Progress progress)throws IOException{client.upload(path,f,active,progress);}public void download(AttachmentClient600.RemoteFile f,Path path,java.util.function.BooleanSupplier active,AttachmentClient600.Progress progress)throws IOException{client.download(f,path,active,progress);}public void abort(String id)throws IOException{client.abort(id);}public void close(){client.close();}};}
  private static String hash(Path file)throws Exception{MessageDigest digest=MessageDigest.getInstance("SHA-256");try(InputStream in=Files.newInputStream(file)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1)digest.update(b,0,n);}return HexFormat.of().formatHex(digest.digest());}
  private static void pace(long done,long total)throws IOException{try{Thread.sleep(160);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IOException(interrupted);}}
  private AttachmentFeatures600 feature(String audience)throws Exception{return AttachmentFeatures600.sign(recipientLocal.identity(),audience,org.securemail.client.crypto.Secrets.random(32),System.currentTimeMillis());}
  @Test void actualMailManagerFiveHundredMiBDurableResumeE2eeDescriptorAndDownload()throws Exception {
    long started=System.nanoTime(),size=StreamingAttachmentCipher.MAX_PLAINTEXT;Path source=home.resolve("Источник-500МиБ.bin"),destination=home.resolve("Получено-500МиБ.bin");
    try(OutputStream out=Files.newOutputStream(source)){byte[] bytes=new byte[65536];for(int i=0;i<bytes.length;i++)bytes[i]=(byte)(i*17+3);for(long left=size;left>0;left-=Math.min(left,bytes.length))out.write(bytes,0,(int)Math.min(left,bytes.length));}
    var contact=new UserInfo(recipientLocal.identity().userId(),"blackfox",recipientLocal.identity().publicKey(),null);String audience=IdentityProtocol.id(attachmentKey.getPublic().getEncoded());
    try(SocksFixture socks=new SocksFixture("a".repeat(56)+".onion",()->attachmentHttp.port())){
      try(var manager=new MailAttachmentManager600(senderLocal,audience,remote(client(sender,socks)),()->true)){
        assertThrows(IOException.class,()->manager.prepareVerified(contact,List.of(source),86400000,new char[0],new char[0],feature(audience),(done,total)->{if(done>=2L*1048576)throw new IOException("planned interruption");}));
      }
      // Both the manager vault queue and immutable server files survive a real close/reopen.
      senderLocal.close();senderLocal=new LocalStore(home.resolve("sender-mail"),"synthetic-vault-password".toCharArray(),Clock.systemUTC(),Limits.HARD_FILE_BYTES,1024L*1024*1024);assertEquals(sender.session().accountId(),senderLocal.identity().userId());
      attachmentHttp.close();objects.close();objects=new AttachmentStore(home.resolve("objects"),Clock.systemUTC(),AttachmentStore.Quotas.defaults());attachmentHttp=new AttachmentHttpServer(new InetSocketAddress("127.0.0.1",0),objects,authority::authorize,attachmentKey);attachmentHttp.start();
      try(var manager=new MailAttachmentManager600(senderLocal,audience,remote(client(sender,socks)),()->true);var receiver=new MailAttachmentManager600(recipientLocal,audience,remote(client(recipient,socks)),()->true);var manifest=manager.prepareVerified(contact,List.of(source),86400000,new char[0],new char[0],feature(audience),MailAttachmentHttpIntegration600Test::pace)){
        assertEquals(size,manifest.files().getFirst().context().plaintextBytes());assertFalse(manifest.protectedKeys());assertTrue(manifest.encode().length<4096);EncryptedPacket packet;
        var encryption=new AutomaticEncryption(Clock.systemUTC());try(var plain=PlainMessage.streaming("Потоковое вложение","Проверка реального файла",new byte[0],null,manifest.encode())){packet=encryption.encrypt(plain,86400,86400000,senderLocal.identity(),"raven",contact);}
        assertTrue(packet.ciphertext().length<8192);assertTrue(org.securemail.client.crypto.Identity.verifyPacket(packet));byte[] encoded=PacketCodec.encode(packet);senderLocal.writeExtension("out-"+packet.messageId(),encoded,Limits.HARD_FILE_BYTES+8192);senderLocal.saveSent(packet,contact.nickname(),0);Arrays.fill(encoded,(byte)0);manager.packetPersisted();
        try(var files=Files.list(senderLocal.root().resolve("attachment-spool6"))){assertEquals(0,files.count());}recipientLocal.trust(new UserInfo(senderLocal.identity().userId(),"raven",senderLocal.identity().publicKey(),null));recipientLocal.accept(packet);
        try(var opened=encryption.decrypt(packet,recipientLocal.identity(),Limits.HARD_FILE_BYTES);var decoded=AttachmentManifest600.decode(opened.streamingManifest())){
          assertTrue(opened.streamingAttachments());assertEquals("Проверка реального файла",opened.text());receiver.download(decoded,decoded.files().getFirst(),decoded.ordinaryCandidate(),sender.session().accountId(),destination,()->true,MailAttachmentHttpIntegration600Test::pace);assertEquals(size,Files.size(destination));assertEquals(hash(source),hash(destination));
        }
        assertTrue(Files.isRegularFile(source));assertFalse(manifest.toString().contains(manifest.ordinaryCandidate()));
      }
    }
    System.out.println("{\"scope\":\"actual-Mail-manager-500MiB-local-SOCKS-HTTP-Identity-E2EE-not-Relay-public-Tor\",\"plaintextBytes\":"+size+",\"heapMaxBytes\":"+Runtime.getRuntime().maxMemory()+",\"durationMillis\":"+((System.nanoTime()-started)/1000000)+"}");
  }
  @Test void protectedManagerDescriptorUsesExistingLetterPasswordAndFf1WithoutEarlyPlaintext()throws Exception {
    Path source=home.resolve("Защищённый.bin"),destination=home.resolve("Открытый.bin"),wrong=home.resolve("Неверный.bin");byte[] input=new byte[1048576+7];new Random(1).nextBytes(input);Files.write(source,input);var contact=new UserInfo(recipientLocal.identity().userId(),"blackfox",recipientLocal.identity().publicKey(),null);String audience=IdentityProtocol.id(attachmentKey.getPublic().getEncoded());char[] password="synthetic-letter-password".toCharArray(),code="12345678".toCharArray();
    try(SocksFixture socks=new SocksFixture("a".repeat(56)+".onion",()->attachmentHttp.port());var manager=new MailAttachmentManager600(senderLocal,audience,remote(client(sender,socks)),()->true);var receiver=new MailAttachmentManager600(recipientLocal,audience,remote(client(recipient,socks)),()->true);var manifest=manager.prepareVerified(contact,List.of(source),86400000,password,code,feature(audience),(done,total)->{})){
      assertTrue(manifest.protectedKeys());assertThrows(IOException.class,manifest::ordinaryCandidate);var encryption=new AutomaticEncryption(Clock.systemUTC());EncryptedPacket packet;byte[] letter=LetterEnvelope.seal("Защищённое письмо",password,code);
      try(var plain=PlainMessage.streaming("Проверка","",letter,null,manifest.encode())){packet=encryption.encrypt(plain,86400,86400000,senderLocal.identity(),"raven",contact);}finally{Arrays.fill(letter,(byte)0);}
      try(var opened=encryption.decrypt(packet,recipientLocal.identity(),Limits.HARD_FILE_BYTES);var decoded=AttachmentManifest600.decode(opened.streamingManifest());var unlock=LetterEnvelope.open(decoded.keyPayload(),password)){
        String incorrect=unlock.candidate("87654321".toCharArray());assertThrows(Exception.class,()->receiver.download(decoded,decoded.files().getFirst(),incorrect,sender.session().accountId(),wrong,()->true,(done,total)->{}));assertFalse(Files.exists(wrong));
        assertThrows(Exception.class,()->receiver.download(decoded,decoded.files().getFirst(),unlock.candidate(code),sender.session().accountId(),destination,()->false,(done,total)->{}));assertFalse(Files.exists(destination));
        receiver.download(decoded,decoded.files().getFirst(),unlock.candidate(code),sender.session().accountId(),destination,()->true,(done,total)->{});assertArrayEquals(input,Files.readAllBytes(destination));
      }
    }finally{Arrays.fill(password,'\0');Arrays.fill(code,'\0');Arrays.fill(input,(byte)0);}
  }
  @Test void multipleFilesCommitWithoutExhaustingConcurrentUploadSlotsAndRemainReopenable()throws Exception {
    List<Path> files=new ArrayList<>();for(int i=0;i<4;i++){Path path=home.resolve("Файл-"+i+".bin");byte[] content=new byte[65536+i];Arrays.fill(content,(byte)(i+1));Files.write(path,content);files.add(path);}
    var contact=new UserInfo(recipientLocal.identity().userId(),"blackfox",recipientLocal.identity().publicKey(),null);String audience=IdentityProtocol.id(attachmentKey.getPublic().getEncoded());
    try(SocksFixture socks=new SocksFixture("a".repeat(56)+".onion",()->attachmentHttp.port());var senderManager=new MailAttachmentManager600(senderLocal,audience,remote(client(sender,socks)),()->true);var receiver=new MailAttachmentManager600(recipientLocal,audience,remote(client(recipient,socks)),()->true);var manifest=senderManager.prepareVerified(contact,files,86400000,new char[0],new char[0],feature(audience),(done,total)->{})){
      assertEquals(4,manifest.files().size());assertEquals(4,objects.transferCount());long retained=objects.reservedBytes();assertTrue(retained>0);
      for(int i=0;i<4;i++){Path output=home.resolve("Получено-"+i+".bin");receiver.download(manifest,manifest.files().get(i),manifest.ordinaryCandidate(),sender.session().accountId(),output,()->true,(done,total)->{});assertEquals(hash(files.get(i)),hash(output));}
      Path repeated=home.resolve("Повторно.bin");receiver.download(manifest,manifest.files().getFirst(),manifest.ordinaryCandidate(),sender.session().accountId(),repeated,()->true,(done,total)->{});assertEquals(hash(files.getFirst()),hash(repeated));assertEquals(retained,objects.reservedBytes());assertEquals(4,objects.transferCount());
    }
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
