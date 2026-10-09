package org.securemail.client.storage;

import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.securemail.client.crypto.*;
import org.securemail.client.crypto.Identity;
import org.securemail.protocol.*;

/** Encrypted local state and mail files; never stores message plaintext. */
public final class LocalStore implements AutoCloseable {
  private static final int MAIL_MAGIC = 0x534d4c31;
  private final Path root, mail, sent;
  private final byte[] key;
  private final Clock clock;
  private final long anchorWall, anchorNanos = System.nanoTime();
  private final int maxCipher;
  private final long maxBytes;
  private final FileChannel lockChannel;
  private final FileLock lock;
  private final Map<String, UserInfo> contacts = new TreeMap<>();
  private final Map<String, Seen> seen = new HashMap<>();
  private Identity identity;
  private String nickname = "";
  private long lastWall;
  private boolean closed;
  private volatile long changeCounter;
  private volatile long avatarRevision;
  public long avatarRevision(){return avatarRevision;}
  private final ArrayDeque<DeliveryNotice> notices=new ArrayDeque<>();
  private final Set<String> expiredMetadata=new HashSet<>();
  public synchronized Set<String> drainExpiredMetadata(){var result=Set.copyOf(expiredMetadata);expiredMetadata.clear();return result;}
  public record DeliveryNotice(String id,String senderId){}
  public synchronized List<DeliveryNotice> drainNotices(){var result=List.copyOf(notices);notices.clear();return result;}
  public long changeCounter(){return changeCounter;}

  private record Seen(byte[] digest, long received, long deadline) {}

  private record Stored(long received, long expiry, EncryptedPacket packet) {}

  public record InboxItem(
      String messageId, String sender, Algorithm algorithm, long receivedAt, long expiresAt) {}

  public LocalStore(Path root, char[] password, Clock clock, int maxCipher, long maxBytes)
      throws IOException, GeneralSecurityException {
    this(root,password,null,clock,maxCipher,maxBytes);
  }
  public static LocalStore resume(Path root,byte[] key,Clock clock,int maxCipher,long maxBytes)throws IOException,GeneralSecurityException {
    if(key.length!=32||!Files.isRegularFile(root.resolve("state.vault"),LinkOption.NOFOLLOW_LINKS)||!modernVault(root))throw new IOException("Remembered vault unavailable");
    return new LocalStore(root,null,key,clock,maxCipher,maxBytes);
  }
  private LocalStore(Path root,char[] password,byte[] resumeKey,Clock clock,int maxCipher,long maxBytes)throws IOException,GeneralSecurityException {
    this.root = root.toAbsolutePath();
    mail = this.root.resolve("mail");
    sent = this.root.resolve("sent");
    this.clock = clock;
    this.maxCipher = maxCipher;
    this.maxBytes = maxBytes;
    anchorWall = clock.millis();
    AtomicFiles.directory(this.root);
    AtomicFiles.directory(mail);
    AtomicFiles.directory(sent);
    lockChannel =
        FileChannel.open(
            this.root.resolve("client.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
    FileLock acquired;
    try {
      acquired = lockChannel.tryLock();
    } catch (OverlappingFileLockException e) {
      lockChannel.close();
      throw new IOException("Хранилище уже открыто");
    }
    if (acquired == null) {
      lockChannel.close();
      throw new IOException("Хранилище уже открыто");
    }
    lock = acquired;
    byte[] derived = null;
    try {
      for (Path dir : List.of(this.root, mail, sent))
        try (var files = Files.newDirectoryStream(dir, ".atomic-*.tmp")) {
          for (Path f : files) Files.deleteIfExists(f);
        }
      Path salt = this.root.resolve("salt");
      if (!Files.exists(salt)) {
        if (Files.exists(this.root.resolve("state.vault")))
          throw new IOException("Missing vault salt");
        AtomicFiles.write(salt, Secrets.random(16));
      }
      if (!Files.exists(this.root.resolve("state.vault"))) AtomicFiles.write(this.root.resolve("vault-kdf"),"AEGIS-VAULT-v1\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
      derived = resumeKey!=null?resumeKey.clone():modernVault(this.root) ? Secrets.deriveVault(password, AtomicFiles.read(salt, 16)) : Secrets.derive(password, AtomicFiles.read(salt, 16));
      key = derived;
      if (Files.exists(this.root.resolve("state.vault"))) readState();
      else {
        identity = Identity.create();
        save();
      }
      if (clock.millis() < lastWall)
        for (Path folder : List.of(mail, sent)) try (var files = Files.newDirectoryStream(folder, "*.sm")) {
          for (Path f : files) Files.deleteIfExists(f);
        }
      cleanup();
    } catch (IOException | GeneralSecurityException | RuntimeException e) {
      if (derived != null) Arrays.fill(derived, (byte) 0);
      lock.release();
      lockChannel.close();
      throw e;
    }
  }

  public synchronized long now() {
    return Math.max(clock.millis(), anchorWall + (System.nanoTime() - anchorNanos) / 1_000_000);
  }

  public Identity identity() {
    return identity;
  }

  /** Only for OS-protected local session envelopes. Caller must wipe its defensive copy. */
  public synchronized byte[] sessionUnlockKey()throws IOException {ensureOpen();return key.clone();}
  private Path avatarPath(String nickname)throws GeneralSecurityException {
    String name=Limits.nickname(nickname);Path dir=root.resolve("avatars");return dir.resolve(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(name.getBytes(java.nio.charset.StandardCharsets.US_ASCII)))+".enc");
  }
  public synchronized void avatar(String nickname,byte[] png)throws IOException,GeneralSecurityException {
    ensureOpen();nickname=Limits.nickname(nickname);
    if(!nickname.equals(this.nickname))throw new IOException("Можно изменять только собственный аватар");
    Path path=avatarPath(nickname);AtomicFiles.directory(path.getParent());if(png==null){Files.deleteIfExists(path);avatarRevision++;return;}if(png.length>1024*1024)throw new IOException("Avatar too large");
    AtomicFiles.write(path,seal(png,("avatar/v1/"+nickname).getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    avatarRevision++;
  }
  public synchronized byte[] avatar(String nickname)throws IOException,GeneralSecurityException {
    ensureOpen();nickname=Limits.nickname(nickname);
    if(!nickname.equals(this.nickname)){var profile=cachedProfile(nickname);return profile==null||!profile.visible()||profile.avatar().length==0?null:AvatarCodec.normalize(profile.avatar());}
    Path path=avatarPath(nickname);if(!Files.exists(path))return null;return open(AtomicFiles.read(path,1024*1024+128),("avatar/v1/"+nickname).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
  }
  public synchronized byte[] readFeatures()throws IOException,GeneralSecurityException{
    ensureOpen();Path path=root.resolve("features-v1.vault");return Files.exists(path)?open(AtomicFiles.read(path,2*1024*1024+128),"features/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII)):null;
  }
  public synchronized void writeFeatures(byte[] data)throws IOException,GeneralSecurityException{
    ensureOpen();if(data.length>2*1024*1024)throw new IOException("Local feature quota");
    AtomicFiles.write(root.resolve("features-v1.vault"),seal(data,"features/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
  }
  public synchronized PublicProfile cachedProfile(String nick)throws IOException,GeneralSecurityException{
    UserInfo owner=nick.equals(nickname)?new UserInfo(identity.userId(),nickname,identity.publicKey(),null):contact(nick);if(owner==null)return null;
    Path path=root.resolve("profiles").resolve(owner.userId()+".enc");if(!Files.exists(path))return null;
    byte[] bytes=open(AtomicFiles.read(path,PublicProfile.MAX_ENCODED+128),("profile/v1/"+owner.userId()).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    try(var input=new DataInputStream(new ByteArrayInputStream(bytes))){var result=PublicProfile.read(input);Binary.end(input);verifyProfileOwner(owner,result);return result;}finally{Arrays.fill(bytes,(byte)0);}
  }
  private void verifyProfileOwner(UserInfo owner,PublicProfile profile)throws IOException,GeneralSecurityException{
    if(!profile.userId().equals(owner.userId())||!profile.nickname().equals(owner.nickname())||!MessageDigest.isEqual(profile.publicKey(),owner.publicKey())||!Identity.id(profile.publicKey()).equals(profile.userId())||!Identity.verify(owner.publicKey(),profile.signingBytes(),profile.signature()))throw new GeneralSecurityException("Profile identity mismatch");
  }
  /** Remote avatars only enter through a signed profile whose identity is already pinned. */
  public synchronized void cacheProfile(PublicProfile profile)throws IOException,GeneralSecurityException{
    ensureOpen();UserInfo owner=profile.nickname().equals(nickname)?new UserInfo(identity.userId(),nickname,identity.publicKey(),null):contact(profile.nickname());
    if(owner==null)throw new IOException("Verify contact before caching its profile");verifyProfileOwner(owner,profile);
    // A valid owner signature does not make an image decoder input trustworthy.
    byte[] avatar=profile.avatar();try{if(avatar.length!=0){byte[] checked=AvatarCodec.normalize(avatar);Arrays.fill(checked,(byte)0);}}finally{Arrays.fill(avatar,(byte)0);}
    var previous=cachedProfile(profile.nickname());if(previous!=null&&previous.revision()>profile.revision())throw new GeneralSecurityException("Profile replay");
    if(previous!=null&&previous.revision()==profile.revision()){
      if(!Arrays.equals(Binary.encode(previous::write),Binary.encode(profile::write)))throw new GeneralSecurityException("Profile revision conflict");return;
    }
    Path path=root.resolve("profiles").resolve(profile.userId()+".enc");AtomicFiles.directory(path.getParent());
    byte[] data=Binary.encode(profile::write);try{AtomicFiles.write(path,seal(data,("profile/v1/"+profile.userId()).getBytes(java.nio.charset.StandardCharsets.US_ASCII)));}finally{Arrays.fill(data,(byte)0);}
    avatarRevision++;
  }

  public synchronized String nickname() {
    return nickname;
  }

  public synchronized void bindNickname(String name) throws IOException, GeneralSecurityException {
    name = Limits.nickname(name);
    if (!nickname.isEmpty() && !nickname.equals(name))
      throw new IOException("Для другого аккаунта нужно отдельное хранилище");
    nickname = name;
    save();
  }

  public synchronized List<UserInfo> contacts() {
    return List.copyOf(contacts.values());
  }

  public synchronized UserInfo contact(String nick) {
    return contacts.get(Limits.nickname(nick));
  }

  public synchronized void trust(UserInfo user) throws IOException, GeneralSecurityException {
    if (!Identity.id(user.publicKey()).equals(user.userId())
        || user.userId().equals(identity.userId())) throw new IOException("Неверный контакт");
    UserInfo old = contacts.get(user.nickname());
    if (old != null && !old.userId().equals(user.userId()))
      throw new IOException("Ключ контакта изменился. Проверьте его заново.");
    if (old == null && contacts.size() >= 32) throw new IOException("Слишком много контактов");
    contacts.put(
        user.nickname(), new UserInfo(user.userId(), user.nickname(), user.publicKey(), null));
    save();
  }

  public synchronized void removeContact(String nick) throws IOException, GeneralSecurityException {
    contacts.remove(Limits.nickname(nick));
    Files.deleteIfExists(avatarPath(nick));
    save();
  }

  public synchronized Receipt accept(EncryptedPacket p)
      throws IOException, GeneralSecurityException {
    ensureOpen();
    long now = now();
    if (!p.recipientId().equals(identity.userId())
        || !Identity.verifyPacket(p)) throw new IOException("Недоверенный отправитель или подпись");
    if (p.deliveryDeadline() <= now || p.createdAt() > now + 300_000)
      throw new IOException("Срок доставки истёк или неверное время");
    byte[] digest = Identity.digest(p);
    Seen old = seen.get(p.messageId());
    if (old != null) {
      if (!MessageDigest.isEqual(old.digest(), digest))
        throw new IOException("Message ID conflict");
      return identity.receipt(p, old.received());
    }
    Path file = mail.resolve(p.messageId() + ".sm");
    if (Files.exists(file)) {
      Stored stored = readMail(file);
      if (!MessageDigest.isEqual(Identity.digest(stored.packet()), digest))
        throw new IOException("Message ID conflict");
      seen.put(p.messageId(), new Seen(digest, stored.received(), p.deliveryDeadline()));
      save();
      return identity.receipt(p, stored.received());
    }
    cleanup();
    byte[] packet = PacketCodec.encode(p);
    if (packet.length > maxCipher + 4096
        || usedBytes() + packet.length > maxBytes
        || seen.size() >= 8192) throw new IOException("Локальное хранилище заполнено");
    long expiry = Math.addExact(now, p.ttlAfterDelivery() * 1000);
    byte[] sealed = seal(packet, mailAad(p.messageId(), now, expiry));
    AtomicFiles.write(
        file,
        Binary.encode(
            out -> {
              out.writeInt(MAIL_MAGIC);
              out.writeLong(now);
              out.writeLong(expiry);
              Binary.bytes(out, sealed);
            }));
    seen.put(p.messageId(), new Seen(digest, now, p.deliveryDeadline()));
    save();
    changeCounter++;
    if(notices.size()<1024)notices.addLast(new DeliveryNotice(p.messageId(),p.senderId()));
    return identity.receipt(p, now); // File, state and containing directories have been fsynced.
  }

  private Stored readMail(Path file) throws IOException, GeneralSecurityException {
    try (var in =
        new DataInputStream(new ByteArrayInputStream(AtomicFiles.read(file, maxCipher + 8192)))) {
      if (in.readInt() != MAIL_MAGIC) throw new IOException("Corrupt local packet");
      long received = in.readLong(), expires = in.readLong();
      String id = file.getFileName().toString().replaceFirst("\\.sm$", "");
      Limits.messageId(id);
      byte[] opened = open(Binary.bytes(in, maxCipher + 4096), mailAad(id, received, expires));
      Binary.end(in);
      try {
        var p = PacketCodec.decode(opened, maxCipher);
        if (!p.messageId().equals(id)
            || expires != Math.addExact(received, p.ttlAfterDelivery() * 1000))
          throw new IOException("Invalid local deadline");
        return new Stored(received, expires, p);
      } finally {
        Arrays.fill(opened, (byte) 0);
      }
    }
  }

  public synchronized List<InboxItem> inbox() throws IOException, GeneralSecurityException {
    ensureOpen();
    cleanup();
    var result = new ArrayList<InboxItem>();
    try (var files = Files.newDirectoryStream(mail, "*.sm")) {
      for (Path f : files) {
        Stored s = readMail(f);
        var p = s.packet();
        result.add(
            new InboxItem(
                p.messageId(), p.senderNickname(), p.algorithm(), s.received(), s.expiry()));
      }
    }
    result.sort(Comparator.comparingLong(InboxItem::receivedAt).reversed());
    return result;
  }

  public synchronized EncryptedPacket load(String id) throws IOException, GeneralSecurityException {
    ensureOpen();
    Limits.messageId(id);
    cleanup();
    Stored s = readMail(mail.resolve(id + ".sm"));
    if (s.expiry() <= now()) throw new IOException("Письмо удалено");
    return s.packet();
  }

  public synchronized void delete(String id) throws IOException {
    Limits.messageId(id);
    Files.deleteIfExists(mail.resolve(id + ".sm"));
    AtomicFiles.syncDirectory(mail);
  }

  public synchronized void cleanup() throws IOException {
    expiredMetadata.addAll(cleanupExpiredFiles(root, now()));
    seen.entrySet().removeIf(e -> e.getValue().deadline() <= now());
  }

  /** The user timer can remove expired sealed packets without knowing the vault password. */
  public static void cleanupLockedFiles(Path root, long now) throws IOException {
    cleanupExpiredFiles(root,now);
  }
  private static Set<String> cleanupExpiredFiles(Path root,long now)throws IOException{
    Set<String> expiredIds=new HashSet<>();
    for (Path folder : List.of(root.resolve("mail"), root.resolve("sent"))) {
      if (!Files.isDirectory(folder)) continue;
      try (var files = Files.newDirectoryStream(folder, "*.sm")) {
        for (Path f : files) {
          if (Files.isSymbolicLink(f)) continue;
          boolean expired;
          try (var in = new DataInputStream(Files.newInputStream(f))) {
            if (in.readInt() != MAIL_MAGIC) continue;
            in.readLong(); expired = in.readLong() <= now;
          }
          if (expired&&Files.deleteIfExists(f)){expiredIds.add(f.getFileName().toString().replaceFirst("\\.sm$",""));} // Close first: Windows denies deleting an open file.
        }
      }
    }
    return expiredIds;
  }

  private long usedBytes() throws IOException {
    long n = 0;
    for (Path dir : List.of(mail, sent)) try (var files = Files.newDirectoryStream(dir, "*.sm")) {
      for (Path f : files) n += Files.size(f);
    }
    return n;
  }

  public record HistoryItem(String id, String contact, boolean outgoing, String status,
                            long time, long expiresAt, EncryptedPacket packet) {}

  /** A valid signature is independent of a previously verified contact binding. */
  public record SenderAssessment(boolean signatureValid,boolean inContacts,boolean keyMatches) {}
  public synchronized SenderAssessment assessSender(EncryptedPacket packet)throws IOException {
    ensureOpen();UserInfo known=contacts.get(packet.senderNickname());
    boolean matches=known!=null&&known.userId().equals(packet.senderId())
        &&MessageDigest.isEqual(known.publicKey(),packet.senderPublicKey());
    return new SenderAssessment(Identity.verifyPacket(packet),known!=null,matches);
  }

  private static byte[] sentAad(String id, long at, long expiry) throws IOException {
    return Binary.encode(o -> { Binary.text(o,"sent/v1"); Binary.text(o,id); o.writeLong(at); o.writeLong(expiry); });
  }

  public synchronized void saveSent(EncryptedPacket p, String contact, long confirmedAt)
      throws IOException, GeneralSecurityException {
    ensureOpen();
    if (!p.senderId().equals(identity.userId()) || !Identity.verifyPacket(p)) throw new IOException("Invalid outgoing packet");
    String nick = Limits.nickname(contact);
    long time=p.createdAt(), expiry=confirmedAt>0 ? Math.addExact(confirmedAt,p.ttlAfterDelivery()*1000) : Math.min(p.deliveryDeadline(),Math.addExact(p.createdAt(),p.ttlAfterDelivery()*1000));
    byte[] plain=Binary.encode(o->{ Binary.text(o,nick);o.writeBoolean(confirmedAt>0); PacketCodec.write(o,p); });
    try {
      if (usedBytes()+plain.length>maxBytes) throw new IOException("Локальное хранилище заполнено");
      byte[] encrypted=seal(plain,sentAad(p.messageId(),time,expiry));
      AtomicFiles.write(sent.resolve(p.messageId()+".sm"),Binary.encode(o->{o.writeInt(MAIL_MAGIC);o.writeLong(time);o.writeLong(expiry);Binary.bytes(o,encrypted);}));
      changeCounter++;
    } finally { Arrays.fill(plain,(byte)0); }
  }

  /** Metadata index only; do not keep all attachment packets in the GUI. */
  public record MailItem(String id,String contact,boolean outgoing,String status,long time,long expiresAt) {}
  public synchronized List<MailItem> mailboxIndex(boolean outgoing) throws IOException, GeneralSecurityException {
    ensureOpen();cleanup();var result=new ArrayList<MailItem>();
    if(!outgoing) for(var item:inbox()) result.add(new MailItem(item.messageId(),item.sender(),false,"Получено",item.receivedAt(),item.expiresAt()));
    else try(var files=Files.newDirectoryStream(sent,"*.sm")) {
      for(Path file:files) {var item=readSent(file);result.add(new MailItem(item.id(),item.contact(),true,item.status(),item.time(),item.expiresAt()));}
    }
    result.sort(Comparator.comparingLong(MailItem::time).reversed());return result;
  }
  private HistoryItem readSent(Path file) throws IOException,GeneralSecurityException {
    try(var in=new DataInputStream(new ByteArrayInputStream(AtomicFiles.read(file,maxCipher+8192)))) {
      if(in.readInt()!=MAIL_MAGIC)throw new IOException("Локальное хранилище повреждено");
      long time=in.readLong(),expiry=in.readLong();String id=file.getFileName().toString().replaceFirst("\\.sm$","");Limits.messageId(id);
      byte[] plain=open(Binary.bytes(in,maxCipher+4096),sentAad(id,time,expiry));Binary.end(in);
      try(var data=new DataInputStream(new ByteArrayInputStream(plain))) {
        String contact=Binary.text(data,32);boolean delivered=data.readBoolean();var packet=PacketCodec.read(data,maxCipher);Binary.end(data);
        if(!packet.messageId().equals(id))throw new IOException("Invalid local packet");
        return new HistoryItem(id,contact,true,delivered?"Доставлено":"На сервере · подтверждение недоступно",time,expiry,packet);
      }finally{Arrays.fill(plain,(byte)0);}
    }
  }
  public synchronized HistoryItem loadHistory(String id,boolean outgoing) throws IOException,GeneralSecurityException {
    Limits.messageId(id);ensureOpen();cleanup();
    if(outgoing){var item=readSent(sent.resolve(id+".sm"));if(item.expiresAt()<=now())throw new IOException("Письмо удалено");return item;}
    var stored=readMail(mail.resolve(id+".sm"));if(stored.expiry()<=now())throw new IOException("Письмо удалено");
    return new HistoryItem(id,stored.packet().senderNickname(),false,"Получено",stored.received(),stored.expiry(),stored.packet());
  }
  public synchronized List<HistoryItem> history(String contact) throws IOException,GeneralSecurityException {
    String nick=Limits.nickname(contact);var result=new ArrayList<HistoryItem>();
    for(boolean outgoing:new boolean[]{false,true})for(var item:mailboxIndex(outgoing))if(item.contact().equals(nick))result.add(loadHistory(item.id(),outgoing));
    result.sort(Comparator.comparingLong(HistoryItem::time));return result;
  }

  public synchronized void deleteHistory(String id, boolean outgoing) throws IOException {
    Limits.messageId(id); Path folder=outgoing?sent:mail;Files.deleteIfExists(folder.resolve(id+".sm"));AtomicFiles.syncDirectory(folder);
    changeCounter++;
  }

  public static boolean modernVault(Path root) throws IOException {
    Path marker=root.resolve("vault-kdf");if(!Files.exists(marker))return false;
    if(!Arrays.equals(AtomicFiles.read(marker,64),"AEGIS-VAULT-v1\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII)))throw new IOException("Unknown vault KDF");return true;
  }
  /** Copy and re-encrypt every vault file, preserving signed packets, ACKs and deadlines. */
  public synchronized void rekeyCopy(Path target,char[] accountPassword) throws Exception {
    ensureOpen();if(Files.exists(target))throw new IOException("Migration target exists");checkpoint();
    AtomicFiles.directory(target);AtomicFiles.directory(target.resolve("mail"));AtomicFiles.directory(target.resolve("sent"));
    byte[] salt=Secrets.random(16),next=Secrets.deriveVault(accountPassword,salt);
    try {
      AtomicFiles.write(target.resolve("salt"),salt);AtomicFiles.write(target.resolve("vault-kdf"),"AEGIS-VAULT-v1\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
      byte[] state=open(AtomicFiles.read(root.resolve("state.vault"),2*1024*1024),"state/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
      try{AtomicFiles.write(target.resolve("state.vault"),sealWith(next,state,"state/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));}finally{Arrays.fill(state,(byte)0);}
      for(Path folder:List.of(mail,sent))try(var files=Files.newDirectoryStream(folder,"*.sm")){
        for(Path path:files)try(var in=new DataInputStream(new ByteArrayInputStream(AtomicFiles.read(path,maxCipher+8192)))){
          if(in.readInt()!=MAIL_MAGIC)throw new IOException("Corrupt local packet");long at=in.readLong(),expires=in.readLong();String id=path.getFileName().toString().replaceFirst("\\.sm$","");Limits.messageId(id);
          byte[] aad=folder.equals(mail)?mailAad(id,at,expires):sentAad(id,at,expires);byte[] packet=open(Binary.bytes(in,maxCipher+4096),aad);Binary.end(in);
          try{byte[] sealed=sealWith(next,packet,aad);AtomicFiles.write(target.resolve(folder.getFileName()).resolve(path.getFileName()),Binary.encode(o->{o.writeInt(MAIL_MAGIC);o.writeLong(at);o.writeLong(expires);Binary.bytes(o,sealed);}));}finally{Arrays.fill(packet,(byte)0);}
        }
      }
      if(Files.isDirectory(root.resolve("avatars"))){
        AtomicFiles.directory(target.resolve("avatars"));Set<String> people=new HashSet<>(contacts.keySet());if(!nickname.isBlank())people.add(nickname);
        for(String person:people){byte[] pixels=avatar(person);if(pixels!=null)try{Path old=avatarPath(person);AtomicFiles.write(target.resolve("avatars").resolve(old.getFileName()),sealWith(next,pixels,("avatar/v1/"+person).getBytes(java.nio.charset.StandardCharsets.US_ASCII)));}finally{Arrays.fill(pixels,(byte)0);}}
      }
      byte[] features=readFeatures();if(features!=null)try{AtomicFiles.write(target.resolve("features-v1.vault"),sealWith(next,features,"features/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));}finally{Arrays.fill(features,(byte)0);}
      Path profiles=root.resolve("profiles");if(Files.isDirectory(profiles,LinkOption.NOFOLLOW_LINKS)){
        AtomicFiles.directory(target.resolve("profiles"));try(var files=Files.list(profiles)){
          for(Path file:files.toList()){
            String id=file.getFileName().toString().replaceFirst("\\.enc$","");Limits.userId(id);byte[] aad=("profile/v1/"+id).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] plain=open(AtomicFiles.read(file,PublicProfile.MAX_ENCODED+128),aad);try{AtomicFiles.write(target.resolve("profiles").resolve(file.getFileName()),sealWith(next,plain,aad));}finally{Arrays.fill(plain,(byte)0);}
          }
        }
      }
      AtomicFiles.write(target.resolve("client-version"),"1.0.0\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
      try(var verified=new LocalStore(target,accountPassword,clock,maxCipher,maxBytes)){
        if(!identity.userId().equals(verified.identity().userId())||!nickname.equals(verified.nickname())||!contacts.keySet().equals(verified.contacts.keySet())||!seen.keySet().equals(verified.seen.keySet()))throw new IOException("Migration verification failed");
        for(boolean outgoing:new boolean[]{false,true})for(var item:verified.mailboxIndex(outgoing))verified.loadHistory(item.id(),outgoing);
      }
    }finally{Arrays.fill(next,(byte)0);}
  }
  /** AEB2 adds the vault KDF marker; AEB1 remains importable. */
  public synchronized void exportIdentity(Path target) throws IOException, GeneralSecurityException {
    checkpoint();boolean modern=modernVault(root);byte[] backup=Binary.encode(o->{o.writeInt(modern?0x41454232:0x41454231);Binary.bytes(o,AtomicFiles.read(root.resolve("salt"),16));Binary.bytes(o,AtomicFiles.read(root.resolve("state.vault"),2*1024*1024));});
    try(var out=FileChannel.open(target,Set.of(StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE),AtomicFiles.exportAttributes(target.toAbsolutePath().getParent()))) {java.nio.ByteBuffer b=java.nio.ByteBuffer.wrap(backup);while(b.hasRemaining())out.write(b);out.force(true);}
  }
  public static void restoreIdentity(Path source, Path target, char[] password, int maxCipher, long maxBytes) throws Exception {
    if(Files.exists(target)) throw new IOException("Выберите новый каталог для восстановления");
    byte[] salt,state;boolean modern;
    try(var in=new DataInputStream(new ByteArrayInputStream(AtomicFiles.read(source,2*1024*1024+128)))) {
      int magic=in.readInt();if(magic!=0x41454231&&magic!=0x41454232)throw new IOException("Неверный формат резервной копии");modern=magic==0x41454232;
      salt=Binary.bytes(in,16);state=Binary.bytes(in,2*1024*1024);Binary.end(in);if(salt.length!=16)throw new IOException("Неверный формат резервной копии");
    }
    AtomicFiles.directory(target);AtomicFiles.write(target.resolve("salt"),salt);AtomicFiles.write(target.resolve("state.vault"),state);
    if(modern)AtomicFiles.write(target.resolve("vault-kdf"),"AEGIS-VAULT-v1\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    try(var verified=new LocalStore(target,password,Clock.systemUTC(),maxCipher,maxBytes)) {verified.checkpoint();}
  }

  private byte[] mailAad(String id, long received, long expiry) throws IOException {
    return Binary.encode(
        o -> {
          Binary.text(o, "mail/v1");
          Binary.text(o, id);
          o.writeLong(received);
          o.writeLong(expiry);
        });
  }

  private byte[] seal(byte[] plain, byte[] aad) throws GeneralSecurityException {
    return sealWith(key,plain,aad);
  }
  private static byte[] sealWith(byte[] key,byte[] plain,byte[] aad) throws GeneralSecurityException {
    byte[] nonce = Secrets.random(12);
    var c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
    c.updateAAD(aad);
    byte[] cipher = c.doFinal(plain), result = new byte[12 + cipher.length];
    System.arraycopy(nonce, 0, result, 0, 12);
    System.arraycopy(cipher, 0, result, 12, cipher.length);
    return result;
  }

  private byte[] open(byte[] sealed, byte[] aad) throws GeneralSecurityException {
    if (sealed.length < 28) throw new GeneralSecurityException("Invalid vault");
    var c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, sealed, 0, 12));
    c.updateAAD(aad);
    return c.doFinal(sealed, 12, sealed.length - 12);
  }

  public synchronized void checkpoint() throws IOException, GeneralSecurityException {
    ensureOpen();
    cleanup();
    save();
  }

  private void save() throws IOException, GeneralSecurityException {
    lastWall = now();
    byte[] secret = identity.privateKey();
    byte[] state =
        Binary.encode(
            o -> {
              o.writeInt(1);
              Binary.bytes(o, identity.publicKey());
              Binary.bytes(o, secret);
              Binary.text(o, nickname);
              o.writeLong(lastWall);
              o.writeInt(contacts.size());
              for (var u : contacts.values()) u.write(o);
              o.writeInt(seen.size());
              for (var e : seen.entrySet()) {
                Binary.text(o, e.getKey());
                Binary.bytes(o, e.getValue().digest());
                o.writeLong(e.getValue().received());
                o.writeLong(e.getValue().deadline());
              }
            });
    try {
      AtomicFiles.write(
          root.resolve("state.vault"),
          seal(state, "state/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    } finally {
      Arrays.fill(state, (byte) 0);
      Arrays.fill(secret, (byte) 0);
    }
  }

  private void readState() throws IOException, GeneralSecurityException {
    byte[] opened =
        open(
            AtomicFiles.read(root.resolve("state.vault"), 2 * 1024 * 1024),
            "state/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    try (var in = new DataInputStream(new ByteArrayInputStream(opened))) {
      if (in.readInt() != 1) throw new IOException("Bad vault version");
      byte[] pub = Binary.bytes(in, 44), secret = Binary.bytes(in, 128);
      try {
        identity = Identity.restore(pub, secret);
      } finally {
        Arrays.fill(secret, (byte) 0);
      }
      nickname = Binary.text(in, 32);
      lastWall = in.readLong();
      int n = in.readInt();
      if (n < 0 || n > 32) throw new IOException("Bad contacts");
      for (int i = 0; i < n; i++) {
        var u = UserInfo.read(in);
        contacts.put(u.nickname(), u);
      }
      n = in.readInt();
      if (n < 0 || n > 8192) throw new IOException("Bad dedup state");
      for (int i = 0; i < n; i++)
        seen.put(Binary.text(in, 36), new Seen(Binary.bytes(in, 32), in.readLong(), in.readLong()));
      Binary.end(in);
    } finally {
      Arrays.fill(opened, (byte) 0);
    }
  }

  private void ensureOpen() throws IOException {
    if (closed) throw new IOException("Хранилище закрыто");
  }

  @Override
  public synchronized void close() throws IOException {
    if (closed) return;
    try {
      save();
    } catch (GeneralSecurityException e) {
      throw new IOException("Could not seal state");
    } finally {
      closed = true;
      Arrays.fill(key, (byte) 0);
      identity = null;
      contacts.clear();
      seen.clear();
      lock.release();
      lockChannel.close();
    }
  }
}
