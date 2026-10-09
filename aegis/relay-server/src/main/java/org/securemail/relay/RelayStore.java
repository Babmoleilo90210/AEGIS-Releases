package org.securemail.relay;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.sql.*;
import java.time.Clock;
import java.util.*;
import org.securemail.protocol.*;

/** Serialized database transactions. Fetch does not delete; authenticated ACK does. */
public final class RelayStore implements AutoCloseable {
  private final Connection db;
  private final RelayConfig config;
  private final Clock clock;

  public RelayStore(RelayConfig config, Clock clock) throws SQLException, IOException {
    this.config = config;
    this.clock = clock;
    Path parent = config.databasePath().toAbsolutePath().getParent();
    Files.createDirectories(parent);
    Files.setPosixFilePermissions(parent, PosixFilePermissions.fromString("rwx------"));
    if (Files.isSymbolicLink(config.databasePath()))
      throw new IOException("Symlink database is not allowed");
    db = DriverManager.getConnection("jdbc:sqlite:" + config.databasePath().toAbsolutePath());
    Files.setPosixFilePermissions(
        config.databasePath(), PosixFilePermissions.fromString("rw-------"));
    try (var s = db.createStatement()) {
      s.execute("PRAGMA journal_mode=DELETE");
      s.execute("PRAGMA synchronous=FULL");
      s.execute("PRAGMA secure_delete=ON");
      s.execute("PRAGMA foreign_keys=ON");
      s.execute("PRAGMA busy_timeout=5000");
      s.execute("PRAGMA auto_vacuum=INCREMENTAL");
      s.execute(
          "CREATE TABLE IF NOT EXISTS users(user_id TEXT PRIMARY KEY,nickname TEXT UNIQUE NOT"
              + " NULL,password_hash BLOB NOT NULL,password_salt BLOB NOT NULL,public_key BLOB NOT"
              + " NULL)");
      s.execute(
          "CREATE TABLE IF NOT EXISTS mailbox(message_id TEXT PRIMARY KEY,recipient_id TEXT NOT"
              + " NULL REFERENCES users(user_id),encrypted_payload BLOB NOT NULL,packet_digest BLOB"
              + " NOT NULL,created_at INTEGER NOT NULL,delivery_deadline INTEGER NOT NULL)");
      s.execute("CREATE INDEX IF NOT EXISTS mailbox_recipient ON mailbox(recipient_id,created_at)");
      s.execute(
          "CREATE TABLE IF NOT EXISTS receipts(message_id TEXT PRIMARY KEY,recipient_id TEXT NOT"
              + " NULL,packet_digest BLOB NOT NULL,delivery_deadline INTEGER NOT NULL)");
    }
    migratePublicData();cleanup();
  }
  private void migratePublicData()throws SQLException{
    db.setAutoCommit(false);
    try(var statement=db.createStatement()){
      statement.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY,applied_at INTEGER NOT NULL)");
      statement.execute("CREATE TABLE IF NOT EXISTS public_profiles(user_id TEXT PRIMARY KEY REFERENCES users(user_id),revision INTEGER NOT NULL,signed_payload BLOB NOT NULL)");
      statement.execute("CREATE TABLE IF NOT EXISTS contact_assertions(owner_id TEXT NOT NULL REFERENCES users(user_id),target_id TEXT NOT NULL REFERENCES users(user_id),revision INTEGER NOT NULL,signed_payload BLOB NOT NULL,PRIMARY KEY(owner_id,target_id))");
      try(var insert=db.prepareStatement("INSERT OR IGNORE INTO schema_migrations VALUES('public-data-v1',?)")){insert.setLong(1,clock.millis());insert.executeUpdate();}
      db.commit();
    }catch(SQLException failure){db.rollback();throw failure;}finally{db.setAutoCommit(true);}
  }
  public synchronized PublicProfile profile(String nickname)throws Exception{
    UserInfo owner=find(nickname);if(owner==null)throw new IOException("Unknown user");
    try(var q=db.prepareStatement("SELECT signed_payload FROM public_profiles WHERE user_id=?")){
      q.setString(1,owner.userId());try(var r=q.executeQuery()){if(!r.next())return null;try(var in=new DataInputStream(new ByteArrayInputStream(r.getBytes(1)))){var value=PublicProfile.read(in);Binary.end(in);return value;}}
    }
  }
  public synchronized void putProfile(UserInfo user,PublicProfile profile)throws Exception{
    if(!profile.userId().equals(user.userId())||!profile.nickname().equals(user.nickname())
        ||!MessageDigest.isEqual(profile.publicKey(),user.publicKey())||profile.revision()>clock.millis()+300000
        ||!Signatures.verify(user.publicKey(),profile.signingBytes(),profile.signature()))throw new IOException("Profile rejected");
    byte[] encoded=Binary.encode(profile::write);PublicProfile previous=profile(user.nickname());
    if(previous!=null){if(previous.revision()>profile.revision())throw new IOException("Profile replay");if(previous.revision()==profile.revision()){if(!Arrays.equals(Binary.encode(previous::write),encoded))throw new IOException("Profile revision conflict");return;}}
    try(var q=db.prepareStatement("INSERT INTO public_profiles VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET revision=excluded.revision,signed_payload=excluded.signed_payload")){
      q.setString(1,user.userId());q.setLong(2,profile.revision());q.setBytes(3,encoded);q.executeUpdate();
    }
  }
  public synchronized ContactAssertion assertion(String owner,String target)throws Exception{
    Limits.userId(owner);Limits.userId(target);
    try(var q=db.prepareStatement("SELECT signed_payload FROM contact_assertions WHERE owner_id=? AND target_id=?")){
      q.setString(1,owner);q.setString(2,target);try(var r=q.executeQuery()){if(!r.next())return null;try(var in=new DataInputStream(new ByteArrayInputStream(r.getBytes(1)))){var value=ContactAssertion.read(in);Binary.end(in);return value;}}
    }
  }
  public synchronized void putAssertion(UserInfo user,ContactAssertion assertion)throws Exception{
    if(!assertion.ownerId().equals(user.userId())||!MessageDigest.isEqual(user.publicKey(),assertion.publicKey())
        ||assertion.revision()>clock.millis()+300000||!Signatures.verify(user.publicKey(),assertion.signingBytes(),assertion.signature()))throw new IOException("Contact consent rejected");
    byte[] encoded=Binary.encode(assertion::write);var previous=assertion(user.userId(),assertion.targetId());
    if(previous!=null){if(previous.revision()>assertion.revision())throw new IOException("Contact replay");if(previous.revision()==assertion.revision()){if(!Arrays.equals(Binary.encode(previous::write),encoded))throw new IOException("Contact revision conflict");return;}}
    try(var q=db.prepareStatement("SELECT COUNT(*) FROM contact_assertions WHERE owner_id=?")){q.setString(1,user.userId());try(var r=q.executeQuery()){r.next();if(previous==null&&r.getLong(1)>=128)throw new IOException("Contact quota");}}
    try(var q=db.prepareStatement("INSERT INTO contact_assertions VALUES(?,?,?,?) ON CONFLICT(owner_id,target_id) DO UPDATE SET revision=excluded.revision,signed_payload=excluded.signed_payload")){
      q.setString(1,user.userId());q.setString(2,assertion.targetId());q.setLong(3,assertion.revision());q.setBytes(4,encoded);q.executeUpdate();
    }
  }

  public synchronized UserInfo register(String nickname, byte[] password, byte[] pub)
      throws Exception {
    String nick = Limits.nickname(nickname);
    if(!config.allowRegistration())throw new Rejection(2);
    if(!config.allowedNicknames().isEmpty()&&!config.allowedNicknames().contains(nick))throw new Rejection(3);
    if(find(nick)!=null)throw new Rejection(4);
    if(userCount()>=config.maxUsers())throw new Rejection(5);
    if(pub.length!=44)throw new Rejection(1);
    KeyFactory.getInstance("Ed25519")
        .generatePublic(new java.security.spec.X509EncodedKeySpec(pub));
    byte[] salt = Authentication.salt(), hash = Authentication.hash(password, salt);
    String id = Signatures.id(pub);
    try (var s = db.prepareStatement("INSERT INTO users VALUES(?,?,?,?,?)")) {
      s.setString(1, id);
      s.setString(2, nick);
      s.setBytes(3, hash);
      s.setBytes(4, salt);
      s.setBytes(5, pub);
      s.executeUpdate();
    } finally {
      Arrays.fill(hash, (byte) 0);
    }
    return new UserInfo(id, nick, pub, null);
  }

  public synchronized UserInfo login(String nickname, byte[] password) throws Exception {
    String nick = Limits.nickname(nickname);
    byte[] salt = new byte[16], expected = new byte[32];
    UserInfo result = null;
    try (var s = db.prepareStatement("SELECT * FROM users WHERE nickname=?")) {
      s.setString(1, nick);
      try (var r = s.executeQuery()) {
        if (r.next()) {
          salt = r.getBytes("password_salt");
          expected = r.getBytes("password_hash");
          result = readUser(r);
        }
      }
    }
    byte[] actual = Authentication.hash(password, salt);
    try {
      if (!MessageDigest.isEqual(actual, expected) || result == null)
        throw new Rejection(6);
      return result;
    } finally {
      Arrays.fill(actual, (byte) 0);
      Arrays.fill(expected, (byte) 0);
    }
  }

  private UserInfo readUser(ResultSet r) throws SQLException {
    return new UserInfo(
        r.getString("user_id"), r.getString("nickname"), r.getBytes("public_key"), null);
  }

  public synchronized UserInfo find(String nick) throws SQLException {
    try (var s =
        db.prepareStatement("SELECT user_id,nickname,public_key FROM users WHERE nickname=?")) {
      s.setString(1, Limits.nickname(nick));
      try (var r = s.executeQuery()) {
        return r.next() ? readUser(r) : null;
      }
    }
  }

  public synchronized void store(UserInfo sender, EncryptedPacket p) throws Exception {
    cleanup();
    long now = clock.millis();
    if (!sender.userId().equals(p.senderId())
        || !sender.nickname().equals(p.senderNickname())
        || !MessageDigest.isEqual(sender.publicKey(), p.senderPublicKey())
        || p.createdAt() > now + 300_000
        || p.deliveryDeadline() <= now
        || p.deliveryDeadline() - now > config.maxMessageAge() + 300_000
        || p.ciphertext().length > config.maxCiphertext()) throw new IOException("Packet rejected");
    byte[] digest = Signatures.digest(p);
    if (!Signatures.verify(sender.publicKey(), digest, p.signature()))
      throw new IOException("Signature rejected");
    for (String table : List.of("mailbox", "receipts"))
      try (var s =
          db.prepareStatement(
              "SELECT recipient_id,packet_digest FROM " + table + " WHERE message_id=?")) {
        s.setString(1, p.messageId());
        try (var r = s.executeQuery()) {
          if (r.next()) {
            if (!r.getString(1).equals(p.recipientId())
                || !MessageDigest.isEqual(r.getBytes(2), digest))
              throw new IOException("Message ID conflict");
            return;
          }
        }
      }
    byte[] encoded = PacketCodec.encode(p);
    if(Files.getFileStore(config.databasePath()).getUsableSpace() < 512L*1024*1024 + 3L*encoded.length)
      throw new IOException("Insufficient relay disk space");
    try (var s =
        db.prepareStatement(
            "SELECT COUNT(*),COALESCE(SUM(length(encrypted_payload)),0) FROM mailbox WHERE"
                + " recipient_id=?")) {
      s.setString(1, p.recipientId());
      try (var r = s.executeQuery()) {
        r.next();
        if (r.getLong(1) >= config.maxPendingPackets()
            || r.getLong(2) + encoded.length > config.maxPendingStoragePerUser())
          throw new IOException("Mailbox full");
      }
    }
    if (scalar("SELECT COUNT(*) FROM receipts") >= 8192L * config.maxUsers())
      throw new IOException("Receipt quota reached");
    try (var s = db.prepareStatement("INSERT INTO mailbox VALUES(?,?,?,?,?,?)")) {
      s.setString(1, p.messageId());
      s.setString(2, p.recipientId());
      s.setBytes(3, encoded);
      s.setBytes(4, digest);
      s.setLong(5, now);
      s.setLong(6, Math.min(p.deliveryDeadline(), now + config.maxMessageAge()));
      s.executeUpdate();
    }
  }

  public synchronized EncryptedPacket fetch(UserInfo recipient) throws Exception {
    cleanup();
    try (var s =
        db.prepareStatement(
            "SELECT encrypted_payload FROM mailbox WHERE recipient_id=? ORDER BY"
                + " created_at,message_id LIMIT 1")) {
      s.setString(1, recipient.userId());
      try (var r = s.executeQuery()) {
        return r.next() ? PacketCodec.decode(r.getBytes(1), config.maxCiphertext()) : null;
      }
    }
  }

  public synchronized void acknowledge(UserInfo recipient, Receipt ack) throws Exception {
    if (!Signatures.verify(recipient.publicKey(), ack.signingBytes(), ack.signature()))
      throw new IOException("ACK rejected");
    db.setAutoCommit(false);
    try {
      byte[] digest = null;
      long deadline = 0;
      try (var s =
          db.prepareStatement(
              "SELECT packet_digest,delivery_deadline FROM mailbox WHERE message_id=? AND"
                  + " recipient_id=?")) {
        s.setString(1, ack.messageId());
        s.setString(2, recipient.userId());
        try (var r = s.executeQuery()) {
          if (r.next()) {
            digest = r.getBytes(1);
            deadline = r.getLong(2);
          }
        }
      }
      if (digest == null) {
        try (var s =
            db.prepareStatement(
                "SELECT packet_digest FROM receipts WHERE message_id=? AND recipient_id=?")) {
          s.setString(1, ack.messageId());
          s.setString(2, recipient.userId());
          try (var r = s.executeQuery()) {
            if (!r.next() || !MessageDigest.isEqual(r.getBytes(1), ack.packetDigest()))
              throw new IOException("Unknown ACK");
          }
        }
      } else {
        if (!MessageDigest.isEqual(digest, ack.packetDigest()))
          throw new IOException("ACK digest mismatch");
        try (var s = db.prepareStatement("INSERT INTO receipts VALUES(?,?,?,?)")) {
          s.setString(1, ack.messageId());
          s.setString(2, recipient.userId());
          s.setBytes(3, digest);
          s.setLong(4, deadline);
          s.executeUpdate();
        }
        try (var s =
            db.prepareStatement("DELETE FROM mailbox WHERE message_id=? AND recipient_id=?")) {
          s.setString(1, ack.messageId());
          s.setString(2, recipient.userId());
          s.executeUpdate();
        }
      }
      db.commit();
    } catch (Exception e) {
      db.rollback();
      throw e;
    } finally {
      db.setAutoCommit(true);
    }
  }

  /** Recipient-owned discard, not an administrator read/export operation. */
  public synchronized void discard(UserInfo recipient, String id) throws SQLException {
    Limits.messageId(id);
    db.setAutoCommit(false);
    try {
      try (var s =
          db.prepareStatement(
              "INSERT OR IGNORE INTO receipts SELECT"
                  + " message_id,recipient_id,packet_digest,delivery_deadline FROM mailbox WHERE"
                  + " message_id=? AND recipient_id=?")) {
        s.setString(1, id);
        s.setString(2, recipient.userId());
        s.executeUpdate();
      }
      try (var s =
          db.prepareStatement("DELETE FROM mailbox WHERE message_id=? AND recipient_id=?")) {
        s.setString(1, id);
        s.setString(2, recipient.userId());
        s.executeUpdate();
      }
      db.commit();
    } catch (SQLException e) {
      db.rollback();
      throw e;
    } finally {
      db.setAutoCommit(true);
    }
  }

  public synchronized void cleanup() throws SQLException {
    for (String table : List.of("mailbox", "receipts"))
      try (var s = db.prepareStatement("DELETE FROM " + table + " WHERE delivery_deadline<=?")) {
        s.setLong(1, clock.millis());
        s.executeUpdate();
      }
    try (var s = db.createStatement()) {
      s.execute("PRAGMA incremental_vacuum(64)");
    }
  }

  private long scalar(String sql) throws SQLException {
    try (var s = db.createStatement();
        var r = s.executeQuery(sql)) {
      r.next();
      return r.getLong(1);
    }
  }

  public synchronized long userCount() throws SQLException {
    return scalar("SELECT COUNT(*) FROM users");
  }

  public synchronized long packetCount() throws SQLException {
    return scalar("SELECT COUNT(*) FROM mailbox");
  }

  public synchronized long pendingBytes() throws SQLException {
    return scalar("SELECT COALESCE(SUM(length(encrypted_payload)),0) FROM mailbox");
  }

  @Override
  public synchronized void close() throws SQLException {
    db.close();
  }
}
