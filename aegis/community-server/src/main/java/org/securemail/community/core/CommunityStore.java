package org.securemail.community.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.time.Clock;
import java.util.*;

/** One serialized connection, FULL durable transactions, bounded persisted identity/nonce state.
 * Authorization and mutation MUST execute in the same tx to make revocation atomic. */
public final class CommunityStore implements AutoCloseable {
 @FunctionalInterface public interface SqlWork<T>{T run(Connection db)throws Exception;}
 private final Connection db; private final Clock clock; private int depth;private byte[]auditKey;private NotificationSink notifications;private String serviceIdentity;private List<SqlWork<?>>rollbackCallbacks;
 @FunctionalInterface public interface NotificationSink {void emit(String identity,String category,String title)throws Exception;}
 public synchronized void setNotificationSink(NotificationSink sink){notifications=Objects.requireNonNull(sink);}
 public void notifyAccount(String identity,String category,String title)throws Exception{Values.identity(identity);if(title.length()>240)throw CommunityException.invalid();if(notifications!=null)notifications.emit(identity,category,title);}
 public void notifyAdministrators(String category,String title)throws Exception{tx(c->{try(var q=c.createStatement();var r=q.executeQuery("SELECT identity FROM global_admins LIMIT 256")){while(r.next())notifyAccount(r.getString(1),category,title);}return null;});}
 public CommunityStore(Path file,Clock clock)throws Exception{
  this.clock=Objects.requireNonNull(clock);Path absolute=file.toAbsolutePath().normalize();
  if(Files.isSymbolicLink(absolute))throw new IOException("Symbolic database forbidden");
  Path parent=absolute.getParent();Files.createDirectories(parent);
  if(!parent.toRealPath().equals(parent))throw new IOException("Symbolic database parent forbidden");
  try{Files.setPosixFilePermissions(parent,PosixFilePermissions.fromString("rwx------"));}catch(UnsupportedOperationException ignored){}
  db=DriverManager.getConnection("jdbc:sqlite:"+absolute);
  try{Files.setPosixFilePermissions(absolute,PosixFilePermissions.fromString("rw-------"));}catch(UnsupportedOperationException ignored){}
  try(var s=db.createStatement()){
   s.execute("PRAGMA journal_mode=DELETE");s.execute("PRAGMA synchronous=FULL");s.execute("PRAGMA foreign_keys=ON");s.execute("PRAGMA secure_delete=ON");s.execute("PRAGMA busy_timeout=5000");
   for(String q:SCHEMA)s.execute(q);
  }
  if(!verifyAudit())throw new IOException("Administrative audit integrity rejected");
 }
 public CommunityStore(Path file)throws Exception{this(file,Clock.systemUTC());}
 public Clock clock(){return clock;}
 public synchronized void bindServiceIdentity(String identity)throws IOException{if(identity==null||!identity.matches("[a-f0-9]{64}")||serviceIdentity!=null&&!serviceIdentity.equals(identity))throw new IOException("Community service identity already bound or invalid");serviceIdentity=identity;}
 public synchronized String serviceIdentity()throws CommunityException{if(serviceIdentity==null)throw new CommunityException("FACTOR_UNCONFIGURED","Криптографическая идентичность сервиса не настроена");return serviceIdentity;}
 public synchronized void setAuditKey(byte[]key)throws Exception{if(key.length!=32)throw new IllegalArgumentException("Audit key length");if(auditKey!=null)Arrays.fill(auditKey,(byte)0);auditKey=key.clone();if(!verifyAudit())throw new IOException("Authenticated administrative audit integrity rejected");}
 private String auditMac(String digest)throws Exception{var mac=javax.crypto.Mac.getInstance("HmacSHA256");mac.init(new javax.crypto.spec.SecretKeySpec(auditKey,"HmacSHA256"));return hex(mac.doFinal(digest.getBytes(StandardCharsets.US_ASCII)));}
 public synchronized <T>T tx(SqlWork<T> work)throws Exception{
  if(depth>0){depth++;try{return work.run(db);}finally{depth--;}}
  db.setAutoCommit(false);depth=1;List<SqlWork<?>>callbacks=new ArrayList<>();rollbackCallbacks=callbacks;
  try{T value=work.run(db);db.commit();return value;}catch(Exception|Error e){db.rollback();depth=0;db.setAutoCommit(true);rollbackCallbacks=null;for(SqlWork<?>callback:callbacks)try{tx(c->{callback.run(c);return null;});}catch(Exception persistenceFailure){e.addSuppressed(persistenceFailure);}throw e;}finally{depth=0;rollbackCallbacks=null;db.setAutoCommit(true);}
 }
 /** Security attempt counters must survive an enclosing HTTP transaction rollback. */
 public synchronized void persistAfterRollback(SqlWork<?>work)throws Exception{if(depth>0){if(rollbackCallbacks==null||rollbackCallbacks.size()>=32)throw new IllegalStateException("Rollback callback bound");rollbackCallbacks.add(work);}else tx(c->{work.run(c);return null;});}

 public String ensureIdentity(byte[] encoded,String nickname)throws Exception{
  if(encoded.length!=44||nickname==null||nickname.length()>64)throw CommunityException.invalid();
  PublicKey parsed=KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));if(!MessageDigest.isEqual(parsed.getEncoded(),encoded))throw CommunityException.invalid();String identity=hex(hash(encoded));
  return tx(c->{try(var q=c.prepareStatement("SELECT public_key FROM identities WHERE identity=?")){q.setString(1,identity);try(var r=q.executeQuery()){if(r.next()){if(!MessageDigest.isEqual(encoded,r.getBytes(1)))throw CommunityException.denied();return identity;}}}
   if(count(c,"identities")>=1000000)throw new CommunityException("LIMIT","Достигнут предел пользователей");
   try(var q=c.prepareStatement("INSERT INTO identities(identity,public_key,nickname) VALUES(?,?,?)")){q.setString(1,identity);q.setBytes(2,encoded);q.setString(3,nickname);q.executeUpdate();}return identity;});
 }
 public void consumeNonce(String identity,String nonce,long expires)throws Exception{
  Values.identity(identity);if(nonce==null||!nonce.matches("[A-Za-z0-9_-]{22,86}")||expires<clock.millis()||expires>clock.millis()+600000)throw CommunityException.invalid();
  tx(c->{try(var d=c.prepareStatement("DELETE FROM request_nonces WHERE expires<?")){d.setLong(1,clock.millis());d.executeUpdate();}
   try(var q=c.prepareStatement("SELECT count(*) FROM request_nonces WHERE identity=?")){q.setString(1,identity);try(var r=q.executeQuery()){r.next();if(r.getInt(1)>=2048)throw new CommunityException("RATE_LIMIT","Слишком много запросов");}}
   try(var q=c.prepareStatement("INSERT INTO request_nonces VALUES(?,?,?)")){q.setString(1,identity);q.setString(2,nonce);q.setLong(3,expires);try{q.executeUpdate();}catch(SQLException e){throw new CommunityException("REPLAY","Повторный запрос отклонён");}}return null;});
 }
 public void audit(Connection c,String actor,String action,String target,String details)throws Exception{
  if(details.length()>8192)throw CommunityException.invalid();
  String prev="0".repeat(64);long seq=1;
  try(var q=c.createStatement();var r=q.executeQuery("SELECT seq,digest FROM audit ORDER BY seq DESC LIMIT 1")){if(r.next()){seq=r.getLong(1)+1;prev=r.getString(2);}}
  long time=clock.millis();String digest=auditHash(seq,time,actor,action,target,details,prev);
  try(var q=c.prepareStatement("INSERT INTO audit VALUES(?,?,?,?,?,?,?,?)")){q.setLong(1,seq);q.setLong(2,time);q.setString(3,actor);q.setString(4,action);q.setString(5,target);q.setString(6,details);q.setString(7,prev);q.setString(8,digest);q.executeUpdate();}
  if(auditKey!=null)try(var q=c.prepareStatement("INSERT INTO audit_auth VALUES(?,?)")){q.setLong(1,seq);q.setString(2,auditMac(digest));q.executeUpdate();}
 }
 public boolean verifyAudit()throws Exception{return tx(c->{String prev="0".repeat(64);long seq=0;try(var q=c.createStatement();var r=q.executeQuery("SELECT * FROM audit ORDER BY seq")){while(r.next()){if(r.getLong("seq")!=++seq||!prev.equals(r.getString("previous")))return false;String h=auditHash(seq,r.getLong("created"),r.getString("actor"),r.getString("action"),r.getString("target"),r.getString("details"),prev);if(!h.equals(r.getString("digest")))return false;if(auditKey!=null){try(var a=c.prepareStatement("SELECT mac FROM audit_auth WHERE seq=?")){a.setLong(1,seq);try(var z=a.executeQuery()){if(!z.next()||!MessageDigest.isEqual(auditMac(h).getBytes(StandardCharsets.US_ASCII),z.getString(1).getBytes(StandardCharsets.US_ASCII)))return false;}}}prev=h;}}return true;});}
 private static String auditHash(long seq,long time,String actor,String action,String target,String details,String prev)throws Exception{
  var out=new java.io.ByteArrayOutputStream();try(var d=new java.io.DataOutputStream(out)){d.writeUTF("AEGIS-COMMUNITY-AUDIT-v1");d.writeLong(seq);d.writeLong(time);for(String s:List.of(actor,action,target,details,prev)){byte[] b=s.getBytes(StandardCharsets.UTF_8);d.writeInt(b.length);d.write(b);}}return hex(hash(out.toByteArray()));
 }
 public static byte[] hash(byte[] value)throws NoSuchAlgorithmException{return MessageDigest.getInstance("SHA-256").digest(value);}
 public static String hex(byte[] value){return HexFormat.of().formatHex(value);}
 public static long count(Connection c,String table)throws SQLException{if(!Set.of("identities","roles","organizations","org_applications","critical_requests").contains(table))throw new IllegalArgumentException();try(var s=c.createStatement();var r=s.executeQuery("SELECT count(*) FROM "+table)){r.next();return r.getLong(1);}}
 public void bumpEpoch(Connection c)throws SQLException{try(var q=c.createStatement()){q.executeUpdate("UPDATE identities SET epoch=epoch+1");}}
 public void bumpEpoch(Connection c,String identity)throws SQLException{try(var q=c.prepareStatement("UPDATE identities SET epoch=epoch+1 WHERE identity=?")){q.setString(1,identity);q.executeUpdate();}}
 public void bumpRoleEpoch(Connection c,String role)throws SQLException{try(var q=c.prepareStatement("WITH RECURSIVE descendants(id) AS (SELECT ? UNION SELECT p.role FROM role_parents p JOIN descendants d ON p.parent=d.id) UPDATE identities SET epoch=epoch+1 WHERE identity IN (SELECT a.identity FROM assignments a JOIN descendants d ON d.id=a.role UNION SELECT a.identity FROM role_restrictions a JOIN descendants d ON d.id=a.role)")){q.setString(1,role);q.executeUpdate();}}
 public void revokeStepUp(Connection c,String identity)throws SQLException{try(var q=c.prepareStatement("DELETE FROM stepup_tokens WHERE identity=?")){q.setString(1,identity);q.executeUpdate();}try(var q=c.prepareStatement("DELETE FROM stepup_challenges WHERE identity=?")){q.setString(1,identity);q.executeUpdate();}}
 @Override public synchronized void close()throws SQLException{if(auditKey!=null)Arrays.fill(auditKey,(byte)0);db.close();}
 private static final List<String>SCHEMA=List.of(
 "CREATE TABLE IF NOT EXISTS identities(identity TEXT PRIMARY KEY,public_key BLOB NOT NULL,nickname TEXT NOT NULL,clearance INTEGER NOT NULL DEFAULT 0,epoch INTEGER NOT NULL DEFAULT 1)",
 "CREATE TABLE IF NOT EXISTS global_admins(identity TEXT PRIMARY KEY REFERENCES identities(identity),created INTEGER NOT NULL)",
 "CREATE TABLE IF NOT EXISTS access_levels(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,rank INTEGER NOT NULL UNIQUE,revision INTEGER NOT NULL DEFAULT 1)",
 "CREATE TABLE IF NOT EXISTS roles(id TEXT PRIMARY KEY,scope TEXT NOT NULL,name TEXT NOT NULL,clearance INTEGER NOT NULL DEFAULT 0,revision INTEGER NOT NULL DEFAULT 1,UNIQUE(scope,name))",
 "CREATE TABLE IF NOT EXISTS role_permissions(role TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,permission TEXT NOT NULL,PRIMARY KEY(role,permission))",
 "CREATE TABLE IF NOT EXISTS role_denials(role TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,permission TEXT NOT NULL,PRIMARY KEY(role,permission))",
 "CREATE TABLE IF NOT EXISTS role_parents(role TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,parent TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,PRIMARY KEY(role,parent),CHECK(role<>parent))",
 "CREATE TABLE IF NOT EXISTS assignments(identity TEXT NOT NULL REFERENCES identities(identity),role TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,PRIMARY KEY(identity,role))",
 "CREATE TABLE IF NOT EXISTS role_restrictions(identity TEXT NOT NULL REFERENCES identities(identity),role TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,PRIMARY KEY(identity,role))",
 "CREATE INDEX IF NOT EXISTS role_restrictions_role ON role_restrictions(role,identity)",
 "INSERT OR IGNORE INTO role_restrictions(identity,role) SELECT identity,role FROM assignments",
 "CREATE TRIGGER IF NOT EXISTS assigned_role_restriction AFTER INSERT ON assignments BEGIN INSERT OR IGNORE INTO role_restrictions(identity,role) VALUES(NEW.identity,NEW.role); END",
 "CREATE INDEX IF NOT EXISTS roles_scope ON roles(scope,id)",
 "CREATE INDEX IF NOT EXISTS role_parent_parent ON role_parents(parent,role)",
 "CREATE INDEX IF NOT EXISTS assignments_role ON assignments(role,identity)",
 "CREATE TABLE IF NOT EXISTS org_applications(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES identities(identity),name TEXT NOT NULL,description TEXT NOT NULL,purpose TEXT NOT NULL,city TEXT NOT NULL,emblem BLOB NOT NULL,join_policy TEXT NOT NULL,status TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,created INTEGER NOT NULL)",
 "CREATE TABLE IF NOT EXISTS organizations(id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT NOT NULL,city TEXT NOT NULL,emblem BLOB NOT NULL,join_policy TEXT NOT NULL,owner TEXT NOT NULL REFERENCES identities(identity),revision INTEGER NOT NULL DEFAULT 1)",
 "CREATE TABLE IF NOT EXISTS org_delegations(org TEXT NOT NULL REFERENCES organizations(id),permission TEXT NOT NULL,PRIMARY KEY(org,permission))",
 "CREATE TABLE IF NOT EXISTS memberships(org TEXT NOT NULL REFERENCES organizations(id),identity TEXT NOT NULL REFERENCES identities(identity),created INTEGER NOT NULL,PRIMARY KEY(org,identity))",
 "CREATE INDEX IF NOT EXISTS membership_identity ON memberships(identity,org)",
 "CREATE TABLE IF NOT EXISTS org_join_requests(org TEXT NOT NULL REFERENCES organizations(id),identity TEXT NOT NULL REFERENCES identities(identity),created INTEGER NOT NULL,PRIMARY KEY(org,identity))",
 "CREATE TABLE IF NOT EXISTS org_invitations(org TEXT NOT NULL REFERENCES organizations(id),identity TEXT NOT NULL REFERENCES identities(identity),expires INTEGER NOT NULL,PRIMARY KEY(org,identity))",
 "CREATE TABLE IF NOT EXISTS verifications(id TEXT PRIMARY KEY,subject TEXT NOT NULL REFERENCES identities(identity),kind TEXT NOT NULL,value TEXT NOT NULL,basis TEXT NOT NULL,issuer TEXT NOT NULL,created INTEGER NOT NULL,revoked INTEGER,revoker TEXT,revoke_basis TEXT)",
 "CREATE INDEX IF NOT EXISTS verification_subject ON verifications(subject,created)",
 "CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY,created INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,details TEXT NOT NULL,previous TEXT NOT NULL,digest TEXT NOT NULL)",
 "CREATE TABLE IF NOT EXISTS audit_auth(seq INTEGER PRIMARY KEY REFERENCES audit(seq),mac TEXT NOT NULL)",
 "CREATE TABLE IF NOT EXISTS stepup_attempts(identity TEXT PRIMARY KEY REFERENCES identities(identity),window INTEGER NOT NULL,failures INTEGER NOT NULL,blocked_until INTEGER NOT NULL)",
 "CREATE TABLE IF NOT EXISTS request_nonces(identity TEXT NOT NULL REFERENCES identities(identity),nonce TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(identity,nonce))",
 "CREATE INDEX IF NOT EXISTS nonce_expiry ON request_nonces(expires)",
 "CREATE TABLE IF NOT EXISTS second_factors(identity TEXT PRIMARY KEY REFERENCES identities(identity),nonce BLOB NOT NULL,ciphertext BLOB NOT NULL,last_counter INTEGER NOT NULL,version INTEGER NOT NULL DEFAULT 1)",
 "CREATE TABLE IF NOT EXISTS factor_enrollment(identity TEXT PRIMARY KEY REFERENCES identities(identity),enrollment_id TEXT NOT NULL UNIQUE,nonce BLOB NOT NULL,ciphertext BLOB NOT NULL,expires INTEGER NOT NULL)",
 "CREATE TABLE IF NOT EXISTS stepup_challenges(challenge TEXT PRIMARY KEY,identity TEXT NOT NULL REFERENCES identities(identity),expires INTEGER NOT NULL)",
 "CREATE TABLE IF NOT EXISTS stepup_tokens(token_hash TEXT PRIMARY KEY,identity TEXT NOT NULL REFERENCES identities(identity),expires INTEGER NOT NULL,epoch INTEGER NOT NULL)",
 "CREATE TABLE IF NOT EXISTS critical_requests(id TEXT PRIMARY KEY,kind TEXT NOT NULL,payload TEXT NOT NULL,digest TEXT NOT NULL,initiator TEXT NOT NULL REFERENCES identities(identity),approver TEXT REFERENCES identities(identity),expires INTEGER NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1)",
 "CREATE INDEX IF NOT EXISTS critical_pending ON critical_requests(state,expires)",
 "CREATE INDEX IF NOT EXISTS applications_owner ON org_applications(owner,status,created)",
 "CREATE TABLE IF NOT EXISTS community_schema(version INTEGER PRIMARY KEY,applied INTEGER NOT NULL)",
 "INSERT OR IGNORE INTO community_schema VALUES(1,0)"
 );
}
