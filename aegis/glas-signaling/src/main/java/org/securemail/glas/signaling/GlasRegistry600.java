package org.securemail.glas.signaling;

import com.google.gson.*;
import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.sql.*;
import java.time.Clock;
import java.util.*;
import org.securemail.attachments.*;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.glas.protocol600.GlasProtocol600;

/** Expiring, contact-only onion registry. No audio, media offer, account private key or call history. */
public final class GlasRegistry600 implements AutoCloseable {
  private final Connection db;private final FileChannel lockChannel;private final FileLock lock;
  private final IdentityRemoteAuthority identity;private final byte[] identityPublic;private final String serviceAudience;
  private final Clock clock;private final int capacity;private long wallFloor,anchorWall,anchorNano;
  public GlasRegistry600(Path directory,IdentityRemoteAuthority identity,byte[] identityPublic,byte[] servicePublic,Clock clock,int capacity)throws IOException,SQLException {
    if(capacity<1||capacity>10000)throw new IllegalArgumentException("Лимит регистраций");this.capacity=capacity;this.identity=Objects.requireNonNull(identity);IdentityProtocol.publicKey(identityPublic);IdentityProtocol.publicKey(servicePublic);this.identityPublic=identityPublic.clone();serviceAudience=IdentityProtocol.id(servicePublic);this.clock=Objects.requireNonNull(clock);
    directory=directory.toAbsolutePath().normalize();if(!Files.isDirectory(directory,LinkOption.NOFOLLOW_LINKS)||!directory.toRealPath().equals(directory)||Files.getPosixFilePermissions(directory).stream().anyMatch(p->p.name().startsWith("GROUP_")||p.name().startsWith("OTHERS_")))throw denied();
    Path lockPath=directory.resolve("registry.lock"),database=directory.resolve("registry.sqlite");
    for(Path p:List.of(lockPath,database))if(Files.exists(p,LinkOption.NOFOLLOW_LINKS)&&!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS))throw denied();
    lockChannel=FileChannel.open(lockPath,StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);Files.setPosixFilePermissions(lockPath,PosixFilePermissions.fromString("rw-------"));FileLock candidate;
    try{candidate=lockChannel.tryLock();if(candidate==null)throw denied();}catch(IOException|OverlappingFileLockException failure){lockChannel.close();throw denied();}lock=candidate;
    Connection connection=null;
    try {
      connection=DriverManager.getConnection("jdbc:sqlite:"+database);db=connection;Files.setPosixFilePermissions(database,PosixFilePermissions.fromString("rw-------"));
      try(Statement s=db.createStatement()){s.execute("PRAGMA journal_mode=DELETE");s.execute("PRAGMA synchronous=FULL");s.execute("PRAGMA secure_delete=ON");s.execute("PRAGMA busy_timeout=3000");s.execute("CREATE TABLE IF NOT EXISTS registrations(account TEXT PRIMARY KEY,capability TEXT NOT NULL,request BLOB NOT NULL,issued INTEGER NOT NULL,expires INTEGER NOT NULL)");s.execute("CREATE INDEX IF NOT EXISTS registration_expiry ON registrations(expires)");s.execute("CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),wall_floor INTEGER NOT NULL)");s.execute("INSERT OR IGNORE INTO settings VALUES(1,0)");}
      try(Statement s=db.createStatement();ResultSet r=s.executeQuery("SELECT wall_floor FROM settings WHERE id=1")){r.next();wallFloor=r.getLong(1);}
      if(clock.millis()<wallFloor-1000)throw denied();anchorWall=Math.max(clock.millis(),wallFloor);anchorNano=System.nanoTime();cleanup(256);
    }catch(IOException|SQLException|RuntimeException failure){if(connection!=null)connection.close();lock.release();lockChannel.close();throw failure;}
  }
  public synchronized JsonObject execute(GlasProtocol600.Request request,IdentityRemoteAuthority.Proof proof)throws IOException,SQLException {
    byte[] body=request.encode();var authorization=identity.authorize(proof,"glas.call",body);var cap=IdentityProtocol.decodeCapability(proof.capability());
    if(cap.appId!=IdentityProtocol.App.GLAS||!cap.capabilities.contains(IdentityProtocol.Scope.VOICE_CALL)||authorization.context().appId!=IdentityProtocol.App.GLAS)throw denied();authorization.check();long now=now();cleanup(128);
    JsonObject result=new JsonObject();
    switch(request.command){
      case REGISTER -> {
        if(!GlasProtocol600.verifyDelegation(request.delegation,cap,identityPublic,now)||!request.endpoint.verify(serviceAudience,request.delegation,now)||request.endpoint.expiresAt>cap.expiresAt||request.incoming.contains(cap.accountId)||request.outgoing.contains(cap.accountId))throw denied();
        long prior=-1;try(PreparedStatement q=db.prepareStatement("SELECT issued FROM registrations WHERE account=?")){q.setString(1,cap.accountId);try(ResultSet r=q.executeQuery()){if(r.next())prior=r.getLong(1);}}
        if(prior>request.endpoint.issuedAt)throw denied();
        if(prior<0)try(Statement q=db.createStatement();ResultSet r=q.executeQuery("SELECT COUNT(*) FROM registrations")){r.next();if(r.getInt(1)>=capacity)throw denied();}
        authorization.check();try(PreparedStatement s=db.prepareStatement("INSERT INTO registrations(account,capability,request,issued,expires) VALUES(?,?,?,?,?) ON CONFLICT(account) DO UPDATE SET capability=excluded.capability,request=excluded.request,issued=excluded.issued,expires=excluded.expires")){s.setString(1,cap.accountId);s.setString(2,proof.capability());s.setBytes(3,body);s.setLong(4,request.endpoint.issuedAt);s.setLong(5,request.endpoint.expiresAt);s.executeUpdate();}result.addProperty("registered",true);result.addProperty("expiresAt",request.endpoint.expiresAt);
      }
      case UNREGISTER -> {authorization.check();try(PreparedStatement s=db.prepareStatement("DELETE FROM registrations WHERE account=?")){s.setString(1,cap.accountId);s.executeUpdate();}result.addProperty("unregistered",true);}
      case LOOKUP -> {
        if(request.targetId.equals(cap.accountId))throw denied();Row caller=row(cap.accountId),target=row(request.targetId);
        if(caller==null||target==null||caller.request.endpoint.expiresAt<=now||target.request.endpoint.expiresAt<=now||!MessageDigest.isEqual(request.targetRoot(),target.request.delegation.accountPublic()))throw denied();
        boolean permitted=request.lookupIncoming?caller.request.incoming.contains(request.targetId)&&target.request.outgoing.contains(cap.accountId):caller.request.outgoing.contains(request.targetId)&&target.request.incoming.contains(cap.accountId);
        if(!permitted)throw denied();
        // Both participants must still own the exact registered app capabilities. No cached/offline target lookup.
        if(!identity.isActive(caller.capability)||!identity.isActive(target.capability)||!identity.isActive(proof.capability()))throw denied();authorization.check();
        if(!caller.request.delegation.accountId().equals(cap.accountId)||!MessageDigest.isEqual(caller.request.delegation.appPublic(),cap.proofKey)||caller.request.delegation.generation!=cap.generation||!GlasProtocol600.verifyDelegation(target.request.delegation,IdentityProtocol.decodeCapability(target.capability),identityPublic,now())||!target.request.endpoint.verify(serviceAudience,target.request.delegation,now()))throw denied();
        result.addProperty("delegation",IdentityProtocol.b64(target.request.delegation.encode()));result.addProperty("endpoint",IdentityProtocol.b64(target.request.endpoint.encode()));
      }
    }
    return result;
  }
  private record Row(String capability,GlasProtocol600.Request request){}
  private Row row(String account)throws SQLException,IOException{try(PreparedStatement s=db.prepareStatement("SELECT capability,request FROM registrations WHERE account=?")){s.setString(1,account);try(ResultSet r=s.executeQuery()){if(!r.next())return null;var request=GlasProtocol600.decode(r.getBytes(2));if(request.command!=GlasProtocol600.Command.REGISTER)throw denied();return new Row(r.getString(1),request);}}}
  public synchronized int cleanup(int batch)throws SQLException,IOException{if(batch<1||batch>256)throw new IllegalArgumentException("Пакет очистки");try(PreparedStatement s=db.prepareStatement("DELETE FROM registrations WHERE account IN (SELECT account FROM registrations WHERE expires<=? LIMIT ?)")){s.setLong(1,now());s.setInt(2,batch);return s.executeUpdate();}}
  private long now()throws IOException,SQLException{long elapsed=System.nanoTime()-anchorNano;if(elapsed<0)throw denied();long time=Math.max(clock.millis(),Math.max(wallFloor,anchorWall+elapsed/1000000));if(time>wallFloor){try(PreparedStatement s=db.prepareStatement("UPDATE settings SET wall_floor=? WHERE id=1")){s.setLong(1,time);s.executeUpdate();}wallFloor=time;}return time;}
  private static IOException denied(){return new IOException("Голосовое соединение недоступно");}
  @Override public synchronized void close()throws SQLException,IOException{try{db.close();}finally{try{lock.release();}finally{lockChannel.close();}}}
}
