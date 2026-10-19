package org.securemail.client.ecosystem;

import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;
import org.securemail.client.crypto.*;
import org.securemail.client.storage.LocalStore;
import org.securemail.client.archive.EncryptedArchive;
import org.securemail.protocol.*;

/** Runs in a separate JVM against the exact released 5.0.0 JAR. Public synthetic passwords only; no owner's data. */
public final class Legacy500VaultProbe {
  public static final String MAIL_PASSWORD="public old500 rollback fixture password",ARCHIVE_PASSWORD="public old500 independent archive fixture";
  private Legacy500VaultProbe(){}
  public static void main(String[] args)throws Exception{
    Path app=Path.of(args[1]),vault=app.resolve("data"),archive=vault.resolveSibling("data.personal-archive");boolean init=args[0].equals("init");
    try(LocalStore store=new LocalStore(vault,MAIL_PASSWORD.toCharArray(),Clock.systemUTC(),1000000,8_000_000)){
      if(init){store.bindNickname("raven");Identity sender=Identity.create();store.trust(new UserInfo(sender.userId(),"heron",sender.publicKey(),null));try(var clear=PlainMessage.text("retained old500 encrypted letter")){var packet=new AutomaticEncryption(Clock.systemUTC()).encrypt(clear,1800,60_000,sender,"heron",new UserInfo(store.identity().userId(),"raven",store.identity().publicKey(),null));store.accept(packet);}
        String item;try(var created=EncryptedArchive.create(archive,app.resolve("archive-guards"),ARCHIVE_PASSWORD.toCharArray(),false,Clock.systemUTC()).archive()){item=created.importBytes("preserved.txt","text","old500 archive survives rollback".getBytes(java.nio.charset.StandardCharsets.UTF_8),"",false,EncryptedArchive.QUIET,()->false).id();}Files.writeString(vault.resolve("fixture-archive-id"),item);
      }
      if(args[0].equals("rekey")){try{store.rekeyCopy(app.resolve("must-not-be-used-as-downgrade"),MAIL_PASSWORD.toCharArray());throw new AssertionError("old rekey unexpectedly accepted new extension names");}catch(IllegalArgumentException expected){System.out.println("PASS: exact 5.0 rekey rejects unknown 6.0 extensions; use verified pre-6 snapshot");return;}}
      byte[] archiveBytes;try(var opened=EncryptedArchive.open(archive,app.resolve("archive-guards"),ARCHIVE_PASSWORD.toCharArray(),false,Clock.systemUTC())){archiveBytes=opened.previewBytes(Files.readString(vault.resolve("fixture-archive-id")),1024);}
      System.out.println(store.identity().userId()+" "+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(store.identity().privateKey()))+" "+store.contacts().size()+" "+store.inbox().size()+" "+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(archiveBytes)));
    }
  }
}
