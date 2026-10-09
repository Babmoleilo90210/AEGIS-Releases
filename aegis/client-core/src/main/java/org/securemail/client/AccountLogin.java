package org.securemail.client;

import java.nio.file.*;
import java.time.Clock;
import java.util.UUID;
import javax.crypto.AEADBadTagException;
import org.securemail.client.net.*;
import org.securemail.client.storage.*;

/** A successful relay login is required before changing the local vault password. */
public final class AccountLogin {
  private AccountLogin() {}
  public static ClientSession offline(ClientConfig config,char[] password)throws Exception{
    if(!Files.isRegularFile(config.storagePath().resolve("state.vault"),LinkOption.NOFOLLOW_LINKS))throw new java.io.IOException("Локальное хранилище не найдено");
    ClientUpgrade.recover(config.storagePath());return new ClientSession(config,password);
  }
  public static final class OldPasswordRequired extends Exception {
    private static final long serialVersionUID=1L;
    public OldPasswordRequired(){super("Не удалось открыть старое локальное хранилище. Проверьте старый пароль хранилища.");}
  }
  public static final class MigrationFailed extends java.io.IOException {
    private static final long serialVersionUID=1L;
    public MigrationFailed(Throwable cause){super("Не удалось обновить хранилище. Старые данные и резервная копия сохранены.",cause);}
  }
  public static ClientSession open(ClientConfig config,String nick,char[] account,char[] oldPassword)throws Exception {
    Path root=config.storagePath();ClientUpgrade.beforeOpen(root,AppPaths.root().resolve("backups"));
    if(!Files.exists(root.resolve("state.vault")))throw new java.io.IOException("Восстановите идентичность из резервной копии");
    boolean modern=LocalStore.modernVault(root);LocalStore local;
    try{local=new LocalStore(root,modern||oldPassword==null?account:oldPassword,Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage());}
    catch(AEADBadTagException bad){if(!modern)throw new OldPasswordRequired();throw bad;}
    try{
      if(!modern){
        var auth=new NetworkService(new TorTransport(config.torSocksAddress(),config.torSocksPort()),config.relayOnionAddress(),config.relayPort(),local,config.maxCiphertext());
        try{auth.authenticate(nick,account,false);}finally{auth.forgetSession();}
        Path staged=root.resolveSibling(root.getFileName()+".migration-"+UUID.randomUUID());
        try{local.rekeyCopy(staged,account);local.close();local=null;ClientUpgrade.commit(root,staged);}catch(Exception failure){throw new MigrationFailed(failure);}
        local=new LocalStore(root,account,Clock.systemUTC(),config.maxCiphertext(),config.maxLocalStorage());
      }
      var session=new ClientSession(config,local);local=null;
      try{session.login(nick,account,false);return session;}catch(Exception e){session.close();throw e;}
    }finally{if(local!=null)local.close();}
  }
}
