package org.securemail.client.ecosystemauth;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.securemail.client.AppPaths;
import org.securemail.client.storage.AtomicFiles;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.protocol.Limits;

/** Non-secret, operator-configured Identity endpoint and independent trust pin. No account private key is loaded here. */
public record CorePublicConfig600(String identityOnion,int identityPort,byte[] identityPublicKey,int socksPort) {
  public CorePublicConfig600 {
    Limits.onion(identityOnion);IdentityProtocol.publicKey(identityPublicKey);
    if(identityPort<1||identityPort>65535||socksPort<1||socksPort>65535)throw new IllegalArgumentException("Некорректный порт Identity");identityPublicKey=identityPublicKey.clone();
  }
  @Override public byte[] identityPublicKey(){return identityPublicKey.clone();}
  public static Path defaultFile(){return AppPaths.root().resolve("core600/identity.properties");}
  public static CorePublicConfig600 fromDefaultFile()throws IOException{return load(defaultFile());}
  public static CorePublicConfig600 load(Path file)throws IOException {
    for(Path parent=file.toAbsolutePath().normalize();parent!=null;parent=parent.getParent())if(Files.isSymbolicLink(parent))throw new IOException("Ссылки в конфигурации Identity запрещены");
    Properties p=new Properties();try(var in=new ByteArrayInputStream(AtomicFiles.read(file,16384))){p.load(in);}
    if(!p.stringPropertyNames().equals(Set.of("identityOnion","identityPort","identityPublicKey","socksPort")))throw new IOException("Некорректные поля конфигурации Identity");
    try{return new CorePublicConfig600(p.getProperty("identityOnion"),Integer.parseInt(p.getProperty("identityPort")),IdentityProtocol.unb64(p.getProperty("identityPublicKey"),44),Integer.parseInt(p.getProperty("socksPort")));}
    catch(IllegalArgumentException e){throw new IOException("Не настроен доверенный сервер Identity",e);}
  }
}
