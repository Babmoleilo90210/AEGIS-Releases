package org.securemail.client.ecosystemauth;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.securemail.client.storage.AtomicFiles;
import org.securemail.ecosystem.protocol.IdentityProtocol;
import org.securemail.protocol.Limits;

/** Explicit operator public pins. No discovery of a new trust root from the untrusted network. */
public final class CoreServiceEndpoints600 {
  public enum Service {
    COMMUNITY("Сообщества и Вестник","community.properties","publicKey",true),LIBRARY("Общая библиотека","library.properties","publicKey",true),GLAS("Сигнализация Гласа","glas600.properties","servicePublicKey",true),RELAY("Почтовый Relay","relay600.properties","servicePublicKey",false),MANAGEMENT("Управление сервером","management.properties","publicKey",true),ATTACHMENTS("Крупные вложения","attachments600.properties","servicePublicKey",true);
    private final String title,file,key;private final boolean endpoint;
    Service(String title,String file,String key,boolean endpoint){this.title=title;this.file=file;this.key=key;this.endpoint=endpoint;}
    public String title(){return title;}public boolean hasEndpoint(){return endpoint;}@Override public String toString(){return title;}
  }
  public record Endpoint(String onion,int port,byte[] publicKey){
    public Endpoint {IdentityProtocol.publicKey(publicKey);publicKey=publicKey.clone();if(onion==null)onion="";if(onion.isEmpty()){if(port!=0)throw new IllegalArgumentException("Лишний порт");}else{Limits.onion(onion);if(port<1||port>65535)throw new IllegalArgumentException("Некорректный порт");}}
    @Override public byte[] publicKey(){return publicKey.clone();}public String fingerprint(){return IdentityProtocol.id(publicKey);}
  }
  private final Path directory;public CoreServiceEndpoints600(Path directory){this.directory=directory.toAbsolutePath().normalize();}
  public Optional<Endpoint> load(Service service)throws IOException {Path file=path(service);check(file);if(!Files.exists(file,LinkOption.NOFOLLOW_LINKS))return Optional.empty();Properties p=new Properties();try(var in=new ByteArrayInputStream(AtomicFiles.read(file,4096))){p.load(in);}if(!p.stringPropertyNames().equals(service.endpoint?Set.of("onion","port",service.key):Set.of(service.key)))throw new IOException("Некорректные параметры сервиса");try{return Optional.of(new Endpoint(service.endpoint?p.getProperty("onion"):"",service.endpoint?Integer.parseInt(p.getProperty("port")):0,IdentityProtocol.unb64(p.getProperty(service.key),44)));}catch(IllegalArgumentException invalid){throw new IOException("Повреждены доверенные параметры сервиса",invalid);}}
  public void save(Service service,Endpoint value)throws IOException {if(service.hasEndpoint()==value.onion().isEmpty())throw new IOException("Некорректные поля сервиса");Path file=path(service);check(file);AtomicFiles.directory(directory);Properties p=new Properties();if(service.endpoint){p.setProperty("onion",value.onion());p.setProperty("port",Integer.toString(value.port()));}p.setProperty(service.key,IdentityProtocol.b64(value.publicKey()));ByteArrayOutputStream bytes=new ByteArrayOutputStream();p.store(bytes,"AEGIS 6 public operator service configuration");AtomicFiles.write(file,bytes.toByteArray());}
  private Path path(Service service){return directory.resolve(Objects.requireNonNull(service).file);}
  private static void check(Path file)throws IOException {for(Path p=file;p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("Ссылка в настройках сервиса запрещена");}
}
