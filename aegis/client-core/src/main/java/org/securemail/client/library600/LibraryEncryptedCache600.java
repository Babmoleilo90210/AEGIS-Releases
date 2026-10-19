package org.securemail.client.library600;

import org.securemail.client.security.SystemSecrets;
import org.securemail.client.storage.AtomicFiles;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;
import java.util.function.LongSupplier;

/** AES-256-GCM at-rest cache with a separate OS device-secret namespace.
 * No plaintext key fallback. Permits are NEVER serialized: restart requires fresh
 * per-material server authorization, even if old wall-clock expiry looks valid.
 * Package-only verified methods are called after signed HTTP+app PoP verification. */
public final class LibraryEncryptedCache600 implements AutoCloseable {
    public static final long MAX_BYTES=128L*1024*1024;public static final int MAX_ENTRIES=512,MAX_TEXT=1024*1024;
    private static final byte[]MAGIC="AEGIS-LIBRARY-CACHE/v1".getBytes(StandardCharsets.US_ASCII);
    record Cached(String id,long revision,String markdown,LibraryLease600 lease,VaultProjection600.Context context){}
    private record Grant(long revision,String sha256,LibraryLease600 lease,VaultProjection600.Context context){}
    private final Path root;private final String account,device;private final Clock clock;private final LongSupplier nano;private byte[]key;
    private final Map<String,Grant>grants=new HashMap<>();private long epoch=-1,generation=-1;private boolean closed;
    public static LibraryEncryptedCache600 open(Path ownRoot,String accountId,String deviceId,Clock clock,LongSupplier nano)throws IOException {
        SystemSecrets lazy=new SystemSecrets(){private SystemSecrets nativeStore;private SystemSecrets store()throws IOException{if(nativeStore==null)nativeStore=SystemSecrets.current(ownRoot.resolve("library-only-os-key"));return nativeStore;}public byte[]load()throws IOException{return store().load();}public void store(byte[]secret)throws IOException{store().store(secret);}public void clear()throws IOException{store().clear();}};return new LibraryEncryptedCache600(ownRoot,accountId,deviceId,lazy,clock,nano);
    }
    LibraryEncryptedCache600(Path ownRoot,String accountId,String deviceId,SystemSecrets secrets,Clock clock,LongSupplier nano)throws IOException {
        if(!accountId.matches("[a-f0-9]{64}")||!deviceId.matches("[A-Za-z0-9_-]{1,128}"))throw new IllegalArgumentException("Cache identity binding");account=accountId;device=deviceId;this.clock=Objects.requireNonNull(clock);this.nano=Objects.requireNonNull(nano);
        Path canonical=ownRoot.toAbsolutePath().normalize();if(Files.exists(canonical,LinkOption.NOFOLLOW_LINKS)&&(!Files.isDirectory(canonical,LinkOption.NOFOLLOW_LINKS)||!canonical.toRealPath().equals(canonical)))throw new IOException("Небезопасный каталог кэша");
        if(Files.isDirectory(canonical)&&!Files.exists(canonical.resolve(".library-cache600"),LinkOption.NOFOLLOW_LINKS)){try(var files=Files.list(canonical)){if(files.findAny().isPresent())throw new IOException("Чужой каталог нельзя использовать как кэш");}}
        AtomicFiles.directory(canonical);root=canonical;String marker="AEGIS-LIBRARY-CACHE600\n"+account+"\n"+device+"\n";Path ownership=root.resolve(".library-cache600");if(Files.exists(ownership,LinkOption.NOFOLLOW_LINKS)){if(!new String(AtomicFiles.read(ownership,512),StandardCharsets.US_ASCII).equals(marker))throw new IOException("Кэш другого аккаунта или устройства");}else AtomicFiles.write(ownership,marker.getBytes(StandardCharsets.US_ASCII));
        byte[]loaded=secrets.load();if(loaded==null){loaded=new byte[32];new SecureRandom().nextBytes(loaded);try{secrets.store(loaded);byte[]check=secrets.load();try{if(check==null||!MessageDigest.isEqual(loaded,check))throw new IOException("Система не подтвердила ключ кэша");}finally{if(check!=null)Arrays.fill(check,(byte)0);}}catch(IOException|RuntimeException failure){Arrays.fill(loaded,(byte)0);throw failure;}}
        if(loaded.length!=32){Arrays.fill(loaded,(byte)0);throw new IOException("Неверный ключ кэша");}key=loaded.clone();Arrays.fill(loaded,(byte)0);
    }
    /** A full signed project response. Metadata and body are encrypted together. */
    synchronized void storeVerified(Map<String,Object>envelope)throws Exception {
        GrantAndId verified=accept(envelope,true);String id=verified.id;Grant grant=verified.grant;Map<?,?>data=(Map<?,?>)envelope.get("data");String markdown=(String)data.get("markdown");byte[]text=markdown.getBytes(StandardCharsets.UTF_8);if(text.length>MAX_TEXT)throw new IOException("Материал превышает лимит кэша");
        byte[]plain=null,sealed=null,nonce=new byte[12];new SecureRandom().nextBytes(nonce);
        try {var output=new ByteArrayOutputStream();try(var out=new DataOutputStream(output)){out.writeUTF("AEGIS-LIBRARY-CACHED-MATERIAL/v1");out.writeUTF(account);out.writeUTF(device);out.writeUTF(id);out.writeLong(grant.revision);out.writeLong(grant.context.generation());out.writeLong(grant.context.aclEpoch());out.writeBoolean(true);out.writeInt(text.length);out.write(text);}plain=output.toByteArray();var cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(aad(id));sealed=cipher.doFinal(plain);byte[]file=ByteBuffer.allocate(4+12+sealed.length).putInt(1).put(nonce).put(sealed).array();Path target=entry(id);capacity(target,file.length);AtomicFiles.write(target,file);grants.put(id,grant);}finally{Arrays.fill(text,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);if(sealed!=null)Arrays.fill(sealed,(byte)0);Arrays.fill(nonce,(byte)0);}
    }
    /** Fresh cache.authorize response supplies exact revision+SHA, never just a general Library capability. */
    synchronized Cached authorizeAndReadVerified(Map<String,Object>envelope)throws Exception {
        GrantAndId verified=accept(envelope,false);Grant old=grants.remove(verified.id);if(old!=null)old.lease.revoke();Cached result=decrypt(verified.id,verified.grant);grants.put(verified.id,verified.grant);return result;
    }
    synchronized Cached readOffline(String id)throws Exception {check();Grant grant=grants.get(uuid(id));if(grant==null)throw new IOException("После перезапуска требуется новая серверная проверка конкретного материала");return decrypt(id,grant);}
    synchronized boolean offlineAvailable(String id){try{Grant g=grants.get(uuid(id));if(g==null)return false;g.lease.require(account,device,g.context.generation(),g.context.aclEpoch());return Files.isRegularFile(entry(id),LinkOption.NOFOLLOW_LINKS);}catch(Exception denied){return false;}}
    synchronized boolean contains(String id)throws IOException{return Files.isRegularFile(entry(id),LinkOption.NOFOLLOW_LINKS);}
    private record GrantAndId(String id,Grant grant){}
    private GrantAndId accept(Map<String,Object>envelope,boolean full)throws Exception {
        try{check();if(!account.equals(envelope.get("accountId"))||!device.equals(envelope.get("deviceId")))throw new IOException("Кэш другой identity");long gen=integer(envelope,"generation"),nextEpoch=integer(envelope,"aclEpoch");if(gen<1||nextEpoch<0||generation>=0&&gen<generation||epoch>=0&&nextEpoch<epoch)throw new IOException("Устаревший контекст кэша");
        if(gen!=generation||nextEpoch!=epoch){revokePermits();generation=gen;epoch=nextEpoch;}
        if(!(envelope.get("data") instanceof Map<?,?>data)||!Boolean.TRUE.equals(data.get("offlineAllowed")))throw new IOException("Сервер не разрешил офлайн-копию");String id=uuid((String)data.get("id"));long revision=integer(data,"revision");if(revision<1)throw new IOException("Неверная версия кэша");String hash;
        if(full){if(!(data.get("markdown") instanceof String markdown)||markdown.getBytes(StandardCharsets.UTF_8).length>MAX_TEXT)throw new IOException("Неверное тело кэша");hash=sha(markdown.getBytes(StandardCharsets.UTF_8));}
        else{Object value=data.get("sha256");if(!(value instanceof String s)||!s.matches("[a-f0-9]{64}"))throw new IOException("Нет серверной контрольной суммы материала");hash=s;}
        var context=new VaultProjection600.Context(account,device,gen,nextEpoch);var lease=LibraryLease600.acceptVerified(account,device,gen,nextEpoch,integer(envelope,"serverNow"),integer(envelope,"leaseUntil"),true,clock,nano,envelope.containsKey("_localRoundTripMillis600")?integer(envelope,"_localRoundTripMillis600"):0);return new GrantAndId(id,new Grant(revision,hash,lease,context));}catch(Exception denied){revokePermits();throw denied;}
    }
    private Cached decrypt(String id,Grant grant)throws Exception {
        check();grant.lease.require(account,device,grant.context.generation(),grant.context.aclEpoch());byte[]raw=AtomicFiles.read(entry(id),MAX_TEXT+2048),plain=null;
        try {ByteBuffer header=ByteBuffer.wrap(raw);if(raw.length<32||header.getInt()!=1)throw new IOException("Повреждён кэш");byte[]nonce=new byte[12];header.get(nonce);var cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(aad(id));plain=cipher.doFinal(Arrays.copyOfRange(raw,16,raw.length));
            try(var in=new DataInputStream(new ByteArrayInputStream(plain))){if(!"AEGIS-LIBRARY-CACHED-MATERIAL/v1".equals(in.readUTF())||!account.equals(in.readUTF())||!device.equals(in.readUTF())||!id.equals(in.readUTF())||in.readLong()!=grant.revision)throw new IOException("Подмена привязки материала");long oldGeneration=in.readLong(),oldEpoch=in.readLong();if(oldGeneration<1||oldGeneration>grant.context.generation()||oldEpoch<0||oldEpoch>grant.context.aclEpoch()||!in.readBoolean())throw new IOException("Неверная политика кэша");int size=in.readInt();if(size<0||size>MAX_TEXT)throw new IOException("Размер кэша");byte[]text=in.readNBytes(size);try{if(text.length!=size||in.read()!=-1||!sha(text).equals(grant.sha256))throw new IOException("Кэш не совпадает с текущим серверным материалом");String markdown=new String(text,StandardCharsets.UTF_8);if(!Arrays.equals(text,markdown.getBytes(StandardCharsets.UTF_8)))throw new IOException("Повреждён UTF-8 кэша");grant.lease.require(account,device,grant.context.generation(),grant.context.aclEpoch());return new Cached(id,grant.revision,markdown,grant.lease,grant.context);}finally{Arrays.fill(text,(byte)0);}}
        }finally{Arrays.fill(raw,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);}
    }
    synchronized void invalidate(String id)throws IOException {check();Grant old=grants.remove(uuid(id));if(old!=null)old.lease.revoke();Files.deleteIfExists(entry(id));}
    public synchronized void clear()throws IOException {check();revokePermits();try(var files=Files.list(root)){for(Path p:files.toList())if(p.getFileName().toString().endsWith(".lc6")){if(Files.isSymbolicLink(p))throw new IOException("Ссылка в кэше");Files.delete(p);}}}
    private void revokePermits(){for(Grant g:grants.values())g.lease.revoke();grants.clear();}
    private void capacity(Path target,long size)throws IOException {long bytes=0;int count=0;try(var files=Files.list(root)){for(Path p:files.toList())if(p.getFileName().toString().endsWith(".lc6")){if(Files.isSymbolicLink(p)||!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||Files.size(p)>MAX_TEXT+2048)throw new IOException("Повреждён каталог кэша");if(!p.equals(target)){bytes+=Files.size(p);count++;}}}if(count>=MAX_ENTRIES||bytes+size>MAX_BYTES)throw new IOException("Лимит зашифрованного кэша; очистите старые материалы");}
    private Path entry(String id)throws IOException {Path p=root.resolve(uuid(id)+".lc6");if(Files.isSymbolicLink(p))throw new IOException("Ссылка вместо кэша");return p;}
    private byte[]aad(String id)throws IOException {var bytes=new ByteArrayOutputStream();try(var out=new DataOutputStream(bytes)){out.write(MAGIC);out.writeUTF(account);out.writeUTF(device);out.writeUTF(uuid(id));}return bytes.toByteArray();}
    private static String uuid(String id)throws IOException{try{if(id==null||!UUID.fromString(id).toString().equals(id))throw new IOException("Неверный UUID кэша");return id;}catch(IllegalArgumentException e){throw new IOException("Неверный UUID кэша");}}
    private static long integer(Map<?,?>m,String key)throws IOException{if(!(m.get(key)instanceof Number n))throw new IOException("Поле кэша "+key);try{return new java.math.BigDecimal(n.toString()).longValueExact();}catch(RuntimeException e){throw new IOException("Некорректное поле кэша");}}
    private static String sha(byte[]bytes)throws GeneralSecurityException{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private void check()throws IOException{if(closed||key==null)throw new IOException("Кэш заблокирован");}
    @Override public synchronized void close(){if(closed)return;closed=true;revokePermits();if(key!=null){Arrays.fill(key,(byte)0);key=null;}}
}
