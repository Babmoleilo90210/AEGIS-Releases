package org.securemail.client.library600;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.function.LongSupplier;

/** Restricted connector. Only an already signature/proof-verified HTTP adapter may implement Transport.
 * No root identity key is transferred to Obsidian. No interface is exposed to arbitrary local processes.
 * Caller runs periodic maintain() and closes the owned protected process before closing this connector. */
public final class LibraryConnector600 implements AutoCloseable {
    @FunctionalInterface public interface Transport {
        /** Verify server response signature, body/request binding and current Identity generation before returning. */
        Map<String,Object> verifiedRequest(String action, Map<String,Object> args) throws Exception;
    }
    private final Transport transport;
    private final VaultProjection600 projection;
    private final String accountId,deviceId;
    private final long generation;
    private final Clock clock;
    private final LongSupplier nanoClock;
    private final LibraryEncryptedCache600 cache;
    private long epoch=-1;
    private boolean closed;
    public LibraryConnector600(Transport transport, VaultProjection600 projection, String accountId,
            String deviceId, long generation, Clock clock, LongSupplier nanoClock) {this(transport,projection,accountId,deviceId,generation,clock,nanoClock,null);}
    public LibraryConnector600(Transport transport,VaultProjection600 projection,String accountId,String deviceId,long generation,Clock clock,LongSupplier nanoClock,LibraryEncryptedCache600 cache) {
        this.transport=Objects.requireNonNull(transport);this.projection=Objects.requireNonNull(projection);
        if(accountId==null||!accountId.matches("[a-f0-9]{64}")||deviceId==null||!deviceId.matches("[A-Za-z0-9_-]{1,128}")||generation<1)
            throw new IllegalArgumentException("Некорректная сессия библиотеки");
        this.accountId=accountId;this.deviceId=deviceId;this.generation=generation;this.clock=Objects.requireNonNull(clock);this.nanoClock=Objects.requireNonNull(nanoClock);this.cache=cache;
    }
    public Path project(String materialId)throws Exception {
        boolean cachedExists;synchronized(this){check();cachedExists=cache!=null&&cache.contains(materialId);}if(!cachedExists)return projectOnline(materialId);
        final Map<String,Object>response=request("library600.cache.authorize",materialId);
        synchronized(this){check();context(response);try{var cached=cache.authorizeAndReadVerified(response);if(!materialId.equals(cached.id()))throw new IOException("Другой материал кэша");return projection.publish(materialId,cached.revision(),cached.markdown(),cached.lease(),cached.context());}catch(java.io.IOException|java.security.GeneralSecurityException stale){cache.invalidate(materialId);}}
        return projectOnline(materialId);
    }
    private Path projectOnline(String materialId)throws Exception {
        synchronized(this){check();}
        final Map<String,Object> response;
        try{response=transport.verifiedRequest("library600.project",Map.of("id",materialId));}
        catch(HttpLibraryTransport600.Rejected denied){synchronized(this){if(!closed){projection.revokeAll();if(cache!=null)cache.clear();}}throw denied;}
        catch(Exception unavailable){synchronized(this){if(!closed)projection.prune();}throw unavailable;}
        synchronized(this){
        check();
        try {
            if(response==null||!accountId.equals(response.get("accountId"))||!deviceId.equals(response.get("deviceId"))
                    ||integer(response,"generation")!=generation)throw new IOException("Подмена сессии библиотеки");
            long nextEpoch=integer(response,"aclEpoch"),serverNow=integer(response,"serverNow"),expires=integer(response,"leaseUntil");
            if(nextEpoch<0||epoch>=0&&nextEpoch<epoch)throw new IOException("Устаревшие полномочия библиотеки");
            if(epoch>=0&&nextEpoch!=epoch)projection.revokeAll();epoch=nextEpoch;
            if(!(response.get("data") instanceof Map<?,?> raw))throw new IOException("Некорректная проекция");
            if(!materialId.equals(raw.get("id"))||!Boolean.TRUE.equals(raw.get("offlineAllowed"))
                    ||!(raw.get("markdown") instanceof String markdown))throw new IOException("Экспорт материала не разрешён");
            long revision=integer(raw,"revision");
            LibraryLease600 lease=LibraryLease600.acceptVerified(accountId,deviceId,generation,epoch,serverNow,expires,true,clock,nanoClock,response.containsKey("_localRoundTripMillis600")?integer(response,"_localRoundTripMillis600"):0);
            Path file=projection.publish(materialId,revision,markdown,lease,new VaultProjection600.Context(accountId,deviceId,generation,epoch));if(cache!=null)cache.storeVerified(response);return file;
        } catch(Exception invalid){projection.revokeAll();throw invalid;}
        }
    }
    private Map<String,Object> request(String operation,String materialId)throws Exception {try{return transport.verifiedRequest(operation,Map.of("id",materialId));}catch(HttpLibraryTransport600.Rejected denied){synchronized(this){if(!closed){projection.revokeAll();if(cache!=null)cache.clear();}}throw denied;}}
    private void context(Map<String,Object>response)throws Exception {try{if(!accountId.equals(response.get("accountId"))||!deviceId.equals(response.get("deviceId"))||integer(response,"generation")!=generation)throw new IOException("Подмена сессии кэша");long next=integer(response,"aclEpoch");if(next<0||epoch>=0&&next<epoch)throw new IOException("Устаревшие полномочия");if(epoch>=0&&next!=epoch)projection.revokeAll();epoch=next;}catch(Exception invalid){projection.revokeAll();if(cache!=null)cache.clear();throw invalid;}}
    public synchronized boolean offlineAvailable(String materialId){return !closed&&cache!=null&&cache.offlineAvailable(materialId);}
    public synchronized Path projectOffline(String materialId)throws Exception {check();if(cache==null)throw new IOException("Зашифрованный офлайн-кэш не включён");var cached=cache.readOffline(materialId);var c=cached.context();if(!accountId.equals(c.accountId())||!deviceId.equals(c.deviceId())||generation!=c.generation()||epoch>=0&&epoch!=c.aclEpoch())throw new IOException("Офлайн-копия другой сессии");epoch=c.aclEpoch();return projection.publish(materialId,cached.revision(),cached.markdown(),cached.lease(),c);}
    public synchronized void maintain()throws IOException {check();projection.prune();}
    /** Ordinary document changes remove plaintext but preserve authenticated encrypted disk entries. */
    public synchronized void clearPlaintextProjections()throws IOException {check();projection.revokeAll();}
    public synchronized void revokeProjections()throws IOException {check();projection.revokeAll();if(cache!=null)cache.clear();}
    /** Called on verified revocation, logout, full Core close, or OS/session lock. */
    public synchronized void revoke()throws IOException {if(closed)return;try{if(cache!=null)cache.clear();}finally{close();}}
    @Override public synchronized void close()throws IOException {if(!closed){try{projection.close();}finally{closed=true;if(cache!=null)cache.close();}}}
    private void check()throws IOException {if(closed)throw new IOException("Коннектор библиотеки заблокирован");}
    private static long integer(Map<?,?>m,String key)throws IOException {
        Object raw=m.get(key);if(!(raw instanceof Number))throw new IOException("Некорректное поле "+key);
        try{return new java.math.BigDecimal(raw.toString()).longValueExact();}catch(RuntimeException e){throw new IOException("Некорректное поле "+key,e);}
    }
}
