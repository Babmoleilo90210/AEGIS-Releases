package org.securemail.client.library600;

import java.io.IOException;
import java.time.Clock;
import java.util.Objects;
import java.util.function.LongSupplier;

/** Process-local permit accepted only from a verified server response. Never serialized or restored.
 * It bounds a plaintext export, not already copied files or an untrusted operating system. */
public final class LibraryLease600 {
    public static final long MAX_OFFLINE_MILLIS = 24 * 60 * 60 * 1000L;
    private final String accountId, deviceId;
    private final long generation, aclEpoch, issuedWall, issuedNano, lifetimeMillis;
    private final Clock clock;
    private final LongSupplier nanoClock;
    private boolean revoked;

    private LibraryLease600(String accountId, String deviceId, long generation, long aclEpoch,
                            long lifetimeMillis, Clock clock, LongSupplier nanoClock) {
        this.accountId = Objects.requireNonNull(accountId);
        this.deviceId = Objects.requireNonNull(deviceId);
        if (!accountId.matches("[a-f0-9]{64}") || !deviceId.matches("[A-Za-z0-9_-]{1,128}")
                || generation < 1 || aclEpoch < 0 || lifetimeMillis < 1 || lifetimeMillis > MAX_OFFLINE_MILLIS)
            throw new IllegalArgumentException("Некорректный допуск библиотеки");
        this.generation = generation; this.aclEpoch = aclEpoch; this.lifetimeMillis = lifetimeMillis;
        this.clock = Objects.requireNonNull(clock); this.nanoClock = Objects.requireNonNull(nanoClock);
        issuedWall = clock.millis(); issuedNano = nanoClock.getAsLong();
    }

    /** onlineOnly content cannot be exported. Explicit offline grant is mandatory even for a short lease. */
    public static LibraryLease600 acceptVerified(String accountId, String deviceId, long generation, long aclEpoch,
            long serverNow, long leaseUntil, boolean offlineAllowed, Clock clock, LongSupplier nanoClock) throws IOException {
        return acceptVerified(accountId,deviceId,generation,aclEpoch,serverNow,leaseUntil,offlineAllowed,clock,nanoClock,0);
    }
    public static LibraryLease600 acceptVerified(String accountId,String deviceId,long generation,long aclEpoch,
            long serverNow,long leaseUntil,boolean offlineAllowed,Clock clock,LongSupplier nanoClock,long roundTripMillis)throws IOException {
        if (!offlineAllowed || serverNow < 0 || leaseUntil <= serverNow || leaseUntil - serverNow > MAX_OFFLINE_MILLIS)
            throw new IOException("Материал не разрешён для локального vault");
        if(roundTripMillis<0||roundTripMillis>120000)throw new IOException("Некорректное время сетевой проверки");
        long remaining=Math.min(leaseUntil-serverNow-roundTripMillis,leaseUntil-clock.millis());
        if(remaining<=0)throw new IOException("Ответ получен после истечения допуска");
        return new LibraryLease600(accountId, deviceId, generation, aclEpoch, remaining, clock, nanoClock);
    }
    public synchronized void require(String accountId, String deviceId, long generation, long aclEpoch) throws IOException {
        long elapsed = nanoClock.getAsLong() - issuedNano; // subtraction intentionally handles nanoTime wrap
        long wall = clock.millis();
        if (revoked || !this.accountId.equals(accountId) || !this.deviceId.equals(deviceId)
                || this.generation != generation || this.aclEpoch != aclEpoch || elapsed < 0
                || elapsed / 1_000_000L >= lifetimeMillis || wall < issuedWall
                || wall - issuedWall >= lifetimeMillis)
            throw new IOException("Допуск библиотеки истёк или отозван");
    }
    public synchronized void revoke() { revoked = true; }
}
