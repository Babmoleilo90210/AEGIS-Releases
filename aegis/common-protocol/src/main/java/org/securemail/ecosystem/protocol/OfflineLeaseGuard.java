package org.securemail.ecosystem.protocol;

/** Local conservative lease guard. Caller persists highest wall time in its encrypted state,
 * bound to the capability tokenId, and supplies a monotonic elapsed clock (Android elapsedRealtime).
 * It does not promise revocation of offline copies or resist restoration of both disk and OS clock.
 * Closed materials require a separate policy; this guard always denies them while offline.
 */
public final class OfflineLeaseGuard {
    private final IdentityProtocol.Capability capability;
    private final long receivedWall,receivedElapsed,serverTime;
    private long highestWall,highestElapsed;
    public OfflineLeaseGuard(IdentityProtocol.Capability capability,byte[] pinnedServiceKey,long authenticatedServerTime,long wallMillis,long elapsedMillis,long persistedHighestWall) {
        if(!IdentityProtocol.verifyCapability(capability,pinnedServiceKey,authenticatedServerTime)||wallMillis<0||elapsedMillis<0||persistedHighestWall>wallMillis)throw new IllegalArgumentException("Invalid offline lease anchor");
        this.capability=capability;this.serverTime=authenticatedServerTime;this.receivedWall=wallMillis;this.receivedElapsed=elapsedMillis;this.highestWall=wallMillis;this.highestElapsed=elapsedMillis;
    }
    public synchronized boolean allows(long wallMillis,long elapsedMillis,long persistedHighestWall,boolean closedMaterial) {
        if(closedMaterial||capability.offlineUntil<=serverTime||wallMillis<highestWall||wallMillis<persistedHighestWall||elapsedMillis<highestElapsed||elapsedMillis<receivedElapsed)return false;
        highestWall=wallMillis;highestElapsed=elapsedMillis;
        long wallDelta=wallMillis-receivedWall,elapsedDelta=elapsedMillis-receivedElapsed;
        long elapsed=Math.max(wallDelta,elapsedDelta);
        if(elapsed<0||elapsed>=IdentityProtocol.MAX_LEASE_MILLIS)return false;
        long remaining=capability.offlineUntil-serverTime;
        return remaining>0&&elapsed<remaining;
    }
    public synchronized long highestWallMillis(){return highestWall;}
    public String tokenId(){return capability.tokenId;}
}
