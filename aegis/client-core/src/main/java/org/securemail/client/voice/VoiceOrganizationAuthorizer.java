package org.securemail.client.voice;

import java.io.IOException;
import org.securemail.protocol.Limits;

/** Adapter to authenticated community-server authorization. authorize() is always
 * cache-only: audio, permission revocation and timers must never block on network I/O.
 * prepare() may refresh one verified contact on the bounded incoming handshake worker.
 * A missing, revoked, malformed, stale or unavailable server decision denies access.
 */
@FunctionalInterface
public interface VoiceOrganizationAuthorizer {
  /** Bounded optional server refresh; invoked before incoming TLS, never on FX/audio/tick. */
  default void prepare(String localUserId,String peerUserId,VoiceCallService.Direction direction)throws IOException {}
  Decision authorize(String localUserId,String peerUserId,VoiceCallService.Direction direction);
  VoiceOrganizationAuthorizer DENY=(local,peer,direction)->null;
  long MAX_VALIDITY_MILLIS=30_000;
  record Decision(String localUserId,String peerUserId,VoiceCallService.Direction direction,long issuedAt,long expiresAt,boolean allowed) {
    public Decision {Limits.userId(localUserId);Limits.userId(peerUserId);java.util.Objects.requireNonNull(direction);if(issuedAt<0||expiresAt<=issuedAt||expiresAt-issuedAt>MAX_VALIDITY_MILLIS)throw new IllegalArgumentException("Срок разрешения звонка");}
    public boolean permits(String local,String peer,VoiceCallService.Direction requested,long now){return allowed&&localUserId.equals(local)&&peerUserId.equals(peer)&&direction==requested&&now>=issuedAt&&now<expiresAt;}
  }
}
