# Voice controller verification

Targeted verification performed against the development/aegis-2.5.0 working tree based on f173b4a1. This report describes executed checks; it does not grant a native acceptance gate.

Java 21 compilation of ClientSession, PeerServer, NetworkService, VoiceCallService and the three test classes completed successfully. The final JUnit run completed in 19,826 ms: **20 found, 20 started, 20 successful, 0 failed, 0 skipped**. JUnit XML from that run is stored in this directory.

The test classes are:

- VoiceCallServiceTest: 14 integration and ownership cases.
- VoiceHistoryTest: 3 encrypted persistence, migration and corruption cases.
- VoiceFramesTest: 3 bounded hostile-input and serialization cases.

VoiceCallServiceTest uses real JSSE TLS 1.3, the existing Ed25519 identities, signed ephemeral certificate offers and real PeerServer framing. Its connector is an explicitly injected loopback test connector. Its audio device factory is a deterministic substitute; short byte strings stand in for encoded Opus packets. These tests prove neither Tor reachability nor physical microphone/playback behavior.

Executed controller scenarios include consent before either media device is created, microphone off at connection and after fresh authenticated reconnect, explicit mute and queue gating, matching certificate-pair verification codes, encrypted mail delivery on the same active peer listener, declined and disabled incoming calls, unknown and blocked identity suppression, contact key replacement, another authenticated caller receiving busy, legacy peer rejection followed by working mail, audio before acceptance rejection, ringing/reconnect deadlines, unavailable device recovery, responsive snapshots during a slow dial, retained ownership during slow device cleanup, optional damaged voice metadata leaving the identity and mail usable, and unchecked microphone/configuration driver failures ending the call before a fresh call succeeds.

History tests verified that saving is disabled by default, opted-in metadata and device settings are encrypted in voice-v1.vault, disable/clear work, schema 1 receives safe schema 2 defaults, rekeyCopy preserves the encrypted sidecar, oversized state is rejected, and modified ciphertext fails authentication. Corrupt optional voice state disables calls until the owner explicitly clears that state; it does not prevent the existing vault, letters or archive from opening.

The production call connector always uses NetworkService.connectVoice, a pinned contact and a current signed onion route through TorTransport.connectPeer. The test connector is package-private and is not selected by a runtime flag. Voice operation 101 extends only the client peer listener; production Relay operations and messages are unchanged.

Native Windows 11, CachyOS KDE Wayland/X11, real Tor onion speech transport, physical device behavior and speech quality remain separate acceptance checks. They must not be marked PASS from these results.
