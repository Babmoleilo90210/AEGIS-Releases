package org.securemail.client.voice;

import org.junit.jupiter.api.*;
import org.securemail.client.crypto.Identity;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/** Real JSSE socket handshakes. Loopback is a test transport, not a Tor acceptance claim. */
@Timeout(20)
class VoiceTlsTest {
    static Identity alice, bob, mallory;
    @BeforeAll static void identities() throws Exception { alice = Identity.create(); bob = Identity.create(); mallory = Identity.create(); }

    @Test void authenticatesBothContactsAndTransfersDuplexRecordsOverTls13() throws Exception {
        try (var pair = connect()) {
            assertEquals("TLSv1.3", pair.client.getSession().getProtocol());
            assertEquals("TLSv1.3", pair.server.getSession().getProtocol());
            assertEquals(VoiceTls.ALPN, pair.client.getApplicationProtocol());
            assertEquals(VoiceTls.ALPN, pair.server.getApplicationProtocol());
            assertArrayEquals(pair.callee.offer().certificate(), pair.client.getSession().getPeerCertificates()[0].getEncoded());
            assertArrayEquals(pair.caller.offer().certificate(), pair.server.getSession().getPeerCertificates()[0].getEncoded());
            byte[] frame = new byte[32_000]; new java.security.SecureRandom().nextBytes(frame);
            pair.client.getOutputStream().write(frame); pair.client.getOutputStream().flush();
            assertArrayEquals(frame, pair.server.getInputStream().readNBytes(frame.length));
            pair.server.getOutputStream().write("peer response".getBytes(java.nio.charset.StandardCharsets.UTF_8)); pair.server.getOutputStream().flush();
            assertEquals("peer response", new String(pair.client.getInputStream().readNBytes(13), java.nio.charset.StandardCharsets.UTF_8));
        }
    }

    @Test void standardTlsKeyUpdatePreservesBidirectionalChannel() throws Exception {
        try (var pair = connect()) {
            VoiceTls.requestKeyUpdate(pair.client);
            pair.client.getOutputStream().write(17); pair.client.getOutputStream().flush();
            assertEquals(17, pair.server.getInputStream().read());
            VoiceTls.requestKeyUpdate(pair.server);
            pair.server.getOutputStream().write(29); pair.server.getOutputStream().flush();
            assertEquals(29, pair.client.getInputStream().read());
        }
    }

    @Test void wireContainsNoPlaintextAudioAndTamperedTlsRecordIsRejected() throws Exception {
        UUID id = UUID.randomUUID();
        try (var caller = caller(id); var callee = callee(id); var proxy = new TamperingProxy(); var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<SSLSocket> serverFuture = executor.submit(() -> callee.handshake(proxy.server, caller.offer(), alice.publicKey(), false));
            SSLSocket client = caller.handshake(proxy.client, callee.offer(), bob.publicKey(), true);
            SSLSocket server = serverFuture.get(5, TimeUnit.SECONDS);
            byte[] audio = ("PRIVATE-AUDIO-FRAME-" + "voice".repeat(100)).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            proxy.tamper.set(true);
            client.getOutputStream().write(audio); client.getOutputStream().flush();
            assertThrows(SSLException.class, () -> server.getInputStream().readNBytes(audio.length));
            assertTrue(proxy.modified.get(), "The network proxy must actually modify an encrypted record");
            assertFalse(new String(proxy.captured(), java.nio.charset.StandardCharsets.ISO_8859_1).contains("PRIVATE-AUDIO-FRAME-"));
            proxy.disconnect(); // Interrupt idle peer reads before closing layered TLS sockets.
            try { client.close(); } catch (IOException ignored) { }
            try { server.close(); } catch (IOException ignored) { }
        }
    }

    @Test void codeMatchesBothDirectionsAndChangesWithFreshCertificatePair() throws Exception {
        try (var pair = connect(); var next = connect()) {
            String code = VoiceTls.shortCode(pair.caller.offer(), pair.callee.offer());
            assertEquals(code, VoiceTls.shortCode(pair.callee.offer(), pair.caller.offer()));
            assertTrue(code.matches("[0-9A-F]{4}( [0-9A-F]{4}){5}"));
            assertNotEquals(code, VoiceTls.shortCode(next.caller.offer(), next.callee.offer()));
        }
    }

    @Test void signedOffersHaveBoundedRoundTripAndDefensiveArrays() throws Exception {
        try (var pending = caller(UUID.randomUUID())) {
            var source = pending.offer();
            var output = new ByteArrayOutputStream(); source.write(new DataOutputStream(output));
            assertTrue(output.size() <= VoiceTls.MAX_OFFER_BYTES + 4);
            var decoded = VoiceTls.read(new DataInputStream(new ByteArrayInputStream(output.toByteArray())));
            decoded.verify(alice.publicKey(), bob.publicKey(), source.callId(), VoiceTls.Role.CALLER, System.currentTimeMillis());
            assertArrayEquals(source.certificate(), decoded.certificate());
            decoded.signature()[0] ^= 1; decoded.certificate()[0] ^= 1; decoded.identityPublicKey()[0] ^= 1;
            decoded.verify(alice.publicKey(), bob.publicKey(), source.callId(), VoiceTls.Role.CALLER, System.currentTimeMillis());
        }
    }

    @Test void rejectsContactIdentitySubstitution() throws Exception {
        try (var pending = caller(UUID.randomUUID())) {
            assertThrows(GeneralSecurityException.class, () -> pending.offer().verify(mallory.publicKey(), bob.publicKey(), pending.offer().callId(), VoiceTls.Role.CALLER, System.currentTimeMillis()));
        }
    }

    @Test void rejectsAnotherRecipientEvenWithValidSenderSignature() throws Exception {
        try (var pending = caller(UUID.randomUUID())) {
            assertThrows(GeneralSecurityException.class, () -> pending.offer().verify(alice.publicKey(), mallory.publicKey(), pending.offer().callId(), VoiceTls.Role.CALLER, System.currentTimeMillis()));
        }
    }

    @Test void rejectsCrossCallAndRoleReversal() throws Exception {
        try (var pending = caller(UUID.randomUUID())) {
            assertThrows(GeneralSecurityException.class, () -> pending.offer().verify(alice.publicKey(), bob.publicKey(), UUID.randomUUID(), VoiceTls.Role.CALLER, System.currentTimeMillis()));
            assertThrows(GeneralSecurityException.class, () -> pending.offer().verify(alice.publicKey(), bob.publicKey(), pending.offer().callId(), VoiceTls.Role.CALLEE, System.currentTimeMillis()));
        }
    }

    @Test void rejectsAlteredSignatureAndAlteredCertificate() throws Exception {
        try (var pending = caller(UUID.randomUUID())) {
            var source = pending.offer();
            byte[] signature = source.signature(); signature[3] ^= 1;
            var badSignature = copy(source, source.certificate(), signature);
            assertThrows(GeneralSecurityException.class, () -> badSignature.verify(alice.publicKey(), bob.publicKey(), source.callId(), source.role(), System.currentTimeMillis()));
            byte[] certificate = source.certificate(); certificate[certificate.length - 1] ^= 1;
            var badCertificate = copy(source, certificate, source.signature());
            assertThrows(GeneralSecurityException.class, () -> badCertificate.verify(alice.publicKey(), bob.publicKey(), source.callId(), source.role(), System.currentTimeMillis()));
        }
    }

    @Test void rejectsExpiredAndFutureSignedOffers() throws Exception {
        for (long delta : new long[] {-240_000, 90_000}) {
            long now = System.currentTimeMillis();
            try (var pending = VoiceTls.create(alice, UUID.randomUUID(), VoiceTls.Role.CALLER, bob.publicKey(), Clock.fixed(Instant.ofEpochMilli(now + delta), ZoneOffset.UTC))) {
                assertThrows(GeneralSecurityException.class, () -> pending.offer().verify(alice.publicKey(), bob.publicKey(), pending.offer().callId(), pending.offer().role(), now));
            }
        }
    }

    @Test void rejectsOversizedTruncatedUnsupportedAndTrailingOfferFields() throws Exception {
        assertThrows(IOException.class, () -> VoiceTls.read(new DataInputStream(new ByteArrayInputStream(ByteBuffer.allocate(4).putInt(VoiceTls.MAX_OFFER_BYTES + 1).array()))));
        assertThrows(IOException.class, () -> VoiceTls.read(new DataInputStream(new ByteArrayInputStream(new byte[0]))));
        try (var pending = caller(UUID.randomUUID())) {
            var output = new ByteArrayOutputStream(); pending.offer().write(new DataOutputStream(output));
            byte[] wire = output.toByteArray();
            ByteBuffer.wrap(wire).putInt(8, 2);
            assertThrows(IOException.class, () -> VoiceTls.read(new DataInputStream(new ByteArrayInputStream(wire))));
            output.reset(); pending.offer().write(new DataOutputStream(output));
            byte[] trailing = Arrays.copyOf(output.toByteArray(), output.size() + 1);
            ByteBuffer.wrap(trailing).putInt(output.size() - 3);
            assertThrows(IOException.class, () -> VoiceTls.read(new DataInputStream(new ByteArrayInputStream(trailing))));
        }
    }

    @Test void eachAttemptUsesDifferentEphemeralCertificateAndCannotReusePending() throws Exception {
        UUID id = UUID.randomUUID();
        try (var one = caller(id); var two = caller(id); var pair = connect()) {
            assertFalse(Arrays.equals(one.offer().certificate(), two.offer().certificate()));
            Socket unused = new Socket();
            assertThrows(GeneralSecurityException.class, () -> pair.caller.handshake(unused, pair.callee.offer(), bob.publicKey(), true));
            assertTrue(unused.isClosed());
        }
    }

    @Test void closedPendingCannotBeUsedAndNoSocketIsOpenedByLibrary() throws Exception {
        var pending = caller(UUID.randomUUID()); pending.close();
        Socket unconnected = new Socket();
        assertThrows(GeneralSecurityException.class, () -> pending.handshake(unconnected, pending.offer(), bob.publicKey(), true));
        assertTrue(unconnected.isClosed());
    }

    @Test void roleMismatchFailsBeforeAnyTlsApplicationData() throws Exception {
        UUID id = UUID.randomUUID();
        try (var pending = caller(id); var remote = callee(id); var sockets = new RawPair()) {
            assertThrows(GeneralSecurityException.class, () -> pending.handshake(sockets.client, remote.offer(), bob.publicKey(), false));
            assertEquals(-1, sockets.server.getInputStream().read());
        }
    }

    @Test void validIdentityCannotSubstituteAnotherTlsCertificateOnWire() throws Exception {
        UUID id = UUID.randomUUID();
        try (var caller = caller(id); var actualServer = callee(id); var advertisedServer = callee(id); var sockets = new RawPair(); var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<SSLSocket> server = executor.submit(() -> actualServer.handshake(sockets.server, caller.offer(), alice.publicKey(), false));
            assertThrows(IOException.class, () -> caller.handshake(sockets.client, advertisedServer.offer(), bob.publicKey(), true));
            assertThrows(ExecutionException.class, () -> server.get(5, TimeUnit.SECONDS));
        }
    }

    @Test void rejectsTls12PeerInsteadOfDowngrading() throws Exception { rejectsNonGlasPeer("TLSv1.2", VoiceTls.ALPN); }
    @Test void rejectsWrongAlpnInsteadOfReturningUnauthenticatedChannel() throws Exception { rejectsNonGlasPeer("TLSv1.3", "other/application"); }

    private void rejectsNonGlasPeer(String protocol, String alpn) throws Exception {
        UUID id = UUID.randomUUID();
        try (var caller = caller(id); var server = callee(id); var sockets = new RawPair(); var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<SSLSocket> accepted = executor.submit(() -> server.handshake(sockets.server, caller.offer(), alice.publicKey(), false));
            try (var client = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket(sockets.client, "test.invalid", sockets.client.getPort(), true)) {
                client.setUseClientMode(true); client.setEnabledProtocols(new String[] {protocol}); client.setSoTimeout(5000);
                var params = client.getSSLParameters(); params.setApplicationProtocols(new String[] {alpn}); client.setSSLParameters(params);
                assertThrows(IOException.class, client::startHandshake);
            }
            assertThrows(ExecutionException.class, () -> accepted.get(5, TimeUnit.SECONDS));
        }
    }

    private static VoiceTls.Offer copy(VoiceTls.Offer source, byte[] certificate, byte[] signature) {
        return new VoiceTls.Offer(source.callId(), source.role(), source.callerId(), source.calleeId(), source.issuedAtMillis(), source.expiresAtMillis(), source.identityPublicKey(), certificate, signature);
    }
    private static VoiceTls.Pending caller(UUID id) throws Exception { return VoiceTls.create(alice, id, VoiceTls.Role.CALLER, bob.publicKey()); }
    private static VoiceTls.Pending callee(UUID id) throws Exception { return VoiceTls.create(bob, id, VoiceTls.Role.CALLEE, alice.publicKey()); }

    private static Pair connect() throws Exception {
        UUID id = UUID.randomUUID();
        var caller = caller(id); var callee = callee(id);
        RawPair sockets = new RawPair();
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<SSLSocket> server = executor.submit(() -> callee.handshake(sockets.server, caller.offer(), alice.publicKey(), false));
            SSLSocket client = caller.handshake(sockets.client, callee.offer(), bob.publicKey(), true);
            return new Pair(caller, callee, client, server.get(5, TimeUnit.SECONDS), sockets);
        } catch (Exception bad) { caller.close(); callee.close(); sockets.close(); throw bad; }
    }

    private record Pair(VoiceTls.Pending caller, VoiceTls.Pending callee, SSLSocket client, SSLSocket server, RawPair sockets) implements AutoCloseable {
        public void close() throws IOException {
            // Both test peers are idle here. Close the owned transport first instead of
            // waiting synchronously for the other idle endpoint's TLS close_notify.
            sockets.close();
            try { client.close(); } catch (IOException ignored) { }
            try { server.close(); } catch (IOException ignored) { }
            caller.close(); callee.close();
        }
    }
    private static final class RawPair implements AutoCloseable {
        final Socket client, server;
        RawPair() throws IOException {
            try (var listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                listener.setSoTimeout(5000);
                client = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
                server = listener.accept(); client.setSoTimeout(5000); server.setSoTimeout(5000);
            }
        }
        public void close() throws IOException { try { client.close(); } finally { server.close(); } }
    }

    /** A real loopback TCP relay that mutates ciphertext after the real TLS handshake. */
    private static final class TamperingProxy implements AutoCloseable {
        final Socket client, server, inbound, outbound;
        final AtomicBoolean tamper = new AtomicBoolean(), modified = new AtomicBoolean();
        final ByteArrayOutputStream capture = new ByteArrayOutputStream();
        final ExecutorService pumps = Executors.newVirtualThreadPerTaskExecutor();
        TamperingProxy() throws IOException {
            try (var endpoint = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
                 var relay = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                endpoint.setSoTimeout(5000); relay.setSoTimeout(5000);
                client = new Socket(InetAddress.getLoopbackAddress(), relay.getLocalPort());
                inbound = relay.accept(); outbound = new Socket(InetAddress.getLoopbackAddress(), endpoint.getLocalPort()); server = endpoint.accept();
                client.setSoTimeout(5000); server.setSoTimeout(5000);
            }
            pumps.submit(() -> pump(inbound, outbound, true)); pumps.submit(() -> pump(outbound, inbound, false));
        }
        private void pump(Socket from, Socket to, boolean clientDirection) {
            try {
                byte[] buffer = new byte[32_768]; int count;
                while ((count = from.getInputStream().read(buffer)) != -1) {
                    if (clientDirection) {
                        synchronized (capture) { capture.write(buffer, 0, count); }
                        if (tamper.compareAndSet(true, false)) { buffer[count - 1] ^= 1; modified.set(true); }
                    }
                    to.getOutputStream().write(buffer, 0, count); to.getOutputStream().flush();
                }
            } catch (IOException closed) { }
        }
        byte[] captured() { synchronized (capture) { return capture.toByteArray(); } }
        void disconnect() {
            for (Socket socket : List.of(client, server, inbound, outbound)) try { socket.close(); } catch (IOException ignored) { }
            pumps.shutdownNow();
        }
        public void close() { disconnect(); }
    }
}
