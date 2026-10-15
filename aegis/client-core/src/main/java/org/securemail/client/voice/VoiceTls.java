package org.securemail.client.voice;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.securemail.client.crypto.Identity;
import org.securemail.protocol.Binary;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Standard JSSE TLS 1.3 over an externally supplied connected Tor socket.
 * An existing contact identity signs the public ephemeral certificate advertisement only;
 * no long-term private identity, custom media AEAD, key agreement or direct socket is used.
 * See GLAS-CRYPTOGRAPHY-2.5.0.md, written before this implementation.
 */
public final class VoiceTls {
    public static final String ALPN = "aegis-glas/1";
    public static final int MAX_OFFER_BYTES = 8192;
    public static final int HANDSHAKE_TIMEOUT_MILLIS = 15_000;
    public static final long OFFER_LIFETIME_MILLIS = 120_000;
    private static final long CLOCK_SKEW_MILLIS = 30_000;
    private static final int MAGIC = 0x474C5343, VERSION = 1;
    private static final String DOMAIN = "AEGIS/GLAS/CERT-BINDING/v1";
    private static final byte[] ED25519_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final Set<String> CIPHERS = Set.of("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256");

    private VoiceTls() { }
    public enum Role { CALLER, CALLEE; public Role peer() { return this == CALLER ? CALLEE : CALLER; } }

    public static Pending create(Identity identity, UUID callId, Role role, byte[] expectedPeerPublicKey)
            throws GeneralSecurityException, IOException {
        return create(identity, callId, role, expectedPeerPublicKey, Clock.systemUTC());
    }

    static Pending create(Identity identity, UUID callId, Role role, byte[] expectedPeerPublicKey, Clock clock)
            throws GeneralSecurityException, IOException {
        Objects.requireNonNull(identity); Objects.requireNonNull(callId); Objects.requireNonNull(role); Objects.requireNonNull(clock);
        byte[] localPublic = identity.publicKey();
        publicIdentity(localPublic); publicIdentity(expectedPeerPublicKey);
        if (MessageDigest.isEqual(localPublic, expectedPeerPublicKey)) throw new GeneralSecurityException("A voice call needs two distinct identities");
        long now = clock.millis();
        KeyPair ephemeral = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] certificate = certificate(ephemeral, now);
        String localId = Identity.id(localPublic), remoteId = Identity.id(expectedPeerPublicKey);
        Offer unsigned = new Offer(callId, role, role == Role.CALLER ? localId : remoteId,
                role == Role.CALLER ? remoteId : localId, now, Math.addExact(now, OFFER_LIFETIME_MILLIS),
                localPublic, certificate, new byte[64]);
        Offer signed = new Offer(callId, role, unsigned.callerId(), unsigned.calleeId(), now, unsigned.expiresAtMillis(),
                localPublic, certificate, identity.sign(unsigned.signingBytes()));
        return new Pending(signed, expectedPeerPublicKey, ephemeral.getPrivate(), clock);
    }

    /** Bounded, immutable public advertisement. It creates no trust until verify uses contact keys. */
    public record Offer(UUID callId, Role role, String callerId, String calleeId, long issuedAtMillis,
                        long expiresAtMillis, byte[] identityPublicKey, byte[] certificate, byte[] signature) {
        public Offer {
            Objects.requireNonNull(callId); Objects.requireNonNull(role);
            if (callerId == null || calleeId == null || !callerId.matches("[a-f0-9]{64}")
                    || !calleeId.matches("[a-f0-9]{64}") || callerId.equals(calleeId)) throw new IllegalArgumentException("Invalid voice participants");
            if (identityPublicKey == null || identityPublicKey.length != 44 || certificate == null
                    || certificate.length == 0 || certificate.length > 4096 || signature == null || signature.length != 64)
                throw new IllegalArgumentException("Invalid voice certificate advertisement");
            identityPublicKey = identityPublicKey.clone(); certificate = certificate.clone(); signature = signature.clone();
        }
        @Override public byte[] identityPublicKey() { return identityPublicKey.clone(); }
        @Override public byte[] certificate() { return certificate.clone(); }
        @Override public byte[] signature() { return signature.clone(); }

        byte[] signingBytes() throws IOException {
            return Binary.encode(out -> {
                Binary.text(out, DOMAIN); out.writeInt(MAGIC); out.writeInt(VERSION); Binary.text(out, ALPN);
                out.writeLong(callId.getMostSignificantBits()); out.writeLong(callId.getLeastSignificantBits());
                out.writeByte(role.ordinal()); Binary.text(out, callerId); Binary.text(out, calleeId);
                out.writeLong(issuedAtMillis); out.writeLong(expiresAtMillis);
                Binary.bytes(out, identityPublicKey); Binary.bytes(out, certificate); Binary.bytes(out, digest(certificate));
            });
        }

        public void verify(byte[] expectedRemoteKey, byte[] expectedLocalKey, UUID expectedCallId,
                           Role expectedRemoteRole, long nowMillis) throws GeneralSecurityException, IOException {
            publicIdentity(expectedRemoteKey); publicIdentity(expectedLocalKey); publicIdentity(identityPublicKey);
            if (!MessageDigest.isEqual(expectedRemoteKey, identityPublicKey) || !callId.equals(expectedCallId)
                    || role != expectedRemoteRole) throw new GeneralSecurityException("Voice identity, role or call ID mismatch");
            String remoteId = Identity.id(expectedRemoteKey), localId = Identity.id(expectedLocalKey);
            if (!callerId.equals(role == Role.CALLER ? remoteId : localId)
                    || !calleeId.equals(role == Role.CALLER ? localId : remoteId))
                throw new GeneralSecurityException("Voice advertisement has a different recipient");
            if (issuedAtMillis < 0 || issuedAtMillis > nowMillis + CLOCK_SKEW_MILLIS || expiresAtMillis <= nowMillis
                    || expiresAtMillis <= issuedAtMillis || expiresAtMillis - issuedAtMillis > OFFER_LIFETIME_MILLIS)
                throw new GeneralSecurityException("Expired or future voice advertisement");
            if (!Identity.verify(expectedRemoteKey, signingBytes(), signature)) throw new GeneralSecurityException("Invalid voice identity signature");
            validateCertificate(parseCertificate(certificate), nowMillis);
        }

        public void write(DataOutput output) throws IOException {
            byte[] bytes = Binary.encode(out -> {
                out.writeInt(MAGIC); out.writeInt(VERSION);
                out.writeLong(callId.getMostSignificantBits()); out.writeLong(callId.getLeastSignificantBits()); out.writeByte(role.ordinal());
                Binary.text(out, callerId); Binary.text(out, calleeId); out.writeLong(issuedAtMillis); out.writeLong(expiresAtMillis);
                Binary.bytes(out, identityPublicKey); Binary.bytes(out, certificate); Binary.bytes(out, signature);
            });
            if (bytes.length > MAX_OFFER_BYTES) throw new IOException("Voice offer is too large");
            Binary.bytes(output, bytes);
        }
    }

    public static Offer read(DataInput input) throws IOException {
        byte[] bytes = Binary.bytes(input, MAX_OFFER_BYTES);
        try (var in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (in.readInt() != MAGIC || in.readInt() != VERSION) throw new IOException("Unsupported voice certificate protocol");
            UUID id = new UUID(in.readLong(), in.readLong());
            int role = in.readUnsignedByte();
            if (role >= Role.values().length) throw new IOException("Unsupported voice role");
            Offer offer = new Offer(id, Role.values()[role], Binary.text(in, 64), Binary.text(in, 64),
                    in.readLong(), in.readLong(), Binary.bytes(in, 44), Binary.bytes(in, 4096), Binary.bytes(in, 64));
            Binary.end(in);
            return offer;
        } catch (IllegalArgumentException invalid) { throw new IOException("Invalid voice certificate offer", invalid); }
    }

    public static final class Pending implements AutoCloseable {
        private final Offer offer;
        private final byte[] expectedPeer;
        private final Clock clock;
        private final AtomicBoolean used = new AtomicBoolean(), closed = new AtomicBoolean();
        private volatile PrivateKey key;
        private volatile SSLSocket negotiating;
        private Pending(Offer offer, byte[] expectedPeer, PrivateKey key, Clock clock) {
            this.offer = offer; this.expectedPeer = expectedPeer.clone(); this.key = key; this.clock = clock;
        }
        public Offer offer() { return offer; }

        /** Owns connected on entry; any failure closes it. No connect()/DNS/plaintext fallback. */
        public SSLSocket handshake(Socket connected, Offer remote, byte[] expectedRemoteKey, boolean clientMode)
                throws IOException, GeneralSecurityException {
            SSLSocket tls = null;
            boolean success = false;
            try {
                if (closed.get() || !used.compareAndSet(false, true)) throw new GeneralSecurityException("Voice TLS attempt was already used or closed");
                if (!connected.isConnected() || connected.isClosed()) throw new IOException("A connected Tor socket is required");
                if (clientMode != (offer.role() == Role.CALLER)) throw new GeneralSecurityException("TLS role does not match the authenticated call role");
                if (!MessageDigest.isEqual(expectedPeer, expectedRemoteKey)) throw new GeneralSecurityException("Voice contact changed during setup");
                long now = clock.millis();
                offer.verify(offer.identityPublicKey(), expectedPeer, offer.callId(), offer.role(), now);
                remote.verify(expectedPeer, offer.identityPublicKey(), offer.callId(), offer.role().peer(), now);
                PrivateKey signingKey = key;
                if (signingKey == null || closed.get()) throw new GeneralSecurityException("Voice TLS attempt was closed");
                SSLContext context = SSLContext.getInstance("TLSv1.3", "SunJSSE");
                context.init(new KeyManager[] {new EphemeralKeyManager(signingKey, parseCertificate(offer.certificate()))},
                        new TrustManager[] {new PinnedTrust(remote.certificate(), clock)}, new SecureRandom());
                connected.setSoTimeout(HANDSHAKE_TIMEOUT_MILLIS);
                tls = (SSLSocket) context.getSocketFactory().createSocket(connected, "aegis-glas.invalid", connected.getPort(), true);
                negotiating = tls;
                tls.setUseClientMode(clientMode);
                SSLParameters parameters = tls.getSSLParameters();
                parameters.setProtocols(new String[] {"TLSv1.3"});
                parameters.setCipherSuites(Arrays.stream(context.getSupportedSSLParameters().getCipherSuites()).filter(CIPHERS::contains).toArray(String[]::new));
                parameters.setApplicationProtocols(new String[] {ALPN});
                parameters.setServerNames(List.of());
                parameters.setEndpointIdentificationAlgorithm(""); // Exact authenticated certificate pin replaces DNS identity.
                if (!clientMode) parameters.setNeedClientAuth(true);
                tls.setSSLParameters(parameters);
                tls.startHandshake();
                if (!"TLSv1.3".equals(tls.getSession().getProtocol()) || !ALPN.equals(tls.getApplicationProtocol())
                        || !CIPHERS.contains(tls.getSession().getCipherSuite())) throw new SSLHandshakeException("Voice TLS protocol mismatch");
                if (!MessageDigest.isEqual(remote.certificate(), tls.getSession().getPeerCertificates()[0].getEncoded()))
                    throw new SSLPeerUnverifiedException("Voice TLS peer certificate mismatch");
                byte[] binding = binding(offer, remote);
                tls.getOutputStream().write(binding); tls.getOutputStream().flush();
                byte[] received = tls.getInputStream().readNBytes(binding.length);
                if (!MessageDigest.isEqual(binding, received)) throw new SSLHandshakeException("Voice call context mismatch");
                remote.verify(expectedPeer, offer.identityPublicKey(), offer.callId(), offer.role().peer(), clock.millis());
                if (closed.get()) throw new IOException("Voice call setup was cancelled");
                tls.getSession().invalidate(); // Current connection continues; this attempt/context is never reused.
                negotiating = null; key = null; success = true;
                return tls;
            } finally {
                if (!success) {
                    negotiating = null; key = null;
                    // A failed setup has no media to drain. Closing the owned transport
                    // first also prevents an uncooperative peer stalling close_notify.
                    try { connected.close(); } finally { if (tls != null) tls.close(); }
                }
            }
        }

        @Override public void close() throws IOException {
            closed.set(true); used.set(true); key = null;
            SSLSocket socket = negotiating;
            if (socket != null) socket.close();
        }
    }

    /** Standard SunJSSE TLS 1.3 post-handshake KeyUpdate; no custom key schedule. */
    public static void requestKeyUpdate(SSLSocket socket) throws IOException {
        if (socket.isClosed() || !"TLSv1.3".equals(socket.getSession().getProtocol()) || !ALPN.equals(socket.getApplicationProtocol()))
            throw new SSLException("KeyUpdate requires an established Glas TLS 1.3 connection");
        if (!socket.getClass().getName().startsWith("sun.security.ssl."))
            throw new SSLException("Explicit Glas KeyUpdate requires the supported SunJSSE provider");
        socket.startHandshake();
    }

    /** Certificate-pair comparison code, not a TLS exporter. Use only after authenticated setup. */
    public static String shortCode(Offer first, Offer second) throws IOException {
        String value = HexFormat.of().withUpperCase().formatHex(Arrays.copyOf(binding(first, second), 12));
        return value.replaceAll("(.{4})(?!$)", "$1 ");
    }

    private static byte[] binding(Offer first, Offer second) throws IOException {
        Offer caller = first.role() == Role.CALLER ? first : second, callee = first.role() == Role.CALLEE ? first : second;
        if (caller.role() != Role.CALLER || callee.role() != Role.CALLEE || !caller.callId().equals(callee.callId())
                || !caller.callerId().equals(callee.callerId()) || !caller.calleeId().equals(callee.calleeId()))
            throw new IOException("Voice offers belong to different call contexts");
        return digest(Binary.encode(out -> {
            Binary.text(out, "AEGIS/GLAS/TLS-CONTEXT/v1"); caller.write(out); callee.write(out);
        }));
    }

    private static X509Certificate parseCertificate(byte[] bytes) throws CertificateException {
        var input = new ByteArrayInputStream(bytes);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        if (input.available() != 0) throw new CertificateException("Trailing voice certificate data");
        return certificate;
    }

    private static void validateCertificate(X509Certificate certificate, long now) throws GeneralSecurityException {
        certificate.checkValidity(new Date(now));
        if (!EdECObjectIdentifiers.id_Ed25519.getId().equals(certificate.getSigAlgOID())
                || certificate.getBasicConstraints() != -1 || certificate.hasUnsupportedCriticalExtension())
            throw new CertificateException("Unsupported voice certificate");
        publicIdentity(certificate.getPublicKey().getEncoded());
        boolean[] usage = certificate.getKeyUsage();
        if (usage == null || usage.length == 0 || !usage[0]) throw new CertificateException("Voice certificate cannot sign");
        certificate.verify(certificate.getPublicKey());
    }

    private static byte[] certificate(KeyPair pair, long now) throws GeneralSecurityException, IOException {
        AlgorithmIdentifier algorithm = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
        V3TBSCertificateGenerator generator = new V3TBSCertificateGenerator();
        generator.setSerialNumber(new ASN1Integer(new java.math.BigInteger(160, new SecureRandom()).setBit(159)));
        X500Name subject = new X500Name("CN=AEGIS Glas ephemeral");
        generator.setSignature(algorithm); generator.setIssuer(subject); generator.setSubject(subject);
        generator.setStartDate(new Time(new Date(now - 60_000))); generator.setEndDate(new Time(new Date(now + 7_200_000)));
        generator.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));
        ExtensionsGenerator extensions = new ExtensionsGenerator();
        extensions.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        extensions.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        extensions.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
        generator.setExtensions(extensions.generate());
        TBSCertificate tbs = generator.generateTBSCertificate();
        Signature signer = Signature.getInstance("Ed25519"); signer.initSign(pair.getPrivate()); signer.update(tbs.getEncoded(ASN1Encoding.DER));
        return new DERSequence(new ASN1Encodable[] {tbs, algorithm, new DERBitString(signer.sign())}).getEncoded(ASN1Encoding.DER);
    }

    private static void publicIdentity(byte[] encoded) throws GeneralSecurityException {
        if (encoded == null || encoded.length != 44 || !MessageDigest.isEqual(ED25519_PREFIX, Arrays.copyOf(encoded, ED25519_PREFIX.length)))
            throw new GeneralSecurityException("Unsupported Ed25519 identity encoding");
    }
    private static byte[] digest(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static final class EphemeralKeyManager extends X509ExtendedKeyManager {
        private final PrivateKey key;
        private final X509Certificate certificate;
        private EphemeralKeyManager(PrivateKey key, X509Certificate certificate) { this.key = key; this.certificate = certificate; }
        private static boolean accepts(String type) { return "EdDSA".equals(type) || "Ed25519".equals(type); }
        public String[] getClientAliases(String type, Principal[] issuers) { return accepts(type) ? new String[] {"glas"} : null; }
        public String[] getServerAliases(String type, Principal[] issuers) { return getClientAliases(type, issuers); }
        public String chooseClientAlias(String[] types, Principal[] issuers, Socket socket) { return Arrays.stream(types).anyMatch(EphemeralKeyManager::accepts) ? "glas" : null; }
        public String chooseServerAlias(String type, Principal[] issuers, Socket socket) { return accepts(type) ? "glas" : null; }
        public String chooseEngineClientAlias(String[] types, Principal[] issuers, SSLEngine engine) { return chooseClientAlias(types, issuers, null); }
        public String chooseEngineServerAlias(String type, Principal[] issuers, SSLEngine engine) { return chooseServerAlias(type, issuers, null); }
        public X509Certificate[] getCertificateChain(String alias) { return "glas".equals(alias) ? new X509Certificate[] {certificate} : null; }
        public PrivateKey getPrivateKey(String alias) { return "glas".equals(alias) ? key : null; }
    }

    private static final class PinnedTrust extends X509ExtendedTrustManager {
        private final byte[] expected;
        private final Clock clock;
        private PinnedTrust(byte[] expected, Clock clock) { this.expected = expected.clone(); this.clock = clock; }
        private void check(X509Certificate[] chain) throws CertificateException {
            try {
                if (chain == null || chain.length != 1 || !MessageDigest.isEqual(expected, chain[0].getEncoded()))
                    throw new CertificateException("Unpinned voice TLS certificate");
                validateCertificate(chain[0], clock.millis());
            } catch (GeneralSecurityException bad) { throw new CertificateException("Invalid pinned voice TLS certificate", bad); }
        }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        public void checkClientTrusted(X509Certificate[] chain, String type) throws CertificateException { check(chain); }
        public void checkServerTrusted(X509Certificate[] chain, String type) throws CertificateException { check(chain); }
        public void checkClientTrusted(X509Certificate[] chain, String type, Socket socket) throws CertificateException { check(chain); }
        public void checkServerTrusted(X509Certificate[] chain, String type, Socket socket) throws CertificateException { check(chain); }
        public void checkClientTrusted(X509Certificate[] chain, String type, SSLEngine engine) throws CertificateException { check(chain); }
        public void checkServerTrusted(X509Certificate[] chain, String type, SSLEngine engine) throws CertificateException { check(chain); }
    }
}
