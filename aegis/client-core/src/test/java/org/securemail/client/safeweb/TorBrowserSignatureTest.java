package org.securemail.client.safeweb;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/** Cryptographic verification with ephemeral RSA keypairs; never touches production secrets. */
class TorBrowserSignatureTest {
    private static final Instant NOW = Instant.parse("2026-10-15T00:00:00Z");
    private static final Instant CREATED = NOW.minusSeconds(3600);
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static PGPKeyPair primary;
    private static PGPKeyPair subkey;
    @TempDir Path root;

    @BeforeAll static void generateTestKeys() throws Exception {
        primary = key();
        subkey = key();
    }

    /** Optional test-tool fixture exporter. Exports only a throwaway public key and signature. */
    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 2) throw new IllegalArgumentException("archive output-directory");
        generateTestKeys();
        var fixture = fixture(true, true, false, false, false, 0);
        var directory = Files.createDirectories(Path.of(arguments[1]));
        byte[] bytes = Files.readAllBytes(Path.of(arguments[0]));
        Files.write(directory.resolve("fixture-public.asc"), armor(fixture.keyring));
        Files.write(directory.resolve("fixture-signature.asc"), armor(sign(bytes, subkey, HashAlgorithmTags.SHA256, NOW.minusSeconds(60))));
        Files.writeString(directory.resolve("fixture-fingerprint.txt"), pin());
    }

    @Test void authenticatesBinaryBytesAndReturnsExactHash() throws Exception {
        var fixture = fixture(false, true, false, false, false, 0);
        var verified = verify(fixture);
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(fixture.payload)), verified.sha256());
        assertEquals(pin(), verified.primaryFingerprint());
        assertEquals(pin(), verified.signingFingerprint());
        assertEquals(fixture.payload.length, verified.size());
        assertEquals(NOW.minusSeconds(60), verified.signatureCreated());
    }

    @Test void verifiesCertifiedSigningSubkeyAndBackSignature() throws Exception {
        var fixture = fixture(true, true, false, false, false, 0);
        assertEquals(fingerprint(subkey.getPublicKey()), verify(fixture).signingFingerprint());
    }

    @Test void productionPinCannotBeReplacedByCallerProvidedKey() throws Exception {
        var fixture = fixture(false, true, false, false, false, 0);
        Path archive = write("tor.tar.xz", fixture.payload), asc = write("tor.tar.xz.asc", fixture.signature);
        assertThrows(IOException.class, () -> TorBrowserSignature.verify(archive, asc, new ByteArrayInputStream(fixture.keyring)));
        // Also exercises loading and parsing the actual embedded official Tor public key.
        IOException missing = assertThrows(IOException.class, () -> TorBrowserSignature.verify(archive, asc));
        assertEquals("Detached signature uses an unknown signing key", missing.getMessage());
    }

    @Test void rejectsModifiedDistribution() throws Exception {
        var fixture = fixture(true, true, false, false, false, 0);
        fixture.payload[10] ^= 1;
        assertThrows(IOException.class, () -> verify(fixture));
    }

    @Test void rejectsWrongPrimaryFingerprint() throws Exception {
        var fixture = fixture(false, true, false, false, false, 0);
        assertThrows(IOException.class, () -> TorBrowserSignature.verifyTrusted(
                write("tor.tar.xz", fixture.payload), write("tor.asc", fixture.signature),
                new ByteArrayInputStream(fixture.keyring), "0".repeat(40), CLOCK));
    }

    @Test void rejectsUnboundSigningSubkey() throws Exception {
        var fixture = fixture(true, true, false, false, false, 0);
        var parsed = new PGPPublicKeyRing(fixture.keyring, new BcKeyFingerprintCalculator());
        var unbound = parsed.getPublicKey(subkey.getKeyID());
        var bindings = unbound.getSignatures();
        while (bindings.hasNext()) unbound = PGPPublicKey.removeCertification(unbound, bindings.next());
        var stripped = PGPPublicKeyRing.insertPublicKey(parsed, unbound);
        assertThrows(IOException.class, () -> verify(new Fixture(fixture.payload, fixture.signature, stripped.getEncoded())));
    }

    @Test void rejectsMissingBackSignature() throws Exception {
        assertThrows(IOException.class, () -> verify(fixture(true, false, false, false, false, 0)));
    }

    @Test void rejectsRevokedPrimaryKey() throws Exception {
        assertThrows(IOException.class, () -> verify(fixture(false, true, true, false, false, 0)));
    }

    @Test void rejectsRevokedSigningSubkey() throws Exception {
        assertThrows(IOException.class, () -> verify(fixture(true, true, false, true, false, 0)));
    }

    @Test void rejectsExpiredSigningKey() throws Exception {
        assertThrows(IOException.class, () -> verify(fixture(true, true, false, false, false, 60)));
    }

    @Test void rejectsFutureSignature() throws Exception {
        var f = fixture(true, true, false, false, true, 0);
        assertThrows(IOException.class, () -> verify(f));
    }

    @Test void rejectsWeakSha1DetachedSignature() throws Exception {
        var f = fixture(false, true, false, false, false, 0);
        byte[] weak = sign(f.payload, primary, HashAlgorithmTags.SHA1, NOW.minusSeconds(60));
        assertThrows(IOException.class, () -> verify(new Fixture(f.payload, weak, f.keyring)));
    }

    @Test void rejectsKeyWithoutSigningPermission() throws Exception {
        var cert = packets(primary, CREATED, KeyFlags.CERTIFY_OTHER, 0);
        var generator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, primary,
                "Ephemeral fixture", new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), cert, null, signer(), null);
        var payload = payload();
        assertThrows(IOException.class, () -> verify(new Fixture(payload, sign(payload, primary, HashAlgorithmTags.SHA256, NOW.minusSeconds(60)),
                generator.generatePublicKeyRing().getEncoded())));
    }

    @Test void rejectsMultipleDetachedSignatures() throws Exception {
        var f = fixture(false, true, false, false, false, 0);
        var out = new ByteArrayOutputStream();
        out.write(f.signature); out.write(f.signature);
        assertThrows(IOException.class, () -> verify(new Fixture(f.payload, out.toByteArray(), f.keyring)));
    }

    @Test void rejectsMalformedOversizedAndCompressedMetadataBeforeParsing() throws Exception {
        var f = fixture(false, true, false, false, false, 0);
        for (byte[] invalid : List.of(new byte[0], new byte[] {(byte)0xc2, (byte)0xff, 0x7f, (byte)0xff, (byte)0xff, (byte)0xff},
                new byte[] {(byte)0xc2, (byte)0xe0, 1}, new byte[] {(byte)0xc8, 1, 0}, new byte[1024 * 1024 + 1]))
            assertThrows(IOException.class, () -> verify(new Fixture(f.payload, invalid, f.keyring)));
    }

    @Test void refusesSymlinksAndOversizedDistribution() throws Exception {
        var f = fixture(false, true, false, false, false, 0);
        Path archive = write("tor.tar.xz", f.payload), asc = write("tor.asc", f.signature);
        Path link = root.resolve("linked.tar.xz");
        Files.createSymbolicLink(link, archive);
        assertThrows(IOException.class, () -> TorBrowserSignature.verifyTrusted(link, asc, new ByteArrayInputStream(f.keyring), pin(), CLOCK));
        Path huge = root.resolve("huge.tar.xz");
        try (var file = new RandomAccessFile(huge.toFile(), "rw")) { file.setLength(TorBrowserSignature.MAX_ARCHIVE_BYTES + 1); }
        assertThrows(IOException.class, () -> TorBrowserSignature.verifyTrusted(huge, asc, new ByteArrayInputStream(f.keyring), pin(), CLOCK));
    }

    @Test void supportsAsciiArmoredDetachedSignatureAndPublicKey() throws Exception {
        var f = fixture(true, true, false, false, false, 0);
        assertEquals(pin(), verify(new Fixture(f.payload, armor(f.signature), armor(f.keyring))).primaryFingerprint());
    }

    private TorBrowserSignature.Verified verify(Fixture fixture) throws Exception {
        return TorBrowserSignature.verifyTrusted(write("tor.tar.xz", fixture.payload), write("tor.asc", fixture.signature),
                new ByteArrayInputStream(fixture.keyring), pin(), CLOCK);
    }

    private Path write(String name, byte[] bytes) throws IOException { return Files.write(root.resolve(name), bytes); }
    private record Fixture(byte[] payload, byte[] signature, byte[] keyring) { }

    private static Fixture fixture(boolean useSubkey, boolean crossCert, boolean revokePrimary,
                                   boolean revokeSubkey, boolean future, long keyExpiration) throws Exception {
        var cert = packets(primary, CREATED, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, keyExpiration);
        var generator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, primary,
                "AEGIS ephemeral verifier fixture <fixture.invalid>",
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), cert, null, signer(), null);
        if (useSubkey) {
            var binding = packets(primary, CREATED, KeyFlags.SIGN_DATA, keyExpiration);
            if (crossCert) {
                var back = new PGPSignatureGenerator(signer(), subkey.getPublicKey());
                back.init(PGPSignature.PRIMARYKEY_BINDING, subkey.getPrivateKey());
                back.setHashedSubpackets(packets(subkey, CREATED, KeyFlags.SIGN_DATA, 0));
                var authenticated = new PGPSignatureSubpacketGenerator(binding);
                authenticated.addEmbeddedSignature(false, back.generateCertification(primary.getPublicKey(), subkey.getPublicKey()));
                binding = authenticated.generate();
            }
            generator.addSubKey(subkey, binding, null);
        }
        PGPPublicKeyRing ring = generator.generatePublicKeyRing();
        if (revokePrimary) ring = PGPPublicKeyRing.insertPublicKey(ring, PGPPublicKey.addCertification(
                ring.getPublicKey(), revoke(primary, null)));
        if (revokeSubkey) ring = PGPPublicKeyRing.insertPublicKey(ring, PGPPublicKey.addCertification(
                ring.getPublicKey(subkey.getKeyID()), revoke(primary, subkey)));
        byte[] payload = payload();
        return new Fixture(payload, sign(payload, useSubkey ? subkey : primary, HashAlgorithmTags.SHA256,
                future ? NOW.plusSeconds(3600) : NOW.minusSeconds(60)), ring.getEncoded());
    }

    private static PGPSignature revoke(PGPKeyPair issuer, PGPKeyPair subject) throws Exception {
        var generator = new PGPSignatureGenerator(signer(), issuer.getPublicKey());
        generator.init(subject == null ? PGPSignature.KEY_REVOCATION : PGPSignature.SUBKEY_REVOCATION, issuer.getPrivateKey());
        generator.setHashedSubpackets(packets(issuer, NOW.minusSeconds(120), 0, 0));
        return subject == null ? generator.generateCertification(issuer.getPublicKey())
                : generator.generateCertification(issuer.getPublicKey(), subject.getPublicKey());
    }

    private static byte[] sign(byte[] payload, PGPKeyPair key, int hash, Instant signedAt) throws Exception {
        var generator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(key.getPublicKey().getAlgorithm(), hash), key.getPublicKey());
        generator.init(PGPSignature.BINARY_DOCUMENT, key.getPrivateKey());
        generator.setHashedSubpackets(packets(key, signedAt, KeyFlags.SIGN_DATA, 0));
        generator.update(payload);
        return generator.generate().getEncoded();
    }

    private static PGPSignatureSubpacketVector packets(PGPKeyPair issuer, Instant created, int flags, long expiry) {
        var packets = new PGPSignatureSubpacketGenerator();
        packets.setSignatureCreationTime(true, Date.from(created));
        packets.setIssuerFingerprint(false, issuer.getPublicKey());
        packets.setKeyFlags(false, flags);
        if (expiry > 0) packets.setKeyExpirationTime(false, expiry);
        return packets.generate();
    }

    private static BcPGPContentSignerBuilder signer() { return new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA256); }
    private static PGPKeyPair key() throws Exception {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 3072, 80));
        return new BcPGPKeyPair(4, PublicKeyAlgorithmTags.RSA_GENERAL, generator.generateKeyPair(), Date.from(CREATED));
    }

    private static byte[] armor(byte[] bytes) throws IOException {
        var output = new ByteArrayOutputStream();
        try (var armored = new ArmoredOutputStream(output)) { armored.write(bytes); }
        return output.toByteArray();
    }
    private static byte[] payload() { byte[] bytes = new byte[128 * 1024 + 37]; new SecureRandom().nextBytes(bytes); return bytes; }
    private static String fingerprint(PGPPublicKey key) { return HexFormat.of().withUpperCase().formatHex(key.getFingerprint()); }
    private static String pin() { return fingerprint(primary.getPublicKey()); }
}
