package org.securemail.client.safeweb;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.*;

/**
 * Verifies an official Tor Browser distribution, never an AEGIS update/signing identity.
 * No subprocess, trust database, secret key, DNS lookup or global security provider is used.
 * The only trust anchor is the full Tor Browser primary-key fingerprint published at
 * https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/ .
 *
 * <p>A successful result authenticates these exact bytes. Installation must stage an immutable
 * owner-only copy and compare its SHA-256 before extracting/running it. This class neither
 * executes an archive nor claims its version is fresh. An offline key snapshot cannot detect
 * a later unpublished revocation; callers may supply a refreshed public key with the same pin.</p>
 */
public final class TorBrowserSignature {
    public static final String PRIMARY_FINGERPRINT = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290";
    public static final long MAX_ARCHIVE_BYTES = 1024L * 1024 * 1024;
    private static final int MAX_METADATA_BYTES = 1024 * 1024;
    private static final int MAX_PACKET_BYTES = 64 * 1024;
    private static final Set<Integer> CRITICAL_TAGS = Set.of(
            SignatureSubpacketTags.CREATION_TIME, SignatureSubpacketTags.EXPIRE_TIME,
            SignatureSubpacketTags.KEY_EXPIRE_TIME, SignatureSubpacketTags.KEY_FLAGS,
            SignatureSubpacketTags.ISSUER_KEY_ID, SignatureSubpacketTags.ISSUER_FINGERPRINT,
            SignatureSubpacketTags.EMBEDDED_SIGNATURE, SignatureSubpacketTags.REVOCATION_REASON);

    private TorBrowserSignature() { }

    public record Verified(String sha256, String primaryFingerprint, String signingFingerprint,
                           Instant signatureCreated, long size) { }

    public static Verified verify(Path archive, Path detachedSignature) throws IOException {
        try (InputStream key = TorBrowserSignature.class.getResourceAsStream("tor-browser-developers.asc")) {
            if (key == null) throw failure("Tor Browser signing key is missing");
            return verify(archive, detachedSignature, key);
        }
    }

    /** Accepts a refreshed untrusted keyring; the production fingerprint cannot be overridden. */
    public static Verified verify(Path archive, Path detachedSignature, InputStream publicKey) throws IOException {
        return verifyTrusted(archive, detachedSignature, publicKey, PRIMARY_FINGERPRINT, Clock.systemUTC());
    }

    // Package-private deterministic fixture seam. Production API always pins PRIMARY_FINGERPRINT.
    static Verified verifyTrusted(Path archive, Path detachedSignature, InputStream publicKey,
                                  String expectedFingerprint, Clock clock) throws IOException {
        Objects.requireNonNull(publicKey, "publicKey");
        try {
            Instant now = clock.instant();
            byte[] keyBytes = decode(publicKey);
            validatePackets(keyBytes, false);
            PGPObjectFactory keyFactory = factory(keyBytes);
            Object keyObject = keyFactory.nextObject();
            if (!(keyObject instanceof PGPPublicKeyRing ring) || keyFactory.nextObject() != null)
                throw failure("Exactly one public keyring is required");
            PGPPublicKey primary = ring.getPublicKey();
            if (!primary.isMasterKey() || !fingerprint(primary).equals(expectedFingerprint))
                throw failure("Tor Browser primary signing fingerprint mismatch");
            checkKeyAlgorithm(primary);
            PGPSignature primaryBinding = primaryBinding(primary, now);
            keyTime(primary, primaryBinding, now, now);
            if (isRevoked(primary, primary, now)) throw failure("Primary signing key was revoked");

            byte[] signatureBytes;
            regularFile(detachedSignature, MAX_METADATA_BYTES);
            try (InputStream input = Files.newInputStream(detachedSignature, LinkOption.NOFOLLOW_LINKS)) {
                signatureBytes = decode(input);
            }
            validatePackets(signatureBytes, true);
            PGPObjectFactory signatureFactory = factory(signatureBytes);
            Object item = signatureFactory.nextObject();
            if (!(item instanceof PGPSignatureList signatures) || signatures.size() != 1
                    || signatureFactory.nextObject() != null)
                throw failure("Exactly one detached signature is required");
            PGPSignature signature = signatures.get(0);
            if (signature.getSignatureType() != PGPSignature.BINARY_DOCUMENT)
                throw failure("A binary detached signature is required");
            Instant signedAt = signatureTime(signature, now);
            PGPPublicKey signer = ring.getPublicKey(signature.getKeyID());
            if (signer == null) throw failure("Detached signature uses an unknown signing key");
            checkKeyAlgorithm(signer);
            signaturePolicy(signature, signer);
            keyTime(primary, primaryBinding, signedAt, now);
            if (signer.isMasterKey()) {
                requireSigningFlag(primaryBinding);
            } else {
                if (isRevoked(primary, signer, now)) throw failure("Signing subkey was revoked");
                PGPSignature binding = subkeyBinding(primary, signer, now);
                keyTime(signer, binding, signedAt, now);
                requireSigningFlag(binding);
                verifyCrossCertification(primary, signer, binding, now);
            }

            signature.init(new BcPGPContentVerifierBuilderProvider(), signer);
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            BasicFileAttributes before = regularFile(archive, MAX_ARCHIVE_BYTES);
            long bytes = 0;
            try (InputStream input = Files.newInputStream(archive, LinkOption.NOFOLLOW_LINKS)) {
                byte[] buffer = new byte[64 * 1024];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    bytes += count;
                    if (bytes > MAX_ARCHIVE_BYTES || bytes > before.size())
                        throw failure("Distribution changed or exceeds the size limit");
                    signature.update(buffer, 0, count);
                    hash.update(buffer, 0, count);
                }
            }
            BasicFileAttributes after = regularFile(archive, MAX_ARCHIVE_BYTES);
            if (bytes != before.size() || bytes != after.size()
                    || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || !Objects.equals(before.fileKey(), after.fileKey()))
                throw failure("Distribution changed during verification");
            if (!signature.verify()) throw failure("Invalid Tor Browser distribution signature");
            return new Verified(HexFormat.of().formatHex(hash.digest()), fingerprint(primary),
                    fingerprint(signer), signedAt, bytes);
        } catch (PGPException | NoSuchAlgorithmException | IllegalArgumentException e) {
            throw new IOException("Tor Browser distribution verification failed", e);
        }
    }

    private static PGPSignature primaryBinding(PGPPublicKey primary, Instant now) throws PGPException, IOException {
        PGPSignature latest = null;
        Iterator<PGPSignature> direct = primary.getSignaturesOfType(PGPSignature.DIRECT_KEY);
        while (direct.hasNext()) {
            PGPSignature candidate = direct.next();
            if (selfSignature(candidate, primary, now) && candidate.verifyCertification(primary))
                latest = newest(latest, candidate);
        }
        Iterator<byte[]> ids = primary.getRawUserIDs();
        while (ids.hasNext()) {
            byte[] id = ids.next();
            Iterator<PGPSignature> certificates = primary.getSignaturesForID(id);
            while (certificates.hasNext()) {
                PGPSignature candidate = certificates.next();
                if (PGPSignature.isCertification(candidate.getSignatureType())
                        && selfSignature(candidate, primary, now) && candidate.verifyCertification(id, primary))
                    latest = newest(latest, candidate);
            }
        }
        if (latest == null) throw failure("Primary key has no valid current self certification");
        signatureTime(latest, now);
        return latest;
    }

    private static PGPSignature subkeyBinding(PGPPublicKey primary, PGPPublicKey subkey, Instant now)
            throws PGPException, IOException {
        PGPSignature latest = null;
        Iterator<PGPSignature> bindings = subkey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
        while (bindings.hasNext()) {
            PGPSignature candidate = bindings.next();
            if (selfSignature(candidate, primary, now) && candidate.verifyCertification(primary, subkey))
                latest = newest(latest, candidate);
        }
        if (latest == null) throw failure("Signing subkey is not bound to the pinned primary key");
        signatureTime(latest, now);
        return latest;
    }

    private static void verifyCrossCertification(PGPPublicKey primary, PGPPublicKey subkey,
                                                 PGPSignature binding, Instant now) throws PGPException, IOException {
        PGPSignatureList embedded = binding.getHashedSubPackets().getEmbeddedSignatures();
        // RFC 4880 permits embedded back signatures in the unhashed area of the primary's
        // binding: their own cryptographic signature still binds both exact key packets.
        if (embedded.isEmpty() && binding.getUnhashedSubPackets() != null)
            embedded = binding.getUnhashedSubPackets().getEmbeddedSignatures();
        for (PGPSignature back : embedded) {
            if (back.getSignatureType() == PGPSignature.PRIMARYKEY_BINDING
                    && selfSignature(back, subkey, now) && back.verifyCertification(primary, subkey)) {
                signatureTime(back, now);
                return;
            }
        }
        throw failure("Signing subkey has no valid back signature");
    }

    private static boolean selfSignature(PGPSignature signature, PGPPublicKey signer, Instant now)
            throws PGPException, IOException {
        if (signature.getKeyID() != signer.getKeyID()) return false;
        signaturePolicy(signature, signer);
        PGPSignatureSubpacketVector hashed = signature.getHashedSubPackets();
        if (hashed.getSignatureCreationTime().toInstant().isAfter(now)) return false;
        signature.init(new BcPGPContentVerifierBuilderProvider(), signer);
        return true;
    }

    private static boolean isRevoked(PGPPublicKey primary, PGPPublicKey subject, Instant now)
            throws PGPException, IOException {
        int type = subject.isMasterKey() ? PGPSignature.KEY_REVOCATION : PGPSignature.SUBKEY_REVOCATION;
        Iterator<PGPSignature> revocations = subject.getSignaturesOfType(type);
        while (revocations.hasNext()) {
            PGPSignature signature = revocations.next();
            if (selfSignature(signature, primary, now)
                    && (subject.isMasterKey() ? signature.verifyCertification(primary)
                    : signature.verifyCertification(primary, subject))) return true;
        }
        return false;
    }

    private static void requireSigningFlag(PGPSignature binding) throws IOException {
        if ((binding.getHashedSubPackets().getKeyFlags() & KeyFlags.SIGN_DATA) == 0)
            throw failure("Key is not certified for signing distributions");
    }

    private static void keyTime(PGPPublicKey key, PGPSignature binding, Instant signedAt, Instant now) throws IOException {
        Instant created = key.getCreationTime().toInstant();
        if (created.isAfter(signedAt) || created.isAfter(now)) throw failure("Signing key was not yet valid");
        long seconds = binding.getHashedSubPackets().getKeyExpirationTime();
        if (seconds != 0 && (!created.plusSeconds(seconds).isAfter(now)
                || !created.plusSeconds(seconds).isAfter(signedAt))) throw failure("Signing key has expired");
    }

    private static Instant signatureTime(PGPSignature signature, Instant now) throws IOException {
        PGPSignatureSubpacketVector hashed = signature.getHashedSubPackets();
        if (hashed == null || hashed.getSignatureCreationTime() == null)
            throw failure("Signature has no authenticated creation time");
        for (int tag : new int[] { SignatureSubpacketTags.CREATION_TIME,
                SignatureSubpacketTags.EXPIRE_TIME, SignatureSubpacketTags.KEY_EXPIRE_TIME,
                SignatureSubpacketTags.KEY_FLAGS, SignatureSubpacketTags.ISSUER_FINGERPRINT })
            if (hashed.getSubpackets(tag).length > 1) throw failure("Ambiguous duplicate OpenPGP subpacket");
        Instant created = hashed.getSignatureCreationTime().toInstant();
        if (created.isAfter(now)) throw failure("Signature creation time is in the future");
        long expiration = hashed.getSignatureExpirationTime();
        if (expiration != 0 && !created.plusSeconds(expiration).isAfter(now))
            throw failure("Signature has expired");
        return created;
    }

    private static void signaturePolicy(PGPSignature signature, PGPPublicKey signer) throws IOException {
        if (signature.getVersion() != 4 || signature.getKeyAlgorithm() != signer.getAlgorithm())
            throw failure("Unsupported OpenPGP signature version or algorithm");
        if (!Set.of(HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA512)
                .contains(signature.getHashAlgorithm())) throw failure("Weak signature hash is rejected");
        PGPSignatureSubpacketVector hashed = signature.getHashedSubPackets();
        if (hashed == null || hashed.getSignatureCreationTime() == null)
            throw failure("Signature has no authenticated creation time");
        for (PGPSignatureSubpacketVector vector : new PGPSignatureSubpacketVector[] {
                hashed, signature.getUnhashedSubPackets() }) {
            if (vector == null) continue;
            for (int tag : vector.getCriticalTags()) if (!CRITICAL_TAGS.contains(tag))
                throw failure("Unsupported critical OpenPGP subpacket");
            if (vector.getIssuerFingerprint() != null && !MessageDigest.isEqual(
                    vector.getIssuerFingerprint().getFingerprint(), signer.getFingerprint()))
                throw failure("Signature issuer fingerprint mismatch");
        }
    }

    private static void checkKeyAlgorithm(PGPPublicKey key) throws IOException {
        if (key.getVersion() != 4 || (key.getAlgorithm() != PublicKeyAlgorithmTags.RSA_GENERAL
                && key.getAlgorithm() != PublicKeyAlgorithmTags.RSA_SIGN) || key.getBitStrength() < 3072)
            throw failure("Only Tor's RSA signing keys of at least 3072 bits are supported");
    }

    private static PGPSignature newest(PGPSignature previous, PGPSignature candidate) {
        return previous == null || candidate.getCreationTime().after(previous.getCreationTime()) ? candidate : previous;
    }

    private static String fingerprint(PGPPublicKey key) {
        return HexFormat.of().withUpperCase().formatHex(key.getFingerprint());
    }

    private static PGPObjectFactory factory(byte[] encoded) {
        return new PGPObjectFactory(encoded, new BcKeyFingerprintCalculator()).setThrowForUnknownCriticalPackets(true);
    }

    private static byte[] decode(InputStream input) throws IOException {
        byte[] raw = bounded(input);
        try (InputStream decoded = PGPUtil.getDecoderStream(new ByteArrayInputStream(raw))) {
            return bounded(decoded);
        }
    }

    private static byte[] bounded(InputStream input) throws IOException {
        byte[] bytes = input.readNBytes(MAX_METADATA_BYTES + 1);
        if (bytes.length > MAX_METADATA_BYTES) throw failure("OpenPGP metadata exceeds its size limit");
        return bytes;
    }

    /** Check packet lengths before BC parses them; reject compressed/partial/indefinite packets. */
    private static void validatePackets(byte[] bytes, boolean signature) throws IOException {
        int offset = 0, packets = 0;
        while (offset < bytes.length) {
            if (++packets > 512) throw failure("Too many OpenPGP packets");
            int header = bytes[offset++] & 255;
            if ((header & 0x80) == 0) throw failure("Invalid OpenPGP packet header");
            int tag;
            long length;
            if ((header & 0x40) != 0) {
                tag = header & 63;
                if (offset >= bytes.length) throw failure("Truncated OpenPGP packet");
                int first = bytes[offset++] & 255;
                if (first < 192) length = first;
                else if (first < 224) {
                    if (offset >= bytes.length) throw failure("Truncated OpenPGP packet");
                    length = ((first - 192) << 8) + (bytes[offset++] & 255) + 192;
                } else if (first == 255) {
                    if (offset + 4 > bytes.length) throw failure("Truncated OpenPGP packet");
                    length = 0;
                    for (int i = 0; i < 4; i++) length = (length << 8) | (bytes[offset++] & 255);
                } else throw failure("Partial OpenPGP packet lengths are not accepted");
            } else {
                tag = (header >> 2) & 15;
                int kind = header & 3;
                if (kind == 3) throw failure("Indefinite OpenPGP packet lengths are not accepted");
                int count = 1 << kind;
                if (offset + count > bytes.length) throw failure("Truncated OpenPGP packet");
                length = 0;
                for (int i = 0; i < count; i++) length = (length << 8) | (bytes[offset++] & 255);
            }
            if (signature ? tag != 2 : !Set.of(2, 6, 13, 14, 17).contains(tag))
                throw failure("Unexpected OpenPGP packet type");
            if (length <= 0 || length > MAX_PACKET_BYTES || length > bytes.length - offset)
                throw failure("Invalid or oversized OpenPGP packet length");
            offset += (int) length;
        }
        if (packets == 0) throw failure("Empty OpenPGP metadata");
    }

    private static BasicFileAttributes regularFile(Path path, long maximum) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile() || attributes.size() <= 0 || attributes.size() > maximum)
            throw failure("A bounded regular file is required");
        return attributes;
    }

    private static IOException failure(String reason) { return new IOException(reason); }
}
