/*
 * Copyright 2024 Kroxylicious Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.kroxylicious.filter.pqc.crypto;

import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig.KemAlgorithm;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Core PQC cryptographic engine providing ML-KEM key encapsulation
 * with AES-256-GCM symmetric encryption for Kafka record payloads.
 *
 * <p>Supports two modes:
 * <ul>
 *   <li><strong>PQC-only:</strong> ML-KEM encapsulation directly derives the AES key</li>
 *   <li><strong>Hybrid:</strong> Combines ML-KEM + X25519 ECDH shared secrets via
 *       HKDF to derive the AES key, providing defense-in-depth</li>
 * </ul>
 *
 * <h2>Encrypted message format</h2>
 * <pre>
 * PQC-only mode (v3, current):
 * [1 byte: version 0x03] [4 bytes: key ID] [2 bytes: encapsulation length]
 * [N bytes: ML-KEM encapsulation] [12 bytes: AES-GCM IV]
 * [remaining: AES-GCM ciphertext + 16-byte auth tag]
 *
 * Hybrid mode (v4, current):
 * [1 byte: version 0x04] [4 bytes: key ID] [2 bytes: encapsulation length]
 * [N bytes: ML-KEM encapsulation] [32 bytes: X25519 ephemeral public key]
 * [12 bytes: AES-GCM IV] [remaining: AES-GCM ciphertext + 16-byte auth tag]
 *
 * Legacy formats (v1/v2) without key ID are still supported for decryption.
 * </pre>
 */
public class PqcCryptoEngine {

    private static final Logger LOG = LoggerFactory.getLogger(PqcCryptoEngine.class);

    // Legacy envelope versions (no key ID)
    private static final byte VERSION_PQC_ONLY = 0x01;
    private static final byte VERSION_HYBRID = 0x02;
    // Current envelope versions (with 4-byte key ID)
    private static final byte VERSION_PQC_ONLY_KEYED = 0x03;
    private static final byte VERSION_HYBRID_KEYED = 0x04;

    private static final int KEY_ID_LENGTH = 4;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int AES_KEY_LENGTH = 32;
    private static final String AES_GCM = "AES/GCM/NoPadding";

    /** Sentinel value indicating no key ID is present (legacy envelope). */
    public static final int NO_KEY_ID = -1;

    private static final byte[] HKDF_SALT_PQC = "kroxylicious-pqc-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final byte[] HKDF_INFO_PQC = "pqc-aes256-key".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final byte[] HKDF_SALT_HYBRID = "kroxylicious-pqc-hybrid-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final byte[] HKDF_INFO_HYBRID = "hybrid-aes256-key".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private final KemAlgorithm kemAlgorithm;
    private final boolean hybridMode;
    private final PublicKey mlKemPublicKey;
    private final PrivateKey mlKemPrivateKey;
    private final SecureRandom secureRandom;
    private final int keyId;

    // Static X25519 key pair for hybrid mode (persistent across encrypt/decrypt)
    private final PublicKey x25519StaticPublicKey;
    private final PrivateKey x25519StaticPrivateKey;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public PqcCryptoEngine(KemAlgorithm kemAlgorithm, boolean hybridMode,
                           PublicKey mlKemPublicKey, PrivateKey mlKemPrivateKey) {
        this(kemAlgorithm, hybridMode, mlKemPublicKey, mlKemPrivateKey, null);
    }

    public PqcCryptoEngine(KemAlgorithm kemAlgorithm, boolean hybridMode,
                           PublicKey mlKemPublicKey, PrivateKey mlKemPrivateKey,
                           KeyPair x25519KeyPair) {
        this.kemAlgorithm = kemAlgorithm;
        this.hybridMode = hybridMode;
        this.mlKemPublicKey = mlKemPublicKey;
        this.mlKemPrivateKey = mlKemPrivateKey;
        this.secureRandom = new SecureRandom();

        if (hybridMode) {
            if (x25519KeyPair != null) {
                this.x25519StaticPublicKey = x25519KeyPair.getPublic();
                this.x25519StaticPrivateKey = x25519KeyPair.getPrivate();
            }
            else {
                try {
                    KeyPair generated = generateX25519KeyPair();
                    this.x25519StaticPublicKey = generated.getPublic();
                    this.x25519StaticPrivateKey = generated.getPrivate();
                }
                catch (GeneralSecurityException e) {
                    throw new IllegalStateException("Failed to generate X25519 static key pair for hybrid mode", e);
                }
            }
            this.keyId = computeKeyId(mlKemPublicKey, x25519StaticPublicKey);
        }
        else {
            this.x25519StaticPublicKey = null;
            this.x25519StaticPrivateKey = null;
            this.keyId = computeKeyId(mlKemPublicKey);
        }
    }

    /**
     * Encrypt a plaintext payload using ML-KEM + AES-256-GCM.
     *
     * @param plaintext the raw Kafka record value
     * @return the encrypted envelope containing the KEM encapsulation and ciphertext
     * @throws GeneralSecurityException if any cryptographic operation fails
     */
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException {
        if (plaintext == null) {
            return null;
        }

        // Step 1: ML-KEM encapsulation - generate shared secret + encapsulation
        KeyGenerator kemKeyGen = KeyGenerator.getInstance("Kyber", "BCPQC");
        kemKeyGen.init(new KEMGenerateSpec(mlKemPublicKey, "AES"), secureRandom);
        SecretKeyWithEncapsulation encapsulatedKey = (SecretKeyWithEncapsulation) kemKeyGen.generateKey();

        byte[] mlKemSecret = encapsulatedKey.getEncoded();
        byte[] encapsulation = encapsulatedKey.getEncapsulation();

        byte[] aesKeyBytes;
        byte[] ephemeralX25519PubKey = null;

        if (hybridMode) {
            // Step 2a (Hybrid): X25519 ECDH key agreement
            KeyPairGenerator x25519Gen = KeyPairGenerator.getInstance("X25519");
            KeyPair ephemeralKp = x25519Gen.generateKeyPair();
            ephemeralX25519PubKey = ephemeralKp.getPublic().getEncoded();
            // Extract raw 32-byte X25519 public key from X.509 encoding
            ephemeralX25519PubKey = extractRawX25519PublicKey(ephemeralX25519PubKey);

            // For hybrid mode, we derive the AES key by hashing both secrets together
            // HKDF-like derivation: SHA-256(mlKemSecret || x25519SharedSecret)
            byte[] x25519Secret = performX25519Agreement(ephemeralKp);
            aesKeyBytes = deriveHybridKey(mlKemSecret, x25519Secret);
            Arrays.fill(x25519Secret, (byte) 0);
        }
        else {
            // Step 2b (PQC-only): derive AES key directly from ML-KEM secret
            aesKeyBytes = deriveKey(mlKemSecret);
        }

        // Step 3: AES-256-GCM encryption
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_GCM);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Step 4: Assemble the encrypted envelope
        Arrays.fill(aesKeyBytes, (byte) 0);
        Arrays.fill(mlKemSecret, (byte) 0);

        return assembleEnvelope(encapsulation, ephemeralX25519PubKey, iv, ciphertext);
    }

    /**
     * Decrypt an encrypted envelope back to plaintext.
     *
     * @param envelope the encrypted message envelope
     * @return the decrypted Kafka record value
     * @throws GeneralSecurityException if decryption or verification fails
     */
    public byte[] decrypt(byte[] envelope) throws GeneralSecurityException {
        if (envelope == null) {
            return null;
        }

        ByteBuffer buf = ByteBuffer.wrap(envelope);

        // Read version byte
        byte version = buf.get();
        boolean isHybridEnvelope;
        switch (version) {
            case VERSION_PQC_ONLY:
            case VERSION_PQC_ONLY_KEYED:
                isHybridEnvelope = false;
                break;
            case VERSION_HYBRID:
            case VERSION_HYBRID_KEYED:
                isHybridEnvelope = true;
                break;
            default:
                throw new GeneralSecurityException("Unsupported PQC envelope version: " + version);
        }

        // Skip key ID for keyed versions (already extracted by caller if needed)
        if (version == VERSION_PQC_ONLY_KEYED || version == VERSION_HYBRID_KEYED) {
            buf.getInt(); // skip 4-byte key ID
        }

        // Read ML-KEM encapsulation
        int encapLen = Short.toUnsignedInt(buf.getShort());
        byte[] encapsulation = new byte[encapLen];
        buf.get(encapsulation);

        // Step 1: ML-KEM decapsulation - recover shared secret
        KeyGenerator kemKeyGen = KeyGenerator.getInstance("Kyber", "BCPQC");
        kemKeyGen.init(new KEMExtractSpec(mlKemPrivateKey, encapsulation, "AES"), secureRandom);
        SecretKeyWithEncapsulation decapsulatedKey = (SecretKeyWithEncapsulation) kemKeyGen.generateKey();
        byte[] mlKemSecret = decapsulatedKey.getEncoded();

        byte[] aesKeyBytes;

        if (isHybridEnvelope) {
            // Read X25519 ephemeral public key
            byte[] ephemeralX25519PubKeyRaw = new byte[X25519_PUBLIC_KEY_LENGTH];
            buf.get(ephemeralX25519PubKeyRaw);

            // Recover X25519 shared secret using our static X25519 private key
            // For hybrid decryption, the receiver needs a persistent X25519 key pair
            // We derive it deterministically from the ML-KEM private key for simplicity
            byte[] x25519Secret = performX25519Decapsulation(ephemeralX25519PubKeyRaw);
            aesKeyBytes = deriveHybridKey(mlKemSecret, x25519Secret);
            Arrays.fill(x25519Secret, (byte) 0);
        }
        else {
            aesKeyBytes = deriveKey(mlKemSecret);
        }

        // Step 2: Read IV and ciphertext
        byte[] iv = new byte[GCM_IV_LENGTH];
        buf.get(iv);
        byte[] ciphertext = new byte[buf.remaining()];
        buf.get(ciphertext);

        // Step 3: AES-256-GCM decryption
        Cipher cipher = Cipher.getInstance(AES_GCM);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] plaintext = cipher.doFinal(ciphertext);

        Arrays.fill(aesKeyBytes, (byte) 0);
        Arrays.fill(mlKemSecret, (byte) 0);

        return plaintext;
    }

    /**
     * Generate a new ML-KEM key pair and write to the specified paths.
     */
    public static KeyPair generateKeyPair(KemAlgorithm algorithm) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(getKyberParameterSpec(algorithm), new SecureRandom());
        return kpg.generateKeyPair();
    }

    /**
     * Load an ML-KEM public key from a file (X.509 DER encoded).
     */
    public static PublicKey loadPublicKey(Path path) throws GeneralSecurityException, IOException {
        byte[] keyBytes = Files.readAllBytes(path);
        KeyFactory kf = KeyFactory.getInstance("Kyber", "BCPQC");
        return kf.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    /**
     * Load an ML-KEM private key from a file (PKCS#8 DER encoded).
     */
    public static PrivateKey loadPrivateKey(Path path) throws GeneralSecurityException, IOException {
        byte[] keyBytes = Files.readAllBytes(path);
        KeyFactory kf = KeyFactory.getInstance("Kyber", "BCPQC");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    /**
     * Save a key to file in DER format.
     */
    public static void saveKey(Path path, byte[] encodedKey) throws IOException {
        Files.createDirectories(path.getParent());
        Files.write(path, encodedKey);
    }

    /**
     * Return the key ID for this engine, derived from the key material used for encryption.
     * In PQC-only mode this is derived from the ML-KEM public key alone.
     * In hybrid mode this incorporates both the ML-KEM and X25519 public keys.
     */
    public int getKeyId() {
        return keyId;
    }

    /**
     * Compute a 4-byte key ID from an ML-KEM public key (PQC-only mode).
     * The key ID is the first 4 bytes of SHA-256(publicKey.getEncoded()),
     * interpreted as a big-endian int.
     */
    public static int computeKeyId(PublicKey publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(publicKey.getEncoded());
            return ByteBuffer.wrap(hash, 0, KEY_ID_LENGTH).getInt();
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Compute a 4-byte key ID from both ML-KEM and X25519 public keys (hybrid mode).
     * The key ID is the first 4 bytes of SHA-256(mlKemPublicKey.getEncoded() || x25519PublicKey.getEncoded()),
     * interpreted as a big-endian int. This ensures the key ID changes if either key changes.
     */
    public static int computeKeyId(PublicKey mlKemPublicKey, PublicKey x25519PublicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(mlKemPublicKey.getEncoded());
            byte[] hash = digest.digest(x25519PublicKey.getEncoded());
            return ByteBuffer.wrap(hash, 0, KEY_ID_LENGTH).getInt();
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Extract the key ID from an encrypted envelope without decrypting it.
     *
     * @param envelope the encrypted envelope bytes
     * @return the key ID, or {@link #NO_KEY_ID} if the envelope uses a legacy format (v1/v2)
     * @throws GeneralSecurityException if the envelope is too short or has an unsupported version
     */
    public static int extractKeyId(byte[] envelope) throws GeneralSecurityException {
        if (envelope == null || envelope.length < 1) {
            throw new GeneralSecurityException("Envelope is null or empty");
        }
        byte version = envelope[0];
        if (version == VERSION_PQC_ONLY || version == VERSION_HYBRID) {
            return NO_KEY_ID;
        }
        if (version == VERSION_PQC_ONLY_KEYED || version == VERSION_HYBRID_KEYED) {
            if (envelope.length < 1 + KEY_ID_LENGTH) {
                throw new GeneralSecurityException("Envelope too short to contain key ID");
            }
            return ByteBuffer.wrap(envelope, 1, KEY_ID_LENGTH).getInt();
        }
        throw new GeneralSecurityException("Unsupported PQC envelope version: " + version);
    }

    /**
     * Generate a new X25519 key pair for hybrid mode.
     */
    public static KeyPair generateX25519KeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        return kpg.generateKeyPair();
    }

    /**
     * Load an X25519 public key from a file (X.509 DER encoded).
     */
    public static PublicKey loadX25519PublicKey(Path path) throws GeneralSecurityException, IOException {
        byte[] keyBytes = Files.readAllBytes(path);
        KeyFactory kf = KeyFactory.getInstance("X25519");
        return kf.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    /**
     * Load an X25519 private key from a file (PKCS#8 DER encoded).
     */
    public static PrivateKey loadX25519PrivateKey(Path path) throws GeneralSecurityException, IOException {
        byte[] keyBytes = Files.readAllBytes(path);
        KeyFactory kf = KeyFactory.getInstance("X25519");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    // --- Internal helpers ---

    private byte[] assembleEnvelope(byte[] encapsulation, byte[] ephemeralX25519PubKey,
                                    byte[] iv, byte[] ciphertext) {
        byte version = hybridMode ? VERSION_HYBRID_KEYED : VERSION_PQC_ONLY_KEYED;
        int totalSize = 1 + KEY_ID_LENGTH + 2 + encapsulation.length + GCM_IV_LENGTH + ciphertext.length;
        if (hybridMode) {
            totalSize += X25519_PUBLIC_KEY_LENGTH;
        }

        ByteBuffer buf = ByteBuffer.allocate(totalSize);
        buf.put(version);
        buf.putInt(keyId);
        buf.putShort((short) encapsulation.length);
        buf.put(encapsulation);
        if (hybridMode && ephemeralX25519PubKey != null) {
            buf.put(ephemeralX25519PubKey);
        }
        buf.put(iv);
        buf.put(ciphertext);

        return buf.array();
    }

    private byte[] deriveKey(byte[] secret) {
        // HKDF-SHA256 (RFC 5869) extract-and-expand
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(secret, HKDF_SALT_PQC, HKDF_INFO_PQC));
        byte[] okm = new byte[AES_KEY_LENGTH];
        hkdf.generateBytes(okm, 0, AES_KEY_LENGTH);
        return okm;
    }

    private byte[] deriveHybridKey(byte[] pqcSecret, byte[] classicalSecret) {
        // HKDF-SHA256 (RFC 5869) extract-and-expand with concatenated IKM
        byte[] ikm = new byte[pqcSecret.length + classicalSecret.length];
        System.arraycopy(pqcSecret, 0, ikm, 0, pqcSecret.length);
        System.arraycopy(classicalSecret, 0, ikm, pqcSecret.length, classicalSecret.length);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, HKDF_SALT_HYBRID, HKDF_INFO_HYBRID));
        byte[] okm = new byte[AES_KEY_LENGTH];
        hkdf.generateBytes(okm, 0, AES_KEY_LENGTH);
        Arrays.fill(ikm, (byte) 0);
        return okm;
    }

    private byte[] performX25519Agreement(KeyPair ephemeralKp) throws GeneralSecurityException {
        // ECDH key agreement: ephemeral private key + static receiver public key
        // The static public key is persistent across the engine's lifetime, ensuring
        // that the decrypt side (which holds the matching static private key) can
        // recover the same shared secret.
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(ephemeralKp.getPrivate());
        ka.doPhase(x25519StaticPublicKey, true);
        return ka.generateSecret();
    }

    private byte[] performX25519Decapsulation(byte[] ephemeralPubKeyRaw) throws GeneralSecurityException {
        // Reconstruct ephemeral X25519 public key from the envelope and perform
        // ECDH key agreement with our persistent static private key.
        // This mirrors performX25519Agreement(): ECDH(ephPriv, staticPub) == ECDH(staticPriv, ephPub)
        KeyFactory kf = KeyFactory.getInstance("X25519");
        byte[] x509Encoded = wrapRawX25519PublicKey(ephemeralPubKeyRaw);
        PublicKey ephemeralPubKey = kf.generatePublic(new X509EncodedKeySpec(x509Encoded));

        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(x25519StaticPrivateKey);
        ka.doPhase(ephemeralPubKey, true);
        return ka.generateSecret();
    }

    private byte[] extractRawX25519PublicKey(byte[] x509Encoded) {
        // X25519 X.509 SubjectPublicKeyInfo is 44 bytes; raw key is last 32
        if (x509Encoded.length == X25519_PUBLIC_KEY_LENGTH) {
            return x509Encoded;
        }
        byte[] raw = new byte[X25519_PUBLIC_KEY_LENGTH];
        System.arraycopy(x509Encoded, x509Encoded.length - X25519_PUBLIC_KEY_LENGTH,
                raw, 0, X25519_PUBLIC_KEY_LENGTH);
        return raw;
    }

    private byte[] wrapRawX25519PublicKey(byte[] raw) {
        // Wrap raw 32-byte X25519 key in X.509 SubjectPublicKeyInfo structure
        byte[] x509Header = new byte[]{
                0x30, 0x2a, // SEQUENCE (42 bytes)
                0x30, 0x05, // SEQUENCE (5 bytes) - AlgorithmIdentifier
                0x06, 0x03, 0x2b, 0x65, 0x6e, // OID 1.3.101.110 (X25519)
                0x03, 0x21, 0x00 // BIT STRING (33 bytes, 0 unused bits)
        };
        byte[] result = new byte[x509Header.length + raw.length];
        System.arraycopy(x509Header, 0, result, 0, x509Header.length);
        System.arraycopy(raw, 0, result, x509Header.length, raw.length);
        return result;
    }

    static KyberParameterSpec getKyberParameterSpec(KemAlgorithm algorithm) {
        return switch (algorithm) {
            case ML_KEM_512 -> KyberParameterSpec.kyber512;
            case ML_KEM_768 -> KyberParameterSpec.kyber768;
            case ML_KEM_1024 -> KyberParameterSpec.kyber1024;
        };
    }
}
