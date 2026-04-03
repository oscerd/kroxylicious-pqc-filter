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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PqcCryptoEngineTest {

    @ParameterizedTest
    @EnumSource(KemAlgorithm.class)
    void shouldEncryptAndDecryptWithAllKemVariants(KemAlgorithm algorithm) throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(algorithm);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                algorithm, false, keyPair.getPublic(), keyPair.getPrivate());
        byte[] plaintext = "Hello, Post-Quantum World!".getBytes(StandardCharsets.UTF_8);

        // When
        byte[] encrypted = engine.encrypt(plaintext);
        byte[] decrypted = engine.decrypt(encrypted);

        // Then
        assertThat(decrypted).isEqualTo(plaintext);
        assertThat(encrypted).isNotEqualTo(plaintext);
        assertThat(encrypted.length).isGreaterThan(plaintext.length);
    }

    @Test
    void shouldHandleNullPlaintext() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());

        // When/Then
        assertThat(engine.encrypt(null)).isNull();
        assertThat(engine.decrypt(null)).isNull();
    }

    @Test
    void shouldEncryptAndDecryptEmptyPayload() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());
        byte[] plaintext = new byte[0];

        // When
        byte[] encrypted = engine.encrypt(plaintext);
        byte[] decrypted = engine.decrypt(encrypted);

        // Then
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void shouldEncryptAndDecryptLargePayload() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());
        byte[] plaintext = new byte[1024 * 1024]; // 1MB
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) (i % 256);
        }

        // When
        byte[] encrypted = engine.encrypt(plaintext);
        byte[] decrypted = engine.decrypt(encrypted);

        // Then
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void shouldProduceDifferentCiphertextForSamePlaintext() throws Exception {
        // Given (each encryption uses a fresh KEM encapsulation + random IV)
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());
        byte[] plaintext = "deterministic test".getBytes(StandardCharsets.UTF_8);

        // When
        byte[] encrypted1 = engine.encrypt(plaintext);
        byte[] encrypted2 = engine.encrypt(plaintext);

        // Then - same plaintext should produce different ciphertext (semantic security)
        assertThat(encrypted1).isNotEqualTo(encrypted2);

        // Both should decrypt to the same plaintext
        assertThat(engine.decrypt(encrypted1)).isEqualTo(plaintext);
        assertThat(engine.decrypt(encrypted2)).isEqualTo(plaintext);
    }

    @Test
    void shouldRejectTamperedCiphertext() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());
        byte[] plaintext = "integrity test".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = engine.encrypt(plaintext);

        // Tamper with the ciphertext (flip a bit near the end, in the AES-GCM region)
        encrypted[encrypted.length - 5] ^= 0x01;

        // When/Then - AES-GCM should reject tampered data
        assertThatThrownBy(() -> engine.decrypt(encrypted))
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldRejectInvalidVersion() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());
        byte[] envelope = new byte[]{(byte) 0xFF, 0x00, 0x00}; // invalid version

        // When/Then
        assertThatThrownBy(() -> engine.decrypt(envelope))
                .isInstanceOf(java.security.GeneralSecurityException.class)
                .hasMessageContaining("Unsupported PQC envelope version");
    }

    @Test
    void shouldGenerateKeyPair() throws Exception {
        // When
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);

        // Then
        assertThat(keyPair).isNotNull();
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
        assertThat(keyPair.getPublic().getEncoded()).isNotEmpty();
        assertThat(keyPair.getPrivate().getEncoded()).isNotEmpty();
    }

    @Test
    void envelopeVersionByteShouldBePqcOnlyKeyed() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());
        byte[] plaintext = "version check".getBytes(StandardCharsets.UTF_8);

        // When
        byte[] encrypted = engine.encrypt(plaintext);

        // Then
        assertThat(encrypted[0]).isEqualTo((byte) 0x03); // VERSION_PQC_ONLY_KEYED
    }

    @Test
    void envelopeVersionByteShouldBeHybridKeyed() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, true, keyPair.getPublic(), keyPair.getPrivate());
        byte[] plaintext = "hybrid version check".getBytes(StandardCharsets.UTF_8);

        // When
        byte[] encrypted = engine.encrypt(plaintext);

        // Then
        assertThat(encrypted[0]).isEqualTo((byte) 0x04); // VERSION_HYBRID_KEYED
    }

    @ParameterizedTest
    @EnumSource(KemAlgorithm.class)
    void shouldEncryptAndDecryptInHybridModeWithAllKemVariants(KemAlgorithm algorithm) throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(algorithm);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                algorithm, true, keyPair.getPublic(), keyPair.getPrivate());
        byte[] plaintext = "Hybrid mode roundtrip test!".getBytes(StandardCharsets.UTF_8);

        // When
        byte[] encrypted = engine.encrypt(plaintext);
        byte[] decrypted = engine.decrypt(encrypted);

        // Then
        assertThat(encrypted[0]).isEqualTo((byte) 0x04); // VERSION_HYBRID_KEYED
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void shouldProduceDifferentCiphertextInHybridMode() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, true, keyPair.getPublic(), keyPair.getPrivate());
        byte[] plaintext = "hybrid semantic security".getBytes(StandardCharsets.UTF_8);

        // When
        byte[] encrypted1 = engine.encrypt(plaintext);
        byte[] encrypted2 = engine.encrypt(plaintext);

        // Then - different ciphertexts (fresh ephemeral X25519 + ML-KEM per call)
        assertThat(encrypted1).isNotEqualTo(encrypted2);
        assertThat(engine.decrypt(encrypted1)).isEqualTo(plaintext);
        assertThat(engine.decrypt(encrypted2)).isEqualTo(plaintext);
    }

    @Test
    void shouldDecryptWithProvidedX25519KeyPairAcrossEngineInstances() throws Exception {
        // Given - encrypt with engine1 using a persisted X25519 key pair
        KeyPair mlKemKeyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        KeyPair x25519KeyPair = PqcCryptoEngine.generateX25519KeyPair();

        PqcCryptoEngine engine1 = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, true,
                mlKemKeyPair.getPublic(), mlKemKeyPair.getPrivate(), x25519KeyPair);
        byte[] plaintext = "cross-restart test".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = engine1.encrypt(plaintext);

        // When - decrypt with engine2 using the same X25519 key pair (simulates restart)
        PqcCryptoEngine engine2 = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, true,
                mlKemKeyPair.getPublic(), mlKemKeyPair.getPrivate(), x25519KeyPair);
        byte[] decrypted = engine2.decrypt(encrypted);

        // Then
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void hybridModeShouldProduceLargerEnvelopeThanPqcOnly() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine pqcOnly = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());
        PqcCryptoEngine hybrid = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, true, keyPair.getPublic(), keyPair.getPrivate());
        byte[] plaintext = "size comparison".getBytes(StandardCharsets.UTF_8);

        // When
        byte[] pqcEncrypted = pqcOnly.encrypt(plaintext);
        byte[] hybridEncrypted = hybrid.encrypt(plaintext);

        // Then - hybrid adds 32 bytes for the X25519 ephemeral public key
        assertThat(hybridEncrypted.length).isEqualTo(pqcEncrypted.length + 32);
    }

    // --- Key ID tests ---

    @Test
    void shouldComputeDeterministicKeyId() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);

        // When
        int keyId1 = PqcCryptoEngine.computeKeyId(keyPair.getPublic());
        int keyId2 = PqcCryptoEngine.computeKeyId(keyPair.getPublic());

        // Then - same key always produces same ID
        assertThat(keyId1).isEqualTo(keyId2);
    }

    @Test
    void shouldComputeDifferentKeyIdsForDifferentKeys() throws Exception {
        // Given
        KeyPair keyPair1 = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        KeyPair keyPair2 = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);

        // When
        int keyId1 = PqcCryptoEngine.computeKeyId(keyPair1.getPublic());
        int keyId2 = PqcCryptoEngine.computeKeyId(keyPair2.getPublic());

        // Then - different keys produce different IDs (statistically near-certain)
        assertThat(keyId1).isNotEqualTo(keyId2);
    }

    @Test
    void shouldEmbedKeyIdInEnvelope() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());
        byte[] plaintext = "key id test".getBytes(StandardCharsets.UTF_8);

        // When
        byte[] encrypted = engine.encrypt(plaintext);

        // Then - key ID is at bytes 1-4
        int embeddedKeyId = ByteBuffer.wrap(encrypted, 1, 4).getInt();
        assertThat(embeddedKeyId).isEqualTo(engine.getKeyId());
    }

    @Test
    void shouldExtractKeyIdFromEnvelope() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());
        byte[] encrypted = engine.encrypt("extract test".getBytes(StandardCharsets.UTF_8));

        // When
        int extractedKeyId = PqcCryptoEngine.extractKeyId(encrypted);

        // Then
        assertThat(extractedKeyId).isEqualTo(engine.getKeyId());
    }

    @Test
    void shouldExtractKeyIdFromHybridEnvelope() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, true, keyPair.getPublic(), keyPair.getPrivate());
        byte[] encrypted = engine.encrypt("hybrid key id".getBytes(StandardCharsets.UTF_8));

        // When
        int extractedKeyId = PqcCryptoEngine.extractKeyId(encrypted);

        // Then
        assertThat(extractedKeyId).isEqualTo(engine.getKeyId());
    }

    @Test
    void shouldReturnNoKeyIdForLegacyEnvelope() throws Exception {
        // Given - construct a legacy v1 envelope manually
        byte[] legacyEnvelope = new byte[]{0x01, 0x00, 0x10}; // version=1, encapLen=16

        // When
        int keyId = PqcCryptoEngine.extractKeyId(legacyEnvelope);

        // Then
        assertThat(keyId).isEqualTo(PqcCryptoEngine.NO_KEY_ID);
    }

    @Test
    void shouldRejectExtractKeyIdFromNullEnvelope() {
        assertThatThrownBy(() -> PqcCryptoEngine.extractKeyId(null))
                .isInstanceOf(java.security.GeneralSecurityException.class)
                .hasMessageContaining("null or empty");
    }

    @Test
    void engineKeyIdShouldMatchComputedKeyId() throws Exception {
        // Given
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);

        // When
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());

        // Then
        assertThat(engine.getKeyId()).isEqualTo(PqcCryptoEngine.computeKeyId(keyPair.getPublic()));
    }
}
