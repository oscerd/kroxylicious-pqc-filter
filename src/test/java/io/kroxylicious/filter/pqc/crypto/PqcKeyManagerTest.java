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

import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig;
import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig.KemAlgorithm;
import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig.KeyConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PqcKeyManagerTest {

    @TempDir
    Path tempDir;

    @Test
    void shouldGenerateAndSaveKeysWhenFilesDoNotExist() throws Exception {
        // Given
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        // When
        PqcKeyManager keyManager = new PqcKeyManager(config);

        // Then
        assertThat(pubKeyPath).exists();
        assertThat(privKeyPath).exists();
        assertThat(keyManager.getKeyProvider()).isInstanceOf(FileSystemKeyProvider.class);
        assertThat(keyManager.getAlgorithm()).isEqualTo(KemAlgorithm.ML_KEM_768);
    }

    @Test
    void shouldLoadExistingKeys() throws Exception {
        // Given - generate and save keys first
        Path pubKeyPath = tempDir.resolve("existing-pub.der");
        Path privKeyPath = tempDir.resolve("existing-priv.der");
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine.saveKey(pubKeyPath, keyPair.getPublic().getEncoded());
        PqcCryptoEngine.saveKey(privKeyPath, keyPair.getPrivate().getEncoded());

        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        // When
        PqcKeyManager keyManager = new PqcKeyManager(config);

        // Then
        KeyPair loadedKeyPair = keyManager.getKeyProvider().getActiveKeyPair(KemAlgorithm.ML_KEM_768);
        assertThat(loadedKeyPair.getPublic().getEncoded())
                .isEqualTo(keyPair.getPublic().getEncoded());
        assertThat(loadedKeyPair.getPrivate().getEncoded())
                .isEqualTo(keyPair.getPrivate().getEncoded());
    }

    @Test
    void shouldCreateEngineFromKeyManager() throws Exception {
        // Given
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        PqcKeyManager keyManager = new PqcKeyManager(config);

        // When
        PqcCryptoEngine engine = keyManager.createEngine(false);

        // Then
        byte[] plaintext = "engine creation test".getBytes();
        byte[] encrypted = engine.encrypt(plaintext);
        byte[] decrypted = engine.decrypt(encrypted);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void shouldRejectUnknownKeyProviderType() {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                "/tmp/pub.der", "/tmp/priv.der", null, "nonexistent", null);

        assertThatThrownBy(() -> new PqcKeyManager(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No KeyProvider found for type 'nonexistent'");
    }

    @Test
    void shouldUseFilesystemProviderByDefault() throws Exception {
        // Given
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        // When
        PqcKeyManager keyManager = new PqcKeyManager(config);

        // Then
        assertThat(keyManager.getKeyProvider().type()).isEqualTo("filesystem");
    }

    @Test
    void shouldUseExplicitFilesystemProviderType() throws Exception {
        // Given
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, "filesystem", null);

        // When
        PqcKeyManager keyManager = new PqcKeyManager(config);

        // Then
        assertThat(keyManager.getKeyProvider()).isInstanceOf(FileSystemKeyProvider.class);
    }

    // --- Key rotation tests ---

    @Test
    void shouldPreloadRetiredKeysIntoEngineCache() throws Exception {
        // Given - two key pairs
        KeyPair kp1 = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        KeyPair kp2 = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);

        Path key1Dir = tempDir.resolve("key1");
        Path key2Dir = tempDir.resolve("key2");
        key1Dir.toFile().mkdirs();
        key2Dir.toFile().mkdirs();

        PqcCryptoEngine.saveKey(key1Dir.resolve("pub.der"), kp1.getPublic().getEncoded());
        PqcCryptoEngine.saveKey(key1Dir.resolve("priv.der"), kp1.getPrivate().getEncoded());
        PqcCryptoEngine.saveKey(key2Dir.resolve("pub.der"), kp2.getPublic().getEncoded());
        PqcCryptoEngine.saveKey(key2Dir.resolve("priv.der"), kp2.getPrivate().getEncoded());

        List<KeyConfig> keys = List.of(
                new KeyConfig("current", key1Dir.resolve("pub.der").toString(),
                        key1Dir.resolve("priv.der").toString()),
                new KeyConfig("retired", key2Dir.resolve("pub.der").toString(),
                        key2Dir.resolve("priv.der").toString()));

        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false, null, null, null, null, null,
                "current", keys);

        PqcKeyManager keyManager = new PqcKeyManager(config);

        // When
        PqcCryptoEngine activeEngine = keyManager.createEngine(false);

        // Then - encrypt with retired key and verify resolveEngine finds it
        PqcCryptoEngine retiredEngine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, kp2.getPublic(), kp2.getPrivate());
        byte[] encrypted = retiredEngine.encrypt("preload test".getBytes());

        PqcCryptoEngine resolved = keyManager.resolveEngine(encrypted);
        byte[] decrypted = resolved.decrypt(encrypted);
        assertThat(new String(decrypted)).isEqualTo("preload test");
    }

    @Test
    void shouldDecryptRecordsAfterKeyRotation() throws Exception {
        // Given - generate two key pairs and save them
        KeyPair kp1 = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        KeyPair kp2 = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);

        Path key1Dir = tempDir.resolve("key1");
        Path key2Dir = tempDir.resolve("key2");
        key1Dir.toFile().mkdirs();
        key2Dir.toFile().mkdirs();

        PqcCryptoEngine.saveKey(key1Dir.resolve("pub.der"), kp1.getPublic().getEncoded());
        PqcCryptoEngine.saveKey(key1Dir.resolve("priv.der"), kp1.getPrivate().getEncoded());
        PqcCryptoEngine.saveKey(key2Dir.resolve("pub.der"), kp2.getPublic().getEncoded());
        PqcCryptoEngine.saveKey(key2Dir.resolve("priv.der"), kp2.getPrivate().getEncoded());

        // Phase 1: encrypt records with key1 as the active key
        List<KeyConfig> phase1Keys = List.of(
                new KeyConfig("key1", key1Dir.resolve("pub.der").toString(),
                        key1Dir.resolve("priv.der").toString()));
        PqcEncryptionConfig phase1Config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false, null, null, null, null, null,
                "key1", phase1Keys);

        PqcKeyManager phase1Manager = new PqcKeyManager(phase1Config);
        PqcCryptoEngine phase1Engine = phase1Manager.createEngine(false);

        byte[] plaintext1 = "message encrypted with key1".getBytes();
        byte[] encrypted1 = phase1Engine.encrypt(plaintext1);

        // Phase 2: rotate to key2, keep key1 as retired
        List<KeyConfig> phase2Keys = List.of(
                new KeyConfig("key2", key2Dir.resolve("pub.der").toString(),
                        key2Dir.resolve("priv.der").toString()),
                new KeyConfig("key1", key1Dir.resolve("pub.der").toString(),
                        key1Dir.resolve("priv.der").toString()));
        PqcEncryptionConfig phase2Config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false, null, null, null, null, null,
                "key2", phase2Keys);

        PqcKeyManager phase2Manager = new PqcKeyManager(phase2Config);
        PqcCryptoEngine phase2Engine = phase2Manager.createEngine(false);

        // When - encrypt new records with key2
        byte[] plaintext2 = "message encrypted with key2".getBytes();
        byte[] encrypted2 = phase2Engine.encrypt(plaintext2);

        // Then - can decrypt both old (key1) and new (key2) records
        PqcCryptoEngine resolved1 = phase2Manager.resolveEngine(encrypted1);
        assertThat(resolved1.decrypt(encrypted1)).isEqualTo(plaintext1);

        PqcCryptoEngine resolved2 = phase2Manager.resolveEngine(encrypted2);
        assertThat(resolved2.decrypt(encrypted2)).isEqualTo(plaintext2);

        // Verify different engines are used for different keys
        assertThat(resolved1.getKeyId()).isNotEqualTo(resolved2.getKeyId());
    }

    @Test
    void shouldDecryptWithRotatedKeyInHybridMode() throws Exception {
        // Given - two key pairs with shared X25519
        KeyPair kp1 = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        KeyPair kp2 = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);

        Path key1Dir = tempDir.resolve("key1");
        Path key2Dir = tempDir.resolve("key2");
        key1Dir.toFile().mkdirs();
        key2Dir.toFile().mkdirs();

        PqcCryptoEngine.saveKey(key1Dir.resolve("pub.der"), kp1.getPublic().getEncoded());
        PqcCryptoEngine.saveKey(key1Dir.resolve("priv.der"), kp1.getPrivate().getEncoded());
        PqcCryptoEngine.saveKey(key2Dir.resolve("pub.der"), kp2.getPublic().getEncoded());
        PqcCryptoEngine.saveKey(key2Dir.resolve("priv.der"), kp2.getPrivate().getEncoded());

        // Phase 1: encrypt with key1 in hybrid mode
        List<KeyConfig> phase1Keys = List.of(
                new KeyConfig("key1", key1Dir.resolve("pub.der").toString(),
                        key1Dir.resolve("priv.der").toString()));
        PqcEncryptionConfig phase1Config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, true, null, null, null, null, null,
                "key1", phase1Keys);

        PqcKeyManager phase1Manager = new PqcKeyManager(phase1Config);
        PqcCryptoEngine phase1Engine = phase1Manager.createEngine(true);
        byte[] encrypted1 = phase1Engine.encrypt("hybrid key rotation test".getBytes());

        // Copy X25519 keys from key1Dir to key2Dir (shared X25519 across rotation)
        java.nio.file.Files.copy(key1Dir.resolve("x25519-public.der"),
                key2Dir.resolve("x25519-public.der"));
        java.nio.file.Files.copy(key1Dir.resolve("x25519-private.der"),
                key2Dir.resolve("x25519-private.der"));

        // Phase 2: rotate to key2, keep key1 as retired
        List<KeyConfig> phase2Keys = List.of(
                new KeyConfig("key2", key2Dir.resolve("pub.der").toString(),
                        key2Dir.resolve("priv.der").toString()),
                new KeyConfig("key1", key1Dir.resolve("pub.der").toString(),
                        key1Dir.resolve("priv.der").toString()));
        PqcEncryptionConfig phase2Config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, true, null, null, null, null, null,
                "key2", phase2Keys);

        PqcKeyManager phase2Manager = new PqcKeyManager(phase2Config);
        phase2Manager.createEngine(true);

        // When/Then - can decrypt old hybrid records using retired key
        PqcCryptoEngine resolved = phase2Manager.resolveEngine(encrypted1);
        byte[] decrypted = resolved.decrypt(encrypted1);
        assertThat(new String(decrypted)).isEqualTo("hybrid key rotation test");
    }

    @Test
    void shouldRejectUnknownKeyIdInResolveEngine() throws Exception {
        // Given - set up with a single key
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        PqcKeyManager keyManager = new PqcKeyManager(config);
        keyManager.createEngine(false);

        // Create an envelope encrypted with a different (unknown) key
        KeyPair unknownKp = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine unknownEngine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, unknownKp.getPublic(), unknownKp.getPrivate());
        byte[] encryptedWithUnknown = unknownEngine.encrypt("unknown key test".getBytes());

        // When/Then
        assertThatThrownBy(() -> keyManager.resolveEngine(encryptedWithUnknown))
                .isInstanceOf(java.security.GeneralSecurityException.class)
                .hasMessageContaining("No key pair found for key ID");
    }
}
