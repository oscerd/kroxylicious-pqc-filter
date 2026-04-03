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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.KeyPair;

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
}
