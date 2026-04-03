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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FileSystemKeyProviderTest {

    @TempDir
    Path tempDir;

    @Test
    void shouldReturnFilesystemType() {
        FileSystemKeyProvider provider = new FileSystemKeyProvider();
        assertThat(provider.type()).isEqualTo("filesystem");
    }

    @Test
    void shouldGenerateKeysWhenFilesDoNotExist() throws Exception {
        // Given
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        FileSystemKeyProvider provider = new FileSystemKeyProvider();

        // When
        provider.configure(config);

        // Then
        assertThat(pubKeyPath).exists();
        assertThat(privKeyPath).exists();
        KeyPair keyPair = provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768);
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
    }

    @Test
    void shouldLoadExistingKeys() throws Exception {
        // Given - generate and save keys first
        Path pubKeyPath = tempDir.resolve("existing-pub.der");
        Path privKeyPath = tempDir.resolve("existing-priv.der");
        KeyPair originalKeyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine.saveKey(pubKeyPath, originalKeyPair.getPublic().getEncoded());
        PqcCryptoEngine.saveKey(privKeyPath, originalKeyPair.getPrivate().getEncoded());

        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        FileSystemKeyProvider provider = new FileSystemKeyProvider();

        // When
        provider.configure(config);

        // Then
        KeyPair loadedKeyPair = provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768);
        assertThat(loadedKeyPair.getPublic().getEncoded())
                .isEqualTo(originalKeyPair.getPublic().getEncoded());
        assertThat(loadedKeyPair.getPrivate().getEncoded())
                .isEqualTo(originalKeyPair.getPrivate().getEncoded());
    }

    @Test
    void shouldReturnDefaultKeyId() {
        FileSystemKeyProvider provider = new FileSystemKeyProvider();
        assertThat(provider.listKeyIds()).containsExactly("default");
    }

    @Test
    void shouldReturnKeyPairByDefaultId() throws Exception {
        // Given
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        FileSystemKeyProvider provider = new FileSystemKeyProvider();
        provider.configure(config);

        // When
        KeyPair keyPair = provider.getKeyPairById("default", KemAlgorithm.ML_KEM_768);

        // Then
        assertThat(keyPair.getPublic()).isNotNull();
        assertThat(keyPair.getPrivate()).isNotNull();
    }

    @Test
    void shouldRejectUnknownKeyId() throws Exception {
        // Given
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        FileSystemKeyProvider provider = new FileSystemKeyProvider();
        provider.configure(config);

        // When/Then
        assertThatThrownBy(() -> provider.getKeyPairById("unknown-key", KemAlgorithm.ML_KEM_768))
                .isInstanceOf(GeneralSecurityException.class)
                .hasMessageContaining("Unknown key ID 'unknown-key'");
    }

    @Test
    void shouldThrowWhenNotConfigured() {
        FileSystemKeyProvider provider = new FileSystemKeyProvider();

        assertThatThrownBy(() -> provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not been configured");
    }

    @Test
    void shouldRejectNullPublicKeyPath() {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                null, "/tmp/priv.der", null, null, null);

        FileSystemKeyProvider provider = new FileSystemKeyProvider();

        assertThatThrownBy(() -> provider.configure(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("publicKeyPath");
    }

    @Test
    void shouldRejectNullPrivateKeyPath() {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                "/tmp/pub.der", null, null, null, null);

        FileSystemKeyProvider provider = new FileSystemKeyProvider();

        assertThatThrownBy(() -> provider.configure(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("privateKeyPath");
    }

    @Test
    void shouldProduceWorkingCryptoEngineKeys() throws Exception {
        // Given
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        FileSystemKeyProvider provider = new FileSystemKeyProvider();
        provider.configure(config);
        KeyPair keyPair = provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768);

        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());

        // When
        byte[] plaintext = "KeyProvider roundtrip test".getBytes();
        byte[] encrypted = engine.encrypt(plaintext);
        byte[] decrypted = engine.decrypt(encrypted);

        // Then
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void shouldGenerateX25519KeysWhenHybridModeEnabled() throws Exception {
        // Given
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, true,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        FileSystemKeyProvider provider = new FileSystemKeyProvider();

        // When
        provider.configure(config);

        // Then
        assertThat(tempDir.resolve("x25519-public.der")).exists();
        assertThat(tempDir.resolve("x25519-private.der")).exists();
        assertThat(provider.getX25519KeyPair()).isNotNull();
        assertThat(provider.getX25519KeyPair().getPublic()).isNotNull();
        assertThat(provider.getX25519KeyPair().getPrivate()).isNotNull();
    }

    @Test
    void shouldLoadExistingX25519Keys() throws Exception {
        // Given - generate and save keys first
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config1 = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, true,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        FileSystemKeyProvider provider1 = new FileSystemKeyProvider();
        provider1.configure(config1);
        KeyPair originalX25519 = provider1.getX25519KeyPair();

        // When - load with a fresh provider
        PqcEncryptionConfig config2 = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, true,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);
        FileSystemKeyProvider provider2 = new FileSystemKeyProvider();
        provider2.configure(config2);

        // Then - same X25519 keys loaded
        assertThat(provider2.getX25519KeyPair().getPublic().getEncoded())
                .isEqualTo(originalX25519.getPublic().getEncoded());
        assertThat(provider2.getX25519KeyPair().getPrivate().getEncoded())
                .isEqualTo(originalX25519.getPrivate().getEncoded());
    }

    @Test
    void shouldNotGenerateX25519KeysWhenHybridModeDisabled() throws Exception {
        // Given
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        FileSystemKeyProvider provider = new FileSystemKeyProvider();

        // When
        provider.configure(config);

        // Then
        assertThat(tempDir.resolve("x25519-public.der")).doesNotExist();
        assertThat(tempDir.resolve("x25519-private.der")).doesNotExist();
        assertThat(provider.getX25519KeyPair()).isNull();
    }

    @Test
    void shouldProduceWorkingHybridCryptoWithPersistedX25519Keys() throws Exception {
        // Given - first provider generates keys
        Path pubKeyPath = tempDir.resolve("pub.der");
        Path privKeyPath = tempDir.resolve("priv.der");
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, true,
                pubKeyPath.toString(), privKeyPath.toString(), null, null, null);

        FileSystemKeyProvider provider1 = new FileSystemKeyProvider();
        provider1.configure(config);
        KeyPair mlKem1 = provider1.getActiveKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine1 = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, true, mlKem1.getPublic(), mlKem1.getPrivate(),
                provider1.getX25519KeyPair());

        byte[] plaintext = "cross-restart hybrid test".getBytes();
        byte[] encrypted = engine1.encrypt(plaintext);

        // When - second provider loads the same keys (simulates restart)
        FileSystemKeyProvider provider2 = new FileSystemKeyProvider();
        provider2.configure(config);
        KeyPair mlKem2 = provider2.getActiveKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine2 = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, true, mlKem2.getPublic(), mlKem2.getPrivate(),
                provider2.getX25519KeyPair());

        byte[] decrypted = engine2.decrypt(encrypted);

        // Then
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void shouldBeDiscoverableViaServiceLoader() {
        ServiceLoader<KeyProvider> loader = ServiceLoader.load(KeyProvider.class);
        Iterator<KeyProvider> it = loader.iterator();
        boolean found = false;
        while (it.hasNext()) {
            try {
                KeyProvider provider = it.next();
                if ("filesystem".equals(provider.type())) {
                    found = true;
                    assertThat(provider).isInstanceOf(FileSystemKeyProvider.class);
                }
            }
            catch (ServiceConfigurationError e) {
                // Skip optional providers not on classpath (e.g., VaultKeyProvider)
            }
        }
        assertThat(found)
                .as("FileSystemKeyProvider should be discoverable via ServiceLoader")
                .isTrue();
    }
}
