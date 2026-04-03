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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultVersionedKeyValueOperations;
import org.springframework.vault.support.Versioned;

import java.lang.reflect.Field;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VaultKeyProviderTest {

    @Mock
    VaultTemplate vaultTemplate;

    @Mock
    VaultVersionedKeyValueOperations kvOps;

    private VaultKeyProvider provider;
    private KeyPair testKeyPair;
    private String publicKeyB64;
    private String privateKeyB64;

    @BeforeEach
    void setUp() throws Exception {
        provider = new VaultKeyProvider();
        testKeyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        publicKeyB64 = Base64.getEncoder().encodeToString(testKeyPair.getPublic().getEncoded());
        privateKeyB64 = Base64.getEncoder().encodeToString(testKeyPair.getPrivate().getEncoded());
    }

    @Test
    void shouldReturnVaultType() {
        assertThat(provider.type()).isEqualTo("vault");
    }

    @Test
    void shouldRejectMissingSecretPath() {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false, null, null, null, "vault",
                Map.of("vaultAddress", "http://localhost:8200", "vaultToken", "test-token"));

        assertThatThrownBy(() -> provider.configure(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("secretPath");
    }

    @Test
    void shouldRejectMissingVaultAddress() {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false, null, null, null, "vault",
                Map.of("secretPath", "kroxylicious/pqc"));

        assertThatThrownBy(() -> provider.configure(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Vault address");
    }

    @Test
    void shouldRejectMissingTokenForTokenAuth() {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false, null, null, null, "vault",
                Map.of("vaultAddress", "http://localhost:8200",
                        "secretPath", "kroxylicious/pqc",
                        "authMethod", "token"));

        assertThatThrownBy(() -> provider.configure(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Vault token");
    }

    @Test
    void shouldRejectMissingAppRoleCredentials() {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false, null, null, null, "vault",
                Map.of("vaultAddress", "http://localhost:8200",
                        "secretPath", "kroxylicious/pqc",
                        "authMethod", "approle"));

        assertThatThrownBy(() -> provider.configure(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("roleId and secretId");
    }

    @Test
    void shouldRejectMissingKubeRole() {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false, null, null, null, "vault",
                Map.of("vaultAddress", "http://localhost:8200",
                        "secretPath", "kroxylicious/pqc",
                        "authMethod", "kubernetes"));

        assertThatThrownBy(() -> provider.configure(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("kubeRole");
    }

    @Test
    void shouldRejectUnsupportedAuthMethod() {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false, null, null, null, "vault",
                Map.of("vaultAddress", "http://localhost:8200",
                        "secretPath", "kroxylicious/pqc",
                        "authMethod", "ldap"));

        assertThatThrownBy(() -> provider.configure(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported Vault auth method: ldap");
    }

    @Test
    void shouldThrowWhenNotConfigured() {
        assertThatThrownBy(() -> provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not been configured");
    }

    @Test
    void shouldReturnEmptyKeyIdsWhenNotConfigured() {
        assertThat(provider.listKeyIds()).isEmpty();
    }

    @Test
    void shouldFetchAndDecodeKeysFromVault() throws Exception {
        // Inject the mocked VaultTemplate
        injectVaultTemplate(provider, vaultTemplate);

        Versioned<Map<String, Object>> secret = Versioned.create(
                Map.of("publicKey", publicKeyB64, "privateKey", privateKeyB64),
                Versioned.Version.from(3));

        doReturn(kvOps).when(vaultTemplate).opsForVersionedKeyValue("secret");
        doReturn(secret).when(kvOps).get("kroxylicious/pqc");

        // Set internal state to simulate post-configure
        setProviderFields("secret", "kroxylicious/pqc");

        // Trigger key fetch via reflection
        provider.getClass().getDeclaredMethod("fetchKeys").setAccessible(true);
        var fetchKeysMethod = provider.getClass().getDeclaredMethod("fetchKeys");
        fetchKeysMethod.setAccessible(true);
        fetchKeysMethod.invoke(provider);

        // Verify
        KeyPair keyPair = provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768);
        assertThat(keyPair.getPublic().getEncoded()).isEqualTo(testKeyPair.getPublic().getEncoded());
        assertThat(keyPair.getPrivate().getEncoded()).isEqualTo(testKeyPair.getPrivate().getEncoded());
        assertThat(provider.listKeyIds()).containsExactly("3");
    }

    @Test
    void shouldFetchKeysByVersion() throws Exception {
        injectVaultTemplate(provider, vaultTemplate);
        setProviderFields("secret", "kroxylicious/pqc");

        // Set up active key
        Versioned<Map<String, Object>> latestSecret = Versioned.create(
                Map.of("publicKey", publicKeyB64, "privateKey", privateKeyB64),
                Versioned.Version.from(2));
        when(vaultTemplate.opsForVersionedKeyValue("secret")).thenReturn(kvOps);
        when(kvOps.get("kroxylicious/pqc")).thenReturn(latestSecret);

        var fetchKeysMethod = provider.getClass().getDeclaredMethod("fetchKeys");
        fetchKeysMethod.setAccessible(true);
        fetchKeysMethod.invoke(provider);

        // Set up versioned fetch for an older version
        KeyPair olderKeyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        String olderPubB64 = Base64.getEncoder().encodeToString(olderKeyPair.getPublic().getEncoded());
        String olderPrivB64 = Base64.getEncoder().encodeToString(olderKeyPair.getPrivate().getEncoded());

        Versioned<Map<String, Object>> olderSecret = Versioned.create(
                Map.of("publicKey", olderPubB64, "privateKey", olderPrivB64),
                Versioned.Version.from(1));
        doReturn(olderSecret).when(kvOps).get(eq("kroxylicious/pqc"), eq(Versioned.Version.from(1)));

        // Fetch by version
        KeyPair result = provider.getKeyPairById("1", KemAlgorithm.ML_KEM_768);
        assertThat(result.getPublic().getEncoded()).isEqualTo(olderKeyPair.getPublic().getEncoded());
    }

    @Test
    void shouldReturnCachedKeyForActiveVersion() throws Exception {
        injectVaultTemplate(provider, vaultTemplate);
        setProviderFields("secret", "kroxylicious/pqc");

        Versioned<Map<String, Object>> secret = Versioned.create(
                Map.of("publicKey", publicKeyB64, "privateKey", privateKeyB64),
                Versioned.Version.from(5));
        doReturn(kvOps).when(vaultTemplate).opsForVersionedKeyValue("secret");
        doReturn(secret).when(kvOps).get("kroxylicious/pqc");

        var fetchKeysMethod = provider.getClass().getDeclaredMethod("fetchKeys");
        fetchKeysMethod.setAccessible(true);
        fetchKeysMethod.invoke(provider);

        // Fetching by active version ID should return cached key, no extra Vault call
        KeyPair result = provider.getKeyPairById("5", KemAlgorithm.ML_KEM_768);
        assertThat(result.getPublic().getEncoded()).isEqualTo(testKeyPair.getPublic().getEncoded());
    }

    @Test
    void shouldRejectInvalidVersionKeyId() throws Exception {
        injectVaultTemplate(provider, vaultTemplate);
        setProviderFields("secret", "kroxylicious/pqc");

        Versioned<Map<String, Object>> secret = Versioned.create(
                Map.of("publicKey", publicKeyB64, "privateKey", privateKeyB64),
                Versioned.Version.from(1));
        doReturn(kvOps).when(vaultTemplate).opsForVersionedKeyValue("secret");
        doReturn(secret).when(kvOps).get("kroxylicious/pqc");

        var fetchKeysMethod = provider.getClass().getDeclaredMethod("fetchKeys");
        fetchKeysMethod.setAccessible(true);
        fetchKeysMethod.invoke(provider);

        assertThatThrownBy(() -> provider.getKeyPairById("not-a-number", KemAlgorithm.ML_KEM_768))
                .isInstanceOf(GeneralSecurityException.class)
                .hasMessageContaining("Invalid Vault version key ID");
    }

    @Test
    void shouldRejectMissingPublicKeyInSecret() throws Exception {
        injectVaultTemplate(provider, vaultTemplate);
        setProviderFields("secret", "kroxylicious/pqc");

        Versioned<Map<String, Object>> secret = Versioned.create(
                Map.of("privateKey", privateKeyB64),
                Versioned.Version.from(1));
        doReturn(kvOps).when(vaultTemplate).opsForVersionedKeyValue("secret");
        doReturn(secret).when(kvOps).get("kroxylicious/pqc");

        var fetchKeysMethod = provider.getClass().getDeclaredMethod("fetchKeys");
        fetchKeysMethod.setAccessible(true);

        assertThatThrownBy(() -> fetchKeysMethod.invoke(provider))
                .hasCauseInstanceOf(GeneralSecurityException.class)
                .hasRootCauseMessage("Vault secret missing 'publicKey' field. "
                        + "Expected base64-encoded DER (X.509) ML-KEM public key.");
    }

    @Test
    void shouldRejectMissingPrivateKeyInSecret() throws Exception {
        injectVaultTemplate(provider, vaultTemplate);
        setProviderFields("secret", "kroxylicious/pqc");

        Versioned<Map<String, Object>> secret = Versioned.create(
                Map.of("publicKey", publicKeyB64),
                Versioned.Version.from(1));
        doReturn(kvOps).when(vaultTemplate).opsForVersionedKeyValue("secret");
        doReturn(secret).when(kvOps).get("kroxylicious/pqc");

        var fetchKeysMethod = provider.getClass().getDeclaredMethod("fetchKeys");
        fetchKeysMethod.setAccessible(true);

        assertThatThrownBy(() -> fetchKeysMethod.invoke(provider))
                .hasCauseInstanceOf(GeneralSecurityException.class)
                .hasRootCauseMessage("Vault secret missing 'privateKey' field. "
                        + "Expected base64-encoded DER (PKCS#8) ML-KEM private key.");
    }

    @Test
    void shouldProduceWorkingCryptoEngineKeys() throws Exception {
        injectVaultTemplate(provider, vaultTemplate);
        setProviderFields("secret", "kroxylicious/pqc");

        Versioned<Map<String, Object>> secret = Versioned.create(
                Map.of("publicKey", publicKeyB64, "privateKey", privateKeyB64),
                Versioned.Version.from(1));
        doReturn(kvOps).when(vaultTemplate).opsForVersionedKeyValue("secret");
        doReturn(secret).when(kvOps).get("kroxylicious/pqc");

        var fetchKeysMethod = provider.getClass().getDeclaredMethod("fetchKeys");
        fetchKeysMethod.setAccessible(true);
        fetchKeysMethod.invoke(provider);

        KeyPair keyPair = provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());

        byte[] plaintext = "Vault roundtrip test".getBytes();
        byte[] encrypted = engine.encrypt(plaintext);
        byte[] decrypted = engine.decrypt(encrypted);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void shouldClearStateOnClose() throws Exception {
        injectVaultTemplate(provider, vaultTemplate);
        setProviderFields("secret", "kroxylicious/pqc");

        Versioned<Map<String, Object>> secret = Versioned.create(
                Map.of("publicKey", publicKeyB64, "privateKey", privateKeyB64),
                Versioned.Version.from(1));
        doReturn(kvOps).when(vaultTemplate).opsForVersionedKeyValue("secret");
        doReturn(secret).when(kvOps).get("kroxylicious/pqc");

        var fetchKeysMethod = provider.getClass().getDeclaredMethod("fetchKeys");
        fetchKeysMethod.setAccessible(true);
        fetchKeysMethod.invoke(provider);

        // Verify keys are loaded
        assertThat(provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768)).isNotNull();

        // Close and verify state is cleared
        provider.close();
        assertThatThrownBy(() -> provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768))
                .isInstanceOf(IllegalStateException.class);
    }

    // --- Test helpers ---

    private void injectVaultTemplate(VaultKeyProvider provider, VaultTemplate template) throws Exception {
        Field field = VaultKeyProvider.class.getDeclaredField("vaultTemplate");
        field.setAccessible(true);
        field.set(provider, template);
    }

    private void setProviderFields(String engine, String path) throws Exception {
        Field engineField = VaultKeyProvider.class.getDeclaredField("secretEngine");
        engineField.setAccessible(true);
        engineField.set(provider, engine);

        Field pathField = VaultKeyProvider.class.getDeclaredField("secretPath");
        pathField.setAccessible(true);
        pathField.set(provider, path);
    }
}
