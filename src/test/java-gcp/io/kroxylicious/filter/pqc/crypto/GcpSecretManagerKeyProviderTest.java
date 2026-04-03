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

import com.google.cloud.secretmanager.v1.AccessSecretVersionRequest;
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretPayload;
import com.google.protobuf.ByteString;
import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig;
import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig.KemAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GcpSecretManagerKeyProviderTest {

    @Mock
    SecretManagerServiceClient secretManagerClient;

    private GcpSecretManagerKeyProvider provider;
    private KeyPair testKeyPair;
    private String publicKeyB64;
    private String privateKeyB64;

    @BeforeEach
    void setUp() throws Exception {
        provider = new GcpSecretManagerKeyProvider();
        testKeyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        publicKeyB64 = Base64.getEncoder().encodeToString(testKeyPair.getPublic().getEncoded());
        privateKeyB64 = Base64.getEncoder().encodeToString(testKeyPair.getPrivate().getEncoded());
    }

    @Test
    void shouldReturnGcpSecretManagerType() {
        assertThat(provider.type()).isEqualTo("gcp-secret-manager");
    }

    @Test
    void shouldRejectMissingProjectId() {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false, null, null, null, "gcp-secret-manager",
                Map.of("secretId", "my-secret"));

        assertThatThrownBy(() -> provider.configure(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("project ID");
    }

    @Test
    void shouldRejectMissingSecretId() {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false, null, null, null, "gcp-secret-manager",
                Map.of("projectId", "my-project"));

        assertThatThrownBy(() -> provider.configure(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("secretId");
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
    void shouldFetchAndDecodeKeysFromGcp() throws Exception {
        injectClient(provider, secretManagerClient);
        setProviderFields("my-project", "my-secret", "latest");

        String jsonPayload = buildJsonPayload(publicKeyB64, privateKeyB64, null, null);
        AccessSecretVersionResponse response = buildResponse(
                "projects/my-project/secrets/my-secret/versions/3", jsonPayload);
        when(secretManagerClient.accessSecretVersion(any(AccessSecretVersionRequest.class)))
                .thenReturn(response);

        invokeMethod("fetchKeys", String.class, "latest");

        KeyPair keyPair = provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768);
        assertThat(keyPair.getPublic().getEncoded()).isEqualTo(testKeyPair.getPublic().getEncoded());
        assertThat(keyPair.getPrivate().getEncoded()).isEqualTo(testKeyPair.getPrivate().getEncoded());
        assertThat(provider.listKeyIds()).containsExactly("3");
    }

    @Test
    void shouldFetchKeysByVersion() throws Exception {
        injectClient(provider, secretManagerClient);
        setProviderFields("my-project", "my-secret", "latest");

        // Set up active key
        String jsonPayload = buildJsonPayload(publicKeyB64, privateKeyB64, null, null);
        AccessSecretVersionResponse latestResponse = buildResponse(
                "projects/my-project/secrets/my-secret/versions/2", jsonPayload);
        when(secretManagerClient.accessSecretVersion(any(AccessSecretVersionRequest.class)))
                .thenReturn(latestResponse);

        invokeMethod("fetchKeys", String.class, "latest");

        // Set up versioned fetch for an older version
        KeyPair olderKeyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        String olderPubB64 = Base64.getEncoder().encodeToString(olderKeyPair.getPublic().getEncoded());
        String olderPrivB64 = Base64.getEncoder().encodeToString(olderKeyPair.getPrivate().getEncoded());

        String olderPayload = buildJsonPayload(olderPubB64, olderPrivB64, null, null);
        AccessSecretVersionResponse olderResponse = buildResponse(
                "projects/my-project/secrets/my-secret/versions/1", olderPayload);
        when(secretManagerClient.accessSecretVersion(any(AccessSecretVersionRequest.class)))
                .thenReturn(olderResponse);

        KeyPair result = provider.getKeyPairById("1", KemAlgorithm.ML_KEM_768);
        assertThat(result.getPublic().getEncoded()).isEqualTo(olderKeyPair.getPublic().getEncoded());
    }

    @Test
    void shouldReturnCachedKeyForActiveVersion() throws Exception {
        injectClient(provider, secretManagerClient);
        setProviderFields("my-project", "my-secret", "latest");

        String jsonPayload = buildJsonPayload(publicKeyB64, privateKeyB64, null, null);
        AccessSecretVersionResponse response = buildResponse(
                "projects/my-project/secrets/my-secret/versions/5", jsonPayload);
        when(secretManagerClient.accessSecretVersion(any(AccessSecretVersionRequest.class)))
                .thenReturn(response);

        invokeMethod("fetchKeys", String.class, "latest");

        // Fetching by active version ID should return cached key
        KeyPair result = provider.getKeyPairById("5", KemAlgorithm.ML_KEM_768);
        assertThat(result.getPublic().getEncoded()).isEqualTo(testKeyPair.getPublic().getEncoded());
    }

    @Test
    void shouldRejectMissingPublicKeyInSecret() throws Exception {
        injectClient(provider, secretManagerClient);
        setProviderFields("my-project", "my-secret", "latest");

        String jsonPayload = "{\"privateKey\": \"" + privateKeyB64 + "\"}";
        AccessSecretVersionResponse response = buildResponse(
                "projects/my-project/secrets/my-secret/versions/1", jsonPayload);
        when(secretManagerClient.accessSecretVersion(any(AccessSecretVersionRequest.class)))
                .thenReturn(response);

        assertThatThrownBy(() -> invokeMethod("fetchKeys", String.class, "latest"))
                .hasCauseInstanceOf(GeneralSecurityException.class)
                .hasRootCauseMessage("GCP secret missing 'publicKey' field. "
                        + "Expected base64-encoded DER (X.509) ML-KEM public key.");
    }

    @Test
    void shouldRejectMissingPrivateKeyInSecret() throws Exception {
        injectClient(provider, secretManagerClient);
        setProviderFields("my-project", "my-secret", "latest");

        String jsonPayload = "{\"publicKey\": \"" + publicKeyB64 + "\"}";
        AccessSecretVersionResponse response = buildResponse(
                "projects/my-project/secrets/my-secret/versions/1", jsonPayload);
        when(secretManagerClient.accessSecretVersion(any(AccessSecretVersionRequest.class)))
                .thenReturn(response);

        assertThatThrownBy(() -> invokeMethod("fetchKeys", String.class, "latest"))
                .hasCauseInstanceOf(GeneralSecurityException.class)
                .hasRootCauseMessage("GCP secret missing 'privateKey' field. "
                        + "Expected base64-encoded DER (PKCS#8) ML-KEM private key.");
    }

    @Test
    void shouldProduceWorkingCryptoEngineKeys() throws Exception {
        injectClient(provider, secretManagerClient);
        setProviderFields("my-project", "my-secret", "latest");

        String jsonPayload = buildJsonPayload(publicKeyB64, privateKeyB64, null, null);
        AccessSecretVersionResponse response = buildResponse(
                "projects/my-project/secrets/my-secret/versions/1", jsonPayload);
        when(secretManagerClient.accessSecretVersion(any(AccessSecretVersionRequest.class)))
                .thenReturn(response);

        invokeMethod("fetchKeys", String.class, "latest");

        KeyPair keyPair = provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false, keyPair.getPublic(), keyPair.getPrivate());

        byte[] plaintext = "GCP Secret Manager roundtrip test".getBytes();
        byte[] encrypted = engine.encrypt(plaintext);
        byte[] decrypted = engine.decrypt(encrypted);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void shouldLoadX25519KeysFromGcp() throws Exception {
        injectClient(provider, secretManagerClient);
        setProviderFields("my-project", "my-secret", "latest");

        KeyPair x25519KeyPair = PqcCryptoEngine.generateX25519KeyPair();
        String x25519PubB64 = Base64.getEncoder().encodeToString(x25519KeyPair.getPublic().getEncoded());
        String x25519PrivB64 = Base64.getEncoder().encodeToString(x25519KeyPair.getPrivate().getEncoded());

        String jsonPayload = buildJsonPayload(publicKeyB64, privateKeyB64, x25519PubB64, x25519PrivB64);
        AccessSecretVersionResponse response = buildResponse(
                "projects/my-project/secrets/my-secret/versions/1", jsonPayload);
        when(secretManagerClient.accessSecretVersion(any(AccessSecretVersionRequest.class)))
                .thenReturn(response);

        invokeMethod("fetchKeys", String.class, "latest");

        assertThat(provider.getX25519KeyPair()).isNotNull();
        assertThat(provider.getX25519KeyPair().getPublic().getEncoded())
                .isEqualTo(x25519KeyPair.getPublic().getEncoded());
    }

    @Test
    void shouldReturnNullX25519WhenNotPresent() throws Exception {
        injectClient(provider, secretManagerClient);
        setProviderFields("my-project", "my-secret", "latest");

        String jsonPayload = buildJsonPayload(publicKeyB64, privateKeyB64, null, null);
        AccessSecretVersionResponse response = buildResponse(
                "projects/my-project/secrets/my-secret/versions/1", jsonPayload);
        when(secretManagerClient.accessSecretVersion(any(AccessSecretVersionRequest.class)))
                .thenReturn(response);

        invokeMethod("fetchKeys", String.class, "latest");

        assertThat(provider.getX25519KeyPair()).isNull();
    }

    @Test
    void shouldClearStateOnClose() throws Exception {
        injectClient(provider, secretManagerClient);
        setProviderFields("my-project", "my-secret", "latest");

        String jsonPayload = buildJsonPayload(publicKeyB64, privateKeyB64, null, null);
        AccessSecretVersionResponse response = buildResponse(
                "projects/my-project/secrets/my-secret/versions/1", jsonPayload);
        when(secretManagerClient.accessSecretVersion(any(AccessSecretVersionRequest.class)))
                .thenReturn(response);

        invokeMethod("fetchKeys", String.class, "latest");

        assertThat(provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768)).isNotNull();

        provider.close();
        assertThatThrownBy(() -> provider.getActiveKeyPair(KemAlgorithm.ML_KEM_768))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void shouldParseValidJsonPayload() throws Exception {
        String json = "{\"publicKey\": \"abc123\", \"privateKey\": \"def456\"}";
        Map<String, String> result = GcpSecretManagerKeyProvider.parseJsonPayload(json);
        assertThat(result).containsEntry("publicKey", "abc123")
                .containsEntry("privateKey", "def456");
    }

    @Test
    void shouldRejectEmptyJsonPayload() {
        assertThatThrownBy(() -> GcpSecretManagerKeyProvider.parseJsonPayload(""))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("null or blank");
    }

    @Test
    void shouldRejectMalformedJsonPayload() {
        assertThatThrownBy(() -> GcpSecretManagerKeyProvider.parseJsonPayload("not json at all"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Could not parse secret payload");
    }

    // --- Test helpers ---

    private void injectClient(GcpSecretManagerKeyProvider provider,
                              SecretManagerServiceClient client) throws Exception {
        Field field = GcpSecretManagerKeyProvider.class.getDeclaredField("client");
        field.setAccessible(true);
        field.set(provider, client);
    }

    private void setProviderFields(String project, String secret, String version) throws Exception {
        Field projectField = GcpSecretManagerKeyProvider.class.getDeclaredField("projectId");
        projectField.setAccessible(true);
        projectField.set(provider, project);

        Field secretField = GcpSecretManagerKeyProvider.class.getDeclaredField("secretId");
        secretField.setAccessible(true);
        secretField.set(provider, secret);

        Field versionField = GcpSecretManagerKeyProvider.class.getDeclaredField("activeVersion");
        versionField.setAccessible(true);
        versionField.set(provider, version);
    }

    private void invokeMethod(String methodName, Class<?> paramType, Object arg) throws Exception {
        var method = GcpSecretManagerKeyProvider.class.getDeclaredMethod(methodName, paramType);
        method.setAccessible(true);
        method.invoke(provider, arg);
    }

    private static AccessSecretVersionResponse buildResponse(String name, String payload) {
        return AccessSecretVersionResponse.newBuilder()
                .setName(name)
                .setPayload(SecretPayload.newBuilder()
                        .setData(ByteString.copyFromUtf8(payload))
                        .build())
                .build();
    }

    private static String buildJsonPayload(String pubKey, String privKey,
                                           String x25519Pub, String x25519Priv) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"publicKey\": \"").append(pubKey).append("\", ");
        sb.append("\"privateKey\": \"").append(privKey).append("\"");
        if (x25519Pub != null && x25519Priv != null) {
            sb.append(", \"x25519PublicKey\": \"").append(x25519Pub).append("\"");
            sb.append(", \"x25519PrivateKey\": \"").append(x25519Priv).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }
}
