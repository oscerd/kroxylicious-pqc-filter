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
import com.google.cloud.secretmanager.v1.SecretManagerServiceSettings;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig;
import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig.KemAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@link KeyProvider} implementation that fetches ML-KEM key material
 * from Google Cloud Secret Manager.
 *
 * <p>Keys are stored as a JSON payload in a GCP secret with base64-encoded
 * DER values under the keys {@code publicKey} and {@code privateKey}.
 * For hybrid mode, optional {@code x25519PublicKey} and {@code x25519PrivateKey}
 * fields are also supported.
 *
 * <p>Authentication uses Google Application Default Credentials (ADC) by default,
 * which covers:
 * <ul>
 *   <li>GKE Workload Identity</li>
 *   <li>Compute Engine metadata server</li>
 *   <li>{@code GOOGLE_APPLICATION_CREDENTIALS} environment variable</li>
 *   <li>{@code gcloud auth application-default login} for local development</li>
 * </ul>
 * Alternatively, a service account JSON key file can be specified via the
 * {@code credentialsPath} configuration property.
 *
 * <h2>Configuration properties</h2>
 * <p>Set via {@code keyProviderConfig} in the filter YAML:
 * <pre>
 * keyProviderType: gcp-secret-manager
 * keyProviderConfig:
 *   projectId: my-gcp-project
 *   secretId: kroxylicious-pqc-keys
 *   secretVersion: latest
 * </pre>
 *
 * <table>
 * <tr><th>Key</th><th>Required</th><th>Default</th><th>Description</th></tr>
 * <tr><td>projectId</td><td>No</td><td>{@code GOOGLE_CLOUD_PROJECT} env var</td><td>GCP project ID</td></tr>
 * <tr><td>secretId</td><td>Yes</td><td>-</td><td>Secret name in Secret Manager</td></tr>
 * <tr><td>secretVersion</td><td>No</td><td>latest</td><td>Secret version (number or "latest")</td></tr>
 * <tr><td>credentialsPath</td><td>No</td><td>ADC</td><td>Path to service account JSON key file</td></tr>
 * </table>
 *
 * <h2>Secret payload format (JSON)</h2>
 * <pre>
 * {
 *   "publicKey": "&lt;base64-encoded DER X.509 ML-KEM public key&gt;",
 *   "privateKey": "&lt;base64-encoded DER PKCS#8 ML-KEM private key&gt;",
 *   "x25519PublicKey": "&lt;base64-encoded DER X.509 X25519 public key&gt;",
 *   "x25519PrivateKey": "&lt;base64-encoded DER PKCS#8 X25519 private key&gt;"
 * }
 * </pre>
 */
public class GcpSecretManagerKeyProvider implements KeyProvider {

    private static final Logger LOG = LoggerFactory.getLogger(GcpSecretManagerKeyProvider.class);

    private static final Pattern JSON_FIELD_PATTERN =
            Pattern.compile("\"(\\w+)\"\\s*:\\s*\"([^\"]+)\"");

    private SecretManagerServiceClient client;
    private String projectId;
    private String secretId;
    private String activeVersion;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private KeyPair x25519KeyPair;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    @Override
    public String type() {
        return "gcp-secret-manager";
    }

    @Override
    public void configure(PqcEncryptionConfig config) throws GeneralSecurityException, IOException {
        Map<String, String> props = config.getKeyProviderConfig();

        this.projectId = getOrEnv(props, "projectId", "GOOGLE_CLOUD_PROJECT");
        if (projectId == null || projectId.isEmpty()) {
            throw new IllegalArgumentException(
                    "GCP project ID is required. Set 'projectId' in keyProviderConfig "
                            + "or GOOGLE_CLOUD_PROJECT environment variable.");
        }

        this.secretId = props.get("secretId");
        if (secretId == null || secretId.isEmpty()) {
            throw new IllegalArgumentException(
                    "secretId is required in keyProviderConfig for the gcp-secret-manager key provider.");
        }

        this.activeVersion = props.getOrDefault("secretVersion", "latest");

        this.client = createClient(props);

        LOG.info("GCP Secret Manager key provider configured: project={}, secret={}, version={}",
                projectId, secretId, activeVersion);

        fetchKeys(activeVersion);
    }

    @Override
    public KeyPair getActiveKeyPair(KemAlgorithm algorithm) throws GeneralSecurityException {
        ensureConfigured();
        return new KeyPair(publicKey, privateKey);
    }

    @Override
    public KeyPair getKeyPairById(String keyId, KemAlgorithm algorithm) throws GeneralSecurityException {
        ensureConfigured();
        if (keyId.equals(activeVersion)) {
            return new KeyPair(publicKey, privateKey);
        }
        try {
            return fetchKeyPairByVersion(keyId);
        }
        catch (IOException e) {
            throw new GeneralSecurityException(
                    "Failed to fetch key version " + keyId + " from GCP Secret Manager", e);
        }
    }

    @Override
    public KeyPair getX25519KeyPair() {
        return x25519KeyPair;
    }

    @Override
    public List<String> listKeyIds() {
        if (activeVersion == null) {
            return List.of();
        }
        return List.of(activeVersion);
    }

    @Override
    public void close() {
        this.publicKey = null;
        this.privateKey = null;
        this.x25519KeyPair = null;
        if (client != null) {
            client.close();
            client = null;
        }
    }

    private void fetchKeys(String version) throws GeneralSecurityException, IOException {
        SecretVersionName versionName = SecretVersionName.of(projectId, secretId, version);

        AccessSecretVersionResponse response = client.accessSecretVersion(
                AccessSecretVersionRequest.newBuilder()
                        .setName(versionName.toString())
                        .build());

        String payload = response.getPayload().getData().toStringUtf8();
        if (payload == null || payload.isEmpty()) {
            throw new IOException(
                    "Secret payload is empty at " + projectId + "/" + secretId + "/" + version);
        }

        Map<String, String> data = parseJsonPayload(payload);

        // Resolve actual version number from response
        String responseName = response.getName();
        String resolvedVersion = extractVersionFromName(responseName, version);
        this.activeVersion = resolvedVersion;

        this.publicKey = decodePublicKey(data);
        this.privateKey = decodePrivateKey(data);
        this.x25519KeyPair = decodeX25519KeyPair(data);

        if (x25519KeyPair != null) {
            LOG.info("Loaded ML-KEM + X25519 key pairs from GCP Secret Manager (version={})", activeVersion);
        }
        else {
            LOG.info("Loaded ML-KEM key pair from GCP Secret Manager (version={}), no X25519 keys found",
                    activeVersion);
        }
    }

    private KeyPair fetchKeyPairByVersion(String version) throws GeneralSecurityException, IOException {
        SecretVersionName versionName = SecretVersionName.of(projectId, secretId, version);

        AccessSecretVersionResponse response = client.accessSecretVersion(
                AccessSecretVersionRequest.newBuilder()
                        .setName(versionName.toString())
                        .build());

        String payload = response.getPayload().getData().toStringUtf8();
        if (payload == null || payload.isEmpty()) {
            throw new IOException(
                    "Secret version " + version + " payload is empty at " + projectId + "/" + secretId);
        }

        Map<String, String> data = parseJsonPayload(payload);
        return new KeyPair(decodePublicKey(data), decodePrivateKey(data));
    }

    private SecretManagerServiceClient createClient(Map<String, String> props) throws IOException {
        String credentialsPath = props.get("credentialsPath");

        if (credentialsPath != null && !credentialsPath.isEmpty()) {
            LOG.info("Using service account credentials from: {}", credentialsPath);
            GoogleCredentials credentials;
            try (FileInputStream fis = new FileInputStream(credentialsPath)) {
                credentials = ServiceAccountCredentials.fromStream(fis);
            }
            SecretManagerServiceSettings settings = SecretManagerServiceSettings.newBuilder()
                    .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                    .build();
            return SecretManagerServiceClient.create(settings);
        }

        LOG.info("Using Application Default Credentials for GCP Secret Manager");
        return SecretManagerServiceClient.create();
    }

    /**
     * Parse a simple JSON object into a map of string key-value pairs.
     * Uses a lightweight regex approach to avoid pulling in a JSON parser dependency
     * just for this flat structure.
     */
    static Map<String, String> parseJsonPayload(String json) throws IOException {
        if (json == null || json.isBlank()) {
            throw new IOException("Secret payload is null or blank");
        }
        Map<String, String> result = new HashMap<>();
        Matcher matcher = JSON_FIELD_PATTERN.matcher(json);
        while (matcher.find()) {
            result.put(matcher.group(1), matcher.group(2));
        }
        if (result.isEmpty()) {
            throw new IOException(
                    "Could not parse secret payload as JSON. Expected format: "
                            + "{\"publicKey\": \"<base64>\", \"privateKey\": \"<base64>\"}");
        }
        return result;
    }

    private static String extractVersionFromName(String fullName, String fallback) {
        // fullName format: projects/PROJECT/secrets/SECRET/versions/VERSION
        int lastSlash = fullName.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < fullName.length() - 1) {
            return fullName.substring(lastSlash + 1);
        }
        return fallback;
    }

    private static PublicKey decodePublicKey(Map<String, String> data) throws GeneralSecurityException {
        String raw = data.get("publicKey");
        if (raw == null) {
            throw new GeneralSecurityException(
                    "GCP secret missing 'publicKey' field. "
                            + "Expected base64-encoded DER (X.509) ML-KEM public key.");
        }
        byte[] keyBytes = Base64.getDecoder().decode(raw);
        KeyFactory kf = KeyFactory.getInstance("Kyber", "BCPQC");
        return kf.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private static PrivateKey decodePrivateKey(Map<String, String> data) throws GeneralSecurityException {
        String raw = data.get("privateKey");
        if (raw == null) {
            throw new GeneralSecurityException(
                    "GCP secret missing 'privateKey' field. "
                            + "Expected base64-encoded DER (PKCS#8) ML-KEM private key.");
        }
        byte[] keyBytes = Base64.getDecoder().decode(raw);
        KeyFactory kf = KeyFactory.getInstance("Kyber", "BCPQC");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    private static KeyPair decodeX25519KeyPair(Map<String, String> data) throws GeneralSecurityException {
        String rawPub = data.get("x25519PublicKey");
        String rawPriv = data.get("x25519PrivateKey");
        if (rawPub == null || rawPriv == null) {
            return null;
        }
        KeyFactory kf = KeyFactory.getInstance("X25519");
        PublicKey pub = kf.generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(rawPub)));
        PrivateKey priv = kf.generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rawPriv)));
        return new KeyPair(pub, priv);
    }

    private static String getOrEnv(Map<String, String> props, String key, String envVar) {
        String value = props.get(key);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        return System.getenv(envVar);
    }

    private void ensureConfigured() {
        if (publicKey == null || privateKey == null) {
            throw new IllegalStateException(
                    "GcpSecretManagerKeyProvider has not been configured. Call configure() first.");
        }
    }
}
