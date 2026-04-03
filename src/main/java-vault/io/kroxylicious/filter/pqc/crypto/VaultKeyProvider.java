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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.vault.authentication.AppRoleAuthentication;
import org.springframework.vault.authentication.AppRoleAuthenticationOptions;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.authentication.KubernetesAuthentication;
import org.springframework.vault.authentication.KubernetesAuthenticationOptions;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultVersionedKeyValueOperations;
import org.springframework.vault.core.VaultVersionedKeyValueTemplate;
import org.springframework.vault.support.Versioned;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * {@link KeyProvider} implementation that fetches ML-KEM key material
 * from HashiCorp Vault using Spring Vault.
 *
 * <p>Keys are stored in Vault's KV v2 secrets engine as base64-encoded
 * DER values under the keys {@code publicKey} and {@code privateKey}.
 *
 * <p>Supported authentication methods:
 * <ul>
 *   <li>{@code token} - static Vault token</li>
 *   <li>{@code approle} - AppRole role ID + secret ID</li>
 *   <li>{@code kubernetes} - Kubernetes service account JWT</li>
 * </ul>
 *
 * <h2>Configuration properties</h2>
 * <p>Set via {@code keyProviderConfig} in the filter YAML:
 * <pre>
 * keyProviderType: vault
 * keyProviderConfig:
 *   vaultAddress: https://vault.example.com:8200
 *   secretEngine: secret
 *   secretPath: kroxylicious/pqc
 *   authMethod: token
 *   vaultToken: hvs.xxxxx
 * </pre>
 *
 * <table>
 * <tr><th>Key</th><th>Required</th><th>Default</th><th>Description</th></tr>
 * <tr><td>vaultAddress</td><td>No</td><td>{@code VAULT_ADDR} env var</td><td>Vault server URL</td></tr>
 * <tr><td>authMethod</td><td>No</td><td>token</td><td>One of: token, approle, kubernetes</td></tr>
 * <tr><td>vaultToken</td><td>For token auth</td><td>{@code VAULT_TOKEN} env var</td><td>Static Vault token</td></tr>
 * <tr><td>roleId</td><td>For approle</td><td>-</td><td>AppRole role ID</td></tr>
 * <tr><td>secretId</td><td>For approle</td><td>-</td><td>AppRole secret ID</td></tr>
 * <tr><td>kubeRole</td><td>For kubernetes</td><td>-</td><td>Kubernetes auth role</td></tr>
 * <tr><td>kubeTokenPath</td><td>No</td><td>/var/run/secrets/kubernetes.io/serviceaccount/token</td><td>SA token path</td></tr>
 * <tr><td>secretEngine</td><td>No</td><td>secret</td><td>KV v2 engine mount path</td></tr>
 * <tr><td>secretPath</td><td>Yes</td><td>-</td><td>Secret path within the engine</td></tr>
 * </table>
 */
public class VaultKeyProvider implements KeyProvider {

    private static final Logger LOG = LoggerFactory.getLogger(VaultKeyProvider.class);

    static final String DEFAULT_KUBE_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private VaultTemplate vaultTemplate;
    private String secretEngine;
    private String secretPath;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private KeyPair x25519KeyPair;
    private String activeVersion;

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
        return "vault";
    }

    @Override
    public void configure(PqcEncryptionConfig config) throws GeneralSecurityException, IOException {
        Map<String, String> props = config.getKeyProviderConfig();

        String vaultAddress = getOrEnv(props, "vaultAddress", "VAULT_ADDR");
        if (vaultAddress == null || vaultAddress.isEmpty()) {
            throw new IllegalArgumentException(
                    "Vault address is required. Set 'vaultAddress' in keyProviderConfig or VAULT_ADDR environment variable.");
        }

        this.secretEngine = props.getOrDefault("secretEngine", "secret");
        this.secretPath = props.get("secretPath");
        if (secretPath == null || secretPath.isEmpty()) {
            throw new IllegalArgumentException(
                    "secretPath is required in keyProviderConfig for the vault key provider.");
        }

        URI vaultUri = URI.create(vaultAddress);
        VaultEndpoint endpoint = new VaultEndpoint();
        endpoint.setScheme(vaultUri.getScheme());
        endpoint.setHost(vaultUri.getHost());
        if (vaultUri.getPort() != -1) {
            endpoint.setPort(vaultUri.getPort());
        }

        String authMethod = props.getOrDefault("authMethod", "token");
        ClientAuthentication authentication = createAuthentication(authMethod, props, endpoint);

        this.vaultTemplate = new VaultTemplate(endpoint, authentication);

        LOG.info("Vault key provider configured: address={}, engine={}, path={}, auth={}",
                vaultAddress, secretEngine, secretPath, authMethod);

        fetchKeys();
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
        // Fetch a specific version from Vault
        try {
            return fetchKeysByVersion(Integer.parseInt(keyId));
        }
        catch (NumberFormatException e) {
            throw new GeneralSecurityException("Invalid Vault version key ID: " + keyId);
        }
        catch (IOException e) {
            throw new GeneralSecurityException("Failed to fetch key version " + keyId + " from Vault", e);
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
        this.vaultTemplate = null;
    }

    private void fetchKeys() throws GeneralSecurityException, IOException {
        VaultVersionedKeyValueOperations kvOps =
                vaultTemplate.opsForVersionedKeyValue(secretEngine);

        Versioned<Map<String, Object>> secret = kvOps.get(secretPath);
        if (secret == null || secret.getData() == null) {
            throw new IOException(
                    "Secret not found at " + secretEngine + "/" + secretPath + " in Vault");
        }

        Map<String, Object> data = secret.getData();
        this.activeVersion = secret.getVersion() != null
                ? String.valueOf(secret.getVersion().getVersion())
                : "1";

        this.publicKey = decodePublicKey(data);
        this.privateKey = decodePrivateKey(data);

        this.x25519KeyPair = decodeX25519KeyPair(data);
        if (x25519KeyPair != null) {
            LOG.info("Loaded ML-KEM + X25519 key pairs from Vault (version={})", activeVersion);
        }
        else {
            LOG.info("Loaded ML-KEM key pair from Vault (version={}), no X25519 keys found", activeVersion);
        }
    }

    private KeyPair fetchKeysByVersion(int version) throws GeneralSecurityException, IOException {
        VaultVersionedKeyValueOperations kvOps =
                vaultTemplate.opsForVersionedKeyValue(secretEngine);

        Versioned<Map<String, Object>> secret =
                kvOps.get(secretPath, Versioned.Version.from(version));
        if (secret == null || secret.getData() == null) {
            throw new IOException(
                    "Secret version " + version + " not found at " + secretEngine + "/" + secretPath);
        }

        Map<String, Object> data = secret.getData();
        return new KeyPair(decodePublicKey(data), decodePrivateKey(data));
    }

    private ClientAuthentication createAuthentication(
            String authMethod, Map<String, String> props, VaultEndpoint endpoint) {
        return switch (authMethod) {
            case "token" -> {
                String token = getOrEnv(props, "vaultToken", "VAULT_TOKEN");
                if (token == null || token.isEmpty()) {
                    throw new IllegalArgumentException(
                            "Vault token is required for token auth. "
                                    + "Set 'vaultToken' in keyProviderConfig or VAULT_TOKEN environment variable.");
                }
                yield new TokenAuthentication(token);
            }
            case "approle" -> {
                String roleId = props.get("roleId");
                String secretId = props.get("secretId");
                if (roleId == null || secretId == null) {
                    throw new IllegalArgumentException(
                            "roleId and secretId are required in keyProviderConfig for approle auth.");
                }
                AppRoleAuthenticationOptions options = AppRoleAuthenticationOptions.builder()
                        .roleId(AppRoleAuthenticationOptions.RoleId.provided(roleId))
                        .secretId(AppRoleAuthenticationOptions.SecretId.provided(secretId))
                        .build();
                yield new AppRoleAuthentication(options, new RestTemplate());
            }
            case "kubernetes" -> {
                String role = props.get("kubeRole");
                if (role == null || role.isEmpty()) {
                    throw new IllegalArgumentException(
                            "kubeRole is required in keyProviderConfig for kubernetes auth.");
                }
                String tokenPath = props.getOrDefault("kubeTokenPath", DEFAULT_KUBE_TOKEN_PATH);
                String jwt;
                try {
                    jwt = Files.readString(Path.of(tokenPath)).trim();
                }
                catch (IOException e) {
                    throw new IllegalArgumentException(
                            "Cannot read Kubernetes service account token from " + tokenPath, e);
                }
                KubernetesAuthenticationOptions options = KubernetesAuthenticationOptions.builder()
                        .role(role)
                        .jwtSupplier(() -> jwt)
                        .build();
                yield new KubernetesAuthentication(options, new RestTemplate());
            }
            default -> throw new IllegalArgumentException(
                    "Unsupported Vault auth method: " + authMethod
                            + ". Supported: token, approle, kubernetes");
        };
    }

    private static PublicKey decodePublicKey(Map<String, Object> data) throws GeneralSecurityException {
        Object raw = data.get("publicKey");
        if (raw == null) {
            throw new GeneralSecurityException(
                    "Vault secret missing 'publicKey' field. "
                            + "Expected base64-encoded DER (X.509) ML-KEM public key.");
        }
        byte[] keyBytes = Base64.getDecoder().decode(raw.toString());
        KeyFactory kf = KeyFactory.getInstance("Kyber", "BCPQC");
        return kf.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private static PrivateKey decodePrivateKey(Map<String, Object> data) throws GeneralSecurityException {
        Object raw = data.get("privateKey");
        if (raw == null) {
            throw new GeneralSecurityException(
                    "Vault secret missing 'privateKey' field. "
                            + "Expected base64-encoded DER (PKCS#8) ML-KEM private key.");
        }
        byte[] keyBytes = Base64.getDecoder().decode(raw.toString());
        KeyFactory kf = KeyFactory.getInstance("Kyber", "BCPQC");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    private static KeyPair decodeX25519KeyPair(Map<String, Object> data) throws GeneralSecurityException {
        Object rawPub = data.get("x25519PublicKey");
        Object rawPriv = data.get("x25519PrivateKey");
        if (rawPub == null || rawPriv == null) {
            return null;
        }
        KeyFactory kf = KeyFactory.getInstance("X25519");
        PublicKey pub = kf.generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(rawPub.toString())));
        PrivateKey priv = kf.generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rawPriv.toString())));
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
            throw new IllegalStateException("VaultKeyProvider has not been configured. Call configure() first.");
        }
    }
}
