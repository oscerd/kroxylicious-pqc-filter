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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Default {@link KeyProvider} implementation that loads ML-KEM key pairs
 * from the local filesystem. If key files do not exist at the configured
 * paths, a new key pair is generated and saved automatically.
 *
 * <p>Keys are expected in DER encoding:
 * <ul>
 *   <li>Public key: X.509 SubjectPublicKeyInfo format</li>
 *   <li>Private key: PKCS#8 PrivateKeyInfo format</li>
 * </ul>
 *
 * <p>Supports two modes:
 * <ul>
 *   <li><strong>Single-key mode:</strong> Uses {@code publicKeyPath} and
 *       {@code privateKeyPath} from the config. Key ID is {@value #DEFAULT_KEY_ID}.</li>
 *   <li><strong>Multi-key mode:</strong> Uses the {@code keys} list from the config
 *       with an {@code activeKeyId} to identify the current encryption key.
 *       Retired keys are available for decryption.</li>
 * </ul>
 */
public class FileSystemKeyProvider implements KeyProvider {

    private static final Logger LOG = LoggerFactory.getLogger(FileSystemKeyProvider.class);

    static final String DEFAULT_KEY_ID = "default";

    private final Map<String, KeyEntry> keyEntries = new LinkedHashMap<>();
    private String activeKeyId;
    private KeyPair x25519KeyPair;

    static class KeyEntry {
        final PublicKey publicKey;
        final PrivateKey privateKey;

        KeyEntry(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
    }

    @Override
    public String type() {
        return "filesystem";
    }

    @Override
    public void configure(PqcEncryptionConfig config) throws GeneralSecurityException, IOException {
        KemAlgorithm algorithm = config.getKemAlgorithm();
        List<KeyConfig> keys = config.getKeys();

        if (keys != null && !keys.isEmpty()) {
            configureMultiKey(config, algorithm);
        }
        else {
            configureSingleKey(config, algorithm);
        }
    }

    private void configureSingleKey(PqcEncryptionConfig config, KemAlgorithm algorithm)
            throws GeneralSecurityException, IOException {
        String publicKeyPathStr = config.getPublicKeyPath();
        String privateKeyPathStr = config.getPrivateKeyPath();

        if (publicKeyPathStr == null || publicKeyPathStr.isEmpty()) {
            throw new IllegalArgumentException("publicKeyPath is required for filesystem key provider");
        }
        if (privateKeyPathStr == null || privateKeyPathStr.isEmpty()) {
            throw new IllegalArgumentException("privateKeyPath is required for filesystem key provider");
        }

        Path pubKeyPath = Path.of(publicKeyPathStr);
        Path privKeyPath = Path.of(privateKeyPathStr);

        PublicKey publicKey;
        PrivateKey privateKey;

        if (Files.exists(pubKeyPath) && Files.exists(privKeyPath)) {
            LOG.info("Loading existing ML-KEM key pair ({}) from {} and {}",
                    algorithm.getDisplayName(), pubKeyPath, privKeyPath);
            checkPrivateKeyPermissions(privKeyPath);
            publicKey = PqcCryptoEngine.loadPublicKey(pubKeyPath);
            privateKey = PqcCryptoEngine.loadPrivateKey(privKeyPath);
        }
        else {
            LOG.info("Generating new ML-KEM key pair ({}) and saving to {} and {}",
                    algorithm.getDisplayName(), pubKeyPath, privKeyPath);
            KeyPair keyPair = PqcCryptoEngine.generateKeyPair(algorithm);
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();

            PqcCryptoEngine.saveKey(pubKeyPath, publicKey.getEncoded());
            PqcCryptoEngine.saveKey(privKeyPath, privateKey.getEncoded());
        }

        this.activeKeyId = DEFAULT_KEY_ID;
        keyEntries.put(DEFAULT_KEY_ID, new KeyEntry(publicKey, privateKey));

        loadX25519Keys(config, pubKeyPath.getParent());
    }

    private void configureMultiKey(PqcEncryptionConfig config, KemAlgorithm algorithm)
            throws GeneralSecurityException, IOException {
        List<KeyConfig> keys = config.getKeys();
        String configActiveKeyId = config.getActiveKeyId();

        if (configActiveKeyId == null || configActiveKeyId.isEmpty()) {
            throw new IllegalArgumentException(
                    "activeKeyId is required when multiple keys are configured");
        }

        boolean activeKeyFound = false;
        Path x25519Dir = null;

        for (KeyConfig keyConfig : keys) {
            String keyId = keyConfig.getId();
            boolean isActive = keyId.equals(configActiveKeyId);

            String pubPathStr = keyConfig.getPublicKeyPath();
            String privPathStr = keyConfig.getPrivateKeyPath();

            if (privPathStr == null || privPathStr.isEmpty()) {
                throw new IllegalArgumentException(
                        "privateKeyPath is required for key '" + keyId + "'");
            }
            if (pubPathStr == null || pubPathStr.isEmpty()) {
                if (isActive) {
                    throw new IllegalArgumentException(
                            "publicKeyPath is required for active key '" + keyId + "'");
                }
                throw new IllegalArgumentException(
                        "publicKeyPath is required for key '" + keyId
                                + "' (needed for key ID computation)");
            }

            Path pubKeyPath = Path.of(pubPathStr);
            Path privKeyPath = Path.of(privPathStr);

            if (!Files.exists(pubKeyPath)) {
                throw new IllegalArgumentException(
                        "Public key file not found for key '" + keyId + "': " + pubKeyPath);
            }
            if (!Files.exists(privKeyPath)) {
                throw new IllegalArgumentException(
                        "Private key file not found for key '" + keyId + "': " + privKeyPath);
            }

            LOG.info("Loading ML-KEM key pair ({}) for key '{}' from {} and {}",
                    algorithm.getDisplayName(), keyId, pubKeyPath, privKeyPath);
            checkPrivateKeyPermissions(privKeyPath);

            PublicKey publicKey = PqcCryptoEngine.loadPublicKey(pubKeyPath);
            PrivateKey privateKey = PqcCryptoEngine.loadPrivateKey(privKeyPath);
            keyEntries.put(keyId, new KeyEntry(publicKey, privateKey));

            if (isActive) {
                activeKeyFound = true;
                x25519Dir = pubKeyPath.getParent();
            }
        }

        if (!activeKeyFound) {
            throw new IllegalArgumentException(
                    "activeKeyId '" + configActiveKeyId + "' does not match any configured key");
        }

        this.activeKeyId = configActiveKeyId;

        loadX25519Keys(config, x25519Dir);

        LOG.info("Configured {} key(s), active key: '{}'", keys.size(), activeKeyId);
    }

    private void loadX25519Keys(PqcEncryptionConfig config, Path keyDir)
            throws GeneralSecurityException, IOException {
        if (!config.isHybridMode() || keyDir == null) {
            return;
        }

        Path x25519PubPath = keyDir.resolve("x25519-public.der");
        Path x25519PrivPath = keyDir.resolve("x25519-private.der");

        if (Files.exists(x25519PubPath) && Files.exists(x25519PrivPath)) {
            LOG.info("Loading existing X25519 key pair from {} and {}", x25519PubPath, x25519PrivPath);
            checkPrivateKeyPermissions(x25519PrivPath);
            this.x25519KeyPair = new KeyPair(
                    PqcCryptoEngine.loadX25519PublicKey(x25519PubPath),
                    PqcCryptoEngine.loadX25519PrivateKey(x25519PrivPath));
        }
        else {
            LOG.info("Generating new X25519 key pair and saving to {} and {}", x25519PubPath, x25519PrivPath);
            this.x25519KeyPair = PqcCryptoEngine.generateX25519KeyPair();
            PqcCryptoEngine.saveKey(x25519PubPath, x25519KeyPair.getPublic().getEncoded());
            PqcCryptoEngine.saveKey(x25519PrivPath, x25519KeyPair.getPrivate().getEncoded());
        }
    }

    @Override
    public KeyPair getActiveKeyPair(KemAlgorithm algorithm) throws GeneralSecurityException {
        ensureConfigured();
        KeyEntry entry = keyEntries.get(activeKeyId);
        if (entry == null) {
            throw new GeneralSecurityException("Active key '" + activeKeyId + "' not found");
        }
        return new KeyPair(entry.publicKey, entry.privateKey);
    }

    @Override
    public KeyPair getKeyPairById(String keyId, KemAlgorithm algorithm) throws GeneralSecurityException {
        ensureConfigured();
        KeyEntry entry = keyEntries.get(keyId);
        if (entry == null) {
            throw new GeneralSecurityException(
                    "Unknown key ID '" + keyId + "'. Available keys: " + keyEntries.keySet());
        }
        return new KeyPair(entry.publicKey, entry.privateKey);
    }

    @Override
    public KeyPair getX25519KeyPair() {
        return x25519KeyPair;
    }

    @Override
    public List<String> listKeyIds() {
        return List.copyOf(keyEntries.keySet());
    }

    private void checkPrivateKeyPermissions(Path privKeyPath) {
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(privKeyPath);
            if (perms.contains(PosixFilePermission.GROUP_READ) || perms.contains(PosixFilePermission.OTHERS_READ)) {
                LOG.warn("Private key file {} has overly permissive permissions: {}. "
                        + "Only owner-readable (e.g., chmod 600) is recommended.", privKeyPath, perms);
            }
        }
        catch (UnsupportedOperationException e) {
            LOG.debug("POSIX file permissions not supported on this filesystem, skipping permission check for {}", privKeyPath);
        }
        catch (IOException e) {
            LOG.warn("Unable to check file permissions for {}: {}", privKeyPath, e.getMessage());
        }
    }

    private void ensureConfigured() {
        if (keyEntries.isEmpty()) {
            throw new IllegalStateException("KeyProvider has not been configured. Call configure() first.");
        }
    }
}
