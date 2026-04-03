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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

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
 * <p>This provider manages a single key pair identified by the key ID
 * {@value #DEFAULT_KEY_ID}. Key rotation with multiple key pairs is
 * not supported by this provider.
 */
public class FileSystemKeyProvider implements KeyProvider {

    private static final Logger LOG = LoggerFactory.getLogger(FileSystemKeyProvider.class);

    static final String DEFAULT_KEY_ID = "default";

    private PublicKey publicKey;
    private PrivateKey privateKey;

    @Override
    public String type() {
        return "filesystem";
    }

    @Override
    public void configure(PqcEncryptionConfig config) throws GeneralSecurityException, IOException {
        KemAlgorithm algorithm = config.getKemAlgorithm();
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

        if (Files.exists(pubKeyPath) && Files.exists(privKeyPath)) {
            LOG.info("Loading existing ML-KEM key pair ({}) from {} and {}",
                    algorithm.getDisplayName(), pubKeyPath, privKeyPath);
            this.publicKey = PqcCryptoEngine.loadPublicKey(pubKeyPath);
            this.privateKey = PqcCryptoEngine.loadPrivateKey(privKeyPath);
        }
        else {
            LOG.info("Generating new ML-KEM key pair ({}) and saving to {} and {}",
                    algorithm.getDisplayName(), pubKeyPath, privKeyPath);
            KeyPair keyPair = PqcCryptoEngine.generateKeyPair(algorithm);
            this.publicKey = keyPair.getPublic();
            this.privateKey = keyPair.getPrivate();

            PqcCryptoEngine.saveKey(pubKeyPath, publicKey.getEncoded());
            PqcCryptoEngine.saveKey(privKeyPath, privateKey.getEncoded());
        }
    }

    @Override
    public KeyPair getActiveKeyPair(KemAlgorithm algorithm) throws GeneralSecurityException {
        ensureConfigured();
        return new KeyPair(publicKey, privateKey);
    }

    @Override
    public KeyPair getKeyPairById(String keyId, KemAlgorithm algorithm) throws GeneralSecurityException {
        ensureConfigured();
        if (!DEFAULT_KEY_ID.equals(keyId)) {
            throw new GeneralSecurityException(
                    "Unknown key ID '" + keyId + "'. FileSystemKeyProvider only supports key ID '" + DEFAULT_KEY_ID + "'");
        }
        return new KeyPair(publicKey, privateKey);
    }

    @Override
    public List<String> listKeyIds() {
        return List.of(DEFAULT_KEY_ID);
    }

    private void ensureConfigured() {
        if (publicKey == null || privateKey == null) {
            throw new IllegalStateException("KeyProvider has not been configured. Call configure() first.");
        }
    }
}
