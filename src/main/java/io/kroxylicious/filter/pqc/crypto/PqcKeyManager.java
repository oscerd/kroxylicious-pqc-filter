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

/**
 * Manages ML-KEM key pairs for the PQC encryption filter.
 * Handles loading keys from filesystem paths and generating new key pairs.
 */
public class PqcKeyManager {

    private static final Logger LOG = LoggerFactory.getLogger(PqcKeyManager.class);

    private final KemAlgorithm algorithm;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public PqcKeyManager(PqcEncryptionConfig config) throws GeneralSecurityException, IOException {
        this.algorithm = config.getKemAlgorithm();

        Path pubKeyPath = Path.of(config.getPublicKeyPath());
        Path privKeyPath = Path.of(config.getPrivateKeyPath());

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

    /**
     * For testing: construct with pre-generated keys.
     */
    PqcKeyManager(KemAlgorithm algorithm, PublicKey publicKey, PrivateKey privateKey) {
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public KemAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Create a PqcCryptoEngine configured with this key manager's keys.
     */
    public PqcCryptoEngine createEngine(boolean hybridMode) {
        return new PqcCryptoEngine(algorithm, hybridMode, publicKey, privateKey);
    }
}
