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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ServiceLoader;

/**
 * Manages ML-KEM key pairs for the PQC encryption filter.
 * Delegates key loading and storage to a {@link KeyProvider} implementation
 * resolved via {@link ServiceLoader}.
 */
public class PqcKeyManager {

    private static final Logger LOG = LoggerFactory.getLogger(PqcKeyManager.class);

    private final KemAlgorithm algorithm;
    private final KeyProvider keyProvider;

    public PqcKeyManager(PqcEncryptionConfig config) throws GeneralSecurityException, IOException {
        this.algorithm = config.getKemAlgorithm();
        this.keyProvider = resolveKeyProvider(config.getKeyProviderType());

        LOG.info("Using key provider: {} (type={})", keyProvider.getClass().getSimpleName(), keyProvider.type());
        keyProvider.configure(config);
    }

    /**
     * For testing: construct with a pre-configured key provider.
     */
    PqcKeyManager(KemAlgorithm algorithm, KeyProvider keyProvider) {
        this.algorithm = algorithm;
        this.keyProvider = keyProvider;
    }

    public KeyProvider getKeyProvider() {
        return keyProvider;
    }

    public KemAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Create a PqcCryptoEngine configured with the active key pair from this key manager's provider.
     */
    public PqcCryptoEngine createEngine(boolean hybridMode) throws GeneralSecurityException {
        KeyPair keyPair = keyProvider.getActiveKeyPair(algorithm);
        return new PqcCryptoEngine(algorithm, hybridMode, keyPair.getPublic(), keyPair.getPrivate());
    }

    /**
     * Close the underlying key provider, releasing any held resources.
     */
    public void close() {
        keyProvider.close();
    }

    private static KeyProvider resolveKeyProvider(String type) {
        ServiceLoader<KeyProvider> loader = ServiceLoader.load(KeyProvider.class);
        for (KeyProvider provider : loader) {
            if (provider.type().equals(type)) {
                LOG.debug("Resolved key provider '{}' via ServiceLoader: {}",
                        type, provider.getClass().getName());
                return provider;
            }
        }
        // Fallback: if ServiceLoader didn't find it and type is "filesystem", use the built-in default
        if ("filesystem".equals(type)) {
            LOG.debug("Using built-in FileSystemKeyProvider");
            return new FileSystemKeyProvider();
        }
        throw new IllegalArgumentException(
                "No KeyProvider found for type '" + type + "'. "
                        + "Ensure a KeyProvider implementation with this type is on the classpath "
                        + "and registered via META-INF/services/" + KeyProvider.class.getName());
    }
}
