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
import java.util.Iterator;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages ML-KEM key pairs for the PQC encryption filter.
 * Delegates key loading and storage to a {@link KeyProvider} implementation
 * resolved via {@link ServiceLoader}.
 */
public class PqcKeyManager {

    private static final Logger LOG = LoggerFactory.getLogger(PqcKeyManager.class);

    private final KemAlgorithm algorithm;
    private final KeyProvider keyProvider;
    private final Map<Integer, PqcCryptoEngine> engineCache = new ConcurrentHashMap<>();
    private volatile PqcCryptoEngine activeEngine;

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
     * The engine is cached by key ID for reuse during decryption.
     * All other configured keys are also pre-loaded into the cache to support
     * decryption of records encrypted with retired keys.
     */
    public PqcCryptoEngine createEngine(boolean hybridMode) throws GeneralSecurityException {
        KeyPair keyPair = keyProvider.getActiveKeyPair(algorithm);
        KeyPair x25519KeyPair = hybridMode ? keyProvider.getX25519KeyPair() : null;
        PqcCryptoEngine engine = new PqcCryptoEngine(algorithm, hybridMode,
                keyPair.getPublic(), keyPair.getPrivate(), x25519KeyPair);
        this.activeEngine = engine;
        engineCache.put(engine.getKeyId(), engine);
        LOG.info("Active encryption key ID: 0x{}", Integer.toHexString(engine.getKeyId()));

        preloadRetiredKeys(hybridMode, x25519KeyPair);

        return engine;
    }

    private void preloadRetiredKeys(boolean hybridMode, KeyPair x25519KeyPair) {
        for (String keyId : keyProvider.listKeyIds()) {
            try {
                KeyPair kp = keyProvider.getKeyPairById(keyId, algorithm);
                int computedId = (hybridMode && x25519KeyPair != null)
                        ? PqcCryptoEngine.computeKeyId(kp.getPublic(), x25519KeyPair.getPublic())
                        : PqcCryptoEngine.computeKeyId(kp.getPublic());
                if (!engineCache.containsKey(computedId)) {
                    PqcCryptoEngine retiredEngine = new PqcCryptoEngine(algorithm, hybridMode,
                            kp.getPublic(), kp.getPrivate(), x25519KeyPair);
                    engineCache.put(retiredEngine.getKeyId(), retiredEngine);
                    LOG.info("Pre-loaded retired key ID: 0x{} (config ID: {})",
                            Integer.toHexString(computedId), keyId);
                }
            }
            catch (GeneralSecurityException e) {
                LOG.warn("Failed to pre-load key for config ID '{}': {}", keyId, e.getMessage());
            }
        }
    }

    /**
     * Resolve the appropriate engine to decrypt an envelope.
     * Extracts the key ID from the envelope and returns a cached or newly created engine.
     *
     * @param envelope the encrypted envelope bytes
     * @return the engine that can decrypt this envelope
     * @throws GeneralSecurityException if the key ID cannot be resolved
     */
    public PqcCryptoEngine resolveEngine(byte[] envelope) throws GeneralSecurityException {
        int envelopeKeyId = PqcCryptoEngine.extractKeyId(envelope);

        if (envelopeKeyId == PqcCryptoEngine.NO_KEY_ID) {
            // Legacy envelope without key ID — use the active engine
            if (activeEngine == null) {
                throw new GeneralSecurityException("No active engine available to decrypt legacy envelope");
            }
            return activeEngine;
        }

        // Check cache first
        PqcCryptoEngine cached = engineCache.get(envelopeKeyId);
        if (cached != null) {
            return cached;
        }

        throw new GeneralSecurityException(
                "No key pair found for key ID 0x" + Integer.toHexString(envelopeKeyId)
                        + ". The key used to encrypt this record is not available in this key provider.");
    }

    /**
     * Close the underlying key provider, releasing any held resources.
     */
    public void close() {
        keyProvider.close();
    }

    private static KeyProvider resolveKeyProvider(String type) {
        ServiceLoader<KeyProvider> loader = ServiceLoader.load(KeyProvider.class);
        Iterator<KeyProvider> it = loader.iterator();
        while (it.hasNext()) {
            try {
                KeyProvider provider = it.next();
                if (provider.type().equals(type)) {
                    LOG.debug("Resolved key provider '{}' via ServiceLoader: {}",
                            type, provider.getClass().getName());
                    return provider;
                }
            }
            catch (ServiceConfigurationError e) {
                // Skip providers whose classes are not on the classpath
                // (e.g., optional vault provider when built without -Pvault)
                LOG.debug("Skipping unavailable KeyProvider: {}", e.getMessage());
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
