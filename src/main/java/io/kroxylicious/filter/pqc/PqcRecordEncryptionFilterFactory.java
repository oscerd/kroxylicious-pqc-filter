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
package io.kroxylicious.filter.pqc;

import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig;
import io.kroxylicious.filter.pqc.crypto.PqcCryptoEngine;
import io.kroxylicious.filter.pqc.crypto.PqcKeyManager;
import io.kroxylicious.proxy.filter.Filter;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.plugin.Plugin;
import io.kroxylicious.proxy.plugin.PluginConfigurationException;
import io.kroxylicious.proxy.plugin.Plugins;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.regex.Pattern;

/**
 * FilterFactory for the PQC Record Encryption filter.
 *
 * <p>This factory initializes the ML-KEM key management and creates per-connection
 * filter instances that encrypt Produce requests and decrypt Fetch responses
 * using Post-Quantum Cryptography.
 *
 * <p>Registered via ServiceLoader as an implementation of
 * {@code io.kroxylicious.proxy.filter.FilterFactory}.
 *
 * @see PqcRecordEncryptionFilter
 * @see PqcEncryptionConfig
 */
@Plugin(configType = PqcEncryptionConfig.class)
public class PqcRecordEncryptionFilterFactory
        implements FilterFactory<PqcEncryptionConfig, PqcRecordEncryptionFilterFactory.SharedPqcContext> {

    private static final Logger LOG = LoggerFactory.getLogger(PqcRecordEncryptionFilterFactory.class);

    /**
     * Shared context created once during initialization and passed to each filter instance.
     * Contains the crypto engine (thread-safe) and compiled topic patterns.
     */
    public record SharedPqcContext(
            PqcCryptoEngine cryptoEngine,
            List<Pattern> topicPatterns,
            PqcEncryptionConfig config) {
    }

    @Override
    public SharedPqcContext initialize(FilterFactoryContext context, PqcEncryptionConfig config)
            throws PluginConfigurationException {
        Plugins.requireConfig(this, config);

        LOG.info("Initializing PQC Record Encryption filter: algorithm={}, hybridMode={}, topics={}",
                config.getKemAlgorithm().getDisplayName(),
                config.isHybridMode(),
                config.getTopicPatterns());

        try {
            PqcKeyManager keyManager = new PqcKeyManager(config);
            PqcCryptoEngine cryptoEngine = keyManager.createEngine(config.isHybridMode());

            List<Pattern> compiledPatterns = config.getTopicPatterns().stream()
                    .map(Pattern::compile)
                    .toList();

            LOG.info("PQC Record Encryption filter initialized successfully with {} key pair",
                    config.getKemAlgorithm().getDisplayName());

            return new SharedPqcContext(cryptoEngine, compiledPatterns, config);
        }
        catch (GeneralSecurityException | IOException e) {
            throw new PluginConfigurationException(
                    "Failed to initialize PQC encryption: " + e.getMessage(), e);
        }
    }

    @Override
    public Filter createFilter(FilterFactoryContext context, SharedPqcContext sharedContext) {
        LOG.debug("Creating new PQC Record Encryption filter instance");
        return new PqcRecordEncryptionFilter(
                sharedContext.cryptoEngine(),
                sharedContext.topicPatterns());
    }

    @Override
    public void close(SharedPqcContext sharedContext) {
        LOG.info("Closing PQC Record Encryption filter");
    }
}
