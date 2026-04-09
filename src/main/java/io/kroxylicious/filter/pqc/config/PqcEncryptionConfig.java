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
package io.kroxylicious.filter.pqc.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Configuration for the PQC Record Encryption filter.
 *
 * <p>Example YAML configuration:
 * <pre>
 * type: PqcRecordEncryption
 * config:
 *   kemAlgorithm: ML-KEM-768
 *   hybridMode: true
 *   publicKeyPath: /etc/kroxylicious/pqc/recipient.pub
 *   privateKeyPath: /etc/kroxylicious/pqc/recipient.key
 *   topicPatterns:
 *     - "sensitive-.*"
 *     - "pii-data"
 * </pre>
 */
public class PqcEncryptionConfig {

    /**
     * Supported ML-KEM parameter sets per FIPS 203.
     */
    public enum KemAlgorithm {
        /** ML-KEM-512: 128-bit security level, smallest key/ciphertext sizes. */
        ML_KEM_512("ML-KEM-512", "ML-KEM", 512),
        /** ML-KEM-768: 192-bit security level, recommended default by NIST. */
        ML_KEM_768("ML-KEM-768", "ML-KEM", 768),
        /** ML-KEM-1024: 256-bit security level, highest security. */
        ML_KEM_1024("ML-KEM-1024", "ML-KEM", 1024);

        private final String displayName;
        private final String algorithmFamily;
        private final int parameterSize;

        KemAlgorithm(String displayName, String algorithmFamily, int parameterSize) {
            this.displayName = displayName;
            this.algorithmFamily = algorithmFamily;
            this.parameterSize = parameterSize;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getAlgorithmFamily() {
            return algorithmFamily;
        }

        public int getParameterSize() {
            return parameterSize;
        }
    }

    /**
     * Configuration for a single key entry in multi-key rotation mode.
     */
    public static class KeyConfig {
        private final String id;
        private final String publicKeyPath;
        private final String privateKeyPath;

        @JsonCreator
        public KeyConfig(
                @JsonProperty(value = "id", required = true) String id,
                @JsonProperty(value = "publicKeyPath") String publicKeyPath,
                @JsonProperty(value = "privateKeyPath") String privateKeyPath) {
            if (id == null || id.isEmpty()) {
                throw new IllegalArgumentException("Key config 'id' is required");
            }
            this.id = id;
            this.publicKeyPath = publicKeyPath;
            this.privateKeyPath = privateKeyPath;
        }

        public String getId() {
            return id;
        }

        public String getPublicKeyPath() {
            return publicKeyPath;
        }

        public String getPrivateKeyPath() {
            return privateKeyPath;
        }
    }

    /**
     * Policy for handling encryption/decryption failures.
     */
    public enum FailurePolicy {
        /** Fail-closed: propagate the error to the client. Prevents plaintext leakage. */
        FAIL_CLOSED,
        /** Fail-open: log the error and forward data as-is. Use with caution. */
        FAIL_OPEN
    }

    private final KemAlgorithm kemAlgorithm;
    private final boolean hybridMode;
    private final String publicKeyPath;
    private final String privateKeyPath;
    private final List<String> topicPatterns;
    private final String keyProviderType;
    private final Map<String, String> keyProviderConfig;
    private final String activeKeyId;
    private final List<KeyConfig> keys;
    private final FailurePolicy failurePolicy;

    /**
     * Backward-compatible constructor for single-key mode.
     */
    public PqcEncryptionConfig(
            KemAlgorithm kemAlgorithm,
            Boolean hybridMode,
            String publicKeyPath,
            String privateKeyPath,
            List<String> topicPatterns,
            String keyProviderType,
            Map<String, String> keyProviderConfig) {
        this(kemAlgorithm, hybridMode, publicKeyPath, privateKeyPath,
                topicPatterns, keyProviderType, keyProviderConfig, null, null, null);
    }

    /**
     * Constructor with key rotation support (no failure policy).
     */
    public PqcEncryptionConfig(
            KemAlgorithm kemAlgorithm,
            Boolean hybridMode,
            String publicKeyPath,
            String privateKeyPath,
            List<String> topicPatterns,
            String keyProviderType,
            Map<String, String> keyProviderConfig,
            String activeKeyId,
            List<KeyConfig> keys) {
        this(kemAlgorithm, hybridMode, publicKeyPath, privateKeyPath,
                topicPatterns, keyProviderType, keyProviderConfig, activeKeyId, keys, null);
    }

    @JsonCreator
    public PqcEncryptionConfig(
            @JsonProperty(value = "kemAlgorithm") KemAlgorithm kemAlgorithm,
            @JsonProperty(value = "hybridMode") Boolean hybridMode,
            @JsonProperty(value = "publicKeyPath") String publicKeyPath,
            @JsonProperty(value = "privateKeyPath") String privateKeyPath,
            @JsonProperty(value = "topicPatterns") List<String> topicPatterns,
            @JsonProperty(value = "keyProviderType") String keyProviderType,
            @JsonProperty(value = "keyProviderConfig") Map<String, String> keyProviderConfig,
            @JsonProperty(value = "activeKeyId") String activeKeyId,
            @JsonProperty(value = "keys") List<KeyConfig> keys,
            @JsonProperty(value = "failurePolicy") FailurePolicy failurePolicy) {
        this.kemAlgorithm = kemAlgorithm != null ? kemAlgorithm : KemAlgorithm.ML_KEM_768;
        this.hybridMode = hybridMode != null ? hybridMode : true;
        this.publicKeyPath = publicKeyPath;
        this.privateKeyPath = privateKeyPath;
        this.topicPatterns = topicPatterns != null ? List.copyOf(topicPatterns) : List.of(".*");
        this.keyProviderType = keyProviderType != null ? keyProviderType : "filesystem";
        this.keyProviderConfig = keyProviderConfig != null ? Map.copyOf(keyProviderConfig) : Map.of();
        this.activeKeyId = activeKeyId;
        this.keys = keys != null ? Collections.unmodifiableList(List.copyOf(keys)) : null;
        this.failurePolicy = failurePolicy != null ? failurePolicy : FailurePolicy.FAIL_CLOSED;
    }

    public KemAlgorithm getKemAlgorithm() {
        return kemAlgorithm;
    }

    public boolean isHybridMode() {
        return hybridMode;
    }

    public String getPublicKeyPath() {
        return publicKeyPath;
    }

    public String getPrivateKeyPath() {
        return privateKeyPath;
    }

    public List<String> getTopicPatterns() {
        return topicPatterns;
    }

    public String getKeyProviderType() {
        return keyProviderType;
    }

    public Map<String, String> getKeyProviderConfig() {
        return keyProviderConfig;
    }

    public String getActiveKeyId() {
        return activeKeyId;
    }

    public List<KeyConfig> getKeys() {
        return keys;
    }

    public FailurePolicy getFailurePolicy() {
        return failurePolicy;
    }
}
