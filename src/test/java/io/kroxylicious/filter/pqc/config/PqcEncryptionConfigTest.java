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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig.KemAlgorithm;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class PqcEncryptionConfigTest {

    @Test
    void shouldUseDefaultValues() {
        // When
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                null, null, "/tmp/pub.key", "/tmp/priv.key", null);

        // Then
        assertThat(config.getKemAlgorithm()).isEqualTo(KemAlgorithm.ML_KEM_768);
        assertThat(config.isHybridMode()).isTrue();
        assertThat(config.getTopicPatterns()).containsExactly(".*");
    }

    @Test
    void shouldAcceptExplicitValues() {
        // When
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_1024, false,
                "/etc/pqc/pub.key", "/etc/pqc/priv.key",
                List.of("sensitive-.*", "pii-data"));

        // Then
        assertThat(config.getKemAlgorithm()).isEqualTo(KemAlgorithm.ML_KEM_1024);
        assertThat(config.isHybridMode()).isFalse();
        assertThat(config.getPublicKeyPath()).isEqualTo("/etc/pqc/pub.key");
        assertThat(config.getPrivateKeyPath()).isEqualTo("/etc/pqc/priv.key");
        assertThat(config.getTopicPatterns()).containsExactly("sensitive-.*", "pii-data");
    }

    @Test
    void shouldRejectNullPublicKeyPath() {
        assertThatNullPointerException()
                .isThrownBy(() -> new PqcEncryptionConfig(
                        null, null, null, "/tmp/priv.key", null))
                .withMessageContaining("publicKeyPath");
    }

    @Test
    void shouldRejectNullPrivateKeyPath() {
        assertThatNullPointerException()
                .isThrownBy(() -> new PqcEncryptionConfig(
                        null, null, "/tmp/pub.key", null, null))
                .withMessageContaining("privateKeyPath");
    }

    @Test
    void shouldDeserializeFromJson() throws Exception {
        // Given
        String json = """
                {
                    "kemAlgorithm": "ML_KEM_512",
                    "hybridMode": false,
                    "publicKeyPath": "/keys/pub.der",
                    "privateKeyPath": "/keys/priv.der",
                    "topicPatterns": ["orders-.*"]
                }
                """;

        // When
        ObjectMapper mapper = new ObjectMapper();
        PqcEncryptionConfig config = mapper.readValue(json, PqcEncryptionConfig.class);

        // Then
        assertThat(config.getKemAlgorithm()).isEqualTo(KemAlgorithm.ML_KEM_512);
        assertThat(config.isHybridMode()).isFalse();
        assertThat(config.getPublicKeyPath()).isEqualTo("/keys/pub.der");
        assertThat(config.getPrivateKeyPath()).isEqualTo("/keys/priv.der");
        assertThat(config.getTopicPatterns()).containsExactly("orders-.*");
    }

    @Test
    void shouldMakeTopicPatternsImmutable() {
        // Given
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                null, null, "/tmp/pub.key", "/tmp/priv.key",
                List.of("topic1", "topic2"));

        // Then
        assertThat(config.getTopicPatterns()).isUnmodifiable();
    }

    @Test
    void kemAlgorithmShouldHaveCorrectProperties() {
        assertThat(KemAlgorithm.ML_KEM_512.getDisplayName()).isEqualTo("ML-KEM-512");
        assertThat(KemAlgorithm.ML_KEM_512.getAlgorithmFamily()).isEqualTo("ML-KEM");
        assertThat(KemAlgorithm.ML_KEM_512.getParameterSize()).isEqualTo(512);

        assertThat(KemAlgorithm.ML_KEM_768.getDisplayName()).isEqualTo("ML-KEM-768");
        assertThat(KemAlgorithm.ML_KEM_768.getParameterSize()).isEqualTo(768);

        assertThat(KemAlgorithm.ML_KEM_1024.getDisplayName()).isEqualTo("ML-KEM-1024");
        assertThat(KemAlgorithm.ML_KEM_1024.getParameterSize()).isEqualTo(1024);
    }
}
