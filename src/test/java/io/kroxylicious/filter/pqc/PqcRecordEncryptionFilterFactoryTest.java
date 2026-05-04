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
import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig.FailurePolicy;
import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig.KemAlgorithm;
import io.kroxylicious.proxy.filter.Filter;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.plugin.PluginConfigurationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class PqcRecordEncryptionFilterFactoryTest {

    @TempDir
    Path tempDir;

    @Test
    void shouldInitializeWithValidConfig() throws Exception {
        // Given
        FilterFactoryContext ctx = mock(FilterFactoryContext.class);
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                tempDir.resolve("pub.der").toString(),
                tempDir.resolve("priv.der").toString(),
                null, null, null);
        PqcRecordEncryptionFilterFactory factory = new PqcRecordEncryptionFilterFactory();

        // When
        PqcRecordEncryptionFilterFactory.SharedPqcContext sharedContext = factory.initialize(ctx, config);

        // Then
        assertThat(sharedContext).isNotNull();
        assertThat(sharedContext.cryptoEngine()).isNotNull();
        assertThat(sharedContext.keyManager()).isNotNull();
        assertThat(sharedContext.config()).isSameAs(config);
        assertThat(sharedContext.topicPatterns()).hasSize(1);
    }

    @Test
    void shouldCompileMultipleTopicPatterns() throws Exception {
        // Given
        FilterFactoryContext ctx = mock(FilterFactoryContext.class);
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                tempDir.resolve("pub.der").toString(),
                tempDir.resolve("priv.der").toString(),
                List.of("test-.*", "prod-.*", "staging\\.events"),
                null, null);
        PqcRecordEncryptionFilterFactory factory = new PqcRecordEncryptionFilterFactory();

        // When
        PqcRecordEncryptionFilterFactory.SharedPqcContext sharedContext = factory.initialize(ctx, config);

        // Then
        assertThat(sharedContext.topicPatterns()).hasSize(3);
        assertThat(sharedContext.topicPatterns().get(0).pattern()).isEqualTo("test-.*");
        assertThat(sharedContext.topicPatterns().get(1).pattern()).isEqualTo("prod-.*");
        assertThat(sharedContext.topicPatterns().get(2).pattern()).isEqualTo("staging\\.events");
    }

    @Test
    void shouldCreateFilterInstance() throws Exception {
        // Given
        FilterFactoryContext ctx = mock(FilterFactoryContext.class);
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                tempDir.resolve("pub.der").toString(),
                tempDir.resolve("priv.der").toString(),
                null, null, null);
        PqcRecordEncryptionFilterFactory factory = new PqcRecordEncryptionFilterFactory();
        PqcRecordEncryptionFilterFactory.SharedPqcContext sharedContext = factory.initialize(ctx, config);

        // When
        Filter filter = factory.createFilter(ctx, sharedContext);

        // Then
        assertThat(filter).isInstanceOf(PqcRecordEncryptionFilter.class);
    }

    @Test
    void shouldCloseKeyManager() throws Exception {
        // Given
        FilterFactoryContext ctx = mock(FilterFactoryContext.class);
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                tempDir.resolve("pub.der").toString(),
                tempDir.resolve("priv.der").toString(),
                null, null, null);
        PqcRecordEncryptionFilterFactory factory = new PqcRecordEncryptionFilterFactory();
        PqcRecordEncryptionFilterFactory.SharedPqcContext sharedContext = factory.initialize(ctx, config);

        // When/Then
        assertThatNoException().isThrownBy(() -> factory.close(sharedContext));
    }

    @Test
    void shouldHandleCloseWithNullContext() {
        // Given
        PqcRecordEncryptionFilterFactory factory = new PqcRecordEncryptionFilterFactory();

        // When/Then
        assertThatNoException().isThrownBy(() -> factory.close(null));
    }

    @Test
    void shouldRejectNullConfig() {
        // Given
        FilterFactoryContext ctx = mock(FilterFactoryContext.class);
        PqcRecordEncryptionFilterFactory factory = new PqcRecordEncryptionFilterFactory();

        // When/Then
        assertThatThrownBy(() -> factory.initialize(ctx, null))
                .isInstanceOf(PluginConfigurationException.class);
    }

    @Test
    void shouldWrapKeyProviderExceptionInPluginConfigurationException() {
        // Given
        FilterFactoryContext ctx = mock(FilterFactoryContext.class);
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                tempDir.resolve("pub.der").toString(),
                tempDir.resolve("priv.der").toString(),
                null, "nonexistent-provider", null);
        PqcRecordEncryptionFilterFactory factory = new PqcRecordEncryptionFilterFactory();

        // When/Then
        assertThatThrownBy(() -> factory.initialize(ctx, config))
                .isInstanceOf(PluginConfigurationException.class)
                .hasMessageContaining("Failed to initialize key provider");
    }

    @Test
    void shouldInitializeWithDefaultFailurePolicy() throws Exception {
        // Given
        FilterFactoryContext ctx = mock(FilterFactoryContext.class);
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                tempDir.resolve("pub.der").toString(),
                tempDir.resolve("priv.der").toString(),
                null, null, null);
        PqcRecordEncryptionFilterFactory factory = new PqcRecordEncryptionFilterFactory();

        // When
        PqcRecordEncryptionFilterFactory.SharedPqcContext sharedContext = factory.initialize(ctx, config);

        // Then
        assertThat(sharedContext.config().getFailurePolicy()).isEqualTo(FailurePolicy.FAIL_CLOSED);
    }

    @Test
    void shouldInitializeWithExplicitFailurePolicy() throws Exception {
        // Given
        FilterFactoryContext ctx = mock(FilterFactoryContext.class);
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                tempDir.resolve("pub.der").toString(),
                tempDir.resolve("priv.der").toString(),
                null, null, null, null, null, FailurePolicy.FAIL_OPEN);
        PqcRecordEncryptionFilterFactory factory = new PqcRecordEncryptionFilterFactory();

        // When
        PqcRecordEncryptionFilterFactory.SharedPqcContext sharedContext = factory.initialize(ctx, config);

        // Then
        assertThat(sharedContext.config().getFailurePolicy()).isEqualTo(FailurePolicy.FAIL_OPEN);
    }
}
