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
import io.kroxylicious.filter.pqc.crypto.PqcCryptoEngine;
import io.kroxylicious.filter.pqc.crypto.PqcKeyManager;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.proxy.filter.ResponseFilterResult;
import org.apache.kafka.common.compress.Compression;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.header.internals.RecordHeader;
import org.apache.kafka.common.message.FetchResponseData;
import org.apache.kafka.common.message.ProduceRequestData;
import org.apache.kafka.common.message.RequestHeaderData;
import org.apache.kafka.common.message.ResponseHeaderData;
import org.apache.kafka.common.record.MemoryRecords;
import org.apache.kafka.common.record.MemoryRecordsBuilder;
import org.apache.kafka.common.record.Record;
import org.apache.kafka.common.record.RecordBatch;
import org.apache.kafka.common.record.TimestampType;
import org.apache.kafka.common.utils.ByteBufferOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PqcRecordEncryptionFilterTest {

    private static final String PQC_HEADER_KEY = "x-pqc-encrypted";

    @TempDir
    Path tempDir;

    @Mock
    FilterContext filterContext;

    @Mock
    RequestFilterResult requestResult;

    @Mock
    ResponseFilterResult responseResult;

    private PqcCryptoEngine cryptoEngine;
    private PqcKeyManager keyManager;
    private PqcRecordEncryptionFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        PqcEncryptionConfig config = new PqcEncryptionConfig(
                KemAlgorithm.ML_KEM_768, false,
                tempDir.resolve("pub.der").toString(),
                tempDir.resolve("priv.der").toString(),
                null, null, null);
        keyManager = new PqcKeyManager(config);
        cryptoEngine = keyManager.createEngine(false);

        filter = new PqcRecordEncryptionFilter(
                cryptoEngine, keyManager,
                List.of(Pattern.compile("test-.*")),
                FailurePolicy.FAIL_CLOSED);

        when(filterContext.forwardRequest(any(), any()))
                .thenReturn(CompletableFuture.completedFuture(requestResult));
        when(filterContext.forwardResponse(any(), any()))
                .thenReturn(CompletableFuture.completedFuture(responseResult));
    }

    // --- Produce (encryption) tests ---

    @Test
    void shouldEncryptRecordsOnProduce() throws Exception {
        // Given
        byte[] originalValue = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        ProduceRequestData request = buildProduceRequest("test-topic", "key1", originalValue);

        // When
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        List<Record> records = extractRecords(request);
        assertThat(records).hasSize(1);

        Record record = records.get(0);
        assertThat(extractBytes(record.value())).isNotEqualTo(originalValue);
        assertThat(hasPqcHeader(record.headers())).isTrue();
    }

    @Test
    void shouldAddPqcEncryptedHeaderOnProduce() throws Exception {
        // Given
        ProduceRequestData request = buildProduceRequest("test-topic", "key1",
                "data".getBytes(StandardCharsets.UTF_8));

        // When
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecords(request).get(0);
        Header pqcHeader = findHeader(record.headers(), PQC_HEADER_KEY);
        assertThat(pqcHeader).isNotNull();
        assertThat(new String(pqcHeader.value())).isEqualTo("true");
    }

    @Test
    void shouldPassThroughTombstonesOnProduce() throws Exception {
        // Given
        ProduceRequestData request = buildProduceRequest("test-topic", "key1", (byte[]) null);

        // When
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecords(request).get(0);
        assertThat(record.value()).isNull();
        assertThat(hasPqcHeader(record.headers())).isFalse();
    }

    @Test
    void shouldSkipNonMatchingTopicsOnProduce() throws Exception {
        // Given
        byte[] originalValue = "should not be encrypted".getBytes(StandardCharsets.UTF_8);
        ProduceRequestData request = buildProduceRequest("other-topic", "key1", originalValue);

        // When
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecords(request).get(0);
        assertThat(extractBytes(record.value())).isEqualTo(originalValue);
        assertThat(hasPqcHeader(record.headers())).isFalse();
    }

    @Test
    void shouldProcessMultipleTopicPatterns() throws Exception {
        // Given
        PqcRecordEncryptionFilter multiPatternFilter = new PqcRecordEncryptionFilter(
                cryptoEngine, keyManager,
                List.of(Pattern.compile("test-.*"), Pattern.compile("prod-.*")),
                FailurePolicy.FAIL_CLOSED);

        byte[] value = "data".getBytes(StandardCharsets.UTF_8);
        ProduceRequestData request1 = buildProduceRequest("test-topic", "k", value);
        ProduceRequestData request2 = buildProduceRequest("prod-events", "k", value);
        ProduceRequestData request3 = buildProduceRequest("staging-topic", "k", value);

        // When
        multiPatternFilter.onProduceRequest((short) 9, new RequestHeaderData(), request1, filterContext)
                .toCompletableFuture().get();
        multiPatternFilter.onProduceRequest((short) 9, new RequestHeaderData(), request2, filterContext)
                .toCompletableFuture().get();
        multiPatternFilter.onProduceRequest((short) 9, new RequestHeaderData(), request3, filterContext)
                .toCompletableFuture().get();

        // Then
        assertThat(hasPqcHeader(extractRecords(request1).get(0).headers())).isTrue();
        assertThat(hasPqcHeader(extractRecords(request2).get(0).headers())).isTrue();
        assertThat(hasPqcHeader(extractRecords(request3).get(0).headers())).isFalse();
    }

    @Test
    void shouldPreserveExistingHeadersOnProduce() throws Exception {
        // Given
        Header[] originalHeaders = new Header[]{
                new RecordHeader("custom-header", "custom-value".getBytes())
        };
        ProduceRequestData request = buildProduceRequest("test-topic", "key1",
                "data".getBytes(StandardCharsets.UTF_8), originalHeaders);

        // When
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecords(request).get(0);
        assertThat(findHeader(record.headers(), "custom-header")).isNotNull();
        assertThat(hasPqcHeader(record.headers())).isTrue();
    }

    @Test
    void shouldPreserveRecordKeyOnProduce() throws Exception {
        // Given
        byte[] key = "my-record-key".getBytes(StandardCharsets.UTF_8);
        ProduceRequestData request = buildProduceRequest("test-topic", key,
                "data".getBytes(StandardCharsets.UTF_8), new Header[0]);

        // When
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecords(request).get(0);
        assertThat(extractBytes(record.key())).isEqualTo(key);
    }

    @Test
    void shouldHandleMultipleRecordsInBatch() throws Exception {
        // Given
        byte[] value1 = "message-1".getBytes(StandardCharsets.UTF_8);
        byte[] value2 = "message-2".getBytes(StandardCharsets.UTF_8);
        byte[] value3 = "message-3".getBytes(StandardCharsets.UTF_8);

        MemoryRecords records = buildMultiRecordBatch(
                List.of(value1, value2, value3),
                List.of("k1", "k2", "k3"));
        ProduceRequestData request = buildProduceRequestWithRecords("test-topic", records);

        // When
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        List<Record> resultRecords = extractRecords(request);
        assertThat(resultRecords).hasSize(3);
        for (Record record : resultRecords) {
            assertThat(hasPqcHeader(record.headers())).isTrue();
        }
    }

    @Test
    void shouldHandleMultiplePartitions() throws Exception {
        // Given
        byte[] value1 = "partition-0-data".getBytes(StandardCharsets.UTF_8);
        byte[] value2 = "partition-1-data".getBytes(StandardCharsets.UTF_8);

        ProduceRequestData request = new ProduceRequestData();
        ProduceRequestData.TopicProduceData topicData = new ProduceRequestData.TopicProduceData()
                .setName("test-topic");

        ProduceRequestData.PartitionProduceData p0 = new ProduceRequestData.PartitionProduceData()
                .setIndex(0)
                .setRecords(buildMemoryRecords("k1", value1, new Header[0]));
        ProduceRequestData.PartitionProduceData p1 = new ProduceRequestData.PartitionProduceData()
                .setIndex(1)
                .setRecords(buildMemoryRecords("k2", value2, new Header[0]));

        topicData.partitionData().add(p0);
        topicData.partitionData().add(p1);
        request.topicData().add(topicData);

        // When
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        for (ProduceRequestData.PartitionProduceData pd : topicData.partitionData()) {
            MemoryRecords mr = (MemoryRecords) pd.records();
            for (RecordBatch batch : mr.batches()) {
                for (Record record : batch) {
                    assertThat(hasPqcHeader(record.headers())).isTrue();
                }
            }
        }
    }

    @Test
    void shouldHandleEmptyRecords() throws Exception {
        // Given
        ProduceRequestData request = new ProduceRequestData();
        ProduceRequestData.TopicProduceData topicData = new ProduceRequestData.TopicProduceData()
                .setName("test-topic");
        ProduceRequestData.PartitionProduceData partitionData = new ProduceRequestData.PartitionProduceData()
                .setIndex(0)
                .setRecords(MemoryRecords.EMPTY);
        topicData.partitionData().add(partitionData);
        request.topicData().add(topicData);

        // When
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        MemoryRecords resultRecords = (MemoryRecords) partitionData.records();
        assertThat(resultRecords.sizeInBytes()).isEqualTo(0);
        verify(filterContext).forwardRequest(any(), any());
    }

    @Test
    void shouldHandleTransactionalRecords() throws Exception {
        // Given
        byte[] value = "transactional-data".getBytes(StandardCharsets.UTF_8);
        MemoryRecords records = buildTransactionalRecords("key1", value);
        ProduceRequestData request = buildProduceRequestWithRecords("test-topic", records);

        // When
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        List<Record> resultRecords = extractRecords(request);
        assertThat(resultRecords).hasSize(1);
        assertThat(hasPqcHeader(resultRecords.get(0).headers())).isTrue();

        MemoryRecords resultMemRecords = (MemoryRecords) request.topicData().iterator().next()
                .partitionData().iterator().next().records();
        for (RecordBatch batch : resultMemRecords.batches()) {
            assertThat(batch.isTransactional()).isTrue();
        }
    }

    // --- Fetch (decryption) tests ---

    @Test
    void shouldDecryptRecordsOnFetch() throws Exception {
        // Given
        byte[] originalValue = "Hello, decryption!".getBytes(StandardCharsets.UTF_8);
        byte[] encryptedValue = cryptoEngine.encrypt(originalValue);
        Header[] headers = new Header[]{new RecordHeader(PQC_HEADER_KEY, "true".getBytes())};
        MemoryRecords encryptedRecords = buildMemoryRecords("key1", encryptedValue, headers);
        FetchResponseData response = buildFetchResponse("test-topic", encryptedRecords);

        // When
        filter.onFetchResponse((short) 16, new ResponseHeaderData(), response, filterContext)
                .toCompletableFuture().get();

        // Then
        List<Record> records = extractRecordsFromFetch(response);
        assertThat(records).hasSize(1);

        Record record = records.get(0);
        assertThat(extractBytes(record.value())).isEqualTo(originalValue);
        assertThat(hasPqcHeader(record.headers())).isFalse();
    }

    @Test
    void shouldRemovePqcHeaderOnDecrypt() throws Exception {
        // Given
        byte[] encryptedValue = cryptoEngine.encrypt("data".getBytes(StandardCharsets.UTF_8));
        Header[] headers = new Header[]{
                new RecordHeader("custom-header", "keep-me".getBytes()),
                new RecordHeader(PQC_HEADER_KEY, "true".getBytes())
        };
        MemoryRecords encryptedRecords = buildMemoryRecords("key1", encryptedValue, headers);
        FetchResponseData response = buildFetchResponse("test-topic", encryptedRecords);

        // When
        filter.onFetchResponse((short) 16, new ResponseHeaderData(), response, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecordsFromFetch(response).get(0);
        assertThat(hasPqcHeader(record.headers())).isFalse();
        assertThat(findHeader(record.headers(), "custom-header")).isNotNull();
    }

    @Test
    void shouldSkipDecryptionForNonPqcRecords() throws Exception {
        // Given
        byte[] originalValue = "plain text".getBytes(StandardCharsets.UTF_8);
        MemoryRecords records = buildMemoryRecords("key1", originalValue, new Header[0]);
        FetchResponseData response = buildFetchResponse("test-topic", records);

        // When
        filter.onFetchResponse((short) 16, new ResponseHeaderData(), response, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecordsFromFetch(response).get(0);
        assertThat(extractBytes(record.value())).isEqualTo(originalValue);
    }

    @Test
    void shouldPassThroughTombstonesOnFetch() throws Exception {
        // Given
        MemoryRecords records = buildMemoryRecords("key1", (byte[]) null, new Header[0]);
        FetchResponseData response = buildFetchResponse("test-topic", records);

        // When
        filter.onFetchResponse((short) 16, new ResponseHeaderData(), response, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecordsFromFetch(response).get(0);
        assertThat(record.value()).isNull();
    }

    @Test
    void shouldSkipNonMatchingTopicsOnFetch() throws Exception {
        // Given
        byte[] encryptedValue = cryptoEngine.encrypt("data".getBytes(StandardCharsets.UTF_8));
        Header[] headers = new Header[]{new RecordHeader(PQC_HEADER_KEY, "true".getBytes())};
        MemoryRecords records = buildMemoryRecords("key1", encryptedValue, headers);
        FetchResponseData response = buildFetchResponse("other-topic", records);

        // When
        filter.onFetchResponse((short) 16, new ResponseHeaderData(), response, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecordsFromFetch(response).get(0);
        assertThat(extractBytes(record.value())).isEqualTo(encryptedValue);
        assertThat(hasPqcHeader(record.headers())).isTrue();
    }

    @Test
    void shouldDecryptWhenTopicNameIsEmpty() throws Exception {
        // Given (Fetch API v13+ uses topic IDs, topic name is empty)
        byte[] originalValue = "v13 fetch".getBytes(StandardCharsets.UTF_8);
        byte[] encryptedValue = cryptoEngine.encrypt(originalValue);
        Header[] headers = new Header[]{new RecordHeader(PQC_HEADER_KEY, "true".getBytes())};
        MemoryRecords records = buildMemoryRecords("key1", encryptedValue, headers);
        FetchResponseData response = buildFetchResponse("", records);

        // When
        filter.onFetchResponse((short) 16, new ResponseHeaderData(), response, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecordsFromFetch(response).get(0);
        assertThat(extractBytes(record.value())).isEqualTo(originalValue);
        assertThat(hasPqcHeader(record.headers())).isFalse();
    }

    @Test
    void shouldHandleMixedEncryptedAndPlainRecordsOnFetch() throws Exception {
        // Given
        byte[] plainValue = "plain".getBytes(StandardCharsets.UTF_8);
        byte[] originalEncrypted = "secret".getBytes(StandardCharsets.UTF_8);
        byte[] encryptedValue = cryptoEngine.encrypt(originalEncrypted);

        ByteBufferOutputStream out = new ByteBufferOutputStream(4096);
        try (MemoryRecordsBuilder builder = new MemoryRecordsBuilder(
                out, RecordBatch.CURRENT_MAGIC_VALUE, Compression.NONE,
                TimestampType.CREATE_TIME, 0L, System.currentTimeMillis(),
                RecordBatch.NO_PRODUCER_ID, RecordBatch.NO_PRODUCER_EPOCH,
                RecordBatch.NO_SEQUENCE, false, false, 0, out.remaining())) {
            builder.appendWithOffset(0L, System.currentTimeMillis(),
                    "k1".getBytes(), plainValue, new Header[0]);
            builder.appendWithOffset(1L, System.currentTimeMillis(),
                    "k2".getBytes(), encryptedValue,
                    new Header[]{new RecordHeader(PQC_HEADER_KEY, "true".getBytes())});
        }
        MemoryRecords records = MemoryRecords.readableRecords(out.buffer().flip());
        FetchResponseData response = buildFetchResponse("test-topic", records);

        // When
        filter.onFetchResponse((short) 16, new ResponseHeaderData(), response, filterContext)
                .toCompletableFuture().get();

        // Then
        List<Record> resultRecords = extractRecordsFromFetch(response);
        assertThat(resultRecords).hasSize(2);
        assertThat(extractBytes(resultRecords.get(0).value())).isEqualTo(plainValue);
        assertThat(extractBytes(resultRecords.get(1).value())).isEqualTo(originalEncrypted);
    }

    // --- Roundtrip tests ---

    @Test
    void shouldRoundtripEncryptDecrypt() throws Exception {
        // Given
        byte[] originalValue = "Hello, Post-Quantum World!".getBytes(StandardCharsets.UTF_8);
        byte[] originalKey = "record-key".getBytes(StandardCharsets.UTF_8);
        ProduceRequestData request = buildProduceRequest("test-topic", originalKey,
                originalValue, new Header[0]);

        // When - encrypt
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Extract encrypted records and build fetch response
        MemoryRecords encryptedRecords = (MemoryRecords) request.topicData().iterator().next()
                .partitionData().iterator().next().records();
        FetchResponseData response = buildFetchResponse("test-topic", encryptedRecords);

        // When - decrypt
        filter.onFetchResponse((short) 16, new ResponseHeaderData(), response, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecordsFromFetch(response).get(0);
        assertThat(extractBytes(record.value())).isEqualTo(originalValue);
        assertThat(extractBytes(record.key())).isEqualTo(originalKey);
        assertThat(hasPqcHeader(record.headers())).isFalse();
    }

    @Test
    void shouldRoundtripMultipleRecords() throws Exception {
        // Given
        byte[] v1 = "message-1".getBytes(StandardCharsets.UTF_8);
        byte[] v2 = "message-2".getBytes(StandardCharsets.UTF_8);
        MemoryRecords records = buildMultiRecordBatch(List.of(v1, v2), List.of("k1", "k2"));
        ProduceRequestData request = buildProduceRequestWithRecords("test-topic", records);

        // When - encrypt
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        MemoryRecords encryptedRecords = (MemoryRecords) request.topicData().iterator().next()
                .partitionData().iterator().next().records();
        FetchResponseData response = buildFetchResponse("test-topic", encryptedRecords);

        // When - decrypt
        filter.onFetchResponse((short) 16, new ResponseHeaderData(), response, filterContext)
                .toCompletableFuture().get();

        // Then
        List<Record> resultRecords = extractRecordsFromFetch(response);
        assertThat(resultRecords).hasSize(2);
        assertThat(extractBytes(resultRecords.get(0).value())).isEqualTo(v1);
        assertThat(extractBytes(resultRecords.get(1).value())).isEqualTo(v2);
    }

    @Test
    void shouldPreserveRecordOffsetsAndTimestamps() throws Exception {
        // Given
        long timestamp = 1700000000000L;
        byte[] value = "offset-test".getBytes(StandardCharsets.UTF_8);
        ByteBufferOutputStream out = new ByteBufferOutputStream(4096);
        try (MemoryRecordsBuilder builder = new MemoryRecordsBuilder(
                out, RecordBatch.CURRENT_MAGIC_VALUE, Compression.NONE,
                TimestampType.CREATE_TIME, 42L, timestamp,
                RecordBatch.NO_PRODUCER_ID, RecordBatch.NO_PRODUCER_EPOCH,
                RecordBatch.NO_SEQUENCE, false, false, 0, out.remaining())) {
            builder.appendWithOffset(42L, timestamp, "k".getBytes(), value, new Header[0]);
        }
        MemoryRecords records = MemoryRecords.readableRecords(out.buffer().flip());
        ProduceRequestData request = buildProduceRequestWithRecords("test-topic", records);

        // When - encrypt
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        MemoryRecords encryptedRecords = (MemoryRecords) request.topicData().iterator().next()
                .partitionData().iterator().next().records();
        FetchResponseData response = buildFetchResponse("test-topic", encryptedRecords);

        // When - decrypt
        filter.onFetchResponse((short) 16, new ResponseHeaderData(), response, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractRecordsFromFetch(response).get(0);
        assertThat(record.offset()).isEqualTo(42L);
        assertThat(record.timestamp()).isEqualTo(timestamp);
    }

    // --- Failure policy tests ---

    @Test
    void shouldThrowOnEncryptionFailureWithFailClosed() throws Exception {
        // Given
        PqcCryptoEngine failingEngine = mock(PqcCryptoEngine.class);
        when(failingEngine.encrypt(any(byte[].class)))
                .thenThrow(new GeneralSecurityException("encryption error"));

        PqcRecordEncryptionFilter failClosedFilter = new PqcRecordEncryptionFilter(
                failingEngine, keyManager,
                List.of(Pattern.compile("test-.*")),
                FailurePolicy.FAIL_CLOSED);

        ProduceRequestData request = buildProduceRequest("test-topic", "key1",
                "value".getBytes(StandardCharsets.UTF_8));

        // When/Then
        assertThatThrownBy(() -> failClosedFilter.onProduceRequest(
                (short) 9, new RequestHeaderData(), request, filterContext))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("PQC encryption failed");
    }

    @Test
    void shouldForwardUnencryptedOnFailureWithFailOpen() throws Exception {
        // Given
        PqcCryptoEngine failingEngine = mock(PqcCryptoEngine.class);
        when(failingEngine.encrypt(any(byte[].class)))
                .thenThrow(new GeneralSecurityException("encryption error"));

        PqcRecordEncryptionFilter failOpenFilter = new PqcRecordEncryptionFilter(
                failingEngine, keyManager,
                List.of(Pattern.compile("test-.*")),
                FailurePolicy.FAIL_OPEN);

        ProduceRequestData request = buildProduceRequest("test-topic", "key1",
                "value".getBytes(StandardCharsets.UTF_8));

        // When
        failOpenFilter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        verify(filterContext).forwardRequest(any(), any());
    }

    @Test
    void shouldThrowOnDecryptionFailureWithFailClosed() throws Exception {
        // Given
        PqcKeyManager failingKeyManager = mock(PqcKeyManager.class);
        when(failingKeyManager.resolveEngine(any(byte[].class)))
                .thenThrow(new GeneralSecurityException("unknown key"));

        PqcRecordEncryptionFilter failClosedFilter = new PqcRecordEncryptionFilter(
                cryptoEngine, failingKeyManager,
                List.of(Pattern.compile("test-.*")),
                FailurePolicy.FAIL_CLOSED);

        byte[] encryptedValue = cryptoEngine.encrypt("data".getBytes(StandardCharsets.UTF_8));
        Header[] headers = new Header[]{new RecordHeader(PQC_HEADER_KEY, "true".getBytes())};
        MemoryRecords records = buildMemoryRecords("key1", encryptedValue, headers);
        FetchResponseData response = buildFetchResponse("test-topic", records);

        // When/Then
        assertThatThrownBy(() -> failClosedFilter.onFetchResponse(
                (short) 16, new ResponseHeaderData(), response, filterContext))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("PQC decryption failed");
    }

    @Test
    void shouldForwardUndecryptedOnFailureWithFailOpen() throws Exception {
        // Given
        PqcKeyManager failingKeyManager = mock(PqcKeyManager.class);
        when(failingKeyManager.resolveEngine(any(byte[].class)))
                .thenThrow(new GeneralSecurityException("unknown key"));

        PqcRecordEncryptionFilter failOpenFilter = new PqcRecordEncryptionFilter(
                cryptoEngine, failingKeyManager,
                List.of(Pattern.compile("test-.*")),
                FailurePolicy.FAIL_OPEN);

        byte[] encryptedValue = cryptoEngine.encrypt("data".getBytes(StandardCharsets.UTF_8));
        Header[] headers = new Header[]{new RecordHeader(PQC_HEADER_KEY, "true".getBytes())};
        MemoryRecords records = buildMemoryRecords("key1", encryptedValue, headers);
        FetchResponseData response = buildFetchResponse("test-topic", records);

        // When
        failOpenFilter.onFetchResponse((short) 16, new ResponseHeaderData(), response, filterContext)
                .toCompletableFuture().get();

        // Then
        verify(filterContext).forwardResponse(any(), any());
    }

    // --- Topic pattern matching tests ---

    @Test
    void shouldHandleNullTopicNameOnProduce() throws Exception {
        // Given (null topic should not match any pattern)
        ProduceRequestData request = new ProduceRequestData();
        ProduceRequestData.TopicProduceData topicData = new ProduceRequestData.TopicProduceData();
        byte[] value = "data".getBytes(StandardCharsets.UTF_8);
        ProduceRequestData.PartitionProduceData partitionData = new ProduceRequestData.PartitionProduceData()
                .setIndex(0)
                .setRecords(buildMemoryRecords("key1", value, new Header[0]));
        topicData.partitionData().add(partitionData);
        request.topicData().add(topicData);

        // When
        filter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        Record record = extractFirstRecord(partitionData);
        assertThat(extractBytes(record.value())).isEqualTo(value);
        assertThat(hasPqcHeader(record.headers())).isFalse();
    }

    @Test
    void shouldMatchExactTopicPattern() throws Exception {
        // Given
        PqcRecordEncryptionFilter exactFilter = new PqcRecordEncryptionFilter(
                cryptoEngine, keyManager,
                List.of(Pattern.compile("exact-topic")),
                FailurePolicy.FAIL_CLOSED);

        byte[] value = "data".getBytes(StandardCharsets.UTF_8);
        ProduceRequestData matchRequest = buildProduceRequest("exact-topic", "k", value);
        ProduceRequestData noMatchRequest = buildProduceRequest("exact-topic-extra", "k",
                "data".getBytes(StandardCharsets.UTF_8));

        // When
        exactFilter.onProduceRequest((short) 9, new RequestHeaderData(), matchRequest, filterContext)
                .toCompletableFuture().get();
        exactFilter.onProduceRequest((short) 9, new RequestHeaderData(), noMatchRequest, filterContext)
                .toCompletableFuture().get();

        // Then
        assertThat(hasPqcHeader(extractRecords(matchRequest).get(0).headers())).isTrue();
        assertThat(hasPqcHeader(extractRecords(noMatchRequest).get(0).headers())).isFalse();
    }

    @Test
    void shouldMatchWildcardPattern() throws Exception {
        // Given
        PqcRecordEncryptionFilter wildcardFilter = new PqcRecordEncryptionFilter(
                cryptoEngine, keyManager,
                List.of(Pattern.compile(".*")),
                FailurePolicy.FAIL_CLOSED);

        ProduceRequestData request = buildProduceRequest("any-topic", "k",
                "data".getBytes(StandardCharsets.UTF_8));

        // When
        wildcardFilter.onProduceRequest((short) 9, new RequestHeaderData(), request, filterContext)
                .toCompletableFuture().get();

        // Then
        assertThat(hasPqcHeader(extractRecords(request).get(0).headers())).isTrue();
    }

    // --- Lifecycle tests ---

    @Test
    void shouldForwardRequestViaContext() throws Exception {
        // Given
        RequestHeaderData header = new RequestHeaderData();
        ProduceRequestData request = buildProduceRequest("test-topic", "k",
                "data".getBytes(StandardCharsets.UTF_8));

        // When
        filter.onProduceRequest((short) 9, header, request, filterContext)
                .toCompletableFuture().get();

        // Then
        verify(filterContext).forwardRequest(header, request);
    }

    @Test
    void shouldForwardResponseViaContext() throws Exception {
        // Given
        ResponseHeaderData header = new ResponseHeaderData();
        MemoryRecords records = buildMemoryRecords("key1",
                "plain".getBytes(StandardCharsets.UTF_8), new Header[0]);
        FetchResponseData response = buildFetchResponse("other-topic", records);

        // When
        filter.onFetchResponse((short) 16, header, response, filterContext)
                .toCompletableFuture().get();

        // Then
        verify(filterContext).forwardResponse(header, response);
    }

    // --- Helper methods ---

    private MemoryRecords buildMemoryRecords(String key, byte[] value, Header[] headers) {
        byte[] keyBytes = key != null ? key.getBytes(StandardCharsets.UTF_8) : null;
        return buildMemoryRecords(keyBytes, value, headers);
    }

    private MemoryRecords buildMemoryRecords(byte[] key, byte[] value, Header[] headers) {
        ByteBufferOutputStream out = new ByteBufferOutputStream(4096);
        try (MemoryRecordsBuilder builder = new MemoryRecordsBuilder(
                out, RecordBatch.CURRENT_MAGIC_VALUE, Compression.NONE,
                TimestampType.CREATE_TIME, 0L, System.currentTimeMillis(),
                RecordBatch.NO_PRODUCER_ID, RecordBatch.NO_PRODUCER_EPOCH,
                RecordBatch.NO_SEQUENCE, false, false, 0, out.remaining())) {
            builder.appendWithOffset(0L, System.currentTimeMillis(), key, value, headers);
        }
        return MemoryRecords.readableRecords(out.buffer().flip());
    }

    private MemoryRecords buildMultiRecordBatch(List<byte[]> values, List<String> keys) {
        ByteBufferOutputStream out = new ByteBufferOutputStream(4096);
        try (MemoryRecordsBuilder builder = new MemoryRecordsBuilder(
                out, RecordBatch.CURRENT_MAGIC_VALUE, Compression.NONE,
                TimestampType.CREATE_TIME, 0L, System.currentTimeMillis(),
                RecordBatch.NO_PRODUCER_ID, RecordBatch.NO_PRODUCER_EPOCH,
                RecordBatch.NO_SEQUENCE, false, false, 0, out.remaining())) {
            for (int i = 0; i < values.size(); i++) {
                builder.appendWithOffset(i, System.currentTimeMillis(),
                        keys.get(i).getBytes(StandardCharsets.UTF_8),
                        values.get(i), new Header[0]);
            }
        }
        return MemoryRecords.readableRecords(out.buffer().flip());
    }

    private MemoryRecords buildTransactionalRecords(String key, byte[] value) {
        ByteBufferOutputStream out = new ByteBufferOutputStream(4096);
        try (MemoryRecordsBuilder builder = new MemoryRecordsBuilder(
                out, RecordBatch.CURRENT_MAGIC_VALUE, Compression.NONE,
                TimestampType.CREATE_TIME, 0L, System.currentTimeMillis(),
                100L, (short) 1, 0,
                true, false, 0, out.remaining())) {
            builder.appendWithOffset(0L, System.currentTimeMillis(),
                    key.getBytes(StandardCharsets.UTF_8), value, new Header[0]);
        }
        return MemoryRecords.readableRecords(out.buffer().flip());
    }

    private ProduceRequestData buildProduceRequest(String topic, String key, byte[] value) {
        return buildProduceRequest(topic, key, value, new Header[0]);
    }

    private ProduceRequestData buildProduceRequest(String topic, String key, byte[] value,
                                                   Header[] headers) {
        byte[] keyBytes = key != null ? key.getBytes(StandardCharsets.UTF_8) : null;
        return buildProduceRequest(topic, keyBytes, value, headers);
    }

    private ProduceRequestData buildProduceRequest(String topic, byte[] key, byte[] value,
                                                   Header[] headers) {
        MemoryRecords records = buildMemoryRecords(key, value, headers);
        return buildProduceRequestWithRecords(topic, records);
    }

    private ProduceRequestData buildProduceRequestWithRecords(String topic, MemoryRecords records) {
        ProduceRequestData request = new ProduceRequestData();
        ProduceRequestData.TopicProduceData topicData = new ProduceRequestData.TopicProduceData()
                .setName(topic);
        ProduceRequestData.PartitionProduceData partitionData = new ProduceRequestData.PartitionProduceData()
                .setIndex(0)
                .setRecords(records);
        topicData.partitionData().add(partitionData);
        request.topicData().add(topicData);
        return request;
    }

    private FetchResponseData buildFetchResponse(String topic, MemoryRecords records) {
        FetchResponseData response = new FetchResponseData();
        FetchResponseData.FetchableTopicResponse topicResponse = new FetchResponseData.FetchableTopicResponse()
                .setTopic(topic);
        FetchResponseData.PartitionData partitionData = new FetchResponseData.PartitionData()
                .setPartitionIndex(0)
                .setRecords(records);
        topicResponse.partitions().add(partitionData);
        response.responses().add(topicResponse);
        return response;
    }

    private List<Record> extractRecords(ProduceRequestData request) {
        List<Record> result = new ArrayList<>();
        for (ProduceRequestData.TopicProduceData td : request.topicData()) {
            for (ProduceRequestData.PartitionProduceData pd : td.partitionData()) {
                MemoryRecords mr = (MemoryRecords) pd.records();
                for (RecordBatch batch : mr.batches()) {
                    for (Record record : batch) {
                        result.add(record);
                    }
                }
            }
        }
        return result;
    }

    private List<Record> extractRecordsFromFetch(FetchResponseData response) {
        List<Record> result = new ArrayList<>();
        for (FetchResponseData.FetchableTopicResponse tr : response.responses()) {
            for (FetchResponseData.PartitionData pd : tr.partitions()) {
                MemoryRecords mr = (MemoryRecords) pd.records();
                for (RecordBatch batch : mr.batches()) {
                    for (Record record : batch) {
                        result.add(record);
                    }
                }
            }
        }
        return result;
    }

    private Record extractFirstRecord(ProduceRequestData.PartitionProduceData partitionData) {
        MemoryRecords mr = (MemoryRecords) partitionData.records();
        for (RecordBatch batch : mr.batches()) {
            for (Record record : batch) {
                return record;
            }
        }
        throw new AssertionError("No records found");
    }

    private static byte[] extractBytes(ByteBuffer buffer) {
        if (buffer == null) {
            return null;
        }
        byte[] bytes = new byte[buffer.remaining()];
        buffer.duplicate().get(bytes);
        return bytes;
    }

    private static boolean hasPqcHeader(Header[] headers) {
        if (headers == null) {
            return false;
        }
        for (Header h : headers) {
            if (PQC_HEADER_KEY.equals(h.key())) {
                return true;
            }
        }
        return false;
    }

    private static Header findHeader(Header[] headers, String key) {
        if (headers == null) {
            return null;
        }
        for (Header h : headers) {
            if (key.equals(h.key())) {
                return h;
            }
        }
        return null;
    }
}
