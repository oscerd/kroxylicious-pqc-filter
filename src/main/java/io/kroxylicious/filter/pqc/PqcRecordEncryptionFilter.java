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

import io.kroxylicious.filter.pqc.crypto.PqcCryptoEngine;
import io.kroxylicious.filter.pqc.crypto.PqcKeyManager;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.proxy.filter.ResponseFilterResult;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.compress.Compression;
import org.apache.kafka.common.record.MemoryRecords;
import org.apache.kafka.common.record.MemoryRecordsBuilder;
import org.apache.kafka.common.record.Record;
import org.apache.kafka.common.record.RecordBatch;
import org.apache.kafka.common.record.TimestampType;
import org.apache.kafka.common.message.FetchResponseData;
import org.apache.kafka.common.message.ProduceRequestData;
import org.apache.kafka.common.message.RequestHeaderData;
import org.apache.kafka.common.message.ResponseHeaderData;
import org.apache.kafka.common.utils.ByteBufferOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.concurrent.CompletionStage;
import java.util.regex.Pattern;

/**
 * Kroxylicious filter that performs Post-Quantum Cryptography (PQC) record-level
 * encryption and decryption using ML-KEM (FIPS 203) + AES-256-GCM.
 *
 * <p>On <strong>Produce</strong>: encrypts each record value using ML-KEM encapsulation
 * before forwarding to the broker. The encrypted envelope replaces the original value.
 *
 * <p>On <strong>Fetch</strong>: decrypts each record value by performing ML-KEM
 * decapsulation and AES-GCM decryption, restoring the original plaintext.
 *
 * <p>Only records in topics matching the configured topic patterns are encrypted/decrypted.
 * Records with null values (tombstones) are passed through unchanged.
 *
 * <p>A custom Kafka header {@code x-pqc-encrypted: true} is added to encrypted records
 * so consumers can identify PQC-encrypted data even without decryption capability.
 */
public class PqcRecordEncryptionFilter implements
        io.kroxylicious.proxy.filter.ProduceRequestFilter,
        io.kroxylicious.proxy.filter.FetchResponseFilter {

    private static final Logger LOG = LoggerFactory.getLogger(PqcRecordEncryptionFilter.class);
    private static final String PQC_HEADER_KEY = "x-pqc-encrypted";
    private static final byte[] PQC_HEADER_VALUE = "true".getBytes();

    private final PqcCryptoEngine cryptoEngine;
    private final PqcKeyManager keyManager;
    private final List<Pattern> topicPatterns;

    PqcRecordEncryptionFilter(PqcCryptoEngine cryptoEngine, PqcKeyManager keyManager,
                              List<Pattern> topicPatterns) {
        this.cryptoEngine = cryptoEngine;
        this.keyManager = keyManager;
        this.topicPatterns = topicPatterns;
    }

    @Override
    public CompletionStage<RequestFilterResult> onProduceRequest(
            short apiVersion, RequestHeaderData header,
            ProduceRequestData request, FilterContext context) {

        try {
            for (ProduceRequestData.TopicProduceData topicData : request.topicData()) {
                if (!shouldProcessTopic(topicData.name())) {
                    continue;
                }

                LOG.debug("Encrypting records for topic: {}", topicData.name());

                for (ProduceRequestData.PartitionProduceData partitionData : topicData.partitionData()) {
                    MemoryRecords records = (MemoryRecords) partitionData.records();
                    if (records == null || records.sizeInBytes() == 0) {
                        continue;
                    }
                    partitionData.setRecords(encryptRecords(records));
                }
            }
        }
        catch (Exception e) {
            LOG.error("Failed to encrypt Produce request records", e);
            // Forward unencrypted on failure to avoid data loss
        }

        return context.forwardRequest(header, request);
    }

    @Override
    public CompletionStage<ResponseFilterResult> onFetchResponse(
            short apiVersion, ResponseHeaderData header,
            FetchResponseData response, FilterContext context) {

        try {
            for (FetchResponseData.FetchableTopicResponse topicResponse : response.responses()) {
                // In Fetch API v13+ the topic name is empty (topic IDs are used instead).
                // Rely on the per-record x-pqc-encrypted header to identify encrypted records.
                String topicName = topicResponse.topic();
                if (topicName != null && !topicName.isEmpty() && !shouldProcessTopic(topicName)) {
                    continue;
                }

                LOG.debug("Processing fetch response for topic: {}", topicName);

                for (FetchResponseData.PartitionData partitionData : topicResponse.partitions()) {
                    MemoryRecords records = (MemoryRecords) partitionData.records();
                    if (records == null || records.sizeInBytes() == 0) {
                        continue;
                    }
                    partitionData.setRecords(decryptRecords(records));
                }
            }
        }
        catch (Exception e) {
            LOG.error("Failed to decrypt Fetch response records", e);
        }

        return context.forwardResponse(header, response);
    }

    private boolean shouldProcessTopic(String topicName) {
        if (topicName == null) {
            return false;
        }
        return topicPatterns.stream().anyMatch(p -> p.matcher(topicName).matches());
    }

    private MemoryRecords encryptRecords(MemoryRecords records) throws GeneralSecurityException {
        int estimatedSize = records.sizeInBytes() * 2;
        ByteBufferOutputStream outputStream = new ByteBufferOutputStream(estimatedSize);

        for (RecordBatch batch : records.batches()) {
            try (MemoryRecordsBuilder builder = new MemoryRecordsBuilder(
                    outputStream,
                    batch.magic(),
                    Compression.NONE,
                    batch.timestampType() != null ? batch.timestampType() : TimestampType.CREATE_TIME,
                    batch.baseOffset(),
                    batch.maxTimestamp(),
                    batch.producerId(),
                    batch.producerEpoch(),
                    batch.baseSequence(),
                    batch.isTransactional(),
                    batch.isControlBatch(),
                    batch.partitionLeaderEpoch(),
                    outputStream.remaining())) {

                for (Record record : batch) {
                    byte[] value = extractBytes(record.value());
                    byte[] encryptedValue = (value != null) ? cryptoEngine.encrypt(value) : null;

                    Header[] originalHeaders = extractHeaders(record);
                    Header[] newHeaders;
                    if (encryptedValue != null) {
                        newHeaders = new Header[originalHeaders.length + 1];
                        System.arraycopy(originalHeaders, 0, newHeaders, 0, originalHeaders.length);
                        newHeaders[originalHeaders.length] = new PqcHeader();
                    }
                    else {
                        newHeaders = originalHeaders;
                    }

                    builder.appendWithOffset(
                            record.offset(),
                            record.timestamp(),
                            extractBytes(record.key()),
                            encryptedValue,
                            newHeaders);
                }
            }
        }

        return MemoryRecords.readableRecords(outputStream.buffer().flip());
    }

    private MemoryRecords decryptRecords(MemoryRecords records) throws GeneralSecurityException {
        int estimatedSize = records.sizeInBytes();
        ByteBufferOutputStream outputStream = new ByteBufferOutputStream(estimatedSize);

        for (RecordBatch batch : records.batches()) {
            try (MemoryRecordsBuilder builder = new MemoryRecordsBuilder(
                    outputStream,
                    batch.magic(),
                    Compression.NONE,
                    batch.timestampType() != null ? batch.timestampType() : TimestampType.CREATE_TIME,
                    batch.baseOffset(),
                    batch.maxTimestamp(),
                    batch.producerId(),
                    batch.producerEpoch(),
                    batch.baseSequence(),
                    batch.isTransactional(),
                    batch.isControlBatch(),
                    batch.partitionLeaderEpoch(),
                    outputStream.remaining())) {

                for (Record record : batch) {
                    byte[] value = extractBytes(record.value());
                    Header[] headers = extractHeaders(record);

                    byte[] decryptedValue;
                    Header[] cleanHeaders;

                    if (value != null && isPqcEncrypted(headers)) {
                        PqcCryptoEngine engine = keyManager.resolveEngine(value);
                        decryptedValue = engine.decrypt(value);
                        cleanHeaders = removePqcHeader(headers);
                    }
                    else {
                        decryptedValue = value;
                        cleanHeaders = headers;
                    }

                    builder.appendWithOffset(
                            record.offset(),
                            record.timestamp(),
                            extractBytes(record.key()),
                            decryptedValue,
                            cleanHeaders);
                }
            }
        }

        return MemoryRecords.readableRecords(outputStream.buffer().flip());
    }

    private static byte[] extractBytes(ByteBuffer buffer) {
        if (buffer == null) {
            return null;
        }
        byte[] bytes = new byte[buffer.remaining()];
        buffer.duplicate().get(bytes);
        return bytes;
    }

    private static Header[] extractHeaders(Record record) {
        if (record.headers() == null) {
            return new Header[0];
        }
        return record.headers();
    }

    private static boolean isPqcEncrypted(Header[] headers) {
        for (Header header : headers) {
            if (PQC_HEADER_KEY.equals(header.key())) {
                return true;
            }
        }
        return false;
    }

    private static Header[] removePqcHeader(Header[] headers) {
        int count = 0;
        for (Header h : headers) {
            if (!PQC_HEADER_KEY.equals(h.key())) {
                count++;
            }
        }
        if (count == headers.length) {
            return headers;
        }
        Header[] result = new Header[count];
        int idx = 0;
        for (Header h : headers) {
            if (!PQC_HEADER_KEY.equals(h.key())) {
                result[idx++] = h;
            }
        }
        return result;
    }

    private static class PqcHeader implements Header {
        @Override
        public String key() {
            return PQC_HEADER_KEY;
        }

        @Override
        public byte[] value() {
            return PQC_HEADER_VALUE;
        }
    }
}
