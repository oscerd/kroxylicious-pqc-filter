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
package io.kroxylicious.filter.pqc.examples;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.serialization.StringDeserializer;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

/**
 * Example Kafka consumer that reads messages through the Kroxylicious proxy.
 *
 * When connected through the proxy, the PQC filter transparently decrypts
 * messages. The consumer receives plaintext — no PQC awareness needed.
 *
 * When connected directly to the broker (bypassing the proxy), the consumer
 * will see encrypted binary data, demonstrating that data-at-rest is protected.
 *
 * Usage:
 *   # Consume via proxy (decrypted plaintext):
 *   mvn compile exec:java \
 *     -Dexec.mainClass=io.kroxylicious.filter.pqc.examples.PqcConsumerExample \
 *     -Dexec.args="localhost:9192"
 *
 *   # Consume directly from broker (encrypted blobs):
 *   mvn compile exec:java \
 *     -Dexec.mainClass=io.kroxylicious.filter.pqc.examples.PqcConsumerExample \
 *     -Dexec.args="localhost:9092"
 */
public class PqcConsumerExample {

    private static final String TOPIC = "sensitive-orders";

    public static void main(String[] args) {
        String bootstrap = args.length > 0 ? args[0] : "localhost:9192";
        boolean isProxy = bootstrap.contains("9192");

        System.out.println("=== PQC Kafka Consumer Example ===");
        System.out.println("Connecting to: " + bootstrap);
        if (isProxy) {
            System.out.println("Mode: VIA PROXY (messages will be decrypted transparently)");
        }
        else {
            System.out.println("Mode: DIRECT TO BROKER (messages will appear encrypted)");
        }
        System.out.println("Topic: " + TOPIC);
        System.out.println();

        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, "10");

        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props)) {
            // Use assign + seekToBeginning to avoid consumer group coordination
            TopicPartition tp = new TopicPartition(TOPIC, 0);
            consumer.assign(List.of(tp));
            consumer.seekToBeginning(List.of(tp));

            System.out.println("Polling for messages (will stop after 15 seconds of no data)...");
            System.out.println();

            int totalRecords = 0;
            int emptyPolls = 0;
            int maxEmptyPolls = 5;

            while (emptyPolls < maxEmptyPolls) {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofSeconds(3));

                if (records.isEmpty()) {
                    emptyPolls++;
                    continue;
                }

                emptyPolls = 0;

                for (ConsumerRecord<String, String> record : records) {
                    totalRecords++;
                    System.out.printf("Record #%d [partition=%d, offset=%d]%n",
                            totalRecords, record.partition(), record.offset());
                    System.out.printf("  Key:       %s%n", record.key());

                    // Show headers
                    for (Header header : record.headers()) {
                        System.out.printf("  Header:    %s = %s%n",
                                header.key(), new String(header.value()));
                    }

                    // Show value
                    String value = record.value();
                    if (value != null && isPrintable(value)) {
                        System.out.printf("  Value:     %s%n", truncate(value, 100));
                    }
                    else if (value != null) {
                        System.out.printf("  Value:     [ENCRYPTED BINARY DATA, %d chars]%n", value.length());
                        System.out.printf("             Base64: %s...%n",
                                Base64.getEncoder().encodeToString(
                                        value.getBytes()).substring(0, Math.min(60, value.length())));
                    }
                    else {
                        System.out.printf("  Value:     <null>%n");
                    }
                    System.out.println();
                }
            }

            System.out.println("─".repeat(60));
            System.out.printf("Total records consumed: %d%n", totalRecords);
            if (isProxy) {
                System.out.println("All messages were decrypted by the PQC filter in the proxy.");
            }
            else {
                System.out.println("Messages appear as encrypted blobs (not readable without the proxy).");
            }
        }
    }

    private static boolean isPrintable(String s) {
        return s.chars().allMatch(c -> c >= 32 && c < 127 || c == '\n' || c == '\r' || c == '\t');
    }

    private static String truncate(String s, int maxLen) {
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }
}
