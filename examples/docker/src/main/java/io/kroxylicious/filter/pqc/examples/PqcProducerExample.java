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

import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.serialization.StringSerializer;

import java.time.Instant;
import java.util.Collections;
import java.util.Properties;
import java.util.concurrent.Future;

/**
 * Example Kafka producer that sends messages through the Kroxylicious proxy.
 *
 * The PQC filter in the proxy transparently encrypts messages before they
 * reach the Kafka broker. The producer does NOT need any PQC-awareness -
 * it sends plaintext, and the proxy handles encryption.
 *
 * Usage:
 *   # Connect via Kroxylicious proxy (messages will be PQC-encrypted)
 *   mvn compile exec:java -Dexec.mainClass=io.kroxylicious.filter.pqc.examples.PqcProducerExample
 *
 *   # Or specify a custom bootstrap address:
 *   mvn compile exec:java \
 *     -Dexec.mainClass=io.kroxylicious.filter.pqc.examples.PqcProducerExample \
 *     -Dexec.args="localhost:9192"
 */
public class PqcProducerExample {

    private static final String TOPIC = "sensitive-orders";

    public static void main(String[] args) throws Exception {
        String bootstrap = args.length > 0 ? args[0] : "localhost:9192";

        System.out.println("=== PQC Kafka Producer Example ===");
        System.out.println("Connecting to Kroxylicious proxy at: " + bootstrap);
        System.out.println("Topic: " + TOPIC);
        System.out.println();

        // Create topic if it doesn't exist
        createTopicIfNeeded(bootstrap);

        Properties props = new Properties();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.ACKS_CONFIG, "all");

        try (KafkaProducer<String, String> producer = new KafkaProducer<>(props)) {
            String[] sampleOrders = {
                    """
                    {"orderId":"ORD-001","customer":"Alice","amount":1299.99,"card":"4111-XXXX-XXXX-1234","status":"confirmed"}""",
                    """
                    {"orderId":"ORD-002","customer":"Bob","amount":599.50,"card":"5500-XXXX-XXXX-5678","status":"pending"}""",
                    """
                    {"orderId":"ORD-003","customer":"Charlie","amount":2499.00,"card":"3782-XXXX-XXXX-0005","status":"confirmed"}""",
                    """
                    {"orderId":"ORD-004","customer":"Diana","amount":89.99,"card":"6011-XXXX-XXXX-9012","status":"shipped"}""",
                    """
                    {"orderId":"ORD-005","customer":"Eve","amount":15000.00,"card":"4000-XXXX-XXXX-3456","status":"confirmed"}"""
            };

            System.out.println("Sending " + sampleOrders.length + " orders...");
            System.out.println("(The proxy will PQC-encrypt these before storing on the broker)");
            System.out.println();

            for (int i = 0; i < sampleOrders.length; i++) {
                String key = "order-" + (i + 1);
                String value = sampleOrders[i].trim();

                ProducerRecord<String, String> record = new ProducerRecord<>(TOPIC, key, value);
                Future<RecordMetadata> future = producer.send(record);
                RecordMetadata metadata = future.get();

                System.out.printf("  [%s] Sent: key=%s, partition=%d, offset=%d%n",
                        Instant.now(), key, metadata.partition(), metadata.offset());
                System.out.printf("         Plaintext: %s%n", truncate(value, 70));
            }

            producer.flush();
            System.out.println();
            System.out.println("All messages sent successfully!");
            System.out.println("Messages are stored PQC-encrypted on the Kafka broker.");
            System.out.println();
            System.out.println("To verify encryption, try consuming directly from the broker");
            System.out.println("(port 9092) - you'll see encrypted binary data.");
            System.out.println("Then consume through the proxy (port 9192) - you'll see plaintext.");
        }
    }

    private static void createTopicIfNeeded(String bootstrap) {
        Properties adminProps = new Properties();
        adminProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap);

        try (AdminClient admin = AdminClient.create(adminProps)) {
            if (!admin.listTopics().names().get().contains(TOPIC)) {
                admin.createTopics(Collections.singleton(
                        new NewTopic(TOPIC, 1, (short) 1))).all().get();
                System.out.println("Created topic: " + TOPIC);
            }
        }
        catch (Exception e) {
            System.out.println("Note: Could not create topic (may already exist): " + e.getMessage());
        }
    }

    private static String truncate(String s, int maxLen) {
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }
}
