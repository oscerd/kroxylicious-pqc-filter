# Kroxylicious PQC Filter - Examples

Two examples demonstrate the PQC record encryption filter in action.

## Example 1: Standalone Demo (No Kafka Required)

The standalone demo exercises the PQC crypto engine directly, showing
encryption and decryption of simulated Kafka record payloads without
requiring a running Kafka cluster or Kroxylicious proxy.

### What it demonstrates

| Demo | Description |
|------|-------------|
| **1. PQC-Only Mode** | Encrypts a JSON order (with credit card data) using ML-KEM-768 + AES-256-GCM, then decrypts it back to plaintext. Shows the encrypted envelope size and overhead. |
| **2. Hybrid Mode** | Compares PQC-only vs hybrid (ML-KEM + X25519) ciphertext sizes. Explains the defense-in-depth benefit: both classical and quantum attacks must succeed. |
| **3. Parameter Sets** | Generates keys and encrypts with all three ML-KEM variants (512, 768, 1024). Prints a comparison table of public key, private key, and ciphertext sizes. |
| **4. Tamper Detection** | Encrypts a message, flips one bit in the ciphertext, and shows that AES-GCM rejects the tampered data with an `AEADBadTagException`. |
| **5. Semantic Security** | Encrypts the same plaintext three times and shows that each ciphertext is different (IND-CCA2 property). |
| **6. Performance** | Benchmarks encrypt/decrypt throughput for all ML-KEM parameter sets (1,000 iterations, 1 KB messages). |

### How to run

```bash
# From the project root
cd examples/standalone

mvn compile exec:java
```

### Expected output

```
════════════════════════════════════════════════════════════════════════
  Kroxylicious PQC Record Encryption - Standalone Demo
  Post-Quantum Cryptography for Apache Kafka
════════════════════════════════════════════════════════════════════════

DEMO 1: PQC-Only Mode (ML-KEM-768 + AES-256-GCM)
────────────────────────────────────────────────────────────────────────
[1] Generating ML-KEM-768 key pair...
    Public key size:  1206 bytes
    Private key size: 2498 bytes

[2] Original Kafka record value (plaintext):
    {
      "orderId": "ORD-2024-98765",
      "customer": "Alice",
      "amount": 1299.99,
      "currency": "EUR",
      "creditCard": "4111-XXXX-XXXX-1234",
      "status": "confirmed"
    }
    Size: 162 bytes

[3] Encrypting with ML-KEM-768 + AES-256-GCM...
    Encrypted size: 1281 bytes
    Overhead:       1119 bytes
    Version byte:   0x01
    Encrypted (first 80 bytes, base64):
    AQRA8vPZouhhGcKMrC0T2Y6HrLDp0ms6ZGMVm4LzbtzSlHXTWbDr7DSBa...

[4] Stored on Kafka broker: opaque encrypted blob
    A quantum computer CANNOT decrypt this data.

[5] Decrypting with ML-KEM-768 decapsulation...
    Decrypted record value:
    {
      "orderId": "ORD-2024-98765",
      "customer": "Alice",
      ...
    }

    [OK] Decrypted message matches original.

DEMO 2: Hybrid Mode (ML-KEM-768 + X25519 ECDH)
────────────────────────────────────────────────────────────────────────
  Plaintext size:       60 bytes
  PQC-only ciphertext:  1179 bytes (version: 0x01)
  Hybrid ciphertext:    1211 bytes (version: 0x02)
  Hybrid overhead:      +32 bytes (X25519 ephemeral public key)

DEMO 3: ML-KEM Parameter Sets Comparison (FIPS 203)
────────────────────────────────────────────────────────────────────────

  Algorithm       Security    PubKey       PrivKey       Ciphertext
  ──────────────  ──────────  ───────────  ────────────  ──────────────
  ML-KEM-512      128-bit        822 B       1,730 B         854 B
  ML-KEM-768      192-bit      1,206 B       2,498 B       1,174 B
  ML-KEM-1024     256-bit      1,590 B       3,266 B       1,654 B

DEMO 4: Tamper Detection (AES-GCM Authenticated Encryption)
────────────────────────────────────────────────────────────────────────
  [OK] Tampered data REJECTED: AEADBadTagException

DEMO 5: Semantic Security (IND-CCA2)
────────────────────────────────────────────────────────────────────────
  Same plaintext, three encryptions:
    [1] AQRAmDBh9s6sQ0nvmcvdg1SytFGmzJvKbhRJxIAD/aSnCmoDXfuyg77z...
    [2] AQRAvBWu0HYFqKsHajylrS9ZreqkJrw7jQ2tDlx5dfdcEGCw9grUqRHD...
    [3] AQRA4c+vdkG+JT+vXW1uknmUYkdAVP/t1HsyeKuL2jyfbHyiTPCSDjxB...

  All ciphertexts different: true

DEMO 6: Performance Benchmark
────────────────────────────────────────────────────────────────────────
  ML-KEM-768 (1000 iterations, 1KB messages):
    Encrypt: 104 ms total, 9615 msg/s, 0.10 ms/msg
    Decrypt: 98 ms total,  10204 msg/s, 0.10 ms/msg

════════════════════════════════════════════════════════════════════════
  All demos completed successfully!
════════════════════════════════════════════════════════════════════════
```

---

## Example 2: Docker Compose (Kafka + Kroxylicious + PQC Filter)

This example runs a full end-to-end setup with a real Kafka broker and
the Kroxylicious proxy configured with the PQC encryption filter.

### Architecture

```
                      ┌───────────────────────────────────────────┐
                      │              Docker Compose               │
                      │                                           │
 Producer ──:9192──>  │  Kroxylicious (:9192)  ──:29092──> Kafka  │
 (plaintext)          │    PQC filter encrypts                    │
                      │                                           │
 Consumer <──:9192──  │  Kroxylicious (:9192)  <──:29092── Kafka  │
 (plaintext)          │    PQC filter decrypts                    │
                      │                                           │
 Consumer <──:9092──  │                           Kafka (:9092)   │
 (encrypted!)         │                           (direct access) │
                      └───────────────────────────────────────────┘
```

Clients connect to **port 9192** (proxy) and see plaintext.
Direct access to **port 9092** (broker) shows encrypted binary data.

### Prerequisites

- Docker and Docker Compose
- JDK 17+
- Maven 3.8+

### Step-by-step

#### 1. Build the filter JAR

```bash
# From the project root
mvn clean package -DskipTests
```

#### 2. Generate ML-KEM key pair

```bash
mkdir -p examples/docker/config/pqc-keys

java -cp target/kroxylicious-pqc-filter-1.0.0-SNAPSHOT.jar \
  io.kroxylicious.filter.pqc.PqcKeyGeneratorCli \
  ML_KEM_768 \
  examples/docker/config/pqc-keys/
```

This creates `pqc-public.der` and `pqc-private.der` in the keys directory.

#### 3. Start the infrastructure

```bash
cd examples/docker
docker compose up -d
```

Wait for Kafka to become healthy:

```bash
docker compose logs -f kafka
# Look for: "Kafka Server started"
```

#### 4. Produce messages (encrypted by proxy)

```bash
cd examples/docker

mvn compile exec:java \
  -Dexec.mainClass=io.kroxylicious.filter.pqc.examples.PqcProducerExample
```

The producer connects to the proxy at `localhost:9192` and sends 5 sample
orders containing credit card data. The proxy **encrypts them transparently**
before storing on the broker.

Expected output:

```
=== PQC Kafka Producer Example ===
Connecting to Kroxylicious proxy at: localhost:9192
Topic: sensitive-orders

Sending 5 orders...
(The proxy will PQC-encrypt these before storing on the broker)

  [2026-03-30T...] Sent: key=order-1, partition=0, offset=0
         Plaintext: {"orderId":"ORD-001","customer":"Alice","amount":1299.99,"card":"4111...
  [2026-03-30T...] Sent: key=order-2, partition=0, offset=1
         Plaintext: {"orderId":"ORD-002","customer":"Bob","amount":599.50,"card":"5500-XX...
  ...

All messages sent successfully!
Messages are stored PQC-encrypted on the Kafka broker.
```

#### 5. Consume through the proxy (decrypted)

```bash
mvn compile exec:java \
  -Dexec.mainClass=io.kroxylicious.filter.pqc.examples.PqcConsumerExample \
  -Dexec.args="localhost:9192"
```

The consumer connects through the proxy. The filter **decrypts records
transparently** and the consumer sees original plaintext JSON:

```
=== PQC Kafka Consumer Example ===
Connecting to: localhost:9192
Mode: VIA PROXY (messages will be decrypted transparently)

Record #1 [partition=0, offset=0]
  Key:       order-1
  Value:     {"orderId":"ORD-001","customer":"Alice","amount":1299.99,...}

Record #2 [partition=0, offset=1]
  Key:       order-2
  Value:     {"orderId":"ORD-002","customer":"Bob","amount":599.50,...}
...
```

#### 6. Consume directly from broker (encrypted blobs)

```bash
mvn compile exec:java \
  -Dexec.mainClass=io.kroxylicious.filter.pqc.examples.PqcConsumerExample \
  -Dexec.args="localhost:9092"
```

This bypasses the proxy and reads encrypted records directly from the broker.
The consumer sees binary data that cannot be read:

```
=== PQC Kafka Consumer Example ===
Connecting to: localhost:9092
Mode: DIRECT TO BROKER (messages will appear encrypted)

Record #1 [partition=0, offset=0]
  Key:       order-1
  Header:    x-pqc-encrypted = true
  Value:     [ENCRYPTED BINARY DATA, 1281 chars]
             Base64: AQRA8vPZouhhGcKMrC0T2Y6HrLDp0ms6ZGMVm4LzbtzSlHXT...
...

Messages appear as encrypted blobs (not readable without the proxy).
```

This confirms that data at rest on the Kafka broker is PQC-encrypted and
unreadable without the ML-KEM private key.

#### 7. Clean up

```bash
docker compose down
```

### Docker Compose services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `kafka` | `apache/kafka:3.9.0` | 9092 (external), 29092 (internal) | Kafka broker in KRaft mode (no Zookeeper) |
| `kroxylicious` | `quay.io/kroxylicious/kroxylicious:0.19.0` | 9192 | Proxy with PQC filter |

### Proxy configuration

The proxy config is at `examples/docker/config/proxy-config.yaml`:

```yaml
filterDefinitions:
  - name: pqc-encryption
    type: PqcRecordEncryptionFilterFactory
    config:
      kemAlgorithm: ML_KEM_768
      hybridMode: false
      publicKeyPath: /opt/kroxylicious/pqc-keys/pqc-public.der
      privateKeyPath: /opt/kroxylicious/pqc-keys/pqc-private.der
      topicPatterns:
        - "sensitive-.*"

defaultFilters:
  - pqc-encryption
```

Only topics matching `sensitive-.*` are encrypted. Other topics pass through
unchanged.

The filter JAR is loaded via the `KROXYLICIOUS_CLASSPATH` environment variable
set in `docker-compose.yaml`. This tells the Kroxylicious start script to add
`/opt/kroxylicious/plugins/*` to the Java classpath so the `ServiceLoader` can
discover the `PqcRecordEncryptionFilterFactory`.

---

## Example Applications Source Code

### PqcProducerExample

Located at `examples/docker/src/main/java/.../PqcProducerExample.java`.

A standard `KafkaProducer<String, String>` that:
1. Creates the `sensitive-orders` topic if it does not exist
2. Sends 5 JSON order records with customer and payment data
3. Connects to the Kroxylicious proxy (default `localhost:9192`)

The producer has **no awareness of PQC encryption**. It sends plaintext.
The proxy handles encryption transparently.

### PqcConsumerExample

Located at `examples/docker/src/main/java/.../PqcConsumerExample.java`.

A standard `KafkaConsumer<String, String>` that:
1. Subscribes to `sensitive-orders`
2. Polls for records and prints key, value, and headers
3. Detects whether values are printable (plaintext) or binary (encrypted)

When connected via the proxy (`localhost:9192`), records appear as plaintext.
When connected directly to the broker (`localhost:9092`), records appear as
encrypted binary blobs.

### PqcStandaloneDemo

Located at `examples/standalone/src/main/java/.../PqcStandaloneDemo.java`.

A self-contained Java application that uses `PqcCryptoEngine` directly
(no Kafka, no proxy) to demonstrate:
- Key generation for all ML-KEM parameter sets
- Encrypt/decrypt roundtrips
- Hybrid vs PQC-only mode comparison
- AES-GCM tamper detection
- Semantic security (IND-CCA2)
- Performance benchmarking

---

## Troubleshooting

**`Connection refused` on port 9192**
The Kroxylicious proxy may not have started yet. Check:
```bash
docker compose logs kroxylicious
```

**`Topic 'sensitive-orders' not found`**
The producer creates the topic automatically. Run the producer before the
consumer.

**`ClassNotFoundException: PqcRecordEncryptionFilterFactory`**
The filter JAR is not on the Kroxylicious classpath. Verify the Docker
volume mount in `docker-compose.yaml` points to the built JAR.

**`Failed to initialize PQC encryption`**
The key files are missing or unreadable. Regenerate them with
`PqcKeyGeneratorCli` and verify the paths in `proxy-config.yaml`.
