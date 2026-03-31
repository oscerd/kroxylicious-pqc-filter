# Kroxylicious PQC Record Encryption Filter

A [Kroxylicious](https://kroxylicious.io/) filter plugin that provides transparent
**Post-Quantum Cryptography (PQC)** record-level encryption for Apache Kafka using
**ML-KEM** (FIPS 203) key encapsulation with **AES-256-GCM** symmetric encryption.

Kafka producers and consumers require **zero code changes**. The Kroxylicious proxy
intercepts traffic and encrypts on Produce / decrypts on Fetch automatically.

```
Producer ──plaintext──> Kroxylicious ──encrypted──> Kafka Broker
Consumer <──plaintext── Kroxylicious <──encrypted── Kafka Broker
```

## Why PQC for Kafka?

Quantum computers threaten today's public-key cryptography. An adversary can
**harvest encrypted Kafka traffic now** and decrypt it later once a
cryptographically relevant quantum computer exists ("harvest now, decrypt later").

This plugin protects Kafka record values with NIST-standardized post-quantum
algorithms so that data at rest on the broker is resistant to both classical
and quantum attacks.

| Standard | Algorithm | Purpose in this plugin |
|----------|-----------|------------------------|
| FIPS 203 | ML-KEM (Kyber) | Key encapsulation - securely establishes a per-message AES key |
| N/A | AES-256-GCM | Symmetric authenticated encryption of the record payload |
| N/A | X25519 ECDH | Classical key agreement for hybrid mode defense-in-depth |

## Features

- **Transparent encryption/decryption** - no client-side changes required
- **ML-KEM-512, ML-KEM-768 (default), ML-KEM-1024** parameter sets
- **Hybrid mode** (default) - combines ML-KEM + X25519 ECDH so both must be broken
- **Per-record encryption** - each record gets a fresh KEM encapsulation + random IV
- **Topic filtering** - regex patterns select which topics to encrypt
- **Tamper detection** - AES-GCM authenticated encryption rejects modified ciphertext
- **Semantic security** - identical plaintexts produce different ciphertexts (IND-CCA2)
- **Key auto-generation** - generates and saves ML-KEM keys on first startup if absent
- **`x-pqc-encrypted` header** - marks encrypted records for downstream awareness

## Prerequisites

| Requirement | Version |
|-------------|---------|
| JDK | 17+ (21+ recommended) |
| Maven | 3.8+ |
| Kroxylicious | 0.19.0 |
| Apache Kafka | 3.9.x |

## Quick Start

### 1. Build the plugin

```bash
git clone <this-repo>
cd kroxylicious-pqc-filter
mvn clean package -DskipTests
```

The shaded JAR at `target/kroxylicious-pqc-filter-1.0.0-SNAPSHOT.jar` bundles
Bouncy Castle so it can be dropped into Kroxylicious with no extra dependencies.

### 2. Generate ML-KEM keys

```bash
java -cp target/kroxylicious-pqc-filter-1.0.0-SNAPSHOT.jar \
  io.kroxylicious.filter.pqc.PqcKeyGeneratorCli \
  ML_KEM_768 \
  /etc/kroxylicious/pqc/
```

Output:

```
Generating ML-KEM-768 key pair...
Public key:  /etc/kroxylicious/pqc/pqc-public.der
  Size:      1206 bytes
  Format:    X.509
Private key: /etc/kroxylicious/pqc/pqc-private.der
  Size:      2498 bytes
  Format:    PKCS#8
```

Alternatively, omit the key paths in configuration and the filter will generate
keys automatically on first startup.

### 3. Configure Kroxylicious

Add the filter to your Kroxylicious proxy YAML configuration:

```yaml
filterDefinitions:
  - name: pqc-encryption
    type: PqcRecordEncryptionFilterFactory
    config:
      kemAlgorithm: ML_KEM_768
      hybridMode: true
      publicKeyPath: /etc/kroxylicious/pqc/pqc-public.der
      privateKeyPath: /etc/kroxylicious/pqc/pqc-private.der
      topicPatterns:
        - "sensitive-.*"
        - "pii-.*"

defaultFilters:
  - pqc-encryption
```

### 4. Deploy

Place the JAR in a directory accessible to Kroxylicious and add it to the
classpath via the `KROXYLICIOUS_CLASSPATH` environment variable:

```bash
export KROXYLICIOUS_CLASSPATH="/opt/kroxylicious/plugins/*"
```

When using Docker, set it in your container environment:

```yaml
environment:
  KROXYLICIOUS_CLASSPATH: /opt/kroxylicious/plugins/*
```

Then start the proxy. Producers and consumers connect to the proxy port
instead of the broker directly.

## Configuration Reference

| Property | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `kemAlgorithm` | enum | No | `ML_KEM_768` | ML-KEM parameter set. One of `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024`. |
| `hybridMode` | boolean | No | `true` | Combine ML-KEM with X25519 ECDH for defense-in-depth. |
| `publicKeyPath` | string | **Yes** | - | Filesystem path to the ML-KEM public key (X.509 DER encoded). |
| `privateKeyPath` | string | **Yes** | - | Filesystem path to the ML-KEM private key (PKCS#8 DER encoded). |
| `topicPatterns` | list\<string\> | No | `[".*"]` | Java regex patterns. Only records in matching topics are encrypted/decrypted. |

### ML-KEM Parameter Sets

| Algorithm | Security Level | Public Key | Private Key | Ciphertext Overhead | Use Case |
|-----------|---------------|------------|-------------|--------------------:|----------|
| ML-KEM-512 | 128-bit | 822 B | 1,730 B | ~854 B | Lightweight, IoT |
| ML-KEM-768 | 192-bit | 1,206 B | 2,498 B | ~1,174 B | **Recommended default** |
| ML-KEM-1024 | 256-bit | 1,590 B | 3,266 B | ~1,654 B | Classified / long-lived data |

### Encryption Modes

**PQC-only** (`hybridMode: false`):
Uses ML-KEM exclusively. The AES-256 key is derived from the ML-KEM shared secret
via `SHA-256(0x01 || "kroxylicious-pqc-v1" || secret)`.

**Hybrid** (`hybridMode: true`, default):
Combines ML-KEM + X25519. The AES-256 key is derived from both secrets via
`SHA-256(0x02 || "kroxylicious-pqc-hybrid-v1" || pqcSecret || x25519Secret)`.
This ensures security even if one algorithm is broken.

## Encrypted Envelope Format

Every encrypted record value is replaced with a binary envelope:

```
PQC-only (version 0x01):
+--------+-----------+--------------------+--------+---------------------------+
| 1 byte | 2 bytes   | N bytes            | 12 B   | remaining                 |
| 0x01   | encap len | ML-KEM encapsulat. | AES IV | AES-GCM ciphertext + tag  |
+--------+-----------+--------------------+--------+---------------------------+

Hybrid (version 0x02):
+--------+-----------+--------------------+---------+--------+-----------------+
| 1 byte | 2 bytes   | N bytes            | 32 B    | 12 B   | remaining       |
| 0x02   | encap len | ML-KEM encapsulat. | X25519  | AES IV | AES-GCM ct+tag |
|        |           |                    | eph pub |        |                 |
+--------+-----------+--------------------+---------+--------+-----------------+
```

The version byte allows the decryptor to determine the mode without configuration.

## Architecture

### Module Structure

```
kroxylicious-pqc-filter/
  src/main/java/io/kroxylicious/filter/pqc/
    PqcRecordEncryptionFilterFactory.java   # FilterFactory entry point (@Plugin)
    PqcRecordEncryptionFilter.java          # ProduceRequestFilter + FetchResponseFilter
    PqcKeyGeneratorCli.java                 # CLI key generation utility
    config/
      PqcEncryptionConfig.java              # Jackson-deserialized configuration POJO
    crypto/
      PqcCryptoEngine.java                  # ML-KEM encapsulation + AES-256-GCM
      PqcKeyManager.java                    # Key loading, generation, persistence
  src/main/resources/
    META-INF/services/
      io.kroxylicious.proxy.filter.FilterFactory   # ServiceLoader registration
  src/test/java/...                                # Unit tests (22 tests)
  examples/
    standalone/                             # Runs without Kafka (crypto engine demo)
    docker/                                 # Docker Compose: Kafka + Kroxylicious + filter
```

### Filter Lifecycle

```
Startup:
  FilterFactory.initialize()
    -> PqcKeyManager loads/generates ML-KEM key pair
    -> PqcCryptoEngine created with key pair
    -> Topic patterns compiled
    -> SharedPqcContext returned

Per connection:
  FilterFactory.createFilter()
    -> New PqcRecordEncryptionFilter instance
    -> Shares the same PqcCryptoEngine (thread-safe)

Produce request:
  onProduceRequest()
    -> For each topic matching topicPatterns:
      -> For each partition:
        -> For each record:
          -> ML-KEM encapsulate (fresh shared secret + encapsulation)
          -> Derive AES-256 key from shared secret
          -> AES-GCM encrypt the record value
          -> Replace value with encrypted envelope
          -> Add x-pqc-encrypted header
    -> Forward to broker

Fetch response:
  onFetchResponse()
    -> For each topic matching topicPatterns:
      -> For each partition:
        -> For each record with x-pqc-encrypted header:
          -> Read version + encapsulation from envelope
          -> ML-KEM decapsulate (recover shared secret)
          -> Derive AES-256 key
          -> AES-GCM decrypt
          -> Replace value with plaintext
          -> Remove x-pqc-encrypted header
    -> Forward to client
```

### Key Classes

**`PqcRecordEncryptionFilterFactory`** implements `FilterFactory<PqcEncryptionConfig, SharedPqcContext>`.
Annotated with `@Plugin(configType = PqcEncryptionConfig.class)`.
Registered via `META-INF/services/io.kroxylicious.proxy.filter.FilterFactory`.
Called once on startup (`initialize`) and once per client connection (`createFilter`).

**`PqcRecordEncryptionFilter`** implements `ProduceRequestFilter` and `FetchResponseFilter`.
Intercepts `onProduceRequest` to encrypt and `onFetchResponse` to decrypt.
One instance per connection; no synchronization needed (Kroxylicious thread model).

**`PqcCryptoEngine`** performs all cryptographic operations.
Stateless except for key material and `SecureRandom`.
`encrypt()` returns a self-describing envelope; `decrypt()` parses it.
Registers Bouncy Castle providers (`BC`, `BCPQC`) in a static initializer.

**`PqcKeyManager`** loads DER-encoded keys from disk.
If key files do not exist, generates a fresh ML-KEM key pair and saves them.

**`PqcEncryptionConfig`** is a Jackson-annotated POJO.
Deserialized from the `config:` block in the Kroxylicious proxy YAML.
All fields except `publicKeyPath` and `privateKeyPath` have defaults.

## Building and Testing

```bash
# Compile
mvn compile

# Run unit tests (22 tests)
mvn test

# Package (creates shaded JAR with Bouncy Castle bundled)
mvn package

# Install to local Maven repository
mvn install
```

### Test Coverage

| Test Class | Tests | What is verified |
|------------|------:|------------------|
| `PqcCryptoEngineTest` | 12 | Encrypt/decrypt roundtrip for all 3 ML-KEM variants, null handling, empty and 1MB payloads, semantic security, tamper detection, invalid version rejection, key generation, envelope version bytes |
| `PqcEncryptionConfigTest` | 7 | Default values, explicit values, null rejection, JSON deserialization, immutability, enum properties |
| `PqcKeyManagerTest` | 3 | Key auto-generation, loading existing keys, engine creation from key manager |

## Dependencies

### Runtime

| Dependency | Version | Scope | Purpose |
|------------|---------|-------|---------|
| `io.kroxylicious:kroxylicious-api` | 0.19.0 | provided | Filter API interfaces |
| `org.apache.kafka:kafka-clients` | 3.9.0 | provided | Kafka protocol message types |
| `com.fasterxml.jackson.core:jackson-annotations` | 2.18.3 | provided | Configuration binding |
| `org.bouncycastle:bcprov-jdk18on` | 1.83 | compile | ML-KEM, AES-GCM, X25519 (bundled in shaded JAR) |
| `org.bouncycastle:bcutil-jdk18on` | 1.83 | compile | Bouncy Castle utilities (bundled in shaded JAR) |
| `org.slf4j:slf4j-api` | 2.0.17 | provided | Logging |

### Test

JUnit 5.11.4, Mockito 5.15.2, AssertJ 3.27.3, Jackson Databind 2.18.3.

## Performance

Measured on the standalone demo (JVM warm, 1,000 iterations, 1 KB messages):

| Algorithm | Encrypt | Decrypt |
|-----------|--------:|--------:|
| ML-KEM-512 | ~7,700 msg/s (0.13 ms/msg) | ~7,800 msg/s (0.13 ms/msg) |
| ML-KEM-768 | ~9,600 msg/s (0.10 ms/msg) | ~10,200 msg/s (0.10 ms/msg) |
| ML-KEM-1024 | ~8,500 msg/s (0.12 ms/msg) | ~6,900 msg/s (0.14 ms/msg) |

The per-message overhead is sub-millisecond. For typical Kafka workloads
(messages in the KB-MB range), the encryption cost is negligible compared
to network and disk I/O.

## Security Considerations

- **Key protection**: The private key file must be readable only by the
  Kroxylicious process. Use filesystem permissions (`chmod 600`) and
  consider mounting from a secrets manager or HSM.
- **Key rotation**: Generate a new key pair periodically. The version byte
  in the envelope allows future support for key ID headers.
- **Tombstones**: Records with `null` values (Kafka tombstones) are passed
  through unencrypted.
- **Headers**: Record headers are **not** encrypted, only values.
  Do not put sensitive data in headers.
- **Compression**: The filter writes encrypted batches with `Compression.NONE`
  because encrypted data does not compress well.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
