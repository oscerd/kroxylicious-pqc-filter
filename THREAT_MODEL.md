# Threat Model

This document describes the security posture of the Kroxylicious PQC Record
Encryption Filter: what it defends against, what it does not, and the trust
assumptions it makes.

## What This Filter Does

The filter encrypts Kafka **record values** at the Kroxylicious proxy layer
before they reach the broker. Each record is encrypted with a fresh AES-256-GCM
key derived from an ML-KEM encapsulation (and optionally an X25519 ECDH
agreement in hybrid mode). The encrypted envelope replaces the original record
value on the broker.

```
Producer ──plaintext──> Kroxylicious ──encrypted──> Kafka Broker (encrypted at rest)
Consumer <──plaintext── Kroxylicious <──encrypted── Kafka Broker
```

## Threats Defended Against

### 1. Unauthorized access to data at rest on the broker

If an attacker gains read access to broker storage (disk, snapshots, backups,
log segments), they see only encrypted blobs. Without the ML-KEM private key,
the data is unrecoverable.

**Examples:** compromised broker host, stolen disk, leaked backup, insider
with broker-level access but no proxy access.

### 2. Unauthorized consumers bypassing the proxy

A consumer connecting directly to the broker (bypassing Kroxylicious) receives
encrypted binary data that cannot be decrypted without the private key.

### 3. Future quantum attacks on the key encapsulation

ML-KEM (FIPS 203) is designed to resist attacks from cryptographically relevant
quantum computers. An adversary who records the encrypted envelopes today cannot
use a future quantum computer to recover the per-record AES keys from the ML-KEM
encapsulations.

This is the core value proposition of using ML-KEM instead of a classical KEM
(e.g., RSA or ECDH): the key encapsulation step is quantum-resistant.

### 4. Tampered records

AES-256-GCM is authenticated encryption. Any modification to the ciphertext,
IV, or encapsulation is detected and rejected at decryption time
(`AEADBadTagException`).

## Threats NOT Defended Against

### 1. Harvest-now-decrypt-later on TLS traffic

This filter does **not** protect the TLS channel between producers/consumers
and the proxy, or between the proxy and the broker. If an adversary records
network traffic (the "harvest" step), the encrypted payloads they capture are
the **TLS ciphertext**, not the PQC envelopes.

The TLS channel uses classical key exchange (typically ECDHE). A future quantum
computer could break the TLS key exchange and recover the plaintext that was
sent over TLS -- including the original unencrypted record values on the
producer-to-proxy leg.

**Mitigation:** Use PQC-capable TLS (e.g., ML-KEM in TLS 1.3) on all network
hops. This is outside the scope of this filter.

### 2. Proxy host compromise

The Kroxylicious proxy holds **both the public and private ML-KEM keys** (and
X25519 keys in hybrid mode). An attacker who compromises the proxy host can:

- Read all plaintext flowing through the proxy in real time
- Extract the private key and decrypt any stored records
- Impersonate the proxy to producers and consumers

**Mitigation:** Harden the proxy host. Use Vault with short-lived tokens and
restrictive policies. In a future split architecture (see below), the private
key would not reside on the encryption proxy at all.

### 3. Record headers and metadata

Only record **values** are encrypted. Record keys, headers, topic names,
partition assignments, offsets, and timestamps remain in plaintext on the
broker. Do not put sensitive data in headers or record keys.

### 4. Tombstones

Records with `null` values (Kafka tombstones used for log compaction) are
passed through unencrypted, as there is no payload to encrypt.

### 5. Side-channel attacks

The filter does not defend against timing attacks, power analysis, or other
side-channel attacks on the proxy host. The Bouncy Castle ML-KEM implementation
is a software implementation without specific side-channel hardening.

### 6. Key compromise

If the ML-KEM private key is leaked, all records encrypted with that key can
be decrypted. The Vault key provider supports key versioning (rotation), but
records encrypted with a compromised key version remain vulnerable.

## Trust Boundaries

```
                    TRUSTED                           UNTRUSTED
  ┌───────────────────────────────────────┐
  │                                       │
  │  Producer ──plaintext──> Kroxylicious  │──encrypted──> Kafka Broker
  │  Consumer <──plaintext── Kroxylicious  │<──encrypted── Kafka Broker
  │                                       │
  │  Vault (key storage)                  │
  └───────────────────────────────────────┘
```

**Trusted zone:** The proxy, the producer/consumer applications, and the key
store (Vault or filesystem). These components see plaintext and/or hold key
material.

**Untrusted zone:** The Kafka broker, its storage, and the network between the
proxy and the broker. These components only see encrypted data.

**Key assumption:** The proxy host is not compromised. If it is, all security
guarantees are void because the proxy holds both keys and processes plaintext.

## Why ML-KEM Adds Value Beyond AES-256

AES-256 is already considered quantum-resistant for symmetric encryption
(Grover's algorithm provides at most a square-root speedup, reducing effective
security from 256-bit to ~128-bit equivalent, which remains infeasible).

However, the AES key must be **established** somehow. In a classical system,
key establishment uses RSA or ECDH, which are vulnerable to quantum attacks.
ML-KEM provides quantum-resistant key encapsulation: even if a quantum computer
exists, it cannot recover the per-record AES key from the ML-KEM encapsulation
stored in the envelope.

Without ML-KEM, you would need to pre-share or statically configure AES keys,
losing per-record key freshness and forward secrecy.

## Hybrid Mode Rationale

Hybrid mode (`hybridMode: true`) combines ML-KEM + X25519 ECDH. The AES key
is derived from **both** shared secrets. An attacker must break **both**
algorithms to recover the AES key:

| Scenario | PQC-only | Hybrid |
|----------|----------|--------|
| ML-KEM broken (classical flaw) | Compromised | Protected (X25519 still holds) |
| X25519 broken (quantum attack) | Protected | Protected (ML-KEM still holds) |
| Both broken | Compromised | Compromised |

This is a defense-in-depth strategy recommended by NIST, BSI, and ANSSI during
the transition period while post-quantum algorithms gain confidence.

## Future: Split Architecture

The current architecture requires the proxy to hold both keys because it
performs both encryption (on Produce) and decryption (on Fetch). A more secure
architecture would split these roles:

```
Producer ──> Encryption Proxy (public key only) ──> Broker
Consumer <── Decryption Service (private key)   <── Broker
```

In this model:
- The encryption proxy only holds the ML-KEM **public key** and can only encrypt
- The decryption service holds the **private key** and runs in a hardened
  environment (HSM, TEE, or separate security zone)
- Compromising the encryption proxy does not expose the private key or
  previously encrypted data

This is not implemented today but is a natural evolution of the architecture.
