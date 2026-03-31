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

import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig;
import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig.KemAlgorithm;
import io.kroxylicious.filter.pqc.crypto.PqcCryptoEngine;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Standalone demonstration of the PQC encryption engine.
 *
 * This example runs without Kafka or Kroxylicious — it shows how the
 * ML-KEM + AES-256-GCM crypto engine encrypts and decrypts message
 * payloads, simulating what the Kroxylicious filter does transparently
 * on the wire.
 *
 * Run with:
 *   cd examples/standalone
 *   mvn compile exec:java
 */
public class PqcStandaloneDemo {

    private static final String SEPARATOR = "═".repeat(72);
    private static final String THIN_SEP = "─".repeat(72);

    public static void main(String[] args) throws Exception {
        System.out.println();
        System.out.println(SEPARATOR);
        System.out.println("  Kroxylicious PQC Record Encryption - Standalone Demo");
        System.out.println("  Post-Quantum Cryptography for Apache Kafka");
        System.out.println(SEPARATOR);
        System.out.println();

        // ── Demo 1: PQC-Only Mode (ML-KEM-768) ──────────────────────────
        demoPqcOnly();

        // ── Demo 2: Hybrid Mode (ML-KEM-768 + X25519) ───────────────────
        demoHybrid();

        // ── Demo 3: All ML-KEM parameter sets ───────────────────────────
        demoAllAlgorithms();

        // ── Demo 4: Tamper detection ────────────────────────────────────
        demoTamperDetection();

        // ── Demo 5: Semantic security ───────────────────────────────────
        demoSemanticSecurity();

        // ── Demo 6: Performance benchmark ───────────────────────────────
        demoBenchmark();

        System.out.println();
        System.out.println(SEPARATOR);
        System.out.println("  All demos completed successfully!");
        System.out.println(SEPARATOR);
        System.out.println();
    }

    /**
     * Demo 1: Basic PQC-only encryption using ML-KEM-768.
     */
    private static void demoPqcOnly() throws Exception {
        System.out.println("DEMO 1: PQC-Only Mode (ML-KEM-768 + AES-256-GCM)");
        System.out.println(THIN_SEP);

        // Step 1: Generate ML-KEM key pair
        System.out.println("[1] Generating ML-KEM-768 key pair...");
        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        System.out.println("    Public key size:  " + keyPair.getPublic().getEncoded().length + " bytes");
        System.out.println("    Private key size: " + keyPair.getPrivate().getEncoded().length + " bytes");
        System.out.println();

        // Step 2: Create crypto engine
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false,
                keyPair.getPublic(), keyPair.getPrivate());

        // Step 3: Simulate a Kafka message
        String originalMessage = """
                {
                  "orderId": "ORD-2024-98765",
                  "customer": "Alice",
                  "amount": 1299.99,
                  "currency": "EUR",
                  "creditCard": "4111-XXXX-XXXX-1234",
                  "status": "confirmed"
                }""";

        System.out.println("[2] Original Kafka record value (plaintext):");
        System.out.println(indent(originalMessage));
        System.out.println("    Size: " + originalMessage.getBytes().length + " bytes");
        System.out.println();

        // Step 4: Encrypt (what happens on Produce)
        System.out.println("[3] Encrypting with ML-KEM-768 + AES-256-GCM...");
        byte[] encrypted = engine.encrypt(originalMessage.getBytes(StandardCharsets.UTF_8));
        System.out.println("    Encrypted size: " + encrypted.length + " bytes");
        System.out.println("    Overhead:       " + (encrypted.length - originalMessage.getBytes().length) + " bytes");
        System.out.println("    Version byte:   0x" + HexFormat.of().toHexDigits(encrypted[0]));
        System.out.println("    Encrypted (first 80 bytes, base64):");
        System.out.println("    " + Base64.getEncoder().encodeToString(encrypted).substring(0, 80) + "...");
        System.out.println();

        // Step 5: What the broker stores (opaque encrypted blob)
        System.out.println("[4] Stored on Kafka broker: opaque encrypted blob");
        System.out.println("    A quantum computer CANNOT decrypt this data.");
        System.out.println();

        // Step 6: Decrypt (what happens on Fetch)
        System.out.println("[5] Decrypting with ML-KEM-768 decapsulation...");
        byte[] decrypted = engine.decrypt(encrypted);
        String recovered = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println("    Decrypted record value:");
        System.out.println(indent(recovered));
        System.out.println();

        // Verify
        assert originalMessage.equals(recovered) : "Decryption mismatch!";
        System.out.println("    [OK] Decrypted message matches original.");
        System.out.println();
    }

    /**
     * Demo 2: Hybrid mode combining ML-KEM + X25519 ECDH.
     */
    private static void demoHybrid() throws Exception {
        System.out.println("DEMO 2: Hybrid Mode (ML-KEM-768 + X25519 ECDH)");
        System.out.println(THIN_SEP);

        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);

        // PQC-only engine
        PqcCryptoEngine pqcOnly = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false,
                keyPair.getPublic(), keyPair.getPrivate());

        // Hybrid engine (ML-KEM + X25519)
        PqcCryptoEngine hybrid = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, true,
                keyPair.getPublic(), keyPair.getPrivate());

        String message = "Sensitive financial data: account=CH93-0000-0000-0000-0000-0";
        byte[] payload = message.getBytes(StandardCharsets.UTF_8);

        byte[] encPqc = pqcOnly.encrypt(payload);
        byte[] encHybrid = hybrid.encrypt(payload);

        System.out.println("  Plaintext size:       " + payload.length + " bytes");
        System.out.println("  PQC-only ciphertext:  " + encPqc.length + " bytes (version: 0x01)");
        System.out.println("  Hybrid ciphertext:    " + encHybrid.length + " bytes (version: 0x02)");
        System.out.println("  Hybrid overhead:      +" + (encHybrid.length - encPqc.length)
                + " bytes (X25519 ephemeral public key)");
        System.out.println();
        System.out.println("  Hybrid mode provides defense-in-depth:");
        System.out.println("    - Even if ML-KEM is broken, X25519 ECDH still protects the data");
        System.out.println("    - Even if X25519 is broken by quantum, ML-KEM still protects");
        System.out.println("    - Both must be compromised to break the encryption");
        System.out.println();

        // Both can decrypt their own ciphertext
        String decPqc = new String(pqcOnly.decrypt(encPqc), StandardCharsets.UTF_8);
        assert message.equals(decPqc);
        System.out.println("    [OK] PQC-only: encrypt -> decrypt roundtrip successful.");
        System.out.println();
    }

    /**
     * Demo 3: Show all ML-KEM parameter sets with key/ciphertext sizes.
     */
    private static void demoAllAlgorithms() throws Exception {
        System.out.println("DEMO 3: ML-KEM Parameter Sets Comparison (FIPS 203)");
        System.out.println(THIN_SEP);
        System.out.println();
        System.out.printf("  %-14s  %-10s  %-11s  %-12s  %-14s%n",
                "Algorithm", "Security", "PubKey", "PrivKey", "Ciphertext");
        System.out.printf("  %-14s  %-10s  %-11s  %-12s  %-14s%n",
                "─".repeat(14), "─".repeat(10), "─".repeat(11), "─".repeat(12), "─".repeat(14));

        String payload = "Test message for size comparison across ML-KEM variants";
        byte[] data = payload.getBytes(StandardCharsets.UTF_8);

        for (KemAlgorithm alg : KemAlgorithm.values()) {
            KeyPair kp = PqcCryptoEngine.generateKeyPair(alg);
            PqcCryptoEngine engine = new PqcCryptoEngine(alg, false, kp.getPublic(), kp.getPrivate());
            byte[] enc = engine.encrypt(data);
            byte[] dec = engine.decrypt(enc);
            assert payload.equals(new String(dec, StandardCharsets.UTF_8));

            String security = switch (alg) {
                case ML_KEM_512 -> "128-bit";
                case ML_KEM_768 -> "192-bit";
                case ML_KEM_1024 -> "256-bit";
            };

            System.out.printf("  %-14s  %-10s  %,6d B     %,7d B     %,7d B%n",
                    alg.getDisplayName(), security,
                    kp.getPublic().getEncoded().length,
                    kp.getPrivate().getEncoded().length,
                    enc.length);
        }

        System.out.println();
        System.out.println("  NIST recommends ML-KEM-768 as the default choice.");
        System.out.println("  ML-KEM-1024 for maximum security (classified/long-lived data).");
        System.out.println();
    }

    /**
     * Demo 4: Demonstrate AES-GCM tamper detection.
     */
    private static void demoTamperDetection() throws Exception {
        System.out.println("DEMO 4: Tamper Detection (AES-GCM Authenticated Encryption)");
        System.out.println(THIN_SEP);

        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false,
                keyPair.getPublic(), keyPair.getPrivate());

        byte[] payload = "Wire transfer: $1,000,000 to account IBAN-DE89370400".getBytes();
        byte[] encrypted = engine.encrypt(payload);

        System.out.println("  Original message encrypted successfully.");
        System.out.println("  Ciphertext size: " + encrypted.length + " bytes");
        System.out.println();

        // Tamper with the ciphertext
        byte[] tampered = encrypted.clone();
        tampered[tampered.length - 10] ^= 0xFF; // flip bits in the ciphertext

        System.out.println("  Simulating a man-in-the-middle attack...");
        System.out.println("  Tampered byte at position " + (tampered.length - 10));

        try {
            engine.decrypt(tampered);
            System.out.println("  [FAIL] Tampered data was accepted (this should not happen)!");
        }
        catch (Exception e) {
            System.out.println("  [OK] Tampered data REJECTED: " + e.getClass().getSimpleName());
            System.out.println("       AES-GCM authentication tag verification failed.");
            System.out.println("       The message integrity is protected.");
        }
        System.out.println();
    }

    /**
     * Demo 5: Show that the same plaintext produces different ciphertext.
     */
    private static void demoSemanticSecurity() throws Exception {
        System.out.println("DEMO 5: Semantic Security (IND-CCA2)");
        System.out.println(THIN_SEP);

        KeyPair keyPair = PqcCryptoEngine.generateKeyPair(KemAlgorithm.ML_KEM_768);
        PqcCryptoEngine engine = new PqcCryptoEngine(
                KemAlgorithm.ML_KEM_768, false,
                keyPair.getPublic(), keyPair.getPrivate());

        byte[] payload = "Same message encrypted multiple times".getBytes();

        byte[] enc1 = engine.encrypt(payload);
        byte[] enc2 = engine.encrypt(payload);
        byte[] enc3 = engine.encrypt(payload);

        String b64_1 = Base64.getEncoder().encodeToString(enc1).substring(0, 60);
        String b64_2 = Base64.getEncoder().encodeToString(enc2).substring(0, 60);
        String b64_3 = Base64.getEncoder().encodeToString(enc3).substring(0, 60);

        System.out.println("  Same plaintext, three encryptions:");
        System.out.println("    [1] " + b64_1 + "...");
        System.out.println("    [2] " + b64_2 + "...");
        System.out.println("    [3] " + b64_3 + "...");
        System.out.println();

        boolean allDifferent = !java.util.Arrays.equals(enc1, enc2)
                && !java.util.Arrays.equals(enc2, enc3)
                && !java.util.Arrays.equals(enc1, enc3);

        System.out.println("  All ciphertexts different: " + allDifferent);
        System.out.println("  An attacker cannot tell if two records contain the same data.");

        // All decrypt to the same plaintext
        assert new String(engine.decrypt(enc1)).equals(new String(payload));
        assert new String(engine.decrypt(enc2)).equals(new String(payload));
        assert new String(engine.decrypt(enc3)).equals(new String(payload));
        System.out.println("  All three decrypt to the same plaintext.");
        System.out.println();
    }

    /**
     * Demo 6: Simple performance benchmark.
     */
    private static void demoBenchmark() throws Exception {
        System.out.println("DEMO 6: Performance Benchmark");
        System.out.println(THIN_SEP);

        int iterations = 1000;
        byte[] payload = new byte[1024]; // 1KB messages
        java.util.Arrays.fill(payload, (byte) 'A');

        for (KemAlgorithm alg : KemAlgorithm.values()) {
            KeyPair kp = PqcCryptoEngine.generateKeyPair(alg);
            PqcCryptoEngine engine = new PqcCryptoEngine(alg, false, kp.getPublic(), kp.getPrivate());

            // Warm up
            for (int i = 0; i < 50; i++) {
                byte[] enc = engine.encrypt(payload);
                engine.decrypt(enc);
            }

            // Benchmark encrypt
            long startEnc = System.nanoTime();
            byte[][] ciphertexts = new byte[iterations][];
            for (int i = 0; i < iterations; i++) {
                ciphertexts[i] = engine.encrypt(payload);
            }
            long encTimeMs = (System.nanoTime() - startEnc) / 1_000_000;

            // Benchmark decrypt
            long startDec = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                engine.decrypt(ciphertexts[i]);
            }
            long decTimeMs = (System.nanoTime() - startDec) / 1_000_000;

            double encPerSec = (double) iterations / encTimeMs * 1000;
            double decPerSec = (double) iterations / decTimeMs * 1000;

            System.out.printf("  %s (%d iterations, 1KB messages):%n", alg.getDisplayName(), iterations);
            System.out.printf("    Encrypt: %,d ms total, %.0f msg/s, %.2f ms/msg%n",
                    encTimeMs, encPerSec, (double) encTimeMs / iterations);
            System.out.printf("    Decrypt: %,d ms total, %.0f msg/s, %.2f ms/msg%n",
                    decTimeMs, decPerSec, (double) decTimeMs / iterations);
            System.out.println();
        }
    }

    private static String indent(String text) {
        return text.lines()
                .map(line -> "    " + line)
                .reduce((a, b) -> a + "\n" + b)
                .orElse("");
    }
}
