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

import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig.KemAlgorithm;
import io.kroxylicious.filter.pqc.crypto.PqcCryptoEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

/**
 * CLI utility to generate ML-KEM key pairs for the PQC encryption filter.
 *
 * <p>This class is self-contained and does not depend on SLF4J, so it can
 * be run directly from the shaded JAR without a logging implementation.
 *
 * <p>Usage:
 * <pre>
 * java -cp kroxylicious-pqc-filter.jar \
 *   io.kroxylicious.filter.pqc.PqcKeyGeneratorCli \
 *   [ML_KEM_512|ML_KEM_768|ML_KEM_1024] \
 *   &lt;output-directory&gt;
 * </pre>
 *
 * <p>Generates two files:
 * <ul>
 *   <li>{@code pqc-public.der} - ML-KEM public key (X.509 DER encoded)</li>
 *   <li>{@code pqc-private.der} - ML-KEM private key (PKCS#8 DER encoded)</li>
 * </ul>
 */
public class PqcKeyGeneratorCli {

    public static void main(String[] args) throws Exception {
        KemAlgorithm algorithm = KemAlgorithm.ML_KEM_768;
        String outputDir = ".";

        if (args.length >= 1) {
            algorithm = KemAlgorithm.valueOf(args[0]);
        }
        if (args.length >= 2) {
            outputDir = args[1];
        }

        // Register Bouncy Castle providers directly (no SLF4J dependency)
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        System.out.println("Generating " + algorithm.getDisplayName() + " key pair...");

        KyberParameterSpec paramSpec = switch (algorithm) {
            case ML_KEM_512 -> KyberParameterSpec.kyber512;
            case ML_KEM_768 -> KyberParameterSpec.kyber768;
            case ML_KEM_1024 -> KyberParameterSpec.kyber1024;
        };

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(paramSpec, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();

        Path pubKeyPath = Path.of(outputDir, "pqc-public.der");
        Path privKeyPath = Path.of(outputDir, "pqc-private.der");

        Files.createDirectories(pubKeyPath.getParent());
        Files.write(pubKeyPath, keyPair.getPublic().getEncoded());
        Files.createDirectories(privKeyPath.getParent());
        Files.write(privKeyPath, keyPair.getPrivate().getEncoded());

        System.out.println("Public key:  " + pubKeyPath.toAbsolutePath());
        System.out.println("  Size:      " + keyPair.getPublic().getEncoded().length + " bytes");
        System.out.println("  Format:    " + keyPair.getPublic().getFormat());
        System.out.println("Private key: " + privKeyPath.toAbsolutePath());
        System.out.println("  Size:      " + keyPair.getPrivate().getEncoded().length + " bytes");
        System.out.println("  Format:    " + keyPair.getPrivate().getFormat());
        System.out.println("\nDone. Add these paths to your Kroxylicious proxy configuration.");
    }
}
