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
package io.kroxylicious.filter.pqc.crypto;

import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig;
import io.kroxylicious.filter.pqc.config.PqcEncryptionConfig.KemAlgorithm;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.List;

/**
 * Service Provider Interface for pluggable key storage backends.
 *
 * <p>Implementations provide ML-KEM key material from different storage
 * systems (filesystem, HashiCorp Vault, AWS KMS, etc.). The default
 * implementation is {@link FileSystemKeyProvider}.
 *
 * <p>Implementations are discovered via {@link java.util.ServiceLoader}
 * and selected by matching the {@link #type()} identifier against the
 * {@code keyProviderType} field in the filter configuration.
 *
 * @see FileSystemKeyProvider
 */
public interface KeyProvider {

    /**
     * Return the type identifier for this provider.
     * This value is matched against the {@code keyProviderType} configuration
     * property to select which provider to use.
     *
     * @return a non-null type string (e.g., {@code "filesystem"}, {@code "vault"})
     */
    String type();

    /**
     * Configure this provider with the filter's configuration.
     * Called once at startup before any key operations.
     *
     * @param config the filter configuration
     * @throws GeneralSecurityException if key material cannot be loaded or generated
     * @throws IOException if an I/O error occurs accessing key storage
     */
    void configure(PqcEncryptionConfig config) throws GeneralSecurityException, IOException;

    /**
     * Load or fetch the active key pair for encryption.
     *
     * @param algorithm the ML-KEM algorithm variant to use
     * @return the active key pair
     * @throws GeneralSecurityException if the key pair cannot be loaded
     */
    KeyPair getActiveKeyPair(KemAlgorithm algorithm) throws GeneralSecurityException;

    /**
     * Load or fetch a key pair by ID for decryption.
     * This supports key rotation: old records encrypted with a previous key
     * can be decrypted by looking up the key ID from the encrypted envelope.
     *
     * @param keyId the key identifier
     * @param algorithm the ML-KEM algorithm variant
     * @return the key pair for the given ID
     * @throws GeneralSecurityException if the key pair cannot be found or loaded
     */
    KeyPair getKeyPairById(String keyId, KemAlgorithm algorithm) throws GeneralSecurityException;

    /**
     * List all available key IDs managed by this provider.
     *
     * @return an unmodifiable list of key IDs
     */
    List<String> listKeyIds();

    /**
     * Release any resources held by this provider.
     * Called when the filter is shut down.
     */
    default void close() {
    }
}
