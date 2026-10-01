package com.example.crypto;

import javax.crypto.SecretKey;
import java.util.Set;

/**
 * Supplies the symmetric keys used by {@link AesGcmDataCipher}.
 *
 * <p>This is the component's trust boundary for key material. Implementations
 * load keys from somewhere outside the code - environment, a root-owned file, an
 * OS/HSM-backed keystore, a KMS - and must never embed a usable default. The
 * interface supports multiple keys at once so that key rotation can happen
 * without a flag day: new data is encrypted under {@link #activeKeyId()} while
 * older data stays decryptable under its own id.
 *
 * <p>Implementations must be safe for concurrent use.
 */
public interface SecretKeyProvider extends AutoCloseable {

    /**
     * @return the id of the key new ciphertext must be encrypted under; never
     *         {@code null} and always a valid key id
     */
    String activeKeyId();

    /**
     * Looks up a key by id.
     *
     * <p>Called with attacker-controlled input on the decryption path, so
     * implementations must treat {@code keyId} as untrusted, must not create or
     * derive a key on demand, and must fail closed for anything unknown.
     *
     * @param keyId candidate key id, never {@code null}
     * @return the key, or {@code null} if no such key is configured
     */
    SecretKey keyFor(String keyId);

    /** @return the configured key ids; useful for start-up self-checks only. */
    Set<String> keyIds();

    /** Destroys all key material held in memory. Idempotent. */
    @Override
    void close();
}
