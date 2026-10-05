package com.example.crypto;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A {@link SecretKeyProvider} over an in-memory, immutable key set.
 *
 * <p>This is the single place where key lookup happens, so the lookup rules are
 * easy to audit:
 * <ul>
 *   <li>Every id is validated by {@link KeyId} at construction time.</li>
 *   <li>The number of keys is bounded, so a configuration source cannot make us
 *       allocate without limit.</li>
 *   <li>{@link #activeKeyId()} must name a key that is actually present -
 *       otherwise construction fails, instead of the component starting up and
 *       failing on first use.</li>
 *   <li>{@link #keyFor(String)} is a pure map lookup: unknown ids return
 *       {@code null} (fail closed) and nothing is derived on demand.</li>
 * </ul>
 *
 * <p>Instances are immutable after construction and therefore thread-safe; the
 * only mutation is {@link #close()}, which destroys the key material.
 */
public final class KeySetSecretKeyProvider implements SecretKeyProvider {

    /** Upper bound on simultaneously loaded keys (active key plus rotation history). */
    public static final int MAX_KEYS = 64;

    private final Map<String, ZeroizableSecretKey> keys;
    private final String activeKeyId;

    /**
     * @param keys        id to key; copied defensively, must be 1..{@value #MAX_KEYS} entries
     * @param activeKeyId id of the key to encrypt new data with; must be a member of {@code keys}
     */
    public KeySetSecretKeyProvider(Map<String, ZeroizableSecretKey> keys, String activeKeyId) {
        Objects.requireNonNull(keys, "keys");
        KeyId.require(activeKeyId);
        if (keys.isEmpty() || keys.size() > MAX_KEYS) {
            throw new IllegalArgumentException("key set must contain 1-" + MAX_KEYS + " keys");
        }
        Map<String, ZeroizableSecretKey> copy = new LinkedHashMap<>(keys.size() * 2);
        for (Map.Entry<String, ZeroizableSecretKey> entry : keys.entrySet()) {
            String id = KeyId.require(entry.getKey());
            ZeroizableSecretKey key = Objects.requireNonNull(entry.getValue(), "key for id");
            if (key.isDestroyed()) {
                throw new IllegalArgumentException("key material has already been destroyed");
            }
            copy.put(id, key);
        }
        if (!copy.containsKey(activeKeyId)) {
            // Fail closed at start-up: an active id with no key would otherwise
            // surface as a mysterious runtime failure on the first encryption.
            throw new IllegalArgumentException("active key id is not present in the key set");
        }
        this.keys = Collections.unmodifiableMap(copy);
        this.activeKeyId = activeKeyId;
    }

    /** Convenience factory for a single-key deployment. */
    public static KeySetSecretKeyProvider of(String keyId, ZeroizableSecretKey key) {
        return new KeySetSecretKeyProvider(Map.of(KeyId.require(keyId), key), keyId);
    }

    @Override
    public String activeKeyId() {
        return activeKeyId;
    }

    @Override
    public SecretKey keyFor(String keyId) {
        // keyId arrives from the ciphertext envelope and is therefore untrusted.
        // Invalid shapes are rejected without a map lookup; unknown-but-valid
        // ids return null. Both outcomes are reported identically by the caller.
        if (!KeyId.isValid(keyId)) {
            return null;
        }
        return keys.get(keyId);
    }

    @Override
    public Set<String> keyIds() {
        return keys.keySet();
    }

    @Override
    public void close() {
        for (ZeroizableSecretKey key : keys.values()) {
            key.destroy();
        }
    }
}
