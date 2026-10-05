package com.example.crypto;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Loads the key set from process environment variables.
 *
 * <p>Layout, with the default prefix {@code APP_DATA_KEY_}:
 * <pre>
 *   APP_DATA_KEY_ACTIVE_ID      = v2
 *   APP_DATA_KEY_MATERIAL_v2    = &lt;base64 of 32 random bytes&gt;
 *   APP_DATA_KEY_MATERIAL_v1    = &lt;base64 of 32 random bytes&gt;   (kept for decrypting old data)
 * </pre>
 *
 * <p>Nothing here has a default value: if the variables are absent the component
 * refuses to start rather than inventing a key. Values are validated (strict
 * Base64, exactly 256 bits, non-zero) before use, variable names must contain a
 * valid {@link KeyId}, and no value is ever logged or placed in an exception
 * message.
 *
 * <p>Residual risk, stated plainly: environment variables are visible to the
 * process owner and to root through {@code /proc/&lt;pid&gt;/environ}, and are
 * inherited by child processes. A keystore
 * ({@link KeyStoreKeySource}) or a KMS is preferable where available.
 */
public final class EnvironmentKeySource {

    /** Default variable-name prefix. */
    public static final String DEFAULT_PREFIX = "APP_DATA_KEY_";

    private static final String ACTIVE_ID_SUFFIX = "ACTIVE_ID";
    private static final String MATERIAL_INFIX = "MATERIAL_";

    private EnvironmentKeySource() {
    }

    /** Loads the key set using {@link #DEFAULT_PREFIX}. */
    public static KeySetSecretKeyProvider load() {
        return load(DEFAULT_PREFIX, System.getenv());
    }

    /** Loads the key set using a custom variable-name prefix. */
    public static KeySetSecretKeyProvider load(String prefix) {
        return load(prefix, System.getenv());
    }

    /**
     * Testable core: builds the key set from an arbitrary environment map.
     *
     * @param prefix      variable-name prefix, e.g. {@code APP_DATA_KEY_}
     * @param environment the environment to read; treated as untrusted input
     */
    static KeySetSecretKeyProvider load(String prefix, Map<String, String> environment) {
        Objects.requireNonNull(prefix, "prefix");
        Objects.requireNonNull(environment, "environment");
        if (prefix.isEmpty() || prefix.length() > 64) {
            throw new IllegalArgumentException("prefix must be 1-64 characters");
        }

        String activeKeyId = environment.get(prefix + ACTIVE_ID_SUFFIX);
        if (activeKeyId == null) {
            CryptoLog.configProblem("missing environment variable " + prefix + ACTIVE_ID_SUFFIX);
            throw new IllegalStateException("encryption key configuration is incomplete");
        }
        KeyId.require(activeKeyId);

        String materialPrefix = prefix + MATERIAL_INFIX;
        Map<String, ZeroizableSecretKey> keys = new LinkedHashMap<>();
        try {
            for (Map.Entry<String, String> variable : environment.entrySet()) {
                String name = variable.getKey();
                if (name == null || !name.startsWith(materialPrefix)) {
                    continue;
                }
                String keyId = KeyId.require(name.substring(materialPrefix.length()));
                if (keys.size() >= KeySetSecretKeyProvider.MAX_KEYS) {
                    throw new IllegalStateException(
                            "more than " + KeySetSecretKeyProvider.MAX_KEYS + " keys configured");
                }
                char[] encoded = toCharArray(variable.getValue());
                try {
                    keys.put(keyId, KeyMaterial.fromBase64(encoded));
                } finally {
                    // Wipe our copy. The String inside the environment map is
                    // owned by the JVM and cannot be wiped - see the class note.
                    Bytes.wipe(encoded);
                }
            }
            if (!keys.containsKey(activeKeyId)) {
                CryptoLog.configProblem(
                        "no key material configured for the active key id (" + materialPrefix + "<id>)");
                throw new IllegalStateException("encryption key configuration is incomplete");
            }
            return new KeySetSecretKeyProvider(keys, activeKeyId);
        } catch (RuntimeException e) {
            // Do not leave half-loaded key material behind on a failed start-up.
            keys.values().forEach(ZeroizableSecretKey::destroy);
            throw e;
        }
    }

    private static char[] toCharArray(String value) {
        if (value == null) {
            throw new IllegalArgumentException("configured key material is malformed");
        }
        return value.toCharArray();
    }
}
