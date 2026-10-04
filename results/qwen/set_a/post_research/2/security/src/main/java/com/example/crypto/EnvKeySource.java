package com.example.crypto;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Reads a key from an environment variable.
 *
 * <p>The name is validated before it is used, and its value is validated before it is turned into a
 * key. Environment contents are attacker-reachable in the common deployments: a compose file, a
 * {@code .env} in a world-readable checkout, {@code /proc/<pid>/environ} readable by the same uid or
 * by root, and anything that can inject into a parent shell. So an env-supplied key is parsed with the
 * same strict rules as a key file, {@link KeyEncoding}, and a malformed value is refused rather than
 * repaired.
 *
 * <p>Two things this class will not do:
 * <ul>
 *   <li>fall back to another source when the variable is unset - a missing key is an error, never a
 *       default;</li>
 *   <li>echo the value in any message. {@link #describe()} returns the variable's name, and the
 *       failure detail for a bad value reports only its length and shape, never its content.</li>
 * </ul>
 */
public final class EnvKeySource implements KeySource {

    /**
     * Shape of an acceptable variable name: a shell-legal identifier. Anything else cannot be a real
     * variable name, and refusing it stops a caller from passing attacker-chosen text (a name read
     * from a request body, a database row or a config file) to be looked up in the process
     * environment.
     */
    private static final Pattern NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,63}");

    private static final int MAX_VALUE_BYTES = KeyEncoding.MAX_INPUT_BYTES;

    private final String variable;

    /**
     * @param variable environment variable name, {@code [A-Za-z_][A-Za-z0-9_]{0,63}}, supplied by
     *     deployment configuration. It is treated as trusted only in the sense that it is operator
     *     input; it is still validated.
     * @throws CryptoException if the name is null, empty, over 64 characters or not an identifier
     */
    public EnvKeySource(String variable) throws CryptoException {
        if (variable == null || !NAME.matcher(variable).matches()) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "environment variable name must match [A-Za-z_][A-Za-z0-9_]{0,63}");
        }
        this.variable = variable;
    }

    @Override
    public KeyMaterial load() throws CryptoException {
        String value;
        try {
            value = System.getenv(variable);
        } catch (SecurityException e) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "environment is not readable under the current security manager", e);
        }
        if (value == null) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "environment variable " + variable + " is not set");
        }
        if (value.isEmpty()) {
            throw new CryptoException(CryptoException.CryptoFailureCode.KEY_SOURCE_UNAVAILABLE,
                    "environment variable " + variable + " is empty");
        }
        byte[] raw = value.getBytes(StandardCharsets.UTF_8);
        if (raw.length > MAX_VALUE_BYTES) {
            throw new CryptoException(CryptoException.CryptoFailureCode.TOO_LARGE,
                    "environment variable " + variable + " is larger than " + MAX_VALUE_BYTES + " bytes");
        }
        try {
            return KeyMaterial.fromBytes(KeyEncoding.decodeKeyBytes(raw));
        } catch (CryptoException e) {
            /* Prefix the source, and do not let the value survive in the detail. */
            throw new CryptoException(e.code(), variable + ": " + valueShape(raw), e);
        }
    }

    /** Length and character class only - never the value. */
    private static String valueShape(byte[] raw) {
        boolean printable = true;
        for (byte b : raw) {
            int v = b & 0xFF;
            if (v <= 0x20 || v > 0x7E) {
                printable = false;
                break;
            }
        }
        return "value is unusable (" + raw.length + " bytes, " + (printable ? "printable ascii" : "non-printable") + ")";
    }

    /** The variable name. Contains no value. */
    @Override
    public String describe() {
        return "env:" + variable;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof EnvKeySource other && variable.equals(other.variable);
    }

    @Override
    public int hashCode() {
        return variable.hashCode();
    }

    @Override
    public String toString() {
        return describe();
    }
}
