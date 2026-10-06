package app;

import java.util.Arrays;

/**
 * A secret (user password, database password, session token) held in a {@code char[]}
 * so the holder can erase it, with a {@code toString()} that cannot leak it.
 *
 * <p>Callers must not copy the array returned by {@link #chars()} into a {@link String}:
 * Strings are interned in the heap and cannot be zeroed. The one unavoidable exception is
 * the JDBC {@code Properties} hand-off in {@link Config}, which is documented there.
 */
public final class Secrets implements AutoCloseable {

    private char[] value;

    private Secrets(char[] value) {
        this.value = value;
    }

    /** Takes ownership of {@code value} by copying it and erasing the caller's array. */
    public static Secrets ofCharArray(char[] value) {
        char[] copy = value.clone();
        Arrays.fill(value, '\0');
        return new Secrets(copy);
    }

    public static Secrets ofString(String value) {
        return new Secrets(value == null ? null : value.toCharArray());
    }

    /** The live characters. Valid only until {@link #close()}; do not retain. */
    public char[] chars() {
        return value;
    }

    public int length() {
        return value == null ? 0 : value.length;
    }

    public boolean isBlank() {
        if (value == null || value.length == 0) {
            return true;
        }
        for (char c : value) {
            if (!Character.isWhitespace(c) && c != '\0') {
                return false;
            }
        }
        return true;
    }

    /** Overwrites the secret in place. Idempotent. */
    @Override
    public void close() {
        if (value != null) {
            Arrays.fill(value, '\0');
            value = null;
        }
    }

    @Override
    public String toString() {
        return "Secrets[redacted]";
    }

    @Override
    public boolean equals(Object other) {
        return this == other;
    }

    @Override
    public int hashCode() {
        return Secrets.class.getName().hashCode();
    }
}
