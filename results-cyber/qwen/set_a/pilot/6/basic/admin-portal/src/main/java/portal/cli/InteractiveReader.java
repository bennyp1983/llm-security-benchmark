package portal.cli;

/**
 * Input abstraction for the console so the interactive loop can be driven by a script in
 * tests. Implementations that can suppress echo should; those that cannot must say so.
 */
public interface InteractiveReader {

    /** @return the entered line, or null at end of input */
    String readLine(String prompt);

    /**
     * Reads a secret. The returned array is the caller's to erase as soon as it has been
     * hashed; implementations should hand back a fresh array each time.
     *
     * @return the characters, or a zero-length array at end of input
     */
    char[] readSecret(String prompt);

    /** True when secrets can be read without echoing to the terminal. */
    default boolean supportsSecretEntry() {
        return false;
    }
}
