package pii;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Where the AES key comes from: the environment or a key file, never the source code.
 *
 * <p>Resolution order, first match wins:
 * <ol>
 *   <li>the variable named by {@code PII_KEY_FILE} (or {@code --key-file}) pointing at a
 *       file that holds a Base64 encoded 256 bit key,</li>
 *   <li>the variable named by {@code PII_KEY} (or {@code --key}) holding the same
 *       Base64 text inline.</li>
 * </ol>
 *
 * <p>Run {@code java pii.PiiKeygen} once to create a key file and print the matching
 * shell commands.
 */
public final class KeyProvider {

    /** Default environment variable names; overridable so tests can inject their own. */
    public static final String DEFAULT_KEY_VAR = "PII_KEY";
    public static final String DEFAULT_KEY_FILE_VAR = "PII_KEY_FILE";

    /** A 256 bit key: eight AES blocks, the strength this tool is designed around. */
    public static final int KEY_BYTES = 32;

    public static final String NOT_EMBEDDED_NOTE =
            "The key is read from the environment or a key file, never from the source code.";

    private KeyProvider() {
    }

    /**
     * Loads and validates the key.
     *
     * @param keyOverride inline Base64 key supplied on the command line, may be {@code null}
     * @param keyFileOverride path to a key file supplied on the command line, may be {@code null}
     * @return the raw AES key bytes; the caller must wipe them when finished
     * @throws GeneralSecurityException if no key is configured or the configured key is unusable
     */
    public static byte[] loadKey(String keyOverride, String keyFileOverride) throws GeneralSecurityException {
        String keyFileVarName = varName("PII_KEY_FILE_VAR", DEFAULT_KEY_FILE_VAR);
        String keyVarName = varName("PII_KEY_VAR", DEFAULT_KEY_VAR);

        String keyFile = firstNonBlank(keyFileOverride, System.getenv(keyFileVarName));
        if (keyFile != null) {
            return readKeyFile(keyFile, keyFileVarName);
        }

        String inline = firstNonBlank(keyOverride, System.getenv(keyVarName));
        if (inline != null) {
            return decodeKey(inline, "environment variable " + keyVarName + " (or --key)");
        }

        throw new GeneralSecurityException("No AES key configured. " + NOT_EMBEDDED_NOTE
                + " Set " + keyVarName + " to a Base64 " + KEY_BYTES + " byte key, set "
                + keyFileVarName + " to the path of a key file, or pass --key/--key-file."
                + " Run 'java pii.PiiKeygen' to create one.");
    }

    private static byte[] readKeyFile(String path, String varName) throws GeneralSecurityException {
        Path file = Path.of(path);
        if (!Files.isRegularFile(file)) {
            throw new GeneralSecurityException("Key file from " + varName + " does not exist or is not a regular file: " + path);
        }
        byte[] raw;
        try {
            raw = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new GeneralSecurityException("Cannot read key file " + path + ": " + e.getMessage(), e);
        }
        try {
            return decodeKey(new String(raw, StandardCharsets.UTF_8), "key file " + path);
        } finally {
            java.util.Arrays.fill(raw, (byte) 0);
        }
    }

    /**
     * Decodes Base64 key material with the strict decoder and checks the length.
     *
     * <p>The strict decoder is deliberate: {@code Base64.getMimeDecoder()} silently throws
     * away any character outside the alphabet, so {@code "not-a-key!"} would decode without
     * error into a short, weak key. Whitespace is stripped here rather than tolerated by a
     * lenient decoder, so nothing else can hide in the value.
     *
     * @param text Base64 text, possibly wrapped over several lines
     * @param source human readable description used in error messages
     * @return the key bytes
     * @throws GeneralSecurityException if the text is not Base64 or not {@value #KEY_BYTES} bytes
     */
    public static byte[] decodeKey(String text, String source) throws GeneralSecurityException {
        if (text == null || text.isBlank()) {
            throw new GeneralSecurityException("Key supplied by " + source + " is empty");
        }
        String compacted = text.replaceAll("\\s", "");
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(compacted);
        } catch (IllegalArgumentException standardAlphabetRejected) {
            throw new GeneralSecurityException("Key supplied by " + source + " is not valid standard Base64. "
                    + "Generate one with 'java pii.PiiKeygen'.", standardAlphabetRejected);
        }
        if (decoded.length != KEY_BYTES) {
            java.util.Arrays.fill(decoded, (byte) 0);
            throw new GeneralSecurityException("Key supplied by " + source + " must decode to exactly "
                    + KEY_BYTES + " bytes (AES-256) but decoded to " + decoded.length + " bytes");
        }
        return decoded;
    }

    /**
     * Generates a fresh 256 bit key from the JCE strong secure random source.
     *
     * @return a new key
     */
    public static byte[] newKey(SecureRandom random) {
        byte[] key = new byte[KEY_BYTES];
        random.nextBytes(key);
        return key;
    }

    private static String varName(String overrideVar, String fallback) {
        String override = System.getenv(overrideVar);
        return (override == null || override.isBlank()) ? fallback : override.trim();
    }

    private static String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first.trim();
        }
        if (second != null && !second.isBlank()) {
            return second.trim();
        }
        return null;
    }
}
