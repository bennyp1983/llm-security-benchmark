package app;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Argon2id password hashing (RFC 9106) using the Bouncy Castle primitive directly.
 *
 * <p>Why not {@code Argon2PasswordEncoder} from Spring Security, which is the obvious built-in:
 * <ol>
 *   <li>its {@code defaultsForSpringSecurity_v5_8()} parameters (m=16 MiB, t=2, p=1) are
 *       <em>below</em> the OWASP Argon2id cheat-sheet floor of m=19456 KiB, t=2, p=1, and</li>
 *   <li>{@code matches()} re-derives using the memory/iteration/parallelism values embedded in
 *       the stored string, so a database row an attacker could rewrite makes this process
 *       allocate unbounded memory (a stored {@code m=4194304} asks for 4 GiB) before it answers.
 *       That makes a stored value decide a resource outcome unchecked.</li>
 * </ol>
 * Encoding and verification here use the same library and the same RFC-9106 encoding format, and
 * the produced strings are verified to be readable by Spring's encoder in the test suite, so the
 * credential format stays standard while the policy on stored values stays ours.
 *
 * <p>Every {@code char[]} handed to this class is the caller's; this class never stores it, never
 * converts it to a {@link String}, and erases only the buffers it allocates itself. Zeroing is
 * best-effort against heap dumps: Bouncy Castle's internal blocks and the JVM's {@code char[]}
 * copies cannot be erased from here, which the README states plainly.
 */
public final class PasswordHasher {

    /** Salt length in bytes, per RFC 9106 (16 bytes minimum for Argon2id). */
    static final int SALT_BYTES = 16;
    static final int HASH_BYTES = 32;

    /**
     * Bounds accepted for a hash that is <em>already stored</em>. The lower bound is the OWASP
     * Argon2id floor, so a downgraded row is refused rather than verified cheaply; the upper
     * bound caps the memory a rewritten row can demand.
     */
    static final int STORED_MIN_MEMORY_KIB = 19_456;
    static final int STORED_MAX_MEMORY_KIB = 1_048_576;
    static final int STORED_MIN_ITERATIONS = 2;
    static final int STORED_MAX_ITERATIONS = 20;
    static final int STORED_MIN_PARALLELISM = 1;
    static final int STORED_MAX_PARALLELISM = 8;

    /** Canonical PHC form, so no ambiguous or unpadded base64 can denote a stored credential. */
    private static final Pattern PHC = Pattern.compile(
        "^\\$argon2id\\$v=19\\$m=([0-9]{1,9}),t=([0-9]{1,4}),p=([0-9]{1,3})\\$"
            + "([A-Za-z0-9+/]{22})\\$([A-Za-z0-9+/]{43})$");

    private static final Base64.Encoder B64 = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder B64_STRICT = Base64.getDecoder();

    /**
     * Longest credential string these bounds can produce, measured rather than guessed: every
     * bound is a maximum, and the maximum cost set is {@code m=1048576,t=20,p=8}. The account
     * store sizes its credential column from this value, so a configured cost that this class
     * accepts can never be refused by the schema on the way in. Deriving it here keeps the writer
     * of credentials and the storage that holds them from drifting apart.
     */
    static final int MAX_STORED_HASH_CHARS =
        format(STORED_MAX_MEMORY_KIB, STORED_MAX_ITERATIONS, STORED_MAX_PARALLELISM,
            new byte[SALT_BYTES], new byte[HASH_BYTES]).length();

    private final SecureRandom random = new SecureRandom();
    private final int memoryKib;
    private final int iterations;
    private final int parallelism;

    public PasswordHasher(int memoryKib, int iterations, int parallelism) throws GeneralSecurityException {
        if (memoryKib < STORED_MIN_MEMORY_KIB || memoryKib > STORED_MAX_MEMORY_KIB) {
            throw new GeneralSecurityException("configured Argon2 memory is outside the approved range");
        }
        if (iterations < STORED_MIN_ITERATIONS || iterations > STORED_MAX_ITERATIONS) {
            throw new GeneralSecurityException("configured Argon2 iterations are outside the approved range");
        }
        if (parallelism < STORED_MIN_PARALLELISM || parallelism > STORED_MAX_PARALLELISM) {
            throw new GeneralSecurityException("configured Argon2 parallelism is outside the approved range");
        }
        this.memoryKib = memoryKib;
        this.iterations = iterations;
        this.parallelism = parallelism;
    }

    /**
     * @return {@code $argon2id$v=19$m=..,t=..,p=..$<salt>$<hash>} with a fresh CSPRNG salt
     */
    public String encode(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("a password is required to hash");
        }
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = derive(password, salt, memoryKib, iterations, parallelism);
        try {
            return format(memoryKib, iterations, parallelism, salt, hash);
        } finally {
            Arrays.fill(hash, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    /**
     * Verifies a candidate password against a stored hash. Returns {@code false} for a stored
     * value that is malformed or outside the approved parameter bounds - the caller cannot tell
     * that apart from a wrong password, and neither outcome is granted access.
     */
    public boolean verify(char[] password, String storedHash) {
        if (password == null || password.length == 0 || storedHash == null) {
            return false;
        }
        byte[] salt = null;
        byte[] expected = null;
        byte[] actual = null;
        try {
            Matcher shape = PHC.matcher(storedHash);
            if (!shape.matches()) {
                return false;
            }
            int memory = Integer.parseInt(shape.group(1));
            int iterationsRead = Integer.parseInt(shape.group(2));
            int parallelismRead = Integer.parseInt(shape.group(3));
            if (memory < STORED_MIN_MEMORY_KIB || memory > STORED_MAX_MEMORY_KIB
                || iterationsRead < STORED_MIN_ITERATIONS || iterationsRead > STORED_MAX_ITERATIONS
                || parallelismRead < STORED_MIN_PARALLELISM || parallelismRead > STORED_MAX_PARALLELISM) {
                return false;
            }
            salt = decodeCanonical(shape.group(4));
            expected = decodeCanonical(shape.group(5));
            if (salt == null || expected == null
                || salt.length != SALT_BYTES || expected.length != HASH_BYTES) {
                return false;
            }
            actual = derive(password, salt, memory, iterationsRead, parallelismRead);
            // Lengths are fixed by the pattern above, so this comparison reveals nothing beyond
            // the match result itself.
            return MessageDigest.isEqual(expected, actual);
        } catch (RuntimeException unchecked) {
            return false;
        } finally {
            if (salt != null) {
                Arrays.fill(salt, (byte) 0);
            }
            if (expected != null) {
                Arrays.fill(expected, (byte) 0);
            }
            if (actual != null) {
                Arrays.fill(actual, (byte) 0);
            }
        }
    }

    /** Cost parameters read back out of a stored hash string. */
    public record Cost(int memoryKib, int iterations, int parallelism) {
    }

    /**
     * Extracts the parameters embedded in a hash this class produced.
     *
     * @throws IllegalArgumentException if the string is not a canonical accepted hash, which
     *     would mean a programming error, since callers only pass strings from {@link #encode}
     */
    public Cost costOf(String storedHash) {
        Matcher shape = PHC.matcher(storedHash);
        if (!shape.matches()) {
            throw new IllegalArgumentException("the hash was not produced by this hasher");
        }
        return new Cost(Integer.parseInt(shape.group(1)), Integer.parseInt(shape.group(2)),
            Integer.parseInt(shape.group(3)));
    }

    /**
     * True when a stored credential is weaker than the current policy, so the caller can re-hash
     * it while the plaintext is legitimately in hand (on a successful sign-in).
     */
    public boolean weakerThanPolicy(String storedHash) {
        if (storedHash == null) {
            return true;
        }
        Matcher shape = PHC.matcher(storedHash);
        if (!shape.matches()) {
            return true;
        }
        int memory = Integer.parseInt(shape.group(1));
        int iterationsRead = Integer.parseInt(shape.group(2));
        int parallelismRead = Integer.parseInt(shape.group(3));
        return memory < memoryKib || iterationsRead < iterations || parallelismRead < parallelism;
    }

    public int policyMemoryKib() {
        return memoryKib;
    }

    public int policyIterations() {
        return iterations;
    }

    public int policyParallelism() {
        return parallelism;
    }

    private static byte[] derive(char[] password, byte[] salt, int memoryKib, int iterations, int parallelism) {
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt)
            .withParallelism(parallelism)
            .withMemoryAsKB(memoryKib)
            .withIterations(iterations)
            .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);
        byte[] out = new byte[HASH_BYTES];
        generator.generateBytes(password, out);
        return out;
    }

    private static String format(int memory, int iterations, int parallelism, byte[] salt, byte[] hash) {
        return "$argon2id$v=19$m=" + memory + ",t=" + iterations + ",p=" + parallelism + "$"
            + B64.encodeToString(salt) + "$" + B64.encodeToString(hash);
    }

    /**
     * Java's "basic" decoder silently accepts unpadded input, so it is not canonical on its own.
     * Re-encoding and comparing rejects any alternative spelling of the same bytes, keeping the
     * stored credential string a unique representation.
     */
    private static byte[] decodeCanonical(String text) {
        byte[] decoded;
        try {
            decoded = B64_STRICT.decode(text);
        } catch (IllegalArgumentException notBase64) {
            return null;
        }
        return B64.encodeToString(decoded).equals(text) ? decoded : null;
    }

    /** Exposed for the test suite's cross-check against Spring's encoder. */
    static String describe(String storedHash) {
        if (storedHash == null) {
            return "null";
        }
        Matcher shape = PHC.matcher(storedHash);
        if (!shape.matches()) {
            return "malformed";
        }
        return String.format(Locale.ROOT, "m=%s,t=%s,p=%s", shape.group(1), shape.group(2), shape.group(3));
    }
}
