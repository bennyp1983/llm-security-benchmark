package com.example.accounts;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Argon2id password hashing, stored in PHC string format.
 *
 * <p>Rule 8 (prefer the platform): Argon2id is the current OWASP first choice for password storage
 * and this class does not invent any of it -- the KDF is Bouncy Castle's reviewed implementation,
 * the salt comes from {@link SecureRandom}, the comparison is {@link MessageDigest#isEqual} and the
 * on-disk encoding is the standard PHC string, so another tool can verify the same hashes. The JDK
 * ships no Argon2, which is the only reason a third-party dependency appears at all.
 *
 * <p>Rule 1 (trust boundaries): a stored hash is a value read back from a database, i.e. untrusted
 * input. {@link #verify} therefore parses it strictly and rejects out-of-range cost parameters,
 * rather than obediently allocating whatever {@code m=} a tampered row asks for.
 *
 * <p>Rule 5: the plaintext is handled as {@code char[]}, encoded through a {@link CharBuffer} so no
 * {@code String} copy is created, and every intermediate buffer is zeroed in a {@code finally}.
 */
public final class PasswordHasher {

    private static final String ALGORITHM_ID = "argon2id";
    private static final int VERSION = Argon2Parameters.ARGON2_VERSION_13; // 0x13 == 19
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;

    /** Bounds applied when parsing a stored hash, independent of the configured cost. */
    private static final int MIN_MEMORY_KIB = 8;
    private static final int MAX_MEMORY_KIB = 1_048_576;   // 1 GiB ceiling
    private static final int MAX_ITERATIONS = 20;
    private static final int MAX_PARALLELISM = 16;
    private static final int MAX_ENCODED_LENGTH = 512;

    private static final Base64.Encoder B64 = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private final Config.Argon2Settings settings;
    private final byte[] pepper;
    private final SecureRandom random;

    /**
     * @param pepper optional site-wide secret mixed in as Argon2's "secret" parameter; an empty
     *               array means "not configured". Never logged, never persisted with the hash.
     */
    public PasswordHasher(Config.Argon2Settings settings, byte[] pepper) {
        this.settings = settings;
        this.pepper = pepper == null ? new byte[0] : pepper.clone();
        this.random = new SecureRandom();
    }

    /** Hashes {@code password} with a fresh random salt. The caller still owns {@code password}. */
    public String hash(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password must not be empty");
        }
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        byte[] digest = derive(password, salt, settings.memoryKib(), settings.iterations(),
                settings.parallelism());
        try {
            return encode(settings.memoryKib(), settings.iterations(), settings.parallelism(),
                    salt, digest);
        } finally {
            Wipe.bytes(digest);
        }
    }

    /**
     * Verifies {@code password} against a stored PHC string.
     *
     * @return {@code true} only on a match; {@code false} for a mismatch <em>and</em> for any
     *         unparsable or out-of-policy stored value -- a corrupt row fails closed (rule 3).
     */
    public boolean verify(char[] password, String encoded) {
        if (password == null || password.length == 0 || encoded == null) {
            return false;
        }
        Parsed parsed;
        try {
            parsed = parse(encoded);
        } catch (IllegalArgumentException e) {
            return false;
        }
        byte[] actual = null;
        try {
            actual = derive(password, parsed.salt, parsed.memoryKib, parsed.iterations,
                    parsed.parallelism);
            // Constant-time: a timing difference here would leak the hash prefix byte by byte.
            return MessageDigest.isEqual(actual, parsed.hash);
        } finally {
            Wipe.bytes(actual);
            Wipe.bytes(parsed.salt);
            Wipe.bytes(parsed.hash);
        }
    }

    /** True when {@code encoded} is valid but weaker than the current settings (rehash on login). */
    public boolean needsRehash(String encoded) {
        try {
            Parsed parsed = parse(encoded);
            try {
                return parsed.memoryKib < settings.memoryKib()
                        || parsed.iterations < settings.iterations()
                        || parsed.hash.length < HASH_LENGTH
                        || parsed.salt.length < SALT_LENGTH;
            } finally {
                Wipe.bytes(parsed.salt);
                Wipe.bytes(parsed.hash);
            }
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    /**
     * A throwaway hash with the current parameters, used to spend the same CPU on a login for an
     * account that does not exist as on one that does (rule 6: comparable work for every failure).
     */
    public String newDecoyHash() {
        byte[] secret = new byte[32];
        random.nextBytes(secret);
        char[] asChars = new char[secret.length];
        try {
            for (int i = 0; i < secret.length; i++) {
                asChars[i] = (char) ('a' + (secret[i] & 0x0f));
            }
            return hash(asChars);
        } finally {
            Wipe.bytes(secret);
            Wipe.chars(asChars);
        }
    }

    private byte[] derive(char[] password, byte[] salt, int memoryKib, int iterations,
                          int parallelism) {
        byte[] passwordBytes = toUtf8(password);
        try {
            Argon2Parameters.Builder builder =
                    new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                            .withVersion(VERSION)
                            .withSalt(salt)
                            .withMemoryAsKB(memoryKib)
                            .withIterations(iterations)
                            .withParallelism(parallelism);
            if (pepper.length > 0) {
                builder.withSecret(pepper);
            }
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(builder.build());
            byte[] out = new byte[HASH_LENGTH];
            generator.generateBytes(passwordBytes, out);
            return out;
        } finally {
            Wipe.bytes(passwordBytes);
        }
    }

    /** UTF-8 encodes a {@code char[]} without creating an unwipeable {@code String}. */
    private static byte[] toUtf8(char[] password) {
        CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteBuffer buffer;
        try {
            buffer = encoder.encode(CharBuffer.wrap(password));
        } catch (CharacterCodingException e) {
            // Unpaired surrogates are already rejected by InputValidator; fail closed regardless.
            throw new IllegalArgumentException("password is not valid Unicode");
        }
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), (byte) 0);
        }
        return bytes;
    }

    private static String encode(int memoryKib, int iterations, int parallelism, byte[] salt,
                                 byte[] hash) {
        return "$" + ALGORITHM_ID + "$v=" + VERSION
                + "$m=" + memoryKib + ",t=" + iterations + ",p=" + parallelism
                + "$" + B64.encodeToString(salt)
                + "$" + B64.encodeToString(hash);
    }

    private static final class Parsed {
        final int memoryKib;
        final int iterations;
        final int parallelism;
        final byte[] salt;
        final byte[] hash;

        Parsed(int memoryKib, int iterations, int parallelism, byte[] salt, byte[] hash) {
            this.memoryKib = memoryKib;
            this.iterations = iterations;
            this.parallelism = parallelism;
            this.salt = salt;
            this.hash = hash;
        }
    }

    private static Parsed parse(String encoded) {
        if (encoded == null || encoded.isEmpty() || encoded.length() > MAX_ENCODED_LENGTH) {
            throw new IllegalArgumentException("unsupported hash encoding");
        }
        // "$argon2id$v=19$m=..,t=..,p=..$<salt>$<hash>" -> ["", id, version, params, salt, hash]
        String[] parts = encoded.split("\\$", -1);
        if (parts.length != 6 || !parts[0].isEmpty()) {
            throw new IllegalArgumentException("unsupported hash encoding");
        }
        if (!ALGORITHM_ID.equals(parts[1].toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("unsupported hash algorithm");
        }
        if (!parts[2].equals("v=" + VERSION)) {
            throw new IllegalArgumentException("unsupported hash version");
        }
        String[] params = parts[3].split(",", -1);
        if (params.length != 3) {
            throw new IllegalArgumentException("unsupported hash parameters");
        }
        int memoryKib = parseParam(params[0], "m=", MIN_MEMORY_KIB, MAX_MEMORY_KIB);
        int iterations = parseParam(params[1], "t=", 1, MAX_ITERATIONS);
        int parallelism = parseParam(params[2], "p=", 1, MAX_PARALLELISM);

        byte[] salt = decodeBounded(parts[4], 8, 64);
        byte[] hash;
        try {
            hash = decodeBounded(parts[5], 16, 64);
        } catch (RuntimeException e) {
            Wipe.bytes(salt);
            throw e;
        }
        return new Parsed(memoryKib, iterations, parallelism, salt, hash);
    }

    private static int parseParam(String token, String prefix, int min, int max) {
        if (!token.startsWith(prefix) || token.length() > prefix.length() + 9) {
            throw new IllegalArgumentException("unsupported hash parameters");
        }
        int value;
        try {
            value = Integer.parseInt(token.substring(prefix.length()));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("unsupported hash parameters");
        }
        if (value < min || value > max) {
            throw new IllegalArgumentException("hash parameter out of range");
        }
        return value;
    }

    private static byte[] decodeBounded(String base64, int minBytes, int maxBytes) {
        if (base64.isEmpty() || base64.length() > 4 * (maxBytes / 3 + 2)) {
            throw new IllegalArgumentException("unsupported hash encoding");
        }
        byte[] decoded;
        try {
            decoded = B64D.decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("unsupported hash encoding");
        }
        if (decoded.length < minBytes || decoded.length > maxBytes) {
            Wipe.bytes(decoded);
            throw new IllegalArgumentException("unsupported hash encoding");
        }
        return decoded;
    }
}
