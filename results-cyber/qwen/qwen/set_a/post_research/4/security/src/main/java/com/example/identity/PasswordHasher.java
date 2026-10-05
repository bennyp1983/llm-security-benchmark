package com.example.identity;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Password storage: PBKDF2-HMAC-SHA256, per-credential salt, versioned encoding.
 *
 * <h2>Why this algorithm (Rule 8)</h2>
 * The JDK ships PBKDF2 ({@code PBKDF2WithHmacSHA256}), {@link SecureRandom}, Base64 and
 * {@link MessageDigest#isEqual}. It ships no Argon2, scrypt or bcrypt, and pulling in a native
 * crypto library to replace a JCE primitive that meets the current OWASP minimum would add supply
 * chain risk without adding strength. So: platform primitives only, zero third-party crypto.
 * <p>The iteration floor is set to the OWASP 2025 minimum for PBKDF2-HMAC-SHA256 (600,000). That
 * was measured on this machine at roughly 850 ms per derivation, which is the price of one
 * registration or one sign-in, and is paid once per request by every branch including refusals.
 * The value lives in {@link Config}, is validated on read, and is upgraded by re-encoding on
 * successful sign-in ({@link #needsRehash}) rather than by editing a constant nobody notices.
 *
 * <h2>Stored encoding</h2>
 * {@code v1$pbkdf2-sha256$<iterations>$<salt-b64>$<digest-b64>} - all ASCII, no whitespace, no
 * {@code $} inside a field, bounded length. {@link #decode} is strict enough to be a
 * fail-closed boundary in its own right: a corrupt, truncated, over-long or low-iteration row is
 * refused, and the caller then answers with the same generic refusal it uses for a wrong password.
 * This matters because the {@code iterations} field is read from the database and therefore
 * attacker-controlled: an unvalidated field would let anyone who can write a row set
 * {@code iterations=1} and make the KDF effectively free. {@link #decode} refuses it.
 *
 * <h2>Constant time</h2>
 * Comparison uses {@link MessageDigest#isEqual} over derived digests. The failure paths avoid
 * short-circuiting on anything an attacker can observe; {@link #chargeDummy} keeps the cheap
 * branches ({@code unknown account}, {@code malformed identifier}, {@code unhashable candidate})
 * at the same cost as the expensive ones. The per-branch assertion is in the test suite.
 */
public final class PasswordHasher {

    static final String SCHEME = "pbkdf2-sha256";
    static final String VERSION = "v1";
    private static final String TRANSFORMATION = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;   // >= 128 bits, per NIST SP 800-132
    private static final int DIGEST_BITS = 256; // == HMAC-SHA256 output, no truncation
    private static final int DIGEST_BYTES = DIGEST_BITS / 8;
    private static final int MAX_ENCODING_CHARS = 256;
    private static final Base64.Decoder B64 = Base64.getDecoder();

    private final SecureRandom random;
    private final int iterations;
    private final int minIterations;
    private final String dummyEncoding;

    /**
     * @param iterations    cost parameter for new credentials
     * @param minIterations lowest stored cost still accepted; below it a row is treated as corrupt
     *                      rather than cheap
     */
    public PasswordHasher(Config config) throws IdentityStoreException {
        this.random = new SecureRandom();
        this.iterations = config.pbkdf2Iterations();
        this.minIterations = config.pbkdf2MinIterations();
        if (iterations < minIterations) {
            throw new IdentityStoreException(Reason.CONFIG_INVALID,
                    "pbkdf2 iterations must be at least the configured minimum");
        }
        try {
            // Pre-computed once so the equal-work charge needs no password and cannot be
            // skipped by an early return in the caller.
            this.dummyEncoding = hashInternal(dummyCandidate(), config);
        } catch (GeneralSecurityException e) {
            throw new IdentityStoreException(Reason.CRYPTO_FAILURE, "password hashing unavailable", e);
        }
    }

    /** A fixed, never-issued credential used only to spend equal work on a refusal branch. */
    private static char[] dummyCandidate() {
        return "not-a-real-credential-3f9c1a".toCharArray();
    }

    public int iterations() {
        return iterations;
    }

    /**
     * The absolute stored-cost floor, exposed for tests. It is deliberately <em>not</em> read from
     * configuration: a row below it is corrupt no matter what the running config says, so a test
     * that wants to sit one under the floor must be able to name the floor.
     */
    static int minAcceptedIterations() {
        return MIN_ACCEPTED_ITERATIONS;
    }

    // ------------------------------------------------------------------ hashing

    /**
     * Derives a new credential. The caller's password is erased by this method.
     */
    public String hash(Password password) throws IdentityStoreException {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        try {
            byte[] digest = derive(password.chars(), salt, iterations);
            return encode(VERSION, SCHEME, iterations, salt, digest);
        } catch (GeneralSecurityException e) {
            throw new IdentityStoreException(Reason.CRYPTO_FAILURE, "password hashing failed", e);
        } finally {
            password.close();
        }
    }

    /** Internal: hash without taking ownership of the char[]. */
    private String hashInternal(char[] candidate, Config config) throws GeneralSecurityException {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] digest = derive(candidate, salt, config.pbkdf2Iterations());
        return encode(VERSION, SCHEME, config.pbkdf2Iterations(), salt, digest);
    }

    // ------------------------------------------------------------------ verifying

    /**
     * Checks a candidate against a stored encoding.
     *
     * @param storedEncoding the value of the {@code password} column. {@code null} means
     *                       "no such account" and still costs a full derivation.
     * @return true only if the candidate matches a well-formed, adequately-costed row.
     */
    public boolean matchesStored(char[] candidate, String storedEncoding) throws IdentityStoreException {
        StoredCredential stored;
        try {
            stored = decode(storedEncoding);
        } catch (IdentityStoreException corruptOrAbsent) {
            // Same cost as a real verify, so "row missing" and "row corrupt" are not observable
            // as a fast refusal. The reason is logged by the caller, not returned.
            chargeDummy();
            throw corruptOrAbsent;
        }
        byte[] actual;
        try {
            actual = derive(candidate, stored.salt, stored.iterations);
        } catch (GeneralSecurityException e) {
            throw new IdentityStoreException(Reason.CRYPTO_FAILURE, "password verification failed", e);
        }
        byte[] expected;
        try {
            expected = B64.decode(stored.digestB64);
        } catch (IllegalArgumentException e) {
            chargeDummy();
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "digest is not valid base64", e);
        }
        boolean ok = MessageDigest.isEqual(expected, actual);
        Arrays.fill(actual, (byte) 0);
        Arrays.fill(expected, (byte) 0);
        return ok;
    }

    /**
     * Spends one derivation worth of work on a branch that has nothing to verify, so a fast
     * refusal never tells the caller which branch it hit.
     *
     * <p>Takes no candidate, deliberately. The work being equalled is fixed by the dummy's own
     * iteration count, not by the caller's input, so accepting a buffer here would only add a route
     * by which live key material reaches a code path whose job is to hold none. The cost is the
     * same: PBKDF2 at the same iteration count over a comparable-length password.
     */
    public void chargeDummy() throws IdentityStoreException {
        try {
            StoredCredential dummy = decode(dummyEncoding);
            byte[] wasted = derive(dummyCandidate(), dummy.salt, dummy.iterations);
            Arrays.fill(wasted, (byte) 0);
        } catch (GeneralSecurityException e) {
            throw new IdentityStoreException(Reason.CRYPTO_FAILURE, "password hashing unavailable", e);
        }
    }

    /** Cheap: does this stored row use an older version or a lower cost than we now require? */
    public boolean needsRehash(String storedEncoding) {
        try {
            StoredCredential s = decode(storedEncoding);
            return !VERSION.equals(s.version) || !SCHEME.equals(s.scheme) || s.iterations < iterations;
        } catch (IdentityStoreException e) {
            return false; // decode already refuses those rows; nothing to upgrade
        }
    }

    // ------------------------------------------------------------------ encoding

    private static String encode(String version, String scheme, int iters, byte[] salt, byte[] digest) {
        Base64.Encoder enc = Base64.getEncoder();
        // encodeToString, never append(encode(...)): StringBuilder.append(byte[]) prints
        // "[B@6f1c29d1", which compiles clean and only shows up when a later process reloads it.
        StringBuilder sb = new StringBuilder(128);
        sb.append(version).append('$').append(scheme).append('$').append(iters)
          .append('$').append(enc.encodeToString(salt)).append('$').append(enc.encodeToString(digest));
        String out = sb.toString();
        if (out.length() > MAX_ENCODING_CHARS) {
            throw new IllegalStateException("encoded credential exceeds the column width");
        }
        return out;
    }

    /** Parsed, validated stored credential. Fields are already range- and shape-checked. */
static final class StoredCredential {
        final String version;
        final String scheme;
        final int iterations;
        final byte[] salt;
        final String digestB64;

        private StoredCredential(String version, String scheme, int iterations, byte[] salt, String digestB64) {
            this.version = version;
            this.scheme = scheme;
            this.iterations = iterations;
            this.salt = salt;
            this.digestB64 = digestB64;
        }
    }

    /**
     * Strict parser for the stored column. Every field is checked for type, length, character set
     * and range; the caller must not use a stored credential it did not obtain here.
     *
     * @throws IdentityStoreException with {@link Reason#ABSENT_ACCOUNT} for null/empty and
     *         {@link Reason#CORRUPT_RECORD} for anything malformed or under-costed.
     */
    static StoredCredential decode(String stored) throws IdentityStoreException {
        if (stored == null || stored.isEmpty()) {
            throw new IdentityStoreException(Reason.ABSENT_ACCOUNT, "no stored credential");
        }
        if (stored.length() > MAX_ENCODING_CHARS || containsControlOrSpace(stored)) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "credential length or whitespace");
        }
        String[] parts = stored.split("\\$", -1); // literal '$'; split("$") would be a regex
        if (parts.length != 5) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "credential field count");
        }
        String version = parts[0];
        String scheme = parts[1];
        String iterText = parts[2];
        String saltB64 = parts[3];
        String digestB64 = parts[4];

        if (!VERSION.equals(version)) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "unsupported credential version");
        }
        if (!SCHEME.equals(scheme)) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "unsupported credential scheme");
        }
        int iterations = parseIterations(iterText);
        byte[] salt = decodeFixedLength(saltB64, SALT_BYTES, "salt");
        decodeFixedLength(digestB64, DIGEST_BYTES, "digest");

        return new StoredCredential(version, scheme, iterations, salt, digestB64);
    }

    private static int parseIterations(String text) throws IdentityStoreException {
        if (text.isEmpty() || text.length() > 9) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "iteration field shape");
        }
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) < '0' || text.charAt(i) > '9') {
                throw new IdentityStoreException(Reason.CORRUPT_RECORD, "iteration field not decimal");
            }
        }
        // Canonical spelling: exactly one decimal form per cost. A row writer cannot gain a cheaper
        // KDF by padding the field (the numeric floor below is applied to the parsed value either
        // way), but two spellings for one credential means two textual encodings for one account,
        // which is what rehash bookkeeping and any future equality check would have to reason about.
        if (text.charAt(0) == '0') {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "iteration field has a leading zero");
        }
        long value;
        try {
            value = Long.parseLong(text);
        } catch (NumberFormatException e) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "iteration field overflow", e);
        }
        // The range floor is what stops a tampered row from making the KDF free.
        if (value > Integer.MAX_VALUE || (int) value < MIN_ACCEPTED_ITERATIONS) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, "iteration count out of range");
        }
        return (int) value;
    }

    /** Absolute floor, independent of configuration: anything below this is treated as corrupt. */
    private static final int MIN_ACCEPTED_ITERATIONS = 100_000;

    private static byte[] decodeFixedLength(String b64, int expected, String what)
            throws IdentityStoreException {
        if (b64.isEmpty() || b64.length() > 64) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, what + " field shape");
        }
        byte[] raw;
        try {
            raw = B64.decode(b64);
        } catch (IllegalArgumentException e) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD, what + " is not base64", e);
        }
        if (raw.length != expected) {
            throw new IdentityStoreException(Reason.CORRUPT_RECORD,
                    what + " has wrong length: " + raw.length);
        }
        return raw;
    }

    private static boolean containsControlOrSpace(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c <= 0x20 || c == 0x7F) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ KDF

    private static byte[] derive(char[] candidate, byte[] salt, int iterations)
            throws GeneralSecurityException {
        // HMAC output is 32 bytes, so the derived key is 256 bits and PBEKeySpec's own
        // "keyLength > derived key length" overflow check cannot be reached.
        PBEKeySpec spec = new PBEKeySpec(candidate, salt, iterations, DIGEST_BITS);
        try {
            if (spec.getPassword() == null || spec.getPassword().length != candidate.length) {
                // Defensive: PBEKeySpec copies the array; if that ever stops being true the
                // erasure discipline below would be wrong.
                throw new GeneralSecurityException("PBEKeySpec did not copy the candidate");
            }
            return SecretKeyFactory.getInstance(TRANSFORMATION).generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    /** For tests: the fixed candidate used by the equal-work charge. */
    static char[] internalDummyCandidate() {
        return dummyCandidate().clone();
    }

    static int saltBytes() {
        return SALT_BYTES;
    }

    static int digestBytes() {
        return DIGEST_BYTES;
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
