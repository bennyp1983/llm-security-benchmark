package com.portal.auth;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * PBKDF2-HMAC-SHA256 password records, using only the JDK's own key derivation.
 *
 * <p>Record text (this is what is written to the roster file, never a password):
 * <pre>pbkdf2$sha256$&lt;iterations&gt;$&lt;base64 salt&gt;$&lt;base64 derived key&gt;</pre>
 *
 * <p>Why PBKDF2 and not Argon2/bcrypt: the JDK ships no memory-hard KDF and rule 8 says
 * prefer the platform's proven primitive over a hand-rolled or third-party one. The
 * iteration count is stored <em>per record</em> and a floor is enforced, so records can
 * be upgraded (and this class replaced by a memory-hard implementation) without a
 * format break -- see {@link #needsRehash(String)}.
 */
public final class PasswordHasher {

    public static final String ALG = "pbkdf2";
    public static final String HASH_ALG = "sha256";
    /**
     * Administrative "account switched off" marker. A recognised record shape that can
     * never verify (it is not a KDF record, so {@link #verify} runs the decoy KDF and
     * returns false) yet is accepted by the strict roster loader, so disabling one
     * account cannot take the whole roster down.
     */
    public static final String DISABLED_RECORD = "disabled$v1";
    private static final String JCE_KDF = "PBKDF2WithHmacSHA256";

    public static final int SALT_BYTES = 16;
    public static final int KEY_BYTES = 32;
    /** Records below this are refused outright; they are never honoured. */
    public static final int MIN_ITERATIONS = 100_000;
    public static final int MAX_ITERATIONS = 2_000_000;
    public static final int DEFAULT_ITERATIONS = 150_000;

    private final int configuredIterations;

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public PasswordHasher(int configuredIterations) {
        if (configuredIterations < MIN_ITERATIONS || configuredIterations > MAX_ITERATIONS) {
            throw new IllegalArgumentException("iterations out of range");
        }
        this.configuredIterations = configuredIterations;
    }

    public int configuredIterations() {
        return configuredIterations;
    }

    /** Derive a fresh record. The caller wipes {@code secret} (see {@link #hashWithCopy}). */
    public String hash(char[] secret, char[] identity) {
        byte[] salt = Crypto.randomBytes(SALT_BYTES);
        try {
            byte[] key = derive(secret, salt, configuredIterations);
            try {
                return ALG + "$" + HASH_ALG + "$" + configuredIterations + "$"
                        + Crypto.base64(salt) + "$" + Crypto.base64(key);
            } finally {
                Crypto.wipe(key);
            }
        } finally {
            Crypto.wipe(salt);
        }
    }

    /** Convenience for callers that cannot keep a char[] alive: wipes an internal copy. */
    public String hashWithCopy(char[] secret, char[] identity) {
        char[] copy = secret.clone();
        try {
            return hash(copy, identity);
        } finally {
            Crypto.wipe(copy);
        }
    }

    /**
     * Verify a candidate against a stored record.
     *
     * <p>The KDF is <em>always</em> executed, including for a malformed or administratively
     * disabled record, and the comparison is {@link MessageDigest#isEqual}. There is no
     * branch here whose cost depends on whether the account exists, whether its record is
     * corrupt, or how close the password is: a garbage record derives against the same
     * per-identity decoy salt that an <em>absent</em> account would use, which is what
     * makes "unknown name" and "present but broken" cost identical.
     *
     * <p>A record whose stored iteration count differs from policy is honoured (so nobody
     * is locked out by a policy change) and upgraded afterwards by
     * {@link EmployeeStore#rotateSecret}; a record below {@link #MIN_ITERATIONS} never
     * parses at all, so it can never be honoured cheaply.
     */
    public boolean verify(char[] secret, String record, String identityRef) {
        ParsedRecord p = parseLenient(record);
        if (p == null) {
            verifyAgainstDecoy(secret, identityRef);
            return false;
        }
        byte[] key = derive(secret, p.salt, p.iterations);
        try {
            return Crypto.equal(key, p.key);
        } finally {
            Crypto.wipe(key);
            Crypto.wipe(p.salt);
            Crypto.wipe(p.key);
        }
    }

    /**
     * Do the same amount of work as a real verification, for a name that has no record
     * and for every refusal path that must not touch the roster.
     *
     * <p>The salt is derived from the (already boundary-validated) identity reference, so
     * the work for a given guess is stable but there is no single global value an
     * attacker can pre-compute against. The comparison target is a real 32-byte array of
     * the same length as a derived key, so {@link java.security.MessageDigest#isEqual}
     * cannot take a length shortcut and reveal which branch ran.
     *
     * @param identityRef {@link Crypto#idRef} of the presented name, never the name itself
     */
    public boolean verifyAgainstDecoy(char[] secret, String identityRef) {
        if (identityRef == null || identityRef.length() > 64) {
            throw new IllegalArgumentException("decoy-ref");
        }
        byte[] salt = Arrays.copyOf(
                Crypto.sha256((DECOY_DOMAIN + identityRef).getBytes(StandardCharsets.US_ASCII)),
                SALT_BYTES);
        byte[] key = derive(secret, salt, configuredIterations);
        try {
            byte[] target = new byte[KEY_BYTES];
            try {
                return Crypto.equal(key, target);
            } finally {
                Crypto.wipe(target);
            }
        } finally {
            Crypto.wipe(key);
            Crypto.wipe(salt);
        }
    }

    private static final String DECOY_DOMAIN = "portal-decoy-salt-domain-separation-v1:";

    /**
     * Execute exactly one decoy derivation for a secret that may be malformed (the
     * boundary already rejected it, but we still have to spend the same CPU as a real
     * verification). The presented value is normalised into a fixed-shape scratch array
     * first so that (a) a non-ASCII or over-long rejection cannot make {@code derive}
     * throw on a denial path, and (b) the work is bit-identical for every caller of this
     * method regardless of what was actually typed. The scratch array is wiped.
     */
    public void burnOneDigest(char[] maybeMalformedSecret, String identityRef) {
        char[] safe = new char[FIXED_WORK_LENGTH];
        try {
            if (maybeMalformedSecret != null) {
                int n = Math.min(maybeMalformedSecret.length, FIXED_WORK_LENGTH);
                for (int i = 0; i < n; i++) {
                    char c = maybeMalformedSecret[i];
                    safe[i] = (c >= 0x21 && c <= 0x7E) ? c : 'a';
                }
            }
            for (int i = 0; i < FIXED_WORK_LENGTH; i++) {
                if (safe[i] == '\0') {
                    safe[i] = 'a';
                }
            }
            verifyAgainstDecoy(safe, identityRef);
        } finally {
            Crypto.wipe(safe);
        }
    }

    /** Fixed shape so that no rejection path can vary its work by input length. */
    private static final int FIXED_WORK_LENGTH = 64;

    /** True when a stored record is weaker than the current policy. */
    public boolean needsRehash(String record) {
        ParsedRecord p = parseLenient(record);
        if (p == null) {
            return false;
        }
        try {
            return p.iterations < configuredIterations
                    || !HASH_ALG.equals(p.hashAlg)
                    || !ALG.equals(p.alg)
                    || p.key.length != KEY_BYTES
                    || p.salt.length != SALT_BYTES;
        } finally {
            Crypto.wipe(p.salt);
            Crypto.wipe(p.key);
        }
    }

    /** Strict parse used when loading the roster: any deviation is an error, not a default. */
    public void requireValidRecord(String record) {
        if (DISABLED_RECORD.equals(record)) {
            return;
        }
        ParsedRecord p = parseLenient(record);
        if (p == null) {
            throw new IllegalArgumentException("record:malformed");
        }
        try {
            if (p.iterations < MIN_ITERATIONS) {
                throw new IllegalArgumentException("record:iterations-below-floor");
            }
            if (p.salt.length != SALT_BYTES || p.key.length != KEY_BYTES) {
                throw new IllegalArgumentException("record:length");
            }
        } finally {
            Crypto.wipe(p.salt);
            Crypto.wipe(p.key);
        }
    }

    /**
     * Run the platform KDF.
     *
     * <p>{@link PBEKeySpec} takes the {@code char[]} directly. That is safe here and only
     * here: {@code PBEKeySpec} is <b>not</b> injective over arbitrary {@code char[]} --
     * it drops trailing NULs and maps unpaired surrogates to {@code '?'}, so two
     * different secrets can otherwise derive the same key. {@link
     * InputPolicy#isWellFormedSecret} restricts every secret that reaches this method to
     * printable ASCII ({@code 0x21..0x7E}), where no NUL, no surrogate and no whitespace
     * folding is possible, so the mapping is one-to-one. {@link #requirePrintableAscii}
     * re-asserts that immediately before the spec is built, because this invariant is a
     * correctness requirement of the KDF call and not something to trust a caller about.
     */
    private byte[] derive(char[] secret, byte[] salt, int iterations) {
        if (secret == null || secret.length == 0 || salt == null || salt.length == 0) {
            throw new IllegalArgumentException("derive:empty-input");
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            // A file-supplied iteration count outside the policy range is refused rather
            // than trusted: it would let a doctored record cost almost nothing.
            throw new IllegalArgumentException("derive:iterations");
        }
        requirePrintableAscii(secret);
        PBEKeySpec spec = new PBEKeySpec(secret, salt, iterations, KEY_BYTES * 8);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(JCE_KDF);
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("kdf-unavailable", failure);
        } finally {
            // Clears the copy PBEKeySpec made of the password. Our own array is cleared
            // by Authenticator's single exit point.
            spec.clearPassword();
        }
    }

    private static void requirePrintableAscii(char[] secret) {
        for (char c : secret) {
            if (c < 0x21 || c > 0x7E) {
                throw new IllegalArgumentException("derive:secret-not-printable-ascii");
            }
        }
    }

    private static ParsedRecord parseLenient(String record) {
        if (record == null || record.length() > 256) {
            return null;
        }
        String[] parts = record.split("\\$", -1);
        if (parts.length != 5) {
            return null;
        }
        int iterations;
        try {
            iterations = Integer.parseInt(parts[2]);
        } catch (NumberFormatException notInt) {
            return null;
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            return null;
        }
        byte[] salt;
        byte[] key;
        try {
            salt = Crypto.base64Strict(parts[3]);
            key = Crypto.base64Strict(parts[4]);
        } catch (IllegalArgumentException badEncoding) {
            return null;
        }
        if (salt.length != SALT_BYTES || key.length != KEY_BYTES) {
            return null;
        }
        return new ParsedRecord(parts[0], parts[1], iterations, salt, key);
    }

    private static final class ParsedRecord {
        final String alg;
        final String hashAlg;
        final int iterations;
        final byte[] salt;
        final byte[] key;

        ParsedRecord(String alg, String hashAlg, int iterations, byte[] salt, byte[] key) {
            this.alg = alg;
            this.hashAlg = hashAlg;
            this.iterations = iterations;
            this.salt = salt;
            this.key = key;
        }
    }
}
