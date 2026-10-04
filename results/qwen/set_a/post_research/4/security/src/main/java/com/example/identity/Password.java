package com.example.identity;

/**
 * A secret in transit, held as {@code char[]} and erased when the operation that needed it ends.
 *
 * <p>Not a {@code record} and deliberately has no {@code equals}, {@code hashCode} or value
 * {@code toString}: those would either leak the bytes into a log/format string or invite a
 * timing-variable comparison on the authentication path. Byte-for-byte comparison of a secret is
 * only ever done by {@link PasswordHasher#matches} over already-derived digests, in constant time.
 *
 * <h2>Why validation is not just policy</h2>
 * {@link javax.crypto.spec.PBEKeySpec} converts a {@code char[]} with the JCE's own UTF-8 encoder,
 * and that conversion is <em>not injective</em> over the whole {@code char[]} domain. Two specific
 * classes were measured on OpenJDK 17.0.20.1 by deriving through the raw JCE with a fixed salt and
 * iteration count and comparing digests:
 * <ul>
 *   <li>Trailing NULs are dropped: {@code "cafe"} and {@code "cafe\0"} and {@code "cafe\0\0"} all
 *       derive to the same digest. A user who registers one can be signed in by anyone presenting
 *       another.</li>
 *   <li>Unpaired surrogates are mapped to {@code '?'}: {@code "q"+U+D800}, {@code "q"+U+D801} and
 *       {@code "q"+"?"} all derive identically.</li>
 * </ul>
 * Interior NULs are fine (only trailing ones are dropped) and correctly paired surrogate pairs are
 * fine. Both broken classes are rejected rather than sanitised - trimming would silently change
 * the secret the user typed. {@link PasswordTest} re-derives through the raw JCE to prove the
 * collision is real, so the guard cannot be deleted without a test going red.
 *
 * <h2>What erasure can and cannot buy</h2>
 * Erasing the array shrinks the window in which the plaintext sits in a heap dump or swap file. It
 * is not a guarantee: the JVM is free to have copied the chars during {@code PBEKeySpec}
 * construction, and {@code -Xshare:off}/{@code ZeroGarbageCollectors} are out of scope here. The
 * stronger control is that the plaintext never reaches a String, a log, argv, or the environment.
 * {@link #guard()} exists so a forgotten {@code close()} fails loudly instead of silently keeping
 * the bytes alive.
 */
public final class Password implements AutoCloseable {

    public static final int MIN_CP = 10;
    public static final int MAX_CP = 128;
    /**
     * Hard ceiling on anything we will scan, independent of the policy minimum/maximum.
     * Package-visible and named rather than inlined so the test can assert it is applied as a plain
     * length check <em>before</em> the code-point scan, which is the whole point of it.
     */
    static final int HARD_CAP_CP = 4096;

    private char[] value;
    private final int codePoints;

    private Password(char[] value, int codePoints) {
        this.value = value;
        this.codePoints = codePoints;
    }

    /**
     * Takes ownership of {@code chars} and validates it.
     *
     * <p><b>The array is always consumed.</b> It is erased on every path - accepted, rejected, or
     * exceptional - so a caller can never leak the plaintext by forgetting to clear a rejected
     * buffer, and can never double-use a buffer it handed over. After this call the array belongs
     * to nobody; the caller's own variable reads as an all-NUL array.
     *
     * @return the password, or {@code null} if it violates length or the injectivity rules
     */
    public static Password adopt(char[] chars) {
        if (chars == null) {
            return null;
        }
        try {
            Password result = validate(chars);
            if (result == null) {
                erase(chars);
            }
            return result;
        } catch (RuntimeException unexpected) {
            erase(chars);
            throw unexpected;
        }
    }

    private static Password validate(char[] chars) {
        if (chars.length > HARD_CAP_CP) {
            return null;
        }
        int cp = 0;
        int i = 0;
        while (i < chars.length) {
            char c = chars[i];
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= chars.length || !Character.isLowSurrogate(chars[i + 1])) {
                    return null; // unpaired high surrogate: collides with every other unpaired one
                }
                i += 2;
            } else if (Character.isLowSurrogate(c)) {
                return null; // unpaired low surrogate
            } else {
                i += 1;
            }
            cp++;
            if (cp > HARD_CAP_CP) {
                return null;
            }
        }
        if (cp < MIN_CP || cp > MAX_CP) {
            return null;
        }
        // NUL anywhere. Trailing NULs collide under PBEKeySpec (see class docs); interior ones are
        // a truncation and smuggling hazard that no real password needs.
        for (char c : chars) {
            if (c == 0) {
                return null;
            }
        }
        // Newline or CR would let a password forge extra lines in any text sink we ever write to.
        for (char c : chars) {
            if (c == '\n' || c == '\r') {
                return null;
            }
        }
        return new Password(chars, cp);
    }

    /** Copies, for callers that must keep their own buffer (e.g. a console buffer being reused). */
    public static Password copyOf(char[] chars) {
        if (chars == null) {
            return null;
        }
        return adopt(chars.clone());
    }

    /**
     * The live characters, valid only until {@link #close()}. Callers must not copy it into a
     * {@code String} and must not retain it.
     */
    public char[] chars() {
        char[] v = value;
        if (v == null) {
            throw new IllegalStateException("password has been erased");
        }
        return v;
    }

    public int codePointLength() {
        return codePoints;
    }

    /** Length only - never the bytes. */
    @Override
    public String toString() {
        return "Password[len=" + codePoints + "]";
    }

    @Override
    public void close() {
        char[] v = value;
        if (v != null) {
            erase(v);
            value = null;
        }
    }

    /**
     * Fails if the secret is still resident. Call at the end of any operation that adopted a
     * password; a leak then becomes a loud failure instead of an invisible one.
     */
    public void guard() {
        if (value != null) {
            throw new IllegalStateException("password was not erased before the operation ended");
        }
    }

    static void erase(char[] a) {
        if (a != null) {
            java.util.Arrays.fill(a, '\0');
        }
    }
}
