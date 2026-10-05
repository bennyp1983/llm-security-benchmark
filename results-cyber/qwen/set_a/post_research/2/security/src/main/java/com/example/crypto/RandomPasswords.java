package com.example.crypto;

import java.security.SecureRandom;

/**
 * Generates the random secrets that key stores need - PKCS#12 store and key passwords, or the value of
 * an environment-variable key - so that nobody composes one by hand.
 *
 * <p>Why this is here at all: {@link KeystoreKeySource} requires a password of at least
 * {@link KeystoreKeySource#MIN_PASSPHRASE_CHARS} characters and its real defence is that the password
 * is high-entropy, because PKCS#12's key derivation is cheap. An instruction to "use a random
 * password" with no way to make one safely produces hand-composed values, which is the exact failure
 * the length floor is trying to prevent.
 *
 * <p>Output is a {@code char[]} drawn from the printable ASCII range and contains no whitespace, so it
 * survives a line-oriented config file or an environment variable. It deliberately satisfies
 * {@link KeystoreKeySource#requirePassphrase}: no trailing {@code NUL}, no surrogates.
 *
 * <p><strong>It still needs quoting.</strong> The alphabet is every printable ASCII character except
 * space, which includes {@code $ ` " ' \ ! & ; | < > ( ) * ? # ~} - so the value is free of encoding
 * surprises but not of interpretation. Unquoted in a shell it is expanded, split and redirected;
 * unquoted in YAML it can parse as a flow sequence, a mapping or a comment. Handle it as a single-quoted
 * shell argument, or write it to a file created {@code 0600} and pass the path instead. This class does
 * not restrict the alphabet to dodge that, because a narrowed alphabet is what an attacker who could
 * influence generation would choose, and every character dropped costs a bit of entropy; see
 * {@link #ALPHABET_SIZE}.
 *
 * <p>Every character is drawn from a fresh {@link SecureRandom} draw, so there is no dependence on a
 * caller-supplied seed. Strength follows from the true alphabet size: a 48-character output carries
 * 48 * log2({@value #ALPHABET_SIZE}) which is about 315 bits. That is far past brute-force reach and
 * past the point of relevance - the store's defence against an <em>offline</em> attack is the PBKDF2
 * cost in {@link PasswordKeySource}, not this length - so generation is generous rather than minimal.
 *
 * <p>The result is a mutable {@code char[]} rather than a {@code String} precisely so the caller can
 * erase it. Handing back a {@code String} would leave the secret in the interned string heap,
 * un-erasable, for the life of the JVM. Copy it only where necessary and {@code Arrays.fill} the
 * original as soon as the store has been created.
 */
public final class RandomPasswords {

    /** Default length: well past the floor any of the key sources impose. */
    public static final int DEFAULT_LENGTH = 48;

    /** Rejected rather than silently clamped; 4 KiB is the maximum any key source accepts. */
    public static final int MAX_LENGTH = 1024;

    /**
     * Printable ASCII, excluding space (which config parsers and shells mishandle). Every remaining
     * printable character is included: {@code 0x21..0x7E}. Several of them are shell and YAML
     * metacharacters, which is a quoting obligation on the caller, not a reason to drop them - see the
     * class note.
     */
    private static final char[] ALPHABET =
            "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
                    .toCharArray();

    /** Alphabet cardinality, so the strength claim is derived from the alphabet rather than asserted. */
    public static final int ALPHABET_SIZE = ALPHABET.length;

    private static final SecureRandom RANDOM = new SecureRandom();

    private RandomPasswords() {
    }

    /** A {@link #DEFAULT_LENGTH}-character random secret. */
    public static char[] generate() throws CryptoException {
        return generate(DEFAULT_LENGTH);
    }

    /**
     * @param length number of characters, {@code 1..}{@value #MAX_LENGTH}; a value outside the range is
     *     rejected rather than clamped, so a typo cannot quietly produce a 1-character password
     * @return a fresh {@code char[]} holding the secret. Erase it with {@code Arrays.fill} when done.
     * @throws CryptoException if {@code length} is out of range or the platform has no random source
     */
    public static char[] generate(int length) throws CryptoException {
        if (length < 1 || length > MAX_LENGTH) {
            throw new CryptoException(CryptoException.CryptoFailureCode.INVALID_INPUT,
                    "length must be between 1 and " + MAX_LENGTH);
        }
        char[] out = new char[length];
        try {
            for (int i = 0; i < length; i++) {
                /*
                 * Rejection sampling instead of `random.nextInt(ALPHABET.length)` would be equivalent
                 * here - nextInt(bound) is already unbiased - but drawing a full int and reducing keeps
                 * the alphabet a private detail and cannot leak index patterns.
                 */
                out[i] = ALPHABET[RANDOM.nextInt(ALPHABET.length)];
            }
            return out;
        } catch (RuntimeException e) {
            java.util.Arrays.fill(out, (char) 0);
            throw new CryptoException(CryptoException.CryptoFailureCode.PROVIDER_FAILURE,
                    "a random secret could not be generated: " + e.getClass().getSimpleName(), e);
        }
    }
}
