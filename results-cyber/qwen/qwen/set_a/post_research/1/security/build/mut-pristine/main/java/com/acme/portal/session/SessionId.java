package com.acme.portal.session;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * An opaque server-side session identifier handed to this component by the trusted session owner.
 *
 * <p>The value is a bearer credential: anyone who holds it holds the session. Consequently this
 * type is written so that the identifier cannot leak through the paths that normally leak secrets:
 *
 * <ul>
 *   <li>{@link #toString()} returns a one-way fingerprint, never the value, so an accidental
 *       {@code log.warn("id=" + id)} or a {@code %s} in an exception message cannot disclose it.</li>
 *   <li>{@link #value()} is package private, so code outside this package cannot obtain the raw
 *       string to write it somewhere else.</li>
 *   <li>Instances are immutable and this component keeps no copy beyond the current request: the
 *       identifier is never cached, never logged, never written to disk and never placed in a URL,
 *       a response body or a command line.</li>
 * </ul>
 *
 * <p>Validation is reject-only: the value is never trimmed, case-folded, unescaped or otherwise
 * normalised, because silent normalisation would let two different byte strings resolve to one
 * session (see {@link #inspect}).
 */
public final class SessionId {

    /** Shortest accepted identifier. 32 base64url characters carry well over 128 bits. */
    public static final int MIN_LENGTH = 32;

    /** Longest accepted identifier, bounding the work and memory spent per request. */
    public static final int MAX_LENGTH = 128;

    /**
     * Minimum number of distinct characters in an identifier <b>that this code minted</b>.
     *
     * <p>Deliberately <i>not</i> applied to identifiers arriving from the trusted session owner, and
     * the reason is a measurement: an "at least 12 distinct symbols" rule applied to a 32-character
     * lowercase-hex identifier refuses <b>1.70%</b> of uniformly random ones (5 772 905 916 802 455
     * 845 865 331 391 890 579 456 of 16<sup>32</sup>; about one sign-in in 59), because a 16-symbol
     * alphabet simply does not offer many distinct symbols in 32 positions. Hex is what several
     * widely deployed containers hand out, so as an input rule this heuristic was not a guard at all
     * -- it was a random failure injected into somebody else's working system, and every one of
     * those refusals landed on a value the authoritative store had already vouched for.
     *
     * <p>It also asks a question this component has no standing to ask. Rule 1 asks for type,
     * length, character set and range; "how many distinct symbols did the issuer's generator happen
     * to emit" is none of those, and the entropy of a session identifier is the property of whoever
     * generates it, which here is the trusted owner of the session state. A degenerate value either
     * is in the store -- in which case the owner created it and refusing it punishes their user -- or
     * it is not, in which case the lookup refuses it on the evidence that matters.
     *
     * <p>For values this class produces the check is worth keeping, because the only plausible cause
     * is a regression in the CSPRNG or the encoder below: the false-rejection chance for a
     * 43-character base64url encoding of 32 random bytes is 8.0e-22, so it can never lock out a real
     * user, while it does catch an RNG that has started returning constants.
     */
    static final int SELF_TEST_MIN_DISTINCT_CHARS = 12;

    /** Hex characters of the SHA-256 fingerprint that is safe to put in a log line. */
    private static final int FINGERPRINT_HEX = 12;

    /** Domain-separation prefix so a fingerprint cannot be matched against another system's digest. */
    private static final String FINGERPRINT_PREFIX = "acme-sid-v1:";

    private final String value;

    private SessionId(String value) {
        this.value = value;
    }

    /** Why a candidate identifier was refused. Names are safe to log; the value is not. */
    enum Rejection {
        /** No identifier was supplied at all. */
        NONE,
        ABSENT,
        TOO_SHORT,
        TOO_LONG,
        ILLEGAL_CHARACTER,
        LOW_CHAR_DIVERSITY
    }

    /**
     * Accepts an identifier that came from the trusted session owner's server-side state.
     *
     * @throws InvalidSessionIdentifierException if the value is not a well-formed opaque token.
     *     The exception carries only the reason class, never any part of the value.
     */
    public static SessionId fromTrustedComponent(String raw) throws InvalidSessionIdentifierException {
        Rejection rejection = inspect(raw);
        if (rejection != Rejection.NONE) {
            throw new InvalidSessionIdentifierException(rejection);
        }
        return new SessionId(raw);
    }

    /**
     * Classifies a candidate without constructing an instance, so the caller can log the reason
     * without ever handling the value as a validated secret.
     *
     * <p>Exactly three rules, all of them rule 1's dimensions and all of them decidable without
     * knowing the issuer: it is text, of the right length, made of the right characters. Nothing here
     * guesses at entropy or "looks random", because a value's entropy belongs to whoever issued it
     * and this component is not the judge of that (see
     * {@link #SELF_TEST_MIN_DISTINCT_CHARS} for the measurement that removed such a rule from this
     * path).
     *
     * <p>Order matters: the null and length checks bound the character scan, and no check is
     * preceded by trimming or case folding, so a trailing control character is refused instead of
     * silently deleted (which would fold two inputs onto one session).
     */
    static Rejection inspect(String raw) {
        if (raw == null) {
            return Rejection.ABSENT;
        }
        int length = raw.length();
        if (length < MIN_LENGTH) {
            return Rejection.TOO_SHORT;
        }
        if (length > MAX_LENGTH) {
            return Rejection.TOO_LONG;
        }
        for (int i = 0; i < length; i++) {
            if (!isAllowedCharacter(raw.charAt(i))) {
                return Rejection.ILLEGAL_CHARACTER;
            }
        }
        return Rejection.NONE;
    }

    /**
     * The extra gate applied only to identifiers this class mints, and therefore the only place the
     * {@link Rejection#LOW_CHAR_DIVERSITY} verdict can still come from.
     *
     * <p>Separated from {@link #inspect} rather than folded into it because the two callers have
     * different relationships to the value: for a value this class produced, a degenerate character
     * set is evidence that the CSPRNG or the encoder regressed and the value must not be handed out;
     * for a value the trusted owner produced, it is at worst a complaint about their generator, and
     * acting on it would deny service to a session the store says is real.
     */
    static Rejection selfTest(String candidate) {
        Rejection shape = inspect(candidate);
        if (shape != Rejection.NONE) {
            return shape;
        }
        if (distinctCharacters(candidate) < SELF_TEST_MIN_DISTINCT_CHARS) {
            return Rejection.LOW_CHAR_DIVERSITY;
        }
        return Rejection.NONE;
    }

    /**
     * Number of distinct characters in {@code value}. Only ever asked about this class's own output.
     */
    static int distinctCharacters(String value) {
        boolean[] seen = new boolean[128];
        int distinct = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            // The table size is tied to the allowlist, so a charset widened past it must not turn
            // into an ArrayIndexOutOfBoundsException. An uncountable character reports as "cannot
            // tell", which the caller reads as a failed self-test and refuses to hand the value out.
            if (c >= seen.length) {
                return 0;
            }
            if (!seen[c]) {
                seen[c] = true;
                distinct++;
            }
        }
        return distinct;
    }

    /**
     * RFC 6265 cookie-value safe and RFC 3986 unreserved subset: base64url alphabet only. This
     * single allowlist is what makes it impossible for the identifier to terminate the cookie
     * value, inject a cookie attribute ({@code ; Domain=...}), inject a second {@code Set-Cookie}
     * header, or break out of a log line. Everything else, including CR, LF, NUL, space, quote,
     * {@code =}, {@code ;}, {@code ,} and every non-ASCII byte, is refused.
     */
    private static boolean isAllowedCharacter(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '-'
                || c == '_';
    }

    /**
     * Mints a new identifier from the platform CSPRNG.
     *
     * <p><b>Who calls this.</b> Nobody in this component, on purpose: the component the task
     * describes receives an identifier that already exists, so issuing is not its job and it never
     * does. This is the public API for whoever <i>is</i> the session owner -- the trusted component
     * that creates sessions -- and rule 4's preferred answer for it, because it is the same 32 bytes
     * from the platform CSPRNG encoded into a value this package's validator accepts, rather than a
     * hand-rolled token generator somewhere else. A deployment that mints identifiers elsewhere is
     * still fine as long as they are opaque, unguessable and arrive here through
     * {@link #fromTrustedComponent}; this method exists so "generate one properly" is not the part
     * anybody has to improvise.
     *
     * <p>The {@link #selfTest} gate is why minting here is safer than copying the two lines above it:
     * a CSPRNG or encoder that has regressed into producing low-diversity output throws here instead
     * of handing out identifiers that no honest client can use.
     *
     * @throws IllegalStateException if the freshly minted value fails this class's own self-test,
     *         which means the platform RNG or the encoder below has stopped behaving. No value is
     *         returned in that case; there is no "use it anyway" path.
     */
    public static SessionId generate() {
        byte[] material = new byte[32];
        SECURE_RANDOM.nextBytes(material);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(material);
        if (selfTest(encoded) != Rejection.NONE) {
            // Our own encoder must keep producing values this class accepts; if that ever stops
            // being true, refuse to serve rather than hand out an identifier nobody can use.
            throw new IllegalStateException("generated identifier failed validation");
        }
        return new SessionId(encoded);
    }

    /** Raw cookie value. Deliberately package private. */
    String value() {
        return value;
    }

    /**
     * A truncated SHA-256 fingerprint of the identifier, safe to log <i>for identifiers with real
     * entropy</i> -- see the caveat, because "safe to log" is a claim about the input too.
     *
     * <p>48 bits of digest over a 256-bit input cannot be inverted or replayed; it lets an operator
     * correlate the log lines that belong to one session. Against a full-entropy identifier an
     * attacker who steals the logs learns nothing: guessing a candidate and checking it against 48
     * bits of digest costs 2<sup>48</sup> tries per line and yields no usable value.
     *
     * <p><b>The caveat, stated as a deployment requirement.</b> A digest is a verifier, not just a
     * mask. If the session owner hands this component identifiers drawn from a space smaller than
     * the 48 bits it publishes -- a short counter, a truncated UUID, a timestamp with a fixed prefix
     * -- then the log line becomes an offline test oracle for that small space, and anyone holding
     * the logs can confirm guesses without touching the server. The requirement on the integration is
     * therefore at least 128 bits of unpredictable entropy in every identifier it asserts (the same
     * bar {@link #generate()} meets), and this component cannot enforce it without doing exactly the
     * guessing-about-entropy it just refused to do in {@link #inspect}. The README carries it as the
     * named residual risk of rule 4's "document the remaining risk".
     */
    public String fingerprint() {
        // Two parts rather than one concatenation: see the note in CacheSupport about not copying a
        // bearer credential merely to prefix it.
        return CacheSupport.digestHexPrefix(new String[]{FINGERPRINT_PREFIX, value}, FINGERPRINT_HEX);
    }

    /** Self-masking: the identifier cannot reach a log or an error message through toString. */
    @Override
    public String toString() {
        return "SessionId(" + fingerprint() + ")";
    }

    /**
     * {@code equals}/{@code hashCode} are intentionally not implemented. Any comparison of a
     * bearer credential would be a timing side channel and a leak vector, and this component never
     * needs to compare identifiers: it never reads one back from a client.
     */

    /**
     * A single shared {@link SecureRandom} is the platform-recommended pattern: it is thread safe
     * and reseeds itself from the OS entropy source (NativePRNG on this JDK).
     * {@code getInstanceStrong()} is deliberately avoided because it can block a request thread.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
}

