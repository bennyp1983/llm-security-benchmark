package com.example.auth;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Textual input validation for the two client-controlled strings this component accepts.
 *
 * <p>Both checks are fail-closed: anything not explicitly allowed is rejected, there is no
 * normalisation that could fold two different inputs onto the same account, and no rejection ever
 * echoes the offending value.
 */
public final class InputValidator {

    /** Longest username accepted. */
    public static final int MAX_USERNAME_CODEPOINTS = 64;

    /**
     * Shortest username accepted. Kept at two because length is not a security control here -- names
     * are matched exactly, never folded -- so the validator refuses only the degenerate one-character
     * form, which is what survives a truncated copy-paste and invites collisions during log review.
     */
    public static final int MIN_USERNAME_CODEPOINTS = 2;

    /** Shortest password accepted. */
    public static final int MIN_PASSWORD_CODEPOINTS = 10;

    /** Longest password accepted. */
    public static final int MAX_PASSWORD_CODEPOINTS = 256;

    /** Longest source-address string accepted before parsing. */
    public static final int MAX_SOURCE_ADDRESS_CHARS = 45;

    private static final int MAX_UTF8_BYTES_PER_CODEPOINT = 4;

    /**
     * Ceiling on what {@link #encodePassword(char[])} will attempt, so the sizing arithmetic in that
     * method cannot overflow an {@code int}. {@link #MAX_PASSWORD_CODEPOINTS} is far below it; the
     * ceiling is what keeps the guarantee true for a caller that hands over a bigger buffer.
     */
    private static final int MAX_ENCODABLE_CHARS = 1 << 20;

    private InputValidator() {
    }

    /**
     * Parses a source address textually and returns its canonical form, or {@code null} when the
     * value is not a bare IPv4/IPv6 literal.
     *
     * <p>Textual parsing is deliberate: {@link InetAddress#getByName(String)} is forbidden here
     * because it resolves hostnames, and accepting a hostname would let a client rotate its address
     * bucket by pointing additional DNS names at one host. The checks below reject every value the
     * JDK would otherwise accept as a literal that is not a plain address, in particular:
     * <ul>
     *   <li>hostnames and anything else requiring resolution;</li>
     *   <li>IPv6 zone identifiers ({@code fe80::1%eth0}) - the name after {@code %} is caller
     *       chosen, so it would reintroduce hostnames and make buckets forgeable;</li>
     *   <li>URL-looking values carrying a scheme, port, path or query;</li>
     *   <li>bracketed forms ({@code [::1]}), surrounding whitespace, control characters, NUL.</li>
     * </ul>
     *
     * <p>Remaining risk, documented in the README: raw literal addresses cannot distinguish
     * clients behind one NAT gateway or behind a shared proxy, so the per-source budget is shared
     * by everyone appearing to come from the same address. Deployments behind a proxy must pass the
     * real client address; whatever that value is, it is still validated here before use.
     */
    public static String normalizeSourceAddress(String raw) {
        String literalText = normalizeLiteralText(raw);
        if (literalText == null) {
            return null;
        }
        final InetAddress address;
        try {
            address = InetAddress.getByName(literalText);
        } catch (UnknownHostException e) {
            // getByName on a validated literal only fails for a malformed address.
            return null;
        }
        if (!(address instanceof Inet4Address) && !(address instanceof Inet6Address)) {
            return null;
        }
        return canonicalForm(address);
    }

    /**
     * Purely textual check that {@code raw} is a bare IPv4 or IPv6 literal, and nothing else. No
     * name resolution happens here.
     */
    private static String normalizeLiteralText(String raw) {
        if (raw == null) {
            return null;
        }
        if (raw.isEmpty() || raw.length() > MAX_SOURCE_ADDRESS_CHARS) {
            return null;
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            // Control characters and spaces cannot appear in an address; '%', '/' and '@' are the
            // zone-id, CIDR and userinfo forms that would either carry a caller-chosen name or
            // describe a range rather than one host.
            if (c <= 0x20 || c == 0x7f || c == '%' || c == '/' || c == '@' || c == '#') {
                return null;
            }
        }
        boolean v6 = raw.indexOf(':') >= 0;
        if (v6) {
            // A bare IPv6 literal contains only hex digits and colons, plus one embedded strict
            // dotted quad as its tail (the IPv4-mapped form "::ffff:203.0.113.7" that dual-stack
            // stacks and proxies emit for IPv4 peers). Nothing else may contain a dot, which keeps
            // rejecting "::1]", "[::1]" and hostnames containing a colon.
            int lastColon = raw.lastIndexOf(':');
            if (raw.indexOf('.') >= 0) {
                String head = raw.substring(0, lastColon + 1);
                String tail = raw.substring(lastColon + 1);
                if (!isStrictDottedQuad(tail)) {
                    return null;
                }
                for (int i = 0; i < head.length(); i++) {
                    char c = head.charAt(i);
                    boolean allowed = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                            || (c >= 'A' && c <= 'F') || c == ':';
                    if (!allowed) {
                        return null;
                    }
                }
                if (countChar(head, ':') < 2) {
                    return null;
                }
            } else {
                for (int i = 0; i < raw.length(); i++) {
                    char c = raw.charAt(i);
                    boolean allowed = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':';
                    if (!allowed) {
                        return null;
                    }
                }
            }
            if (countChar(raw, ':') < 2) {
                return null;
            }
        } else {
            for (int i = 0; i < raw.length(); i++) {
                char c = raw.charAt(i);
                if ((c < '0' || c > '9') && c != '.') {
                    return null;
                }
            }
            if (countChar(raw, '.') != 3) {
                return null;
            }
        }
        // Java accepts IPv4 literals with fewer than four components (e.g. "3232235777" or
        // "127.1"), which would silently fold several textual forms onto one bucket. Require the
        // strict dotted-quad form with each octet 0-255 and no leading zeros.
        if (!v6 && !isStrictDottedQuad(raw)) {
            return null;
        }
        return raw;
    }

    /**
     * Canonicalises the parsed address so that one host yields one throttle bucket. An IPv4 address
     * submitted in the IPv4-mapped form ({@code ::ffff:203.0.113.7}, which is what a dual-stack stack
     * reports for an IPv4 peer) must land in the same bucket as the dotted-quad spelling, so the
     * mapped prefix is unwrapped. Nothing else is rewritten: {@code ::1} is an IPv6 loopback, not
     * {@code 0.0.0.1}, and folding it would move a real host into another bucket.
     */
    private static String canonicalForm(InetAddress address) {
        if (address instanceof Inet6Address) {
            byte[] bytes = address.getAddress();
            boolean ipv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    ipv4Mapped = false;
                    break;
                }
            }
            if (ipv4Mapped && bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff) {
                try {
                    address = InetAddress.getByAddress(
                            new byte[] {bytes[12], bytes[13], bytes[14], bytes[15]});
                } catch (UnknownHostException e) {
                    return null;
                }
            }
        }
        String canonical = address.getHostAddress();
        if (canonical == null || canonical.isEmpty()) {
            return null;
        }
        // The canonical form must itself be re-acceptable; if it were not, an event line naming it
        // would later be refused and the audit trail would be inconsistent with the decision.
        if (!canonical.equals(normalizeLiteralText(canonical))) {
            return null;
        }
        return canonical;
    }

    /**
     * Validates a username. Returns the value unchanged on success, {@code null} on rejection.
     *
     * <p>Allowed: Unicode letters and decimal digits as {@link Character#isLetterOrDigit(int)}
     * defines them, plus {@code . _ - @}. Rejected: empty, shorter than
     * {@value #MIN_USERNAME_CODEPOINTS} or longer than {@value #MAX_USERNAME_CODEPOINTS} code points,
     * a leading or trailing {@code .} or {@code -}, a trailing {@code _}, any {@code ..}, control
     * characters, spaces, combining marks, emoji, and any code point outside the allowed set. A
     * leading {@code _} is allowed: it is a common identifier prefix and, unlike {@code .} or
     * {@code -}, is never a separator, so it cannot fold two different names onto one.
     *
     * <p>Deliberately absent: case folding and Unicode normalisation. They are what make
     * {@code Admin} / {@code admin} and precomposed / decomposed names collide, so the comparison
     * here is exact and byte-for-byte after validation.
     *
     * <p><b>What that does not do.</b> Because {@code isLetterOrDigit} is Unicode-wide, a name
     * written in another script survives - a Cyrillic {@code U+0430} is not refused as a homoglyph
     * of the Latin {@code U+0061}. No folding happens anywhere else either: the credential lookup,
     * the throttle key and the logged account hash all compare ASCII case only, so a look-alike
     * name is a <em>different</em> account with its own bucket and its own {@code account_id},
     * never a way to reach or shadow someone else's. The exposure left over is a human one - two
     * records in the operator's own file can look alike on screen - which is why names come from
     * that file and not from self-service registration. Suite 1 pins both halves: that such a name
     * is accepted, and that it never resolves to a Latin account.
     */
    public static String validateUsername(String raw) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        if (raw.length() > MAX_USERNAME_CODEPOINTS * 2) {
            return null;
        }
        if (!isAllowedUsernameText(raw)) {
            return null;
        }
        int codePoints = raw.codePointCount(0, raw.length());
        if (codePoints < MIN_USERNAME_CODEPOINTS || codePoints > MAX_USERNAME_CODEPOINTS) {
            return null;
        }
        if (raw.indexOf("..") >= 0) {
            return null;
        }
        int first = raw.codePointAt(0);
        if (!isLetterOrDigit(first) && first != '_') {
            return null;
        }
        int last = raw.offsetByCodePoints(0, codePoints - 1);
        if (!isLetterOrDigit(raw.codePointAt(last))) {
            return null;
        }
        return raw;
    }

    /** Returns {@code true} when {@code candidate} is a username this validator accepts. */
    public static boolean isValidUsername(String candidate) {
        return validateUsername(candidate) != null;
    }

    /**
     * Validates a password and returns a private copy of its characters. The caller's array is
     * never retained, and the caller must wipe its own copy.
     *
     * <p>Rejects: {@code null}; any character below {@code U+0021} or exactly {@code U+007F}, checked
     * before the length rules so a zero-filled buffer cannot qualify as a long-enough password;
     * length outside {@value #MIN_PASSWORD_CODEPOINTS}..{@value #MAX_PASSWORD_CODEPOINTS} code points
     * (so a trailing tab or NUL can never be silently stripped to reach a valid password, and no
     * control character can inject a log record); unpaired surrogates; and any character that the
     * required encoding cannot represent exactly.
     *
     * @throws AuthException with {@link Diagnostic#PASSWORD_ENCODING_UNSUPPORTED} when the value
     *     contains code points that cannot survive the UTF-8 encoding used for hashing. Accepting
     *     them would make two different passwords hash identically.
     */
    public static char[] validatePassword(char[] raw) throws AuthException {
        if (raw == null) {
            throw new AuthException(Diagnostic.PASSWORD_ENCODING_UNSUPPORTED);
        }
        if (raw.length == 0) {
            throw new AuthException(Diagnostic.PASSWORD_TOO_SHORT);
        }
        // First, whatever the length: a single disallowed character anywhere makes the credential
        // unusable, and scanning now is what stops an all-NUL buffer from being accepted on the
        // strength of its size alone.
        for (char c : raw) {
            if (c < 0x21 || c == 0x7f) {
                throw new AuthException(Diagnostic.PASSWORD_CONTROL_CHARACTER);
            }
        }
        if (raw.length < MIN_PASSWORD_CODEPOINTS || raw.length > MAX_PASSWORD_CODEPOINTS * 2) {
            throw new AuthException(Diagnostic.PASSWORD_TOO_SHORT);
        }
        int codePoints = 0;
        for (int i = 0; i < raw.length;) {
            char high = raw[i];
            if (Character.isSurrogate(high)) {
                if (!Character.isHighSurrogate(high)) {
                    throw new AuthException(Diagnostic.PASSWORD_ENCODING_UNSUPPORTED);
                }
                if (i + 1 >= raw.length || !Character.isLowSurrogate(raw[i + 1])) {
                    throw new AuthException(Diagnostic.PASSWORD_ENCODING_UNSUPPORTED);
                }
                i += 2;
            } else {
                i += 1;
            }
            codePoints++;
        }
        if (codePoints < MIN_PASSWORD_CODEPOINTS || codePoints > MAX_PASSWORD_CODEPOINTS) {
            throw new AuthException(Diagnostic.PASSWORD_TOO_SHORT);
        }
        byte[] encoded = encodePassword(raw);
        char[] copy = new char[raw.length];
        System.arraycopy(raw, 0, copy, 0, raw.length);
        java.util.Arrays.fill(encoded, (byte) 0);
        return copy;
    }

    /**
     * Encodes a password as UTF-8 exactly as it will be hashed.
     *
     * <p><b>No copy of the credential is ever made immutable.</b> The obvious implementation -
     * {@code new String(raw).getBytes(UTF_8)} and a round trip back to a String - leaves the
     * password in two {@code String}s that cannot be wiped and linger until the collector moves
     * them, which is exactly what rule 5 asks to be narrowed. This instead encodes straight out of
     * the caller's {@code char[]} through a reporting {@link CharsetEncoder}, so a character the
     * encoding cannot represent is <em>reported</em> rather than silently replaced, and every buffer
     * that holds plaintext is a zeroed array.
     *
     * <p>The refusal matters for correctness, not only hygiene: {@link String#getBytes(java.nio.charset.Charset)}
     * never throws, it substitutes {@code '?'}. Without the report, {@code "caf\u00e9"} under a lossy
     * encoding and a literal {@code "caf?"} produce the same digest and become interchangeable
     * credentials. An unpaired surrogate is refused by the same mechanism.
     *
     * @throws AuthException when the value cannot be encoded byte-for-byte exactly
     */
    public static byte[] encodePassword(char[] raw) throws AuthException {
        if (raw == null) {
            throw new AuthException(Diagnostic.PASSWORD_ENCODING_UNSUPPORTED);
        }
        // Bounded so the sizing arithmetic below cannot overflow; far above any password this
        // component accepts.
        if (raw.length > MAX_ENCODABLE_CHARS) {
            throw new AuthException(Diagnostic.PASSWORD_ENCODING_UNSUPPORTED);
        }
        // UTF-8 needs at most three bytes per UTF-16 code unit (a surrogate pair is two units for
        // four bytes), so this buffer cannot overflow.
        byte[] oversized = new byte[Math.max(1, raw.length * 3)];
        byte[] encoded;
        CharBuffer input = CharBuffer.wrap(raw);
        ByteBuffer output = ByteBuffer.wrap(oversized);
        try {
            CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            CoderResult result = encoder.encode(input, output, true);
            if (!result.isUnderflow()) {
                throw new AuthException(Diagnostic.PASSWORD_ENCODING_UNSUPPORTED);
            }
            if (!encoder.flush(output).isUnderflow()) {
                throw new AuthException(Diagnostic.PASSWORD_ENCODING_UNSUPPORTED);
            }
            int written = output.position();
            if (oversized.length == written) {
                encoded = oversized;
            } else {
                encoded = new byte[written];
                System.arraycopy(oversized, 0, encoded, 0, written);
            }
        } catch (RuntimeException e) {
            java.util.Arrays.fill(oversized, (byte) 0);
            throw new AuthException(Diagnostic.PASSWORD_ENCODING_UNSUPPORTED);
        }
        java.util.Arrays.fill(oversized, (byte) 0);
        if (encoded.length == 0) {
            java.util.Arrays.fill(encoded, (byte) 0);
            throw new AuthException(Diagnostic.PASSWORD_TOO_SHORT);
        }
        return encoded;
    }

    static List<String> immutableCopy(List<String> values) {
        return Collections.unmodifiableList(new ArrayList<>(values));
    }

    private static boolean isAllowedUsernameText(String raw) {
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c <= 0x20 || c == 0x7f) {
                return false;
            }
            if (c == '.' || c == '_' || c == '-' || c == '@') {
                continue;
            }
            if (!isLetterOrDigit(c)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Letter-or-digit test that excludes combining marks and other non-spacing characters, which
     * render invisibly on top of a preceding character and are a classic look-alike account trick.
     */
    private static boolean isLetterOrDigit(int codePoint) {
        if (codePoint < 0x80) {
            return (codePoint >= 'a' && codePoint <= 'z')
                    || (codePoint >= 'A' && codePoint <= 'Z')
                    || (codePoint >= '0' && codePoint <= '9');
        }
        if (!Character.isLetterOrDigit(codePoint)) {
            return false;
        }
        int type = Character.getType(codePoint);
        return type != Character.NON_SPACING_MARK
                && type != Character.COMBINING_SPACING_MARK
                && type != Character.ENCLOSING_MARK
                && type != Character.FORMAT
                && type != Character.PRIVATE_USE
                && type != Character.SURROGATE
                && type != Character.UNASSIGNED;
    }

    private static boolean isStrictDottedQuad(String raw) {
        int octet = 0;
        int digits = 0;
        int octetsSeen = 0;
        // The virtual terminator below is what catches a leading zero in the *last* octet: with the
        // check only at a real '.', "203.0.113.07" slips through, and the JDK folds it onto
        // "203.0.113.7", hiding two spellings of one host behind one accepted literal.
        for (int i = 0; i <= raw.length(); i++) {
            char c = i < raw.length() ? raw.charAt(i) : '.';
            if (c == '.') {
                if (digits == 0 || digits > 3) {
                    return false;
                }
                if (digits > 1 && raw.charAt(i - digits) == '0') {
                    return false;
                }
                if (octet > 255) {
                    return false;
                }
                octetsSeen++;
                octet = 0;
                digits = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
                digits++;
                if (digits > 3) {
                    return false;
                }
            } else {
                return false;
            }
        }
        return octetsSeen == 4;
    }

    private static int countChar(String value, char target) {
        int n = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == target) {
                n++;
            }
        }
        return n;
    }
}
