package com.example.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Renders the account field of an audit record.
 *
 * <p>The username is never written to the log. What is written instead is
 * {@code account_id=<64 hex chars>} - the SHA-256 of the submitted name, ASCII-lower-cased - plus
 * {@code account_hint=<distinct-codepoint-count>} and {@code account_present=true|false}.
 *
 * <p>Why this is safe to keep:
 * <ul>
 *   <li>It is one-way. A log reader cannot recover the name, so a leaked log is not a list of
 *       accounts. The hash is <em>not</em> keyed: an offline dictionary of candidate names can be
 *       hashed and compared, which is why the README lists unsalted account identifiers as residual
 *       risk and why the field exists at all - the alternative is a log that cannot be searched.</li>
 *   <li>It is computed from the <em>submitted</em> text in every code path, so it never depends on
 *       the outcome of the check and cannot tell an attacker anything they can also learn from the
 *       response.</li>
 *   <li>Lower-casing makes {@code Alice} and {@code alice} the same identifier, matching the
 *       store's one-record-per-name rule.</li>
 *   <li>The hint is a number in {@code 0..32}, derived only from the submitted text; it exists so
 *       an operator can tell "one account probed many times" from "many names probed once" without
 *       storing the names.</li>
 * </ul>
 */
final class AccountField {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private AccountField() {
    }

    static String render(String submittedUsername, boolean present) {
        return "account_id=" + accountId(submittedUsername)
                + " account_hint=" + distinctCodePoints(submittedUsername)
                + " account_present=" + (present ? "true" : "false");
    }

    static String accountId(String username) {
        if (username == null) {
            return repeat('0', 64);
        }
        byte[] canonical = lowerAscii(username).getBytes(StandardCharsets.UTF_8);
        final byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(canonical);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is required of every conformant JRE; reaching this means the platform is
            // broken and the attempt must not be logged with a guess.
            throw new IllegalStateException(e);
        }
        char[] out = new char[digest.length * 2];
        for (int i = 0; i < digest.length; i++) {
            int b = digest[i] & 0xff;
            out[i * 2] = HEX[b >>> 4];
            out[i * 2 + 1] = HEX[b & 0x0f];
        }
        return new String(out);
    }

    /**
     * Renders the size hint: how many <em>distinct</em> code points the submitted name used.
     *
     * <p>The set is a fixed 256-bit sketch rather than an exact set, so it saturates at 32 and two
     * very different names can share a value. That is deliberate: the field exists to let a reviewer
     * spot "this name reuses one character 40 times" without storing the name itself, and a
     * collision loses nothing while an exact count would leak the alphabet of a name the log must
     * not contain.
     */
    private static final int MAX_DISTINCT_CODE_POINT_HINT = 32;

    static int distinctCodePoints(String username) {
        if (username == null || username.isEmpty()) {
            return 0;
        }
        int[] seen = new int[8];
        int count = 0;
        int length = username.length();
        for (int i = 0; i < length;) {
            int cp = username.codePointAt(i);
            i += Character.charCount(cp);
            int slot = (cp >>> 5) & 7;
            int bit = cp & 31;
            int mask = 1 << bit;
            if ((seen[slot] & mask) != 0) {
                continue;
            }
            seen[slot] |= mask;
            count++;
            if (count == MAX_DISTINCT_CODE_POINT_HINT) {
                // Saturation, not truncation of the loop: a 40-character name and a 400-character
                // name must not be distinguishable by this field.
                return MAX_DISTINCT_CODE_POINT_HINT;
            }
        }
        return count;
    }

    private static String lowerAscii(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + 32);
            }
            out.append(c);
        }
        return out.toString();
    }

    private static String repeat(char c, int times) {
        char[] out = new char[times];
        java.util.Arrays.fill(out, c);
        return new String(out);
    }
}
