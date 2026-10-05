package com.example.identity;

import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Validated identity strings.
 *
 * <p>Every instance is produced by {@link #parseClientUsername}, {@link #parseClientEmail},
 * {@link #fromStoredUsername} or {@link #fromStoredEmail}. There is no other route to one, so
 * holding this type is proof the value passed validation; callers use it without re-checking and
 * cannot receive an unvalidated value by accident.
 *
 * <p>Two distinct paths on purpose:
 * <ul>
 *   <li><b>client input</b> ({@code parseClient*}) - tolerates surrounding U+0020 only, then
 *       applies the full grammar. Returns {@code null} on anything unacceptable.</li>
 *   <li><b>stored input</b> ({@code fromStored*}) - the database is treated as attacker-controlled
 *       (Rule 1), so the value must <em>already</em> be exactly what our own writer would have
 *       produced: no trimming, no normalisation, strict grammar. A non-conforming row is rejected,
 *       not repaired, and the caller answers with the same generic refusal used for a wrong
 *       password.</li>
 * </ul>
 *
 * <p>Case folding is ASCII-only via {@link Locale#ROOT}. Two consequences are intentional: no
 * locale-dependent fold (the Turkish dotted/dotless I), and non-ASCII is refused outright, which
 * removes the homoglyph impersonation class (Cyrillic U+0430 vs Latin "a") entirely.
 * Internationalised addresses are therefore unsupported - see README "Limitations".
 */
public record Identity(String canonical, Kind kind) {

    public enum Kind { USERNAME, EMAIL }

    public static final int USERNAME_MIN_CP = 3;
    public static final int USERNAME_MAX_CP = 32;
    public static final int EMAIL_MAX_CP = 254;      // RFC 5321 reverse-path limit
    public static final int EMAIL_LOCAL_MAX_CP = 64; // RFC 5321 local-part limit
    /** Nothing hostile gets scanned past this, whatever the transport claims. */
    static final int HARD_INPUT_CAP_CP = 4096;

    private static final Pattern USERNAME_PATTERN =
            Pattern.compile("[a-z0-9][a-z0-9._-]{1,30}[a-z0-9]");

    public Identity {
        // Invariants are asserted here and not only in the factories: a record is reachable by
        // reflection, and a canonical constructor that trusts its caller is a way in.
        if (canonical == null || kind == null) {
            throw new IllegalArgumentException("identity components are required");
        }
        if (canonical.isEmpty() || canonical.length() > HARD_INPUT_CAP_CP) {
            throw new IllegalArgumentException("identity length out of range");
        }
        if (containsControlOrDel(canonical) || !isAllAsciiPrintable(canonical)) {
            throw new IllegalArgumentException("identity character set violated");
        }
        requireAsciiOnly(canonical);
        if (kind == Kind.USERNAME) {
            int cp = canonical.codePointCount(0, canonical.length());
            if (cp < USERNAME_MIN_CP || cp > USERNAME_MAX_CP) {
                throw new IllegalArgumentException("username length out of range");
            }
            if (!USERNAME_PATTERN.matcher(canonical).matches()) {
                throw new IllegalArgumentException("username grammar violated");
            }
            // "admin." and "admin-" are distinct accounts to the grammar above but read as the
            // same name to a human, and ".." can smuggle a label. Refuse the ambiguous forms.
            if (canonical.contains("..")) {
                throw new IllegalArgumentException("username has misplaced dot");
            }
        } else {
            requireEmailGrammar(canonical);
        }
    }

    private static void requireAsciiOnly(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 0x7E) {
                throw new IllegalArgumentException("non-ASCII is not accepted");
            }
        }
    }

    private static void requireEmailGrammar(String s) {
        int cp = s.codePointCount(0, s.length());
        if (cp < 5 || cp > EMAIL_MAX_CP) {
            throw new IllegalArgumentException("email length out of range");
        }
        int at = s.indexOf('@');
        // Exactly one '@'. Rejecting "alice@corp@evil" outright (rather than taking the first or
        // the last '@') is what stops it being treated as alice@corp.
        if (at < 1 || at != s.lastIndexOf('@') || at == s.length() - 1) {
            throw new IllegalArgumentException("email must contain exactly one @");
        }
        String local = s.substring(0, at);
        String domain = s.substring(at + 1);
        if (local.isEmpty() || local.length() > EMAIL_LOCAL_MAX_CP) {
            throw new IllegalArgumentException("email local-part length out of range");
        }
        if (local.charAt(0) == '.' || local.charAt(local.length() - 1) == '.' || local.contains("..")) {
            throw new IllegalArgumentException("email local-part has misplaced dot");
        }
        for (int i = 0; i < local.length(); i++) {
            if (!isLocalCharAllowed(local.charAt(i))) {
                throw new IllegalArgumentException("email local-part character not allowed");
            }
        }
        requireDomainGrammar(domain);
    }

    /**
     * A subset of RFC 5321 dot-atom-text: no {@code !#$%&'*+/=?^_`{|}~-}. Those are legal in an
     * address and useless to us, and several are load-bearing in shells, URLs and config files.
     * Accepting less than the standard is safe; the reverse is not. {@code +} is kept because
     * tag-addressing ({@code user+news@}) is common real-world input we must not silently reject.
     */
    private static boolean isLocalCharAllowed(char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '.' || c == '_' || c == '-' || c == '+';
    }

    private static void requireDomainGrammar(String domain) {
        if (domain.isEmpty() || domain.length() > 253) {
            throw new IllegalArgumentException("email domain length out of range");
        }
        // Bracketed literals ([192.0.2.1]) and anything that looks like a path, URL or Windows
        // share are rare in real mail and are pure attack surface.
        if (indexOfAny(domain, "[]/\\:@") >= 0) {
            throw new IllegalArgumentException("email domain form not allowed");
        }
        // split() takes a regex: "." would match every character and silently validate nothing.
        String[] labels = domain.split("\\.", -1);
        if (labels.length < 2) {
            // Nothing routable; also refuses a bare "localhost", which would otherwise let a
            // registrant claim an address that can never leave this host.
            throw new IllegalArgumentException("email domain must be fully qualified");
        }
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63) {
                throw new IllegalArgumentException("email domain label length out of range");
            }
            if (label.charAt(0) == '-' || label.charAt(label.length() - 1) == '-') {
                throw new IllegalArgumentException("email domain label has misplaced hyphen");
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                if (!ok) {
                    throw new IllegalArgumentException("email domain label character not allowed");
                }
            }
        }
        String tld = labels[labels.length - 1];
        if (tld.length() < 2) {
            throw new IllegalArgumentException("email domain TLD too short");
        }
        // An all-numeric TLD is a mistyped IP address, not a domain.
        for (int i = 0; i < tld.length(); i++) {
            char c = tld.charAt(i);
            if (c < 'a' || c > 'z') {
                throw new IllegalArgumentException("email domain TLD must be alphabetic");
            }
        }
    }

    // ---------------------------------------------------------------- client input

    /**
     * The raw-form gate, run <em>before</em> case folding.
     *
     * <p>{@link String#toLowerCase(Locale)} is not ASCII-preserving in one direction only: it can
     * map a non-ASCII character <em>into</em> ASCII. U+212A KELVIN SIGN folds to "k" - measured on
     * this JDK, and it is the only character in U+0080..U+FFFF whose {@code ROOT} lowercase is pure
     * ASCII alnum. Checking the character set on the folded string alone therefore lets exactly one
     * homoglyph through, and it is silently <em>substituted</em>: {@code Kab<U+212A>ram} was
     * accepted and stored as {@code kabkram}, which is the opposite of Rule 6's "reject invalid
     * input - never substitute a permissive default". Rejecting the raw form first removes the
     * whole class rather than the one character, and it is the same check the record already applies
     * - just applied to bytes the caller actually typed instead of bytes we produced.
     */
    private static boolean rawFormIsAcceptable(String s) {
        return !containsControlOrDel(s) && isAllAsciiPrintable(s);
    }

    public static Identity parseClientUsername(String raw) {
        String s = stripSurroundingSpacesOnly(raw);
        if (s == null || !rawFormIsAcceptable(s)) {
            return null;
        }
        try {
            return new Identity(s.toLowerCase(Locale.ROOT), Kind.USERNAME);
        } catch (IllegalArgumentException rejected) {
            return null;
        }
    }

    public static Identity parseClientEmail(String raw) {
        String s = stripSurroundingSpacesOnly(raw);
        if (s == null || !rawFormIsAcceptable(s)) {
            return null;
        }
        String folded = s.toLowerCase(Locale.ROOT);
        // IDN is a rejection oracle only, never a folding rule: a domain that does not survive a
        // punycode round-trip is malformed and gets refused rather than guessed at.
        int at = folded.indexOf('@');
        if (at > 0 && at == folded.lastIndexOf('@')) {
            String domain = folded.substring(at + 1);
            try {
                if (!IDN.toASCII(domain, IDN.USE_STD3_ASCII_RULES).equals(domain)) {
                    return null;
                }
            } catch (IllegalArgumentException notIdn) {
                return null;
            }
        }
        try {
            return new Identity(folded, Kind.EMAIL);
        } catch (IllegalArgumentException rejected) {
            return null;
        }
    }

    /**
     * A form safe to echo back to the operator ("registered address ..."), or {@code null}.
     * Kept out of {@link Identity} so the record stays immutable; it is never used for lookup or
     * comparison, only for display.
     */
    public static String displayForm(String raw) {
        String s = stripSurroundingSpacesOnly(raw);
        if (s == null || s.length() > EMAIL_MAX_CP) {
            return null;
        }
        if (containsControlOrDel(s) || !isAllAsciiPrintable(s)) {
            return null;
        }
        return s;
    }

    // ---------------------------------------------------------------- stored input

    /** Strict re-validation of a value read back from the database. No normalisation at all. */
    public static Identity fromStoredUsername(String stored) {
        if (stored == null) {
            return null;
        }
        try {
            return new Identity(stored, Kind.USERNAME);
        } catch (IllegalArgumentException corruptRow) {
            return null;
        }
    }

    /** Strict re-validation of a value read back from the database. No normalisation at all. */
    public static Identity fromStoredEmail(String stored) {
        if (stored == null) {
            return null;
        }
        try {
            return new Identity(stored, Kind.EMAIL);
        } catch (IllegalArgumentException corruptRow) {
            return null;
        }
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Strips surrounding U+0020 and nothing else.
     *
     * <p>{@code String.trim()} and {@code String.strip()} remove every character {@code <= U+0020},
     * which includes NUL and TAB. For an identity that is a security defect, not cosmetics:
     * {@code "alice" + '\t'} would fold onto the real account "alice", handing out an invisible
     * second form of someone's login. Here the tab survives stripping and is then refused.
     */
    static String stripSurroundingSpacesOnly(String raw) {
        if (raw == null) {
            return null;
        }
        if (raw.length() > HARD_INPUT_CAP_CP) {
            return null;
        }
        int begin = 0;
        int end = raw.length();
        while (begin < end && raw.charAt(begin) == ' ') {
            begin++;
        }
        while (end > begin && raw.charAt(end - 1) == ' ') {
            end--;
        }
        return raw.substring(begin, end);
    }

    static boolean containsControlOrDel(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x21 || c == 0x7F) {
                return true;
            }
        }
        return false;
    }

    private static boolean isAllAsciiPrintable(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 0x7E) {
                return false;
            }
        }
        return true;
    }

    private static int indexOfAny(String s, String chars) {
        for (int i = 0; i < s.length(); i++) {
            if (chars.indexOf(s.charAt(i)) >= 0) {
                return i;
            }
        }
        return -1;
    }

    /** UTF-8 byte length - the unit a VARCHAR column is charged in. */
    public int utf8Length() {
        return canonical.getBytes(StandardCharsets.UTF_8).length;
    }

    /** Never the raw value; this is what a log line is allowed to contain. */
    @Override
    public String toString() {
        return kind + "[len=" + canonical.length() + "]";
    }
}
