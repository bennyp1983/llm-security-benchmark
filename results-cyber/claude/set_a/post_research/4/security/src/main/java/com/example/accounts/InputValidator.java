package com.example.accounts;

import java.nio.CharBuffer;
import java.text.Normalizer;
import java.util.Locale;
import java.util.Set;

/**
 * Validates and canonicalises the three client-controlled registration inputs.
 *
 * <p>Rule 1 (trust boundaries): email, username and password arrive from an untrusted caller, so
 * each is checked for type, length, allowed characters and range <em>before</em> it reaches the
 * database, the hasher or a log line. Checks are allowlists -- anything not explicitly permitted is
 * rejected rather than stripped, escaped or "fixed", because silent repair is how two inputs end up
 * colliding on one account.
 *
 * <p>Rule 5: upper bounds exist on every field so a caller cannot make us store or hash something
 * arbitrarily large.
 */
public final class InputValidator {

    public static final int EMAIL_MAX_LENGTH = 254;      // RFC 5321 path limit
    public static final int EMAIL_LOCAL_MAX_LENGTH = 64;
    public static final int USERNAME_MIN_LENGTH = 3;
    public static final int USERNAME_MAX_LENGTH = 32;
    public static final int PASSWORD_MIN_LENGTH = 12;    // OWASP minimum for human-chosen secrets
    public static final int PASSWORD_MAX_LENGTH = 128;   // bounds hashing work; well above need

    /** Local-part characters we accept. A deliberate subset of RFC 5322 (see README). */
    private static final String LOCAL_EXTRA = "._%+-";

    /** Names that must not be claimable by an ordinary user. */
    private static final Set<String> RESERVED_USERNAMES = Set.of(
            "abuse", "account", "accounts", "admin", "administrator", "anonymous", "api", "billing",
            "guest", "help", "hostmaster", "login", "logout", "me", "moderator", "noreply",
            "no-reply", "null", "operator", "owner", "postmaster", "register", "root", "security",
            "signin", "signup", "support", "system", "undefined", "user", "users", "webmaster");

    /** A small, high-frequency blocklist; see README for wiring a full breached-password list. */
    private static final Set<String> BLOCKED_PASSWORDS = Set.of(
            "123456789012", "passwordpassword", "password1234", "qwertyuiop12", "administrator",
            "iloveyou1234", "letmein12345", "welcome12345", "monkey123456", "dragon123456",
            "football1234", "baseball1234", "sunshine1234", "princess1234", "qwerty123456",
            "abc123456789", "trustno12345", "changeme1234", "secret123456", "superman1234");

    private InputValidator() {
    }

    /**
     * Returns the canonical (lower-cased) address to store and look up by.
     *
     * <p>Canonicalising the whole address, local part included, is a deliberate product decision:
     * it stops {@code Alice@example.com} and {@code alice@example.com} from becoming two accounts
     * that a user cannot tell apart.
     */
    public static String canonicalEmail(String raw) throws ValidationException {
        if (raw == null) {
            throw new ValidationException("Email address is required.");
        }
        String value = raw.strip();
        if (value.isEmpty()) {
            throw new ValidationException("Email address is required.");
        }
        if (value.length() > EMAIL_MAX_LENGTH) {
            throw new ValidationException("Email address must be at most " + EMAIL_MAX_LENGTH + " characters.");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            // ASCII-only: keeps the address free of look-alike Unicode and of anything that could
            // change meaning in a log line, header or SQL/LDAP context downstream.
            if (c < 0x21 || c > 0x7e) {
                throw new ValidationException("Email address contains an unsupported character.");
            }
        }
        int at = value.indexOf('@');
        if (at < 0 || at != value.lastIndexOf('@')) {
            throw new ValidationException("Email address must contain exactly one '@'.");
        }
        String local = value.substring(0, at);
        String domain = value.substring(at + 1);
        validateEmailLocal(local);
        validateEmailDomain(domain);
        return value.toLowerCase(Locale.ROOT);
    }

    private static void validateEmailLocal(String local) throws ValidationException {
        if (local.isEmpty() || local.length() > EMAIL_LOCAL_MAX_LENGTH) {
            throw new ValidationException("The part before '@' must be 1 to "
                    + EMAIL_LOCAL_MAX_LENGTH + " characters.");
        }
        if (local.startsWith(".") || local.endsWith(".") || local.contains("..")) {
            throw new ValidationException("The part before '@' has a misplaced dot.");
        }
        for (int i = 0; i < local.length(); i++) {
            char c = local.charAt(i);
            if (!isAsciiAlnum(c) && LOCAL_EXTRA.indexOf(c) < 0) {
                throw new ValidationException("The part before '@' contains an unsupported character.");
            }
        }
    }

    private static void validateEmailDomain(String domain) throws ValidationException {
        if (domain.isEmpty() || domain.length() > 253) {
            throw new ValidationException("The domain must be 1 to 253 characters.");
        }
        if (domain.startsWith(".") || domain.endsWith(".") || domain.contains("..")) {
            throw new ValidationException("The domain has a misplaced dot.");
        }
        String[] labels = domain.split("\\.", -1);
        if (labels.length < 2) {
            throw new ValidationException("The domain must include a dot, for example example.com.");
        }
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63) {
                throw new ValidationException("Each domain label must be 1 to 63 characters.");
            }
            if (label.charAt(0) == '-' || label.charAt(label.length() - 1) == '-') {
                throw new ValidationException("Domain labels must not start or end with '-'.");
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!isAsciiAlnum(c) && c != '-') {
                    throw new ValidationException("The domain contains an unsupported character.");
                }
            }
        }
        String tld = labels[labels.length - 1];
        if (tld.length() < 2) {
            throw new ValidationException("The domain suffix must be at least 2 characters.");
        }
        for (int i = 0; i < tld.length(); i++) {
            if (!isAsciiLetter(tld.charAt(i))) {
                throw new ValidationException("The domain suffix must contain letters only.");
            }
        }
    }

    /**
     * Returns the canonical username (NFKC-folded, lower-cased) used for uniqueness and lookup.
     *
     * <p>NFKC before case folding is what stops {@code Ａdmin} (full-width A) from registering as a
     * second, visually identical "admin".
     */
    public static String canonicalUsername(String raw) throws ValidationException {
        if (raw == null) {
            throw new ValidationException("Username is required.");
        }
        String stripped = raw.strip();
        if (stripped.length() > USERNAME_MAX_LENGTH * 4) {
            // Bound the input before normalisation, which can expand it.
            throw new ValidationException("Username must be at most " + USERNAME_MAX_LENGTH + " characters.");
        }
        String value = Normalizer.normalize(stripped, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
        if (value.length() < USERNAME_MIN_LENGTH || value.length() > USERNAME_MAX_LENGTH) {
            throw new ValidationException("Username must be " + USERNAME_MIN_LENGTH + " to "
                    + USERNAME_MAX_LENGTH + " characters.");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!isAsciiAlnum(c) && c != '.' && c != '_' && c != '-') {
                throw new ValidationException(
                        "Username may contain only letters, digits, '.', '_' and '-'.");
            }
        }
        if (!isAsciiAlnum(value.charAt(0)) || !isAsciiAlnum(value.charAt(value.length() - 1))) {
            throw new ValidationException("Username must start and end with a letter or digit.");
        }
        for (int i = 1; i < value.length(); i++) {
            if (!isAsciiAlnum(value.charAt(i)) && !isAsciiAlnum(value.charAt(i - 1))) {
                throw new ValidationException("Username must not contain two separators in a row.");
            }
        }
        if (RESERVED_USERNAMES.contains(value)) {
            // Same wording as a taken name would get, so this leaks no account existence either.
            throw new ValidationException("That username is not available.");
        }
        return value;
    }

    /**
     * Applies RFC 8265 {@code OpaqueString} preparation to a password and returns the prepared
     * form. The input array is not modified; the caller owns and must wipe both arrays.
     */
    public static char[] preparePassword(char[] raw) throws ValidationException {
        if (raw == null || raw.length == 0) {
            throw new ValidationException("Password is required.");
        }
        if (raw.length > PASSWORD_MAX_LENGTH) {
            throw new ValidationException("Password must be at most " + PASSWORD_MAX_LENGTH + " characters.");
        }
        char[] mapped = new char[raw.length];
        for (int i = 0; i < raw.length; i++) {
            char c = raw[i];
            if (Character.getType(c) == Character.SPACE_SEPARATOR) {
                mapped[i] = ' ';                     // OpaqueString: map Zs to SPACE
            } else if (isDisallowedControl(c)) {
                Wipe.chars(mapped);
                throw new ValidationException("Password must not contain control characters.");
            } else {
                mapped[i] = c;
            }
        }
        CharBuffer buffer = CharBuffer.wrap(mapped);
        if (Normalizer.isNormalized(buffer, Normalizer.Form.NFC)) {
            return mapped;                            // common case: no String is ever materialised
        }
        // Rare path: java.text.Normalizer only returns String, so a non-wipeable copy exists until
        // GC. Accepted and documented in the README rather than hand-rolling NFC.
        String normalized = Normalizer.normalize(buffer, Normalizer.Form.NFC);
        Wipe.chars(mapped);
        char[] out = normalized.toCharArray();
        if (out.length > PASSWORD_MAX_LENGTH) {
            Wipe.chars(out);
            throw new ValidationException("Password must be at most " + PASSWORD_MAX_LENGTH + " characters.");
        }
        return out;
    }

    private static boolean isDisallowedControl(char c) {
        if (c == '\t' || c == '\n' || c == '\r') {
            return true;
        }
        int type = Character.getType(c);
        return type == Character.CONTROL || type == Character.FORMAT
                || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR
                || type == Character.SURROGATE || type == Character.PRIVATE_USE
                || type == Character.UNASSIGNED;
    }

    /**
     * Enforces the password policy on an already-prepared password.
     *
     * @param prepared  output of {@link #preparePassword(char[])}
     * @param canonicalUsername canonical username, or {@code null} to skip the similarity check
     * @param canonicalEmail    canonical email, or {@code null} to skip the similarity check
     */
    public static void checkPasswordPolicy(char[] prepared, String canonicalUsername,
                                           String canonicalEmail) throws ValidationException {
        if (prepared == null || prepared.length < PASSWORD_MIN_LENGTH) {
            throw new ValidationException("Password must be at least " + PASSWORD_MIN_LENGTH + " characters.");
        }
        if (prepared.length > PASSWORD_MAX_LENGTH) {
            throw new ValidationException("Password must be at most " + PASSWORD_MAX_LENGTH + " characters.");
        }
        if (countDistinct(prepared) < 5) {
            throw new ValidationException("Password must use at least 5 different characters.");
        }
        // Folded copy for the comparisons below. Note that no String is built from the password:
        // a String could not be wiped and would survive in the heap (rule 5).
        char[] folded = new char[prepared.length];
        for (int i = 0; i < prepared.length; i++) {
            folded[i] = Character.toLowerCase(prepared[i]);
        }
        try {
            for (String blocked : BLOCKED_PASSWORDS) {
                if (equalsChars(folded, blocked)) {
                    throw new ValidationException("That password is too common. Choose a different one.");
                }
            }
            if (canonicalUsername != null && canonicalUsername.length() >= 3
                    && containsChars(folded, canonicalUsername)) {
                throw new ValidationException("Password must not contain your username.");
            }
            if (canonicalEmail != null) {
                int at = canonicalEmail.indexOf('@');
                String localPart = at > 0 ? canonicalEmail.substring(0, at) : canonicalEmail;
                if (localPart.length() >= 3 && containsChars(folded, localPart)) {
                    throw new ValidationException("Password must not contain your email address.");
                }
            }
            if (isSingleRepeatedCharacter(folded) || isMonotonicRun(folded)) {
                throw new ValidationException("That password is too predictable. Choose a different one.");
            }
        } finally {
            Wipe.chars(folded);
        }
    }

    private static int countDistinct(char[] value) {
        int distinct = 0;
        outer:
        for (int i = 0; i < value.length; i++) {
            for (int j = 0; j < i; j++) {
                if (value[j] == value[i]) {
                    continue outer;
                }
            }
            distinct++;
        }
        return distinct;
    }

    private static boolean equalsChars(char[] value, String other) {
        if (value.length != other.length()) {
            return false;
        }
        for (int i = 0; i < value.length; i++) {
            if (value[i] != other.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static boolean containsChars(char[] haystack, String needle) {
        int n = needle.length();
        if (n == 0 || n > haystack.length) {
            return false;
        }
        for (int i = 0; i + n <= haystack.length; i++) {
            int j = 0;
            while (j < n && haystack[i + j] == needle.charAt(j)) {
                j++;
            }
            if (j == n) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSingleRepeatedCharacter(char[] value) {
        for (int i = 1; i < value.length; i++) {
            if (value[i] != value[0]) {
                return false;
            }
        }
        return true;
    }

    /** Detects straight runs such as {@code abcdefghijkl} or {@code 9876543210987}. */
    private static boolean isMonotonicRun(char[] value) {
        boolean up = true;
        boolean down = true;
        for (int i = 1; i < value.length; i++) {
            if (value[i] - value[i - 1] != 1) {
                up = false;
            }
            if (value[i] - value[i - 1] != -1) {
                down = false;
            }
        }
        return up || down;
    }

    private static boolean isAsciiAlnum(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }

    private static boolean isAsciiLetter(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }
}
