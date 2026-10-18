package app;

import java.util.Set;

/**
 * The single trust boundary for every externally supplied value.
 *
 * <p>Nothing is normalised into a different identity: inputs are either accepted exactly as
 * supplied (email is case-folded, which is the documented mailbox-equivalence rule for the
 * domain and is applied consistently on both paths) or refused. There is no
 * {@code trim()}/{@code strip()} step anywhere, because stripping turns
 * {@code "user@corp.example "} or a trailing tab into the real account and undoes every
 * downstream check.
 *
 * <p>Reason strings returned in {@link ValidationException} describe the violated rule only.
 * They never contain the offending value, so they can be written to a log safely.
 */
public final class InputPolicy {

    /** Hard ceiling on any single field, applied before decoding so an oversized line cannot be buffered. */
    public static final int MAX_FIELD_CHARS = 4096;

    public static final int EMAIL_MAX = 254;
    public static final int EMAIL_LOCAL_MAX = 64;
    public static final int EMAIL_LABEL_MAX = 63;

    public static final int USERNAME_MIN = 3;
    public static final int USERNAME_MAX = 32;

    public static final int PASSWORD_MIN = 12;
    public static final int PASSWORD_MAX = 256;

    private static final Set<String> RESERVED_USERNAMES = Set.of(
        "admin", "administrator", "root", "support", "helpdesk", "postmaster",
        "webmaster", "abuse", "security", "noreply", "no-reply", "system", "sysadmin");

    private InputPolicy() {
    }

    /** A violated rule. The message is safe to log: it never contains user input. */
    public static final class ValidationException extends Exception {
        private static final long serialVersionUID = 1L;

        ValidationException(String rule) {
            super(rule);
        }
    }

    /**
     * @return the canonical form (email lower-cased) to store and compare
     * @throws ValidationException if the value is not acceptable exactly as supplied
     */
    public static String email(char[] raw) throws ValidationException {
        String value = text(raw, "email");
        if (value.length() > EMAIL_MAX) {
            throw new ValidationException("email is too long");
        }
        int at = value.indexOf('@');
        if (at < 0 || at != value.lastIndexOf('@')) {
            throw new ValidationException("email must contain exactly one @");
        }
        String local = value.substring(0, at);
        String domain = value.substring(at + 1);
        if (local.isEmpty() || local.length() > EMAIL_LOCAL_MAX) {
            throw new ValidationException("email local part must be 1 to " + EMAIL_LOCAL_MAX + " characters");
        }
        if (local.startsWith(".") || local.endsWith(".") || local.contains("..")) {
            throw new ValidationException("email local part has an invalid dot placement");
        }
        for (int i = 0; i < local.length(); i++) {
            if (LOCAL_PART.indexOf(local.charAt(i)) < 0) {
                throw new ValidationException("email local part contains an unsupported character");
            }
        }
        if (domain.startsWith("[") || domain.endsWith("]")) {
            throw new ValidationException("email domain must be a hostname, not an address literal");
        }
        String[] labels = domain.split("\\.", -1);
        if (labels.length < 2) {
            throw new ValidationException("email domain must contain at least two labels");
        }
        for (String label : labels) {
            if (label.isEmpty() || label.length() > EMAIL_LABEL_MAX) {
                throw new ValidationException("email domain label length is out of range");
            }
            if (label.startsWith("-") || label.endsWith("-")) {
                throw new ValidationException("email domain label may not start or end with a hyphen");
            }
            for (int i = 0; i < label.length(); i++) {
                if (DOMAIN_LABEL.indexOf(label.charAt(i)) < 0) {
                    throw new ValidationException("email domain label contains an unsupported character");
                }
            }
        }
        String last = labels[labels.length - 1];
        boolean allDigits = true;
        for (int i = 0; i < last.length(); i++) {
            if (!Character.isDigit(last.charAt(i))) {
                allDigits = false;
                break;
            }
        }
        if (allDigits) {
            throw new ValidationException("email domain top-level label may not be numeric");
        }
        return value.toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * Usernames are stored and compared exactly as accepted; the character class below makes
     * the stored form already canonical (lower-case ASCII, no separators other than '-').
     */
    public static String username(char[] raw) throws ValidationException {
        String value = text(raw, "username");
        if (value.length() < USERNAME_MIN || value.length() > USERNAME_MAX) {
            throw new ValidationException("username must be " + USERNAME_MIN + " to " + USERNAME_MAX + " characters");
        }
        char first = value.charAt(0);
        if (!isAlpha(first)) {
            throw new ValidationException("username must start with a letter");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (USERNAME.indexOf(c) < 0) {
                throw new ValidationException("username may contain only lower-case letters, digits and hyphens");
            }
        }
        if (value.endsWith("-")) {
            throw new ValidationException("username may not end with a hyphen");
        }
        if (RESERVED_USERNAMES.contains(value)) {
            throw new ValidationException("username is reserved");
        }
        return value;
    }

    /**
     * Passwords are never normalised: no trimming, no case folding, no Unicode normalisation.
     * Rejection of leading/trailing whitespace and of control characters is what prevents an
     * invisible suffix from silently becoming part of a different credential.
     */
    public static void password(char[] raw) throws ValidationException {
        if (raw == null || raw.length == 0) {
            throw new ValidationException("password is required");
        }
        if (raw.length > PASSWORD_MAX) {
            throw new ValidationException("password is too long");
        }
        if (raw.length < PASSWORD_MIN) {
            throw new ValidationException("password is too short");
        }
        if (Character.isWhitespace(raw[0]) || Character.isWhitespace(raw[raw.length - 1])) {
            throw new ValidationException("password may not start or end with whitespace");
        }
        int letters = 0;
        int digits = 0;
        for (int i = 0; i < raw.length; i++) {
            char c = raw[i];
            if (Character.isISOControl(c) || c == '\u007f' || Character.isSpaceChar(c)) {
                throw new ValidationException("password may not contain control or invisible whitespace characters");
            }
            if (Character.isSurrogate(c)) {
                if (!Character.isHighSurrogate(c) || i + 1 >= raw.length || !Character.isLowSurrogate(raw[i + 1])) {
                    throw new ValidationException("password contains an unpaired surrogate character");
                }
                i++;
            }
            if (Character.isLetter(c)) {
                letters++;
            } else if (Character.isDigit(c)) {
                digits++;
            }
        }
        if (letters == 0 || digits == 0) {
            throw new ValidationException("password must contain at least one letter and one digit");
        }
    }

    /**
     * Parses a sign-in identifier. An identifier is <em>either</em> a complete email or a
     * complete username - never a fuzzy blend - and the branch is chosen only by the presence of
     * the one character that cannot appear in a username.
     *
     * <p>Only an email is case-folded, and that folding is the documented mailbox-equivalence
     * rule. A username is matched exactly as validated, so no caller can reach an account by
     * changing its letter case: {@link #username(char[])} already refuses anything but lower-case
     * ASCII, which makes the stored form canonical.
     */
    public record Identity(boolean byEmail, String value) {
    }

    public static Identity identifier(char[] raw) throws ValidationException {
        String value = text(raw, "identifier");
        if (value.indexOf('@') >= 0) {
            return new Identity(true, email(raw));
        }
        return new Identity(false, username(raw));
    }

    /**
     * Rejects the password when it is built from the very identifier being registered.
     * Scans the {@code char[]} directly instead of building a String so the password is not
     * copied onto the heap where it could not be erased.
     */
    public static void passwordNotRelatedTo(char[] password, String... identifiers) throws ValidationException {
        for (String id : identifiers) {
            String needle = id;
            int at = needle.indexOf('@');
            if (at > 0) {
                needle = needle.substring(0, at);
            }
            if (needle.length() >= 3 && containsIgnoreCase(password, needle)) {
                throw new ValidationException("password must not contain the account name");
            }
        }
    }

    private static boolean containsIgnoreCase(char[] haystack, String needle) {
        int limit = haystack.length - needle.length();
        for (int i = 0; i <= limit; i++) {
            int j = 0;
            while (j < needle.length()
                && Character.toLowerCase(haystack[i + j]) == Character.toLowerCase(needle.charAt(j))) {
                j++;
            }
            if (j == needle.length()) {
                return true;
            }
        }
        return false;
    }

    /** Shared structural checks for every free-text field. Returns the value with no change. */
    private static String text(char[] raw, String field) throws ValidationException {
        if (raw == null || raw.length == 0) {
            throw new ValidationException(field + " is required");
        }
        if (raw.length > MAX_FIELD_CHARS) {
            throw new ValidationException(field + " is too long");
        }
        for (int i = 0; i < raw.length; i++) {
            char c = raw[i];
            if (Character.isISOControl(c) || c == '\u007f') {
                throw new ValidationException(field + " may not contain control characters");
            }
            if (Character.isSurrogate(c)
                && !(Character.isHighSurrogate(c) && i + 1 < raw.length && Character.isLowSurrogate(raw[i + 1]))) {
                throw new ValidationException(field + " contains an unpaired surrogate character");
            }
        }
        if (Character.isWhitespace(raw[0]) || Character.isWhitespace(raw[raw.length - 1])) {
            throw new ValidationException(field + " may not start or end with whitespace");
        }
        for (int i = 0; i < raw.length; i++) {
            if (!Character.isWhitespace(raw[i])) {
                return new String(raw);
            }
        }
        throw new ValidationException(field + " must not be blank");
    }

    private static boolean isAlpha(char c) {
        return c >= 'a' && c <= 'z';
    }

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";

    private static final String LOCAL_PART = LOWER + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + DIGITS + "._%+-";
    private static final String DOMAIN_LABEL = LOWER + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + DIGITS + "-";
    private static final String USERNAME = LOWER + DIGITS + "-";
}
