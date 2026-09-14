package portal.auth;

import java.util.Locale;

/**
 * Syntax rules applied to a credential before it is looked up or hashed.
 *
 * <p>Usernames are canonicalised so that {@code " A.Jones "} and
 * {@code "a.jones"} name the same account. Anything that cannot be represented
 * unambiguously is refused instead of being silently rewritten:
 *
 * <ul>
 *   <li>{@link String#trim()} and {@link Character#isWhitespace(char)} delete control characters
 *       (NUL, tab, CR) as if they were blanks, so {@code "a.jones\t"} would reach the real
 *       account. Only U+0020 is stripped here and every other control character is refused.</li>
 *   <li>{@link javax.crypto.spec.PBEKeySpec} drops trailing NUL characters and maps unpaired
 *       surrogates to {@code '?'} when it converts a password, so two different typed passwords
 *       can produce one identical hash. Both are refused.</li>
 * </ul>
 */
public final class CredentialValidator {

    public static final int MIN_USERNAME_LENGTH = 3;
    public static final int MAX_USERNAME_LENGTH = 64;
    public static final int MAX_PASSWORD_LENGTH = 256;

    private CredentialValidator() {
    }

    /**
     * Returns the canonical form of {@code raw}: surrounding spaces removed, lower-cased, ASCII.
     *
     * @throws IllegalArgumentException if the value is missing, blank, oversized, or contains a
     *     character that is not permitted in a username
     */
    public static String canonicalUsername(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("username is missing");
        }
        String value = stripSpaces(raw);
        if (value.isEmpty()) {
            throw new IllegalArgumentException("username is blank");
        }
        if (value.length() < MIN_USERNAME_LENGTH || value.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException(
                    "username must be between " + MIN_USERNAME_LENGTH + " and "
                            + MAX_USERNAME_LENGTH + " characters");
        }
        boolean hasLetterOrDigit = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!isAllowedUsernameChar(c)) {
                throw new IllegalArgumentException("username contains an unsupported character");
            }
            hasLetterOrDigit |= Character.isLetterOrDigit(c);
        }
        if (!hasLetterOrDigit) {
            throw new IllegalArgumentException("username must contain a letter or a digit");
        }
        return value.toLowerCase(Locale.ROOT);
    }

    /**
     * Checks that {@code password} can be hashed without two different typed values colliding.
     *
     * @throws IllegalArgumentException if the value is missing, blank, oversized, or contains a
     *     NUL, another control character, or half of a surrogate pair
     */
    public static void validatePassword(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password is missing");
        }
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "password must be at most " + MAX_PASSWORD_LENGTH + " characters");
        }
        if (password[0] == ' ' || password[password.length - 1] == ' ') {
            throw new IllegalArgumentException("password must not start or end with a space");
        }
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (c < 0x20 || c == 0x7F) {
                throw new IllegalArgumentException(
                        "password must not contain tabs, newlines or other control characters");
            }
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                    throw new IllegalArgumentException(
                            "password contains half of a character pair");
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                throw new IllegalArgumentException("password contains half of a character pair");
            }
        }
    }

    /** Strips U+0020 only, so that no control character can be mistaken for padding. */
    private static String stripSpaces(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && value.charAt(start) == ' ') {
            start++;
        }
        while (end > start && value.charAt(end - 1) == ' ') {
            end--;
        }
        return value.substring(start, end);
    }

    private static boolean isAllowedUsernameChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '.' || c == '_' || c == '-';
    }
}
