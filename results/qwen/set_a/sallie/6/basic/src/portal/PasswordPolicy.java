package portal;

/** Rules a new administrator password must satisfy. */
public final class PasswordPolicy {

    public static final int MIN_CHARS = 10;
    public static final int MAX_CHARS = 1024;

    private PasswordPolicy() {
    }

    /**
     * @return an error message, or {@code null} when the password is acceptable
     */
    public static String check(char[] password, String username) {
        String structural = structural(password);
        if (structural != null) {
            return structural;
        }
        String value = new String(password);
        if (value.codePoints().count() < MIN_CHARS) {
            return "the password must be at least " + MIN_CHARS + " characters";
        }
        if (username != null && !username.isEmpty() && value.toLowerCase(java.util.Locale.ROOT)
                .contains(username.toLowerCase(java.util.Locale.ROOT))) {
            return "the password must not contain the username";
        }
        int classes = 0;
        boolean hasLetter = false;
        boolean hasDigit = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isLetter(c)) {
                hasLetter = true;
                classes |= Character.isUpperCase(c) ? 2 : 1;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
                classes |= 4;
            } else {
                classes |= 8;
            }
        }
        if (!hasLetter || !hasDigit) {
            return "the password must contain at least one letter and one digit";
        }
        if (Integer.bitCount(classes) < 3) {
            return "the password must mix upper case, lower case, digits or other characters";
        }
        return null;
    }

    /**
     * Rejects the two shapes that PBKDF2 cannot round-trip faithfully: a trailing
     * NUL is dropped by {@code PBEKeySpec} and an unpaired surrogate becomes a
     * question mark. Either would let two different inputs unlock the same account.
     *
     * @return an error message, or {@code null} when the array is usable
     */
    public static String structural(char[] password) {
        if (password == null || password.length == 0) {
            return "a password is required";
        }
        if (password.length > MAX_CHARS) {
            return "the password must be at most " + MAX_CHARS + " characters";
        }
        boolean highPending = false;
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (c == '\0') {
                return "the password must not contain a null character";
            }
            if (Character.isHighSurrogate(c)) {
                if (highPending) {
                    return "the password must not contain an incomplete character";
                }
                highPending = true;
            } else if (Character.isLowSurrogate(c)) {
                if (!highPending) {
                    return "the password must not contain an incomplete character";
                }
                highPending = false;
            }
        }
        if (highPending) {
            return "the password must not contain an incomplete character";
        }
        return null;
    }
}
