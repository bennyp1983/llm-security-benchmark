/** Password shape rules applied before any key derivation. */
public final class Passwords {

    public static final int MIN_LENGTH = 8;
    public static final int MAX_LENGTH = 256;

    private Passwords() {
    }

    public static boolean withinLength(char[] password) {
        return password != null && password.length >= MIN_LENGTH && password.length <= MAX_LENGTH;
    }

    /**
     * True when {@code password} can be hashed without colliding with a different password.
     *
     * <p>{@code PBEKeySpec} converts its {@code char[]} with the JCE's own UTF-8 converter,
     * which is not injective: trailing NULs are dropped, so {@code "secret12"} and
     * {@code "secret12\0"} derive the same digest, and every unpaired surrogate becomes
     * {@code '?'} regardless of its value. Both classes are refused rather than trimmed,
     * because trimming would silently change the secret the user supplied.
     *
     * <p>The check is deliberately stricter than the collision itself: any NUL, interior or
     * trailing, is refused, since a NUL cannot be typed. Correctly paired surrogates (an
     * emoji, for example) do hash injectively and are therefore accepted.
     */
    public static boolean isHashable(char[] password) {
        if (!withinLength(password)) {
            return false;
        }
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (c == 0) {
                return false;
            }
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                    return false;
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            }
        }
        return true;
    }

    /**
     * True when the password is long enough and is not a single repeated character class.
     * Deliberately cheap: length plus a small variety check, no composition rules to fight.
     */
    public static boolean strongEnough(char[] password) {
        if (!withinLength(password)) {
            return false;
        }
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean other = false;
        for (char c : password) {
            if (c >= 'a' && c <= 'z') {
                lower = true;
            } else if (c >= 'A' && c <= 'Z') {
                upper = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            } else {
                other = true;
            }
        }
        int classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (other ? 1 : 0);
        return classes >= 2;
    }

    public static void wipe(char[] password) {
        if (password != null) {
            java.util.Arrays.fill(password, '\0');
        }
    }
}
