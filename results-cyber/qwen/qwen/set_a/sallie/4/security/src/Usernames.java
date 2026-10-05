import java.util.Locale;

/** Username rules and the single normalisation used for both registering and logging in. */
public final class Usernames {

    public static final int MIN_LENGTH = 3;
    public static final int MAX_LENGTH = 32;

    private Usernames() {
    }

    /**
     * Returns the store key for {@code raw}, or null when it is not usable.
     *
     * <p>Only ordinary spaces are stripped. {@code String.trim()} would also delete tabs,
     * newlines and NULs, which would fold {@code "alice"} and {@code "alice\0"} onto one
     * account and hand out a second, invisible spelling of somebody's login.
     */
    public static String normalize(String raw) {
        if (raw == null) {
            return null;
        }
        int start = 0;
        int end = raw.length();
        while (start < end && raw.charAt(start) == ' ') {
            start++;
        }
        while (end > start && raw.charAt(end - 1) == ' ') {
            end--;
        }
        String trimmed = raw.substring(start, end);
        if (trimmed.length() < MIN_LENGTH || trimmed.length() > MAX_LENGTH) {
            return null;
        }
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (!isAllowed(c)) {
                return null;
            }
        }
        return lower(trimmed);
    }

    private static boolean isAllowed(char c) {
        return (c >= 'a' && c <= 'z')
                || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9')
                || c == '.' || c == '_' || c == '-' || c == '@';
    }

    private static String lower(String value) {
        return value.toLowerCase(Locale.ROOT);
    }
}
