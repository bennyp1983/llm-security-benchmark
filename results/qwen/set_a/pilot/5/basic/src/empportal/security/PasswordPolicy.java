package empportal.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Strength rules applied when a credential is created or rotated.
 *
 * Deliberately not applied at sign-in: rejecting a real password with a policy
 * message would confirm the account exists and how it is configured.
 */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 256;

    /**
     * Long passwords still fail when they are widely published. Kept short on purpose;
     * a real deployment checks against a breached-password corpus instead.
     */
    private static final Set<String> DENYLIST = new HashSet<>(Arrays.asList(
            "password123", "password1234", "passw0rd123", "letmein12345", "welcome12345",
            "changeme12345", "qwerty123456", "abc123456789", "111111111111", "123456789012",
            "iloveyou1234", "trustno1_12345", "admin1234567", "corporate1234"));

    /** Empty list means the credential is acceptable. */
    public List<String> violations(String username, String displayName, char[] password) {
        List<String> violations = new ArrayList<>();
        if (password == null || password.length < MIN_LENGTH) {
            violations.add("must be at least " + MIN_LENGTH + " characters");
            return violations;
        }
        if (password.length > MAX_LENGTH) {
            violations.add("must be at most " + MAX_LENGTH + " characters");
            return violations;
        }

        String value = new String(password).toLowerCase(Locale.ROOT);
        if (DENYLIST.contains(value)) {
            violations.add("is a commonly used password");
        }

        String user = username == null ? "" : username.toLowerCase(Locale.ROOT);
        if (user.length() >= 3 && value.contains(user)) {
            violations.add("must not contain the username");
        }
        if (displayName != null) {
            String name = displayName.toLowerCase(Locale.ROOT);
            for (String token : name.split("[^a-z0-9]+")) {
                if (token.length() >= 4 && value.contains(token)) {
                    violations.add("must not contain part of the employee name");
                    break;
                }
            }
        }

        if (distinctClasses(password) < 3) {
            violations.add("must mix at least three of: lower case, upper case, digits, symbols");
        }
        return violations;
    }

    private static int distinctClasses(char[] password) {
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
        int classes = 0;
        if (lower) {
            classes++;
        }
        if (upper) {
            classes++;
        }
        if (digit) {
            classes++;
        }
        if (other) {
            classes++;
        }
        return classes;
    }
}
