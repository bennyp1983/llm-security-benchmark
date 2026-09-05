package portal.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Composition rules for administrator passwords. Administrators hold the keys to the
 * portal, so the bar is above the usual 8-character minimum and passwords that merely
 * satisfy the character classes are still rejected if they are guessable.
 */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 1024;
    private static final int MIN_DISTINCT_CHAR_CLASSES = 3;

    private static final Set<String> DENIED = new TreeSet<>(Arrays.asList(
            "password", "password1", "password12", "password123", "passw0rd", "p@ssw0rd",
            "admin", "admin123", "admin1234", "administrator", "changeme", "letmein",
            "welcome", "welcome1", "welcome123", "iloveyou", "qwerty", "qwerty123",
            "abc123", "111111", "123456", "1234567", "12345678", "123456789", "1234567890",
            "000000", "monkey", "dragon", "sunshine", "princess", "football", "baseball",
            "trustno1", "master", "login", "hello", "freedom", "whatever", "starwars",
            "zaq12wsx", "passwort", "contrasena", "root", "toor", "system", "manager",
            "password12345", "passw0rd12345", "administrator1", "changeme12345",
            "welcome123456", "iloveyou12345", "qwertyuiop123", "trustno123456"
    ));

    private static final Set<String> SEQUENCE_CHARS = new HashSet<>(Arrays.asList(
            "0123456789", "abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz0123456789"
    ));

    /** @return human-readable reasons the password is unacceptable; empty means acceptable. */
    public List<String> violations(String candidate, String username) {
        List<String> reasons = new ArrayList<>();
        if (candidate == null || candidate.isEmpty()) {
            reasons.add("password is required");
            return reasons;
        }
        if (candidate.length() < MIN_LENGTH) {
            reasons.add("must be at least " + MIN_LENGTH + " characters");
        }
        if (candidate.length() > MAX_LENGTH) {
            reasons.add("must be at most " + MAX_LENGTH + " characters");
        }
        if (candidate.indexOf('\n') >= 0 || candidate.indexOf('\r') >= 0 || candidate.indexOf('\0') >= 0) {
            reasons.add("must not contain control characters");
        }

        int classes = characterClasses(candidate);
        if (classes < MIN_DISTINCT_CHAR_CLASSES) {
            reasons.add("must mix at least " + MIN_DISTINCT_CHAR_CLASSES
                    + " of: lowercase, uppercase, digit, symbol");
        }
        if (distinctChars(candidate) < 5) {
            reasons.add("must contain at least 5 different characters");
        }

        String lowered = candidate.toLowerCase();
        String deniedWord = DENIED.contains(lowered) ? lowered : null;
        if (deniedWord != null) {
            reasons.add("is a commonly breached password");
        }
        if (username != null && username.length() >= 3) {
            String user = username.toLowerCase();
            if (lowered.contains(user) || reverse(user).equals(lowered)) {
                reasons.add("must not contain the username");
            }
        }
        if (isAllSame(candidate) || isRunOfSequence(lowered)) {
            reasons.add("must not be a repeated or sequential run of characters");
        }
        return reasons;
    }

    /** True only for an acceptable password. */
    public boolean isAcceptable(String candidate, String username) {
        return violations(candidate, username).isEmpty();
    }

    private static int characterClasses(String value) {
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean symbol = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 'a' && c <= 'z') {
                lower = true;
            } else if (c >= 'A' && c <= 'Z') {
                upper = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            } else if (c > ' ' && c < 0x7f) {
                symbol = true;
            }
        }
        int count = 0;
        if (lower) {
            count++;
        }
        if (upper) {
            count++;
        }
        if (digit) {
            count++;
        }
        if (symbol) {
            count++;
        }
        return count;
    }

    private static int distinctChars(String value) {
        Set<Character> seen = new HashSet<>();
        for (int i = 0; i < value.length(); i++) {
            seen.add(value.charAt(i));
        }
        return seen.size();
    }

    private static boolean isAllSame(String value) {
        for (int i = 1; i < value.length(); i++) {
            if (value.charAt(i) != value.charAt(0)) {
                return false;
            }
        }
        return true;
    }

    /** Rejects e.g. "abcdefghijkl" and "987654321098" while allowing one short run. */
    private static boolean isRunOfSequence(String lowered) {
        for (String alphabet : SEQUENCE_CHARS) {
            int run = 1;
            for (int i = 1; i < lowered.length(); i++) {
                int prev = alphabet.indexOf(lowered.charAt(i - 1));
                int cur = alphabet.indexOf(lowered.charAt(i));
                boolean forward = prev >= 0 && cur >= 0 && cur == prev + 1;
                boolean backward = prev > 0 && cur >= 0 && cur == prev - 1;
                run = (forward || backward) ? run + 1 : 1;
                if (run >= 8) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String reverse(String value) {
        return new StringBuilder(value).reverse().toString();
    }
}
