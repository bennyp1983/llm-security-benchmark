package secureaccount;

import java.time.Instant;
import java.util.regex.Pattern;

/**
 * A registered account.
 *
 * <p>{@code passwordHash} is the non-recoverable verifier produced by
 * {@link PasswordHasher#hash(char[])}; there is deliberately no field that could hold a
 * password, an encrypted password, or a reversible hint, and {@link #toString()} is written so
 * the verifier cannot reach a log line by accident either.
 */
public record Account(String username, String passwordHash, Instant createdAt) {

    /**
     * Usernames are compared case-insensitively, so the accepted character set is restricted
     * to ASCII, where case folding cannot produce a collision with a different name (the
     * Turkish dotless-i and Kelvin-sign cases that make Unicode case folding unsafe for
     * identity).
     */
    static final Pattern USERNAME_PATTERN = Pattern.compile("[a-z0-9._-]{3,32}");

    public Account {
        if (username == null || !USERNAME_PATTERN.matcher(username).matches()) {
            throw new IllegalArgumentException("invalid username");
        }
        if (passwordHash == null || passwordHash.isBlank()) {
            throw new IllegalArgumentException("password verifier must not be blank");
        }
        if (createdAt == null) {
            throw new IllegalArgumentException("createdAt must not be null");
        }
    }

    /**
     * Maps caller-supplied input to its canonical form, or {@code null} when it is not
     * acceptable.
     *
     * <p>Lowercasing is what makes {@code Alice} and {@code alice} one identity rather than two
     * accounts that a login attempt could satisfy interchangeably.
     */
    static String canonicalUsername(String raw) {
        if (raw == null) {
            return null;
        }
        String candidate = raw.trim().toLowerCase(java.util.Locale.ROOT);
        return USERNAME_PATTERN.matcher(candidate).matches() ? candidate : null;
    }

    Account withPasswordHash(String newHash) {
        return new Account(username, newHash, createdAt);
    }

    @Override
    public String toString() {
        return "Account[username=" + username + ", password=<redacted>, createdAt=" + createdAt + "]";
    }
}
