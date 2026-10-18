package account;

import java.time.Instant;

/**
 * One registered account. The password itself is never held or stored: only the
 * self-describing PBKDF2 encoding produced by {@link PasswordHasher}.
 */
record User(String username, String passwordEncoding, Instant createdAt) {

    static final char FIELD_SEPARATOR = '|';

    User {
        if (username == null || passwordEncoding == null || createdAt == null) {
            throw new IllegalArgumentException("user fields must not be null");
        }
    }

    /** Serialises this account as a single store line. */
    String toLine() {
        return "v1" + FIELD_SEPARATOR + username + FIELD_SEPARATOR + passwordEncoding
                + FIELD_SEPARATOR + createdAt.getEpochSecond();
    }

    /**
     * Parses one store line. Any deviation from the expected shape is reported as
     * a corrupt store rather than being repaired, so a tampered file fails closed.
     */
    static User fromLine(String line, int lineNumber) {
        String[] parts = line.split("\\" + FIELD_SEPARATOR, -1);
        if (parts.length != 4 || !"v1".equals(parts[0])) {
            throw new IllegalStateException("corrupt account store: malformed record on line " + lineNumber);
        }
        long epochSecond;
        try {
            epochSecond = Long.parseLong(parts[3]);
        } catch (NumberFormatException e) {
            throw new IllegalStateException("corrupt account store: bad timestamp on line " + lineNumber, e);
        }
        return new User(parts[1], parts[2], Instant.ofEpochSecond(epochSecond));
    }
}
