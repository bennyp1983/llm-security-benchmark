package accounts;

import java.util.Arrays;
import java.util.Objects;

/** A stored account: a username plus the parameters needed to verify its password. */
public final class UserAccount {

    private final String username;
    private final byte[] salt;
    private final byte[] passwordHash;
    private final int iterations;

    public UserAccount(String username, byte[] salt, byte[] passwordHash, int iterations) {
        this.username = Objects.requireNonNull(username, "username");
        this.salt = Objects.requireNonNull(salt, "salt").clone();
        this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash").clone();
        this.iterations = iterations;
    }

    /** Creates an account by hashing {@code password} with a fresh random salt. */
    public static UserAccount create(String username, char[] password) {
        byte[] salt = PasswordHasher.newSalt();
        byte[] hash = PasswordHasher.hash(password, salt, PasswordHasher.DEFAULT_ITERATIONS);
        return new UserAccount(username, salt, hash, PasswordHasher.DEFAULT_ITERATIONS);
    }

    public String username() {
        return username;
    }

    public boolean verify(char[] password) {
        return PasswordHasher.matches(password, salt, iterations, passwordHash);
    }

    /** Serializes to a single line: {@code username:iterations:saltB64:hashB64}. */
    String toRecord() {
        return String.join(":",
                username,
                Integer.toString(iterations),
                PasswordHasher.encode(salt),
                PasswordHasher.encode(passwordHash));
    }

    static UserAccount fromRecord(String line) {
        String[] parts = line.split(":", 4);
        if (parts.length != 4) {
            throw new IllegalArgumentException("Malformed account record: " + line);
        }
        return new UserAccount(
                parts[0],
                PasswordHasher.decode(parts[2]),
                PasswordHasher.decode(parts[3]),
                Integer.parseInt(parts[1]));
    }

    @Override
    public String toString() {
        return "UserAccount[" + username + "]";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UserAccount other)) {
            return false;
        }
        return iterations == other.iterations
                && username.equals(other.username)
                && Arrays.equals(salt, other.salt)
                && Arrays.equals(passwordHash, other.passwordHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, iterations, Arrays.hashCode(salt), Arrays.hashCode(passwordHash));
    }
}
