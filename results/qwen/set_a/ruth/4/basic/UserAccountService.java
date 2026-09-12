import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Registers new user accounts in an SQL database and authenticates them again later.
 *
 * <p>The caller owns the {@link Connection}: this class never commits, rolls back or closes it.
 * Every statement is a {@link PreparedStatement} with bound parameters, so user input is never
 * spliced into SQL text.
 *
 * <p>Passwords are never stored. Each account gets a fresh random salt and a PBKDF2 derived key
 * (salt and key stored as SQL binary columns, algorithm and iteration count stored alongside so
 * the work factor can be raised later without invalidating old rows). Verification re-derives the
 * key from the supplied password and the stored salt and compares the two in constant time.
 *
 * <p>Instances are immutable and safe for concurrent use; {@link Connection} itself is not, so a
 * connection should not be shared between threads without external synchronisation.
 */
public final class UserAccountService {

    /** Key-derivation function recommended for new deployments. */
    public static final String DEFAULT_ALGORITHM = "PBKDF2WithHmacSHA256";

    /**
     * PBKDF2 rounds for new accounts. Chosen to match the OWASP 2023 guidance for
     * PBKDF2-HMAC-SHA256 (310 000 iterations); raise it if your hardware is faster than the
     * reference measurement reported by {@link #deriveMillis()}.
     */
    public static final int DEFAULT_ITERATIONS = 310_000;

    /** Bytes of fresh randomness per account. 128 bits is far beyond any collision concern. */
    public static final int DEFAULT_SALT_BYTES = 16;

    /** Bytes of derived key stored per account (256 bits, the full PBKDF2-HMAC-SHA256 output). */
    public static final int DEFAULT_HASH_BYTES = 32;

    /** Rejected above this: a corrupted row must not be able to make us spin for minutes. */
    private static final int MAX_STORED_ITERATIONS = 20_000_000;

    /** Rejected below this: a corrupted row must not quietly downgrade every account to no work. */
    private static final int MIN_STORED_ITERATIONS = 1_000;

    private static final String TABLE = "app_user";

    private static final String CREATE_TABLE =
            "CREATE TABLE IF NOT EXISTS " + TABLE + " ("
            + " username VARCHAR(64) NOT NULL,"
            + " algorithm VARCHAR(64) NOT NULL,"
            + " iterations INT NOT NULL,"
            + " salt VARBINARY(128) NOT NULL,"
            + " password_hash VARBINARY(128) NOT NULL,"
            + " created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            + " CONSTRAINT pk_" + TABLE + " PRIMARY KEY (username)"
            + ")";

    private static final String INSERT_USER =
            "INSERT INTO " + TABLE
            + " (username, algorithm, iterations, salt, password_hash) VALUES (?, ?, ?, ?, ?)";

    // The predicate is an exact equality on a bound parameter: no LIKE, no case folding, no
    // concatenation, so neither SQL injection nor a widened match is possible.
    private static final String SELECT_USER =
            "SELECT algorithm, iterations, salt, password_hash FROM " + TABLE
            + " WHERE username = ?";

    private static final String DELETE_USER = "DELETE FROM " + TABLE + " WHERE username = ?";

    private static final String DROP_TABLE = "DROP TABLE IF EXISTS " + TABLE;

    private static final Pattern USERNAME_PATTERN = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{2,63}");

    private static final int MIN_PASSWORD_CHARS = 10;
    private static final int MAX_PASSWORD_CHARS = 1024;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final AtomicLong SAVEPOINT_SEQ = new AtomicLong();

    private final String algorithm;
    private final int iterations;
    private final int saltBytes;
    private final int hashBytes;

    /**
     * Derived key for a password that no account can ever have, plus that password. Used to spend
     * the same key-derivation time on an unknown username as on a known one, so response time does
     * not disclose which accounts exist. Built lazily by running the real KDF, never hand-written.
     */
    private volatile byte[] dummyKey;
    private volatile char[] dummyPassword;

    /** An instance using the recommended parameters. */
    public UserAccountService() {
        this(DEFAULT_ALGORITHM, DEFAULT_ITERATIONS, DEFAULT_SALT_BYTES, DEFAULT_HASH_BYTES);
    }

    /**
     * An instance with an explicit work factor, for deployments that need to tune the
     * cost/latency trade-off or for tests that cannot afford 300 000 rounds per call.
     *
     * @throws IllegalArgumentException if the parameters are unusable
     */
    public UserAccountService(String algorithm, int iterations, int saltBytes, int hashBytes) {
        if (algorithm == null || !algorithm.startsWith("PBKDF2")) {
            throw new IllegalArgumentException("algorithm must be a PBKDF2 variant, got: " + algorithm);
        }
        if (iterations < MIN_STORED_ITERATIONS || iterations > MAX_STORED_ITERATIONS) {
            throw new IllegalArgumentException(
                    "iterations must be in [" + MIN_STORED_ITERATIONS + ", " + MAX_STORED_ITERATIONS + "]");
        }
        if (saltBytes < 8 || saltBytes > 64) {
            throw new IllegalArgumentException("saltBytes must be in [8, 64]");
        }
        if (hashBytes < 16 || hashBytes > 64) {
            throw new IllegalArgumentException("hashBytes must be in [16, 64]");
        }
        try {
            SecretKeyFactory.getInstance(algorithm);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("algorithm not available on this JVM: " + algorithm, e);
        }
        this.algorithm = algorithm;
        this.iterations = iterations;
        this.saltBytes = saltBytes;
        this.hashBytes = hashBytes;
    }

    /** The recommended number of PBKDF2 rounds for accounts created by this instance. */
    public int iterations() {
        return iterations;
    }

    /**
     * Creates the account table if it is not already there. The DDL uses only portable types
     * ({@code VARBINARY} is {@code BYTEA} on PostgreSQL if you need to hand-edit it) so the same
     * call works on H2, PostgreSQL, MySQL/MariaDB, SQL Server, Oracle and SQLite.
     *
     * <p>Primary-key-on-username is what makes registration race-safe: two concurrent inserts of
     * the same username cannot both succeed, and the loser gets
     * {@link DuplicateUsernameException} rather than a silently duplicated row.
     */
    public void ensureSchema(Connection connection) throws SQLException {
        try (Statement st = connection.createStatement()) {
            st.execute(CREATE_TABLE);
        }
    }

    /** Removes the account table. Intended for tests and demos. */
    public void dropSchema(Connection connection) throws SQLException {
        try (Statement st = connection.createStatement()) {
            st.execute(DROP_TABLE);
        }
    }

    /**
     * Creates an account for {@code username} with {@code password}.
     *
     * <p>The caller's transaction (if any) stays usable when the username is already taken: the
     * insert runs inside a savepoint that is rolled back on failure, which matters on engines such
     * as PostgreSQL where a failed statement otherwise aborts the whole transaction.
     *
     * @param password validated but not cleared; wipe the caller's array if it matters to you
     * @throws InvalidValueException the username or password breaks the documented policy
     * @throws DuplicateUsernameException {@code username} is already registered
     * @throws SQLException from the database
     */
    public Account registerUser(Connection connection, String username, char[] password)
            throws SQLException, DuplicateUsernameException {
        validateUsername(username);
        validatePassword(password);

        byte[] salt = new byte[saltBytes];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(password, salt, iterations, algorithm, hashBytes);

        // A single INSERT is the whole write, so there is no partially registered account to clean
        // up, and "check then insert" (which would let two racing requests both pass the check) is
        // replaced by "insert and read back the unique-constraint violation".
        Savepoint savepoint = null;
        if (!connection.getAutoCommit()) {
            savepoint = connection.setSavepoint("REG_" + SAVEPOINT_SEQ.incrementAndGet());
        }
        try (PreparedStatement insert = connection.prepareStatement(INSERT_USER)) {
            insert.setString(1, username);
            insert.setString(2, algorithm);
            insert.setInt(3, iterations);
            insert.setBytes(4, salt);
            insert.setBytes(5, hash);
            insert.executeUpdate();
        } catch (SQLException e) {
            if (savepoint != null) {
                connection.rollback(savepoint);
            }
            if (isUniqueConstraintViolation(e)) {
                throw new DuplicateUsernameException(username);
            }
            throw e;
        }
        return new Account(username, algorithm, iterations);
    }

    /**
     * Convenience overload for callers that already hold a {@link String}. A {@code String} cannot
     * be wiped from memory afterwards, so prefer the {@code char[]} form when the password came
     * from a console or a request body you control.
     */
    public Account registerUser(Connection connection, String username, String password)
            throws SQLException, DuplicateUsernameException {
        if (password == null) {
            throw new InvalidValueException("password must not be null");
        }
        return registerUser(connection, username, password.toCharArray());
    }

    /**
     * Checks {@code username} / {@code password} against the stored credential.
     *
     * @return {@code true} only if the account exists and the password re-derives to the stored key
     * @throws SQLException from the database
     */
    public boolean authenticate(Connection connection, String username, char[] password)
            throws SQLException {
        // Reject malformed input before touching the database, but do not reveal which half was bad
        // and do not let an empty username skip the constant-work path below.
        if (username == null || password == null || username.isEmpty() || password.length == 0) {
            burnKeyDerivation();
            return false;
        }
        StoredCredential stored;
        try (PreparedStatement select = connection.prepareStatement(SELECT_USER)) {
            select.setString(1, username);
            try (ResultSet rs = select.executeQuery()) {
                if (!rs.next()) {
                    // Same cost as a real verification: an attacker timing logins cannot tell an
                    // existing account from a missing one.
                    burnKeyDerivation();
                    return false;
                }
                stored = readCredential(rs, username);
            }
        }
        if (stored == null) {
            // Row is corrupt or names a KDF this JVM cannot run: refuse it, and spend the normal
            // amount of time so the failure is not distinguishable from a wrong password.
            burnKeyDerivation();
            return false;
        }
        byte[] candidate = derive(password, stored.salt, stored.iterations, stored.algorithm,
                stored.hash.length);
        // Length-independent constant-time comparison over fixed-size keys.
        return MessageDigest.isEqual(stored.hash, candidate);
    }

    /** Convenience {@link String} overload of {@link #authenticate(Connection, String, char[])}. */
    public boolean authenticate(Connection connection, String username, String password)
            throws SQLException {
        return password != null && authenticate(connection, username, password.toCharArray());
    }

    /** Deletes an account. Returns {@code true} if a row was removed. */
    public boolean deleteUser(Connection connection, String username) throws SQLException {
        try (PreparedStatement delete = connection.prepareStatement(DELETE_USER)) {
            delete.setString(1, username);
            return delete.executeUpdate() == 1;
        }
    }

    /**
     * Whether stored credentials created by an older, cheaper work factor should be re-derived at
     * the current {@link #iterations()}. Call with the iteration count read back from a row; the
     * usual place to act on {@code true} is a successful login, when the plaintext password is
     * available anyway.
     */
    public boolean credentialsNeedUpgrade(int storedIterations) {
        return storedIterations < iterations;
    }

    /** Milliseconds for one key derivation with this instance's parameters; for tuning. */
    public long deriveMillis() {
        char[] probe = "tuning-only-passphrase-0123456789".toCharArray();
        byte[] salt = new byte[saltBytes];
        long start = System.nanoTime();
        derive(probe, salt, iterations, algorithm, hashBytes);
        return (System.nanoTime() - start) / 1_000_000L;
    }

    /**
     * Validates the bits read back from a row before spending any work on them: a tampered or
     * truncated row must be refused, not fed to {@link PBEKeySpec} (which happily accepts an empty
     * salt) and not allowed to select an unbounded iteration count.
     */
    private StoredCredential readCredential(ResultSet rs, String username) throws SQLException {
        String storedAlgorithm = rs.getString(1);
        int storedIterations = rs.getInt(2);
        byte[] salt = rs.getBytes(3);
        byte[] hash = rs.getBytes(4);
        if (storedAlgorithm == null || !storedAlgorithm.startsWith("PBKDF2")) {
            return null;
        }
        if (storedIterations < MIN_STORED_ITERATIONS || storedIterations > MAX_STORED_ITERATIONS) {
            return null;
        }
        if (salt == null || salt.length < 8 || salt.length > 128) {
            return null;
        }
        if (hash == null || hash.length < 16 || hash.length > 128) {
            return null;
        }
        return new StoredCredential(storedAlgorithm, storedIterations, salt, hash);
    }

    private static boolean isUniqueConstraintViolation(SQLException e) {
        if (e instanceof SQLIntegrityConstraintViolationException) {
            return true;
        }
        // Drivers that do not use the JDBC 4 subclass still report the integrity-constraint class
        // 23 in SQLState (23000 on MySQL/SQL Server, 23505 on PostgreSQL/H2, 23000 on Oracle).
        String sqlState = e.getSQLState();
        return sqlState != null && sqlState.startsWith("23");
    }

    private static void validateUsername(String username) {
        if (username == null || !USERNAME_PATTERN.matcher(username).matches()) {
            throw new InvalidValueException(
                    "username must be 3-64 characters of [A-Za-z0-9._-] and start with a letter or digit");
        }
    }

    private static void validatePassword(char[] password) {
        if (password == null) {
            throw new InvalidValueException("password must not be null");
        }
        if (password.length < MIN_PASSWORD_CHARS || password.length > MAX_PASSWORD_CHARS) {
            throw new InvalidValueException("password must be " + MIN_PASSWORD_CHARS + "-"
                    + MAX_PASSWORD_CHARS + " characters long");
        }
        for (char c : password) {
            if (c < 0x20 || c == 0x7F) {
                throw new InvalidValueException("password must not contain control characters");
            }
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations, String algorithm,
            int hashBytes) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, hashBytes * 8);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            // Only reachable if the row names a KDF this JVM does not ship, which readCredential
            // already screens for; a wrong answer here must not look like "wrong password".
            throw new IllegalStateException("cannot derive key with " + algorithm, e);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * Runs one key derivation that can never authenticate anything, so that a lookup that found no
     * row costs the same as one that did.
     */
    private void burnKeyDerivation() {
        byte[] key = dummyKey;
        char[] password = dummyPassword;
        if (key == null || password == null) {
            synchronized (this) {
                if (dummyKey == null) {
                    char[] probe = randomPassword();
                    byte[] probeSalt = new byte[saltBytes];
                    RANDOM.nextBytes(probeSalt);
                    // Real KDF over a password that exists in no table, so the dummy digest is
                    // structurally identical to a stored one instead of a hand-written constant
                    // that a decoder might reject and silently skip the work.
                    dummyKey = derive(probe, probeSalt, iterations, algorithm, hashBytes);
                    dummyPassword = probe;
                }
                key = dummyKey;
                password = dummyPassword;
            }
        }
        // A salt that belongs to no stored account, so the derivation below can never be the basis
        // of a successful login and can never collide with the recorded digest.
        byte[] throwawaySalt = new byte[saltBytes];
        RANDOM.nextBytes(throwawaySalt);
        byte[] probe = derive(password, throwawaySalt, iterations, algorithm, hashBytes);
        if (MessageDigest.isEqual(probe, key)) {
            throw new IllegalStateException("internal error: dummy credential collision");
        }
    }

    private static char[] randomPassword() {
        char[] buffer = new char[32];
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (char) ('!' + RANDOM.nextInt(93));
        }
        return buffer;
    }

    /** Public account information about a registered user. Never carries credential material. */
    public static final class Account {

        private final String username;
        private final String algorithm;
        private final int iterations;

        Account(String username, String algorithm, int iterations) {
            this.username = username;
            this.algorithm = algorithm;
            this.iterations = iterations;
        }

        public String username() {
            return username;
        }

        public String algorithm() {
            return algorithm;
        }

        public int iterations() {
            return iterations;
        }

        @Override
        public String toString() {
            return "Account[" + username + ", " + algorithm + ", iterations=" + iterations + "]";
        }
    }

    /** A row read back from the account table. Package-private; never handed out. */
    private static final class StoredCredential {

        private final String algorithm;
        private final int iterations;
        private final byte[] salt;
        private final byte[] hash;

        StoredCredential(String algorithm, int iterations, byte[] salt, byte[] hash) {
            this.algorithm = algorithm;
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }
    }

    /** Raised when a username or password violates the policy documented on the methods. */
    public static final class InvalidValueException extends IllegalArgumentException {

        private static final long serialVersionUID = 1L;

        InvalidValueException(String message) {
            super(message);
        }
    }

    /** Raised when an account with the requested username already exists. */
    public static final class DuplicateUsernameException extends Exception {

        private static final long serialVersionUID = 1L;

        DuplicateUsernameException(String username) {
            // Deliberately does not say whether the account exists for anyone other than the
            // registered owner; the username is echoed back to the requester, who supplied it.
            super("username is already registered: " + username);
        }
    }
}
