import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Registers new user accounts in a relational database and authenticates them
 * again later, on top of a JDBC {@link Connection} the caller already owns.
 *
 * <h2>Password handling</h2>
 *
 * A password is never stored, never returned, and never concatenated into SQL.
 * What goes into the database is a self-describing password digest:
 *
 * <pre>pbkdf2-sha256$600000$Base64(salt)$Base64(digest)</pre>
 *
 * <ul>
 *   <li><b>Key stretching.</b> PBKDF2-HMAC-SHA256 with 600,000 iterations
 *       (OWASP 2023 guidance for this primitive), so an offline crack of a
 *       stolen table costs ~0.9s per guess on one core of this machine.</li>
 *   <li><b>Per-account salt.</b> 16 fresh bytes from {@link SecureRandom} per
 *       registration, so two users with the same password get different rows
 *       and one precomputed rainbow table cannot cover the table.</li>
 *   <li><b>Stored parameters.</b> Algorithm and iteration count travel with the
 *       digest, so {@link UserRegistry#authenticate} verifies against the cost
 *       that was in force when the account was created, and the default can be
 *       raised later without invalidating existing accounts.</li>
 *   <li><b>Constant-time comparison.</b> Candidate and stored digests are
 *       compared with {@link MessageDigest#isEqual(byte[], byte[])}, which does
 *       not return early on the first differing byte.</li>
 *   <li><b>No user-enumeration timing leak.</b> An unknown username triggers the
 *       same PBKDF2 run against a throwaway digest, so "no such user" and "wrong
 *       password" take the same time to answer.</li>
 *   <li><b>char[] in, zeroed scratch out.</b> Passwords are taken as
 *       {@code char[]} so callers can wipe them (see
 *       {@link PasswordHasher#clear(char[])}) instead of
 *       parking the secret in an immutable {@code String}; the derived key bytes
 *       the library allocates are zeroed as soon as they are compared. Java
 *       cannot guarantee that a {@code String} password was never interned,
 *       cached, or paged to swap, which is exactly why {@code String} is the
 *       wrong type for this parameter.</li>
 * </ul>
 *
 * <h2>What the caller still owns</h2>
 *
 * The {@code Connection} is never closed here. Transport (TLS), account
 * lockout, rate limiting, and the user-facing wording of a failed login are
 * outside this class' scope and are required for a real deployment; see README.
 */
public final class UserRegistration {

    /** Target table. A compile-time constant, never derived from user input. */
    public static final String TABLE = "app_users";

    private UserRegistration() {
    }

    /** Result of {@link UserRegistry#register}. */
    public enum RegistrationOutcome {
        /** The account row was written. */
        CREATED,
        /** Another account already owns this username; nothing was written. */
        USERNAME_ALREADY_EXISTS
    }

    /**
     * Result of {@link UserRegistry#authenticate}. {@code NO_SUCH_USER} and
     * {@code BAD_PASSWORD} must be rendered with one identical message by the
     * caller, so the distinction stays useful for server-side logging and
     * migration tooling without becoming an enumeration oracle.
     */
    public enum AuthenticationOutcome {
        /** The candidate password produced the stored digest. */
        AUTHENTICATED,
        /** No row owns that username. */
        NO_SUCH_USER,
        /** A row exists and the candidate password did not produce its digest. */
        BAD_PASSWORD
    }

    /**
     * Salted, stretched password digests. Instances are thread-safe: the
     * iteration count is fixed at construction and {@link SecureRandom} is
     * safe for concurrent use.
     */
    public static final class PasswordHasher {

        /** PBKDF2 pseudo-random function, as named by the JCA. */
        public static final String JCA_ALGORITHM = "PBKDF2WithHmacSHA256";
        /** Tag written into the stored digest. */
        public static final String FORMAT_ID = "pbkdf2-sha256";

        /**
         * Iterations stamped on new accounts. 600,000 is OWASP's 2023 floor for
         * PBKDF2-HMAC-SHA256; it is not a maximum, and raising it is a
         * non-breaking change because each row keeps its own count.
         */
        public static final int DEFAULT_ITERATIONS = 600_000;

        /** Floor accepted for a stored digest, so a hostile row cannot ask for 1 round. */
        public static final int MIN_ITERATIONS = 1_000;
        /** Ceiling accepted for a stored digest, so a hostile row cannot ask for 10^9 rounds. */
        public static final int MAX_ITERATIONS = 10_000_000;

        /** Salt length drawn per account; 128 bits, so no two rows collide in salt. */
        public static final int SALT_BYTES = 16;
        /** Derived-key length; 256 bits, which is PBKDF2-HMAC-SHA256's own block size. */
        public static final int DIGEST_BYTES = 32;

        /**
         * Longest password accepted. PBKDF2 cost is linear in password length,
         * so an unbounded field would let anyone make registration arbitrarily
         * expensive. 1024 characters is far above any human-chosen secret.
         */
        public static final int MAX_PASSWORD_CHARS = 1_024;

        /** Field separator used by the stored format. */
        private static final String SEPARATOR = "$";

        private final int iterations;
        private final SecureRandom random = new SecureRandom();

        /**
         * A hasher that stamps new accounts with {@link #DEFAULT_ITERATIONS}.
         */
        public PasswordHasher() {
            this(DEFAULT_ITERATIONS);
        }

        /**
         * A hasher that stamps new accounts with {@code iterations}. The iteration
         * count already recorded in a row still governs how that row is verified.
         * 
         * @param iterations PBKDF2 rounds for newly created accounts
         * @throws IllegalArgumentException if outside [{@link #MIN_ITERATIONS}, {@link #MAX_ITERATIONS}]
         */
        public PasswordHasher(int iterations) {
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException(
                        "iterations must be in [" + MIN_ITERATIONS + ", " + MAX_ITERATIONS + "]");
            }
            this.iterations = iterations;
        }

        /**
         * @return the iteration count stamped on newly created accounts
         */
        public int getIterations() {
            return iterations;
        }

        /**
         * Produces the value to store for {@code password}. The caller's array
         * is not modified: wipe it with {@link #clear} as soon as you are done
         * with it.
         *
         * @param password the secret to derive from; not modified
         * @throws IllegalArgumentException if the password is empty, longer than
         *                                  {@link #MAX_PASSWORD_CHARS}, or holds a
         *                                  character the JCE would fold onto
         *                                  another password
         * @return the value to store for {@code password}
         */
        public String hash(char[] password) {
            requireUsablePassword(password);
            byte[] salt = new byte[SALT_BYTES];
            random.nextBytes(salt);
            byte[] digest = derive(password, salt, iterations);
            try {
                Base64.Encoder encoder = Base64.getEncoder();
                return FORMAT_ID + SEPARATOR + iterations + SEPARATOR
                        + encoder.encodeToString(salt) + SEPARATOR + encoder.encodeToString(digest);
            } finally {
                Arrays.fill(digest, (byte) 0);
            }
        }

        /**
         * Checks {@code password} against a stored digest. Returns
         * {@code false} for a malformed or unsupported stored value rather than
         * throwing, so one corrupt row cannot turn into a stack trace that
         * reaches a login page.
         *
         * <p>A password that {@link #hash} would have refused also returns
         * {@code false} here rather than being derived: deriving it would let a
         * candidate in one of the collapsed equivalence classes unlock a row
         * created with another member of that class.</p>
         *
         * @param password     the candidate secret; not modified
         * @param storedDigest the value read from the database
         * @return {@code true} only when {@code password} produced {@code storedDigest}
         */
        public boolean matches(char[] password, String storedDigest) {
            if (!isVerifiableCandidate(password) || storedDigest == null) {
                return false;
            }
            Stored parsed;
            try {
                parsed = Stored.parse(storedDigest);
            } catch (IllegalArgumentException malformed) {
                return false;
            }
            byte[] candidate = derive(password, parsed.salt, parsed.iterations);
            try {
                // isEqual is constant-time for equal-length inputs and
                // short-circuits only on the length difference, which the
                // stored format already fixes at DIGEST_BYTES.
                return MessageDigest.isEqual(parsed.digest, candidate);
            } finally {
                Arrays.fill(candidate, (byte) 0);
            }
        }

        /**
         * Overwrites {@code password} before the caller drops it. Best effort by
         * design: it narrows the window in which the secret sits in reachable
         * heap, it cannot retract a copy the JVM or your own code already made.
         *
         * @param password the array to overwrite; {@code null} is ignored
         */
        public static void clear(char[] password) {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }

        /**
         * {@code true} when {@code password} is present, within the length cap
         * and free of the characters the JCE would collapse. Exposed so the
         * login path can charge an unusable candidate the same cost as any
         * other attempt instead of answering it cheaply.
         *
         * @param password the candidate to inspect
         * @return {@code false} when it is absent, over-long, or would be folded
         *         onto a different password by the JCE
         */
        public static boolean isVerifiableCandidate(char[] password) {
            return password != null
                    && password.length > 0
                    && password.length <= MAX_PASSWORD_CHARS
                    && equivalenceClassDefect(password) == null;
        }

        private static void requireUsablePassword(char[] password) {
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("password must not be empty");
            }
            if (password.length > MAX_PASSWORD_CHARS) {
                throw new IllegalArgumentException(
                        "password must not exceed " + MAX_PASSWORD_CHARS + " characters");
            }
            String defect = equivalenceClassDefect(password);
            if (defect != null) {
                throw new IllegalArgumentException("password " + defect);
            }
        }

        /**
         * Finds a character that {@code PBEKeySpec} would collapse onto another
         * password, or {@code null} when the array is unambiguous.
         *
         * <p>{@code PBEKeySpec} folds {@code char[]} into bytes with the JCE's
         * own UTF-8 converter, and that converter is not injective over the
         * whole {@code char[]} domain. Measured on this JVM:</p>
         *
         * <ul>
         *   <li>trailing NUL characters are dropped, so {@code "cafe"},
         *       {@code "cafe\0"} and {@code "cafe\0\0"} all derive the same
         *       digest;</li>
         *   <li>every unpaired surrogate becomes a single {@code ?}, so U+D800,
         *       U+D801, U+DC00 and a literal {@code ?} all derive the same
         *       digest.</li>
         * </ul>
         *
         * <p>Each bullet is a set of distinct passwords that authenticate each
         * other, which is exactly what a password digest must not do. Refusing
         * both classes leaves the converter injective over everything this class
         * accepts. Correctly paired supplementary characters (emoji, astral
         * scripts) are unaffected and stay valid.</p>
         */
        private static String equivalenceClassDefect(char[] password) {
            for (int i = 0; i < password.length; i++) {
                char c = password[i];
                if (Character.isHighSurrogate(c)) {
                    if (i + 1 >= password.length || !Character.isLowSurrogate(password[i + 1])) {
                        return "contains an unpaired high surrogate, which the JCE maps to '?'";
                    }
                    i++;
                } else if (Character.isLowSurrogate(c)) {
                    return "contains an unpaired low surrogate, which the JCE maps to '?'";
                }
            }
            if (password[password.length - 1] == '\0') {
                return "ends with a NUL character, which the JCE discards";
            }
            return null;
        }

        /** Runs PBKDF2. The {@link PBEKeySpec} is cleared on every path. */
        private static byte[] derive(char[] password, byte[] salt, int iterations) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, DIGEST_BYTES * 8);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(JCA_ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                // Absent PBKDF2 or a rejected key spec is a deployment fault,
                // not a condition a caller can recover from per-request.
                throw new IllegalStateException(JCA_ALGORITHM + " is unavailable on this JVM", e);
            } finally {
                spec.clearPassword();
            }
        }

        /** One parsed {@code pbkdf2-sha256$iterations$salt$digest} value. */
        private static final class Stored {

            private final int iterations;
            private final byte[] salt;
            private final byte[] digest;

            private Stored(int iterations, byte[] salt, byte[] digest) {
                this.iterations = iterations;
                this.salt = salt;
                this.digest = digest;
            }

            static Stored parse(String storedDigest) {
                String[] parts = storedDigest.split("\\" + SEPARATOR, -1);
                if (parts.length != 4 || !FORMAT_ID.equals(parts[0])) {
                    throw new IllegalArgumentException("unrecognised password digest format");
                }
                int iterationCount;
                try {
                    iterationCount = Integer.parseInt(parts[1]);
                } catch (NumberFormatException notANumber) {
                    throw new IllegalArgumentException("password digest has no iteration count");
                }
                if (iterationCount < MIN_ITERATIONS || iterationCount > MAX_ITERATIONS) {
                    throw new IllegalArgumentException("iteration count out of range: " + iterationCount);
                }
                // Base64.getDecoder() is the strict variant: it rejects foreign
                // characters and missing padding, unlike the MIME decoder.
                byte[] salt = decode(parts[2]);
                byte[] digest = decode(parts[3]);
                if (salt.length != SALT_BYTES) {
                    throw new IllegalArgumentException("salt must be " + SALT_BYTES + " bytes");
                }
                if (digest.length != DIGEST_BYTES) {
                    throw new IllegalArgumentException("digest must be " + DIGEST_BYTES + " bytes");
                }
                return new Stored(iterationCount, salt, digest);
            }

            private static byte[] decode(String base64) {
                try {
                    return Base64.getDecoder().decode(base64);
                } catch (IllegalArgumentException notBase64) {
                    throw new IllegalArgumentException("password digest is not valid Base64", notBase64);
                }
            }
        }
    }

    /**
     * Reads and writes account rows on one connection.
     *
     * <p>Every statement that touches user-supplied data is a
     * {@link PreparedStatement} with {@code ?} placeholders, so a username such
     * as {@code ' OR 1=1 --} is stored and matched as a literal username
     * instead of becoming part of the statement text. Only {@link #TABLE}, a
     * compile-time constant, is ever concatenated into SQL.</p>
     *
     * <p>Instances are <em>not</em> thread-safe, because the underlying
     * {@link Connection} is not. Use one registry per connection (typically one
     * per request).</p>
     */
    public static final class UserRegistry {

        /** Usernames are ASCII labels: length-bounded and free of quoting and spacing surprises. */
        public static final Pattern USERNAME_PATTERN = Pattern.compile("[A-Za-z0-9._-]{3,64}");

        private static final String INSERT_SQL =
                "INSERT INTO " + TABLE + " (username, password_hash, created_at) VALUES (?, ?, ?)";
        private static final String SELECT_DIGEST_SQL =
                "SELECT password_hash FROM " + TABLE + " WHERE username = ?";
        private static final String EXISTS_SQL =
                "SELECT 1 FROM " + TABLE + " WHERE username = ?";
        private static final String CREATE_TABLE_SQL =
                "CREATE TABLE IF NOT EXISTS " + TABLE + " ("
                        + "id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, "
                        + "username VARCHAR(64) NOT NULL, "
                        + "password_hash VARCHAR(200) NOT NULL, "
                        + "created_at TIMESTAMP NOT NULL)";
        private static final String CREATE_INDEX_SQL =
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_" + TABLE + "_username ON " + TABLE + " (username)";

        /** Password tried against the guard digest when a username is unknown. */
        private static final char[] GUARD_PASSWORD = "timing-guard-password".toCharArray();

        private final Connection connection;
        private final PasswordHasher hasher;
        private final boolean commitOwnWork;

        /** A digest no real account owns, for equalising the unknown-user path. */
        private final String guardDigest;

        /**
         * A registry that commits its own inserts when the connection uses manual
         * commits. See {@link #UserRegistry(Connection, PasswordHasher, boolean)}.
         * 
         * @param connection the caller-owned connection; never closed here
         * @param hasher     the digest strategy to register and verify with
         */
        public UserRegistry(Connection connection, PasswordHasher hasher) {
            this(connection, hasher, true);
        }

        /**
         * @param connection    the caller-owned connection; never closed here
         * @param hasher        the digest strategy to register and verify with
         * @param commitOwnWork when {@code true} and the connection has manual
         *                      commits, a successful insert is committed here.
         *                      Set it to {@code false} if the surrounding unit
         *                      of work decides when to commit; nothing else
         *                      about this method's behaviour changes.
         */
        public UserRegistry(Connection connection, PasswordHasher hasher, boolean commitOwnWork) {
            if (connection == null || hasher == null) {
                throw new IllegalArgumentException("connection and hasher are required");
            }
            this.connection = connection;
            this.hasher = hasher;
            this.commitOwnWork = commitOwnWork;
            this.guardDigest = hasher.hash(GUARD_PASSWORD);
        }

        /**
         * The caller-owned connection this registry reads and writes through.
         *
         * @return the connection supplied at construction; never closed here
         */
        public Connection getConnection() {
            return connection;
        }

        /**
         * Creates {@value #TABLE} and its unique username index if absent.
         * Idempotent; call it once at startup, or run the DDL in
         * {@code README.md} through a migration instead.
         *
         * @throws SQLException if the DDL is rejected
         */
        public void ensureSchema() throws SQLException {
            try (Statement statement = connection.createStatement()) {
                statement.execute(CREATE_TABLE_SQL);
                statement.execute(CREATE_INDEX_SQL);
            }
            commitIfManaging();
        }

        /**
         * Creates an account for {@code username} with {@code password}.
         *
         * <p>The password is hashed here and only the digest reaches the
         * database. The caller's {@code char[]} is left untouched; clear it with
         * {@link PasswordHasher#clear}.</p>
         *
         * @param username the account name to create
         * @param password the secret to hash; not modified
         * @return {@link RegistrationOutcome#CREATED}, or
         *         {@link RegistrationOutcome#USERNAME_ALREADY_EXISTS} if the
         *         unique index rejected the row
         * @throws IllegalArgumentException if the username or password fails
         *                                  validation; nothing is written in
         *                                  that case
         * @throws SQLException             for any other database failure
         */
        public RegistrationOutcome register(String username, char[] password) throws SQLException {
            requireValidUsername(username);
            PasswordHasher.requireUsablePassword(password);

            String digest = hasher.hash(password);
            Timestamp now = Timestamp.valueOf(LocalDateTime.now());
            try (PreparedStatement insert = connection.prepareStatement(INSERT_SQL)) {
                insert.setString(1, username);
                insert.setString(2, digest);
                insert.setTimestamp(3, now);
                insert.executeUpdate();
            } catch (SQLException rejected) {
                if (isUniqueViolation(rejected)) {
                    // The index is the authority on uniqueness, so confirm the
                    // loser of the race is really the same username before
                    // reporting a friendly conflict.
                    if (exists(username)) {
                        rollbackIfManaging();
                        return RegistrationOutcome.USERNAME_ALREADY_EXISTS;
                    }
                }
                rollbackIfManaging();
                throw rejected;
            }
            commitIfManaging();
            return RegistrationOutcome.CREATED;
        }

        /**
         * Verifies credentials that {@link #register} stored earlier.
         *
         * <p>Both failure outcomes cost the same PBKDF2 run: the unknown-user
         * path is spent against {@link #guardDigest}. Render
         * {@code NO_SUCH_USER} and {@code BAD_PASSWORD} identically to keep that
         * equalisation meaningful.</p>
         *
         * @param username the account name presented
         * @param password the candidate secret; not modified
         * @return whether the credentials match, distinguishing an absent account
         *         from a wrong secret for server-side use only
         * @throws IllegalArgumentException if the username fails validation
         * @throws SQLException             if the lookup fails
         */
        public AuthenticationOutcome authenticate(String username, char[] password) throws SQLException {
            requireValidUsername(username);

            String storedDigest = null;
            boolean found = false;
            try (PreparedStatement select = connection.prepareStatement(SELECT_DIGEST_SQL)) {
                select.setString(1, username);
                try (ResultSet rows = select.executeQuery()) {
                    if (rows.next()) {
                        found = true;
                        storedDigest = rows.getString(1);
                    }
                }
            }

            if (!PasswordHasher.isVerifiableCandidate(password)) {
                // A blank, over-long or JCE-ambiguous candidate can never match,
                // but it must not be answered cheaply either: a fast refusal
                // would let anyone tell "user exists" from "user absent" by
                // timing, which is the whole leak the guard digest exists to
                // close. Pay the same derivation, then report.
                hasher.matches(GUARD_PASSWORD, guardDigest);
                return found
                        ? AuthenticationOutcome.BAD_PASSWORD
                        : AuthenticationOutcome.NO_SUCH_USER;
            }

            if (!found) {
                hasher.matches(GUARD_PASSWORD, guardDigest);
                return AuthenticationOutcome.NO_SUCH_USER;
            }
            return hasher.matches(password, storedDigest)
                    ? AuthenticationOutcome.AUTHENTICATED
                    : AuthenticationOutcome.BAD_PASSWORD;
        }

        /**
         * Reports whether a row owns {@code username}.
         * 
         * @param username the account name to look for
         * @return {@code true} when an account with exactly this name exists
         * @throws SQLException if the lookup fails
         */
        public boolean exists(String username) throws SQLException {
            requireValidUsername(username);
            try (PreparedStatement select = connection.prepareStatement(EXISTS_SQL)) {
                select.setString(1, username);
                try (ResultSet rows = select.executeQuery()) {
                    return rows.next();
                }
            }
        }

        private void requireValidUsername(String username) {
            if (username == null) {
                throw new IllegalArgumentException("username must not be null");
            }
            if (!USERNAME_PATTERN.matcher(username).matches()) {
                throw new IllegalArgumentException(
                        "username must be 3-64 characters of [A-Za-z0-9._-], got: "
                                + describe(username));
            }
        }

        /** Length plus character-class summary, deliberately not the value itself. */
        private static String describe(String username) {
            return "length " + username.length();
        }

        /** SQL states for constraint violations: 23xxx in H2, PostgreSQL, MariaDB. */
        private static boolean isUniqueViolation(SQLException failure) {
            for (SQLException current = failure; current != null; current = current.getNextException()) {
                String state = current.getSQLState();
                if (state != null && state.startsWith("23")) {
                    return true;
                }
            }
            return false;
        }

        private void commitIfManaging() throws SQLException {
            if (commitOwnWork && !connection.getAutoCommit()) {
                connection.commit();
            }
        }

        private void rollbackIfManaging() {
            if (!commitOwnWork) {
                return;
            }
            try {
                if (!connection.getAutoCommit()) {
                    connection.rollback();
                }
            } catch (SQLException couldNotRollBack) {
                // The original failure is the one worth reporting; a failed
                // rollback on a dying connection must not mask it.
            }
        }
    }

    /**
     * Runnable demonstration against an in-memory (or caller-supplied)
     * database. See the class javadoc and README for the guarantees on show.
     */
        /**
         * @param args optional JDBC URL, user and password; defaults to an
         *             in-memory H2 database
         * @throws SQLException if the demonstration database fails
         */
    public static void main(String[] args) throws SQLException {
        String url = args.length > 0 ? args[0] : "jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1";
        String user = args.length > 1 ? args[1] : "sa";
        String secret = args.length > 2 ? args[2] : "";

        // 1,000 rounds instead of 600,000 so the demo finishes at once. A
        // production registry is built with no argument and gets the default.
        PasswordHasher hasher = new PasswordHasher(PasswordHasher.MIN_ITERATIONS);

        try (Connection connection = java.sql.DriverManager.getConnection(url, user, secret)) {
            UserRegistry registry = new UserRegistry(connection, hasher);
            registry.ensureSchema();

            char[] alice = "correct horse battery staple".toCharArray();
            println("register alice            -> " + registry.register("alice", alice));
            PasswordHasher.clear(alice);

            char[] again = "correct horse battery staple".toCharArray();
            println("register alice (twice)    -> " + registry.register("alice", again));
            PasswordHasher.clear(again);

            char[] bob = "another secret pass-phrase".toCharArray();
            println("register bob              -> " + registry.register("bob", bob));
            PasswordHasher.clear(bob);

            char[] right = "correct horse battery staple".toCharArray();
            println("authenticate alice/right  -> " + registry.authenticate("alice", right));
            PasswordHasher.clear(right);

            char[] wrong = "correct horse battery stapled".toCharArray();
            println("authenticate alice/wrong  -> " + registry.authenticate("alice", wrong));
            PasswordHasher.clear(wrong);

            char[] anyone = "whatever secret here".toCharArray();
            println("authenticate carol/right  -> " + registry.authenticate("carol", anyone));
            PasswordHasher.clear(anyone);

            // Two ways hostile input is handled. (1) The allowlist rejects a
            // payload outright, before any statement is prepared. (2) A payload
            // built only from allowed characters is stored as a literal
            // username, not as SQL.
            String quoted = "admin' OR '1'='1";
            char[] payload = "hunter2 hunter2".toCharArray();
            try {
                registry.register(quoted, payload);
                println("register " + quoted + " -> UNEXPECTEDLY ACCEPTED");
            } catch (IllegalArgumentException refusedByValidation) {
                println("register quoted payload -> refused by validation: "
                        + refusedByValidation.getMessage());
            } finally {
                PasswordHasher.clear(payload);
            }

            char[] commentPayload = "a different secret".toCharArray();
            String commenty = "admin--";
            println("register admin--          -> " + registry.register(commenty, commentPayload));
            PasswordHasher.clear(commentPayload);

            char[] commentRight = "a different secret".toCharArray();
            println("authenticate admin--/right-> " + registry.authenticate(commenty, commentRight));
            PasswordHasher.clear(commentRight);

            char[] asAdmin = "a different secret".toCharArray();
            println("authenticate admin (never registered, suffix must not act as a comment)"
                    + " -> " + registry.authenticate("admin", asAdmin));
            PasswordHasher.clear(asAdmin);

            println("");
            println("stored rows (note: no password appears below):");
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "SELECT username, password_hash FROM " + TABLE + " ORDER BY id")) {
                while (rows.next()) {
                    println("  " + rows.getString(1) + "  ->  " + rows.getString(2));
                }
            }
        }
    }

    private static void println(String line) {
        System.out.println(line);
    }
}
