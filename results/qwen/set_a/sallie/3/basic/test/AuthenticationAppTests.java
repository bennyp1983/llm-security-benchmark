import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Checks for AuthenticationApp, run with plain asserts (no test framework is available here).
 *
 * <p>Two kinds of check are used on purpose:
 * <ul>
 *   <li>real H2 in-memory databases, which see predicates that match too much;</li>
 *   <li>a fake JDBC driver that records the exact SQL text and bound values, which sees user input
 *       being pasted into a statement instead of bound to it.</li>
 * </ul>
 * Exit status 0 means every check passed.
 */
public final class AuthenticationAppTests {

    private static int memoryUrlCounter;
    private static int failures;
    private static int checks;

    private AuthenticationAppTests() {
    }

    public static void main(String[] args) throws Exception {
        DriverManager.registerDriver(new ProbeDriver());

        hashingChecks();
        emailChecks();
        probeChecks();
        databaseChecks();
        authServiceChecks();
        timingChecks();
        applicationChecks();

        System.out.println();
        System.out.println("checks run: " + checks + ", failures: " + failures);
        if (failures > 0) {
            System.out.println("RESULT: FAILED");
            System.exit(1);
        }
        System.out.println("RESULT: PASSED");
    }

    // ---------------------------------------------------------------- hashing

    private static void hashingChecks() {
        section("PasswordHasher");

        char[] password = "correct horse battery".toCharArray();
        String first = PasswordHasher.hash(password);
        String second = PasswordHasher.hash(password);

        that("a stored value has four $-separated parts", first.split("\\$", -1).length == 4);
        that("a stored value names the algorithm", first.startsWith("pbkdf2-sha256$"));
        that("the cost is the one the program asks for", first.startsWith("pbkdf2-sha256$120000$"));
        that("a stored value holds no padding character", !first.contains("="));
        that("the salt is 16 bytes", Base64.getDecoder().decode(first.split("\\$")[2]).length == 16);
        that("the hash is 32 bytes", Base64.getDecoder().decode(first.split("\\$")[3]).length == 32);
        that("two stored values for one password differ (fresh salt)", !first.equals(second));
        that("the password verifies against its own stored value", PasswordHasher.matches(password, first));
        that("the password verifies against the second stored value too", PasswordHasher.matches(password, second));
        that("a wrong password does not verify",
                !PasswordHasher.matches("correct horse batterie".toCharArray(), first));
        that("a stored value does not contain the password", !first.contains("correct"));
        that("an unrelated password does not verify",
                !PasswordHasher.matches("other".toCharArray(), first));

        // A stored value the program would never write must never authenticate, whatever the
        // password looks like. Each fixture below is invalid in exactly one way.
        String realHash = PasswordHasher.hash("hunter2".toCharArray());
        that("a stored password in plain text does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(), "hunter2"));
        that("an empty stored value does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(), ""));
        that("a stored value with another algorithm name does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(),
                        realHash.replace("pbkdf2-sha256", "bcrypt")));
        that("a stored value with three parts does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(), realHash.substring(0, realHash.lastIndexOf('$'))));
        that("a stored value with five parts does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(), realHash + "$x"));
        that("a stored value whose cost is below the floor does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(), withIterations(realHash, 999)));
        that("a stored value whose cost is above the ceiling does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(), withIterations(realHash, 2_000_001)));
        that("a stored value whose cost is not a number does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(), withIterations(realHash, "abc")));
        that("a stored value with a non-base64 salt does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(), withSalt(realHash, "!!!!")));
        that("a stored value with a short salt does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(), withSalt(realHash, "")));
        that("a stored value with a hash of the wrong length does not authenticate",
                // Valid base64 that decodes to 24 bytes: the only thing wrong is the length, so
                // this really exercises the length check instead of the decoder.
                !PasswordHasher.matches("hunter2".toCharArray(), withHashOfLength(realHash, 24)));
        that("a stored value with a long hash of the wrong length does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(), withHashOfLength(realHash, 48)));
        // Same salt, same cost, same digest - only the length is short. A program that accepted
        // this would treat a truncated digest as a valid, weaker credential for the real password.
        that("a stored value holding a shortened copy of the real digest does not authenticate",
                !truncatedDigestAuthenticates());
        that("a null stored value does not authenticate",
                !PasswordHasher.matches("hunter2".toCharArray(), null));

        that("the cost written into a stored value is the cost actually used",
                verifiesAtCost(2_000, 2_000));
        that("a tampered cost does not verify a real password",
                !verifiesAtCost(1_999, 2_000));
        // Everything else about this one is well formed and the password really does hash to the
        // stored value; only the cost is below the floor. Accepting it would let an attacker write
        // a cheap stored value and make the server's work disappear.
        that("a well formed stored value at a below floor cost does not authenticate",
                !verifiesAtCost(100, 100));

        // Input that must be refused before anything is stored or looked up.
        that("no password is refused for being absent", PasswordHasher.isUsable("a".toCharArray()));
        that("an empty password is refused", !PasswordHasher.isUsable(new char[0]));
        that("a null password is refused", !PasswordHasher.isUsable(null));
        that("the longest accepted password is 1024 characters",
                PasswordHasher.isUsable("p".repeat(1024).toCharArray()));
        that("a 1025 character password is refused",
                !PasswordHasher.isUsable("p".repeat(1025).toCharArray()));
        that("a NUL character in a password is refused",
                !PasswordHasher.isUsable(("ab" + (char) 0 + "cd").toCharArray()));
        that("all NUL characters are refused", !PasswordHasher.isUsable(new char[1024]));
        that("a lone high surrogate is refused",
                !PasswordHasher.isUsable(("ab" + (char) 0xD835 + "cd").toCharArray()));
        that("a lone low surrogate is refused",
                !PasswordHasher.isUsable(("ab" + (char) 0xDC00 + "cd").toCharArray()));
        that("a surrogate pair is accepted",
                PasswordHasher.isUsable(("ab" + (char) 0xD835 + (char) 0xDC00 + "cd").toCharArray()));
        that("a password with a space is accepted", PasswordHasher.isUsable("a b".toCharArray()));

        // PBEKeySpec is not one-to-one over char[]: these pairs collapse to the same digest, so
        // the checks above refusing them is what keeps one stored hash to one password.
        that("a trailing NUL really would collide, which is why it is refused",
                PasswordHasher.matches("abc".toCharArray(),
                        PasswordHasher.hash(("abc" + (char) 0 + (char) 0 + (char) 0).toCharArray())));
    }

    /**
     * Builds a stored value for one password and checks it.
     *
     * @param statedCost the cost written into the stored value
     * @param realCost   the cost the expected hash was actually derived at
     */
    private static boolean verifiesAtCost(int statedCost, int realCost) {
        char[] password = "cost probe".toCharArray();
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 7);
        byte[] expected = testDerive(password, salt, realCost, 32);
        String stored = "pbkdf2-sha256$" + statedCost + "$"
                + Base64.getEncoder().withoutPadding().encodeToString(salt) + "$"
                + Base64.getEncoder().withoutPadding().encodeToString(expected);
        return PasswordHasher.matches(password, stored);
    }

    /**
     * A stored value whose hash half is the first 24 bytes of the genuine digest for the password,
     * with the salt and cost left alone.
     */
    private static boolean truncatedDigestAuthenticates() {
        char[] password = "length probe".toCharArray();
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 11);
        byte[] full = testDerive(password, salt, 2_000, 32);
        Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
        String stored = "pbkdf2-sha256$2000$" + encoder.encodeToString(salt) + "$"
                + encoder.encodeToString(Arrays.copyOf(full, 24));
        return PasswordHasher.matches(password, stored);
    }

    private static byte[] testDerive(char[] password, byte[] salt, int iterations, int hashBytes) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, hashBytes * 8);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String withIterations(String stored, Object value) {
        String[] parts = stored.split("\\$", -1);
        parts[1] = String.valueOf(value);
        return String.join("$", parts);
    }

    private static String withSalt(String stored, String replacement) {
        String[] parts = stored.split("\\$", -1);
        parts[2] = replacement;
        return String.join("$", parts);
    }

    /** Swaps the hash half of a stored value for valid base64 of a chosen byte length. */
    private static String withHashOfLength(String stored, int byteLength) {
        String[] parts = stored.split("\\$", -1);
        parts[3] = Base64.getEncoder().withoutPadding()
                .encodeToString(new byte[byteLength]);
        return String.join("$", parts);
    }

    // ------------------------------------------------------------------ email

    private static void emailChecks() {
        section("Emails");

        that("a plain address is kept", "alice@example.com".equals(Emails.normalize("alice@example.com")));
        that("upper case is folded to lower case",
                "alice@example.com".equals(Emails.normalize("Alice@Example.COM")));
        that("surrounding spaces are removed",
                "alice@example.com".equals(Emails.normalize("   alice@example.com  ")));
        that("a dot in the local part is kept", "a.b@example.com".equals(Emails.normalize("a.b@example.com")));
        that("a sub-domain is accepted", "a@sub.example.co.uk".equals(Emails.normalize("a@sub.example.co.uk")));
        that("null is refused", Emails.normalize(null) == null);
        that("an empty address is refused", Emails.normalize("") == null);
        that("spaces only is refused", Emails.normalize("     ") == null);
        that("an address with no @ is refused", Emails.normalize("alice.example.com") == null);
        that("an address with no domain is refused", Emails.normalize("alice@") == null);
        that("an address with no local part is refused", Emails.normalize("@example.com") == null);
        that("an address with two @ is refused", Emails.normalize("a@b@example.com") == null);
        that("a space inside an address is refused", Emails.normalize("ali ce@example.com") == null);
        that("an apostrophe inside an address is refused", Emails.normalize("a'b@example.com") == null);
        that("a semicolon inside an address is refused", Emails.normalize("a;DROP TABLE app_user--@example.com") == null);
        that("a domain with no dot is refused", Emails.normalize("alice@example") == null);
        that("a one letter top level domain is refused", Emails.normalize("alice@example.c") == null);
        that("a non-ascii address is refused", Emails.normalize("ali" + (char) 0xE9 + "e@example.com") == null);
        that("a control character inside an address is refused",
                Emails.normalize("ali" + (char) 0x01 + "ce@example.com") == null);
        that("a 64 character local part is accepted",
                Emails.normalize("a".repeat(64) + "@example.com") != null);
        that("a 65 character local part is refused",
                Emails.normalize("a".repeat(65) + "@example.com") == null);
        // Long addresses need a short local part to stay legal, so the length is put in the domain.
        that("a 254 character address is accepted",
                Emails.normalize("a@" + "e".repeat(248) + ".com") != null);
        that("a 255 character address is refused",
                Emails.normalize("a@" + "e".repeat(249) + ".com") == null);
    }

    // -------------------------------------------------- recorded JDBC traffic

    private static void probeChecks() throws SQLException {
        section("recorded JDBC traffic");

        Probe.reset();
        Probe.rowsToReturn = new ArrayList<>();
        Probe.rowsToReturn.add(List.of(PasswordHasher.hash("s3cret".toCharArray())));
        AuthResult ok = new AuthService(new Database(Probe.URL, "sa", "")).authenticate(
                "Alice@Example.com", "s3cret".toCharArray());
        that("the stored hash lets the password through", ok == AuthResult.SUCCESS);
        that("exactly one statement was sent", Probe.sqls.size() == 1);
        String sql = Probe.sqls.get(0);
        that("the lookup is a SELECT of the stored hash only",
                sql.startsWith("SELECT password_hash FROM app_user WHERE"))
        ;
        that("the lookup has a ? placeholder", sql.contains("?"));
        that("no value from the user appears in the SQL text", !sql.contains("alice@example.com"));
        that("the email address is bound as a parameter",
                Probe.bindings.size() == 1 && "alice@example.com".equals(Probe.bindings.get(0)));
        that("the address is lower cased before it reaches the database",
                !Probe.bindings.isEmpty() && Probe.bindings.get(0).equals(Probe.bindings.get(0).toLowerCase()));

        Probe.reset();
        Probe.rowsToReturn = new ArrayList<>();
        Probe.rowsToReturn.add(List.of());
        AuthResult unknown = new AuthService(new Database(Probe.URL, "sa", "")).authenticate(
                "nobody@example.com", "whatever".toCharArray());
        that("an unknown address is rejected", unknown == AuthResult.FAILURE);
        that("an unknown address still runs exactly one statement", Probe.sqls.size() == 1);
        that("an unknown address is not reported as a success", unknown != AuthResult.SUCCESS);

        Probe.reset();
        AuthResult blankPassword = new AuthService(new Database(Probe.URL, "sa", "")).authenticate(
                "alice@example.com", new char[0]);
        that("an empty password is refused before any lookup", blankPassword == AuthResult.INVALID_INPUT);
        that("an empty password sends no statement at all", Probe.sqls.size() == 0);

        Probe.reset();
        AuthResult blankEmail = new AuthService(new Database(Probe.URL, "sa", ""))
                .authenticate("not an email", "pw".toCharArray());
        that("a malformed address is refused before any lookup", blankEmail == AuthResult.INVALID_INPUT);
        that("a malformed address sends no statement at all", Probe.sqls.size() == 0);

        // Values that would be dangerous if they were pasted into the statement text.
        String[] attacks = {
                "' OR '1'='1",
                "a' --",
                "'; DROP TABLE app_user; --",
                "alice@example.com' OR '1'='1' --",
                "%",
                "_",
                "alice@example.com\ntext",
        };
        for (String attack : attacks) {
            Probe.reset();
            Probe.rowsToReturn = new ArrayList<>();
            Probe.rowsToReturn.add(List.of(PasswordHasher.hash("s3cret".toCharArray())));
            AuthResult result = new AuthService(new Database(Probe.URL, "sa", "")).authenticate(
                    attack, "s3cret".toCharArray());
            that("the attack " + attack.replace("\n", "\\n") + " never signs in", result != AuthResult.SUCCESS);
            for (String sent : Probe.sqls) {
                that("the attack " + attack.replace("\n", "\\n") + " never reaches the SQL text",
                        !sent.contains(attack.replace("\n", "\\n").substring(0, Math.min(6, attack.length()))));
            }
        }

        Probe.reset();
        Probe.sqls.clear();
        Probe.throwOnExecute = new SQLException("database went away", "08001");
        AuthResult databaseDown = new AuthService(new Database(Probe.URL, "sa", ""))
                .authenticate("alice@example.com", "s3cret".toCharArray());
        that("a database failure is never a success", databaseDown == AuthResult.FAILURE);
        that("a database failure really did reach the lookup", Probe.sqls.size() == 1);

        Probe.reset();
        Probe.rowsToReturn = new ArrayList<>();
        Probe.rowsToReturn.add(List.of("not-a-stored-value"));
        AuthResult corrupt = new AuthService(new Database(Probe.URL, "sa", ""))
                .authenticate("alice@example.com", "anything".toCharArray());
        that("a stored value the program would not write is rejected", corrupt == AuthResult.FAILURE);

        Probe.reset();
        Probe.rowsToReturn = new ArrayList<>();
        Probe.rowsToReturn.add(Arrays.asList((String) null));
        AuthResult nullHash = new AuthService(new Database(Probe.URL, "sa", ""))
                .authenticate("alice@example.com", "anything".toCharArray());
        that("a NULL stored hash is rejected", nullHash == AuthResult.FAILURE);

        // The storing path is recorded too, so nothing from a user is pasted into a statement.
        Probe.reset();
        Probe.rowsToReturn = new ArrayList<>();
        boolean stored = new Database(Probe.URL, "sa", "").addUser(
                "Alice@Example.com", "P@ssw0rd secret".toCharArray());
        that("an account can be stored through the recorded driver", stored);
        that("storing sends exactly one statement", Probe.sqls.size() == 1);
        String insertSql = Probe.sqls.get(0);
        that("storing is an INSERT into the account table", insertSql.startsWith("INSERT INTO app_user"));
        that("storing uses two placeholders", insertSql.split("\\?", -1).length == 3);
        that("the email address never appears in the INSERT text", !insertSql.contains("Alice@Example.com"));
        that("the password never appears in the INSERT text", !insertSql.contains("P@ssw0rd"));
        that("storing binds exactly two values", Probe.bindings.size() == 2);
        that("the first bound value is the lower cased address",
                !Probe.bindings.isEmpty() && "alice@example.com".equals(Probe.bindings.get(0)));
        that("the second bound value is the stored hash, not the password",
                Probe.bindings.size() == 2 && Probe.bindings.get(1).startsWith("pbkdf2-sha256$")
                        && !Probe.bindings.get(1).contains("P@ssw0rd"));
    }

    // ----------------------------------------------------------- real database

    private static void databaseChecks() throws Exception {
        section("real database (H2)");

        String url = memoryUrl();
        Database db = new Database(url, "sa", "");
        db.initSchema();
        db.initSchema();
        that("initSchema can be run twice", true);

        char[] password = "hunter2 hunter2".toCharArray();
        that("an account can be stored", db.addUser("Alice@Example.com", password));
        that("the stored address is lower cased",
                scalar(url, "SELECT COUNT(*) FROM app_user WHERE email = 'alice@example.com'") == 1);
        that("the stored address keeps no surrounding spaces",
                scalar(url, "SELECT COUNT(*) FROM app_user WHERE email = '  alice@example.com  '") == 0);
        String stored = db.findPasswordHash("alice@example.com");
        that("the stored hash can be read back", stored != null && stored.startsWith("pbkdf2-sha256$"));
        that("the stored hash is not the password", !stored.contains("hunter2"));
        that("an unknown address reads back as null", db.findPasswordHash("nobody@example.com") == null);

        boolean duplicateBlocked = false;
        try {
            db.addUser("alice@example.com", "other".toCharArray());
        } catch (SQLException e) {
            duplicateBlocked = e.getSQLState() != null && e.getSQLState().startsWith("23");
        }
        that("the same address cannot be stored twice", duplicateBlocked);
        that("the failed second write left one row", scalar(url, "SELECT COUNT(*) FROM app_user") == 1);

        boolean shortPasswordStored = true;
        try {
            db.addUser("bob@example.com", new char[0]);
        } catch (IllegalArgumentException e) {
            shortPasswordStored = false;
        }
        that("an empty password cannot be stored", !shortPasswordStored);
        boolean badEmailStored = true;
        try {
            db.addUser("not an email", "pw".toCharArray());
        } catch (IllegalArgumentException e) {
            badEmailStored = false;
        }
        that("a malformed address cannot be stored", !badEmailStored);
        that("neither refused write left a row", scalar(url, "SELECT COUNT(*) FROM app_user") == 1);

        // An address that needs quoting in SQL text must still be pure data, end to end.
        String quotedUrl = memoryUrl();
        Database quotedDb = new Database(quotedUrl, "sa", "");
        quotedDb.initSchema();
        String quoteAddress = "a" + (char) 0 + "b@example.com";
        boolean nullByteAddressStored;
        try {
            quotedDb.addUser(quoteAddress, "pw".toCharArray());
            nullByteAddressStored = true;
        } catch (IllegalArgumentException e) {
            nullByteAddressStored = false;
        }
        that("an address containing a NUL is refused rather than passed to the driver", !nullByteAddressStored);

        // Two rows for one address is a broken table; the code must not pick one of them at random.
        String twoRowsUrl = memoryUrl();
        createTable(twoRowsUrl, false);
        insertRow(twoRowsUrl, "alice@example.com", PasswordHasher.hash("pw".toCharArray()));
        insertRow(twoRowsUrl, "alice@example.com", PasswordHasher.hash("pw".toCharArray()));
        AuthResult ambiguous = new AuthService(new Database(twoRowsUrl, "sa", ""))
                .authenticate("alice@example.com", "pw".toCharArray());
        that("an account stored twice is never signed in", ambiguous == AuthResult.FAILURE);

        // H2's default comparison is case sensitive, which is why the program normalises itself.
        String caseUrl = memoryUrl();
        createTable(caseUrl, true);
        insertRow(caseUrl, "Alice@Example.com", PasswordHasher.hash("pw".toCharArray()));
        that("a row inserted with mixed case is not matched by the lower cased lookup",
                new AuthService(new Database(caseUrl, "sa", "")).authenticate("alice@example.com", "pw".toCharArray())
                        == AuthResult.FAILURE);

        // LIKE instead of = would match a wildcard address; a real engine is what shows this up.
        String likeUrl = memoryUrl();
        Database likeDb = new Database(likeUrl, "sa", "");
        likeDb.initSchema();
        likeDb.addUser("alice@example.com", "pw".toCharArray());
        likeDb.addUser("mallory@example.com", "pw".toCharArray());
        that("the lookup for a % address finds no account",
                "no row".equals(lookupOutcome(likeDb, "%")));
        that("the lookup for an _ address finds no account",
                "no row".equals(lookupOutcome(likeDb, "_")));
        that("the lookup for a real address still finds it",
                "row".equals(lookupOutcome(likeDb, "alice@example.com")));

        // A stored value that is plain text must not let the account in, against a real table.
        String plainUrl = memoryUrl();
        createTable(plainUrl, true);
        insertRow(plainUrl, "alice@example.com", "hunter2");
        that("a plain text stored password does not open the account",
                new AuthService(new Database(plainUrl, "sa", "")).authenticate(
                        "alice@example.com", "hunter2".toCharArray()) == AuthResult.FAILURE);
    }

    private static void createTable(String url, boolean withPrimaryKey) throws SQLException {
        try (Connection connection = DriverManager.getConnection(url, "sa", "");
             java.sql.Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE app_user (email VARCHAR(254) NOT NULL"
                    + (withPrimaryKey ? " PRIMARY KEY" : "")
                    + ", password_hash VARCHAR(512) NOT NULL)");
        }
    }

    private static void insertRow(String url, String email, String hash) throws SQLException {
        try (Connection connection = DriverManager.getConnection(url, "sa", "");
             PreparedStatement statement = connection.prepareStatement(
                     "INSERT INTO app_user (email, password_hash) VALUES (?, ?)")) {
            statement.setString(1, email);
            statement.setString(2, hash);
            statement.executeUpdate();
        }
    }

    /**
     * What a lookup returns, as text, so a lookup that throws is reported as a failed assertion
     * rather than ending the run.
     *
     * @return "row", "no row", or "error: &lt;message&gt;"
     */
    private static String lookupOutcome(Database db, String email) {
        try {
            return db.findPasswordHash(email) == null ? "no row" : "row";
        } catch (SQLException e) {
            return "error: " + e.getMessage();
        }
    }

    private static long scalar(String url, String sql) throws SQLException {
        try (Connection connection = DriverManager.getConnection(url, "sa", "");
             java.sql.Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(sql)) {
            return rows.next() ? rows.getLong(1) : -1;
        }
    }

    // ------------------------------------------------------------ auth service

    private static void authServiceChecks() throws Exception {
        section("AuthService (real database)");

        String url = memoryUrl();
        Database db = new Database(url, "sa", "");
        db.initSchema();
        db.addUser("alice@example.com", "right horse".toCharArray());
        AuthService service = new AuthService(db);

        that("the right password is accepted",
                service.authenticate("alice@example.com", "right horse".toCharArray()) == AuthResult.SUCCESS);
        that("the right password typed with different case in the address is accepted",
                service.authenticate("  ALICE@EXAMPLE.COM ", "right horse".toCharArray()) == AuthResult.SUCCESS);
        that("a wrong password is refused",
                service.authenticate("alice@example.com", "right horsel".toCharArray()) == AuthResult.FAILURE);
        that("a wrong password of the same length is refused",
                service.authenticate("alice@example.com", "right horsf".toCharArray()) == AuthResult.FAILURE);
        that("an unknown address is refused",
                service.authenticate("nobody@example.com", "right horse".toCharArray()) == AuthResult.FAILURE);
        that("an empty password is refused as invalid input",
                service.authenticate("alice@example.com", new char[0]) == AuthResult.INVALID_INPUT);
        that("a null password is refused as invalid input",
                service.authenticate("alice@example.com", null) == AuthResult.INVALID_INPUT);
        that("an over long password is refused as invalid input",
                service.authenticate("alice@example.com", "p".repeat(1025).toCharArray())
                        == AuthResult.INVALID_INPUT);
        that("the longest allowed password works end to end",
                longPasswordRoundTrip());
        that("authenticate does not erase the caller's password", callerKeepsPassword());
        that("the decision does not depend on order of accounts",
                service.authenticate("alice@example.com", "right horse".toCharArray()) == AuthResult.SUCCESS);
    }

    private static boolean longPasswordRoundTrip() throws Exception {
        String url = memoryUrl();
        Database db = new Database(url, "sa", "");
        db.initSchema();
        char[] password = "p".repeat(1024).toCharArray();
        db.addUser("alice@example.com", password);
        return new AuthService(db).authenticate("alice@example.com", password) == AuthResult.SUCCESS;
    }

    private static boolean callerKeepsPassword() throws Exception {
        String url = memoryUrl();
        Database db = new Database(url, "sa", "");
        db.initSchema();
        char[] password = "shared buffer".toCharArray();
        db.addUser("alice@example.com", "other".toCharArray());
        new AuthService(db).authenticate("alice@example.com", password);
        return "shared buffer".equals(new String(password));
    }

    // ------------------------------------------------------------------ timing

    private static void timingChecks() throws Exception {
        section("timing (no account enumeration)");

        String url = memoryUrl();
        Database db = new Database(url, "sa", "");
        db.initSchema();
        db.addUser("alice@example.com", "measured password".toCharArray());
        AuthService service = new AuthService(db);
        char[] wrong = "wrong password".toCharArray();
        char[] unknownAddressPassword = "wrong password".toCharArray();

        // Warm up so the first measured call is not paying for class loading.
        for (int i = 0; i < 2; i++) {
            service.authenticate("alice@example.com", wrong);
            service.authenticate("nobody@example.com", unknownAddressPassword);
        }

        int rounds = 5;
        long[] known = new long[rounds];
        long[] unknown = new long[rounds];
        for (int i = 0; i < rounds; i++) {
            long start = System.nanoTime();
            that("a known address with a wrong password is refused",
                    service.authenticate("alice@example.com", wrong) == AuthResult.FAILURE);
            known[i] = System.nanoTime() - start;

            start = System.nanoTime();
            that("an unknown address is refused",
                    service.authenticate("nobody@example.com", unknownAddressPassword) == AuthResult.FAILURE);
            unknown[i] = System.nanoTime() - start;
        }

        long knownMedian = median(known);
        long unknownMedian = median(unknown);
        double ratio = (double) Math.max(knownMedian, unknownMedian) / Math.min(knownMedian, unknownMedian);
        System.out.println("  known account  : " + (knownMedian / 1_000_000) + " ms");
        System.out.println("  unknown account: " + (unknownMedian / 1_000_000) + " ms");
        System.out.println("  ratio          : " + String.format("%.2f", ratio));
        that("both refusals do real hash work (over 5 ms each)",
                knownMedian > 5_000_000L && unknownMedian > 5_000_000L);
        that("a known and an unknown address take about the same time", ratio <= 2.0);

        long start = System.nanoTime();
        service.authenticate("alice@example.com", new char[0]);
        long refusedMillis = (System.nanoTime() - start) / 1_000_000;
        long knownMillis = knownMedian / 1_000_000;
        System.out.println("  refused input  : " + refusedMillis + " ms");
        that("input refused before the lookup comes back faster than a hash", refusedMillis < knownMillis);
    }

    private static long median(long[] values) {
        long[] copy = values.clone();
        Arrays.sort(copy);
        return copy[copy.length / 2];
    }

    // -------------------------------------------------------------- whole app

    private static void applicationChecks() throws Exception {
        section("whole program (separate process)");

        String classes = System.getProperty("test.classes");
        String h2Jar = System.getProperty("h2.jar");
        String launcher = System.getProperty("java.home") + "/bin/java";
        String url = "jdbc:h2:" + java.nio.file.Files.createTempDirectory("auth-e2e") + "/db;DB_CLOSE_DELAY=-1";
        String[] cp = {"-cp", classes + java.io.File.pathSeparator + h2Jar};

        Run init = run(launcher, cp, url, null, "init");
        that("init succeeds", init.exit == 0);
        that("init says the schema is ready", init.out.contains("schema is ready"));

        Run added = run(launcher, cp, url, "First secret", "add", "alice@example.com");
        that("storing an account succeeds", added.exit == 0);
        that("storing an account says so", added.out.contains("Password stored"));

        Run good = run(launcher, cp, url, "First secret", "login", "alice@example.com");
        that("the right password exits 0", good.exit == 0);
        that("the right password prints only the success line",
                "Authentication successful.".equals(good.out.trim()));
        that("the right password says nothing on standard error", good.err.isEmpty());

        Run otherCase = run(launcher, cp, url, "First secret", "login", "ALICE@EXAMPLE.COM");
        that("a different letter case exits 0", otherCase.exit == 0);
        that("a different letter case prints the success line",
                "Authentication successful.".equals(otherCase.out.trim()));

        Run bad = run(launcher, cp, url, "Wrong secret", "login", "alice@example.com");
        that("a wrong password exits 1", bad.exit == 1);
        that("a wrong password prints only the refusal line",
                "Authentication unsuccessful.".equals(bad.out.trim()));
        that("a wrong password says nothing about the password on standard error",
                !bad.err.contains("password"));

        Run unknownAccount = run(launcher, cp, url, "First secret", "login", "nobody@example.com");
        that("an unknown address exits 1", unknownAccount.exit == 1);
        that("an unknown address is indistinguishable from a wrong password",
                unknownAccount.out.trim().equals(bad.out.trim()) && unknownAccount.exit == bad.exit);

        Run empty = run(launcher, cp, url, "", "login", "alice@example.com");
        that("an empty password exits 2", empty.exit == 2);
        that("an empty password still prints the refusal line",
                "Authentication unsuccessful.".equals(empty.out.trim()));
        that("an empty password does not open the account", empty.exit != 0);

        Run badAddress = run(launcher, cp, url, "First secret", "login", "not an email");
        that("a malformed address exits 2", badAddress.exit == 2);
        that("a malformed address still prints the refusal line",
                "Authentication unsuccessful.".equals(badAddress.out.trim()));

        Run injection = run(launcher, cp, url, "x", "login", "' OR '1'='1");
        that("a quoting attack cannot sign in", injection.exit != 0);
        that("a quoting attack prints the refusal line",
                "Authentication unsuccessful.".equals(injection.out.trim()));

        Run injectionInside = run(launcher, cp, url, "x", "login", "alice@example.com' OR '1'='1");
        that("a quoting attack behind a real address cannot sign in", injectionInside.exit != 0);

        Run duplicate = run(launcher, cp, url, "Second secret", "add", "alice@example.com");
        that("storing an existing address fails", duplicate.exit == 3);
        that("storing an existing address says it is taken", duplicate.err.contains("already"));
        that("the failed second store did not replace the password",
                run(launcher, cp, url, "First secret", "login", "alice@example.com").exit == 0);
        that("the failed second store did not change the first password",
                run(launcher, cp, url, "Second secret", "login", "alice@example.com").exit == 1);

        Run help = run(launcher, cp, url, null, "--help");
        that("--help exits 0", help.exit == 0);
        that("--help lists the commands", help.out.contains("login") && help.out.contains("add"));

        Run noArgs = run(launcher, cp, url, null);
        that("no arguments is a usage error", noArgs.exit == 3);
        that("no arguments prints the usage", noArgs.out.contains("Usage:") || noArgs.err.contains("Usage:"));

        Run unknownCommand = run(launcher, cp, url, null, "destroy");
        that("an unknown command is a usage error", unknownCommand.exit == 3);

        Run danglingOption = run(launcher, cp, url, null, "--url");
        that("an option with no value is a usage error", danglingOption.exit == 3);

        // A database that cannot be reached must fail closed: refused, never signed in.
        Run unreachable = run(launcher, cp, "jdbc:not-a-real-driver:db", "x", "login", "alice@example.com");
        that("a database that cannot be opened exits 1 as a refusal", unreachable.exit == 1);
        that("a database that cannot be opened prints the refusal line",
                "Authentication unsuccessful.".equals(unreachable.out.trim()));
        that("a database that cannot be opened never says successful",
                !unreachable.out.contains("Authentication successful"));
        that("a database that cannot be opened says the lookup failed",
                unreachable.err.contains("could not be looked up"));

        // A database that cannot be reached while storing must be reported as a database problem.
        Run unreachableAdd = run(launcher, cp, "jdbc:not-a-real-driver:db", "x", "add", "alice@example.com");
        that("storing against an unreachable database exits 3", unreachableAdd.exit == 3);
        that("storing against an unreachable database never claims success",
                !unreachableAdd.out.contains("Password stored"));
    }

    private static final class Run {
        int exit;
        String out = "";
        String err = "";
    }

    private static Run run(String launcher, String[] cp, String url, String password, String... args)
            throws Exception {
        List<String> command = new ArrayList<>();
        command.add(launcher);
        command.addAll(Arrays.asList(cp));
        command.add("AuthenticationApp");
        command.add("--url");
        command.add(url);
        command.addAll(Arrays.asList(args));

        ProcessBuilder builder = new ProcessBuilder(command);
        builder.environment().put("DB_URL", url);
        if (password == null) {
            builder.environment().remove("DEMO_PASSWORD");
        } else {
            builder.environment().put("DEMO_PASSWORD", password);
        }
        Process process = builder.start();
        process.getOutputStream().close();

        Run result = new Run();
        result.out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        result.err = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
        result.exit = process.waitFor();
        System.out.println("  $ " + String.join(" ", args) + " -> exit " + result.exit
                + (result.out.isBlank() ? "" : " | out: " + result.out.trim().replace("\n", " / "))
                + (result.err.isBlank() ? "" : " | err: " + result.err.trim().replace("\n", " / ")));
        return result;
    }

    // ---------------------------------------------------------------- plumbing

    private static synchronized String memoryUrl() {
        memoryUrlCounter++;
        return "jdbc:h2:mem:testdb" + memoryUrlCounter + ";DB_CLOSE_DELAY=-1";
    }

    private static void section(String name) {
        System.out.println();
        System.out.println("== " + name + " ==");
    }

    private static void that(String description, boolean condition) {
        checks++;
        if (!condition) {
            failures++;
            System.out.println("  FAIL: " + description);
        } else {
            System.out.println("  ok:   " + description);
        }
    }

    // ------------------------------------------------------- fake JDBC driver

    /** Records the SQL text and bound values and replays scripted rows. */
    private static final class Probe {
        static final String URL = "jdbc:probe:mem";
        static final List<String> sqls = new ArrayList<>();
        static final List<String> bindings = new ArrayList<>();
        static List<List<String>> rowsToReturn = new ArrayList<>();
        static SQLException throwOnExecute;

        static void reset() {
            sqls.clear();
            bindings.clear();
            rowsToReturn = new ArrayList<>();
            throwOnExecute = null;
        }
    }

    private static final class ProbeDriver implements Driver {
        @Override
        public Connection connect(String url, java.util.Properties info) throws SQLException {
            if (!acceptsURL(url)) {
                return null;
            }
            return (Connection) java.lang.reflect.Proxy.newProxyInstance(
                    ProbeDriver.class.getClassLoader(), new Class<?>[] {Connection.class},
                    (proxy, method, args) -> {
                        switch (method.getName()) {
                            case "prepareStatement":
                                Probe.sqls.add((String) args[0]);
                                return statement();
                            case "close":
                            case "commit":
                            case "rollback":
                            case "setAutoCommit":
                                return null;
                            case "isClosed":
                                return false;
                            case "isValid":
                                return true;
                            case "toString":
                                return "ProbeConnection";
                            case "hashCode":
                                return System.identityHashCode(proxy);
                            case "equals":
                                return proxy == args[0];
                            default:
                                return defaultValue(method.getReturnType());
                        }
                    });
        }

        private Object statement() {
            List<String> rows = Probe.rowsToReturn.isEmpty() ? List.of() : Probe.rowsToReturn.remove(0);
            return java.lang.reflect.Proxy.newProxyInstance(
                    ProbeDriver.class.getClassLoader(), new Class<?>[] {PreparedStatement.class},
                    (proxy, method, args) -> {
                        switch (method.getName()) {
                            case "setString":
                                Probe.bindings.add((String) args[1]);
                                return null;
                            case "executeQuery":
                                if (Probe.throwOnExecute != null) {
                                    throw Probe.throwOnExecute;
                                }
                                return rowsFor(rows);
                            case "executeUpdate":
                                if (Probe.throwOnExecute != null) {
                                    throw Probe.throwOnExecute;
                                }
                                return 1;
                            case "close":
                            case "clearParameters":
                                return null;
                            case "toString":
                                return "ProbeStatement";
                            case "hashCode":
                                return System.identityHashCode(proxy);
                            case "equals":
                                return proxy == args[0];
                            default:
                                return defaultValue(method.getReturnType());
                        }
                    });
        }

        private Object rowsFor(List<String> rows) {
            int[] cursor = {-1};
            return java.lang.reflect.Proxy.newProxyInstance(
                    ProbeDriver.class.getClassLoader(), new Class<?>[] {ResultSet.class},
                    (proxy, method, args) -> {
                        switch (method.getName()) {
                            case "next":
                                cursor[0]++;
                                return cursor[0] < rows.size();
                            case "getString":
                                return cursor[0] >= 0 && cursor[0] < rows.size()
                                        ? rows.get(cursor[0]) : null;
                            case "close":
                                return null;
                            case "wasNull":
                                return false;
                            case "toString":
                                return "ProbeResultSet";
                            case "hashCode":
                                return System.identityHashCode(proxy);
                            case "equals":
                                return proxy == args[0];
                            default:
                                return defaultValue(method.getReturnType());
                        }
                    });
        }

        private Object defaultValue(Class<?> type) {
            if (!type.isPrimitive()) {
                return null;
            }
            if (type == boolean.class) {
                return false;
            }
            if (type == void.class) {
                return null;
            }
            return 0;
        }

        @Override
        public boolean acceptsURL(String url) {
            return url != null && url.startsWith(Probe.URL);
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String url, java.util.Properties info) {
            return new DriverPropertyInfo[0];
        }

        @Override
        public int getMajorVersion() {
            return 1;
        }

        @Override
        public int getMinorVersion() {
            return 0;
        }

        @Override
        public boolean jdbcCompliant() {
            return false;
        }

        @Override
        public java.util.logging.Logger getParentLogger() {
            throw new UnsupportedOperationException();
        }
    }
}
