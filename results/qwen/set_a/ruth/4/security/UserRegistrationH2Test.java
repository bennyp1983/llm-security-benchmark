import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Integration checks for {@link UserRegistration} against a real H2 database.
 *
 * Run: {@code java -cp out:h2.jar UserRegistrationH2Test [jdbc-url]}
 * Exits non-zero and prints every failed check otherwise.
 */
public final class UserRegistrationH2Test {

    private static final List<String> failures = new ArrayList<>();
    private static int checks;

    /** Small KDF cost keeps the suite quick; the guard digest is still real PBKDF2. */
    private static final int TEST_ITERATIONS = 1_000;

    /** Larger cost for the timing checks, so PBKDF2 dominates the measurement. */
    private static final int TIMING_ITERATIONS = 40_000;

    private UserRegistrationH2Test() {
    }

    public static void main(String[] args) throws Exception {
        String base = args.length > 0 ? args[0] : "jdbc:h2:mem:secsuite;DB_CLOSE_DELAY=-1";
        System.out.println("H2 target: " + base);

        UserRegistration.PasswordHasher hasher = new UserRegistration.PasswordHasher(TEST_ITERATIONS);

        try (Connection connection = DriverManager.getConnection(base, "sa", "")) {
            UserRegistration.UserRegistry registry = freshRegistry(connection, hasher);

            testRegistrationWritesDigestOnly(registry, connection);
            testAuthentication(registry);
            testDuplicateUsername(registry, connection);
            testSamePasswordDifferentDigest(registry);
            testUnknownUser(registry);
            testUsernameLookAlikePayloads(registry);
            testWildcardUsernameIsNotAWildcard(registry);
            testUsernameIsCaseSensitive(registry);
            testValidationRejectsHostileInput(registry, connection);
            testPasswordValidation(registry, connection);
            testDigestFitsColumn(registry);
            testCallerPasswordNotModified(registry);
            testExists(registry);
            testMalformedStoredDigestsFailClosed(hasher);
            testNonCanonicalStoredDigestDoesNotAuthenticate(hasher);
            testKnownAnswerVector();
            testAmbiguousPasswordCharactersAreRefused();
            testHashIsNotIdempotent(hasher);
            testClearZeroesArray(hasher);
            testMigrationFromLowerCostKeepsWorking(hasher, connection);
        }

        testManualCommitOwnsTransaction(base, hasher, true);
        testManualCommitOwnsTransaction(base, hasher, false);
        testUnknownUserTimingIsNotCheap(base, hasher);

        report();
    }

    // ---------------------------------------------------------------- checks

    private static void testRegistrationWritesDigestOnly(UserRegistration.UserRegistry registry,
                                                         Connection connection) throws Exception {
        char[] password = "S3cret! pass-phrase".toCharArray();
        check("register returns CREATED",
                registry.register("digestonly", password) == UserRegistration.RegistrationOutcome.CREATED);

        try (PreparedStatement select =
                     connection.prepareStatement("SELECT username, password_hash FROM app_users WHERE username = ?")) {
            select.setString(1, "digestonly");
            try (ResultSet rows = select.executeQuery()) {
                check("exactly one row was written", rows.next());
                check("no second row was written", !rows.next());
            }
        }

        String stored = digestOf(connection, "digestonly");
        check("stored value is a pbkdf2-sha256 digest",
                stored != null && stored.startsWith("pbkdf2-sha256$" + TEST_ITERATIONS + "$"));
        check("stored value is 4 dollar-separated fields", stored.split("\\$", -1).length == 4);
        check("stored value does not contain the password", !stored.contains("S3cret! pass-phrase"));
        check("stored value is within the declared VARCHAR(200)", stored.length() <= 200);

        String usernameColumn = textOf(connection, "SELECT username FROM app_users WHERE username = ?", "digestonly");
        check("username column does not contain the password", !usernameColumn.contains("S3cret"));
        UserRegistration.PasswordHasher.clear(password);
    }

    private static void testAuthentication(UserRegistration.UserRegistry registry) throws Exception {
        char[] password = "correct horse battery staple".toCharArray();
        registry.register("authcase", password);
        UserRegistration.PasswordHasher.clear(password);

        char[] right = "correct horse battery staple".toCharArray();
        check("correct password authenticates",
                registry.authenticate("authcase", right) == UserRegistration.AuthenticationOutcome.AUTHENTICATED);
        UserRegistration.PasswordHasher.clear(right);

        String[] wrongOnes = {
                "correct horse battery stapled",   // last char
                "Correct horse battery staple",    // case
                "correct horse battery staple ",   // trailing space
                "correct",                         // prefix
                "",                                // empty
        };
        for (String wrong : wrongOnes) {
            char[] candidate = wrong.toCharArray();
            check("rejects password [" + describe(wrong) + "]",
                    registry.authenticate("authcase", candidate)
                            == (wrong.isEmpty()
                            ? UserRegistration.AuthenticationOutcome.BAD_PASSWORD
                            : UserRegistration.AuthenticationOutcome.BAD_PASSWORD));
            UserRegistration.PasswordHasher.clear(candidate);
        }
    }

    private static void testDuplicateUsername(UserRegistration.UserRegistry registry,
                                              Connection connection) throws Exception {
        char[] first = "first secret".toCharArray();
        registry.register("dupcase", first);
        UserRegistration.PasswordHasher.clear(first);
        String originalDigest = digestOf(connection, "dupcase");

        char[] second = "second secret".toCharArray();
        check("duplicate username reports a conflict",
                registry.register("dupcase", second)
                        == UserRegistration.RegistrationOutcome.USERNAME_ALREADY_EXISTS);
        UserRegistration.PasswordHasher.clear(second);

        check("conflict did not overwrite the stored digest",
                originalDigest.equals(digestOf(connection, "dupcase")));
        check("conflict did not add a row", rowCount(connection, "dupcase") == 1);

        char[] firstAgain = "first secret".toCharArray();
        check("original password still authenticates after the conflict",
                registry.authenticate("dupcase", firstAgain)
                        == UserRegistration.AuthenticationOutcome.AUTHENTICATED);
        UserRegistration.PasswordHasher.clear(firstAgain);
    }

    private static void testSamePasswordDifferentDigest(UserRegistration.UserRegistry registry) throws Exception {
        char[] shared = "the very same secret".toCharArray();
        registry.register("salt-a", shared);
        registry.register("salt-b", shared);

        String a = digestOf(registry.getConnection(), "salt-a");
        String b = digestOf(registry.getConnection(), "salt-b");
        check("two accounts with one password get different digests", !a.equals(b));
        check("two accounts with one password get different salts",
                !a.split("\\$", -1)[2].equals(b.split("\\$", -1)[2]));

        char[] same = "the very same secret".toCharArray();
        check("both accounts still authenticate",
                registry.authenticate("salt-a", same) == UserRegistration.AuthenticationOutcome.AUTHENTICATED
                        && registry.authenticate("salt-b", same) == UserRegistration.AuthenticationOutcome.AUTHENTICATED);
        UserRegistration.PasswordHasher.clear(same);
        UserRegistration.PasswordHasher.clear(shared);
    }

    private static void testUnknownUser(UserRegistration.UserRegistry registry) throws Exception {
        char[] password = "any secret at all".toCharArray();
        check("unknown username is not authenticated",
                registry.authenticate("nobody-here", password)
                        == UserRegistration.AuthenticationOutcome.NO_SUCH_USER);
        UserRegistration.PasswordHasher.clear(password);
    }

    private static void testUsernameLookAlikePayloads(UserRegistration.UserRegistry registry) throws Exception {
        char[] password = "payload secret".toCharArray();
        registry.register("payload-case", password);
        UserRegistration.PasswordHasher.clear(password);

        char[] same = "payload secret".toCharArray();
        String[] lookalikes = {
                "admin' OR '1'='1",           // refused by the allowlist
                "payload-case' --",           // refused (space, quote, dashes survive to the check)
                "payload-case",               // control: this one is real
        };
        for (String username : lookalikes) {
            boolean isReal = username.equals("payload-case");
            try {
                UserRegistration.AuthenticationOutcome outcome = registry.authenticate(username, same);
                check("lookup of [" + describe(username) + "] -> " + outcome,
                        isReal ? outcome == UserRegistration.AuthenticationOutcome.AUTHENTICATED
                                : outcome == UserRegistration.AuthenticationOutcome.NO_SUCH_USER);
            } catch (IllegalArgumentException refused) {
                check("lookup of [" + describe(username) + "] is refused by validation", !isReal);
            }
        }

        // A payload made only of allowed characters reaches SQL as data: the
        // trailing "--" must not behave like a SQL comment.
        char[] commentSecret = "comment secret".toCharArray();
        check("username ending in -- can be registered",
                registry.register("admin--", commentSecret) == UserRegistration.RegistrationOutcome.CREATED);
        UserRegistration.PasswordHasher.clear(commentSecret);

        char[] commentRight = "comment secret".toCharArray();
        check("admin-- authenticates itself",
                registry.authenticate("admin--", commentRight) == UserRegistration.AuthenticationOutcome.AUTHENTICATED);
        check("admin (without the --) is still a different account",
                registry.authenticate("admin", commentRight) == UserRegistration.AuthenticationOutcome.NO_SUCH_USER);
        UserRegistration.PasswordHasher.clear(commentRight);
    }

    /**
     * Guards the {@code =} to {@code LIKE} "simplification". Under LIKE the
     * wildcards come from the *supplied* name, so an attacker who controls any
     * account can log in under a username that has no account at all: they
     * register {@code alicex1}, then present {@code alice_1}, and
     * {@code username LIKE 'alice_1'} matches their own row. Login then succeeds
     * for a principal that does not exist, and with several candidate rows the
     * engine picks which identity is returned. {@code _} is the case that
     * survives the username allowlist, which is why it is the one tested.
     */
    private static void testWildcardUsernameIsNotAWildcard(UserRegistration.UserRegistry registry) throws Exception {
        char[] attackerSecret = "wildcard secret".toCharArray();
        registry.register("alicex1", attackerSecret);
        UserRegistration.PasswordHasher.clear(attackerSecret);

        char[] knownSecret = "wildcard secret".toCharArray();
        check("a supplied underscore cannot borrow a neighbouring row",
                registry.authenticate("alice_1", knownSecret) == UserRegistration.AuthenticationOutcome.NO_SUCH_USER);

        char[] ownName = "wildcard secret".toCharArray();
        check("a supplied name still resolves to exactly its own row",
                registry.authenticate("alicex1", ownName) == UserRegistration.AuthenticationOutcome.AUTHENTICATED);
        UserRegistration.PasswordHasher.clear(ownName);

        char[] otherSecret = "a different secret".toCharArray();
        check("a supplied underscore does not authenticate either row",
                registry.authenticate("alice_1", otherSecret) == UserRegistration.AuthenticationOutcome.NO_SUCH_USER);
        UserRegistration.PasswordHasher.clear(otherSecret);
        UserRegistration.PasswordHasher.clear(knownSecret);
    }

    /** Guards the {@code UPPER(username) = UPPER(?)} "improvement": folding case would let {@code aLiCe} log in as {@code Alice}. */
    private static void testUsernameIsCaseSensitive(UserRegistration.UserRegistry registry) throws Exception {
        char[] password = "case secret".toCharArray();
        registry.register("Alice", password);
        UserRegistration.PasswordHasher.clear(password);

        String[] otherCasings = {"alice", "ALICE", "aliCe"};
        for (String casing : otherCasings) {
            char[] candidate = "case secret".toCharArray();
            check("[" + casing + "] cannot log in as Alice",
                    registry.authenticate(casing, candidate) == UserRegistration.AuthenticationOutcome.NO_SUCH_USER);
            UserRegistration.PasswordHasher.clear(candidate);
        }

        char[] right = "case secret".toCharArray();
        check("exact casing still works",
                registry.authenticate("Alice", right) == UserRegistration.AuthenticationOutcome.AUTHENTICATED);
        UserRegistration.PasswordHasher.clear(right);
    }

    private static void testValidationRejectsHostileInput(UserRegistration.UserRegistry registry,
                                                          Connection connection) throws Exception {
        String[] badNames = {
                null,
                "",
                "ab",                                     // too short
                repeat('x', 65),                          // too long
                "bad name",                               // space
                "alice' OR '1'='1",                       // quote
                "Robert'); DROP TABLE app_users;--",       // stacked statement
                "ali\u0000ce",                            // embedded NUL
                "alice\n",                                // newline
                "alice; DELETE FROM app_users",           // statement separator
                "alice\u200b",                            // zero-width space
        };
        char[] password = "anything".toCharArray();
        for (String name : badNames) {
            try {
                UserRegistration.RegistrationOutcome outcome = registry.register(name, password);
                check("register(" + describe(name) + ") was unexpectedly accepted as " + outcome, false);
            } catch (IllegalArgumentException refused) {
                check("register(" + describe(name) + ") is refused before touching SQL", true);
            }
        }
        UserRegistration.PasswordHasher.clear(password);

        check("the hostile names did not damage the table", countRows(connection) >= 1);
        check("no hostile name was stored", rowCount(connection, "alice; DELETE FROM app_users") == 0);
    }

    private static void testPasswordValidation(UserRegistration.UserRegistry registry,
                                               Connection connection) throws Exception {
        char[][] badPasswords = {null, new char[0]};
        for (char[] password : badPasswords) {
            try {
                registry.register("pwcase", password);
                check("an empty password was unexpectedly accepted", false);
            } catch (IllegalArgumentException refused) {
                check("empty/null password is refused", true);
            }
        }
        check("no row was written for the rejected passwords", rowCount(connection, "pwcase") == 0);

        char[] tooLong = repeat('k', UserRegistration.PasswordHasher.MAX_PASSWORD_CHARS + 1).toCharArray();
        try {
            registry.register("pwcase", tooLong);
            check("an over-long password was accepted", false);
        } catch (IllegalArgumentException refused) {
            check("over-long password is refused", true);
        }
        UserRegistration.PasswordHasher.clear(tooLong);

        char[] longest = repeat('k', UserRegistration.PasswordHasher.MAX_PASSWORD_CHARS).toCharArray();
        check("the longest accepted password still registers",
                registry.register("pwcase", longest) == UserRegistration.RegistrationOutcome.CREATED);
        UserRegistration.PasswordHasher.clear(longest);
    }

    private static void testDigestFitsColumn(UserRegistration.UserRegistry registry) throws Exception {
        char[] password = repeat('p', 1_000).toCharArray();
        check("a 1000-character password registers",
                registry.register("longpw", password) == UserRegistration.RegistrationOutcome.CREATED);
        UserRegistration.PasswordHasher.clear(password);
        String stored = digestOf(registry.getConnection(), "longpw");
        check("digest length is independent of password length", stored.length() <= 200);
    }

    private static void testCallerPasswordNotModified(UserRegistration.UserRegistry registry) throws Exception {
        char[] password = "must survive the call".toCharArray();
        String before = new String(password);
        registry.register("untouched", password);
        check("register leaves the caller's password array alone", before.equals(new String(password)));

        registry.authenticate("untouched", password);
        check("authenticate leaves the caller's password array alone", before.equals(new String(password)));
        UserRegistration.PasswordHasher.clear(password);
    }

    private static void testExists(UserRegistration.UserRegistry registry) throws Exception {
        char[] password = "exists secret".toCharArray();
        registry.register("exists-case", password);
        UserRegistration.PasswordHasher.clear(password);
        check("exists() sees a registered username", registry.exists("exists-case"));
        check("exists() does not see an absent username", !registry.exists("absent-case"));
    }

    /** How long a single verification against a hostile stored value may take. */
    private static final long VERIFY_BUDGET_MILLIS = 5_000;

    private static void testMalformedStoredDigestsFailClosed(UserRegistration.PasswordHasher hasher) {
        char[] password = "anything at all".toCharArray();
        String salt = "AAAAAAAAAAAAAAAAAAAAAA==";
        String digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        String[] malformed = {
                null,
                "",
                "plaintext-sha1$abcdef",                                   // foreign format
                "pbkdf2-sha256$" + salt + "$" + digest,                    // missing iteration count
                "pbkdf2-sha256$notanumber$" + salt + "$" + digest,         // junk count
                "pbkdf2-sha256$1$" + salt + "$" + digest,                  // stretch below the floor
                "pbkdf2-sha256$999999999$" + salt + "$" + digest,          // stretch above the ceiling (DoS)
                "pbkdf2-sha256$" + Integer.MAX_VALUE + "$" + salt + "$" + digest, // count that overflows on use
                "pbkdf2-sha256$" + TEST_ITERATIONS + "$" + digest + "$" + salt, // salt/digest swapped
                "pbkdf2-sha256$" + TEST_ITERATIONS + "$not-base64!$" + digest,  // junk base64
                "pbkdf2-sha256$" + TEST_ITERATIONS + "$" + salt + "$",           // truncated
                "01234567890123456789",                                    // bare digest
                "pbkdf2-sha256$" + TEST_ITERATIONS + "$AAAA$" + digest,          // 3-byte salt
        };
        for (String stored : malformed) {
            String verdict = refusalWithinBudget(hasher, password, stored, VERIFY_BUDGET_MILLIS);
            check("a malformed stored digest cannot authenticate: " + describe(stored),
                    "refused".equals(verdict));
            if (!"refused".equals(verdict)) {
                System.out.println("      verdict was: " + verdict);
            }
        }
        UserRegistration.PasswordHasher.clear(password);
    }

    /**
     * Runs one verification off-thread so that a stored value which is accepted
     * without a cost bound shows up as a reported failure ("exceeded the
     * N ms budget") rather than a suite that simply never returns. A digest
     * whose derivation outlives a login request is a denial of service however
     * politely it eventually answers.
     *
     * @return "refused", "accepted" or a description of the timeout
     */
    private static String refusalWithinBudget(final UserRegistration.PasswordHasher hasher,
                                              final char[] password, final String stored,
                                              long budgetMillis) {
        final java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
        final boolean[] matched = new boolean[1];
        Thread worker = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    matched[0] = hasher.matches(password, stored);
                } finally {
                    done.countDown();
                }
            }
        }, "digest-probe");
        worker.setDaemon(true);
        worker.start();
        boolean finished;
        try {
            finished = done.await(budgetMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return "interrupted";
        }
        if (!finished) {
            return "still deriving after " + budgetMillis + " ms";
        }
        return matched[0] ? "accepted" : "refused";
    }

    /**
     * Known-answer test. The salt is the ASCII text {@code 0123456789abcdef},
     * the password is {@code caf} plus U+00E9, and the expected digest is what
     * an independent implementation (Python {@code hashlib.pbkdf2_hmac} over
     * UTF-8) produces for those inputs. It pins three things at once: the KDF
     * parameters are honoured, and this JVM's {@code PBEKeySpec} folds
     * {@code char[]} to bytes as UTF-8 rather than UTF-16BE -- a fact that
     * decides whether a digest survives a JVM change or a migration to another
     * stack, and that cannot be observed any other way from inside the code.
     */
    private static void testKnownAnswerVector() {
        UserRegistration.PasswordHasher hasher = new UserRegistration.PasswordHasher(1_000);
        char[] password = new char[]{'c', 'a', 'f', (char) 0xE9};
        String expected = "pbkdf2-sha256$1000$MDEyMzQ1Njc4OWFiY2RlZg=="
                + "$SpPbMsB2Jp2sIgwjl5JBGZLxjqpRBAPmJ99m8fIg+dg=";

        byte[] fixedSalt = decodeBase64("MDEyMzQ1Njc4OWFiY2RlZg==");
        check("the fixed salt is 16 bytes of ASCII",
                fixedSalt.length == 16 && new String(fixedSalt, java.nio.charset.StandardCharsets.US_ASCII)
                        .equals("0123456789abcdef"));

        check("the digest matches an independent implementation",
                expected.equals(hashWithSalt(hasher, password, fixedSalt)));
        check("the known-answer digest verifies", hasher.matches(password, expected));

        char[] lookalikeUtf16 = new char[]{'c', 'a', 'f', (char) 0xE9, (char) 0x00};
        check("a password ending in NUL is refused rather than silently collapsed",
                !hasher.matches(lookalikeUtf16, expected));
        UserRegistration.PasswordHasher.clear(password);
        UserRegistration.PasswordHasher.clear(lookalikeUtf16);
    }

    /**
     * {@code PBEKeySpec} is not injective over the whole {@code char[]} domain:
     * it discards trailing NULs and maps every unpaired surrogate to a single
     * {@code ?}. Left alone, that yields sets of distinct passwords that derive
     * the same digest -- so a user who set one would be logged in by anyone who
     * presented another. This test demonstrates each collision at the raw KDF
     * level (to prove the defect is real and that the guard, not luck, is what
     * closes it) and then asserts that {@code PasswordHasher} refuses to hash or
     * verify any of them.
     */
    private static void testAmbiguousPasswordCharactersAreRefused() throws Exception {
        byte[] salt = "0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        String base = rawDerive(new char[]{'c', 'a', 'f', (char) 0xE9}, salt);
        String trailingNul = rawDerive(new char[]{'c', 'a', 'f', (char) 0xE9, (char) 0}, salt);
        String twoTrailingNuls = rawDerive(new char[]{'c', 'a', 'f', (char) 0xE9, (char) 0, (char) 0}, salt);
        check("the JCE really does collapse a trailing NUL onto the shorter password",
                base.equals(trailingNul) && base.equals(twoTrailingNuls));

        char[] loneHigh = new char[]{'q', (char) 0xD800};
        char[] otherLoneHigh = new char[]{'q', (char) 0xD801};
        char[] loneLow = new char[]{'q', (char) 0xDC00};
        char[] literalQuestion = new char[]{'q', '?'};
        String collapsed = rawDerive(loneHigh, salt);
        check("the JCE really does map every unpaired surrogate onto a literal '?'",
                collapsed.equals(rawDerive(otherLoneHigh, salt))
                        && collapsed.equals(rawDerive(loneLow, salt))
                        && collapsed.equals(rawDerive(literalQuestion, salt)));

        UserRegistration.PasswordHasher hasher = new UserRegistration.PasswordHasher(1_000);
        String knownAnswerDigest = "pbkdf2-sha256$1000$MDEyMzQ1Njc4OWFiY2RlZg=="
                + "$SpPbMsB2Jp2sIgwjl5JBGZLxjqpRBAPmJ99m8fIg+dg=";
        char[][] refused = {
                new char[]{'c', 'a', 'f', (char) 0xE9, (char) 0},
                new char[]{'c', 'a', 'f', (char) 0xE9, (char) 0, (char) 0},
                loneHigh, otherLoneHigh, loneLow,
                new char[]{'q', (char) 0xD800, (char) 0xD801},
                new char[]{(char) 0xDC00},
        };
        for (char[] password : refused) {
            boolean hashRefused;
            try {
                hasher.hash(password);
                hashRefused = false;
            } catch (IllegalArgumentException expected) {
                hashRefused = true;
            }
            check("refuses to hash a password the JCE would collapse (shape " + shape(password) + ")",
                    hashRefused);
            check("refuses to verify such a password (shape " + shape(password) + ")",
                    !hasher.matches(password, knownAnswerDigest));
            check("a refused password cannot authenticate through the registry path either",
                    refusesThroughRegistry(hasher, password));
        }

        // The guard must not reject legitimate Unicode: a properly paired
        // supplementary character is unambiguous and has to keep working.
        char[] astral = new char[]{'p', 'a', 's', 's', (char) 0xD83D, (char) 0xDE00, '!'};
        char[] interiorNul = new char[]{'p', 'a', (char) 0, 's', 's'};
        String astralDigest;
        try {
            astralDigest = hasher.hash(astral);
            check("a correctly paired supplementary character is accepted", true);
        } catch (IllegalArgumentException wronglyRefused) {
            astralDigest = null;
            check("a correctly paired supplementary character is accepted: "
                    + wronglyRefused.getMessage(), false);
        }
        if (astralDigest != null) {
            check("the supplementary character round-trips", hasher.matches(astral, astralDigest));
            char[] wrongPair = new char[]{'p', 'a', 's', 's', (char) 0xD83D, (char) 0xDE01, '!'};
            check("a different supplementary character does not match",
                    !hasher.matches(wrongPair, astralDigest));
            UserRegistration.PasswordHasher.clear(wrongPair);
        }
        try {
            check("an interior NUL is unambiguous and stays valid",
                    hasher.matches(interiorNul, hasher.hash(interiorNul)));
        } catch (IllegalArgumentException wronglyRefused) {
            check("an interior NUL is unambiguous and stays valid: " + wronglyRefused.getMessage(), false);
        }
    }

    /** Registry-level view of the same refusal: no row is written, no login succeeds. */
    private static boolean refusesThroughRegistry(UserRegistration.PasswordHasher hasher, char[] password)
            throws SQLException {
        try (Connection connection =
                     DriverManager.getConnection("jdbc:h2:mem:ambig" + System.nanoTime() + ";DB_CLOSE_DELAY=-1", "sa", "")) {
            UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(connection, hasher);
            registry.ensureSchema();
            try {
                registry.register("ambiguity-case", password);
                return false;
            } catch (IllegalArgumentException expected) {
                return rowCount(connection, "ambiguity-case") == 0;
            }
        }
    }

    /** Derives with the raw JCE, bypassing every guard, to demonstrate the underlying collapse. */
    private static String rawDerive(char[] password, byte[] salt) throws GeneralSecurityException {
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(password, salt, 1_000, 256);
        byte[] digest = javax.crypto.SecretKeyFactory
                .getInstance(UserRegistration.PasswordHasher.JCA_ALGORITHM)
                .generateSecret(spec).getEncoded();
        spec.clearPassword();
        return java.util.Base64.getEncoder().encodeToString(digest);
    }

    /** Character-class label for a check name; never the secret itself. */
    private static String shape(char[] password) {
        StringBuilder out = new StringBuilder();
        for (char c : password) {
            if (out.length() > 0) {
                out.append(' ');
            }
            if (Character.isSurrogate(c)) {
                out.append("sur+").append(Integer.toHexString(c));
            } else if (c >= ' ' && c <= '~') {
                out.append(c);
            } else {
                out.append('U').append(Integer.toHexString(c));
            }
        }
        return out.toString();
    }

    /**
     * Re-derives {@code hash()} with a caller-supplied salt, so a fixed salt can
     * be used against a published vector. Mirrors {@code PasswordHasher.hash}.
     */
    private static String hashWithSalt(UserRegistration.PasswordHasher hasher, char[] password, byte[] salt) {
        try {
            javax.crypto.spec.PBEKeySpec spec =
                    new javax.crypto.spec.PBEKeySpec(password, salt, 1_000, 256);
            byte[] digest = javax.crypto.SecretKeyFactory
                    .getInstance(UserRegistration.PasswordHasher.JCA_ALGORITHM)
                    .generateSecret(spec).getEncoded();
            spec.clearPassword();
            return UserRegistration.PasswordHasher.FORMAT_ID + "$1000$"
                    + java.util.Base64.getEncoder().encodeToString(salt) + "$"
                    + java.util.Base64.getEncoder().encodeToString(digest);
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static byte[] decodeBase64(String value) {
        try {
            return java.util.Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException notBase64) {
            throw new IllegalStateException("test vector is not Base64", notBase64);
        }
    }

    /**
     * A stored digest is a canonical string, not "any Base64-ish text that
     * happens to decode". A lenient decoder (the MIME one, which discards
     * characters outside its alphabet) would accept the same credential written
     * two different ways, so a row and the credential it represents would no
     * longer have a one-to-one spelling: a copy of a digest with a line break
     * pasted into it still logs in, while any string comparison against the
     * original says they differ. The strict decoder must reject it outright.
     */
    private static void testNonCanonicalStoredDigestDoesNotAuthenticate(
            UserRegistration.PasswordHasher hasher) {
        char[] password = "smuggled secret".toCharArray();
        String clean = hasher.hash(password);
        check("the canonical digest verifies", hasher.matches(password, clean));

        String[] parts = clean.split("\\$", -1);
        String smuggledInSalt = parts[0] + "$" + parts[1] + "$"
                + parts[2].substring(0, 8) + "\r\n" + parts[2].substring(8) + "$" + parts[3];
        String smuggledInDigest = parts[0] + "$" + parts[1] + "$" + parts[2] + "$"
                + parts[3].substring(0, 8) + "\r\n" + parts[3].substring(8);
        String paddedWithSpace = clean + " ";

        check("a line break smuggled into the salt field does not authenticate",
                !hasher.matches(password, smuggledInSalt));
        check("a line break smuggled into the digest field does not authenticate",
                !hasher.matches(password, smuggledInDigest));
        check("trailing whitespace does not authenticate",
                !hasher.matches(password, paddedWithSpace));
        check("the canonical spelling still verifies", hasher.matches(password, clean));
        UserRegistration.PasswordHasher.clear(password);
    }

    private static void testHashIsNotIdempotent(UserRegistration.PasswordHasher hasher) {
        char[] password = "one secret".toCharArray();
        String first = hasher.hash(password);
        String second = hasher.hash(password);
        check("hashing the same password twice gives different values", !first.equals(second));
        check("both values verify against the password", hasher.matches(password, first) && hasher.matches(password, second));
        UserRegistration.PasswordHasher.clear(password);
    }

    private static void testClearZeroesArray(UserRegistration.PasswordHasher hasher) {
        char[] password = "wipe me".toCharArray();
        UserRegistration.PasswordHasher.clear(password);
        boolean allZero = true;
        for (char c : password) {
            allZero &= c == '\0';
        }
        check("clear() zeroes the caller's array", allZero);
        UserRegistration.PasswordHasher.clear(null);
        check("clear(null) is harmless", true);
    }

    /**
     * The stored iteration count is what verification must use: an account
     * created under an older, cheaper cost has to keep working after the
     * default is raised.
     */
    private static void testMigrationFromLowerCostKeepsWorking(UserRegistration.PasswordHasher hasher,
                                                              Connection unusedConnection) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:h2:mem:migration;DB_CLOSE_DELAY=-1", "sa", "")) {
            UserRegistration.UserRegistry cheapRegistry =
                    new UserRegistration.UserRegistry(connection, new UserRegistration.PasswordHasher(1_000));
            cheapRegistry.ensureSchema();
            char[] password = "legacy secret".toCharArray();
            cheapRegistry.register("legacy", password);

            String legacyDigest = digestOf(connection, "legacy");
            check("legacy row carries the old iteration count",
                    legacyDigest.startsWith("pbkdf2-sha256$1000$"));

            UserRegistration.UserRegistry expensiveRegistry = new UserRegistration.UserRegistry(
                    connection, new UserRegistration.PasswordHasher(UserRegistration.PasswordHasher.MIN_ITERATIONS * 2));
            char[] right = "legacy secret".toCharArray();
            check("a raised default does not lock out an old account",
                    expensiveRegistry.authenticate("legacy", right)
                            == UserRegistration.AuthenticationOutcome.AUTHENTICATED);
            UserRegistration.PasswordHasher.clear(right);

            char[] wrong = "legacy secret2".toCharArray();
            check("a raised default does not weaken the old account",
                    expensiveRegistry.authenticate("legacy", wrong)
                            == UserRegistration.AuthenticationOutcome.BAD_PASSWORD);
            UserRegistration.PasswordHasher.clear(wrong);
            UserRegistration.PasswordHasher.clear(password);
        }
    }

    /**
     * With manual commits the registry owns the transaction: the row must be
     * visible from another connection only when {@code commitOwnWork} asked it
     * to commit.
     */
    private static void testManualCommitOwnsTransaction(String base, UserRegistration.PasswordHasher hasher,
                                                        boolean commitOwnWork) throws Exception {
        String url = "jdbc:h2:mem:tx" + (commitOwnWork ? "commit" : "manual") + ";DB_CLOSE_DELAY=-1";
        try (Connection owner = DriverManager.getConnection(url, "sa", "")) {
            owner.setAutoCommit(false);
            UserRegistration.UserRegistry registry =
                    new UserRegistration.UserRegistry(owner, hasher, commitOwnWork);
            registry.ensureSchema();

            char[] password = "tx secret".toCharArray();
            check("register works under manual commit (commitOwnWork=" + commitOwnWork + ")",
                    registry.register("txcase", password) == UserRegistration.RegistrationOutcome.CREATED);
            UserRegistration.PasswordHasher.clear(password);

            boolean visibleElsewhere;
            try (Connection observer = DriverManager.getConnection(url, "sa", "")) {
                observer.setAutoCommit(true);
                visibleElsewhere = countRows(observer) > 0;
            }
            check("visibility from a second connection matches commitOwnWork=" + commitOwnWork,
                    visibleElsewhere == commitOwnWork);

            if (!commitOwnWork) {
                owner.rollback();
                try (Connection observer = DriverManager.getConnection(url, "sa", "")) {
                    check("an uncommitted row can still be rolled back by the owner", countRows(observer) == 0);
                }
            }
        }
    }

    /**
     * The unknown-user path must cost a full key derivation, otherwise response
     * time tells an attacker which usernames exist. Measured as a ratio over
     * repeated runs so scheduler noise cannot decide the outcome.
     */
    private static void testUnknownUserTimingIsNotCheap(String base, UserRegistration.PasswordHasher unused)
            throws Exception {
        UserRegistration.PasswordHasher slow = new UserRegistration.PasswordHasher(TIMING_ITERATIONS);
        try (Connection connection = DriverManager.getConnection("jdbc:h2:mem:timing;DB_CLOSE_DELAY=-1", "sa", "")) {
            UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(connection, slow);
            registry.ensureSchema();
            char[] enrolled = "a genuinely long secret".toCharArray();
            registry.register("timing-user", enrolled);
            UserRegistration.PasswordHasher.clear(enrolled);

            char[] wrongPassword = "a genuinely long secrey".toCharArray();
            char[] absentPassword = "a genuinely long secrez".toCharArray();

            // Warm both paths (JIT, H2 page cache) before measuring.
            for (int i = 0; i < 2; i++) {
                registry.authenticate("timing-user", wrongPassword);
                registry.authenticate("absent-user", absentPassword);
            }

            long wrongBest = Long.MAX_VALUE;
            long absentBest = Long.MAX_VALUE;
            for (int i = 0; i < 5; i++) {
                long start = System.nanoTime();
                registry.authenticate("timing-user", wrongPassword);
                wrongBest = Math.min(wrongBest, System.nanoTime() - start);

                start = System.nanoTime();
                registry.authenticate("absent-user", absentPassword);
                absentBest = Math.min(absentBest, System.nanoTime() - start);
            }
            UserRegistration.PasswordHasher.clear(wrongPassword);
            UserRegistration.PasswordHasher.clear(absentPassword);

            double ratio = (double) absentBest / (double) wrongBest;
            System.out.printf("      timing: wrong-password=%.0f ms, unknown-user=%.0f ms, ratio=%.2f%n",
                    wrongBest / 1e6, absentBest / 1e6, ratio);
            check("a wrong password costs a full key derivation",
                    wrongBest / 1_000_000 >= TIMING_ITERATIONS / 20_000);
            check("an unknown username is not answered cheaply (ratio >= 0.5)", ratio >= 0.5);

            // A candidate the KDF cannot use at all (unpaired surrogate) is
            // refused without being derived. If that refusal were free, it would
            // re-open the very oracle the guard digest closes: present such a
            // candidate and a fast answer means the row exists.
            char[] ambiguous = new char[]{'q', (char) 0xD800};
            long ambiguousBest = Long.MAX_VALUE;
            boolean ambiguousAlwaysRefused = true;
            for (int i = 0; i < 5; i++) {
                long start = System.nanoTime();
                UserRegistration.AuthenticationOutcome outcome =
                        registry.authenticate("timing-user", ambiguous);
                ambiguousBest = Math.min(ambiguousBest, System.nanoTime() - start);
                ambiguousAlwaysRefused &= outcome == UserRegistration.AuthenticationOutcome.BAD_PASSWORD;
            }
            check("an ambiguous candidate against an existing user is refused", ambiguousAlwaysRefused);
            double ambiguousRatio = (double) ambiguousBest / (double) wrongBest;
            System.out.printf("      timing: refused-candidate=%.0f ms, ratio=%.2f%n",
                    ambiguousBest / 1e6, ambiguousRatio);
            check("a refused candidate is not answered cheaply either (ratio >= 0.5)",
                    ambiguousRatio >= 0.5);

            long blankBest = Long.MAX_VALUE;
            for (int i = 0; i < 3; i++) {
                long start = System.nanoTime();
                registry.authenticate("timing-user", new char[0]);
                blankBest = Math.min(blankBest, System.nanoTime() - start);
            }
            check("a blank candidate is not answered cheaply either (ratio >= 0.5)",
                    (double) blankBest / (double) wrongBest >= 0.5);
            UserRegistration.PasswordHasher.clear(ambiguous);
        }
    }

    // ----------------------------------------------------------------- plumbing

    private static UserRegistration.UserRegistry freshRegistry(Connection connection,
                                                               UserRegistration.PasswordHasher hasher)
            throws SQLException {
        UserRegistration.UserRegistry registry = new UserRegistration.UserRegistry(connection, hasher);
        registry.ensureSchema();
        try (Statement clear = connection.createStatement()) {
            clear.executeUpdate("DELETE FROM app_users");
        }
        return registry;
    }

    private static String digestOf(Connection connection, String username) throws SQLException {
        return textOf(connection, "SELECT password_hash FROM app_users WHERE username = ?", username);
    }

    private static String textOf(Connection connection, String sql, String username) throws SQLException {
        try (PreparedStatement select = connection.prepareStatement(sql)) {
            select.setString(1, username);
            try (ResultSet rows = select.executeQuery()) {
                if (!rows.next()) {
                    throw new IllegalStateException("no row for " + username);
                }
                return rows.getString(1);
            }
        }
    }

    private static int rowCount(Connection connection, String username) throws SQLException {
        try (PreparedStatement count =
                     connection.prepareStatement("SELECT COUNT(*) FROM app_users WHERE username = ?")) {
            count.setString(1, username);
            try (ResultSet rows = count.executeQuery()) {
                return rows.next() ? rows.getInt(1) : 0;
            }
        }
    }

    private static int countRows(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("SELECT COUNT(*) FROM app_users")) {
            return rows.next() ? rows.getInt(1) : 0;
        }
    }

    private static String repeat(char c, int times) {
        char[] buffer = new char[times];
        java.util.Arrays.fill(buffer, c);
        return new String(buffer);
    }

    /** Summary of a value, safe to print and unambiguous enough to name a check. */
    private static String describe(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length() && i < 24; i++) {
            char c = value.charAt(i);
            if (c >= ' ' && c <= '~') {
                out.append(c);
            } else {
                out.append("(c").append((int) c).append(")");
            }
        }
        return "'" + out + "'(len " + value.length() + ")";
    }

    private static void check(String what, boolean condition) {
        checks++;
        if (!condition) {
            failures.add(what);
            System.out.println("FAIL  " + what);
        } else {
            System.out.println("ok    " + what);
        }
    }

    private static void report() {
        System.out.println("");
        if (failures.isEmpty()) {
            System.out.println(checks + " checks passed.");
            return;
        }
        System.out.println(failures.size() + " of " + checks + " checks FAILED:");
        for (String failure : failures) {
            System.out.println("  - " + failure);
        }
        System.exit(1);
    }
}
