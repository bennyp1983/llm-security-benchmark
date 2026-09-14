import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Verification suite 1: JDBC stand-ins.
 *
 * <p>Every assertion here is about what the service hands to the driver: the exact statement text,
 * which setters were used, and whether the objects were closed. A real database cannot see that a
 * predicate was widened from {@code =} to {@code LIKE} when the scripted answer is the same, so
 * this suite and the H2 suite (AuthH2Test) cover different failure modes.
 *
 * <p>Run: {@code java -cp build AuthDoublesTest}
 */
public final class AuthDoublesTest {

    private static final List<String> failures = new ArrayList<>();
    private static int checks;

    // Recorders filled by the proxies.
    private static final List<String> preparedSql = new ArrayList<>();
    private static final List<Object[]> boundValues = new ArrayList<>();
    private static final List<String> methods = new ArrayList<>();
    private static final List<Integer> timeouts = new ArrayList<>();
    private static boolean connectionClosed;
    private static boolean statementClosed;
    private static boolean resultClosed;

    private static final String ALICE = "alice@example.com";
    private static final String PW = "Fresh-Admin-21";

    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            args_sourcePath = args[0];
        }
        String stored = AuthenticationService.Passwords.hash(PW.toCharArray());

        happyPath(stored);
        statementIsInvariant(stored);
        payloadStaysOutOfStatementText();
        onlyParameterisedStatementsAreUsed(stored);
        closesResourcesOnSuccess(stored);
        closesResourcesWhenQueryFails();
        nullHashIsRefused(stored);
        unparsableHashIsRefusedAndCostsOneDigest();
        secretIsWipedOnEveryPath(stored);
        denialTextIsIdenticalForKnownAndUnknown(stored);
        emptyPasswordRefusedBeforeQuery();
        oversizedPasswordRefusedBeforeQuery();
        unusablePasswordCharactersRefused(stored);
        malformedAddressesRefusedBeforeQuery();
        nonAsciiAddressesRefusedBeforeQuery();
        nothingAboutTheCredentialIsPrinted(stored);
        digestComparisonIsConstantTime();
        registerAlsoBindsItsValues();

        System.out.println("SUITE=doubles checks=" + checks + " failed=" + failures.size());
        for (String f : failures) {
            System.out.println("FAILED: " + f);
        }
        if (!failures.isEmpty()) {
            System.exit(1);
        }
    }

    // -------------------------------------------------------------------------------------
    // Checks
    // -------------------------------------------------------------------------------------

    private static void happyPath(String stored) {
        reset();
        AuthenticationService service = service(row(stored), null);
        AuthenticationService.AuthResult ok = service.authenticate("  " + ALICE + "  ", PW.toCharArray());
        check("bound email is normalised, not raw input", boundValues.size() == 1
                && ALICE.equals(boundValues.get(0)[1]));
        check("success reported for the stored credential", ok.isAuthenticated());
        check("success message is the success sentence",
                "Authentication successful.".equals(ok.message()));
        check("one statement per login", preparedSql.size() == 1);
        check("timeout was set on the query", !timeouts.isEmpty() && timeouts.get(0) > 0);
    }

    private static void statementIsInvariant(String stored) {
        reset();
        AuthenticationService service = service(row(stored), null);
        service.authenticate(ALICE, PW.toCharArray());
        service.authenticate("someone.else@example.org", "whatever-1".toCharArray());
        check("every login prepares exactly the constant statement",
                preparedSql.size() == 2
                        && AuthenticationService.SELECT_BY_EMAIL.equals(preparedSql.get(0))
                        && AuthenticationService.SELECT_BY_EMAIL.equals(preparedSql.get(1)));
        String sql = preparedSql.get(0);
        check("statement selects by a single placeholder",
                sql.contains("WHERE email = ?") && countChar(sql, '?') == 1);
        check("statement carries no boolean shortcut, comment or separator",
                !sql.contains("OR") && !sql.contains("--") && !sql.contains(";")
                        && !sql.contains("#"));
        check("statement is not a LIKE or folded comparison",
                !sql.contains("LIKE") && !sql.contains("UPPER") && !sql.contains("LOWER"));
        check("login never sends the password to the database",
                sql.toLowerCase(java.util.Locale.ROOT).indexOf("password_hash")
                        == sql.toLowerCase(java.util.Locale.ROOT).lastIndexOf("password_hash")
                        && !sql.contains(PW));
    }

    private static void payloadStaysOutOfStatementText() {
        String[] payloads = {
                "x' OR '1'='1",
                "x'--",
                "x'; DROP TABLE users;--",
                "x' UNION SELECT password_hash FROM users WHERE '1'='1",
                "alice@example.com' OR 1=1 --",
                "'/**/OR/**/1=1",
                "admin'/*",
                // These satisfy the address grammar, so they really do reach the driver.
                "a--@example.com",
                "%25@example.com",
                "_wildcard%@example.com",
                "union.select--@example.com",
                "%@example.com",
        };
        int reachedDatabase = 0;
        for (String payload : payloads) {
            reset();
            AuthenticationService.AuthResult result =
                    service(row("nope"), null).authenticate(payload, "guessing-1".toCharArray());
            check("payload does not authenticate: " + describe(payload), !result.isAuthenticated());
            check("no write statement for a payload login: " + describe(payload),
                    !methods.contains("executeUpdate") && !methods.contains("execute"));
            if (preparedSql.isEmpty()) {
                check("payload refused before any statement was prepared: " + describe(payload),
                        result.outcome() == AuthenticationService.Outcome.INVALID_INPUT);
                continue;
            }
            reachedDatabase++;
            check("payload reached the database only as a bound value: " + describe(payload),
                    AuthenticationService.SELECT_BY_EMAIL.equals(preparedSql.get(0))
                            && boundValues.size() == 1
                            && payload.equals(boundValues.get(0)[1]));
            check("statement text still has no trace of the payload: " + describe(payload),
                    !preparedSql.get(0).contains(payload)
                            && !preparedSql.get(0).contains("--")
                            && !preparedSql.get(0).contains("'"));
        }
        check("at least some injection-shaped payloads reached the driver (guard is not vacuous)",
                reachedDatabase >= 5);
        System.out.println("NOTE payloads_reaching_driver=" + reachedDatabase + "/" + payloads.length);
    }

    private static void onlyParameterisedStatementsAreUsed(String stored) {
        reset();
        AuthenticationService service = service(row(stored), null);
        service.authenticate(ALICE, "wrong-password".toCharArray());
        check("createStatement is never used", !methods.contains("createStatement"));
        check("prepareCall is never used", !methods.contains("prepareCall"));
        check("addBatch is never used", !methods.contains("addBatch"));
        check("only setString is used for binding", onlyStringSetters());
        check("the credential column is read by index, never by concatenation",
                methods.contains("ResultSet.getString"));
    }

    private static void closesResourcesOnSuccess(String stored) {
        reset();
        service(row(stored), null).authenticate(ALICE, PW.toCharArray());
        check("result set closed", resultClosed);
        check("statement closed", statementClosed);
        check("connection closed", connectionClosed);
    }

    private static void closesResourcesWhenQueryFails() {
        reset();
        AuthenticationService.AuthResult result =
                service(null, new SQLException("simulated outage")).authenticate(ALICE, PW.toCharArray());
        check("outage is refused", !result.isAuthenticated());
        check("outage says the service is unreachable, not that credentials are wrong",
                result.outcome() == AuthenticationService.Outcome.UNAVAILABLE);
        check("connection closed after a failed query", connectionClosed);
        check("statement closed after a failed query", statementClosed);
        check("outage message never mentions the account",
                !result.message().toLowerCase(java.util.Locale.ROOT).contains("alice"));
    }

    private static void nullHashIsRefused(String stored) {
        reset();
        AuthenticationService.AuthResult result =
                service(row(null), null).authenticate(ALICE, PW.toCharArray());
        check("a row with no stored digest cannot log in", !result.isAuthenticated());
        check("a row with no stored digest is refused, not an outage",
                result.outcome() == AuthenticationService.Outcome.DENIED);
        check("a row with no stored digest still costs one digest",
                elapsedMs(() -> service(row(null), null).authenticate(ALICE, PW.toCharArray())) >= 30);
    }

    private static void unparsableHashIsRefusedAndCostsOneDigest() throws Exception {
        // A digest recorded with far too few rounds: the bytes are genuinely valid for the
        // password, so only the round-count guard stands between it and a working login.
        String lazilyRecorded = AuthenticationService.Passwords.hash(PW.toCharArray())
                .replaceFirst("\\$100000\\$", "\\$500\\$");
        long lazyMs = elapsedMs(() -> service(row(lazilyRecorded), null)
                .authenticate(ALICE, PW.toCharArray()));
        AuthenticationService.AuthResult lazy = service(row(lazilyRecorded), null)
                .authenticate(ALICE, PW.toCharArray());
        check("a digest recorded with too few rounds cannot be used to log in",
                !lazy.isAuthenticated());
        check("a digest recorded with too few rounds costs the standard digest rather than its "
                + "own cheap one (" + lazyMs + " ms)", lazyMs >= 30);

        String[] broken = {
                "plaintext-password",
                "pbkdf2-sha256$100000$!!!!not-base64$also-not-base64",
                "pbkdf2-sha256$10$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "pbkdf2-sha256$100000$AAAAAAAAAAAAAAAAAAAAAA==",
                // Correct shape and round count, but the digest is 3 bytes instead of 32.
                "pbkdf2-sha256$100000$AAAAAAAAAAAAAAAAAAAAAA==$Zm9v",
                "pbkdf2-sha256$100000$AAAAAAAAAAAAAAAAAAAAAA==$"
                        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "PBKDF2-SHA256$100000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        };
        for (String record : broken) {
            long ms = elapsedMs(() -> service(row(record), null)
                    .authenticate(ALICE, "Fresh-Admin-21".toCharArray()));
            AuthenticationService.AuthResult result =
                    service(row(record), null).authenticate(ALICE, "Fresh-Admin-21".toCharArray());
            check("unparsable stored record is refused: " + describe(record),
                    !result.isAuthenticated()
                            && result.outcome() == AuthenticationService.Outcome.DENIED);
            check("unparsable stored record still costs a full digest: " + describe(record), ms >= 30);
        }
    }

    private static void secretIsWipedOnEveryPath(String stored) {
        Object[][] cases = {
                {ALICE, PW.toCharArray(), service(row(stored), null)},
                {ALICE, "nope-not-it".toCharArray(), service(row(stored), null)},
                {"not-an-email", "nope-not-it".toCharArray(), service(row(stored), null)},
                {"a".repeat(300) + "@example.com", "nope-not-it".toCharArray(), service(row(stored), null)},
                {ALICE, new char[0], service(row(stored), null)},
                {ALICE, ("tab" + (char) 0x09 + "inside").toCharArray(), service(row(stored), null)},
                {ALICE, "p".repeat(AuthenticationService.PASSWORD_MAX + 7).toCharArray(),
                        service(row(stored), null)},
                {ALICE, ("surrogate" + (char) 0xD83D).toCharArray(), service(row(stored), null)},
                {"unknown@example.net", PW.toCharArray(), service(noRow(), null)},
                // The two refusal paths that happen after the database answer arrives.
                {ALICE, PW.toCharArray(), service(noRow(), new SQLException("simulated outage"))},
                {ALICE, PW.toCharArray(), service(row("garbage-record"), null)},
        };
        for (Object[] c : cases) {
            char[] secret = (char[]) c[1];
            ((AuthenticationService) c[2]).authenticate((String) c[0], secret);
            boolean zeroed = true;
            for (char ch : secret) {
                if (ch != 0) {
                    zeroed = false;
                }
            }
            check("password characters are erased after the attempt (" + describe((String) c[0]) + ")",
                    zeroed);
        }
    }

    /**
     * Characters the key-derivation step cannot represent faithfully. NUL matters most: the
     * derivation stops at a NUL, so without this rule {@code "password"} and
     * {@code "password" + NUL} would be the same secret, giving anyone who can append an invisible
     * character a second way into the real account.
     */
    private static void unusablePasswordCharactersRefused(String stored) {
        String[] unusable = {
                PW + (char) 0x00,
                PW + (char) 0x09,
                PW + (char) 0x0D,
                PW + (char) 0x1F,
                (char) 0x1B + PW,
                PW + (char) 0x7F,
        };
        for (String password : unusable) {
            reset();
            AuthenticationService.AuthResult result =
                    service(row(stored), null).authenticate(ALICE, password.toCharArray());
            check("a password with an invisible character cannot log in as alice: "
                            + describe(password),
                    !result.isAuthenticated()
                            && result.outcome() == AuthenticationService.Outcome.INVALID_INPUT);
            check("a password with an invisible character never reaches the database: "
                            + describe(password),
                    preparedSql.isEmpty());
        }

        // An unpaired half of a surrogate pair is replaced by '?' by the key specification, so two
        // different secrets would collapse onto one digest.
        reset();
        AuthenticationService.AuthResult unpaired = service(row(stored), null)
                .authenticate(ALICE, (PW + (char) 0xD83D).toCharArray());
        check("a password ending in an unpaired high surrogate is refused",
                unpaired.outcome() == AuthenticationService.Outcome.INVALID_INPUT
                        && preparedSql.isEmpty());
        reset();
        check("a password starting with an unpaired low surrogate is refused",
                service(row(stored), null)
                        .authenticate(ALICE, ((char) 0xDE80 + PW).toCharArray())
                        .outcome() == AuthenticationService.Outcome.INVALID_INPUT);

        // A whole pair is a legitimate character and must not be refused, or the rule above would
        // just be "no emoji in passwords".
        reset();
        char[] paired = (PW + new String(new int[] {0xD83D, 0xDE80}, 0, 2)).toCharArray();
        AuthenticationService.AuthResult withPair =
                service(row(stored), null).authenticate(ALICE, paired);
        check("a password containing a whole surrogate pair is digested, not refused",
                withPair.outcome() == AuthenticationService.Outcome.DENIED
                        && !preparedSql.isEmpty());

        // A space and a non-breaking space are ordinary password characters. Refusing them would
        // turn this rule into "no unusual passwords at all".
        reset();
        char[] withSpaces = (PW + "  " + (char) 0xA0).toCharArray();
        AuthenticationService.AuthResult spaces =
                service(row(stored), null).authenticate(ALICE, withSpaces);
        check("a password with ordinary and non-breaking trailing spaces is digested, not refused",
                spaces.outcome() == AuthenticationService.Outcome.DENIED
                        && !preparedSql.isEmpty());
    }

    /**
     * The size limit, tested with printable characters. A plain {@code new char[1025]} is a
     * thousand NULs, which a *different* rule refuses, so it proves nothing about this one.
     */
    private static void oversizedPasswordRefusedBeforeQuery() {
        reset();
        char[] tooLong = "p".repeat(AuthenticationService.PASSWORD_MAX + 1).toCharArray();
        AuthenticationService.AuthResult result =
                service(row("nope"), null).authenticate(ALICE, tooLong);
        check("an over-long printable password is refused as bad input",
                result.outcome() == AuthenticationService.Outcome.INVALID_INPUT);
        check("an over-long printable password never reaches the database", preparedSql.isEmpty());
        boolean zeroed = true;
        for (char ch : tooLong) {
            if (ch != 0) {
                zeroed = false;
            }
        }
        check("an over-long printable password is still erased", zeroed);

        reset();
        char[] atLimit = "p".repeat(AuthenticationService.PASSWORD_MAX).toCharArray();
        AuthenticationService.AuthResult accepted =
                service(row("nope"), null).authenticate(ALICE, atLimit);
        check("a password one character shorter is accepted for verification",
                accepted.outcome() == AuthenticationService.Outcome.DENIED
                        && !preparedSql.isEmpty());
    }

    /**
     * Addresses with more than one {@code @}, and with invisible characters in each position an
     * address has. Both are refused before anything is sent.
     */
    private static void malformedAddressesRefusedBeforeQuery() {
        String[] malformed = {
                "a@@example.com",
                "two@@two@example.com",
                "@example.com",
                "alice@",
                "alice@example",
                ".alice@example.com",
                "alice.@example.com",
                "al..ice@example.com",
                "alice@.example.com",
                "alice@example..com",
                "a".repeat(AuthenticationService.EMAIL_LOCAL_MAX + 1) + "@example.com",
                "a".repeat(300) + "@example.com",
                "al ice@example.com",
                "alice@exam ple.com",
                "ali" + (char) 0x00 + "ce@example.com",
                "alice@exa" + (char) 0x09 + "mple.com",
                "alice@example.com" + (char) 0x0D,
                "alice@example.co" + (char) 0x1F + "m",
                "alice@exam" + (char) 0x7F + "ple.com",
        };
        for (String address : malformed) {
            reset();
            AuthenticationService.AuthResult result = service(row("nope"), null)
                    .authenticate(address, "guessing-1".toCharArray());
            check("malformed address refused before any query: " + describe(address),
                    result.outcome() == AuthenticationService.Outcome.INVALID_INPUT
                            && preparedSql.isEmpty());
        }
    }

    private static void denialTextIsIdenticalForKnownAndUnknown(String stored) {
        reset();
        AuthenticationService.AuthResult known =
                service(row(stored), null).authenticate(ALICE, "totally-wrong".toCharArray());
        AuthenticationService.AuthResult unknown =
                service(noRow(), null).authenticate("carol@example.com", "totally-wrong".toCharArray());
        check("wrong password for a known account is refused", !known.isAuthenticated());
        check("unknown account is refused", !unknown.isAuthenticated());
        check("both refusals are the same bytes", known.message().equals(unknown.message()));
        check("the shared refusal states it is a credential problem",
                known.message().contains("invalid email address or password"));
        check("the shared refusal does not name the account",
                !known.message().contains("alice") && !known.message().contains("carol"));
        String[] revealsExistence = {"not found", "no such", "unknown", "does not exist",
                "no account", "not recognised", "exists", "found"};
        String lower = known.message().toLowerCase(java.util.Locale.ROOT);
        for (String needle : revealsExistence) {
            check("the refusal does not hint at account existence (\"" + needle + "\")",
                    !lower.contains(needle));
        }
    }

    /**
     * Guards that run before the database must refuse without doing the expensive work, which is
     * how they stay distinguishable from a credential denial.
     */
    private static void emptyPasswordRefusedBeforeQuery() {
        reset();
        AuthenticationService.AuthResult empty = service(row("nope"), null)
                .authenticate(ALICE, new char[0]);
        check("an empty password is refused as bad input",
                empty.outcome() == AuthenticationService.Outcome.INVALID_INPUT);
        check("an empty password never reaches the database", preparedSql.isEmpty());
    }

    private static void nonAsciiAddressesRefusedBeforeQuery() {
        // Built from code points: this machine's javac defaults to US-ASCII, so non-ASCII literals
        // in a source file would not compile. U+00A0 also survives trim(), which is the point.
        String nonBreakingSpace = "ali" + (char) 0xA0 + "ce@example.com";
        String kanjiUser = new String(new int[] {0x7528, 0x6237}, 0, 2) + "@example.com";
        String[] invisible = {
                ALICE + (char) 0x00,
                ALICE + (char) 0x09,
                ALICE + (char) 0x0D,
                ALICE + (char) 0x1F,
                (char) 0x1B + ALICE,
                "a" + (char) 0x7F + "@example.com",
                nonBreakingSpace,
                kanjiUser,
        };
        for (String address : invisible) {
            reset();
            AuthenticationService.AuthResult result = service(row("nope"), null)
                    .authenticate(address, "guessing-1".toCharArray());
            check("invisible or non-ASCII address refused before any query: " + describe(address),
                    result.outcome() == AuthenticationService.Outcome.INVALID_INPUT
                            && preparedSql.isEmpty());
        }
    }

    /**
     * The digest comparison has to be the constant-time one. Nothing observable at runtime can show
     * the difference (a 32-byte compare is lost in the noise of a 100 000-round key derivation in
     * front of it), so the source itself is checked. Comments are stripped first, with a literal-aware
     * scanner, so this file's own prose about the comparison cannot satisfy it by accident.
     */
    private static void digestComparisonIsConstantTime() throws IOException {
        java.nio.file.Path source =
                java.nio.file.Paths.get(args_sourcePath == null ? "AuthenticationService.java"
                        : args_sourcePath);
        if (!java.nio.file.Files.isRegularFile(source)) {
            check("the source under test can be read: " + source, false);
            return;
        }
        String raw = new String(java.nio.file.Files.readAllBytes(source), StandardCharsets.UTF_8);
        String code = stripComments(raw);
        check("the comment stripper found code to work on", code.contains("PreparedStatement"));
        check("the comment stripper actually removed something", code.length() < raw.length());
        check("the stored digest is compared with MessageDigest.isEqual",
                code.contains("MessageDigest.isEqual(expected, actual)"));
        check("no plain array equality is used for the digest comparison",
                !code.contains("Arrays.equals"));
    }

    /** Removes // and block comments, without mistaking a delimiter inside a literal for one. */
    static String stripComments(String text) {
        StringBuilder out = new StringBuilder(text.length());
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (c == '"' || c == '\'') {
                char quote = c;
                out.append(c);
                i++;
                while (i < text.length()) {
                    char inside = text.charAt(i);
                    out.append(inside);
                    if (inside == '\\' && i + 1 < text.length()) {
                        out.append(text.charAt(i + 1));
                        i += 2;
                        continue;
                    }
                    i++;
                    if (inside == quote) {
                        break;
                    }
                }
                continue;
            }
            if (c == '/' && i + 1 < text.length() && text.charAt(i + 1) == '/') {
                while (i < text.length() && text.charAt(i) != '\n') {
                    i++;
                }
                continue;
            }
            if (c == '/' && i + 1 < text.length() && text.charAt(i + 1) == '*') {
                i += 2;
                while (i + 1 < text.length() && !(text.charAt(i) == '*' && text.charAt(i + 1) == '/')) {
                    if (text.charAt(i) == '\n') {
                        out.append('\n');
                    }
                    i++;
                }
                i = Math.min(i + 2, text.length());
                continue;
            }
            out.append(c);
            i++;
        }
        return out.toString();
    }

    static String args_sourcePath;

    private static void registerAlsoBindsItsValues() throws Exception {
        reset();
        AuthenticationService service = service(noRow(), null);
        char[] secret = PW.toCharArray();
        service.register("Doreen.Visor@example.com", secret);
        check("register prepares the constant insert",
                AuthenticationService.INSERT_USER.equals(preparedSql.get(0)));
        check("register binds two values, neither built into the SQL",
                boundValues.size() == 2 && !preparedSql.get(0).contains("Doreen"));
        check("register stores a digest, never the password",
                boundValues.get(0)[1].equals("doreen.visor@example.com")
                        && String.valueOf(boundValues.get(1)[1]).startsWith("pbkdf2-sha256$")
                        && !String.valueOf(boundValues.get(1)[1]).contains(PW));
        boolean zeroed = true;
        for (char ch : secret) {
            if (ch != 0) {
                zeroed = false;
            }
        }
        check("register wipes the password it was given", zeroed);
    }

    // -------------------------------------------------------------------------------------
    // Harness
    // -------------------------------------------------------------------------------------

    private static interface Body {
        void run();
    }

    /** Runs a body with System.out and System.err captured. */
    private static String captureOutput(Body body) {
        java.io.PrintStream originalOut = System.out;
        java.io.PrintStream originalErr = System.err;
        java.io.ByteArrayOutputStream sink = new java.io.ByteArrayOutputStream();
        java.io.PrintStream capture =
                new java.io.PrintStream(sink, true, StandardCharsets.UTF_8);
        try {
            System.setOut(capture);
            System.setErr(capture);
            body.run();
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
        return new String(sink.toByteArray(), StandardCharsets.UTF_8);
    }

    /**
     * A refusal must not become a way to read the credential store. Both the stored digest and the
     * text of the query (with the address visible) are caught here if anything writes them out.
     *
     * <p>Non-vacuity: each case also asserts the outcome it captured, so an empty capture means
     * "nothing was printed", not "the code path never ran"; the outage case asserts its capture is
     * non-empty, which proves this helper really does see System.err.
     */
    private static void nothingAboutTheCredentialIsPrinted(String stored) {
        reset();
        AuthenticationService.AuthResult[] held = new AuthenticationService.AuthResult[1];
        String denialOutput = captureOutput(() -> held[0] = service(row(stored), null)
                .authenticate(ALICE, "totally-wrong-pw".toCharArray()));
        check("the captured run really was a refused login",
                held[0] != null && held[0].outcome() == AuthenticationService.Outcome.DENIED);
        check("a refused login prints the stored digest to no stream",
                !denialOutput.contains(stored) && !denialOutput.contains("pbkdf2-sha256"));
        check("a refused login prints the query text to no stream",
                !denialOutput.contains("SELECT password_hash FROM users"));
        check("a refused login prints the password to no stream",
                !denialOutput.contains("totally-wrong-pw"));

        reset();
        AuthenticationService.AuthResult[] won = new AuthenticationService.AuthResult[1];
        String successOutput = captureOutput(() -> won[0] = service(row(stored), null)
                .authenticate(ALICE, PW.toCharArray()));
        check("the captured run really was a successful login",
                won[0] != null && won[0].isAuthenticated());
        check("a successful login prints the stored digest to no stream",
                !successOutput.contains(stored) && !successOutput.contains("pbkdf2-sha256"));
        check("a successful login prints the password to no stream", !successOutput.contains(PW));
        check("a successful login prints no query text", !successOutput.contains("SELECT"));

        reset();
        String outageOutput = captureOutput(() -> service(noRow(), new SQLException("simulated"))
                .authenticate(ALICE, PW.toCharArray()));
        check("the capture helper really does see what the service writes",
                outageOutput.contains("refusing login"));
        check("an outage prints no stack trace", !outageOutput.contains("\tat "));
        check("an outage prints the stored digest to no stream",
                !outageOutput.contains("pbkdf2-sha256"));
        check("an outage names only the exception class, not the driver's text",
                outageOutput.contains("SQLException") && !outageOutput.contains("simulated"));
    }

    private static long elapsedMs(Body body) {
        long start = System.nanoTime();
        body.run();
        return (System.nanoTime() - start) / 1_000_000L;
    }

    private static void check(String what, boolean condition) {
        checks++;
        if (!condition) {
            failures.add(what);
        }
    }

    private static void reset() {
        preparedSql.clear();
        boundValues.clear();
        methods.clear();
        timeouts.clear();
        connectionClosed = false;
        statementClosed = false;
        resultClosed = false;
    }

    private static int countChar(String value, char needle) {
        int n = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == needle) {
                n++;
            }
        }
        return n;
    }

    private static boolean onlyStringSetters() {
        for (String m : methods) {
            if (m.startsWith("set") && !m.equals("setString") && !m.equals("setQueryTimeout")
                    && !m.equals("setFetchSize") && !m.equals("setMaxRows")) {
                return false;
            }
        }
        return true;
    }

    private static String describe(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < value.length() && b.length() < 30; i++) {
            char c = value.charAt(i);
            b.append(c < 0x20 || c == 0x7F ? "<" + (int) c + ">" : c);
        }
        if (value.length() > 30) {
            b.append("...");
        }
        return b.length() == 0 ? "empty" : b.toString();
    }

    // -------------------------------------------------------------------------------------
    // Stand-ins
    // -------------------------------------------------------------------------------------

    /** One scripted row; {@code hash} may be null to mimic a NULL column. */
    private static final class Row {
        final boolean present;
        final String hash;

        Row(boolean present, String hash) {
            this.present = present;
            this.hash = hash;
        }
    }

    /** A row exists and holds {@code hash} (which may itself be a broken or NULL value). */
    private static Row row(String hash) {
        return new Row(true, hash);
    }

    /** The lookup matched no row at all. */
    private static Row noRow() {
        return new Row(false, null);
    }

    private static AuthenticationService service(Row rowOrNull, SQLException failure) {
        return new AuthenticationService(() -> connection(rowOrNull, failure));
    }

    private static Connection connection(Row rowOrNull, SQLException failure) {
        return (Connection) Proxy.newProxyInstance(AuthDoublesTest.class.getClassLoader(),
                new Class<?>[] {Connection.class}, new ConnectionHandler(rowOrNull, failure));
    }

    private static final class ConnectionHandler implements InvocationHandler {
        private final Row rowOrNull;
        private final SQLException failure;

        ConnectionHandler(Row rowOrNull, SQLException failure) {
            this.rowOrNull = rowOrNull;
            this.failure = failure;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            String name = method.getName();
            methods.add(name);
            switch (name) {
                case "equals":
                    return proxy == args[0];
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "toString":
                    return "ConnectionDouble";
                case "prepareStatement":
                    preparedSql.add(String.valueOf(args[0]));
                    return statement(rowOrNull, failure);
                case "prepareCall":
                    return null;
                case "close":
                    connectionClosed = true;
                    return null;
                case "isClosed":
                    return connectionClosed;
                default:
                    return defaultValue(method);
            }
        }
    }

    private static PreparedStatement statement(Row rowOrNull, SQLException failure) {
        return (PreparedStatement) Proxy.newProxyInstance(AuthDoublesTest.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class},
                new StatementHandler(rowOrNull, failure));
    }

    private static final class StatementHandler implements InvocationHandler {
        private final Row rowOrNull;
        private final SQLException failure;

        StatementHandler(Row rowOrNull, SQLException failure) {
            this.rowOrNull = rowOrNull;
            this.failure = failure;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws SQLException {
            String name = method.getName();
            methods.add(name);
            switch (name) {
                case "equals":
                    return proxy == args[0];
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "toString":
                    return "PreparedStatementDouble";
                case "setString":
                    boundValues.add(new Object[] {args[0], args[1]});
                    return null;
                case "setQueryTimeout":
                    timeouts.add((Integer) args[0]);
                    return null;
                case "executeQuery":
                    if (failure != null) {
                        throw failure;
                    }
                    return resultSet(rowOrNull);
                case "executeUpdate":
                    return 1;
                case "close":
                    statementClosed = true;
                    return null;
                case "isClosed":
                    return statementClosed;
                default:
                    return defaultValue(method);
            }
        }
    }

    private static ResultSet resultSet(Row rowOrNull) {
        return (ResultSet) Proxy.newProxyInstance(AuthDoublesTest.class.getClassLoader(),
                new Class<?>[] {ResultSet.class}, new ResultHandler(rowOrNull));
    }

    private static final class ResultHandler implements InvocationHandler {
        private final Row row;
        private boolean consumed;

        ResultHandler(Row row) {
            this.row = row;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            String name = method.getName();
            methods.add("ResultSet." + name);
            switch (name) {
                case "equals":
                    return proxy == args[0];
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "toString":
                    return "ResultSetDouble";
                case "next": {
                    if (consumed || row == null || !row.present) {
                        return false;
                    }
                    consumed = true;
                    return true;
                }
                case "getString":
                    return row == null ? null : row.hash;
                case "close":
                    resultClosed = true;
                    return null;
                case "isClosed":
                    return resultClosed;
                default:
                    return defaultValue(method);
            }
        }
    }

    private static Object defaultValue(Method method) {
        Class<?> type = method.getReturnType();
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        return null;
    }
}
