package app;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.EnumSet;
import java.util.List;

/**
 * The real command line, driven the way a script or an attacker drives it: piped standard input,
 * arguments, and a hostile environment. The unit suites prove the components; this one proves the
 * wiring, because a correct library behind a CLI that echoes a secret or accepts a credential in
 * argv is still an insecure feature.
 *
 * <p>Every run uses the shipped Argon2id defaults (64 MiB, t=3), so the runs here are deliberately
 * few and each one asserts several properties at once.
 */
public final class CliTest {

    /**
     * Shares no substring with either identifier: "cli" is the email's local part, so a password
     * containing it would be refused by the "password must not contain the account name" rule and
     * every assertion below would then be about that rule instead of the one it names.
     */
    private static final String PASSWORD = "Violet-Harbor-42";
    private static final String EMAIL = "cli@corp.example";
    private static final String NAME = "cli-user";
    private static final String DB_PASSWORD = "Cli-Store-Password-0123456";

    public static void main(String[] argv) throws Exception {
        Path base = Harness.scratch("cli");
        Harness.remove(base);

        usageAndBadConfig(base);
        registerLoginVerifyLogout(base.resolve("happy"));
        refusedRegistration(base.resolve("refused"));
        uniformLoginRefusals(base.resolve("uniform"));
        oversizedInput(base.resolve("oversized"));
        revokeSessionsCommand(base.resolve("revoke"));
        bearerTokenNeverAnArgument(base.resolve("argv"));
        sourceIdentityIgnoresForgedName(base.resolve("source-key"));
        crashIsReportedGenerically(base.resolve("crash"));

        System.exit(Harness.report("CliTest"));
    }

    private static void usageAndBadConfig(Path base) throws Exception {
        Harness.section("the command line refuses to start without a validated configuration");
        Harness.check(System.console() == null,
            "this run has no terminal, so the CLI's byte-input path is the one under test");
        Run noArgs = run(base, List.of(), env(base, null));
        Harness.equal(Main.BAD_USAGE, noArgs.exit(), "no command is a usage error");
        Harness.check(noArgs.err().contains("Usage:"), "usage goes to the error channel for a usage error");

        Run help = run(base, List.of("--help"), env(base, null));
        Harness.equal(Main.OK, help.exit(), "--help exits cleanly");
        Harness.check(help.out().contains("APP_ARGON2_MEMORY_KIB"),
            "the usage text documents the tuning variables an operator needs");

        Run noSecret = run(base, List.of("register"), env(base, null));
        Harness.equal(Main.BAD_CONFIG, noSecret.exit(), "a missing database password stops the program");
        Harness.check(noSecret.err().contains(Config.ENV_DB_PASSWORD),
            "the message names the missing setting");
        Path worldWritable = base.resolve("ww");
        Files.createDirectories(worldWritable);
        Files.setPosixFilePermissions(worldWritable, EnumSet.allOf(PosixFilePermission.class));
        Run unsafe = run(worldWritable, List.of("login"), env(worldWritable, DB_PASSWORD));
        Harness.equal(Main.BAD_CONFIG, unsafe.exit(),
            "a world-writable data directory is refused before the store is opened");

        Path wrongMode = base.resolve("wrongmode");
        Run first = run(wrongMode, List.of("--help"), env(wrongMode, DB_PASSWORD));
        Harness.equal(Main.OK, first.exit(), "the help path does not touch the store");
        Run createStore = run(wrongMode, List.of("register"), env(wrongMode, DB_PASSWORD)
            .withInput(EMAIL + "\n" + NAME + "\n" + PASSWORD + "\n"));
        Harness.check(createStore.exit() == Main.OK || createStore.exit() == Main.REFUSED,
            "the store file is created 0600 and the command ran (exit " + createStore.exit() + ")");
        if (Files.exists(wrongMode.resolve("accounts.mv.db"))) {
            Harness.equal("rw-------", Harness.permissionString(wrongMode.resolve("accounts.mv.db")),
                "the database the CLI created is owner-only, not the 0644 umask default");
        }
        Path audit = wrongMode.resolve("audit.log");
        if (Files.exists(audit)) {
            Harness.equal("rw-------", Harness.permissionString(audit),
                "the audit log the CLI created is owner-only");
        }
    }

    private static void registerLoginVerifyLogout(Path dir) throws Exception {
        Harness.section("register, login, verify and logout work end to end over a pipe");
        Env env = env(dir, DB_PASSWORD);

        Run registered = run(dir, List.of("register"),
            env.withInput(EMAIL + "\n" + NAME + "\n" + PASSWORD + "\n"));
        Harness.equal(Main.OK, registered.exit(), "registration completed");
        Harness.check(registered.out().contains(AccountStore.OUTCOME_MESSAGE),
            "the registration answer is the fixed sentence");
        Harness.check(!registered.out().contains(EMAIL) && !registered.out().contains(NAME),
            "the answer does not echo the address or the username");
        Harness.check(!registered.out().contains(PASSWORD), "the answer never echoes the password");
        Harness.check(!registered.err().contains(PASSWORD), "nor does the error stream");

        Run duplicate = run(dir, List.of("register"),
            env.withInput(EMAIL + "\n" + otherName() + "\n" + PASSWORD + "\n"));
        Harness.equal(registered.out().trim(), duplicate.out().trim(),
            "a taken mailbox answers with exactly the sentence a success printed");

        Run signedIn = run(dir, List.of("login"),
            env.withInput(EMAIL + "\n" + PASSWORD + "\n"));
        Harness.equal(Main.OK, signedIn.exit(), "the correct credential signs in");
        String header = lastLine(signedIn.out());
        Harness.check(header.startsWith("Set-Cookie: " + CookiePolicy.SESSION_COOKIE_NAME + '='),
            "the session is returned as a session cookie header");
        Harness.check(header.contains("HttpOnly") && header.contains("Secure")
                && header.contains("SameSite=Strict") && header.contains("Path=/"),
            "the printed header carries every protective attribute");
        String token = tokenOf(header);
        Harness.check(SessionStore.isWellFormedToken(token), "the printed token is well-formed");
        Harness.check(!signedIn.out().contains(PASSWORD), "the login output never echoes the password");

        Run verified = run(dir, List.of("verify"), env.withInput(token + "\n"));
        Harness.equal(Main.OK, verified.exit(), "the issued cookie validates");
        Harness.check(verified.out().contains("The session is valid."), "and says so");

        Run verifyNameValue = run(dir, List.of("verify"),
            env.withInput(CookiePolicy.SESSION_COOKIE_NAME + "=" + token + "; Path=/\n"));
        Harness.equal(Main.OK, verifyNameValue.exit(),
            "a cookie header fragment (name=value; attributes) is parsed, not refused");

        Run verifyGarbage = run(dir, List.of("verify"), env.withInput("not-a-session\n"));
        Harness.equal(Main.REFUSED, verifyGarbage.exit(), "a malformed cookie is refused");
        Harness.check(verifyGarbage.out().contains("The session is not valid."),
            "and the answer is the generic one");

        Run loggedOut = run(dir, List.of("logout"), env.withInput(token + "\n"));
        Harness.equal(Main.OK, loggedOut.exit(), "logout completes");
        Harness.check(loggedOut.out().contains("Set-Cookie: " + CookiePolicy.expiredSessionCookie("/")),
            "logout mirrors the cookie with an expired one so the client drops it");
        Harness.equal(Main.REFUSED, run(dir, List.of("verify"), env.withInput(token + "\n")).exit(),
            "the revoked cookie no longer validates");
        Harness.equal(Main.OK, run(dir, List.of("logout"), env.withInput(token + "\n")).exit(),
            "logging out twice answers the same - the second is not an error");

        Run wrongPassword = run(dir, List.of("login"), env.withInput(EMAIL + "\n" + "Wrong-Cli-9\n"));
        Harness.equal(Main.REFUSED, wrongPassword.exit(), "a wrong password is refused");
        Harness.check(wrongPassword.out().contains(AuthService.INVALID_MESSAGE),
            "with the shared sentence");

        List<String> trail = Files.readAllLines(dir.resolve("audit.log"), StandardCharsets.UTF_8);
        Harness.requireNotEmpty(trail, "the CLI's audit trail");
        String joined = String.join("\n", trail);
        Harness.check(joined.contains("REGISTRATION_ACCEPTED"), "registration is recorded");
        Harness.check(joined.contains("LOGIN_SUCCESS"), "the sign-in is recorded");
        Harness.check(joined.contains("SESSION_ISSUED") && joined.contains("SESSION_REVOKED"),
            "the session's whole life is recorded");
        Harness.check(!joined.contains(PASSWORD) && !joined.contains(token)
                && !joined.contains(EMAIL) && !joined.contains(NAME),
            "the trail carries tags: no password, no bearer token, no identifiers");
        Harness.check(!joined.contains(Digests.sha256Hex(token.getBytes(StandardCharsets.US_ASCII))),
            "not even the stored token hash is in the trail");
        Harness.check(trail.stream().allMatch(line -> line.startsWith("{") && line.endsWith("}")),
            "every trail line is one JSON object");
    }

    private static void refusedRegistration(Path dir) throws Exception {
        Harness.section("invalid registration input is refused with the rule, and nothing is stored");
        Env env = env(dir, DB_PASSWORD);
        List<String> cases = List.of(
            "not-an-email\n" + NAME + "\n" + PASSWORD + "\n",
            EMAIL + "\nBad Name!\n" + PASSWORD + "\n",
            EMAIL + "\n" + NAME + "\nshort\n");
        Harness.requireNotEmpty(cases, "the invalid-input capture");
        for (String input : cases) {
            Run refused = run(dir, List.of("register"), env.withInput(input));
            Harness.equal(Main.REFUSED, refused.exit(), "invalid input is refused, not accepted");
            Harness.check(refused.out().lines().anyMatch(line -> line.startsWith("Registration refused: ")),
                "the person registering is told which rule failed, on a line of its own");
            Harness.check(!refused.out().contains(PASSWORD) && !refused.out().contains("not-an-email"),
                "the refusal names the rule, never the offending value");

        }
        Harness.equal(0L, rows(dir, "SELECT COUNT(*) FROM accounts"),
            "none of the refused attempts created a row");
        Harness.check(Files.exists(dir.resolve("audit.log")),
            "the refusals are recorded even though nothing was stored");
    }

    private static void uniformLoginRefusals(Path dir) throws Exception {
        Harness.section("every CLI login refusal prints the same line and exits the same way");
        Env env = env(dir, DB_PASSWORD);
        Harness.equal(Main.OK, run(dir, List.of("register"),
            env.withInput(EMAIL + "\n" + NAME + "\n" + PASSWORD + "\n")).exit(),
            "the CLI fixture has an account to test against");

        List<String> attempts = List.of(
            "!!broken!!\n" + PASSWORD + "\n",
            "ghost@corp.example\n" + PASSWORD + "\n",
            "ghost-user\n" + PASSWORD + "\n",
            EMAIL + "\nWrong-Cli-9\n",
            EMAIL + "\n\n");
        Harness.requireNotEmpty(attempts, "the login-refusal capture");
        for (String input : attempts) {
            Run refused = run(dir, List.of("login"), env.withInput(input));
            Harness.equal(Main.REFUSED, refused.exit(), "the refusal exit code is uniform");
            Harness.equal(AuthService.INVALID_MESSAGE, lastLine(refused.out()),
                "and so is the printed line, for every refusal path");
        }
        Harness.check(!lastLine(run(dir, List.of("login"), env.withInput(
            EMAIL + "\n" + PASSWORD + "\n")).out()).contains(AuthService.INVALID_MESSAGE),
            "the correct credential is still accepted - the uniformity above is not blanket failure");
    }

    private static void oversizedInput(Path dir) throws Exception {
        Harness.section("an oversized line is refused while it is being read");
        Env env = env(dir, DB_PASSWORD);
        String huge = "a".repeat(InputPolicy.MAX_FIELD_CHARS + 500);
        Run refused = run(dir, List.of("register"),
            env.withInput(huge + "\n" + NAME + "\n" + PASSWORD + "\n"));
        Harness.equal(Main.REFUSED, refused.exit(), "an oversized email is refused outright");
        Harness.equal(0L, rows(dir, "SELECT COUNT(*) FROM accounts"),
            "and the oversized value never reached the store");
        Harness.check(!refused.out().contains(huge), "the oversized input is not echoed back");

        Run hugeSecret = run(dir, List.of("login"),
            env.withInput(EMAIL + "\n" + "z".repeat(InputPolicy.PASSWORD_MAX + 400) + "\n"));
        Harness.equal(Main.REFUSED, hugeSecret.exit(),
            "an oversized password is refused too, before any key-derivation budget is spent on it");
    }

    private static void revokeSessionsCommand(Path dir) throws Exception {
        Harness.section("revoke-sessions ends live sessions and never says whether the account exists");
        Env env = env(dir, DB_PASSWORD);
        Harness.equal(Main.OK, run(dir, List.of("register"),
            env.withInput(EMAIL + "\n" + NAME + "\n" + PASSWORD + "\n")).exit(), "the CLI fixture registers");
        Run signedIn = run(dir, List.of("login"), env.withInput(NAME + "\n" + PASSWORD + "\n"));
        String token = tokenOf(lastLine(signedIn.out()));
        Harness.equal(Main.OK, run(dir, List.of("verify"), env.withInput(token + "\n")).exit(),
            "the username path issued a live session");

        Run revoked = run(dir, List.of("revoke-sessions"), env.withInput(NAME + "\n"));
        Harness.equal(Main.OK, revoked.exit(), "the operator command ran");
        Harness.check(revoked.out().contains("Sign-out is complete."),
            "the operator command prints the fixed sentence");
        Harness.equal(Main.REFUSED, run(dir, List.of("verify"), env.withInput(token + "\n")).exit(),
            "the session it swept no longer validates");

        Run unknown = run(dir, List.of("revoke-sessions"), env.withInput("no-such-user\n"));
        Harness.equal(revoked.out().trim(), unknown.out().trim(),
            "revoking for an account that does not exist prints the same sentence");

        Run badName = run(dir, List.of("revoke-sessions"), env.withInput("Bad Name!\n"));
        Harness.equal(revoked.out().trim(), badName.out().trim(),
            "and so does a malformed username");

        List<String> trail = Files.readAllLines(dir.resolve("audit.log"), StandardCharsets.UTF_8);
        Harness.requireNotEmpty(trail, "the revoke command's audit trail");
        Harness.check(trail.stream().anyMatch(line -> line.contains("ADMIN_REVOKE_REQUESTED")
                && line.contains("\"count\":\"1\"")),
            "the operator action is recorded with the number of sessions it actually ended");
        Harness.check(trail.stream().anyMatch(
                line -> line.contains("ADMIN_REVOKE_REFUSED_INVALID_INPUT")),
            "the malformed operator request is recorded as a refused revoke, not silently dropped");
        Harness.check(trail.stream().noneMatch(
                line -> line.contains("REGISTRATION_REFUSED_INVALID_INPUT")),
            "an admin refusal is not labelled a refused sign-up, which would send whoever reads the"
                + " trail looking for registrations that never happened");
    }

    private static void bearerTokenNeverAnArgument(Path dir) throws Exception {
        Harness.section("a session cookie is prompted for, never taken from the command line");
        Env env = env(dir, DB_PASSWORD);
        Harness.equal(Main.OK, run(dir, List.of("register"),
            env.withInput(EMAIL + "\n" + NAME + "\n" + PASSWORD + "\n")).exit(), "the CLI fixture registers");
        String token = tokenOf(lastLine(
            run(dir, List.of("login"), env.withInput(EMAIL + "\n" + PASSWORD + "\n")).out()));

        // The token stays supplied as an operand here on purpose: the point is that it is refused
        // for that, and that the refused run still never consumes it from the process arguments.
        Run verifyAsArgument = run(dir, List.of("verify", token), env);
        Harness.equal((long) Main.REFUSED, (long) verifyAsArgument.exit(),
            "a cookie handed over as an argument is refused, not merely 'not accepted'");
        Harness.check(verifyAsArgument.err().contains("arguments are visible in other users' process listings"),
            "the operator is told why, on the error channel");
        Harness.check(!verifyAsArgument.out().contains("The session is valid."),
            "the refused run does not report the session as valid");

        Run logoutAsArgument = run(dir, List.of("logout", token), env);
        Harness.equal((long) Main.REFUSED, (long) logoutAsArgument.exit(),
            "logout refuses the cookie as an argument with a non-success exit, not a fabricated success");
        Harness.check(logoutAsArgument.err().contains("arguments are visible in other users' process listings"),
            "and gives the same explanation");
        Harness.check(!logoutAsArgument.out().contains("Sign-out is complete."),
            "it does not claim to have signed the session out when nothing was revoked");
        Harness.check(!logoutAsArgument.out().contains(CookiePolicy.SESSION_COOKIE_NAME),
            "and emits no expired-cookie header, which would tell a client a live token is dead");
        Harness.check(!logoutAsArgument.out().contains(token),
            "the refused run does not echo the bearer value it was handed");
        Harness.equal(Main.OK, run(dir, List.of("verify"), env.withInput(token + "\n")).exit(),
            "and the session really was not consumed - it still validates when typed, so logout"
                + " declined the argv value instead of acting on it");

        String usage = run(dir, List.of("--help"), env).out();
        Harness.requireNotEmpty(usage, "the usage text");
        Harness.check(!usage.contains("verify <") && !usage.contains("logout <"),
            "the usage text shows no cookie placeholder, so it never teaches the unsafe form");
        Harness.check(usage.contains("standard input") || usage.contains("prompted"),
            "and it says where the cookie belongs");

        // An ended input is a plain refusal, not a fault: it must not be reported as a crash.
        Run inputEnded = run(dir, List.of("verify"), env);
        Harness.equal(Main.REFUSED, inputEnded.exit(),
            "a session command whose input ended immediately is refused");
        Harness.check(inputEnded.out().contains("The session is not valid."),
            "with the same answer a bad cookie gets");
        Harness.check(!inputEnded.err().contains("at app.") && !inputEnded.out().contains("at app."),
            "and no stack trace on either channel");
    }

    /**
     * The per-source rate-limit identity must be a kernel fact, not a launch-time property. A key
     * derived from {@code System.getProperty("user.name")} lets anyone who can add {@code
     * -Duser.name=$RANDOM} mint a brand-new, full budget on every attempt, which makes the per-source
     * limit decorative. This section mutates {@code user.name} between attempts on a fresh store: if
     * the key tracked the property, no attempt would ever be throttled; because it tracks the uid, the
     * shared budget is spent and the flood is refused.
     */
    private static void sourceIdentityIgnoresForgedName(Path dir) throws Exception {
        Harness.section("a forged -Duser.name cannot mint a fresh rate-limit budget");
        Env env = env(dir, DB_PASSWORD);
        String savedName = System.getProperty("user.name");
        try {
            for (int attempt = 0; attempt < Throttle.SOURCE_MAX_ATTEMPTS + 3; attempt++) {
                // A distinct user.name each time: the old property-derived key would treat every
                // attempt as a different source and refill its budget.
                System.setProperty("user.name", "attacker-" + attempt);
                run(dir, List.of("login"),
                    env.withInput("flood" + attempt + "@corp.example\n" + PASSWORD + "\n"));
            }
        } finally {
            if (savedName != null) {
                System.setProperty("user.name", savedName);
            } else {
                System.clearProperty("user.name");
            }
        }
        List<String> trail = Files.readAllLines(dir.resolve("audit.log"), StandardCharsets.UTF_8);
        Harness.requireNotEmpty(trail, "the flood produced an audit trail to inspect");
        Harness.check(trail.stream().anyMatch(line -> line.contains("LOGIN_THROTTLED_SOURCE")),
            "the attempts from differing user.name values shared one budget and ran into the per-source"
                + " limit, so the key is not derived from a property a caller controls");
    }

    /**
     * {@code Path.of} raises an unchecked {@code InvalidPathException} for a path containing a NUL,
     * which escapes configuration parsing and reaches the last-resort handler. That is the seam
     * used here: the assertion is about what the handler prints, and a NUL makes the failure
     * deterministic without adding a test-only hook to production code.
     */
    private static void crashIsReportedGenerically(Path dir) throws Exception {
        Harness.section("an unchecked failure prints a generic refusal, not a stack trace");
        // One argument, the shipped form: as two arguments this is a malformed option and is refused
        // by configuration, which is a different path and would leave the handler untested.
        Run crashed = runRaw(List.of("login", "--data-dir=" + dir + "/hidden\u0000dir"),
            dir, DB_PASSWORD, Harness.PW_ONE + "\n");
        Harness.equal((long) crashed.exit(), (long) Main.UNAVAILABLE,
            "an unexpected failure refuses the operation rather than reporting success");
        Harness.check(crashed.err().contains(AuthService.INTERNAL_MESSAGE),
            "the client sees the generic unavailability sentence, on the same channel as every other"
                + " start-up failure");
        Harness.check(!crashed.out().contains("at app."),
            "nothing on stdout either");
        Harness.check(crashed.err().contains("NOTE unexpected failure of type"),
            "the operator gets the exception's one-line identity to look up");
        Harness.check(!crashed.err().contains("at app.") && !crashed.out().contains("at app.")
                && !crashed.err().contains("\tat "),
            "no stack trace is printed on either channel");
        Harness.check(!crashed.err().contains("hidden") && !crashed.out().contains("hidden"),
            "the refused path is not echoed - the exception's own message would name it");
        Harness.check(!crashed.err().contains(DB_PASSWORD) && !crashed.out().contains(DB_PASSWORD),
            "nor is the database password");
    }

    // ------------------------------------------------------------------ running the binary

    private record Run(int exit, String out, String err) {
    }

    private record Env(java.nio.file.Path dir, String dbPassword, String input) {
        Env withInput(String replacement) {
            return new Env(dir, dbPassword, replacement);
        }
    }

    private static Env env(Path dir, String dbPassword) {
        return new Env(dir, dbPassword, "");
    }

    /**
     * Drives {@link Main#run} with an explicit environment function, so no test depends on the
     * ambient shell environment or leaks state into another test.
     */
    private static Run run(Path dir, List<String> argv, Env environment) {
        java.util.Map<String, String> values = new java.util.HashMap<>();
        values.put(Config.ENV_DATA_DIR, dir.toString());
        if (environment.dbPassword() != null) {
            values.put(Config.ENV_DB_PASSWORD, environment.dbPassword());
        }
        return invoke(argv, values, environment.input());
    }

    /** Same drive, but the caller owns argv entirely and the environment carries no data directory. */
    private static Run runRaw(List<String> argv, Path dir, String dbPassword, String input) {
        java.util.Map<String, String> values = new java.util.HashMap<>();
        values.put(Config.ENV_DB_PASSWORD, dbPassword);
        return invoke(argv, values, input);
    }

    private static Run invoke(List<String> argv, java.util.Map<String, String> values, String input) {
        ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
        ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(outBuffer, true, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(errBuffer, true, StandardCharsets.UTF_8);
        int exit = Main.run(argv.toArray(new String[0]), values::get,
            new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)), out, err);
        out.flush();
        err.flush();
        return new Run(exit, outBuffer.toString(StandardCharsets.UTF_8),
            errBuffer.toString(StandardCharsets.UTF_8));
    }

    // ------------------------------------------------------------------ helpers

    private static String lastLine(String output) {
        String[] lines = output.split("\n");
        for (int i = lines.length - 1; i >= 0; i--) {
            if (!lines[i].isEmpty()) {
                return lines[i];
            }
        }
        return "";
    }

    private static String tokenOf(String header) {
        String value = header.substring(header.indexOf('=') + 1);
        int semicolon = value.indexOf(';');
        return semicolon < 0 ? value : value.substring(0, semicolon);
    }

    private static String otherName() {
        return "other-cli-user";
    }

    /** Opens the store read-only-ish, counts rows and always ends the transaction it started. */
    private static long rows(Path dir, String sql) throws SQLException {
        java.util.Properties props = new java.util.Properties();
        props.setProperty("user", "app");
        props.setProperty("password", DB_PASSWORD);
        try (java.sql.Connection connection = java.sql.DriverManager.getConnection(
            "jdbc:h2:file:" + dir.resolve("accounts")
                + ";DB_CLOSE_ON_EXIT=FALSE;AUTO_SERVER=FALSE;TRACE_LEVEL_FILE=0", props)) {
            connection.setAutoCommit(false);
            try (PreparedStatement count = connection.prepareStatement(sql);
                 ResultSet found = count.executeQuery()) {
                found.next();
                long rows = found.getLong(1);
                connection.commit();
                return rows;
            } catch (SQLException failed) {
                connection.rollback();
                throw failed;
            }
        }
    }
}
