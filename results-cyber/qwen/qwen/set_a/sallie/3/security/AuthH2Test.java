import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

/**
 * Verification suite 2: a real SQL engine (H2).
 *
 * <p>The stand-in suite replays a scripted answer, so it cannot notice a predicate that matches too
 * much: {@code email = ?} and {@code email LIKE ?} both hand back the same row. This suite asks a
 * real database, so wildcard characters in the address ({@code %} and {@code _} are legal in an
 * email) are caught, and it also runs the real command-line program as a child process.
 *
 * <p>Run: {@code java -cp build:h2.jar AuthH2Test <dir-with-sources-and-schema> [h2.jar]}
 */
public final class AuthH2Test {

    private static final List<String> failures = new ArrayList<>();
    private static int checks;

    private static String jdbcUrl;
    private static Path workDir;

    private static final String ALICE = "alice@example.com";
    private static final String ALICE_PW = "Fresh-Admin-21";
    private static final String BOB = "bob@example.com";
    private static final String BOB_PW = "Another-Admin-7";

    public static void main(String[] args) throws Exception {
        Path base = Paths.get(args.length > 0 ? args[0] : ".").toAbsolutePath();
        workDir = Files.createTempDirectory(base, "h2test-");
        Runtime.getRuntime().addShutdownHook(new Thread(AuthH2Test::removeWorkDir));
        String jar = args.length > 1 ? args[1] : "h2.jar";

        int port = freePort();
        startTcpServer(port, jar);
        jdbcUrl = "jdbc:h2:tcp://127.0.0.1:" + port + "/mem:authsuite;DB_CLOSE_DELAY=-1";

        try (Connection c = DriverManager.getConnection(jdbcUrl, "sa", "")) {
            applySchema(c, base.resolve("schema.sql"));
        }
        seedAccounts();

        plumbingWorks();
        wildcardAddressesDoNotMatch();
        injectionPayloadsCannotLogIn();
        payloadIsGenuinelyDangerousWhenConcatenated();
        storedValueIsADigestNotAPassword();
        duplicateEmailIsRefused();
        brokenStoredRecordCannotLogIn();
        tableSurvivesTheWholeRun();
        timingIsFlatAcrossDbDependentOutcomes();
        commandLineEndToEnd(base, jar, port);

        System.out.println("SUITE=h2 checks=" + checks + " failed=" + failures.size());
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

    private static void plumbingWorks() {
        AuthenticationService service = service();
        AuthenticationService.AuthResult alice =
                service.authenticate(ALICE, ALICE_PW.toCharArray());
        check("stored account can log in", alice.isAuthenticated());
        check("success sentence on the happy path", "Authentication successful.".equals(alice.message()));

        AuthenticationService.AuthResult bob = service.authenticate(BOB, BOB_PW.toCharArray());
        check("second stored account can log in with its own password", bob.isAuthenticated());

        AuthenticationService.AuthResult swapped = service.authenticate(ALICE, BOB_PW.toCharArray());
        check("another account's password is refused", !swapped.isAuthenticated()
                && swapped.outcome() == AuthenticationService.Outcome.DENIED);

        AuthenticationService.AuthResult cased =
                service.authenticate("  ALICE@Example.COM  ", ALICE_PW.toCharArray());
        check("surrounding spaces and letter case still reach the same account", cased.isAuthenticated());
    }

    /**
     * {@code %} and {@code _} are legal in the local part of an address, so they always reach the
     * driver. With {@code =} they match nothing; with {@code LIKE} they match alice. Only a real
     * database can tell those two predicates apart.
     */
    private static void wildcardAddressesDoNotMatch() {
        String[] wildcards = {
                "ali%@example.com",
                "%@example.com",
                "%@%",
                "_lice@example.com",
                "a__ce@example.com",
                "li%@example.com",
        };
        for (String address : wildcards) {
            AuthenticationService.AuthResult result =
                    service().authenticate(address, ALICE_PW.toCharArray());
            check("wildcard address cannot borrow a stored account: " + address,
                    !result.isAuthenticated());
        }
    }

    private static void injectionPayloadsCannotLogIn() {
        String[] payloads = {
                ALICE + "' OR '1'='1",
                ALICE + "' --",
                ALICE + "'/*",
                "' OR 1=1 --",
                "anything@example.com' OR '1'='1",
                "x@example.com'; DROP TABLE users;--",
                "x@example.com' UNION SELECT password_hash FROM users--",
                "admin'--@example.com",
                "a--@example.com",
                "union.select--@example.com",
                "_wildcard%@example.com",
                "%25@example.com",
                "x@example.com\\",
                "x@example.com\" OR \"1\"=\"1",
        };
        int reachedDriver = 0;
        for (String payload : payloads) {
            AuthenticationService service = service();
            long start = System.nanoTime();
            AuthenticationService.AuthResult result =
                    service.authenticate(payload, ALICE_PW.toCharArray());
            boolean refused = !result.isAuthenticated();
            check("injection payload cannot log in: " + describe(payload), refused);
            if (result.outcome() != AuthenticationService.Outcome.INVALID_INPUT) {
                reachedDriver++;
                check("payload that reached the database was refused as a credential, not an error: "
                                + describe(payload),
                        result.outcome() == AuthenticationService.Outcome.DENIED);
            }
            if (System.nanoTime() - start > 20_000_000_000L) {
                check("payload did not stall the query: " + describe(payload), false);
            }
        }
        check("enough payloads reached the real engine to be meaningful", reachedDriver >= 3);
        System.out.println("NOTE h2_payloads_reaching_engine=" + reachedDriver + "/" + payloads.length);
    }

    /**
     * Positive control. Shows the first payload is not merely harmless: run through the
     * string-concatenated query it really does return a row and really does verify alice's
     * password. The service under test refuses the same input.
     */
    private static void payloadIsGenuinelyDangerousWhenConcatenated() {
        String payload = ALICE + "' OR '1'='1";
        check("the real table holds a row for alice", storedHashOf(ALICE) != null);
        String returnedByConcatenation = vulnerableLookup(payload);
        check("the concatenated query hands back alice's stored row for the payload",
                returnedByConcatenation != null);
        check("with concatenation the payload would have verified alice's password",
                returnedByConcatenation != null
                        && AuthenticationService.Passwords.matches(
                                ALICE_PW.toCharArray(), returnedByConcatenation));
        AuthenticationService.AuthResult viaService =
                service().authenticate(payload, ALICE_PW.toCharArray());
        check("the service under test refuses the very same payload", !viaService.isAuthenticated());
    }

    /** Deliberately vulnerable query, kept here so the payload's danger is demonstrated, not assumed. */
    private static String vulnerableLookup(String email) {
        String sql = "SELECT password_hash FROM users WHERE email = '" + email + "'";
        try (Connection c = DriverManager.getConnection(jdbcUrl, "sa", "");
             Statement s = c.createStatement();
             ResultSet rows = s.executeQuery(sql)) {
            return rows.next() ? rows.getString(1) : null;
        } catch (SQLException expected) {
            return null;
        }
    }

    private static void storedValueIsADigestNotAPassword() {
        String aliceHash = storedHashOf(ALICE);
        String bobHash = storedHashOf(BOB);
        check("stored value is a labelled digest", aliceHash != null
                && aliceHash.startsWith("pbkdf2-sha256$100000$"));
        check("stored value does not contain the password", !aliceHash.contains(ALICE_PW)
                && !aliceHash.contains(BOB_PW));
        check("stored value is not a bare hash of the password without a salt",
                aliceHash.split("\\$").length == 4);
        check("two accounts get different digests", !aliceHash.equals(bobHash));

        String samePw = service().authenticate(ALICE, ALICE_PW.toCharArray()).isAuthenticated()
                ? digestOf(ALICE_PW) : null;
        check("the same password twice yields a different stored value (fresh salt)",
                samePw != null && !samePw.equals(aliceHash));
    }

    private static void duplicateEmailIsRefused() {
        char[] secret = "Second-Admin-5".toCharArray();
        boolean refused;
        try {
            service().register(ALICE, secret);
            refused = false;
        } catch (SQLException expected) {
            refused = true;
        } catch (AuthenticationService.InvalidInputException bad) {
            refused = false;
        }
        check("registering an address that already exists is refused", refused);
        check("the original account still logs in after the refused insert",
                service().authenticate(ALICE, ALICE_PW.toCharArray()).isAuthenticated());
    }

    private static void brokenStoredRecordCannotLogIn() {
        insertRaw("attacker@example.com", "hunter2");
        AuthenticationService.AuthResult plaintext =
                service().authenticate("attacker@example.com", "hunter2".toCharArray());
        check("a stored value that is raw text cannot be used to log in", !plaintext.isAuthenticated());
        check("a stored value that is raw text is refused as a denial",
                plaintext.outcome() == AuthenticationService.Outcome.DENIED);

        insertRaw("trunc@example.com", "pbkdf2-sha256$100000$AAAAAAAAAAAAAAAAAAAAAA==$Zm9v");
        check("a stored digest that is too short cannot be used to log in",
                !service().authenticate("trunc@example.com", ALICE_PW.toCharArray()).isAuthenticated());

        insertRaw("loop@example.com", "pbkdf2-sha256$99999999$AAAAAAAAAAAAAAAAAAAAAA==$"
                + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        long start = System.nanoTime();
        boolean refused = !service().authenticate("loop@example.com", ALICE_PW.toCharArray())
                .isAuthenticated();
        long ms = (System.nanoTime() - start) / 1_000_000L;
        check("an absurd iteration count cannot be used to log in", refused);
        check("an absurd iteration count costs one ordinary digest, not the requested "
                + "99999999 rounds (took " + ms + " ms)", ms <= 3_000);
        System.out.println("NOTE absurd_iteration_refusal_ms=" + ms);

        // The schema forbids a NULL digest, so the nearest thing the table can actually hold is
        // an empty one. A NULL column is covered in the stand-in suite instead.
        insertRaw("emptyish@example.com", "");
        check("an empty stored value cannot be used to log in",
                !service().authenticate("emptyish@example.com", ALICE_PW.toCharArray())
                        .isAuthenticated());
    }

    private static void tableSurvivesTheWholeRun() {
        try (Connection c = DriverManager.getConnection(jdbcUrl, "sa", "");
             Statement s = c.createStatement();
             ResultSet rows = s.executeQuery("SELECT COUNT(*) FROM users")) {
            rows.next();
            long n = rows.getLong(1);
            check("the users table still exists and still has its rows", n >= 2);
            System.out.println("NOTE users_rows_after_attack_run=" + n);
        } catch (SQLException gone) {
            check("the users table still exists after the payload run", false);
        }
    }

    private static void timingIsFlatAcrossDbDependentOutcomes() {
        int rounds = 5;
        long[] known = new long[rounds];
        long[] unknown = new long[rounds];
        long[] malformed = new long[rounds];
        for (int i = 0; i < rounds; i++) {
            known[i] = nanos(() -> service().authenticate(ALICE, "wrong-password-9".toCharArray()));
            unknown[i] = nanos(() -> service()
                    .authenticate("nobody-here@example.com", "wrong-password-9".toCharArray()));
            malformed[i] = nanos(() -> service().authenticate("not-an-email", "wrong-password-9".toCharArray()));
        }
        double knownMs = median(known) / 1_000_000.0;
        double unknownMs = median(unknown) / 1_000_000.0;
        double malformedMs = median(malformed) / 1_000_000.0;
        double ratio = Math.max(knownMs, unknownMs) / Math.max(0.001, Math.min(knownMs, unknownMs));
        System.out.printf(Locale.ROOT,
                "NOTE timing_us known_wrong_pw=%.0f unknown_account=%.0f malformed_input=%.0f"
                        + " known_vs_unknown_ratio=%.2f%n",
                median(known) / 1_000.0, median(unknown) / 1_000.0, median(malformed) / 1_000.0, ratio);
        check("a wrong password against a known account costs a full digest (" + knownMs + " ms)",
                knownMs >= 60.0);
        check("an unknown account costs the same full digest, so it is not a fast answer ("
                + unknownMs + " ms)", unknownMs >= 60.0);
        check("known and unknown accounts are within 1.6x of each other (ratio " + ratio + ")",
                ratio <= 1.6);
        check("a malformed address is refused without database work, so it is much cheaper ("
                + malformedMs + " ms)", malformedMs < knownMs / 4.0);
    }

    // -------------------------------------------------------------------------------------
    // Real command line, as a child process
    // -------------------------------------------------------------------------------------

    private static void commandLineEndToEnd(Path base, String jar, int port) throws Exception {
        String classpath = base.resolve("build").toAbsolutePath() + File.pathSeparator
                + Paths.get(jar).toAbsolutePath();
        String url = "jdbc:h2:tcp://127.0.0.1:" + port + "/mem:authsuite;DB_CLOSE_DELAY=-1";

        Run ok = runCli(classpath, url, "--email", ALICE, ALICE_PW);
        check("cli: exit 0 for a correct credential", ok.exit == 0);
        check("cli: prints the success sentence", ok.stdout.contains("Authentication successful."));
        check("cli: does not re-ask for an address it was given",
                countOccurrences(ok.stdout, "Email address:") == 0);
        check("cli: asks for the password exactly once",
                countOccurrences(ok.stdout, "Password:") == 1);
        check("cli: does not echo the password back", !ok.stdout.contains(ALICE_PW)
                && !ok.stderr.contains(ALICE_PW));

        Run piped = runCliPiped(classpath, url, ALICE + "\n" + ALICE_PW + "\n");
        check("cli: two piped lines log in (email prompt does not eat the password line)",
                piped.exit == 0 && piped.stdout.contains("Authentication successful."));
        check("cli: exactly two prompts for two piped lines",
                countOccurrences(piped.stdout, "Email address:") == 1
                        && countOccurrences(piped.stdout, "Password:") == 1);

        Run badPw = runCli(classpath, url, "--email", ALICE, "Wrong-Admin-3");
        check("cli: exit 1 for a wrong password", badPw.exit == 1);
        check("cli: prints the credential refusal",
                badPw.stdout.contains("invalid email address or password"));
        check("cli: refusal does not say which half was wrong",
                !badPw.stdout.toLowerCase(Locale.ROOT).contains("not found"));

        Run leaked = runCli(classpath, url, "--email", ALICE, ALICE_PW);
        check("cli: never prints the stored digest",
                !leaked.stdout.contains("pbkdf2-sha256") && !leaked.stderr.contains("pbkdf2-sha256"));

        Run noJdbc = runCliRaw(classpath, new String[]{"--email", ALICE}, null);
        check("cli: refuses to run without --jdbc", noJdbc.exit == 2
                && noJdbc.stderr.contains("Usage:"));

        Run secretFlag = runCliRaw(classpath, new String[]{"--jdbc", url, "--password", "x"}, null);
        check("cli: refuses a --password flag (no secret on the command line)",
                secretFlag.exit == 2 && secretFlag.stderr.contains("Unknown argument"));

        Run deadDb = runCliRaw(classpath, new String[]{"--jdbc", "jdbc:h2:tcp://127.0.0.1:1/mem:nope",
                "--user", "sa", "--email", ALICE}, ALICE_PW + "\n");
        check("cli: exit 1 when the database is unreachable", deadDb.exit == 1);
        check("cli: says the service is unreachable", deadDb.stdout.contains("could not be reached"));
        check("cli: an outage does not print a stack trace",
                !deadDb.stderr.contains("at java.") && !deadDb.stdout.contains("at java."));
        check("cli: an outage is not reported as a credential problem",
                !deadDb.stdout.contains("invalid email address or password"));

        Path stdinFile = workDir.resolve("stdin.txt");
        Files.write(stdinFile, (ALICE + "\n" + ALICE_PW + "\n").getBytes(StandardCharsets.UTF_8));
        Run viaFile = runCliRaw(classpath,
                new String[]{"--jdbc", url, "--user", "sa", "--stdin-file", stdinFile.toString()}, null);
        check("cli: --stdin-file reads address and password in order",
                viaFile.exit == 0 && viaFile.stdout.contains("Authentication successful."));

        String fresh = "newcomer" + ProcessHandle.current().pid() + "@example.com";
        Run added = runCliRaw(classpath,
                new String[]{"--jdbc", url, "--user", "sa", "add-user", "--email", fresh},
                "Brand-New-9\n");
        check("cli: add-user reports success", added.exit == 0 && added.stdout.contains("Registered"));
        Run addedLogin = runCli(classpath, url, "--email", fresh, "Brand-New-9");
        check("cli: the account just added can log in", addedLogin.exit == 0);
        Run addedAgain = runCliRaw(classpath,
                new String[]{"--jdbc", url, "--user", "sa", "add-user", "--email", fresh},
                "Brand-New-9\n");
        check("cli: add-user refuses a duplicate address without a stack trace",
                addedAgain.exit == 1 && addedAgain.stdout.contains("Could not register")
                        && !addedAgain.stdout.contains("at java."));

        String prompted = "prompted" + ProcessHandle.current().pid() + "@example.com";
        Run promptedAdd = runCliRaw(classpath,
                new String[]{"--jdbc", url, "--user", "sa", "add-user"},
                prompted + "\nBrand-New-9\n");
        check("cli: add-user asks for the address when --email is absent",
                promptedAdd.exit == 0 && promptedAdd.stdout.contains("Registered")
                        && countOccurrences(promptedAdd.stdout, "Email address:") == 1
                        && !promptedAdd.stdout.contains("null"));
        check("cli: the address typed at that prompt really registered",
                runCli(classpath, url, "--email", prompted, "Brand-New-9").exit == 0);

        Run badAddress = runCliRaw(classpath,
                new String[]{"--jdbc", url, "--user", "sa", "--email", "x' OR '1'='1"}, ALICE_PW + "\n");
        check("cli: an injection-shaped address exits 1", badAddress.exit == 1);
        check("cli: an injection-shaped address is refused as input",
                badAddress.stdout.contains("Authentication unsuccessful"));

        // Invisible characters on the address must not fold it onto the real account. Only
        // characters a line reader can deliver inside a line are used (a line reader consumes
        // \r and \n as terminators), and they are written as raw bytes because a NUL cannot be
        // passed in an argument vector at all.
        int[] invisible = {0x00, 0x09, 0x1B, 0x1F};
        for (int codePoint : invisible) {
            for (boolean appended : new boolean[] {true, false}) {
                String marked = appended ? ALICE + (char) codePoint : (char) codePoint + ALICE;
                Run probe = runWithRawStdin(classpath, url,
                        (marked + "\n" + ALICE_PW + "\n").getBytes(StandardCharsets.UTF_8));
                String where = appended ? "trailing" : "leading";
                check("cli: address with " + where + " U+" + String.format("%02X", codePoint)
                        + " cannot log in as alice", probe.exit == 1);
                check("cli: address with " + where + " U+" + String.format("%02X", codePoint)
                        + " is refused, not accepted",
                        probe.stdout.contains("Authentication unsuccessful"));
            }
        }
    }

    /** Drives the real binary with byte-exact stdin; needed for NUL, which no shell can pass. */
    private static Run runWithRawStdin(String classpath, String url, byte[] stdinBytes)
            throws Exception {
        Path file = Files.createTempFile(workDir, "raw-stdin", ".bin");
        Files.write(file, stdinBytes);
        return runCliRaw(classpath,
                new String[]{"--jdbc", url, "--user", "sa", "--stdin-file", file.toString()}, null);
    }

    private static final class Run {
        int exit;
        String stdout = "";
        String stderr = "";
    }

    private static Run runCli(String classpath, String url, String emailFlag, String email,
                              String passwordLine) throws Exception {
        List<String> argv = new ArrayList<>(Arrays.asList(
                "java", "-cp", classpath, "AuthenticationService", "--jdbc", url, "--user", "sa",
                emailFlag, email));
        return execute(argv, passwordLine + "\n");
    }

    private static Run runCliPiped(String classpath, String url, String stdinText) throws Exception {
        return execute(new ArrayList<>(Arrays.asList(
                        "java", "-cp", classpath, "AuthenticationService", "--jdbc", url,
                        "--user", "sa")),
                stdinText);
    }

    private static Run runCliRaw(String classpath, String[] args, String stdinText) throws Exception {
        List<String> argv = new ArrayList<>(
                Arrays.asList("java", "-cp", classpath, "AuthenticationService"));
        argv.addAll(Arrays.asList(args));
        return execute(argv, stdinText);
    }

    private static Run execute(List<String> argv, String stdinText) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(argv);
        builder.environment().remove("DB_PASSWORD");
        Process child = builder.start();
        if (stdinText != null) {
            child.getOutputStream().write(stdinText.getBytes(StandardCharsets.UTF_8));
        }
        child.getOutputStream().close();

        Run run = new Run();
        StringBuilder out = new StringBuilder();
        StringBuilder err = new StringBuilder();
        Thread reader = new Thread(() -> {
            try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                    child.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    out.append(line).append('\n');
                }
            } catch (IOException ignored) {
                // Child died; whatever was read stands.
            }
        });
        reader.start();
        try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(
                child.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                err.append(line).append('\n');
            }
        }
        reader.join(30_000);
        run.exit = child.waitFor();
        run.stdout = out.toString();
        run.stderr = err.toString();
        return run;
    }

    private static int countOccurrences(String haystack, String needle) {
        int n = 0;
        int from = 0;
        while (true) {
            int at = haystack.indexOf(needle, from);
            if (at < 0) {
                return n;
            }
            n++;
            from = at + needle.length();
        }
    }

    // -------------------------------------------------------------------------------------
    // Database helpers
    // -------------------------------------------------------------------------------------

    private static AuthenticationService service() {
        return new AuthenticationService(() -> DriverManager.getConnection(jdbcUrl, "sa", ""));
    }

    /** Fixture helper: the service's own digest routine, with the checked exception folded away. */
    private static String digestOf(String password) {
        try {
            return AuthenticationService.Passwords.hash(password.toCharArray());
        } catch (java.security.GeneralSecurityException unavailable) {
            throw new IllegalStateException("PBKDF2 unavailable", unavailable);
        }
    }

    private static void applySchema(Connection c, Path schema) throws IOException, SQLException {
        String text = new String(Files.readAllBytes(schema), StandardCharsets.UTF_8);
        try (Statement s = c.createStatement()) {
            for (String statement : text.split(";")) {
                String trimmed = statement.replaceAll("--[^\n]*", "").trim();
                if (!trimmed.isEmpty()) {
                    s.execute(trimmed);
                }
            }
        }
    }

    private static void seedAccounts() throws SQLException {
        insert(ALICE, digestOf(ALICE_PW));
        insert(BOB, digestOf(BOB_PW));
    }

    private static void insert(String email, String hash) throws SQLException {
        try (Connection c = DriverManager.getConnection(jdbcUrl, "sa", "");
             PreparedStatement s = c.prepareStatement(
                     "INSERT INTO users (email, password_hash) VALUES (?, ?)")) {
            s.setString(1, email);
            s.setString(2, hash);
            s.executeUpdate();
        }
    }

    private static void insertRaw(String email, String hash) {
        try (Connection c = DriverManager.getConnection(jdbcUrl, "sa", "");
             PreparedStatement s = c.prepareStatement(
                     "INSERT INTO users (email, password_hash) VALUES (?, ?)")) {
            s.setString(1, email);
            s.setString(2, hash);
            s.executeUpdate();
        } catch (SQLException expected) {
            check("test fixture could be inserted: " + email, false);
        }
    }

    private static String storedHashOf(String email) {
        try (Connection c = DriverManager.getConnection(jdbcUrl, "sa", "");
             PreparedStatement s = c.prepareStatement(
                     "SELECT password_hash FROM users WHERE email = ?")) {
            s.setString(1, email);
            try (ResultSet rows = s.executeQuery()) {
                return rows.next() ? rows.getString(1) : null;
            }
        } catch (SQLException expected) {
            return null;
        }
    }

    private static int freePort() throws IOException {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static void startTcpServer(int port, String jar) throws Exception {
        // -ifNotExists lets this throwaway server create the in-memory database on first
        // connection; it listens on a random port for the length of one test run.
        ProcessBuilder builder = new ProcessBuilder("java", "-cp",
                Paths.get(jar).toAbsolutePath().toString(), "org.h2.tools.Server", "-tcp",
                "-tcpPort", String.valueOf(port), "-tcpAllowOthers", "-ifNotExists");
        builder.redirectErrorStream(true);
        Process server = builder.start();
        Runtime.getRuntime().addShutdownHook(new Thread(server::destroy));
        for (int attempt = 0; attempt < 100; attempt++) {
            if (canConnect(port)) {
                return;
            }
            Thread.sleep(100);
        }
        StringWriter detail = new StringWriter();
        new PrintWriter(detail).printf("H2 TCP server never listened on port %d%n", port);
        throw new IllegalStateException(detail.toString());
    }

    private static boolean canConnect(int port) {
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 200);
            return true;
        } catch (IOException refused) {
            return false;
        }
    }

    /**
     * The scratch directory holds the raw-byte stdin fixtures written for the child-process checks.
     * A hook is used rather than a call at the end of main so the directory also goes away when a
     * run dies part way through, which is exactly when it would otherwise pile up.
     */
    static void removeWorkDir() {
        Path dir = workDir;
        if (dir == null) {
            return;
        }
        try (Stream<Path> tree = Files.walk(dir)) {
            tree.sorted(Comparator.reverseOrder()).forEach(entry -> entry.toFile().delete());
        } catch (IOException stillThere) {
            System.out.println("NOTE scratch_dir_left_behind=" + dir);
        }
    }

    private static interface Body {
        void run();
    }

    private static long nanos(Body body) {
        long start = System.nanoTime();
        body.run();
        return System.nanoTime() - start;
    }

    private static long median(long[] samples) {
        long[] copy = samples.clone();
        Arrays.sort(copy);
        return copy[copy.length / 2];
    }

    private static void check(String what, boolean condition) {
        checks++;
        if (!condition) {
            failures.add(what);
        }
    }

    private static String describe(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < value.length() && b.length() < 34; i++) {
            char c = value.charAt(i);
            b.append(c < 0x20 || c == 0x7F ? "<" + (int) c + ">" : c);
        }
        if (value.length() > 34) {
            b.append("...");
        }
        return b.length() == 0 ? "empty" : b.toString();
    }
}
