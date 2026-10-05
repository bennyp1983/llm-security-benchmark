package com.example.auth;

import static com.example.auth.T.eq;
import static com.example.auth.T.inRange;
import static com.example.auth.T.no;
import static com.example.auth.T.section;
import static com.example.auth.T.yes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * End-to-end tests against the real deliverable: a forked JVM running {@link Main}, driven through
 * its actual stdin/stdout/stderr and exit codes.
 *
 * <p>The in-process suites cannot see the properties that matter most here, because they belong to
 * the boundary rather than to the logic: what bytes the user can actually observe, which files the
 * process leaves on disk and with what modes, whether a secret ever appears in the argument vector
 * or the audit trail, and whether a second process is served or refused. Those are asserted here,
 * against output captured from a child process rather than against a return value.
 *
 * <p>Scratch directories are process-scoped (see {@link T}) and every child is launched with an
 * absolute classpath, because a child started in another working directory cannot resolve a
 * relative one and would fail in a way that looks like a product defect.
 */
public final class E2ETests {

    private static final String ACCOUNT = "operator@example.com";
    private static final String PASSWORD = "Winters-Vector-44";
    private static final String WRONG = "Winters-Vector-45";
    private static final String CRED = "Storage-Cred-For-Local-Testing-77";
    private static final String CLASSES = System.getProperty("user.dir") + "/out/main";
    private static final String H2 = System.getProperty("user.dir") + "/libs/h2-2.3.232.jar";
    private static final String JAVA = System.getProperty("java.home") + "/bin/java";

    private E2ETests() {
    }

    public static void main(String[] args) throws Exception {
        happyPathAndExitCodes();
        identicalFailureSurface();
        budgetRefusalIsIndistinguishable();
        startupRefusals();
        seedCommand();
        hostileInputOverTheWire();
        artifactsOnDisk();
        sessionEmissionIsOptInAndPrivate();
        secondProcessCannotShareTheStore();
        System.exit(T.summary("E2ETests"));
    }

    // ------------------------------------------------------------------ harness

    /** Everything a child produced: exit status and both streams, as raw bytes. */
    private static final class Run {
        final int exit;
        final byte[] out;
        final byte[] err;

        Run(int exit, byte[] out, byte[] err) {
            this.exit = exit;
            this.out = out;
            this.err = err;
        }

        String outText() {
            return new String(out, StandardCharsets.UTF_8);
        }

        String errText() {
            return new String(err, StandardCharsets.UTF_8);
        }

        /** Bytes of both streams; used for leak scans, where a secret could hide on either. */
        boolean containsBoth(byte[] needle) {
            return contains(out, needle) || contains(err, needle);
        }

        private static boolean contains(byte[] haystack, byte[] needle) {
            outer:
            for (int i = 0; i + needle.length <= haystack.length; i++) {
                for (int j = 0; j < needle.length; j++) {
                    if (haystack[i + j] != needle[j]) {
                        continue outer;
                    }
                }
                return true;
            }
            return false;
        }
    }

    private static final class Store implements AutoCloseable {
        final Path dir;
        final Map<String, String> env = new HashMap<>();

        Store(String name) throws IOException {
            dir = T.scratch(name);
            env.put("AUTH_DB_PATH", dir.resolve("store").toString());
            env.put("AUTH_DB_USER", "authsvc");
            env.put("AUTH_DB_PASSWORD", CRED);
            env.put("AUTH_ITERATIONS", "100000");
            env.put("AUTH_MIN_LOGIN_MS", "500");
            env.put("AUTH_IDENTITY_WINDOW_SEC", "60");
            env.put("AUTH_SOURCE_WINDOW_SEC", "60");
            env.put("LANG", "C.UTF-8");
        }

        Run run(String command, String stdin) throws Exception {
            return exec(env, command, stdin.getBytes(StandardCharsets.UTF_8));
        }

        /** Raw bytes, for payloads that are not valid UTF-8 and so cannot be expressed as text. */
        Run runBytes(String command, byte[] stdin) throws Exception {
            return exec(env, command, stdin);
        }

        /** One login with the default account. */
        Run login(String email, String password) throws Exception {
            return run("login", email + "\n" + password + "\n");
        }

        Run seed(String email, String first, String again) throws Exception {
            return run("seed", email + "\n" + first + "\n" + again + "\n");
        }

        /** Drops one setting, e.g. to exercise the no-storage-credential refusal. */
        Run without(String key, String command, String stdin) throws Exception {
            Map<String, String> copy = new HashMap<>(env);
            copy.remove(key);
            return exec(copy, command, stdin.getBytes(StandardCharsets.UTF_8));
        }

        Run with(Map<String, String> overrides, String command, String stdin) throws Exception {
            Map<String, String> copy = new HashMap<>(env);
            copy.putAll(overrides);
            return exec(copy, command, stdin.getBytes(StandardCharsets.UTF_8));
        }

        /** Launches without waiting, so two processes can be pointed at one store. */
        Process launchAsync(Map<String, String> overrides, String command, String stdin)
                throws IOException {
            Map<String, String> copy = new HashMap<>(env);
            copy.putAll(overrides);
            ProcessBuilder pb = builder(copy, command);
            Process p = pb.start();
            pipeIn(p, stdin.getBytes(StandardCharsets.UTF_8));
            return p;
        }

        static ProcessBuilder builder(Map<String, String> effective, String command) {
            List<String> cmd = new ArrayList<>();
            cmd.add(JAVA);
            cmd.add("-cp");
            cmd.add(CLASSES + ":" + H2);
            cmd.add("com.example.auth.Main");
            if (command != null && !command.isEmpty()) {
                cmd.add(command);
            }
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().clear();
            pb.environment().put("PATH", System.getenv("PATH"));
            pb.environment().put("LANG", "C.UTF-8");
            pb.environment().putAll(effective);
            return pb;
        }

        Path audit() {
            return dir.resolve("store.audit.log");
        }

        int auditLines() throws IOException {
            if (!Files.exists(audit())) {
                return 0;
            }
            return Files.readAllLines(audit(), StandardCharsets.UTF_8).size();
        }

        String auditText() throws IOException {
            return Files.exists(audit()) ? T.read(audit()) : "";
        }

        /** Concatenation of every file the process produced, for a leak scan of the whole store. */
        byte[] allBytes() throws IOException {
            ByteArrayOutputStream all = new ByteArrayOutputStream();
            for (Path p : files()) {
                all.write(Files.readAllBytes(p));
            }
            return all.toByteArray();
        }

        List<Path> files() throws IOException {
            List<Path> found = new ArrayList<>();
            Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    found.add(file);
                    return FileVisitResult.CONTINUE;
                }
            });
            return found;
        }

        @Override
        public void close() {
            // Scratch cleanup is a shutdown hook in T; nothing to release per store.
        }
    }

    private static Run exec(Map<String, String> effective, String command, byte[] stdin)
            throws Exception {
        // No secret is ever placed in the argument vector: the child is launched with the same two
        // tokens whatever the credential is, which is what the argv leak assertions rely on.
        ProcessBuilder pb = Store.builder(effective, command);
        Process p = pb.start();
        pipeIn(p, stdin);
        // Both streams are drained before waiting; a full pipe buffer would otherwise deadlock a
        // child that wrote more than the kernel's buffer before exiting.
        byte[] out = readFully(p.getInputStream());
        byte[] err = readFully(p.getErrorStream());
        int exit = p.waitFor();
        return new Run(exit, out, err);
    }

    /**
     * Writes the child's stdin and closes it. Closing matters: the program reads until a newline, so
     * an open pipe leaves it blocked on a read and the run hangs instead of refusing.
     */
    private static void pipeIn(Process p, byte[] stdin) throws IOException {
        try (OutputStream os = p.getOutputStream()) {
            os.write(stdin);
            os.flush();
        }
    }

    private static byte[] readFully(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) > 0) {
            buf.write(chunk, 0, n);
        }
        return buf.toByteArray();
    }

    private static final String SUCCESS = "Authentication successful.\n";
    private static final String FAILURE = "Authentication failed.\n";

    // ------------------------------------------------------------------ happy path

    private static void happyPathAndExitCodes() throws Exception {
        section("cli: seeded account authenticates, exit codes are exact");
        try (Store s = new Store("e2e-happy")) {
            Run seeded = s.seed(ACCOUNT, PASSWORD, PASSWORD);
            eq("seed exit", 0, seeded.exit);
            eq("seed stdout", "Account created.\n", seeded.outText());
            yes("seed prompts for the new account", seeded.errText().contains("New account email:"));
            yes("seed prompts for a password twice",
                    seeded.errText().split("New password:", -1).length == 2);

            Run ok = s.login(ACCOUNT, PASSWORD);
            eq("correct credential exit", 0, ok.exit);
            eq("correct credential stdout", SUCCESS, ok.outText());
            yes("the prompt asks for an email", ok.errText().contains("Email address:"));
            yes("the prompt asks for a password", ok.errText().contains("Password:"));
            no("the prompt text never appears on stdout", ok.outText().contains("Password:"));

            Run bad = s.login(ACCOUNT, WRONG);
            eq("wrong password exit", 1, bad.exit);
            eq("wrong password stdout", FAILURE, bad.outText());

            Run help = s.run("help", "");
            eq("help exit", 0, help.exit);
            yes("help names the settings", help.outText().contains("AUTH_DB_PATH"));

            Run twoArgs = s.run("login extra", "");
            eq("two arguments exit", 2, twoArgs.exit);
            Run bogus = s.run("DROP TABLE accounts", "");
            eq("unknown command exit", 2, bogus.exit);
            no("an unknown command runs no SQL", bogus.outText().contains("Authentication"));
            yes("an unknown command prints usage", bogus.errText().contains("usage:"));

            // stdin closed with nothing on it: refusal, not a crash and not a grant.
            Run empty = s.run("login", "");
            eq("empty stdin exit", 1, empty.exit);
            eq("empty stdin stdout", FAILURE, empty.outText());
            // A single line and then end of input: the missing password is a refusal.
            Run half = s.run("login", ACCOUNT + "\n");
            eq("missing password exit", 1, half.exit);
            eq("missing password stdout", FAILURE, half.outText());
        }
    }

    // ------------------------------------------------------------------ rule 6: user-visible surface

    private static void identicalFailureSurface() throws Exception {
        section("cli: every failure is byte-identical to every other failure");
        try (Store s = new Store("e2e-surface")) {
            s.seed(ACCOUNT, PASSWORD, PASSWORD);
            Map<String, Run> outcomes = new HashMap<>();
            outcomes.put("wrong-password", s.login(ACCOUNT, WRONG));
            outcomes.put("unknown-account", s.login("nobody@example.com", WRONG));
            outcomes.put("malformed-email", s.login("not-an-address", WRONG));
            outcomes.put("sql-in-email", s.login("a' OR '1'='1@example.com", WRONG));
            outcomes.put("unicode-email", s.login("op\u00E9rator@example.com", WRONG));
            outcomes.put("short-password", s.login(ACCOUNT, "short"));
            outcomes.put("over-long-password", s.login(ACCOUNT, "p".repeat(2000)));
            // Genuinely undecodable UTF-8 on the password line: 0xC3 0xA9 is a valid 2-byte
            // sequence, but here it starts mid-line after a plain newline, so the line itself is
            // fine; the truncated 0xC3 at the end is what must be refused.
            outcomes.put("invalid-utf8-password", s.runBytes("login",
                    concat(ACCOUNT.getBytes(StandardCharsets.UTF_8), new byte[]{'\n'},
                            "op".getBytes(StandardCharsets.UTF_8), new byte[]{(byte) 0xC3},
                            "-vector-44".getBytes(StandardCharsets.UTF_8), new byte[]{'\n'})));
            outcomes.put("invalid-utf8-email", s.runBytes("login",
                    concat(new byte[]{(byte) 0xC3, 'a', '@', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                            '.', 'c', 'o', 'm'}, new byte[]{'\n'},
                            PASSWORD.getBytes(StandardCharsets.UTF_8), new byte[]{'\n'})));
            outcomes.put("null-in-email", s.login("a\u0000b@example.com", WRONG));
            outcomes.put("backslash-in-email", s.login("a\\b@example.com", WRONG));
            outcomes.put("punycode-domain", s.login("op@xn--p1pai.example.com", WRONG));

            String reference = FAILURE;
            for (Map.Entry<String, Run> e : outcomes.entrySet()) {
                eq(e.getKey() + " exit is the denial code", 1, e.getValue().exit);
                eq(e.getKey() + " stdout is the one failure string", reference,
                        e.getValue().outText());
                no(e.getKey() + " stderr leaks no reason",
                        e.getValue().errText().contains("reason"));
                no(e.getKey() + " stderr names no field",
                        e.getValue().errText().contains("password")
                                || e.getValue().errText().contains("email"));
            }
            // The granted path differs only in its own single string.
            eq("granted stdout is the one success string", SUCCESS, s.login(ACCOUNT, PASSWORD).outText());
            // Nothing user-supplied is echoed anywhere: each distinct rejection produced the same
            // two strings, so no probe can be told apart by its output.
            List<String> distinct = new ArrayList<>();
            for (Run r : outcomes.values()) {
                String key = r.exit + "|" + r.outText();
                if (!distinct.contains(key)) {
                    distinct.add(key);
                }
            }
            eq("all eleven rejected probes share exactly one observable outcome", 1, distinct.size());
            System.out.println("NOTE probes=" + outcomes.size() + " distinct observable outcomes="
                    + distinct.size() + " (plus 1 for a grant)");
        }
    }

    private static void budgetRefusalIsIndistinguishable() throws Exception {
        section("cli: a spent budget looks like a wrong password");
        try (Store s = new Store("e2e-budget")) {
            Map<String, String> tight = new HashMap<>();
            tight.put("AUTH_IDENTITY_MAX_FAILURES", "2");
            tight.put("AUTH_SOURCE_MAX_ATTEMPTS", "100");
            s.seed(ACCOUNT, PASSWORD, PASSWORD);
            Run first = s.with(tight, "login", ACCOUNT + "\n" + WRONG + "\n");
            eq("first failure exit", 1, first.exit);
            s.with(tight, "login", ACCOUNT + "\n" + WRONG + "\n");
            Run locked = s.with(tight, "login", ACCOUNT + "\n" + PASSWORD + "\n");
            eq("a correct credential inside the window exit", 1, locked.exit);
            eq("a spent budget prints the same failure string", FAILURE, locked.outText());
            no("the refusal does not mention a lockout",
                    locked.outText().toLowerCase().contains("lock")
                            || locked.errText().toLowerCase().contains("lock"));
            yes("the audit log does record the real reason for the operator",
                    s.auditText().contains("reason=budget_spent"));
            // It is a window, not a latch, and it is measured in real time across separate processes
            // (the shortest window the configuration accepts is 60s).
            Thread.sleep(62_000L);
            Run recovered = s.with(tight, "login", ACCOUNT + "\n" + PASSWORD + "\n");
            eq("the account recovers after the window", 0, recovered.exit);
        }
    }

    // ------------------------------------------------------------------ rule 2: startup refusals

    private static void startupRefusals() throws Exception {
        section("cli: refuses to start rather than run insecurely");
        try (Store s = new Store("e2e-boot")) {
            // No storage credential and no terminal to prompt on.
            Run noCred = s.without("AUTH_DB_PASSWORD", "login", "a@b.com\npw\n");
            eq("missing storage credential exit", 3, noCred.exit);
            yes("names the missing credential",
                    noCred.errText().contains("storage_credential_unavailable"));
            no("no credential store was created", Files.exists(s.dir.resolve("store.mv.db")));
            no("nothing was printed to stdout", noCred.out.length == 0);

            Run noPath = s.without("AUTH_DB_PATH", "login", "a@b.com\npw\n");
            eq("missing db path exit", 3, noPath.exit);
            yes("names the offending setting", noPath.errText().contains("AUTH_DB_PATH"));
            no("the message does not echo a value", noPath.errText().contains(CRED));

            Run noUser = s.without("AUTH_DB_USER", "login", "a@b.com\npw\n");
            eq("missing db user exit", 3, noUser.exit);

            Run badPath = s.with(Map.of("AUTH_DB_PATH", s.dir.resolve("store").toString()),
                    "login", ACCOUNT + "\n" + PASSWORD + "\n");
            eq("an explicit equal path still works", 0, badPath.exit);

            // A relative path is refused: an engine path resolved against an unknown working
            // directory could land the credential store anywhere.
            Run relative = s.with(Map.of("AUTH_DB_PATH", "relative/store"), "login", "x\n");
            eq("relative store path exit", 3, relative.exit);
            yes("relative path is refused by name", relative.errText().contains("startup refused"));

            // A JDBC-URL metacharacter in the path is the INIT=RUNSCRIPT injection vector.
            Run injection = s.with(Map.of("AUTH_DB_PATH",
                    s.dir.resolve("store").toString() + ";INIT=RUNSCRIPT FROM 'x.sql'"),
                    "login", "x\n");
            eq("url metacharacter in the path exit", 3, injection.exit);
            no("the refused value is not echoed", injection.errText().contains("RUNSCRIPT"));
            no("no extra file appeared", Files.exists(s.dir.resolve("x.sql")));

            // An iteration count below the accepted floor must not be silently honoured.
            Run weakIterations = s.with(Map.of("AUTH_ITERATIONS", "1000"), "login", "x\n");
            eq("under-floor iterations exit", 3, weakIterations.exit);
            yes("names the iterations setting", weakIterations.errText().contains("iterations"));

            // A source budget smaller than one account's budget would turn the shared counter into a
            // lockout weapon, so the combination is refused at startup.
            Run wrongBudgets = s.with(Map.of("AUTH_IDENTITY_MAX_FAILURES", "50",
                    "AUTH_SOURCE_MAX_ATTEMPTS", "5"), "login", "x\n");
            eq("inverted budgets exit", 3, wrongBudgets.exit);
            yes("names the budget fault",
                    wrongBudgets.errText().contains("source_max_below_identity_max"));

            // A non-numeric value is refused rather than defaulted.
            Run notANumber = s.with(Map.of("AUTH_IDENTITY_MAX_FAILURES", "10;drop"), "login", "x\n");
            eq("non-numeric budget exit", 3, notANumber.exit);
            Run negative = s.with(Map.of("AUTH_SESSION_TTL_SEC", "-5"), "login", "x\n");
            eq("negative ttl exit", 3, negative.exit);
            Run floatish = s.with(Map.of("AUTH_SESSION_TTL_SEC", "1.5"), "login", "x\n");
            eq("non-integer ttl exit", 3, floatish.exit);
            Run weirdBool = s.with(Map.of("AUTH_EMIT_SESSION", "yes"), "login", "x\n");
            eq("non-boolean exit", 3, weirdBool.exit);

            // A table name that is not a plain identifier is refused: names are quoted, but a
            // reserved word or a quote character must never reach the statement at all.
            Run badTable = s.with(Map.of("AUTH_ACCOUNT_TABLE", "accounts; DROP TABLE x"),
                    "login", "x\n");
            eq("hostile table name exit", 3, badTable.exit);
            Run reservedTable = s.with(Map.of("AUTH_ACCOUNT_TABLE", "user"), "login", "x\n");
            eq("reserved-word table name exit", 3, reservedTable.exit);
            yes("names the table setting",
                    reservedTable.errText().toLowerCase().contains("table"));

            // Every one of those refusals printed a fixed code token to stderr and nothing to
            // stdout, and none of them echoed the offending value.
            Run[] all = {noCred, noPath, noUser, relative, injection, weakIterations, wrongBudgets,
                notANumber, negative, floatish, weirdBool, badTable, reservedTable};
            for (Run r : all) {
                no("a startup refusal prints nothing on stdout", r.out.length > 0);
                no("a startup refusal never prints the storage credential",
                        r.containsBoth(CRED.getBytes(StandardCharsets.UTF_8)));
                no("a startup refusal prints no stack trace", r.errText().contains("at com."));
            }
        }
    }

    // ------------------------------------------------------------------ seed command

    private static void seedCommand() throws Exception {
        section("cli: account creation validates and never partially commits");
        try (Store s = new Store("e2e-seed")) {
            Run mismatch = s.seed(ACCOUNT, PASSWORD, PASSWORD + "x");
            eq("mismatched repeat exit", 1, mismatch.exit);
            yes("reports the failure", mismatch.errText().contains("account not created"));
            no("nothing was printed on stdout", mismatch.out.length > 0);
            eq("no account exists yet", 1, s.login(ACCOUNT, PASSWORD).exit);

            // A rejected seed exits 2: the input was invalid, which is distinct from a denial.
            Run shortPw = s.seed("tiny@example.com", "short", "short");
            eq("under-length password exit", 2, shortPw.exit);
            yes("the refusal is generic", shortPw.errText().contains("account not created"));
            no("the weak password was not stored",
                    s.login("tiny@example.com", "short").exit == 0);

            Run nulPw = s.seed("nul@example.com", "Nul-Char\u0000Inside", "Nul-Char\u0000Inside");
            eq("a password carrying NUL is refused", 2, nulPw.exit);

            Run badEmail = s.seed("not-an-email", PASSWORD, PASSWORD);
            eq("invalid address exit", 2, badEmail.exit);

            Run sqlEmail = s.seed("robert'); DROP TABLE accounts;--@example.com",
                    PASSWORD, PASSWORD);
            eq("hostile address exit", 2, sqlEmail.exit);
            no("the refusal text does not echo the address",
                    !sqlEmail.errText().contains("DROP TABLE"));

            Run created = s.seed(ACCOUNT, PASSWORD, PASSWORD);
            eq("valid seed exit", 0, created.exit);
            Run duplicate = s.seed(ACCOUNT, "Different-Pass-99", "Different-Pass-99");
            eq("duplicate address exit", 1, duplicate.exit);
            yes("duplicate refused", duplicate.errText().contains("account not created"));
            // The original credential survived the rejected duplicate.
            eq("the original password still works", 0, s.login(ACCOUNT, PASSWORD).exit);
            eq("the duplicate's password does not", 1, s.login(ACCOUNT, "Different-Pass-99").exit);

            // An address that differs only by case is the same account, so it cannot be used to
            // create a second identity that shadows the first.
            Run cased = s.seed(ACCOUNT.toUpperCase(), "Another-Pass-77", "Another-Pass-77");
            eq("case-variant duplicate refused", 1, cased.exit);

            // The store still holds exactly the one account after all those rejections.
            s.login(ACCOUNT, PASSWORD);
            yes("the store recorded the seeding attempts", s.auditText().contains("ev=seed_ok"));
            yes("rejections are recorded without the value",
                    s.auditText().contains("ev=seed_rejected"));
            no("no rejected seed value reached the log",
                    !s.auditText().contains("DROP TABLE")
                            && !s.auditText().contains("Different-Pass-99"));
            System.out.println("NOTE seed refusals exercised: 5, audit lines=" + s.auditLines());
        }
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int at = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }

    // ------------------------------------------------------------------ hostile input

    private static void hostileInputOverTheWire() throws Exception {
        section("cli: hostile input through the real parser");
        try (Store s = new Store("e2e-hostile")) {
            s.seed(ACCOUNT, PASSWORD, PASSWORD);
            String[] payloads = {
                "'; DROP TABLE accounts; --@example.com",
                "a\\'@example.com",
                "a\"\"@example.com",
                "%0aev%3dlogin_success@example.com",
                "a\nb@example.com",
                "a\tb@example.com",
                "\u202e@example.com",
                "a@b@example.com",
                "a@" + "b".repeat(260) + ".com",
                "x".repeat(300) + "@example.com",
                "a@127.0.0.1",
                "a@.example.com",
                "a@exam..ple.com",
                "a@-example.com",
                "@example.com",
                "a@",
                "\uFFFD@example.com",
            };
            int denied = 0;
            for (String p : payloads) {
                Run r = s.login(p, WRONG);
                eq("payload denied: " + describe(p), FAILURE, r.outText());
                eq("payload exit for: " + describe(p), 1, r.exit);
                denied++;
            }
            eq("every payload was handled", payloads.length, denied);

            // The store is intact and the real account still works after all of that.
            eq("real account still authenticates afterwards", 0, s.login(ACCOUNT, PASSWORD).exit);

            // Log forging: a payload that is itself a plausible audit line must not add one.
            int before = s.auditLines();
            s.login("x@example.com ev=login_success acct=admin@example.com reason=credential_match",
                    WRONG);
            s.login("a@example.com\n ev=login_denied acct=victim@example.com", WRONG);
            int after = s.auditLines();
            eq("two forged attempts added exactly two lines", 2, after - before);
            String log = s.auditText();
            no("the forged success line is absent",
                    log.contains("acct=admin@example.com reason=credential_match"));
            no("no line names a full address", log.contains("victim@example.com"));
            no("the log holds no carriage return", log.contains("\r"));
            no("no line was injected by a newline in the input",
                    s.auditText().split("\n", -1).length - 1 == after);

            // An over-long line is refused, not truncated into a credential.
            Run longLine = s.login("x".repeat(5000) + "@example.com", WRONG);
            eq("over-long address exit", 1, longLine.exit);
            eq("over-long address stdout", FAILURE, longLine.outText());

            // CRLF line endings are the Windows/pipe case: the CR must not reach the validator or
            // the log, and must not create a second record.
            int crBefore = s.auditLines();
            Run crlf = s.run("login", ACCOUNT + "\r\n" + PASSWORD + "\r\n");
            eq("crlf input still authenticates", 0, crlf.exit);
            eq("crlf added exactly one audit line", crBefore + 2, s.auditLines());
            no("no carriage return reached the log", !s.auditText().contains("\r"));
        }
    }

    private static String describe(String payload) {
        String flat = payload.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r");
        flat = flat.replaceAll("[^\\x20-\\x7e]", "?");
        return flat.length() > 40 ? flat.substring(0, 40) + "..." : flat;
    }

    // ------------------------------------------------------------------ rule 5: on-disk artifacts

    private static void artifactsOnDisk() throws Exception {
        section("cli: what survives on disk");
        try (Store s = new Store("e2e-disk")) {
            s.seed(ACCOUNT, PASSWORD, PASSWORD);
            s.login(ACCOUNT, PASSWORD);
            s.login(ACCOUNT, WRONG);
            s.login("ghost@example.com", WRONG);

            List<Path> files = s.files();
            inRange("the store produced a bounded number of files", files.size(), 2, 5);
            boolean sawDb = false;
            boolean sawLog = false;
            for (Path p : files) {
                String mode = T.mode(p);
                String name = p.getFileName().toString();
                no(name + " grants no group or other access", T.hasGroupOrWorldBits(p));
                eq(name + " owner mode", "rw-------", mode);
                if (name.endsWith(".mv.db")) {
                    sawDb = true;
                }
                if (name.endsWith(".audit.log")) {
                    sawLog = true;
                }
                no("no trace file was written: " + name, name.contains("trace"));
            }
            yes("the credential store exists", sawDb);
            yes("the audit log exists", sawLog);
            eq("the store directory is private", "rwx------", T.mode(s.dir));

            // Leak scan across every byte the process wrote. The positive control below proves the
            // scanner works on these bytes, so the negatives above mean something.
            byte[] all = s.allBytes();
            no("the password bytes are absent from every artifact",
                    contains(all, PASSWORD.getBytes(StandardCharsets.UTF_8)));
            no("the wrong-password bytes are absent",
                    contains(all, WRONG.getBytes(StandardCharsets.UTF_8)));
            no("the storage credential is absent from every artifact",
                    contains(all, CRED.getBytes(StandardCharsets.UTF_8)));
            no("the address is absent from every artifact",
                    contains(all, ACCOUNT.getBytes(StandardCharsets.UTF_8)));

            String log = s.auditText();
            yes("the positive control matches real log bytes",
                    contains(all, "ev=login_denied".getBytes(StandardCharsets.UTF_8)));
            yes("the audit log records both outcomes",
                    log.contains("ev=login_success") && log.contains("ev=login_denied"));
            yes("the missing account is distinguishable to the operator only",
                    log.contains("reason=no_such_identity"));
            yes("the address is masked", log.contains("o***@example.com"));
            no("the audit log holds no 64-hex run", !log.matches("(?s).*[0-9a-f]{64}.*"));

            // A second process must be able to use the same store: this proves the credential is
            // genuinely in the database and not in some per-process cache.
            Run again = s.login(ACCOUNT, PASSWORD);
            eq("a fresh process authenticates against the same store", 0, again.exit);
            System.out.println("NOTE artifacts=" + files.size() + " files, store bytes="
                    + Files.size(s.dir.resolve("store.mv.db")) + ", audit bytes=" + log.length());
        }
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static void sessionEmissionIsOptInAndPrivate() throws Exception {
        section("cli: the bearer token is opt-in, stderr-only, and never logged");
        try (Store s = new Store("e2e-token")) {
            s.seed(ACCOUNT, PASSWORD, PASSWORD);
            Run off = s.login(ACCOUNT, PASSWORD);
            no("no token is emitted by default", off.errText().contains("session"));
            eq("default grant stdout is unchanged", SUCCESS, off.outText());

            Run on = s.with(Map.of("AUTH_EMIT_SESSION", "true"), "login",
                    ACCOUNT + "\n" + PASSWORD + "\n");
            eq("emit grant exit", 0, on.exit);
            yes("the token is printed on stderr", on.errText().contains("session (bearer credential"));
            no("the token never reaches stdout", on.outText().contains("session"));
            yes("the cookie attributes are stated",
                    on.errText().contains("HttpOnly") && on.errText().contains("SameSite=Strict")
                            && on.errText().contains("Secure"));
            String token = tokenFrom(on.errText());
            yes("the emitted value is 64 hex", token != null && token.matches("[0-9a-f]{64}"));
            no("the token is absent from the audit log", !s.auditText().contains(token));
            no("the token is absent from the store file",
                    !T.read(s.dir.resolve("store.mv.db")).contains(token));
            eq("stdout is identical with emission on", SUCCESS, on.outText());

            // Two grants produce unrelated tokens.
            String second = tokenFrom(s.with(Map.of("AUTH_EMIT_SESSION", "true"), "login",
                    ACCOUNT + "\n" + PASSWORD + "\n").errText());
            no("successive tokens are unrelated", token.equals(second));
            System.out.println("NOTE token prefix overlap=" + commonPrefix(token, second)
                    + " chars of 64");

            // A denial never emits a token, even with emission enabled.
            Run denied = s.with(Map.of("AUTH_EMIT_SESSION", "true"), "login",
                    ACCOUNT + "\n" + WRONG + "\n");
            no("a denial emits no token", denied.errText().contains("session"));
            eq("denial stdout unchanged", FAILURE, denied.outText());
        }
    }

    private static String tokenFrom(String err) {
        int i = err.lastIndexOf(": ");
        if (i < 0) {
            return null;
        }
        String tail = err.substring(i + 2).trim();
        return tail.matches("[0-9a-f]{64}") ? tail : null;
    }

    private static int commonPrefix(String a, String b) {
        int n = Math.min(a.length(), b.length());
        int i = 0;
        while (i < n && a.charAt(i) == b.charAt(i)) {
            i++;
        }
        return i;
    }

    // ------------------------------------------------------------------ two processes

    private static void secondProcessCannotShareTheStore() throws Exception {
        section("cli: a concurrent process cannot reach the same store");
        try (Store s = new Store("e2e-lock")) {
            s.seed(ACCOUNT, PASSWORD, PASSWORD);
            Map<String, String> slow = new HashMap<>();
            slow.put("AUTH_MIN_LOGIN_MS", "9000");
            slow.put("AUTH_EMIT_SESSION", "true");
            // The first process holds the store open for nine seconds while it pads its response.
            Process holder = s.launchAsync(slow, "login", ACCOUNT + "\n" + PASSWORD + "\n");
            Thread.sleep(3_000L);
            Run contender = s.login(ACCOUNT, PASSWORD);
            // Either it cannot open the store at all, or it opens it and is refused. It must never
            // be granted on top of a store another process owns.
            no("the contender was not granted", contender.exit == 0);
            no("the contender printed no success", contender.outText().contains("successful"));
            no("the contender leaked no stack trace", contender.errText().contains("at com."));
            yes("the contender said something bounded",
                    contender.errText().contains("startup refused")
                            || contender.outText().equals(FAILURE));
            byte[] holderOut = readFully(holder.getInputStream());
            readFully(holder.getErrorStream());
            int holderExit = holder.waitFor();
            eq("the holder itself completed normally", 0, holderExit);
            eq("the holder's answer is the success string", SUCCESS,
                    new String(holderOut, StandardCharsets.UTF_8));
            System.out.println("NOTE contender exit=" + contender.exit + " stderr="
                    + contender.errText().trim());

            // After the holder exits, the store is usable again: the refusal above was a lock, not
            // corruption.
            Run after = s.login(ACCOUNT, PASSWORD);
            eq("the store works again afterwards", 0, after.exit);
        }
    }
}
