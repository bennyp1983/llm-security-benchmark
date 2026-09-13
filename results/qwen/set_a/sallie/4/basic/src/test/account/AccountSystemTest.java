package account;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.function.Supplier;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Self-checking harness for the account program. Run with
 * {@code java -cp out:out-test account.AccountSystemTest}; prints one line per
 * check and exits non-zero if any check fails.
 */
public final class AccountSystemTest {

    private static final List<String> FAILURES = new ArrayList<>();
    private static final String ABSOLUTE_CLASS_PATH = absoluteClassPath();
    private static int checks;
    private static Path workDir;
    private static Run lastRun;

    public static void main(String[] args) throws Exception {
        workDir = Files.createTempDirectory("account-test");
        long startedAt = System.nanoTime();

        registrationAndLogin();
        persistenceAcrossRestart();
        duplicateHandling();
        storedFormHasNoPlainText();
        distinctSaltsPerAccount();
        usernameRules();
        identityFoldingRefused();
        passwordRules();
        passwordCollisionGuard();
        corruptStoreFailsClosed();
        unreadableEncodingIsRejected();
        weakStoredCostIsRejected();
        timingDoesNotLeakExistence();
        concurrentProcesses();
        commandLineEndToEnd();

        long millis = (System.nanoTime() - startedAt) / 1_000_000L;
        System.out.println();
        System.out.println(checks + " checks, " + FAILURES.size() + " failure(s), " + millis + " ms");
        for (String failure : FAILURES) {
            System.out.println("FAILED: " + failure);
        }
        if (!FAILURES.isEmpty() && lastRun != null) {
            // Last child transcript, so a CLI failure can be diagnosed without rerunning.
            System.out.println("--- last CLI run: exit=" + lastRun.exit()
                    + "\nstdout> " + lastRun.out().replace("\n", "\nstdout> ")
                    + "stderr> " + lastRun.err().replace("\n", "\nstderr> "));
        }
        System.exit(FAILURES.isEmpty() ? 0 : 1);
    }

    // ---------------------------------------------------------------- happy path

    private static void registrationAndLogin() {
        Path file = store("basic.txt");
        try (AccountService service = new AccountService(file)) {
            check(service.register("alice", pw("correct horse battery")) == AccountService.Result.REGISTERED,
                    "register accepts a valid username and password");
            check(service.accountCount() == 1, "registration adds exactly one account");
            check(service.authenticate("alice", pw("correct horse battery"))
                            == AccountService.Result.AUTHENTICATED,
                    "the registered password authenticates");
            check(service.authenticate("alice", pw("correct horse batterx"))
                            == AccountService.Result.INVALID_CREDENTIALS,
                    "a wrong password is refused");
            check(service.authenticate("nobody", pw("correct horse battery"))
                            == AccountService.Result.UNKNOWN_USER,
                    "an unknown username is reported as unknown");
        }
    }

    private static void persistenceAcrossRestart() {
        Path file = store("restart.txt");
        try (AccountService service = new AccountService(file)) {
            service.register("bob", pw("second factor phrase"));
        }
        // A brand new process must see the account written by the previous one.
        try (AccountService reopened = new AccountService(file)) {
            check(reopened.accountCount() == 1, "the account survives reopening the store");
            check(reopened.authenticate("bob", pw("second factor phrase"))
                            == AccountService.Result.AUTHENTICATED,
                    "the stored credentials authenticate in a new process");
            check(reopened.authenticate("bob", pw("second factor phrasx"))
                            == AccountService.Result.INVALID_CREDENTIALS,
                    "the reopened store still refuses a wrong password");
        }
    }

    private static void duplicateHandling() {
        Path file = store("duplicate.txt");
        try (AccountService service = new AccountService(file)) {
            service.register("carol", pw("first chosen secret"));
            AccountService.Result again = service.register("carol", pw("another secret 123"));
            check(again == AccountService.Result.USERNAME_TAKEN, "a second registration is refused");
            check(service.accountCount() == 1, "the refused registration did not add an account");
            check(service.authenticate("carol", pw("first chosen secret"))
                            == AccountService.Result.AUTHENTICATED,
                    "the refused registration did not overwrite the original password");
            check(service.authenticate("carol", pw("another secret 123"))
                            == AccountService.Result.INVALID_CREDENTIALS,
                    "the rejected second password cannot log in");
        }
    }

    private static void storedFormHasNoPlainText() throws Exception {
        Path file = store("shape.txt");
        try (AccountService service = new AccountService(file)) {
            service.register("dave", pw("topsecretphrase9999"));
        }
        String raw = Files.readString(file, StandardCharsets.UTF_8);
        check(!raw.contains("topsecretphrase9999"), "the store never contains the password text");
        check(raw.contains("dave"), "the store does contain the username");
        String[] record = recordFor(raw, "dave");
        check("pbkdf2-sha256".equals(record[0]), "the record names the hash algorithm");
        check(Integer.parseInt(record[1]) >= 100_000, "the recorded iteration count is at least 100000");
        check(Base64.getDecoder().decode(record[2]).length == 16, "the stored salt is 16 bytes");
        check(Base64.getDecoder().decode(record[3]).length == 32, "the stored hash is 32 bytes");
    }

    private static void distinctSaltsPerAccount() throws Exception {
        Path file = store("salts.txt");
        try (AccountService service = new AccountService(file)) {
            service.register("erin", pw("the very same secret"));
            service.register("fred", pw("the very same secret"));
        }
        String raw = Files.readString(file, StandardCharsets.UTF_8);
        check(!recordFor(raw, "erin")[2].equals(recordFor(raw, "fred")[2]),
                "two accounts with the same password get different salts");
        check(!recordFor(raw, "erin")[3].equals(recordFor(raw, "fred")[3]),
                "the same password hashes to different digests for different accounts");
    }

    // ------------------------------------------------------------------- validation

    private static void usernameRules() {
        List<String> rejected = List.of(
                "",
                "   ",
                "ab",                                     // too short
                "x".repeat(33),                           // too long
                "alice bob",                              // inner space
                "ali" + (char) 0x09 + "ce",               // tab inside
                "alice" + (char) 0x00,                    // trailing NUL
                "alice" + (char) 0x0A,                    // trailing newline
                (char) 0x00 + "alice",                    // leading NUL
                "alice@corp",                             // outside the alphabet
                "ali(ce)",
                "\u00e9lodie",                            // accented letters
                "\u7528\u6237\u540d");                    // non-latin script
        for (String username : rejected) {
            refused(() -> AccountService.normalizeUsername(username),
                    () -> "username rejected: " + describe(username), IllegalArgumentException.class);
        }
        List<String> accepted = List.of("abc", "alice", "Alice_9", "a.b-c_1", "x".repeat(32));
        for (String username : accepted) {
            try {
                check(username.equals(AccountService.normalizeUsername(username)),
                        "username accepted unchanged: " + username);
            } catch (IllegalArgumentException e) {
                fail("username accepted unchanged: " + username + " (threw " + e.getMessage() + ")");
            }
        }
        check("alice".equals(AccountService.normalizeUsername("  alice  ")),
                "surrounding spaces are trimmed off a username");
    }

    private static void identityFoldingRefused() {
        Path file = store("folding.txt");
        try (AccountService service = new AccountService(file)) {
            service.register("alice", pw("chosen passphrase 1"));
            // An invisible trailing character must not resolve to the real alice.
            refused(() -> service.authenticate("alice" + (char) 0x00, pw("chosen passphrase 1")),
                    () -> "trailing NUL username cannot log in as alice", IllegalArgumentException.class);
            refused(() -> service.authenticate("alice" + (char) 0x09, pw("chosen passphrase 1")),
                    () -> "trailing tab username cannot log in as alice", IllegalArgumentException.class);
            refused(() -> service.authenticate((char) 0x00 + "alice", pw("chosen passphrase 1")),
                    () -> "leading NUL username cannot log in as alice", IllegalArgumentException.class);
            refused(() -> service.register("alice" + (char) 0x00, pw("chosen passphrase 2")),
                    () -> "trailing NUL username cannot be registered", IllegalArgumentException.class);
            // Legitimate surrounding spaces still work, and land on the same account.
            check(service.authenticate("  alice  ", pw("chosen passphrase 1"))
                            == AccountService.Result.AUTHENTICATED,
                    "a username typed with surrounding spaces still logs in");
        }
    }

    private static void passwordRules() {
        List<String> rejected = List.of(
                "",
                "x".repeat(9),                            // below the minimum
                "x".repeat(257),                          // above the maximum
                "secret1234" + (char) 0x00,               // trailing NUL
                "q" + (char) 0xD800 + "rest1234",         // unpaired high surrogate
                "q" + (char) 0xDC00 + "rest1234",         // unpaired low surrogate
                "p" + (char) 0xD83D + "assword12345");    // high surrogate mid-string
        for (String password : rejected) {
            refused(() -> PasswordHasher.validatePassword(password.toCharArray()),
                    () -> "password rejected: " + describe(password), IllegalArgumentException.class);
        }
        List<String> accepted = List.of(
                "0123456789",                             // exactly the minimum
                "x".repeat(256),                          // exactly the maximum
                "p" + (char) 0x00 + "ssword1234",         // interior NUL is fine
                "secret1234" + (char) 0x20,               // trailing space is fine
                "emo" + (char) 0xD83D + (char) 0xDE00 + "tail12345"); // astral pair is fine
        for (String password : accepted) {
            accepted(password, "password accepted: " + describe(password));
        }
        Path file = store("passwords.txt");
        try (AccountService service = new AccountService(file)) {
            String exotic = "emo" + (char) 0xD83D + (char) 0xDE00 + "tail12345";
            // A valid password has to register without throwing just because it holds a
            // surrogate pair, so a throw here is reported as a failed check.
            check("REGISTERED".equals(outcome(() -> service.register("gina", pw(exotic)).name())),
                    "a surrogate-pair password can be registered");
            check("AUTHENTICATED".equals(outcome(() -> service.authenticate("gina", pw(exotic)).name())),
                    "an account with a surrogate-pair password can log in");
            check("INVALID_CREDENTIALS".equals(outcome(() -> service.authenticate(
                            "gina", pw("emo" + (char) 0xD83D + (char) 0xDE01 + "tail12345")).name())),
                    "a different astral character is not accepted for that account");
        }
    }

    /**
     * PBEKeySpec is not injective over char[]: trailing NULs are dropped and every
     * unpaired surrogate becomes '?'. The collisions are reproduced here through the
     * raw JCE so the guard above is pinned to a measured defect, not an assumption.
     */
    private static void passwordCollisionGuard() throws Exception {
        byte[] salt = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        String[] nulGroup = {"cafe123456", "cafe123456" + (char) 0x00, "cafe123456" + (char) 0x00 + (char) 0x00};
        check(rawDerive(nulGroup[0], salt).equals(rawDerive(nulGroup[1], salt))
                        && rawDerive(nulGroup[1], salt).equals(rawDerive(nulGroup[2], salt)),
                "raw JCE really collapses trailing-NUL passwords");
        String[] surrogateGroup = {"q" + (char) 0xD800 + "rest1234", "q" + (char) 0xD801 + "rest1234",
                "q?rest1234"};
        check(rawDerive(surrogateGroup[0], salt).equals(rawDerive(surrogateGroup[1], salt))
                        && rawDerive(surrogateGroup[1], salt).equals(rawDerive(surrogateGroup[2], salt)),
                "raw JCE really collapses unpaired-surrogate passwords");
        check(!rawDerive("p" + (char) 0x00 + "ssword1234", salt).equals(rawDerive("pssword1234", salt)),
                "an interior NUL really does give a different digest, so it stays allowed");
        for (String password : Arrays.copyOfRange(nulGroup, 1, 3)) {
            refused(() -> PasswordHasher.validatePassword(password.toCharArray()),
                    () -> "colliding trailing-NUL password refused: " + describe(password),
                    IllegalArgumentException.class);
        }
        for (String password : Arrays.copyOf(surrogateGroup, 2)) {
            refused(() -> PasswordHasher.validatePassword(password.toCharArray()),
                    () -> "colliding unpaired-surrogate password refused: " + describe(password),
                    IllegalArgumentException.class);
        }
    }

    // ---------------------------------------------------------------------- store

    private static void corruptStoreFailsClosed() throws Exception {
        List<String> corrupt = List.of(
                "no header and no separators\n",
                "# account-store v1\nnot-v1|alice|whatever|1700000000\n",
                "# account-store v1\nv1|alice|pbkdf2-sha256$210000$abc$def\nextra\n",
                "# account-store v1\nv1|alice|pbkdf2-sha256$210000$abc$def|not-a-number\n",
                "# account-store v1\nv1|alice|pbkdf2-sha256$210000$abc$def|1700000000\n"
                        + "v1|alice|pbkdf2-sha256$210000$xyz$ghi|1700000001\n");
        for (int i = 0; i < corrupt.size(); i++) {
            Path file = store("corrupt" + i + ".txt");
            Files.writeString(file, corrupt.get(i), StandardCharsets.UTF_8);
            int index = i;
            refused(() -> {
                AccountService opened = new AccountService(file);
                opened.close();
                // Opening a corrupt store at all is the failure under test.
            }, () -> "corrupt store variant " + index + " is refused", IllegalStateException.class);
        }
    }

    private static void unreadableEncodingIsRejected() throws Exception {
        Path file = store("junk-encoding.txt");
        // A record whose digest is not valid Base64 must fail closed at login time
        // rather than throw and leak which half of the pair was wrong.
        Files.writeString(file, "# account-store v1\nv1|hank|pbkdf2-sha256$210000$!!!!$####|1700000000\n",
                StandardCharsets.UTF_8);
        try (AccountService service = new AccountService(file)) {
            check(service.accountCount() == 1, "a record with a junk digest still loads");
            check(service.authenticate("hank", pw("some password 123"))
                            == AccountService.Result.INVALID_CREDENTIALS,
                    "a junk digest refuses every password instead of throwing");
        }
    }

    private static void weakStoredCostIsRejected() throws Exception {
        byte[] salt = "fedcba9876543210".getBytes(StandardCharsets.US_ASCII);
        String password = "cheap cost password";
        String weak = "pbkdf2-sha256$1$" + Base64.getEncoder().encodeToString(salt) + "$"
                + Base64.getEncoder().encodeToString(rawDeriveBytes(password, salt, 1));
        Path file = store("weak-cost.txt");
        Files.writeString(file, "# account-store v1\nv1|ivan|" + weak + "|1700000000\n", StandardCharsets.UTF_8);
        try (AccountService service = new AccountService(file)) {
            check(service.authenticate("ivan", pw(password)) == AccountService.Result.INVALID_CREDENTIALS,
                    "a tampered one-iteration record is refused even with the right password");
        }
    }

    // ----------------------------------------------------------------------- timing

    private static void timingDoesNotLeakExistence() {
        Path file = store("timing.txt");
        try (AccountService service = new AccountService(file)) {
            service.register("timed", pw("measured passphrase"));
            long known = fastestNanos(3, () -> service.authenticate("timed", pw("wrong passphrase x")));
            long unknown = fastestNanos(3, () -> service.authenticate("ghostuser", pw("wrong passphrase x")));
            double ratio = (double) unknown / (double) known;
            System.out.println("  timing: known=" + (known / 1_000_000L) + " ms unknown="
                    + (unknown / 1_000_000L) + " ms ratio=" + Math.round(ratio * 100) / 100.0);
            check(ratio >= 0.4 && ratio <= 2.5,
                    "an unknown username costs about the same work as a known one (ratio "
                            + Math.round(ratio * 100) / 100.0 + ")");
        }
    }

    // ------------------------------------------------------------------ concurrency

    private static void concurrentProcesses() throws Exception {
        Path file = store("concurrent.txt");
        int processes = 6;
        List<Process> running = new ArrayList<>();
        for (int i = 0; i < processes; i++) {
            // register asks for the password twice, so two lines per child.
            running.add(launch(file, List.of("register", "racer" + i),
                    List.of("race passphrase " + i, "race passphrase " + i)));
        }
        List<String> transcripts = new ArrayList<>();
        int succeeded = 0;
        for (Process process : running) {
            int exit = process.waitFor();
            String out = readFully(process.getInputStream());
            String err = readFully(process.getErrorStream());
            transcripts.add("exit=" + exit + " stdout[" + out.trim() + "] stderr[" + err.trim() + "]");
            if (exit == 0) {
                succeeded++;
            }
        }
        if (succeeded != processes) {
            for (String transcript : transcripts) {
                System.out.println("  child " + transcript);
            }
        }
        check(succeeded == processes, "all " + processes + " concurrent registrations succeeded");
        try (AccountService service = new AccountService(file)) {
            check(service.accountCount() == processes,
                    "no concurrent registration was lost (found " + service.accountCount() + ")");
            boolean allLogIn = true;
            for (int i = 0; i < processes; i++) {
                allLogIn &= service.authenticate("racer" + i, pw("race passphrase " + i))
                        == AccountService.Result.AUTHENTICATED;
            }
            check(allLogIn, "every concurrently registered account can authenticate");
        }
    }

    // ---------------------------------------------------------------- command line

    private static void commandLineEndToEnd() throws Exception {
        Path file = store("cli.txt");
        Run registered = run(file, List.of("register", "clerk"), "clerk passphrase 1", "clerk passphrase 1");
        check(registered.exit() == 0, "CLI register succeeds");
        check(registered.out().contains("Registered"), "CLI register reports success");
        // The piped path has no Console, so the program must warn that input echoes.
        check(registered.err().contains("echoed"), "CLI warns when the password will echo");

        Run good = run(file, List.of("login", "clerk"), "clerk passphrase 1");
        check(good.exit() == 0 && good.out().contains("Login OK"), "CLI login succeeds");

        Run bad = run(file, List.of("login", "clerk"), "clerk passphrase 2");
        check(bad.exit() == 1 && bad.err().contains("invalid username or password"),
                "CLI login reports one generic failure message");

        Run ghost = run(file, List.of("login", "nobodyhere"), "clerk passphrase 1");
        check(ghost.exit() == 1 && ghost.err().equals(bad.err()),
                "an unknown username gets the same CLI message as a wrong password");

        Run clash = run(file, List.of("register", "clerk"), "another passphrase", "another passphrase");
        check(clash.exit() == 1 && clash.err().contains("already registered"),
                "CLI register refuses a taken username");

        Run mismatch = run(file, List.of("register", "typo"), "phrase number one", "phrase number two");
        check(mismatch.exit() == 1 && mismatch.err().contains("do not match"),
                "CLI register refuses mismatched confirmation");

        Run weak = run(file, List.of("register", "weakling"), "short", "short");
        check(weak.exit() == 2 && weak.err().contains("at least"),
                "CLI register explains a too-short password");

        Run verified = run(file, List.of("verify", "clerk", "clerk passphrase 1"));
        check(verified.exit() == 0 && verified.out().trim().equals("OK"), "CLI verify prints OK");

        Run rejected = run(file, List.of("verify", "clerk", "clerk passphrase 9"));
        check(rejected.exit() == 1 && rejected.out().trim().equals("FAIL"), "CLI verify prints FAIL");

        Run listed = run(file, List.of("list"));
        check(listed.exit() == 0 && listed.out().contains("1 account(s)"),
                "CLI list counts the stored account");

        Run unknownCommand = run(file, List.of("frobnicate"));
        check(unknownCommand.exit() == 2 && unknownCommand.err().contains("unknown command"),
                "CLI rejects an unknown command");

        Run missingStoreArg = run(file, List.of("--store"));
        check(missingStoreArg.exit() == 2 && missingStoreArg.err().contains("needs a file path"),
                "CLI reports a --store with no value");

        Run extraOperand = run(file, List.of("register", "clerk", "surprise"), "a", "a");
        check(extraOperand.exit() == 2 && extraOperand.err().contains("at most a username"),
                "CLI register refuses a password given as an argument");

        Run help = run(file, List.of("help"));
        check(help.exit() == 0 && help.out().contains("Usage:"), "CLI help prints usage");
    }

    // --------------------------------------------------------------------- plumbing

    private record Run(int exit, String out, String err) {
    }

    private static Run run(Path storeFile, List<String> args, String... stdinLines) throws Exception {
        Process process = launch(storeFile, args, Arrays.asList(stdinLines));
        String out = readFully(process.getInputStream());
        String err = readFully(process.getErrorStream());
        lastRun = new Run(process.waitFor(), out, err);
        return lastRun;
    }

    /** Starts the CLI with stdin fully written and closed, so every prompt is answered. */
    private static Process launch(Path storeFile, List<String> args, List<String> stdinLines) throws IOException {
        List<String> command = new ArrayList<>(List.of(
                System.getProperty("java.home") + "/bin/java",
                "-cp", ABSOLUTE_CLASS_PATH,
                "-Daccount.store=" + storeFile.toAbsolutePath(),
                "account.Main"));
        command.addAll(args);
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(workDir.toFile());
        Process process = builder.start();
        try (var stdin = process.getOutputStream()) {
            for (String line : stdinLines) {
                stdin.write((line + "\n").getBytes(StandardCharsets.UTF_8));
            }
            stdin.flush();
        }
        return process;
    }

    /**
     * The children run with the temporary directory as their working directory, so the
     * inherited classpath has to be made absolute or no class is found.
     */
    private static String absoluteClassPath() {
        Path base = Paths.get(System.getProperty("user.dir"));
        List<String> entries = new ArrayList<>();
        for (String entry : System.getProperty("java.class.path").split(
                java.io.File.pathSeparator, -1)) {
            if (!entry.isEmpty()) {
                entries.add(base.resolve(entry).toAbsolutePath().toString());
            }
        }
        return String.join(java.io.File.pathSeparator, entries);
    }

    private static String readFully(InputStream stream) throws IOException {
        return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
    }

    private static Path store(String name) {
        return workDir.resolve(name);
    }

    private static char[] pw(String value) {
        return value.toCharArray();
    }

    /** Returns the algorithm, iterations, salt and digest fields of one stored record. */
    private static String[] recordFor(String rawStore, String username) {
        for (String line : rawStore.split("\n")) {
            if (line.startsWith("v1" + User.FIELD_SEPARATOR + username + User.FIELD_SEPARATOR)) {
                String[] parts = line.split("\\" + User.FIELD_SEPARATOR, -1);
                if (parts.length == 4) {
                    return parts[2].split("\\$", -1);
                }
            }
        }
        throw new AssertionError("no stored record for " + username);
    }

    private static long fastestNanos(int rounds, Runnable body) {
        long best = Long.MAX_VALUE;
        for (int i = 0; i < rounds; i++) {
            long start = System.nanoTime();
            body.run();
            best = Math.min(best, System.nanoTime() - start);
        }
        return best;
    }

    private static String rawDerive(String password, byte[] salt) throws Exception {
        return Base64.getEncoder().encodeToString(rawDeriveBytes(password, salt, 120_000));
    }

    private static byte[] rawDeriveBytes(String password, byte[] salt, int iterations) throws Exception {
        // Deliberately the raw JCE call, without this program's validation, to show
        // what that API does to an unfiltered password.
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }

    /**
     * Runs an operation that should succeed and returns its result name, or the
     * exception name if it threw, so an unexpected throw becomes a failed check
     * rather than an aborted run.
     */
    private static String outcome(Supplier<String> operation) {
        try {
            return operation.get();
        } catch (RuntimeException e) {
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    private static void accepted(String password, String name) {
        try {
            PasswordHasher.validatePassword(password.toCharArray());
            check(true, name);
        } catch (IllegalArgumentException e) {
            fail(name + " (threw " + e.getMessage() + ")");
        }
    }

    private interface Body {
        void run() throws Exception;
    }

    private static void refused(Body body, Supplier<String> name, Class<? extends Exception> expected) {
        try {
            body.run();
            fail(name.get() + " (nothing was refused)");
        } catch (Exception actual) {
            if (expected.isInstance(actual)) {
                check(true, name.get());
            } else {
                fail(name.get() + " (wrong exception " + actual.getClass().getSimpleName() + ")");
            }
        }
    }

    private static void check(boolean condition, String name) {
        checks++;
        System.out.println((condition ? "ok   " : "FAIL ") + name);
        if (!condition) {
            FAILURES.add(name);
        }
    }

    private static void fail(String name) {
        check(false, name);
    }

    private static String describe(String value) {
        StringBuilder text = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 0x21 && c <= 0x7E) {
                text.append(c);
            } else {
                text.append(String.format("\\u%04X", (int) c));
            }
        }
        return text.append('"').append(" (").append(value.length()).append(" chars)").toString();
    }
}
