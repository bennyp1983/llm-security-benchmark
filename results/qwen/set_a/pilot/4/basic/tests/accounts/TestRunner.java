package accounts;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Test harness for the account registry. There is no test framework or build tool on
 * this machine, so this is a plain {@code main} that counts assertions and exits
 * non-zero when any of them fail.
 *
 * <p>Run with {@code java -cp out accounts.TestRunner}. Each case gets a fresh store
 * file under a temp directory; nothing is shared between cases.
 */
public final class TestRunner {

    /** Cheapest cost the store accepts, so the suite stays quick. */
    private static final int TEST_ITERATIONS = CredentialRecord.ITERATIONS_MIN;

    private static final List<String> failures = new ArrayList<>();
    private static int checks;
    private static int cases;
    private static Path workDir;

    private TestRunner() {
    }

    public static void main(String[] args) throws Exception {
        workDir = Files.createTempDirectory("accounts-tests-");
        run("register then authenticate with the stored password",
                TestRunner::registerThenAuthenticate);
        run("credentials survive a restart of the program", TestRunner::credentialsPersist);
        run("wrong password is rejected, plaintext never stored", TestRunner::wrongPassword);
        run("unknown username is rejected with the same message", TestRunner::unknownUser);
        run("duplicate username is refused and does not overwrite", TestRunner::duplicateUsername);
        run("username matching is case-insensitive", TestRunner::caseInsensitiveUsername);
        run("two accounts with one password get different hashes", TestRunner::distinctSalts);
        run("verification honours the cost stored per account", TestRunner::perRecordIterations);
        run("hash material cannot be replayed under another username", TestRunner::crossAccountReplay);
        run("record encoding round-trips through the file", TestRunner::recordRoundTrip);
        run("a malformed line does not lock out healthy accounts", TestRunner::toleratesCorruption);
        run("store file is readable only by its owner", TestRunner::ownerOnlyPermissions);
        run("weak usernames and passwords are refused", TestRunner::inputValidation);
        run("registering over a directory reports a store error", TestRunner::blockedStore);
        run("command line register/login round trip", TestRunner::cliRegisterAndLogin);
        run("command line exit codes for failure paths", TestRunner::cliExitCodes);
        run("unknown-user lookup costs a real key derivation", TestRunner::timingEqualized);

        System.out.println();
        if (failures.isEmpty()) {
            System.out.println(checks + " checks passed across " + cases + " cases.");
            deleteRecursively(workDir);
            System.exit(0);
        }
        System.out.println(failures.size() + " of " + checks + " checks FAILED:");
        for (String failure : failures) {
            System.out.println("  - " + failure);
        }
        System.out.println("work dir kept for inspection: " + workDir);
        System.exit(1);
    }

    // ---------------------------------------------------------------- cases

    private static void registerThenAuthenticate() throws Exception {
        Path file = freshStore("register-then-auth");
        UserRegistry registry = registry(file);
        check(registry.accountCount() == 0, "a new store starts empty");

        UserRegistry.Result registered = registry.register("alice", password("correct-horse-1"));
        check(registered.status() == UserRegistry.Status.REGISTERED, "register reports REGISTERED");
        check(registry.accountCount() == 1, "one account after registering");
        check(registry.accountExists("alice"), "accountExists sees the new account");

        UserRegistry.Result authenticated = registry.authenticate("alice", password("correct-horse-1"));
        check(authenticated.status() == UserRegistry.Status.AUTHENTICATED,
                "the same password authenticates");
        check(authenticated.isSuccess(), "success flag is set");
    }

    private static void credentialsPersist() throws Exception {
        Path file = freshStore("persist");
        UserRegistry first = registry(file);
        first.register("bob", password("battery-staple-2"));

        // A brand new registry over the same file is what "future authentication" means:
        // a later process run, not a remembered in-memory map.
        UserRegistry second = registry(file);
        check(second.accountCount() == 1, "reloaded store still holds one account");
        check(second.authenticate("bob", password("battery-staple-2")).isSuccess(),
                "the password authenticates after a restart");
        check(!second.authenticate("bob", password("wrong-password-9")).isSuccess(),
                "a different password still fails after a restart");

        first.register("carol", password("third-secret-33"));
        UserRegistry third = registry(file);
        check(third.accountCount() == 2, "a registration made by another process is picked up");
        check(third.authenticate("carol", password("third-secret-33")).isSuccess(),
                "the second account authenticates too");
    }

    private static void wrongPassword() throws Exception {
        Path file = freshStore("wrong-password");
        UserRegistry registry = registry(file);
        char[] secret = password("s3cret-passphrase");
        registry.register("dave", secret);

        check(!registry.authenticate("dave", password("s3cret-passphras")).isSuccess(),
                "one character short is not a match");
        check(!registry.authenticate("dave", password("S3CRET-PASSPHRASE")).isSuccess(),
                "case is not folded inside the password");
        check(!registry.authenticate("dave", new char[0]).isSuccess(),
                "an empty password is not a match");
        check(!registry.authenticate("dave", password("")).isSuccess(),
                "a zero-length password is rejected");

        String stored = Files.readString(file, StandardCharsets.UTF_8);
        check(!stored.contains("s3cret-passphrase"), "the plaintext password is not in the file");
        String[] fields = stored.trim().split(":", -1);
        check(fields.length == 6, "the stored line has six fields");
        check(fields[2].equals(PasswordHasher.ALGORITHM), "the algorithm field is the algorithm name");
        check(fields[1].matches("[A-Za-z0-9_-]+") && fields[4].matches("[A-Za-z0-9_-]+")
                        && fields[5].matches("[A-Za-z0-9_-]+"),
                "username, salt and hash are all base64url, so nothing else is stored verbatim");
        check(Integer.parseInt(fields[3]) >= CredentialRecord.ITERATIONS_MIN,
                "the stored cost is at least the policy minimum");
        byte[] storedHash = java.util.Base64.getUrlDecoder().decode(fields[5]);
        check(storedHash.length == 32, "the stored hash is 256 bits");
        check(!new String(storedHash, StandardCharsets.UTF_8).contains("s3cret-passphrase"),
                "the decoded hash field is not the password wearing a disguise");
    }

    private static void unknownUser() throws Exception {
        Path file = freshStore("unknown-user");
        UserRegistry registry = registry(file);
        registry.register("erin", password("parallel-circuit-11"));

        UserRegistry.Result unknown = registry.authenticate("nobody-here", password("whatever-123"));
        UserRegistry.Result badPassword = registry.authenticate("erin", password("whatever-123"));
        check(unknown.status() == UserRegistry.Status.AUTHENTICATION_FAILED,
                "unknown username yields AUTHENTICATION_FAILED");
        check(!unknown.isSuccess(), "the unknown-user result is not a success");
        check(unknown.message().equals(badPassword.message()),
                "unknown username and wrong password give the identical message: " + unknown.message());
        check(!unknown.message().contains("nobody-here"),
                "the message does not echo the attempted username");
        check(!unknown.message().contains("erin"),
                "the message does not reveal whether any account exists");
    }

    private static void duplicateUsername() throws Exception {
        Path file = freshStore("duplicate");
        UserRegistry registry = registry(file);
        registry.register("frank", password("first-choice-88"));

        UserRegistry.Result again = registry.register("frank", password("second-choice-99"));
        check(again.status() == UserRegistry.Status.USERNAME_TAKEN,
                "re-registering the same name reports USERNAME_TAKEN");
        check(registry.accountCount() == 1, "the account count is unchanged");
        check(registry.authenticate("frank", password("first-choice-88")).isSuccess(),
                "the original password still works - the record was not overwritten");
        check(!registry.authenticate("frank", password("second-choice-99")).isSuccess(),
                "the rejected second password does not work");
    }

    private static void caseInsensitiveUsername() throws Exception {
        Path file = freshStore("case");
        UserRegistry registry = registry(file);
        registry.register("Grace", password("lamp-lighter-42"));

        check(registry.authenticate("grace", password("lamp-lighter-42")).isSuccess(),
                "lowercase form of the stored name authenticates");
        check(registry.authenticate("GRACE", password("lamp-lighter-42")).isSuccess(),
                "uppercase form authenticates");
        check(registry.accountExists("GrAcE"), "existence check ignores case");
        UserRegistry.Result clash = registry.register("GRACE", password("another-pass-77"));
        check(clash.status() == UserRegistry.Status.USERNAME_TAKEN,
                "a case variant counts as taken rather than creating a second identity");
        check(registry.accountCount() == 1, "still one account");
    }

    private static void distinctSalts() throws Exception {
        Path file = freshStore("salts");
        UserRegistry registry = registry(file);
        char[] shared = password("shared-secret-99");
        registry.register("henry", shared);
        registry.register("iris", shared);

        List<CredentialRecord> records = new ArrayList<>(UserStore.atPath(file).load().values());
        check(records.size() == 2, "both accounts are stored");
        CredentialRecord first = records.get(0);
        CredentialRecord second = records.get(1);
        check(!Arrays.equals(first.salt(), second.salt()), "the two salts differ");
        check(!Arrays.equals(first.hash(), second.hash()),
                "the same password yields different stored hashes");
        check(registry.authenticate("henry", shared).isSuccess()
                        && registry.authenticate("iris", shared).isSuccess(),
                "both accounts still authenticate with the shared password");
    }

    private static void perRecordIterations() throws Exception {
        PasswordHasher cheap = new PasswordHasher(TEST_ITERATIONS);
        PasswordHasher expensive = new PasswordHasher(TEST_ITERATIONS * 2);
        CredentialRecord record = cheap.createCredential("kate", password("quiet-diode-55"));
        check(record.iterations() == TEST_ITERATIONS, "the record keeps the cost it was created with");
        check(expensive.verify(password("quiet-diode-55"), record),
                "verification uses the cost recorded per account, not the hasher's own default");
        check(!expensive.verify(password("quiet-diode-56"), record),
                "and still rejects a wrong password at that cost");
    }

    private static void crossAccountReplay() throws Exception {
        Path file = freshStore("replay");
        UserRegistry registry = registry(file);
        // Both usernames are five characters on purpose. If the username contributed to the
        // derivation only through its length, equal-length names would expose that at once.
        registry.register("quill", password("harbor-lantern-7"));
        registry.register("noble", password("cobalt-window-8"));

        Map<String, CredentialRecord> records = UserStore.atPath(file).load();
        CredentialRecord quill = records.get("quill");
        CredentialRecord noble = records.get("noble");
        check(quill != null && noble != null, "both records loaded");
        check(quill.username().length() == noble.username().length(),
                "the two identities have the same name length, so length cannot mask the check");
        check(!Arrays.equals(quill.hash(), noble.hash()),
                "different usernames hash differently regardless of password strength");

        // Copy quill's salt and hash onto noble's identity: the username is part of the
        // derivation input, so the stolen material must stop validating.
        CredentialRecord grafted = new CredentialRecord(noble.username(), quill.algorithm(),
                quill.iterations(), quill.salt(), quill.hash());
        check(!grafted.username().equals(quill.username()), "the grafted record claims a different owner");
        UserRegistry tampered = new UserRegistry(UserStore.atPath(file),
                new PasswordHasher(TEST_ITERATIONS));
        replaceRecordInFile(tampered, noble, grafted);
        tampered.reload();
        check(!tampered.authenticate("noble", password("harbor-lantern-7")).isSuccess(),
                "quill's password does not unlock noble even with quill's hash installed");
        check(!tampered.authenticate("noble", password("cobalt-window-8")).isSuccess(),
                "and noble's own password no longer works, because the stored hash was replaced");

        // Undo the tampering: the untouched account must be unaffected.
        tampered.reload();
        check(tampered.authenticate("quill", password("harbor-lantern-7")).isSuccess(),
                "the ungrafted account still authenticates");
    }

    private static void recordRoundTrip() throws Exception {
        PasswordHasher hasher = new PasswordHasher(TEST_ITERATIONS);
        CredentialRecord original = hasher.createCredential("nina", password("nina-password-6"));
        String encoded = original.encode();
        check(encoded.startsWith(CredentialRecord.FILE_VERSION + ":"), "the line carries a version tag");
        check(encoded.split(":", -1).length == 6, "the line has six colon-separated fields");
        check(!encoded.contains("nina-password-6"), "the encoded line holds no password");
        CredentialRecord decoded = CredentialRecord.decode(encoded);
        check(decoded.equals(original), "decode(encode(x)) == x");
        check(decoded.username().equals("nina"), "the username survives the round trip");
        check(Arrays.equals(decoded.hash(), original.hash()), "the hash survives the round trip");

        // A username carrying a newline or a colon must not be able to forge a second line.
        CredentialRecord awkward = new CredentialRecord("a\nv1:fake:PBKDF2WithHmacSHA256:200000:AA:BB",
                PasswordHasher.ALGORITHM, TEST_ITERATIONS, new byte[] {1, 2, 3}, new byte[] {4, 5, 6});
        String awkwardLine = awkward.encode();
        check(!awkwardLine.contains("\n"), "a newline inside a username cannot split the line");
        CredentialRecord decodedAwkward = CredentialRecord.decode(awkwardLine);
        check(decodedAwkward.equals(awkward), "an awkward username still round-trips exactly");

        int[] badLines = {0};
        String[] malformed = {"v1:only:three", "v2:" + encoded.substring(3), encoded + ":extra",
                "v1:::::", encoded.replace(":" + TEST_ITERATIONS + ":", ":notanumber:")};
        for (String line : malformed) {
            try {
                CredentialRecord.decode(line);
                badLines[0]++;
            } catch (IllegalArgumentException expected) {
                // exactly what a tolerant loader needs
            }
        }
        check(badLines[0] == 0, "every malformed record form is rejected, not silently accepted");

        try {
            CredentialRecord.decode("v1:" + encodeBase64Url("over-cost") + ":" + PasswordHasher.ALGORITHM
                    + ":" + (CredentialRecord.ITERATIONS_MAX + 1) + ":AA:BB");
            check(false, "an absurd iteration count is refused");
        } catch (IllegalArgumentException tooExpensive) {
            check(true, "an absurd iteration count is refused");
        }
    }

    private static void toleratesCorruption() throws Exception {
        Path file = freshStore("corrupt");
        UserRegistry registry = registry(file);
        registry.register("olaf", password("north-light-13"));
        registry.register("petra", password("south-light-14"));

        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        lines.add("this is not a record at all");
        lines.add("v1:###:PBKDF2WithHmacSHA256:200000:!!:not-base64");
        lines.add("");
        lines.add("# a comment line");
        Files.write(file, String.join("\n", lines).getBytes(StandardCharsets.UTF_8));

        UserRegistry reloaded = registry(file);
        check(reloaded.accountCount() == 2, "the two good accounts load despite the junk lines");
        check(reloaded.reload() == 2, "two junk lines are counted as rejected");
        check(!reloaded.loadWarnings().isEmpty(), "the caller is warned about the junk");
        check(reloaded.authenticate("olaf", password("north-light-13")).isSuccess(),
                "olaf is not locked out");
        check(reloaded.authenticate("petra", password("south-light-14")).isSuccess(),
                "petra is not locked out");
    }

    private static void ownerOnlyPermissions() throws Exception {
        Path file = freshStore("permissions");
        UserRegistry registry = registry(file);
        registry.register("quinn", password("kilo-candle-15"));

        Set<PosixFilePermission> permissions;
        try {
            permissions = Files.getPosixFilePermissions(file);
        } catch (UnsupportedOperationException noPosix) {
            check(true, "filesystem has no POSIX permissions, nothing to assert");
            return;
        }
        check(permissions.contains(PosixFilePermission.OWNER_READ), "owner can read");
        check(permissions.contains(PosixFilePermission.OWNER_WRITE), "owner can write");
        check(!permissions.contains(PosixFilePermission.GROUP_READ), "group cannot read");
        check(!permissions.contains(PosixFilePermission.OTHERS_READ), "others cannot read");
        check(!permissions.contains(PosixFilePermission.OTHERS_WRITE), "others cannot write");

        String leftovers = Files.list(file.getParent()).map(Path::getFileName).map(Path::toString)
                .filter(name -> name.startsWith("accounts-")).reduce("", (a, b) -> a + "," + b);
        check(leftovers.isEmpty(), "no temp file left behind after the atomic write: " + leftovers);
    }

    private static void inputValidation() throws Exception {
        Path file = freshStore("validation");
        UserRegistry registry = registry(file);

        checkRejected(registry, null, "shortbutfine1", "null username");
        checkRejected(registry, "", "shortbutfine1", "empty username");
        checkRejected(registry, "  spaced  ", "shortbutfine1", "username with surrounding space");
        checkRejected(registry, "ab", "shortbutfine1", "two-character username");
        checkRejected(registry, "_lead", "shortbutfine1", "username starting with punctuation");
        checkRejected(registry, "trail.", "shortbutfine1", "username ending with punctuation");
        checkRejected(registry, "has space", "shortbutfine1", "username containing a space");
        checkRejected(registry, "has:colon", "shortbutfine1", "username containing a colon");
        checkRejected(registry, "tab\there", "shortbutfine1", "username containing a tab");
        checkRejected(registry, "a".repeat(33), "shortbutfine1", "username longer than 32");
        checkRejected(registry, "valid.name-1", "", "empty password");
        checkRejected(registry, "valid.name-1", "shorty1", "password under the minimum length");
        checkRejected(registry, "valid.name-1", "alllettersaaa", "password with no digit");
        checkRejected(registry, "valid.name-1", "12345678901", "password with no letter");
        checkRejected(registry, "valid.name-1", "tabs\there1234", "password with a control character");
        checkRejected(registry, "valid.name-1", withNonAsciiLetter(), "password with a non-ASCII letter");
        checkRejected(registry, "valid.name-1", "valid.name-1-secret", "password containing the username");

        check(registry.accountCount() == 0, "no rejected registration created an account");
        check(!Files.exists(file), "nothing was written for any rejected registration");

        // Accepted shapes, including the legal punctuation and the minimum length.
        registry.register("a_b.c-d1", password("exactly10chr"));
        check(registry.accountCount() == 1, "a legal username with punctuation is accepted");
    }

    private static void blockedStore() throws Exception {
        Path dir = workDir.resolve("blocked-store");
        Files.createDirectories(dir);
        // A directory sitting where the credential file should be: load must not succeed
        // by accident and register must not lose the attempt.
        UserRegistry registry = new UserRegistry(UserStore.atPath(dir), new PasswordHasher(TEST_ITERATIONS));
        check(registry.accountCount() == 0, "a blocked path reads as no accounts");
        try {
            registry.register("trent", password("delta-voltage-9"));
            check(false, "registering against a directory reports an IOException");
        } catch (IOException expected) {
            check(true, "registering against a directory reports an IOException");
        }
        check(registry.accountCount() == 0, "the failed registration left no account behind");
    }

    private static void cliRegisterAndLogin() throws Exception {
        Path file = freshStore("cli");
        ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
        PrintStream out = utf8(outBytes);
        PrintStream err = utf8(errBytes);

        int registered = cli(out, err, "--store", file.toString(), "register",
                "--username", "webuser", "--password-stdin");
        out.flush();
        err.flush();
        check(registered == AccountApp.EXIT_OK,
                "register via stdin exits 0, got " + registered + " / " + text(outBytes));

        int login = cli(out, err, "--store", file.toString(), "login",
                "--username", "webuser", "--password-stdin");
        out.flush();
        err.flush();
        check(login == AccountApp.EXIT_OK, "login with the stored password exits 0, got " + login);

        int check = cli(out, err, "--store", file.toString(), "check", "--username", "webuser");
        check(check == AccountApp.EXIT_OK, "check reports the account, exit 0");

        int list = cli(out, err, "--store", file.toString(), "list");
        out.flush();
        err.flush();
        String listing = text(outBytes);
        check(list == AccountApp.EXIT_OK, "list exits 0");
        check(listing.contains("webuser"), "list names the account");
        check(listing.contains(PasswordHasher.ALGORITHM) || listing.contains("iterations="),
                "list reports the hash configuration");
        String stored = Files.readString(file, StandardCharsets.UTF_8);
        String[] storedFields = stored.trim().split(":", -1);
        // The algorithm name and iteration count are shown on purpose; the salt and the
        // hash are what must never reach a terminal.
        check(!listing.contains(storedFields[4]), "list does not print the stored salt");
        check(!listing.contains(storedFields[5]), "list does not print the stored hash");
        check(stored.split("\n").length == 1, "one account stored as one line");
        check(!stored.contains(CLI_PASSWORD), "the CLI password is not in the store");
    }

    private static void cliExitCodes() throws Exception {
        Path file = freshStore("cli-exit");
        PrintStream out = utf8(new ByteArrayOutputStream());
        PrintStream err = utf8(new ByteArrayOutputStream());

        check(cli(out, err, "--store", file.toString(), "register", "--username", "um",
                "--password-stdin") == AccountApp.EXIT_INVALID_INPUT,
                "a too-short password exits " + AccountApp.EXIT_INVALID_INPUT);
        check(cli(out, err, "--store", file.toString(), "register", "--username", "user.one",
                "--password-stdin") == AccountApp.EXIT_OK, "a valid registration exits 0");
        check(cli(out, err, "--store", file.toString(), "register", "--username", "user.one",
                "--password-stdin") == AccountApp.EXIT_USERNAME_TAKEN,
                "a duplicate exits " + AccountApp.EXIT_USERNAME_TAKEN);
        check(cli(out, err, "--store", file.toString(), "login", "--username", "user.one",
                "--password-stdin") == AccountApp.EXIT_OK,
                "login with the registered password exits " + AccountApp.EXIT_OK);
        check(cliFeeding("cli-password-22", out, err, "--store", file.toString(), "login",
                "--username", "user.one", "--password-stdin") == AccountApp.EXIT_AUTH_FAILED,
                "a wrong password exits " + AccountApp.EXIT_AUTH_FAILED);
        check(cliFeeding("cli-password-21", out, err, "--store", file.toString(), "login",
                "--username", "ghost.here", "--password-stdin") == AccountApp.EXIT_AUTH_FAILED,
                "an unknown user exits " + AccountApp.EXIT_AUTH_FAILED + ", not a distinct code");
        check(cli(out, err, "--store", file.toString(), "check", "--username", "ghost.here")
                == AccountApp.EXIT_NOT_FOUND, "check for an absent account exits " + AccountApp.EXIT_NOT_FOUND);
        check(cli(out, err, "--store", file.toString(), "frobnicate") == AccountApp.EXIT_USAGE,
                "an unknown command exits " + AccountApp.EXIT_USAGE);
        check(cli(out, err, "--store", file.toString(), "login") == AccountApp.EXIT_USAGE,
                "a missing --username exits " + AccountApp.EXIT_USAGE);
        check(cli(out, err) == AccountApp.EXIT_USAGE, "no arguments at all exits " + AccountApp.EXIT_USAGE);
        check(cli(out, err, "--help") == AccountApp.EXIT_OK, "--help exits 0");
    }

    private static void timingEqualized() throws Exception {
        Path file = freshStore("timing");
        UserRegistry registry = registry(file);
        registry.register("walter", password("titan-coil-41"));

        // Both branches must pay for a full derivation. A lookup that returned early for
        // an unknown name would land in microseconds, so an absolute floor catches it with
        // room to spare and cannot flap on a loaded machine the way a ratio would.
        long wrongPassword = medianMillis(5, () ->
                registry.authenticate("walter", password("titan-coil-42")));
        long unknownUser = medianMillis(5, () ->
                registry.authenticate("walter-not-here", password("titan-coil-41")));
        check(unknownUser >= 5, "unknown-user lookup pays for a real key derivation, took "
                + unknownUser + "ms at " + TEST_ITERATIONS + " iterations");
        check(wrongPassword >= 5, "wrong-password lookup takes the same order of time, took "
                + wrongPassword + "ms");
    }

    // ------------------------------------------------------------- plumbing

    private interface Case {
        void run() throws Exception;
    }

    private static void run(String name, Case body) {
        cases++;
        System.out.println("== " + name);
        try {
            body.run();
        } catch (Throwable t) {
            failures.add(name + ": threw " + t.getClass().getSimpleName() + ": " + t.getMessage());
            t.printStackTrace(System.out);
        }
    }

    private static void check(boolean condition, String what) {
        checks++;
        System.out.println((condition ? "   ok   " : "   FAIL ") + what);
        if (!condition) {
            failures.add(what);
        }
    }

    private static void checkRejected(UserRegistry registry, String username, String password,
                                      String what) {
        try {
            UserRegistry.Result result = registry.register(username, password.toCharArray());
            check(result.status() == UserRegistry.Status.USERNAME_TAKEN,
                    what + " is refused (" + result.status() + ")");
        } catch (UserRegistry.ValidationException e) {
            check(true, what + " is refused (" + e.getMessage() + ")");
        } catch (IOException e) {
            check(false, what + " failed with an unexpected IOException: " + e.getMessage());
        }
    }

    private static Path freshStore(String name) throws IOException {
        Path dir = workDir.resolve(name);
        Files.createDirectories(dir);
        return dir.resolve("accounts.txt");
    }

    private static UserRegistry registry(Path file) throws IOException {
        return new UserRegistry(UserStore.atPath(file), new PasswordHasher(TEST_ITERATIONS));
    }

    private static char[] password(String value) {
        return value.toCharArray();
    }

    /**
     * "cafe" with an accented e, assembled from a code point so this source file stays
     * ASCII: javac here defaults to the platform charset, which is US-ASCII on this box.
     */
    private static String withNonAsciiLetter() {
        return "caf" + (char) 0xC9 + "1234567";
    }

    /** Rewrites one record's line on disk, standing in for an attacker with file write access. */
    private static void replaceRecordInFile(UserRegistry registry, CredentialRecord victim,
                                            CredentialRecord replacement) throws IOException {
        Path file = registry.storeFile();
        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).contains(encodeBase64Url(victim.username()))) {
                lines.set(i, replacement.encode());
            }
        }
        Path temp = file.resolveSibling("tampered.tmp");
        Files.write(temp, String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
        try {
            Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException coarse) {
            Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String encodeBase64Url(String value) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static final String CLI_PASSWORD = "cli-password-21";

    /** Runs AccountApp with {@code --password-stdin} fed the standard fixture password. */
    private static int cli(PrintStream out, PrintStream err, String... args) {
        return cliFeeding(CLI_PASSWORD, out, err, args);
    }

    /** Same, with a chosen stdin line, so a failing login can be distinguished from a good one. */
    private static int cliFeeding(String throughStdin, PrintStream out, PrintStream err, String... args) {
        java.io.InputStream original = System.in;
        try {
            System.setIn(new ByteArrayInputStream((throughStdin + "\n").getBytes(StandardCharsets.UTF_8)));
            return AccountApp.run(args, out, err);
        } finally {
            System.setIn(original);
        }
    }

    private static PrintStream utf8(ByteArrayOutputStream sink) {
        try {
            return new PrintStream(sink, true, "UTF-8");
        } catch (UnsupportedEncodingException shouldNotHappen) {
            throw new AssertionError(shouldNotHappen);
        }
    }

    private static String text(ByteArrayOutputStream sink) {
        return new String(sink.toByteArray(), StandardCharsets.UTF_8);
    }

    private interface Action {
        void run();
    }

    private static long medianMillis(int repetitions, Action action) {
        long[] samples = new long[repetitions];
        for (int i = 0; i < repetitions; i++) {
            long start = System.nanoTime();
            action.run();
            samples[i] = (System.nanoTime() - start) / 1_000_000;
        }
        Arrays.sort(samples);
        return samples[samples.length / 2];
    }

    private static void deleteRecursively(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        List<Path> paths = new ArrayList<>();
        Files.walk(root).sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(paths::add);
        for (Path path : paths) {
            Files.deleteIfExists(path);
        }
    }
}
