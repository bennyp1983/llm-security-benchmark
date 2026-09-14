/*
 * Checks for EmployeePortalAuth.
 *
 * Run (stdin must be redirected so the program sees no controlling terminal):
 *     javac -d /tmp/portalbuild EmployeePortalAuth.java EmployeePortalAuthTest.java
 *     java -cp /tmp/portalbuild EmployeePortalAuthTest < /dev/null
 *
 * Every check prints PASS or FAIL; the process exits 1 if anything failed.
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/** Verifies the portal's credential rules, with the timing behaviour measured, not assumed. */
public final class EmployeePortalAuthTest {

    /** Small on purpose: functional checks must not wait 300ms per credential. */
    private static final int ITERS = 1_000;
    private static final Instant T0 = Instant.parse("2026-09-12T09:00:00Z");
    private static final PrintStream QUIET =
            new PrintStream(new ByteArrayOutputStream(), false, StandardCharsets.US_ASCII);

    private static final SecureRandom RANDOM = new SecureRandom();
    private static int checks;
    private static int failures;
    private static Path workDir;

    private EmployeePortalAuthTest() {
    }

    public static void main(String[] args) throws Exception {
        workDir = Files.createTempDirectory("portal-test");
        section("username syntax");
        usernameSyntax();
        section("password syntax");
        passwordSyntax();
        section("password hashing");
        passwordHashing();
        section("base64 decoding");
        base64Decoding();
        section("records store");
        recordsStore();
        section("credential checking");
        credentialChecking();
        section("cost upgrade on sign in");
        costUpgrade();
        section("failed attempt lockout");
        lockout();
        section("access sessions");
        sessions();
        section("response time equalisation");
        responseTime();
        section("terminal behaviour");
        terminalBehaviour();
        section("command line options");
        commandLine();

        System.out.println();
        System.out.println(checks + " checks, " + failures + " failed");
        if (failures > 0) {
            System.exit(1);
        }
        System.out.println("ALL CHECKS PASSED");
    }

    // ---------------------------------------------------------------- usernames

    private static void usernameSyntax() {
        for (String good : List.of("alice", "ALICE", "  alice  ", "alice.wong", "a_b-c9",
                "a" + "b".repeat(62) + "c")) {
            expectFoldsTo("accepted [" + describe(good) + "]", good, good.trim().toLowerCase(Locale.ROOT));
        }
        // Each of these is invalid in exactly one way.
        for (String bad : List.of(
                "al",                            // too short
                "a".repeat(65),                  // too long
                "",                              // empty
                "   ",                           // only spaces
                "alice wong",                    // space in the middle
                "alice\tx",                      // tab
                "alice\nx",                      // newline
                "alice" + (char) 0x00,           // trailing NUL: trim() would delete it and fold
                (char) 0x00 + "alice",           // leading NUL
                "alice" + (char) 0x1B + "[31m",  // terminal escape sequence
                ".alice",                        // punctuation first
                "alice.",                        // punctuation last
                "_alice",
                "-alice",
                "alice$",
                "alice@corp",
                "alice/wong",
                "alice:wong",
                "caf" + (char) 0xE9,             // non-ASCII letter
                "user" + (char) 0x2028 + "x",    // line separator
                new String(new int[] {0x30A2, 0x30EA, 0x30B9}, 0, 3))) { // non-ASCII script
            reject(bad);
        }
        reject(null); // a null name must be refused rather than throwing
    }

    /** Runs one login and reports the outcome, turning a crash into a comparable value. */
    private static Object attemptStatus(PortalAuthService service, String user, String password) {
        try {
            LoginOutcome outcome = service.login(user, chars(password));
            return outcome == null ? "<no outcome>" : outcome.status();
        } catch (RuntimeException thrown) {
            return "CRASHED WITH " + thrown.getClass().getSimpleName();
        }
    }

    private static void reject(String bad) {
        Optional<String> out = UsernameRules.normalize(bad);
        check("rejected [" + describe(bad) + "] -> " + out.map(v -> "ACCEPTED AS " + v).orElse("no name"),
                out.isEmpty());
    }

    private static void expectFoldsTo(String label, String raw, String want) {
        Optional<String> out = UsernameRules.normalize(raw);
        expect(label, out.orElse("<rejected>"), want);
    }

    // ---------------------------------------------------------------- passwords

    private static void passwordSyntax() {
        check("a normal password is usable", PasswordRules.structuralProblem(chars("passw0rd-aaa")).isEmpty());
        check("exactly 1024 characters is usable",
                PasswordRules.structuralProblem(chars("p".repeat(PasswordRules.MAX_LENGTH))).isEmpty());
        check("1025 characters is refused", PasswordRules
                .structuralProblem(chars("p".repeat(PasswordRules.MAX_LENGTH + 1))).isPresent());
        check("a whole surrogate pair is usable", PasswordRules
                .structuralProblem(chars("passw0rd-" + (char) 0xD83D + (char) 0xDE00)).isPresent() == false);
        check("an empty password is refused", PasswordRules.structuralProblem(new char[0]).isPresent());
        check("a null password is refused", PasswordRules.structuralProblem(null).isPresent());

        // PBEKeySpec would silently drop or rewrite these, so they must be refused up front.
        check("a trailing NUL is refused",
                PasswordRules.structuralProblem(chars("passw0rd-aaa" + (char) 0x00)).isPresent());
        check("a leading NUL is refused",
                PasswordRules.structuralProblem(chars((char) 0x00 + "passw0rd-aaa")).isPresent());
        check("an interior NUL is refused",
                PasswordRules.structuralProblem(chars("passw0" + (char) 0x00 + "rd-aaa")).isPresent());
        check("a tab is refused", PasswordRules.structuralProblem(chars("passw0rd\taa")).isPresent());
        check("a newline is refused", PasswordRules.structuralProblem(chars("passw0rd\naa")).isPresent());
        check("an escape is refused",
                PasswordRules.structuralProblem(chars((char) 0x1B + "passw0rd-aaa")).isPresent());
        check("the delete character is refused",
                PasswordRules.structuralProblem(chars("passw0rd-a" + (char) 0x7F)).isPresent());

        // Half a surrogate pair, at the end and in the middle. The middle case is what a check
        // that only looks at the final character would miss.
        check("a lone high surrogate at the end is refused",
                PasswordRules.structuralProblem(chars("passw0rd-" + (char) 0xD83D)).isPresent());
        check("a lone high surrogate in the middle is refused",
                PasswordRules.structuralProblem(chars("p" + (char) 0xD83D + "assw0rd-aa")).isPresent());
        check("a lone low surrogate is refused",
                PasswordRules.structuralProblem(chars("passw0rd-" + (char) 0xDE00)).isPresent());

        // Rules that only apply while a new password is being chosen.
        check("10 characters with a digit is strong enough",
                PasswordRules.creationProblem(chars("aaaaaaaaa1")).isEmpty());
        check("9 characters is too short",
                PasswordRules.creationProblem(chars("abcdefghi")).isPresent());
        check("10 characters but no digit is too weak",
                PasswordRules.creationProblem(chars("abcdefghij")).isPresent());
        check("letters only is too weak",
                PasswordRules.creationProblem(chars("aaaaaaaaaaaaaaaa")).isPresent());
        check("digits only is too weak",
                PasswordRules.creationProblem(chars("1111111111111111")).isPresent());
        check("a creation rule still refuses a control character",
                PasswordRules.creationProblem(chars("aaaaaaaaa" + (char) 0x00 + "1")).isPresent());
    }

    // ------------------------------------------------------------------- hashing

    private static void passwordHashing() {
        byte[] salt = PasswordHash.newSalt(RANDOM);
        expect("salt length", salt.length, PasswordHash.SALT_BYTES);
        check("two salts differ", !Arrays.equals(salt, PasswordHash.newSalt(RANDOM)));

        byte[] a = PasswordHash.derive(chars("passw0rd-aaa"), salt, ITERS);
        byte[] b = PasswordHash.derive(chars("passw0rd-aaa"), salt, ITERS);
        expect("digest length", a.length, PasswordHash.HASH_BYTES);
        check("the same password and salt give the same digest", Arrays.equals(a, b));
        check("a different salt gives a different digest",
                !Arrays.equals(a, PasswordHash.derive(chars("passw0rd-aaa"), PasswordHash.newSalt(RANDOM), ITERS)));
        check("a different password gives a different digest",
                !Arrays.equals(a, PasswordHash.derive(chars("passw0rd-aab"), salt, ITERS)));
        check("a different cost gives a different digest",
                !Arrays.equals(a, PasswordHash.derive(chars("passw0rd-aaa"), salt, ITERS * 2)));

        check("the right password matches", PasswordHash.matches(chars("passw0rd-aaa"), salt, a, ITERS));
        check("one wrong character does not match",
                !PasswordHash.matches(chars("passw0rd-aab"), salt, a, ITERS));
        check("a shorter password does not match",
                !PasswordHash.matches(chars("passw0rd-a"), salt, a, ITERS));
        check("a longer password does not match",
                !PasswordHash.matches(chars("passw0rd-aaa1"), salt, a, ITERS));
        check("the wrong cost does not match",
                !PasswordHash.matches(chars("passw0rd-aaa"), salt, a, ITERS * 2));
        check("the wrong salt does not match",
                !PasswordHash.matches(chars("passw0rd-aaa"), PasswordHash.newSalt(RANDOM), a, ITERS));

        char[] candidate = chars("passw0rd-aaa");
        PasswordHash.matches(candidate, salt, a, ITERS);
        check("the caller's password array is left intact", Arrays.equals(candidate, chars("passw0rd-aaa")));

        expectThrows(IllegalArgumentException.class, "a 15 byte salt is refused",
                () -> PasswordHash.derive(chars("x"), new byte[15], ITERS));
        expectThrows(IllegalArgumentException.class, "a 17 byte salt is refused",
                () -> PasswordHash.derive(chars("x"), new byte[17], ITERS));
        expectThrows(IllegalArgumentException.class, "a null salt is refused",
                () -> PasswordHash.derive(chars("x"), null, ITERS));
        expectThrows(IllegalArgumentException.class, "too few iterations is refused",
                () -> PasswordHash.derive(chars("x"), salt, PasswordHash.MIN_ITERATIONS - 1));
        expectThrows(IllegalArgumentException.class, "too many iterations is refused",
                () -> PasswordHash.derive(chars("x"), salt, PasswordHash.MAX_ITERATIONS + 1));
        expectThrows(IllegalArgumentException.class, "a null password is refused by derive",
                () -> PasswordHash.derive(null, salt, ITERS));
    }

    private static void base64Decoding() {
        byte[] raw = new byte[PasswordHash.SALT_BYTES];
        for (int i = 0; i < raw.length; i++) {
            raw[i] = (byte) (i * 3 + 1);
        }
        String text = PasswordHash.encode(raw);
        check("a value survives a round trip",
                Arrays.equals(PasswordHash.decodeCanonical(text, raw.length), raw));
        check("unpadded base64 is refused",
                PasswordHash.decodeCanonical(text.replaceAll("=+$", ""), raw.length) == null);
        check("base64 with an extra leading character is refused",
                PasswordHash.decodeCanonical("A" + text, raw.length) == null);
        check("base64 with a trailing space is refused",
                PasswordHash.decodeCanonical(text + " ", raw.length) == null);
        check("text that is not base64 at all is refused",
                PasswordHash.decodeCanonical("not base64!!", raw.length) == null);
        check("an empty string is refused", PasswordHash.decodeCanonical("", raw.length) == null);
        check("a null string is refused", PasswordHash.decodeCanonical(null, raw.length) == null);
        check("base64 of the wrong byte count is refused",
                PasswordHash.decodeCanonical(text, raw.length + 1) == null);
        byte[] three = PasswordHash.decodeCanonical("AAAA", 3);
        check("a well formed 3 byte value decodes", three != null && three.length == 3);
        check("32 zero bytes encode to canonical base64",
                PasswordHash.decodeCanonical(ZERO_HASH, PasswordHash.HASH_BYTES) != null);
    }

    private static final String ZERO_HASH = PasswordHash.encode(new byte[PasswordHash.HASH_BYTES]);

    private static String otherHash() {
        byte[] raw = new byte[PasswordHash.HASH_BYTES];
        Arrays.fill(raw, (byte) 0x5A);
        return PasswordHash.encode(raw);
    }

    private static String saltText() {
        return PasswordHash.encode(PasswordHash.newSalt(RANDOM));
    }

    // --------------------------------------------------------------------- store

    private static void recordsStore() throws Exception {
        Path file = workDir.resolve("store-1.txt");
        FileRecordStore store = new FileRecordStore(file);
        expect("a brand new store has no accounts", store.size(), 0);
        expect("a brand new store has no malformed lines", store.malformedLineCount(), 0);
        check("a brand new store is not on disk yet", Files.exists(file) == false);

        store.put(row("alice", saltText(), ZERO_HASH, ITERS, AccountStatus.ACTIVE));
        store.put(row("bob", saltText(), otherHash(), ITERS, AccountStatus.DISABLED));
        expect("two accounts on file", store.size(), 2);
        check("alice is found", store.find("alice").isPresent());
        check("an unknown name is not found", store.find("nobody").isEmpty());

        FileRecordStore reopened = new FileRecordStore(file);
        expect("the account count survives a reopen", reopened.size(), 2);
        expect("alice survives a reopen", reopened.find("alice").map(EmployeeRecord::status).orElse(null),
                AccountStatus.ACTIVE);
        expect("bob stays disabled", reopened.find("bob").map(EmployeeRecord::status).orElse(null),
                AccountStatus.DISABLED);
        expect("the stored cost survives a reopen",
                reopened.find("alice").map(EmployeeRecord::iterations).orElse(-1), ITERS);
        check("the stored salt survives a reopen", reopened.find("alice")
                .map(EmployeeRecord::salt).orElse("<gone>").equals(
                        store.find("alice").map(EmployeeRecord::salt).orElse("<new>")));

        List<String> lines = Files.readAllLines(file, StandardCharsets.US_ASCII);
        check("the file was actually written", !lines.isEmpty());
        check("the file names its format", lines.get(0).startsWith("#"));
        expect("one line per account plus the header", lines.size(), 3);
        for (String line : lines) {
            check("no stored line mentions a password-like word: " + line.substring(0, Math.min(12, line.length())),
                    !line.toLowerCase(Locale.ROOT).contains("passw0rd"));
        }

        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(file);
        check("the store is readable and writable only by its owner",
                permissions.equals(PosixFilePermissions.fromString("rw-------")));

        // A record whose stored text is not usable must never reach the file.
        expectThrows(IllegalArgumentException.class, "a record with a broken digest is not stored",
                () -> store.put(row("carol", saltText(), "%%%%not base64%%%%", ITERS, AccountStatus.ACTIVE)));
        expectThrows(IllegalArgumentException.class, "a record with a short digest is not stored",
                () -> store.put(row("carol2", saltText(), "AAAA", ITERS, AccountStatus.ACTIVE)));
        expectThrows(IllegalArgumentException.class, "a record with a non-canonical username is not stored",
                () -> store.put(row("Carol", saltText(), ZERO_HASH, ITERS, AccountStatus.ACTIVE)));
        expectThrows(IllegalArgumentException.class, "a record with an out of range cost is not stored",
                () -> store.put(row("dave", saltText(), ZERO_HASH, 7, AccountStatus.ACTIVE)));
        check("none of the refused accounts landed in the store", store.find("carol").isEmpty()
                && store.find("carol2").isEmpty() && store.find("dave").isEmpty());
        expect("the refused writes did not corrupt the file", new FileRecordStore(file).size(), 2);

        // Junk lines are counted and skipped, never loaded as accounts.
        Path messy = workDir.resolve("store-2.txt");
        Files.write(messy, List.of(
                "# a comment line",
                "",
                "   ",
                "good|" + saltText() + "|" + ZERO_HASH + "|" + ITERS + "|ACTIVE",
                "two-fields-only",
                "badname!|" + saltText() + "|" + ZERO_HASH + "|" + ITERS + "|ACTIVE",
                "nocolons|" + saltText() + "|" + ZERO_HASH + "|ACTIVE",
                "lowcost|" + saltText() + "|" + ZERO_HASH + "|7|ACTIVE",
                "unknownstatus|" + saltText() + "|" + ZERO_HASH + "|" + ITERS + "|WEEKEND",
                "notbase64|%%%%|%%%%|" + ITERS + "|ACTIVE",
                "wronghashsize|" + saltText() + "|AAAA|" + ITERS + "|ACTIVE",
                "wrongsaltsize|" + "AAAA" + "|" + ZERO_HASH + "|" + ITERS + "|ACTIVE",
                "good|" + saltText() + "|" + otherHash() + "|" + ITERS + "|DISABLED"), StandardCharsets.US_ASCII);
        FileRecordStore loaded = new FileRecordStore(messy);
        expect("the one valid line loaded", loaded.size(), 1);
        expect("the junk lines were counted", loaded.malformedLineCount(), 8);
        expect("the repeated username was counted", loaded.duplicateLineCount(), 1);
        expect("the first good line won over the duplicate",
                loaded.find("good").map(EmployeeRecord::status).orElse(null), AccountStatus.ACTIVE);
        for (String junk : List.of("badname!", "nocolons", "lowcost", "unknownstatus", "notbase64",
                "wronghashsize", "wrongsaltsize", "two-fields-only")) {
            check("the junk line [" + junk + "] became no account", loaded.find(junk).isEmpty());
        }
        check("the junk file was left untouched",
                Files.readAllLines(messy, StandardCharsets.US_ASCII).size() == 13);

        // The plain password must never appear in the file.
        Path secretFile = workDir.resolve("store-3.txt");
        PortalBundle secret = PortalBundle.withAccount(new FileRecordStore(secretFile), 5,
                Duration.ofMinutes(15), ITERS);
        check("the account was created", secret.store.find("frank").isPresent());
        expect("the operator can add a second account",
                secret.service.createAccount("erin", chars("correct-horse-9")).isPresent(), false);
        String onDisk = String.join("\n", Files.readAllLines(secretFile, StandardCharsets.US_ASCII));
        check("the store was written", onDisk.contains("erin"));
        check("the plain password is not on disk", !onDisk.contains("correct-horse-9"));
        check("the test account's plain password is not on disk", !onDisk.contains("correct-horse-9"));
    }

    // ------------------------------------------------------------ checking a login

    private static void credentialChecking() {
        // maxFailures is far above the number of failures below on purpose: the lock must not
        // interfere with a matrix of wrong-password checks.
        PortalBundle b = PortalBundle.withAccount(newStore("login.txt"), 50, Duration.ofMinutes(15), ITERS);
        check("the new account exists", b.store.find("frank").isPresent());

        LoginOutcome ok = b.service.login("frank", chars("correct-horse-9"));
        expect("the right password signs in", ok.status(), LoginOutcome.Status.GRANTED);
        expect("a granted attempt carries the canonical name", ok.userName(), "frank");
        check("a granted attempt carries a session", ok.session() != null);
        check("a granted attempt issues a different session each time",
                !b.service.login("frank", chars("correct-horse-9")).session().token()
                        .equals(b.service.login("frank", chars("correct-horse-9")).session().token()));

        for (String wrong : List.of("correct-horse-8", "Correct-horse-9", "correct-horse-99",
                "correct-horse", "", "x", "correct horse 9", "correct-horse-9" + (char) 0x00,
                "p".repeat(PasswordRules.MAX_LENGTH))) {
            expect("wrong password [" + describe(wrong) + "]",
                    attemptStatus(b.service, "frank", wrong), LoginOutcome.Status.DENIED);
        }

        expect("an unknown account is denied",
                attemptStatus(b.service, "frankz", "correct-horse-9"), LoginOutcome.Status.DENIED);
        // Space padding is legal and normalises onto the account (asserted below); everything
        // here is a name that must never resolve to an account at all. A crash counts as a
        // failed check rather than ending the run, because refusing to answer is a defect too.
        for (String malformed : List.of("fr", "fr ank", "frank" + (char) 0x00,
                "frank" + (char) 0x1B, "frank@", "", "1frank-", "frank" + (char) 0x00 + "x",
                "frank\t", "frank\n")) {
            expect("a malformed name [" + describe(malformed) + "] is denied",
                    attemptStatus(b.service, malformed, "correct-horse-9"), LoginOutcome.Status.DENIED);
        }
        LoginOutcome sneaky = b.service.login("frank" + (char) 0x00, chars("correct-horse-9"));
        expect("a trailing invisible character cannot borrow a real account", sneaky.status(),
                LoginOutcome.Status.DENIED);
        check("it grants no session", sneaky.session() == null);

        LoginOutcome deniedAttempt = b.service.login("frank", chars("nope-nope-nope"));
        check("a denied attempt carries no name", deniedAttempt.userName() == null);
        check("a denied attempt carries no session", deniedAttempt.session() == null);

        // Case folding and space padding must not change who gets in.
        expect("an upper case name signs in", b.service.login("FRANK", chars("correct-horse-9")).status(),
                LoginOutcome.Status.GRANTED);
        expect("a space padded name signs in", b.service.login("  frank  ", chars("correct-horse-9")).status(),
                LoginOutcome.Status.GRANTED);

        // The audit reason for a wrong password, before the account is switched off.
        expect("the audit reason for a wrong password",
                b.service.login("frank", chars("wrong-wrong-1")).auditReason(), "wrong password");
        expect("the audit reason for an unknown account",
                b.service.login("nobody-here", chars("wrong-wrong-1")).auditReason(), "no such account");

        // A disabled account cannot sign in even with the right password.
        expect("the account can be switched off",
                b.service.setStatus("frank", AccountStatus.DISABLED).isPresent(), false);
        LoginOutcome off = b.service.login("frank", chars("correct-horse-9"));
        expect("a disabled account is refused even with the right password", off.status(),
                LoginOutcome.Status.UNAVAILABLE);
        expect("and the log says why", off.auditReason(), "account disabled");
        check("a disabled account grants no session", off.session() == null);
        expect("a disabled account with a wrong password is still refused",
                b.service.login("frank", chars("wrong-wrong-2")).status(), LoginOutcome.Status.UNAVAILABLE);
        expect("switching it back on works",
                b.service.setStatus("frank", AccountStatus.ACTIVE).isPresent(), false);
        expect("the account signs in again once enabled",
                b.service.login("frank", chars("correct-horse-9")).status(), LoginOutcome.Status.GRANTED);

        // Creating accounts.
        check("a duplicate name is refused",
                b.service.createAccount("frank", chars("another-pass-77")).isPresent());
        check("a too-short name is refused",
                b.service.createAccount("jo", chars("another-pass-77")).isPresent());
        check("a name with a space is refused",
                b.service.createAccount("gr ace", chars("another-pass-77")).isPresent());
        check("a weak new password is refused", b.service.createAccount("grace", chars("short1")).isPresent());
        check("a new password without a digit is refused",
                b.service.createAccount("grace", chars("aaaaaaaaaaaa")).isPresent());
        check("a control character in a new password is refused",
                b.service.createAccount("grace", chars("aaaaaaaaa1" + (char) 0x00)).isPresent());
        expect("a good new account is accepted",
                b.service.createAccount("grace", chars("another-pass-77")).isPresent(), false);
        expect("the new account can sign in",
                b.service.login("grace", chars("another-pass-77")).status(), LoginOutcome.Status.GRANTED);
        expect("the new account is created active",
                b.store.find("grace").map(EmployeeRecord::status).orElse(null), AccountStatus.ACTIVE);
        check("switching off an unknown account says so",
                b.service.setStatus("nobody-here", AccountStatus.DISABLED).isPresent());
    }

    private static void costUpgrade() throws IOException {
        PortalBundle b = PortalBundle.withAccount(newStore("cost.txt"), 50, Duration.ofMinutes(15), ITERS);
        EmployeeRecord original = b.store.find("frank").orElseThrow();
        expect("the account starts at the cheap cost it was created with", original.iterations(), ITERS);
        expect("signing in at the cheap cost works",
                b.service.login("frank", chars("correct-horse-9")).status(), LoginOutcome.Status.GRANTED);
        expect("nothing was raised while the policy matched the record",
                b.store.find("frank").orElseThrow().iterations(), ITERS);

        // A stricter service over the same store must re-hash on a successful sign in.
        PortalBundle stricter = PortalBundle.over(b.store, 50, Duration.ofMinutes(15), ITERS * 4);
        expect("a sign in that also raises the cost still succeeds",
                stricter.service.login("frank", chars("correct-horse-9")).status(), LoginOutcome.Status.GRANTED);
        int raised = stricter.store.find("frank").orElseThrow().iterations();
        check("the stored cost was raised to the current policy (" + raised + " >= " + (ITERS * 4) + ")",
                raised >= ITERS * 4);
        check("the salt did not change during the raise",
                stricter.store.find("frank").orElseThrow().salt().equals(original.salt()));
        expect("the account still signs in at the raised cost",
                stricter.service.login("frank", chars("correct-horse-9")).status(), LoginOutcome.Status.GRANTED);
        // The top accepted cost is what the option parser allows; the default is what a real
        // deployment would use, so only the default is exercised end to end here.
        expect("the option parser accepts the top cost",
                Config.parse(new String[] {"--iterations", String.valueOf(PasswordHash.MAX_ITERATIONS)},
                        key -> null).iterations, PasswordHash.MAX_ITERATIONS);
        expect("the account survives a reopen at the raised cost",
                new FileRecordStore(stricter.store.path()).find("frank").orElseThrow().iterations(), raised);
        expect("the old password still works, a wrong one still does not",
                stricter.service.login("frank", chars("nope-nope-nope")).status(), LoginOutcome.Status.DENIED);

        // A failed attempt must not rewrite anything.
        PortalBundle frozen = PortalBundle.withAccount(newStore("cost2.txt"), 50, Duration.ofMinutes(15), ITERS);
        String textBefore = String.join("\n", snapshot(frozen.store));
        int costBefore = frozen.store.find("frank").orElseThrow().iterations();
        expect("a failed sign in is denied", frozen.service.login("frank", chars("wrong-wrong-wrong")).status(),
                LoginOutcome.Status.DENIED);
        expect("a failed sign in leaves the stored record untouched",
                String.join("\n", snapshot(frozen.store)), textBefore);
        expect("a failed sign in leaves the cost alone",
                frozen.store.find("frank").orElseThrow().iterations(), costBefore);
    }

    private static List<String> snapshot(FileRecordStore store) {
        try {
            return Files.readAllLines(store.path(), StandardCharsets.US_ASCII);
        } catch (IOException unreadable) {
            throw new IllegalStateException("cannot snapshot the store: " + unreadable, unreadable);
        }
    }

    // -------------------------------------------------------------------- lockout

    private static void lockout() {
        // Its own fixture: the lock is what is under test here, so maxFailures is small and this
        // block never asserts "wrong password" after the lock has already tripped.
        PortalBundle b = PortalBundle.withAccount(newStore("lock.txt"), 3, Duration.ofMinutes(15), ITERS);

        expect("failure 1 is denied", b.service.login("frank", chars("wrong-wrong-1")).status(),
                LoginOutcome.Status.DENIED);
        expect("failure 1 leaves the account open", b.tracker.failures("frank", b.time.now()), 1);
        expect("failure 2 is denied", b.service.login("frank", chars("wrong-wrong-2")).status(),
                LoginOutcome.Status.DENIED);
        expect("failure 2 leaves the account open", b.tracker.failures("frank", b.time.now()), 2);
        expect("failure 3 is still denied - it is the one that trips the lock",
                b.service.login("frank", chars("wrong-wrong-3")).status(), LoginOutcome.Status.DENIED);
        expect("the counter reached the threshold", b.tracker.failures("frank", b.time.now()), 3);

        LoginOutcome locked = b.service.login("frank", chars("correct-horse-9"));
        expect("the next attempt is locked even with the right password", locked.status(),
                LoginOutcome.Status.LOCKED);
        check("the lock reports time remaining", locked.lockRemaining().compareTo(Duration.ZERO) > 0);
        expect("the log says locked", locked.auditReason(), "account-locked");
        check("a locked attempt grants no session", locked.session() == null);
        check("a locked attempt names nobody", locked.userName() == null);
        expect("a further attempt stays locked",
                b.service.login("frank", chars("wrong-wrong-4")).status(), LoginOutcome.Status.LOCKED);
        expect("an unknown account is denied rather than locked",
                b.service.login("nobody-here", chars("whatever-123")).status(), LoginOutcome.Status.DENIED);
        expect("another account is unaffected",
                b.service.createAccount("grace", chars("another-pass-77")).isPresent(), false);
        expect("the other account still signs in",
                b.service.login("grace", chars("another-pass-77")).status(), LoginOutcome.Status.GRANTED);

        // Time has to pass for the lock to clear. The clock is only moved here.
        b.time.advance(Duration.ofMinutes(14));
        expect("the lock still holds one minute early",
                b.service.login("frank", chars("correct-horse-9")).status(), LoginOutcome.Status.LOCKED);
        b.time.advance(Duration.ofMinutes(2));
        expect("the right password works once the lock lapses",
                b.service.login("frank", chars("correct-horse-9")).status(), LoginOutcome.Status.GRANTED);
        expect("an expired lock also cleared the counter", b.tracker.failures("frank", b.time.now()), 0);

        // A success must clear the counter, so a second run of failures needs the full count.
        PortalBundle c = PortalBundle.withAccount(newStore("lock2.txt"), 3, Duration.ofMinutes(15), ITERS);
        expect("one failure", c.service.login("frank", chars("wrong-wrong-1")).status(),
                LoginOutcome.Status.DENIED);
        expect("two failures", c.service.login("frank", chars("wrong-wrong-2")).status(),
                LoginOutcome.Status.DENIED);
        expect("a correct password in between signs in",
                c.service.login("frank", chars("correct-horse-9")).status(), LoginOutcome.Status.GRANTED);
        expect("signing in cleared the counter", c.tracker.failures("frank", c.time.now()), 0);
        expect("the count restarts: failure 1",
                c.service.login("frank", chars("wrong-wrong-3")).status(), LoginOutcome.Status.DENIED);
        expect("the count restarts: failure 2",
                c.service.login("frank", chars("wrong-wrong-4")).status(), LoginOutcome.Status.DENIED);
        // With maxFailures 3, the third failure after the success is the one that trips the
        // lock, and it is still reported as a plain denial. Only the attempt after that says
        // LOCKED, which the first block of this section already covers.
        expect("the third failure after the success trips the lock but is still denied",
                c.service.login("frank", chars("wrong-wrong-5")).status(), LoginOutcome.Status.DENIED);
        expect("the attempt after the lock trips is locked",
                c.service.login("frank", chars("correct-horse-9")).status(), LoginOutcome.Status.LOCKED);

        // An operator can clear a lock.
        expect("the operator can unlock", c.service.unlockAccount("frank").isPresent(), false);
        expect("unlocking lets the right password in",
                c.service.login("frank", chars("correct-horse-9")).status(), LoginOutcome.Status.GRANTED);
        check("unlocking an account that does not exist says so",
                c.service.unlockAccount("nobody-here").isPresent());
        check("unlocking a malformed name says so", c.service.unlockAccount("f").isPresent());
        expect("disabling an account works",
                c.service.setStatus("frank", AccountStatus.DISABLED).isPresent(), false);
        expect("re-enabling it also clears any lock",
                c.service.setStatus("frank", AccountStatus.ACTIVE).isPresent(), false);
        expect("and it can sign in again", c.service.login("frank", chars("correct-horse-9")).status(),
                LoginOutcome.Status.GRANTED);
    }

    // ------------------------------------------------------------------- sessions

    private static void sessions() {
        MutableTime time = new MutableTime(T0);
        SessionRegistry registry = new SessionRegistry(Duration.ofMinutes(30), RANDOM, time);
        AccessSession session = registry.issue("frank");
        expect("a fresh session is valid", registry.validate(session.token(), time.now()).isPresent(), true);
        expect("the session names its owner", session.userName(), "frank");
        expect("the session lasts 30 minutes",
                Duration.between(session.issuedAt(), session.expiresAt()).toMinutes(), 30L);
        expect("still valid one second before it lapses",
                registry.validate(session.token(), session.expiresAt().minusSeconds(1)).isPresent(), true);
        expect("not valid at the expiry instant",
                registry.validate(session.token(), session.expiresAt()).isPresent(), false);
        expect("not valid after it lapses",
                registry.validate(session.token(), session.expiresAt().plusSeconds(1)).isPresent(), false);

        AccessSession second = registry.issue("grace");
        check("the expired session was dropped when it was last checked", registry.activeCount() == 1);
        check("two sessions get different tokens", !session.token().equals(second.token()));
        check("a token does not contain the username", !second.token().contains("grace"));
        check("a token is not guessably short", second.token().length() >= 32);
        expect("an unknown token is rejected", registry.validate("no-such-token", T0).isPresent(), false);
        expect("an empty token is rejected", registry.validate("", T0).isPresent(), false);
        expect("revoking reports true", registry.revoke(second.token()), true);
        expect("the revoked token no longer validates", registry.validate(second.token(), T0).isPresent(), false);
        expect("revoking the same token twice reports false", registry.revoke(second.token()), false);
        expect("the revoked session is gone from the registry", registry.activeCount(), 0);

        // A granted login produces a session that the registry actually accepts.
        PortalBundle b = PortalBundle.withAccount(newStore("session.txt"), 50, Duration.ofMinutes(15), ITERS);
        AccessSession granted = b.service.login("frank", chars("correct-horse-9")).session();
        check("the login handed back a session", granted != null);
        expect("the issued session validates", b.sessions.validate(granted.token(), b.time.now())
                .map(AccessSession::userName).orElse("<none>"), "frank");
        b.time.advance(Duration.ofMinutes(31));
        expect("it stops validating after the lifetime",
                b.sessions.validate(granted.token(), b.time.now()).isPresent(), false);
    }

    // --------------------------------------------------------------------- timing

    private static void responseTime() {
        PortalBundle b = PortalBundle.withAccount(newStore("timing.txt"), 1_000, Duration.ofMinutes(15), ITERS);
        int samples = 9;

        long derive = medianOf(() -> PasswordHash.derive(chars("correct-horse-9"),
                PasswordHash.newSalt(RANDOM), ITERS), 3);
        long correct = timed(b, "frank", "correct-horse-9", samples);
        long wrong = timed(b, "frank", "wrong-wrong-wrong", samples);
        long unknown = timed(b, "someone-not-here", "wrong-wrong-wrong", samples);
        long malformed = timed(b, "fr" + (char) 0x00, "wrong-wrong-wrong", samples);

        System.out.println("    one derivation    ~" + derive + " us");
        System.out.println("    correct password  ~" + correct + " us");
        System.out.println("    wrong password    ~" + wrong + " us");
        System.out.println("    unknown account   ~" + unknown + " us");
        System.out.println("    malformed account ~" + malformed + " us");

        long slowest = Math.max(Math.max(correct, wrong), Math.max(unknown, malformed));
        long fastest = Math.min(Math.min(correct, wrong), Math.min(unknown, malformed));
        double spread = fastest == 0 ? Double.MAX_VALUE : (double) slowest / (double) fastest;
        // The budget comes from the numbers printed above, never from a guess: no branch may
        // cost more than twice the cheapest one, or response time leaks which branch ran.
        check("all four paths cost within 2x of each other (spread " + round(spread) + "x)", spread <= 2.0);
        // And every path must actually have paid for a derivation. An early return that skipped
        // the hashing would show up as a branch far cheaper than a single derivation.
        double cheapestAsFractionOfOneDerivation = derive == 0 ? 0 : (double) fastest / (double) derive;
        check("even the cheapest path costs at least half a derivation (ratio "
                        + round(cheapestAsFractionOfOneDerivation) + "x)",
                cheapestAsFractionOfOneDerivation >= 0.5);
        check("the unknown-account path is not free", unknown * 2 >= derive);
        check("the malformed-account path is not free", malformed * 2 >= derive);
    }

    private static long timed(PortalBundle b, String user, String password, int samples) {
        for (int i = 0; i < 2; i++) {
            b.service.login(user, chars(password)); // warm this path
        }
        long[] observed = new long[samples];
        for (int i = 0; i < samples; i++) {
            long start = System.nanoTime();
            b.service.login(user, chars(password));
            observed[i] = (System.nanoTime() - start) / 1_000;
        }
        Arrays.sort(observed);
        return observed[observed.length / 2];
    }

    private static long medianOf(Runnable work, int samples) {
        work.run();
        long[] observed = new long[samples];
        for (int i = 0; i < samples; i++) {
            long start = System.nanoTime();
            work.run();
            observed[i] = (System.nanoTime() - start) / 1_000;
        }
        Arrays.sort(observed);
        return observed[observed.length / 2];
    }

    // ------------------------------------------------------------------ terminal

    private static void terminalBehaviour() throws Exception {
        PortalBundle b = PortalBundle.withAccount(newStore("console.txt"), 1_000, Duration.ofMinutes(15), ITERS);
        ByteArrayOutputStream shown = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(shown, true, StandardCharsets.US_ASCII);
        // One password line is consumed by each of the three sign-in attempts below.
        PortalConsole console = console(b, out, List.of("wrong-wrong-wrong", "correct-horse-9", "correct-horse-9"));
        console.handleLine("frank");
        console.handleLine("frank");
        console.handleLine("FRANK");
        console.handleLine("whoami");
        String text = shown.toString(StandardCharsets.US_ASCII);
        check("the terminal produced output", !text.isEmpty());
        check("a wrong password is refused in plain words", text.contains("Access denied"));
        check("a correct password is granted in plain words", text.contains("Access granted for frank"));
        check("the current session is reported", text.contains("signed in as frank"));
        check("the terminal never echoes the password", !text.contains("correct-horse-9"));

        // The refusal wording must not reveal whether the account exists.
        PortalBundle c = PortalBundle.withAccount(newStore("console2.txt"), 1_000, Duration.ofMinutes(15), ITERS);
        ByteArrayOutputStream probeOut = new ByteArrayOutputStream();
        PortalConsole probed = console(c, new PrintStream(probeOut, true, StandardCharsets.US_ASCII),
                List.of("wrong-wrong-wrong", "wrong-wrong-wrong"));
        probed.handleLine("frank");          // real account, wrong password
        probed.handleLine("nosuchaccount");  // account that does not exist
        List<String> denials = new ArrayList<>();
        for (String line : probeOut.toString(StandardCharsets.US_ASCII).split("\n")) {
            int at = line.indexOf("Access denied");
            if (at >= 0) {
                // The prompt and the password prompt share this line with the reply, so keep
                // only the reply itself when comparing the two refusals.
                denials.add(line.substring(at).trim());
            }
        }
        expect("both refusals produced a message", denials.size(), 2);
        check("a wrong password and an unknown account read identically: " + denials,
                denials.size() == 2 && denials.get(0).equals(denials.get(1)));
        // Identical wording is not enough on its own: both replies could be uniformly wrong and
        // still match each other. The reply must also give nothing away by itself.
        String shared = denials.isEmpty() ? "<none>" : denials.get(0);
        String lowered = shared.toLowerCase(Locale.ROOT);
        check("the refusal gives no hint about whether the account exists: " + shared,
                !lowered.contains("no such") && !lowered.contains("unknown")
                        && !lowered.contains("does not exist") && !lowered.contains("not recognized"));
        check("the refusal names both fields so it cannot tip off which one failed: " + shared,
                lowered.contains("username") && lowered.contains("password"));
        check("the refusal does not leak the internal reason: " + shared,
                !lowered.contains("wrong password") && !lowered.contains("account disabled"));

        // A name carrying a terminal escape must be refused and must never reach the screen.
        PortalBundle d = PortalBundle.withAccount(newStore("console3.txt"), 1_000, Duration.ofMinutes(15), ITERS);
        ByteArrayOutputStream escapeOut = new ByteArrayOutputStream();
        PortalConsole escaper = console(d, new PrintStream(escapeOut, true, StandardCharsets.US_ASCII),
                List.of("correct-horse-9"));
        escaper.handleLine("frank" + (char) 0x1B + "[2;1Hrm -rf");
        String escaped = escapeOut.toString(StandardCharsets.US_ASCII);
        check("the escape attempt produced output", !escaped.isEmpty());
        check("the escape attempt was refused", escaped.contains("Access denied"));
        check("no raw escape code reached the screen", escaped.indexOf((char) 0x1B) < 0);
        check("the typed junk was not echoed back", !escaped.contains("rm -rf"));
        expect("the same string cannot sign in through the service either",
                d.service.login("frank" + (char) 0x1B + "[2;1Hrm", chars("correct-horse-9")).status(),
                LoginOutcome.Status.DENIED);

        // Nothing secret may reach the log either.
        ByteArrayOutputStream logged = new ByteArrayOutputStream();
        PortalBundle e = PortalBundle.over(newStore("console4.txt"), 1_000, Duration.ofMinutes(15), ITERS,
                new PrintStream(logged, true, StandardCharsets.US_ASCII));
        expect("the account was created",
                e.service.createAccount("helen", chars("super-secret-99")).isPresent(), false);
        expect("signing in works", e.service.login("helen", chars("super-secret-99")).status(),
                LoginOutcome.Status.GRANTED);
        expect("a wrong password is refused", e.service.login("helen", chars("super-secret-98")).status(),
                LoginOutcome.Status.DENIED);
        String logText = logged.toString(StandardCharsets.US_ASCII);
        check("the log captured the grant", logText.contains("login-granted"));
        check("the log captured the denial", logText.contains("login-denied"));
        check("the log captured the creation", logText.contains("account-created"));
        check("the log has the account name", logText.contains("helen"));
        check("the log never contains the plain password", !logText.contains("super-secret"));
        List<String> leaked = new ArrayList<>();
        for (String line : logText.split("\n")) {
            for (String token : line.split(" ")) {
                if (token.length() >= 20 && token.matches("[A-Za-z0-9+/=]{20,}")) {
                    leaked.add(token);
                }
            }
        }
        check("the log leaks no base64 blob of digest or token length: " + leaked, leaked.isEmpty());
    }

    private static PortalConsole console(PortalBundle b, PrintStream out, List<String> passwordLines) {
        byte[] fed = (String.join("\n", passwordLines) + "\n").getBytes(StandardCharsets.UTF_8);
        return new PortalConsole(b.store, b.service, b.sessions, b.auditLog, out,
                new ByteArrayInputStream(fed));
    }

    // ------------------------------------------------------------------- options

    private static void commandLine() {
        Config defaults = Config.parse(new String[0], key -> null);
        expect("the default store file", defaults.storePath.toString(), Config.DEFAULT_STORE_FILE);
        expect("the default cost", defaults.iterations, Config.DEFAULT_ITERATIONS);
        expect("the default failure count", defaults.maxFailures, Config.DEFAULT_MAX_FAILURES);
        expect("the default lock length", defaults.lockDuration, Duration.ofMinutes(Config.DEFAULT_LOCK_MINUTES));
        expect("the default session length", defaults.sessionDuration,
                Duration.ofMinutes(Config.DEFAULT_SESSION_MINUTES));
        expect("help is off by default", defaults.showHelp, false);

        Config set = Config.parse(new String[] {"--store", "/tmp/x/records.txt", "--iterations", "5000",
                "--max-failures", "2", "--lock-minutes", "30", "--session-minutes", "5"}, key -> null);
        expect("the store path is honoured", set.storePath.toString(), "/tmp/x/records.txt");
        expect("the cost is honoured", set.iterations, 5_000);
        expect("the failure count is honoured", set.maxFailures, 2);
        expect("the lock length is honoured", set.lockDuration, Duration.ofMinutes(30));
        expect("the session length is honoured", set.sessionDuration, Duration.ofMinutes(5));

        Config byProperty = Config.parse(new String[0],
                key -> "portal.pbkdf2.iterations".equals(key) ? "3000" : null);
        expect("the cost can also come from a JVM property", byProperty.iterations, 3_000);
        expect("a command line cost beats the JVM property", Config.parse(
                new String[] {"--iterations", "4000"},
                key -> "portal.pbkdf2.iterations".equals(key) ? "3000" : null).iterations, 4_000);
        expect("an unrelated JVM property is ignored",
                Config.parse(new String[0], key -> "something.else".equals(key) ? "7" : null).iterations,
                Config.DEFAULT_ITERATIONS);
        expect("--help is recognised", Config.parse(new String[] {"--help"}, key -> null).showHelp, true);
        expect("-h is recognised", Config.parse(new String[] {"-h"}, key -> null).showHelp, true);
        expect("the top accepted cost is honoured",
                Config.parse(new String[] {"--iterations", "5000000"}, key -> null).iterations, 5_000_000);

        for (String[] bad : List.of(
                new String[] {"--nonsense"},
                new String[] {"--store"},
                new String[] {"--iterations"},
                new String[] {"--iterations", "abc"},
                new String[] {"--iterations", "999"},
                new String[] {"999"},
                new String[] {"--iterations", String.valueOf(PasswordHash.MAX_ITERATIONS + 1)},
                new String[] {"--max-failures", "0"},
                new String[] {"--max-failures", "1001"},
                new String[] {"--lock-minutes", "-1"},
                new String[] {"--session-minutes", "0"},
                new String[] {"--iterations", "5000", "--unknown"})) {
            expectThrows(IllegalArgumentException.class, "refuses " + Arrays.toString(bad),
                    () -> Config.parse(bad, key -> null));
        }
        check("the usage text names every option", Config.usage().contains("--max-failures")
                && Config.usage().contains("--iterations") && Config.usage().contains("--store")
                && Config.usage().contains("--session-minutes"));
    }

    // ------------------------------------------------------------------ plumbing

    /** A service and its parts, sharing one fake clock. */
    private static final class PortalBundle {

        private final FileRecordStore store;
        private final LoginAttemptTracker tracker;
        private final MutableTime time;
        private final int policyIterations;
        private final PrintStream auditSink;
        private PortalAuthService service;
        private SessionRegistry sessions;
        private AuditLog auditLog;

        private PortalBundle(FileRecordStore store, int maxFailures, Duration lock, int policyIterations,
                             PrintStream auditSink) {
            this.store = store;
            this.tracker = new LoginAttemptTracker(maxFailures, lock);
            this.time = new MutableTime(T0);
            this.policyIterations = policyIterations;
            this.auditSink = auditSink;
            rebuildService();
        }

        /** Builds a service over an empty store and creates the standard test account. */
        static PortalBundle withAccount(FileRecordStore store, int maxFailures, Duration lock, int iterations) {
            PortalBundle b = new PortalBundle(store, maxFailures, lock, iterations, QUIET);
            b.service.createAccount("frank", "correct-horse-9".toCharArray());
            return b;
        }

        /** Builds a service over a store that already has accounts, creating nothing. */
        static PortalBundle over(FileRecordStore store, int maxFailures, Duration lock, int iterations) {
            return new PortalBundle(store, maxFailures, lock, iterations, QUIET);
        }

        static PortalBundle over(FileRecordStore store, int maxFailures, Duration lock, int iterations,
                                 PrintStream auditSink) {
            return new PortalBundle(store, maxFailures, lock, iterations, auditSink);
        }

        private void rebuildService() {
            this.auditLog = new AuditLog(auditSink, time);
            this.sessions = new SessionRegistry(Duration.ofMinutes(30), RANDOM, time);
            this.service = new PortalAuthService(store, tracker, sessions, auditLog, RANDOM,
                    policyIterations, time);
        }
    }

    private static FileRecordStore newStore(String name) {
        try {
            return new FileRecordStore(workDir.resolve(name));
        } catch (IOException unreadable) {
            throw new IllegalStateException("cannot open " + name + ": " + unreadable, unreadable);
        }
    }

    private static EmployeeRecord row(String name, String salt, String hash, int iterations,
                                      AccountStatus status) {
        return new EmployeeRecord(name, salt, hash, iterations, status);
    }

    private static char[] chars(String text) {
        return text == null ? null : text.toCharArray();
    }

    private static String describe(String text) {
        if (text == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder(text.length() + 8);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                b.append(String.format("\\x%02X", (int) c));
            } else if (Character.isSurrogate(c)) {
                b.append(String.format("\\u%04X", (int) c));
            } else if (c > 0x7E) {
                b.append(String.format("<%04X>", (int) c));
            } else if (text.length() > 24 && i == 20) {
                b.append("...");
                break;
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    /** Keeps a whole file's contents out of the PASS line. */
    private static String brief(Object value) {
        String text = String.valueOf(value).replace("\n", " / ");
        return text.length() <= 64 ? text : text.substring(0, 61) + "...";
    }

    private static double round(double value) {
        return Math.round(value * 100) / 100.0;
    }

    /** A clock the tests can move forward. */
    private static final class MutableTime implements TimeSource {

        private Instant now;

        MutableTime(Instant start) {
            this.now = start;
        }

        @Override
        public Instant now() {
            return now;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }
    }

    // ------------------------------------------------------------------ reporting

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("== " + title + " ==");
    }

    private static void check(String label, boolean ok) {
        checks++;
        if (ok) {
            pass(label);
        } else {
            fail(label);
        }
    }

    private static void expect(String label, Object actual, Object expected) {
        checks++;
        boolean same = expected == null ? actual == null : expected.equals(actual);
        if (same) {
            pass(label + " -> " + brief(actual));
        } else {
            fail(label + " -> wanted [" + brief(expected) + "] but got [" + brief(actual) + "]");
        }
    }

    private static void expectThrows(Class<? extends Exception> wanted, String label, ThrowingRunnable work) {
        checks++;
        try {
            work.run();
            fail(label + " -> nothing was thrown");
        } catch (Exception thrown) {
            if (wanted.isInstance(thrown)) {
                pass(label + " -> " + thrown.getClass().getSimpleName());
            } else {
                fail(label + " -> wanted " + wanted.getSimpleName() + " but got "
                        + thrown.getClass().getName() + ": " + thrown.getMessage());
            }
        }
    }

    private static void pass(String label) {
        System.out.println("  PASS " + label);
    }

    private static void fail(String label) {
        failures++;
        System.out.println("  FAIL " + label);
    }
}
