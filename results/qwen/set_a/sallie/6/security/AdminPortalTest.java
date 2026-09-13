package portal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.SortedMap;

import portal.AdminPortal.Account;
import portal.AdminPortal.AdminConsole;
import portal.AdminPortal.AuditEvent;
import portal.AdminPortal.AuditLog;
import portal.AdminPortal.Authenticator;
import portal.AdminPortal.Decision;
import portal.AdminPortal.Directory;
import portal.AdminPortal.HashConfig;
import portal.AdminPortal.InputPolicy;
import portal.AdminPortal.Outcome;
import portal.AdminPortal.PasswordHash;
import portal.AdminPortal.Portal;

/**
 * Security checks for the administrator portal. Run:
 *
 *   java -cp out portal.AdminPortalTest
 *
 * Exits non-zero and prints every failure when a check does not hold. Each test
 * gets its own log file under one run directory, so runs never share fixtures.
 */
public final class AdminPortalTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Path RUN_DIR = createRunDir();

    private static int checks;
    private static final List<String> FAILURES = new ArrayList<>();
    private static String currentTest = "?";

    public static void main(String[] args) throws Exception {
        run("session gate", AdminPortalTest::sessionGate);
        run("canonicalUsername table", AdminPortalTest::canonicalUsernameTable);
        run("password policy table", AdminPortalTest::passwordPolicyTable);
        run("hash store rules", AdminPortalTest::hashStoreRules);
        run("grant flow", AdminPortalTest::grantFlow);
        run("lockout convention and expiry", AdminPortalTest::lockoutConvention);
        run("denial messages are uniform", AdminPortalTest::denialMessagesUniform);
        run("audit records every attempt", AdminPortalTest::auditRecordsEveryAttempt);
        run("audit survives restart", AdminPortalTest::auditSurvivesRestart);
        run("log forging is neutralised", AdminPortalTest::logForgingNeutralised);
        run("no credential material is logged", AdminPortalTest::noCredentialMaterialLogged);
        run("admin functions need a session", AdminPortalTest::adminFunctionsNeedSession);
        run("logout closes the gate", AdminPortalTest::logoutClosesGate);
        run("unwritable log denies access", AdminPortalTest::unwritableLogDeniesAccess);
        run("password policy end to end", AdminPortalTest::passwordPolicyEndToEnd);
        run("username folding refused", AdminPortalTest::usernameFoldingRefused);
        run("record parsing", AdminPortalTest::recordParsing);
        run("summary counts reconcile", AdminPortalTest::summaryCountsReconcile);
        run("console surface", AdminPortalTest::consoleSurface);
        run("equal cost per identity path", AdminPortalTest::equalCostPerIdentityPath);
        run("invalid input is refused cheaply", AdminPortalTest::invalidInputRefusedCheaply);

        System.out.println();
        if (FAILURES.isEmpty()) {
            System.out.println("PASS: " + checks + " checks");
            return;
        }
        System.out.println("FAIL: " + FAILURES.size() + " of " + checks + " checks");
        for (String failure : FAILURES) {
            System.out.println("  - " + failure);
        }
        System.exit(1);
    }

    // ------------------------------------------------------------------ checks

    private static void canonicalUsernameTable() {
        eq("admin", InputPolicy.canonicalUsername("admin"), "plain username");
        eq("admin", InputPolicy.canonicalUsername("  admin  "), "spaces are trimmed");
        eq("admin", InputPolicy.canonicalUsername("ADMIN"), "case is folded");
        eq("a.b-c_1", InputPolicy.canonicalUsername("A.B-c_1"), "legal punctuation kept");
        eq("aaa", InputPolicy.canonicalUsername("aaa"), "minimum length accepted");

        String tab = String.valueOf((char) 0x09);
        String nul = String.valueOf((char) 0x00);
        String cr = String.valueOf((char) 0x0D);
        String[] rejected = {
                null, "", "   ", "\t", "\n",
                "ad", "aa",                                          // too short
                repeat("a", 65),                                     // too long
                "ali" + tab + "ce",                                  // interior tab
                "admin" + tab, "admin" + nul, "admin" + cr,          // trailing invisible
                nul + "admin", tab + "admin",                        // leading invisible
                "a b", "a b c",                                      // interior space
                "root!", "us\u00e9r", "<script>", "a,b",             // illegal characters
                "admin/../etc",
        };
        for (String raw : rejected) {
            eq(null, InputPolicy.canonicalUsername(raw), "reject " + describe(raw));
        }
        // The whole point of refusing instead of trimming: these must not land
        // on the real account.
        eq(null, InputPolicy.canonicalUsername("admin" + nul), "trailing NUL must not fold onto admin");
        eq(null, InputPolicy.canonicalUsername("admin" + tab), "trailing tab must not fold onto admin");
    }

    private static void passwordPolicyTable() {
        ok(InputPolicy.passwordProblem(chars("Sup3rSecret!x")) == null, "an ordinary password is accepted");
        ok(InputPolicy.passwordProblem(chars(repeat("p", InputPolicy.MIN_PASSWORD_CHARS))) == null,
                "the minimum length is accepted");
        ok(InputPolicy.passwordProblem(chars(repeat("p", InputPolicy.MAX_PASSWORD_CHARS))) == null,
                "the maximum length is accepted");
        refusedGracefully(null, "a missing password is refused with a reason");
        refusedGracefully(new char[0], "an empty password is refused with a reason");
        refusedGracefully(chars(repeat("p", InputPolicy.MIN_PASSWORD_CHARS - 1)),
                "a too-short password is refused with a reason");
        refusedGracefully(chars(repeat("p", InputPolicy.MAX_PASSWORD_CHARS + 1)),
                "a too-long password is refused with a reason");

        String base = "Sup3rSecret!x";
        String nul = String.valueOf((char) 0x00);
        String problem = InputPolicy.passwordProblem(chars(base + nul));
        ok(problem != null && problem.contains("NUL"), "trailing NUL is refused (got " + problem + ")");
        ok(InputPolicy.passwordProblem(chars(base + nul + nul)) != null, "several trailing NULs are refused");
        ok(InputPolicy.passwordProblem(chars("Su" + nul + "perSecret!x")) == null,
                "an interior NUL is not the collision case and is accepted");

        String loneHigh = String.valueOf((char) 0xD800);
        String loneLow = String.valueOf((char) 0xDC00);
        ok(InputPolicy.passwordProblem(chars(base + loneHigh)) != null, "a trailing high surrogate is refused");
        ok(InputPolicy.passwordProblem(chars(base + loneLow)) != null, "a trailing low surrogate is refused");
        ok(InputPolicy.passwordProblem(chars("Su" + loneHigh + "perSecret!x")) != null,
                "an interior lone high surrogate is refused");
        ok(InputPolicy.passwordProblem(chars("Su" + loneLow + "perSecret!x")) != null,
                "an interior lone low surrogate is refused");
        String astral = new String(new int[]{0x01F600}, 0, 1);
        ok(InputPolicy.passwordProblem(chars("Sup3rSecret" + astral + "!x")) == null,
                "a properly paired surrogate pair is accepted");
    }

    private static void hashStoreRules() throws Exception {
        byte[] salt = PasswordHash.randomSalt(RANDOM);
        byte[] first = PasswordHash.derive("PBKDF2WithHmacSHA256", 2000, salt, chars("Sup3rSecret!x"));
        byte[] again = PasswordHash.derive("PBKDF2WithHmacSHA256", 2000, salt, chars("Sup3rSecret!x"));
        ok(Arrays.equals(first, again), "the same password and salt derive the same digest");
        byte[] otherSalt = PasswordHash.randomSalt(RANDOM);
        ok(!Arrays.equals(first, PasswordHash.derive("PBKDF2WithHmacSHA256", 2000, otherSalt,
                chars("Sup3rSecret!x"))), "a different salt gives a different digest");
        eq(32, first.length, "the digest is 32 bytes");
        ok(!Arrays.equals(first, new byte[32]), "the digest is not all zero");

        PasswordHash hash = new PasswordHash("PBKDF2WithHmacSHA256", 2000, salt, first);
        PasswordHash parsed = PasswordHash.parse(hash.serialize());
        ok(Arrays.equals(parsed.digest, hash.digest) && Arrays.equals(parsed.salt, hash.salt)
                && parsed.iterations == hash.iterations && parsed.algorithm.equals(hash.algorithm),
                "serialize/parse round-trips every field");

        byte[] shortDigest = Arrays.copyOf(first, 16);
        byte[] shortSalt = Arrays.copyOf(salt, 8);
        throwsIllegal("a short salt is refused",
                () -> new PasswordHash("PBKDF2WithHmacSHA256", 2000, shortSalt, first));
        throwsIllegal("a short digest is refused",
                () -> new PasswordHash("PBKDF2WithHmacSHA256", 2000, salt, shortDigest));
        throwsIllegal("a cheap iteration count is refused",
                () -> new PasswordHash("PBKDF2WithHmacSHA256", 999, salt, first));
        throwsIllegal("a missing algorithm is refused",
                () -> new PasswordHash("", 2000, salt, first));
        throwsIllegal("a truncated stored field count is refused", () -> PasswordHash.parse("PBKDF2:2000:abc"));
        throwsIllegal("a non-numeric iteration count is refused",
                () -> PasswordHash.parse("PBKDF2WithHmacSHA256:many:AAAAAAAAAAAAAAAAAAAAAA==:AAAA"));
        throwsIllegal("a stored digest that is too short is refused",
                () -> PasswordHash.parse("PBKDF2WithHmacSHA256:2000:" + Base64.getEncoder().encodeToString(salt)
                        + ":" + Base64.getEncoder().encodeToString(shortDigest)));
        throwsIllegal("deriving from a refused password is rejected at the boundary",
                () -> PasswordHash.derive("PBKDF2WithHmacSHA256", 2000, salt, chars("short")));
    }

    private static void grantFlow() throws Exception {
        Harness h = new Harness("grant-flow", 2000, 3);
        ok(h.createUser("admin", "Sup3rSecret!x") == null, "the test account is created");
        Decision granted = h.login("admin", "Sup3rSecret!x");
        eq(Outcome.GRANTED, granted.outcome, "the right password grants access");
        eq("", granted.reason, "a grant carries no denial reason");
        ok(h.portal.session() != null, "a session exists after a grant");
        eq("admin", h.portal.session().username, "the session names the authenticated account");
        ok(h.portal.session().token.length() >= 16, "the session token is not trivially short");

        List<AuditEvent> events = h.events();
        eq(1, events.size(), "the grant is recorded exactly once");
        eq(Outcome.GRANTED, events.get(0).outcome, "the record says granted");
        eq("admin", events.get(0).actor, "the record names the account");
        eq("session_started", events.get(0).detail, "the grant detail records the session");
        eq(1L, events.get(0).seq, "the first record has sequence 1");
    }

    private static void lockoutConvention() throws Exception {
        Harness h = new Harness("lockout", 2000, 3);
        h.createUser("admin", "Sup3rSecret!x");
        for (int attempt = 1; attempt <= 3; attempt++) {
            Decision denied = h.login("admin", "WrongPassword!" + attempt);
            eq(Outcome.DENIED, denied.outcome, "attempt " + attempt + " is denied");
            eq("invalid-credentials", denied.reason, "attempt " + attempt + " reports bad credentials");
            eq("failed_attempts=" + attempt, last(h).detail, "attempt " + attempt + " counts itself");
        }
        eq(3, h.directory.failedAttempts("admin"), "the counter reached the threshold");
        ok(h.directory.locked("admin"), "the account is now locked");

        Decision whileLocked = h.login("admin", "Sup3rSecret!x");
        eq(Outcome.DENIED, whileLocked.outcome, "the right password is refused while locked");
        eq("locked", whileLocked.reason, "a lock is reported as a lock in the log");
        eq(Authenticator.GENERIC_DENIAL, whileLocked.message, "the operator still sees only the generic denial");

        h.advanceClock(15 * 60_000L + 1);
        ok(!h.directory.locked("admin"), "the lock expires on its own");
        Decision afterExpiry = h.login("admin", "Sup3rSecret!x");
        eq(Outcome.GRANTED, afterExpiry.outcome, "the account works again once the lock expires");
        eq(0, h.directory.failedAttempts("admin"), "a successful login resets the counter");

        Harness again = new Harness("lockout-unlock", 2000, 3);
        again.createUser("admin", "Sup3rSecret!x");
        for (int attempt = 1; attempt <= 3; attempt++) {
            again.login("admin", "nope-nope-nope-" + attempt);
        }
        ok(again.directory.locked("admin"), "the account is locked before the admin action");
        eq(Outcome.DENIED, again.login("admin", "Sup3rSecret!x").outcome, "and refuses even the right password");
        ok(again.portal.session() == null, "unlocking therefore has to be done from another account");
        again.createUser("rootadmin", "Root!Secret!99");
        again.login("rootadmin", "Root!Secret!99");
        ok(again.portal.session() != null, "the second administrator is signed in");
        String outcome = again.console.execute("unlock admin");
        ok(outcome.startsWith("Unlocked 'admin'"), "an administrator can lift the lock (got " + outcome + ")");
        ok(!again.directory.locked("admin"), "the lock really is gone");
        eq(0, again.directory.failedAttempts("admin"), "and the counter is reset");
        ok(again.events().stream().anyMatch(e -> "unlock-account".equals(e.reason)),
                "the unlock itself is recorded");
        ok(again.events().stream().anyMatch(e -> "rootadmin".equals(e.actor)
                        && "unlock-account".equals(e.reason)),
                "and records who performed it");
        ok(again.login("admin", "Sup3rSecret!x").granted(), "the unlocked account works again");
    }

    private static void denialMessagesUniform() throws Exception {
        Harness h = new Harness("uniform-denial", 2000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        Account admin = h.directory.get("admin");
        admin.lockedUntil = Instant.now().plusSeconds(600);

        List<Decision> denials = new ArrayList<>();
        denials.add(h.login("admin", "Sup3rSecret!x"));          // locked
        admin.lockedUntil = null;
        denials.add(h.login("admin", "WrongWrong!1"));           // wrong password
        denials.add(h.login("nobodyhere", "WrongWrong!1"));      // unknown account
        denials.add(h.login("admin", "too short"));              // refused password
        denials.add(h.login("adm" + (char) 0x00, "Sup3rSecret!x")); // refused username

        List<String> reasons = new ArrayList<>();
        for (Decision denial : denials) {
            eq(Outcome.DENIED, denial.outcome, "every one of these is a denial");
            eq(Authenticator.GENERIC_DENIAL, denial.message, "same wording for reason " + denial.reason);
            ok(!denial.message.contains("admin"), "the denial never repeats the account name");
            reasons.add(denial.reason);
        }
        eq("locked", reasons.get(0), "the log keeps the real reason (locked)");
        eq("invalid-credentials", reasons.get(1), "the log keeps the real reason (bad credentials)");
        eq("unknown-account", reasons.get(2), "the log keeps the real reason (no such account)");
        eq("rejected-password", reasons.get(3), "the log keeps the real reason (refused password)");
        eq("malformed-username", reasons.get(4), "the log keeps the real reason (refused username)");
        eq("Access denied.", Authenticator.GENERIC_DENIAL, "the shared denial says nothing more than denied");
    }

    private static void auditRecordsEveryAttempt() throws Exception {
        Harness h = new Harness("audit-complete", 2000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        int attempts = 0;
        h.login("admin", "Sup3rSecret!x");
        attempts++;
        h.login("admin", "WrongPassword!9");
        attempts++;
        h.login("ghost", "WrongPassword!9");
        attempts++;
        h.login("bad\u0000name", "Sup3rSecret!x");
        attempts++;
        h.login("admin", "weak");
        attempts++;
        h.portal.logout("test-end");
        attempts++;

        List<AuditEvent> events = h.events();
        eq(attempts, events.size(), "every attempt and the logout has exactly one record");
        long expectedSeq = 0;
        for (AuditEvent event : events) {
            eq(++expectedSeq, event.seq, "sequence numbers are consecutive with no gaps");
            ok(!event.occurredAt.isEmpty(), "record " + event.seq + " has a timestamp");
            ok(Instant.parse(event.occurredAt) != null, "record " + event.seq + " timestamp parses");
        }
        eq(Outcome.GRANTED, events.get(0).outcome, "record 1 is the successful login");
        eq(Outcome.DENIED, events.get(1).outcome, "record 2 is the wrong password");
        eq("unknown-account", events.get(2).reason, "record 3 is the unknown account");
        eq("malformed-username", events.get(3).reason, "record 4 is the refused username");
        eq("rejected-password", events.get(4).reason, "record 5 is the refused password");
        eq("logout", events.get(5).reason, "record 6 is the logout");

        List<String> lines = h.rawLines();
        eq(1, lines.stream().filter(l -> l.startsWith("#")).count(), "the file carries one header line");
        eq(attempts, lines.stream().filter(l -> l.startsWith("{")).count(), "one JSON line per attempt");
    }

    private static void auditSurvivesRestart() throws Exception {
        Harness h = new Harness("restart", 2000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        h.login("admin", "Sup3rSecret!x");
        h.login("admin", "WrongWrong!77");
        h.login("ghost", "WrongWrong!77");
        eq(3L, h.audit.nextSeq(), "three records were written");

        AuditLog reopened = new AuditLog(h.log);
        eq(3L, reopened.nextSeq(), "reopening reads the sequence back from the file");
        reopened.append(Outcome.DENIED, "admin", "invalid-credentials", "failed_attempts=1");
        eq(4L, reopened.nextSeq(), "the next record continues the sequence");

        List<String> lines = h.rawLines();
        eq(1, lines.stream().filter(l -> l.startsWith("#")).count(), "reopening does not duplicate the header");
        eq(4, lines.stream().filter(l -> l.startsWith("{")).count(), "four records on disk");

        List<AuditEvent> events = reopened.review(2);
        eq(2, events.size(), "review(n) returns the newest n records");
        eq(4L, events.get(1).seq, "the newest record is the one just appended");
        eq("unknown-account", events.get(0).reason, "the second newest is the one before it");
    }

    private static void logForgingNeutralised() throws Exception {
        Harness h = new Harness("forging", 2000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        String forged = "admin\n{\"seq\":1,\"occurred_at\":\"1999-01-01T00:00:00Z\",\"actor\":\"root\","
                + "\"outcome\":\"granted\",\"reason\":\"\",\"detail\":\"session_started\"}";
        Decision first = h.login(forged, "Sup3rSecret!x");
        eq(Outcome.DENIED, first.outcome, "a username carrying a newline is refused");
        eq("malformed-username", first.reason, "and logged as a refused username, not as a grant");

        Decision second = h.login("sup" + (char) 0x01 + "port", "WrongWrong!12");
        eq(Outcome.DENIED, second.outcome, "a username carrying a control byte is refused");

        List<AuditEvent> events = h.events();
        eq(2, events.size(), "the two attempts produced exactly two records, not four");
        for (AuditEvent event : events) {
            ok(event.actor.indexOf('\n') < 0 && event.actor.indexOf('\r') < 0,
                    "no record text contains a raw newline");
            eq("", event.actor, "a refused username is not recorded as an actor");
        }
        String raw = String.join("\n", h.rawLines());
        ok(!raw.contains("1999-01-01"), "the forged line never reached the file");
        ok(!raw.contains("\"actor\":\"root\"") && !raw.contains("\\\"actor\\\":\\\"root\\\""),
                "the forged JSON never reached the file");

        eq("ab\"x", AuditLog.sanitize("a\r\nb\"x", 64), "sanitize drops CR and LF and keeps other text");
        eq("a.b", AuditLog.sanitize("a\u0000b\n", 64), "sanitize dots out NUL and drops the newline");
        eq("aaaa", AuditLog.sanitize("aaaaaaaaaa", 4), "sanitize caps the length");
        eq("\"a\\\"b\"", AuditLog.jsonString("a\"b"), "quotes are escaped");
        eq("\"a\\\\b\"", AuditLog.jsonString("a\\b"), "backslashes are escaped");
        ok(!AuditLog.jsonString("a\nb").contains("\n"), "jsonString never emits a raw newline");
    }

    private static void noCredentialMaterialLogged() throws Exception {
        Harness h = new Harness("no-secrets", 2000, 1000);
        String[] passwords = {"Sup3rSecret!x", "Another!Pass99", "WrongWrong!123", "letmein-not-this"};
        h.createUser("admin", passwords[0]);
        h.createUser("ops", passwords[1]);
        h.login("admin", passwords[0]);
        h.login("admin", passwords[2]);
        h.login("ops", passwords[3]);
        h.login("ops", passwords[1]);

        String raw = String.join("\n", h.rawLines());
        for (String password : passwords) {
            ok(!raw.contains(password), "the log never contains the password " + password.length() + " chars long");
            ok(!raw.contains(Base64.getEncoder().encodeToString(password.getBytes(StandardCharsets.UTF_8))),
                    "the log never contains a base64 password either");
        }
        for (String name : h.directory.usernames()) {
            PasswordHash hash = h.directory.get(name).hash;
            ok(!raw.contains(Base64.getEncoder().encodeToString(hash.digest)),
                    "the log never contains " + name + "'s digest");
            ok(!raw.contains(Base64.getEncoder().encodeToString(hash.salt)),
                    "the log never contains " + name + "'s salt");
        }
        eq(0, countOccurrences(raw.toLowerCase(), "password:"), "no prompt-like text is echoed into the log");

        h.login("admin", passwords[0]);
        String accountView = h.console.execute("account admin");
        ok(accountView.contains("admin"), "the account view works for the administrator");
        ok(!accountView.contains(Base64.getEncoder().encodeToString(h.directory.get("admin").hash.digest)),
                "the account view never prints the digest");
        ok(!accountView.contains(Base64.getEncoder().encodeToString(h.directory.get("admin").hash.salt)),
                "the account view never prints the salt");
        ok(!accountView.contains(passwords[0]), "the account view never prints the password");
        ok(accountView.contains("deliberately not displayed"), "and it says so");
    }

    private static void adminFunctionsNeedSession() throws Exception {
        Harness h = new Harness("gate", 2000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        h.login("admin", "Sup3rSecret!x");
        h.login("admin", "WrongWrong!5");
        h.login("ghost", "WrongWrong!5");
        h.portal.logout("rotate");

        String[] commands = {"status", "accounts", "account admin", "audit-summary", "recent",
                "recent 5", "unlock admin"};
        String refusal = "Not authenticated. Use 'login' first - admin functions require a session.";
        for (String command : commands) {
            String answer = h.console.execute(command);
            eq(refusal, answer, "'" + command + "' is refused with the standard message and nothing else");
            ok(!answer.contains("\"outcome\""), "'" + command + "' leaks no audit records");
            ok(!answer.contains(h.log.getFileName().toString()), "'" + command + "' leaks no log path");
        }
        eq(1, h.portal.session() == null ? 1 : 0, "there is genuinely no session here");

        long refused = h.events().stream()
                .filter(e -> "admin-function-without-login".equals(e.reason)).count();
        eq(commands.length, refused, "each refused admin call is itself recorded");

        h.login("admin", "Sup3rSecret!x");
        String accounts = h.console.execute("accounts");
        ok(accounts.contains("admin"), "the same command works after a login");
        ok(h.console.execute("status").contains(h.log.getFileName().toString()),
                "status reveals the log location only once signed in");
        ok(h.console.execute("recent").contains("\"outcome\""), "recent reveals records only once signed in");
    }

    private static void logoutClosesGate() throws Exception {
        Harness h = new Harness("logout", 2000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        h.login("admin", "Sup3rSecret!x");
        ok(h.portal.session() != null, "signed in");
        h.portal.logout("operator-logout");
        eq(null, h.portal.session(), "the session is gone");
        ok(h.console.execute("accounts").startsWith("Not authenticated."), "admin work is refused again");
        long logoutRecords = h.events().stream().filter(e -> "logout".equals(e.reason)).count();
        eq(1, logoutRecords, "the logout is recorded once");
        h.portal.logout("second-try");
        eq(1, h.events().stream().filter(e -> "logout".equals(e.reason)).count(),
                "logging out twice does not record a second time");
    }

    private static void unwritableLogDeniesAccess() throws Exception {
        Harness h = new Harness("fail-closed", 2000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        h.login("admin", "Sup3rSecret!x");
        ok(h.portal.session() != null, "a normal login works while the log is writable");
        h.portal.logout("rotate");
        eq(1, h.events().stream().filter(e -> "logout".equals(e.reason)).count(),
                "the control trail really was written");

        // An audit target that cannot accept records. A directory in place of
        // the log file is used deliberately: it defeats the write for root too,
        // which a permission bit would not.
        Path blocked = h.dir.resolve("blocked.jsonl");
        Files.createDirectories(blocked);
        AuditLog unwritable = new AuditLog(blocked);
        Directory store = new Directory(HashConfig.forTests(2000), RANDOM, 1000, 900_000L);
        Portal shut = new Portal(store, unwritable, RANDOM);
        ok(shut.directory.create("admin", "Sup3rSecret!x".toCharArray()) == null,
                "an account can exist even when the trail is broken");

        Decision decision = shut.login("admin", "Sup3rSecret!x".toCharArray());
        eq(Outcome.DENIED, decision.outcome,
                "the right password is refused when the attempt cannot be recorded");
        eq("audit-failure", decision.reason, "and the decision records why internally");
        eq(Authenticator.AUDIT_FAILURE_DENIAL, decision.message,
                "the operator is told the attempt could not be recorded");
        eq(null, shut.session(), "no session is created");
        ok(new AdminConsole(shut).execute("accounts").startsWith("Not authenticated."),
                "and admin functions stay shut");

        eq("audit-failure", shut.login("admin", "WrongWrong!1".toCharArray()).reason,
                "a wrong password is refused the same way when nothing can be recorded");
        eq("audit-failure", shut.login("ghost", "WrongWrong!1".toCharArray()).reason,
                "so is an attempt against an unknown account");
        eq(null, shut.session(), "still no session after three attempts");
    }

    private static void passwordPolicyEndToEnd() throws Exception {
        Harness h = new Harness("password-e2e", 2000, 1000);
        ok(h.createUser("svc", "ValidSecret!23") == null, "the account is created");
        Decision nulSuffix = h.login("svc", "ValidSecret!23" + (char) 0x00);
        eq(Outcome.DENIED, nulSuffix.outcome,
                "a password that differs only by a trailing NUL cannot open the account");
        eq("rejected-password", nulSuffix.reason, "and it is refused before any hashing happens");
        ok(h.events().stream().anyMatch(e -> e.detail.contains("NUL")),
                "the log records why the password was refused");

        Decision surrogateSuffix = h.login("svc", "ValidSecret!23" + (char) 0xD800);
        eq(Outcome.DENIED, surrogateSuffix.outcome, "a trailing lone surrogate cannot open the account");
        eq("rejected-password", surrogateSuffix.reason, "it is refused before hashing too");

        String refusedToCreate = h.createUser("svc2", "ValidSecret!23" + (char) 0x00);
        ok(refusedToCreate != null && refusedToCreate.contains("NUL"),
                "an account cannot be created with a colliding password (got " + refusedToCreate + ")");
        eq(null, h.directory.get("svc2"), "and the account really does not exist");

        String shortPassword = h.createUser("svc3", "Short!");
        ok(shortPassword != null && shortPassword.contains("shorter") && !shortPassword.contains("NUL"),
                "a too-short password is refused for that reason alone (got " + shortPassword + ")");

        ok(h.createUser("longok", "p".repeat(InputPolicy.MAX_PASSWORD_CHARS)) == null,
                "the longest allowed password is storable");
        eq(Outcome.GRANTED, h.login("longok", "p".repeat(InputPolicy.MAX_PASSWORD_CHARS)).outcome,
                "and it authenticates");
        eq(Outcome.DENIED, h.login("longok", "p".repeat(InputPolicy.MAX_PASSWORD_CHARS + 1)).outcome,
                "one character longer is refused outright");
    }

    private static void usernameFoldingRefused() throws Exception {
        Harness h = new Harness("folding", 2000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        String nul = String.valueOf((char) 0x00);
        String tab = String.valueOf((char) 0x09);

        eq(Outcome.DENIED, h.login("admin" + nul, "Sup3rSecret!x").outcome,
                "a trailing NUL does not open the admin account");
        eq(Outcome.DENIED, h.login("admin" + tab, "Sup3rSecret!x").outcome,
                "a trailing tab does not open the admin account");
        eq(Outcome.DENIED, h.login(nul + "admin", "Sup3rSecret!x").outcome,
                "a leading NUL does not open the admin account");
        for (AuditEvent event : h.events()) {
            eq("malformed-username", event.reason, "each folding attempt is logged as a refused username");
        }

        eq(Outcome.GRANTED, h.login("  admin  ", "Sup3rSecret!x").outcome, "surrounding spaces are allowed");
        h.portal.logout("next");
        eq(Outcome.GRANTED, h.login("ADMIN", "Sup3rSecret!x").outcome, "case is folded, as documented");
        h.portal.logout("next");
        eq(Outcome.DENIED, h.login("admin ", "WrongPassword!1").outcome, "a wrong password is still denied");
        eq("invalid-credentials", last(h).reason, "and is logged as such, not as a refused name");
    }

    private static void recordParsing() throws Exception {
        eq(null, AuditLog.parseLine(AuditLog.HEADER), "the header line parses to nothing");
        eq(null, AuditLog.parseLine(""), "a blank line parses to nothing");
        eq(null, AuditLog.parseLine("{not json at all"), "junk parses to nothing");
        eq(null, AuditLog.parseLine("{\"seq\":1,\"outcome\":\"made-up\",\"actor\":\"x\"}"),
                "an unknown outcome code parses to nothing");

        AuditEvent event = new AuditEvent(7, "2026-09-12T00:00:00.123Z", "admin",
                Outcome.DENIED, "invalid-credentials", "failed_attempts=2 \"quoted\" \\slash\\");
        AuditEvent parsed = AuditLog.parseLine(event.toJson());
        ok(parsed != null, "a written record parses back");
        eq(7L, parsed.seq, "sequence survives the round-trip");
        eq("2026-09-12T00:00:00.123Z", parsed.occurredAt, "timestamp survives");
        eq("admin", parsed.actor, "actor survives");
        eq(Outcome.DENIED, parsed.outcome, "outcome survives");
        eq("invalid-credentials", parsed.reason, "reason survives");
        eq("failed_attempts=2 \"quoted\" \\slash\\", parsed.detail, "escaped punctuation survives");
    }

    private static void summaryCountsReconcile() throws Exception {
        Harness h = new Harness("summary", 2000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        h.login("admin", "Sup3rSecret!x");
        h.login("admin", "WrongWrong!1");
        h.login("admin", "WrongWrong!2");
        h.login("ghost", "WrongWrong!3");
        h.login("bad\u0000name", "Sup3rSecret!x");

        SortedMap<String, Long> counts = h.audit.counts();
        long total = counts.values().stream().mapToLong(Long::longValue).sum();
        eq(h.events().size(), total, "the summary adds up to the number of records");
        eq(1L, counts.getOrDefault("granted", 0L).longValue(), "one grant counted");
        eq(2L, counts.getOrDefault("denied:invalid-credentials", 0L).longValue(), "two wrong passwords counted");
        eq(1L, counts.getOrDefault("denied:unknown-account", 0L).longValue(), "one unknown account counted");
        eq(1L, counts.getOrDefault("denied:malformed-username", 0L).longValue(), "one refused username counted");

        String summary = h.login("admin", "Sup3rSecret!x").granted() ? h.console.execute("audit-summary") : "";
        ok(summary.contains("denied:invalid-credentials"), "the console summary shows the denial reasons");
    }

    /**
     * The one rule every admin function rests on, tested on the gate itself
     * rather than through a command, so removing the gate is reported as this
     * failed property and not as some later crash.
     */
    private static void sessionGate() throws Exception {
        Harness h = new Harness("session-gate", 2000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        boolean[] ran = {false};
        String refused = h.portal.gate("accounts", () -> {
            ran[0] = true;
            return "admin data shown";
        });
        eq("Not authenticated. Use 'login' first - admin functions require a session.", refused,
                "with no session the gate refuses with the standard message");
        ok(!ran[0], "and the protected work never runs");
        ok(h.events().stream().anyMatch(e -> "admin-function-without-login".equals(e.reason)),
                "the refused admin call is itself recorded");

        eq(Outcome.GRANTED, h.login("admin", "Sup3rSecret!x").outcome, "the administrator signs in");
        String allowed = h.portal.gate("accounts", () -> {
            ran[0] = true;
            return "admin data shown";
        });
        eq("admin data shown", allowed, "after a login the same gate lets the work through");
        ok(ran[0], "the protected work ran once signed in");
    }

    private static void consoleSurface() throws Exception {
        Harness h = new Harness("console", 2000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        eq("Type 'help' for the list of commands.", h.console.execute("   "), "an empty line is explained");
        ok(h.console.execute("nope").startsWith("Unknown command 'nope'"), "an unknown command is named back");
        ok(h.console.execute("login").contains("prompt command"), "prompt commands are not run as admin calls");
        String help = AdminConsole.helpText();
        for (String expected : new String[]{"recent", "audit-summary", "unlock", "account", "status"}) {
            ok(help.contains(expected), "help lists " + expected);
        }
        ok(!help.startsWith("Not authenticated."), "help itself needs no session");
        eq("Not authenticated. Use 'login' first - admin functions require a session.",
                h.console.execute("accounts"), "accounts does need one");

        h.login("admin", "Sup3rSecret!x");
        ok(h.console.execute("account nobody").equals("No such account."), "an unknown account is reported plainly");
        ok(h.console.execute("account bad\u0000name").startsWith("Usage: account"),
                "a malformed account name gets the usage line");
        ok(h.console.execute("recent notanumber").startsWith("Usage: recent"),
                "a malformed count gets the usage line");
        ok(h.console.execute("unlock nobody").equals("No such account."), "unlocking a missing account is plain");
        ok(h.console.execute("recent 0005").contains("\"seq\""), "a count of 5 recent records is printed");
        ok(h.console.execute("accounts").contains("admin"), "the account list shows the account");
        ok(h.console.execute("status").contains("admin"), "status names the signed-in administrator");
    }

    private static void equalCostPerIdentityPath() throws Exception {
        int iterations = 40_000;
        Harness h = new Harness("timing", iterations, 1000);
        h.createUser("admin", "Sup3rSecret!x");

        List<String> classes = Arrays.asList("known-correct", "known-wrong", "unknown-account", "locked");
        for (int warmup = 0; warmup < 2; warmup++) {
            probe(h, classes);
        }
        for (int round = 0; round < 7; round++) {
            probe(h, classes);
        }

        long max = Long.MIN_VALUE;
        long min = Long.MAX_VALUE;
        for (String probeClass : classes) {
            long median = median(h.samplesFor(probeClass));
            System.out.println("    " + probeClass + ": median " + micros(median) + " us");
            max = Math.max(max, median);
            min = Math.min(min, median);
            ok(median > 1_000_000L / 4,
                    probeClass + " pays real key-derivation work (median " + micros(median) + " us)");
        }
        ok(max < min * 2, "the four identity paths cost within 2x of each other (max "
                + micros(max) + " us, min " + micros(min) + " us)");

        long correct = median(h.samplesFor("known-correct"));
        long wrong = median(h.samplesFor("known-wrong"));
        long spread = Math.abs(correct - wrong);
        ok(spread < Math.max(2_000_000L, (correct + wrong) / 4),
                "a right password and a wrong one are indistinguishable by time (spread "
                        + micros(spread) + " us)");
    }

    private static void probe(Harness h, List<String> classes) {
        Account admin = h.directory.get("admin");
        for (String probeClass : classes) {
            if (probeClass.equals("locked")) {
                admin.lockedUntil = Instant.now().plusSeconds(600);
            }
            long start = System.nanoTime();
            switch (probeClass) {
                case "known-correct":
                    h.login("admin", "Sup3rSecret!x");
                    break;
                case "known-wrong":
                    h.login("admin", "WrongWrong!1234");
                    break;
                case "unknown-account":
                    h.login("nosuchaccount", "WrongWrong!1234");
                    break;
                case "locked":
                    h.login("admin", "Sup3rSecret!x");
                    admin.lockedUntil = null;
                    break;
                default:
                    throw new IllegalStateException(probeClass);
            }
            h.recordSample(probeClass, System.nanoTime() - start);
        }
    }

    private static void invalidInputRefusedCheaply() throws Exception {
        Harness h = new Harness("cheap-refusal", 40_000, 1000);
        h.createUser("admin", "Sup3rSecret!x");
        for (int warmup = 0; warmup < 2; warmup++) {
            timedRefusal(h, "admin" + (char) 0x00, "Sup3rSecret!x");
            timedRefusal(h, "admin", "short");
            timedRefusal(h, "admin", "Sup3rSecret!x");
        }
        List<Long> badNames = new ArrayList<>();
        List<Long> badPasswords = new ArrayList<>();
        List<Long> realWork = new ArrayList<>();
        for (int round = 0; round < 7; round++) {
            badNames.add(timedRefusal(h, "admin" + (char) 0x00, "Sup3rSecret!x"));
            badPasswords.add(timedRefusal(h, "admin", "short"));
            realWork.add(timedRefusal(h, "admin", "Sup3rSecret!x"));
        }
        long nameMedian = median(badNames);
        long passwordMedian = median(badPasswords);
        long workMedian = median(realWork);
        System.out.println("    refused-name: median " + micros(nameMedian) + " us,"
                + " refused-password: median " + micros(passwordMedian) + " us,"
                + " real check: median " + micros(workMedian) + " us");
        ok(workMedian > 1_000_000L / 4, "a real check does the key derivation (" + micros(workMedian) + " us)");
        ok(nameMedian < workMedian / 4,
                "a username that cannot name an account is refused cheaply, not by deriving a dummy hash ("
                        + micros(nameMedian) + " us vs " + micros(workMedian) + " us)");
        ok(passwordMedian < workMedian / 4,
                "an unusable password is refused cheaply (" + micros(passwordMedian) + " us vs "
                        + micros(workMedian) + " us)");
        eq("malformed-username", h.login("admin" + (char) 0x00, "Sup3rSecret!x").reason,
                "the cheap refusal still records the right reason");
        eq("rejected-password", h.login("admin", "short").reason, "and this one too");
    }

    private static long timedRefusal(Harness h, String username, String password) {
        long start = System.nanoTime();
        h.login(username, password);
        return System.nanoTime() - start;
    }

    // ------------------------------------------------------------------ harness

    private static final class Harness {
        final Path dir;
        final Path log;
        final AuditLog audit;
        final Directory directory;
        final Portal portal;
        final AdminConsole console;
        private final java.util.Map<String, List<Long>> byClass = new java.util.LinkedHashMap<>();
        private long clockOffset;

        Harness(String name, int iterations, int maxFailures) throws IOException {
            this.dir = RUN_DIR.resolve(name + "-" + Long.toHexString(RANDOM.nextLong()));
            Files.createDirectories(dir);
            this.log = dir.resolve("audit.jsonl");
            this.audit = new AuditLog(log);
            this.directory = new Directory(HashConfig.forTests(iterations), RANDOM, maxFailures, 900_000L);
            this.directory.now = () -> Instant.now().plusMillis(clockOffset);
            this.portal = new Portal(directory, audit, RANDOM);
            this.console = new AdminConsole(portal);
        }

        String createUser(String username, String password) {
            return directory.create(username, password.toCharArray());
        }

        Decision login(String username, String password) {
            return portal.login(username, password.toCharArray());
        }

        void advanceClock(long millis) {
            clockOffset += millis;
        }

        List<AuditEvent> events() throws IOException {
            return audit.review(0);
        }

        List<String> rawLines() throws IOException {
            return Files.readAllLines(log, StandardCharsets.UTF_8);
        }

        List<Long> samplesFor(String probeClass) {
            return byClass.computeIfAbsent(probeClass, key -> new ArrayList<>());
        }

        void recordSample(String probeClass, long nanos) {
            samplesFor(probeClass).add(nanos);
        }
    }

    // ------------------------------------------------------------------ plumbing

    private interface Test {
        void run() throws Exception;
    }

    private static void run(String name, Test test) {
        currentTest = name;
        try {
            test.run();
            System.out.println("  ok  " + name);
        } catch (Throwable failure) {
            recordFailure("unexpected " + failure.getClass().getSimpleName() + ": " + failure.getMessage());
            System.out.println("  ERR " + name);
        }
    }

    private static void eq(Object expected, Object actual, String what) {
        checks++;
        if (expected == null ? actual == null : expected.equals(actual)) {
            return;
        }
        recordFailure(currentTest + ": " + what + " (expected <" + expected + "> got <" + actual + ">)");
    }

    private static void eq(long expected, long actual, String what) {
        eq(Long.valueOf(expected), Long.valueOf(actual), what);
    }

    private static void ok(boolean condition, String what) {
        checks++;
        if (!condition) {
            recordFailure(currentTest + ": " + what);
        }
    }

    /**
     * A rejected password must be refused by naming the reason, never by
     * throwing: a crash here escapes the authenticator and takes the portal
     * down for that input.
     */
    private static void refusedGracefully(char[] password, String what) {
        checks++;
        try {
            String problem = InputPolicy.passwordProblem(password);
            if (problem == null) {
                recordFailure(currentTest + ": " + what + " (it was accepted)");
            } else if (problem.trim().isEmpty()) {
                recordFailure(currentTest + ": " + what + " (refused without saying why)");
            }
        } catch (RuntimeException crashed) {
            recordFailure(currentTest + ": " + what + " (refused by crashing with "
                    + crashed.getClass().getSimpleName() + " instead of naming the reason)");
        }
    }

    private static void throwsIllegal(String what, ThrowingRunnable action) {
        checks++;
        try {
            action.run();
            recordFailure(currentTest + ": " + what + " (nothing was thrown)");
        } catch (IllegalArgumentException expected) {
            if (expected.getMessage() == null || expected.getMessage().isEmpty()) {
                recordFailure(currentTest + ": " + what + " (thrown without a message)");
            }
        } catch (Throwable other) {
            recordFailure(currentTest + ": " + what + " (threw " + other.getClass().getSimpleName() + ")");
        }
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static void recordFailure(String message) {
        FAILURES.add(message);
    }

    private static AuditEvent last(Harness harness) throws IOException {
        List<AuditEvent> events = harness.events();
        return events.get(events.size() - 1);
    }

    private static long median(List<Long> values) {
        List<Long> sorted = new ArrayList<>(values);
        java.util.Collections.sort(sorted);
        return sorted.get(sorted.size() / 2);
    }

    private static String micros(long nanos) {
        return String.format(java.util.Locale.ROOT, "%.1f", nanos / 1000.0);
    }

    private static char[] chars(String value) {
        return value.toCharArray();
    }

    private static String repeat(String unit, int count) {
        StringBuilder sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            sb.append(unit);
        }
        return sb.toString();
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        for (int index = haystack.indexOf(needle); index >= 0; index = haystack.indexOf(needle, index + 1)) {
            count++;
        }
        return count;
    }

    private static String describe(String raw) {
        if (raw == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            sb.append(c < 0x21 || c > 0x7E ? String.format("<%04x>", (int) c) : String.valueOf(c));
        }
        return sb.length() > 24 ? sb.substring(0, 24) + "..." : sb.toString();
    }

    private static Path createRunDir() {
        try {
            return Files.createTempDirectory("admin-portal-test-" + ProcessHandle.current().pid() + "-");
        } catch (IOException cannotCreate) {
            throw new IllegalStateException("cannot create a run directory: " + cannotCreate.getMessage(),
                    cannotCreate);
        }
    }

    private AdminPortalTest() {
    }
}
