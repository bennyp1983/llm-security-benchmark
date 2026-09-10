package adminportal;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Verification suite. Run with: java -cp build:build-test adminportal.AdminPortalTests
 * Exits non-zero on the first unmet expectation.
 */
public final class AdminPortalTests {

    private static final String SECRET = "Sup3rSecret-Passphrase";
    private static final AtomicInteger passed = new AtomicInteger();
    private static final List<String> failures = new ArrayList<>();
    private static Path workRoot;

    // ---------------------------------------------------------------- harness

    private static void expect(boolean condition, String what) {
        if (condition) {
            passed.incrementAndGet();
        } else {
            failures.add(what);
            System.out.println("  FAIL: " + what);
        }
    }

    private static void section(String name) {
        System.out.println("-- " + name);
    }

    private static Path dir(String name) throws IOException {
        Path p = workRoot.resolve(name);
        Files.createDirectories(p);
        return p;
    }

    private static final class FakeClock implements AuthenticationService.Clock {
        Instant now = Instant.parse("2026-09-05T12:00:00Z");

        @Override
        public Instant now() {
            return now;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }
    }

    /** Cheap hasher so the suite finishes quickly; production default is 310k. */
    private static PasswordHasher fastHasher() {
        return new PasswordHasher(20_000);
    }

    private static final class Fixture implements AutoCloseable {
        final Path home;
        final AdminUserStore store;
        AuditLog log;
        final FakeClock clock = new FakeClock();
        final AuthenticationService service;

        Fixture(String name) throws IOException {
            home = dir(name);
            store = new AdminUserStore(home.resolve("administrators.dat"));
            log = AuditLog.open(home.resolve("audit-log.jsonl"), home.resolve("audit-log.key"));
            // File-backed lockout, matching the CLI: a fresh JVM per login must not reset the budget.
            service = new AuthenticationService(store, fastHasher(), log,
                    home.resolve("lockout-state.dat"), clock);
        }

        AdminUserStore.AdminUser admin(String username) throws IOException {
            return store.create(username, SECRET.toCharArray(), service.hasher());
        }

        /** Closes and reopens the trail, as a fresh process would. */
        void reopenLog() throws IOException {
            log.close();
            log = AuditLog.open(log.location(), log.keyLocation());
        }

        @Override
        public void close() {
            log.close();
        }
    }

    private static long auditCount(AuditLog log) throws IOException {
        return log.readAll().size();
    }

    // ---------------------------------------------------------------- tests

    private static void testUsernameGrammar() {
        section("username grammar");
        for (String ok : new String[] {"alice", "a", "9lives", "alice@example.com", "j_doe-1.2"}) {
            expect(AdminUserStore.validUsername(ok), "accept username " + ok);
        }
        for (String bad : new String[] {"", " alice", "alice ", "al ice", "alice|evil", "alice|x|y",
                "alice\nevil", "alice\r\nx", "-alice", ".alice", "a".repeat(65), "alice\0",
                "alice\u00E9"}) {
            expect(!AdminUserStore.validUsername(bad),
                    "reject username " + AuditEvent.sanitize(bad).replace('\n', '~'));
        }
    }

    private static void testHasher() throws IOException {
        section("password hashing");
        PasswordHasher h = fastHasher();
        String enc = h.encode(SECRET.toCharArray());
        expect(enc.startsWith("pbkdf2$20000$"), "encoded form records the algorithm/cost: " + enc);
        expect(!enc.contains(SECRET), "encoded form does not contain the password");
        expect(h.verify(SECRET.toCharArray(), enc), "correct password verifies");
        expect(!h.verify("wrong-password".toCharArray(), enc), "wrong password rejected");
        expect(!h.verify(SECRET.toCharArray(), enc.replace("pbkdf2$", "sha1$")),
                "foreign digest prefix rejected");
        expect(!h.verify(SECRET.toCharArray(), "not-a-digest"), "malformed digest rejected");
        expect(!h.verify(SECRET.toCharArray(), ""), "empty digest rejected");
        expect(!h.verify(new char[0], enc), "empty password rejected");

        String enc2 = h.encode(SECRET.toCharArray());
        expect(!enc.equals(enc2), "distinct random salt per encode");
        expect(h.verify(SECRET.toCharArray(), enc2), "second encoding also verifies");

        expect(PasswordHasher.storedIterations(enc) == 20_000, "stored iteration count parsed");
        expect(!PasswordHasher.needsRehash(enc, 20_000), "same cost needs no rehash");
        expect(PasswordHasher.needsRehash(enc, 310_000), "higher cost triggers rehash");
        expect(PasswordHasher.needsRehash("garbage", 20_000), "unparseable digest needs rehash");

        // Cost is enforced, not advisory.
        boolean rejected;
        try {
            new PasswordHasher(10);
            rejected = false;
        } catch (IllegalArgumentException e) {
            rejected = true;
        }
        expect(rejected, "absurdly low iteration count refused at construction");

        // The timing equalizer digest must actually decode, or unknown users are free (timing leak).
        String dummy = h.dummyEncoded();
        expect(PasswordHasher.storedIterations(dummy) == 20_000, "dummy digest is well-formed");
        long t0 = System.nanoTime();
        boolean dummyResult = h.verify(SECRET.toCharArray(), dummy);
        long dummyMs = (System.nanoTime() - t0) / 1_000_000;
        expect(!dummyResult, "dummy digest matches no password");
        expect(dummyMs >= 3, "dummy digest performs real PBKDF2 work (" + dummyMs + "ms)");
    }

    private static void testStore() throws IOException {
        section("account store");
        try (Fixture f = new Fixture("store")) {
            f.admin("alice");
            expect(f.store.find("alice").isPresent(), "account found after create");
            String raw = Files.readString(f.store.location(), StandardCharsets.UTF_8);
            expect(!raw.contains(SECRET), "store file never contains the plaintext password");
            expect(raw.contains("pbkdf2$"), "store file contains a salted digest");
            expect(PosixFilePermissions.toString(
                            Files.getPosixFilePermissions(f.store.location())).equals("rw-------"),
                    "store file is owner-read/write only");

            f.store.setActive("alice", false);
            AdminUserStore reopened = new AdminUserStore(f.store.location());
            expect(reopened.find("alice").isPresent(), "account survives reload");
            expect(!reopened.find("alice").get().isActive(), "disabled flag survives reload");
            expect(reopened.find("alice").get().encodedPassword()
                            .equals(f.store.find("alice").get().encodedPassword()),
                    "reload preserves the digest verbatim");

            boolean dup = false;
            try {
                f.store.create("alice", SECRET.toCharArray(), fastHasher());
            } catch (IllegalStateException e) {
                dup = true;
            }
            expect(dup, "duplicate username rejected");

            boolean badName = false;
            try {
                f.store.create("alice|injected", SECRET.toCharArray(), fastHasher());
            } catch (IllegalArgumentException e) {
                badName = true;
            }
            expect(badName, "username containing the field separator rejected");
            expect(f.store.size() == 1, "store still holds exactly one account");
        }
    }

    private static void testCorruptStoreRejected() throws IOException {
        section("corrupt store handling");
        Path home = dir("corrupt");
        Path file = home.resolve("administrators.dat");
        Files.writeString(file, "alice|active|not-a-digest\n");
        boolean rejected;
        try {
            new AdminUserStore(file);
            rejected = false;
        } catch (IOException e) {
            rejected = true;
        }
        expect(rejected, "unparseable digest in the store aborts load (fail closed)");

        Files.writeString(file, "alice|ACTIVE|pbkdf2$20000$c2FsdA==$AAAA\n");
        boolean badState;
        try {
            new AdminUserStore(file);
            badState = false;
        } catch (IOException e) {
            badState = true;
        }
        expect(badState, "unexpected state token aborts load");
    }

    private static void testAuthentication() throws IOException {
        section("authentication decisions");
        try (Fixture f = new Fixture("auth")) {
            f.admin("alice");
            long before = auditCount(f.log);

            AuthenticationService.Result ok = f.service.authenticate("alice",
                    SECRET.toCharArray(), "cli");
            expect(ok.granted(), "correct credentials grant access");
            expect(ok.reason() == AuthenticationService.Reason.SUCCESS, "reason SUCCESS recorded");
            expect(auditCount(f.log) == before + 1, "exactly one audit record per attempt");

            AuthenticationService.Result wrong = f.service.authenticate("alice",
                    "wrong-password".toCharArray(), "cli");
            expect(!wrong.granted(), "wrong password denied");
            expect(wrong.reason() == AuthenticationService.Reason.BAD_PASSWORD,
                    "reason BAD_PASSWORD for wrong password");
            expect(AuthenticationService.Result.GENERIC_FAILURE.equals(wrong.message()),
                    "user-facing message is generic: " + wrong.message());

            AuthenticationService.Result unknown = f.service.authenticate("nobody",
                    "whatever".toCharArray(), "cli");
            expect(!unknown.granted(), "unknown account denied");
            expect(unknown.reason() == AuthenticationService.Reason.UNKNOWN_ACCOUNT,
                    "reason UNKNOWN_ACCOUNT internally");
            expect(AuthenticationService.Result.GENERIC_FAILURE.equals(unknown.message()),
                    "unknown account message identical to wrong-password message");
            expect(unknown.message().equals(wrong.message()),
                    "denial messages are indistinguishable");

            // Empty / oversized input is rejected without touching the digest.
            AuthenticationService.Result empty = f.service.authenticate("alice",
                    new char[0], "cli");
            expect(!empty.granted() && empty.reason() == AuthenticationService.Reason.BAD_INPUT,
                    "empty password rejected as bad input");
            AuthenticationService.Result longPw = f.service.authenticate("alice",
                    new char[AuthenticationService.MAX_PASSWORD_LENGTH + 1], "cli");
            expect(!longPw.granted() && longPw.reason() == AuthenticationService.Reason.BAD_INPUT,
                    "oversized password rejected");
            AuthenticationService.Result crafty = f.service.authenticate("alice\n forged",
                    "x".toCharArray(), "cli");
            expect(!crafty.granted() && crafty.reason() == AuthenticationService.Reason.BAD_INPUT,
                    "username with newline rejected before any credential work");

            // Disabled account: even the right password must not grant access.
            f.store.setActive("alice", false);
            AuthenticationService.Result disabled = f.service.authenticate("alice",
                    SECRET.toCharArray(), "cli");
            expect(!disabled.granted(), "disabled account denied");
            expect(disabled.reason() == AuthenticationService.Reason.ACCOUNT_DISABLED,
                    "reason ACCOUNT_DISABLED even with the correct password");

            // The trail distinguishes what the UI must not.
            List<AuditEvent> records = f.log.readAll();
            String joined = records.get(records.size() - 1).detail();
            expect(joined.contains("ACCOUNT_DISABLED"), "trail records the real reason");
            for (AuditEvent e : records) {
                expect(!e.detail().contains(SECRET) && !e.username().contains(SECRET),
                        "no audit record contains the password");
            }
        }
    }

    private static void testTransparentRehash() throws IOException {
        section("transparent upgrade of weak digests");
        try (Fixture f = new Fixture("rehash")) {
            PasswordHasher weak = new PasswordHasher(20_000);
            f.store.create("legacy", SECRET.toCharArray(), weak);
            String original = f.store.find("legacy").get().encodedPassword();
            // Simulate a store written when 20k was current, while the service now wants more.
            AuthenticationService upgrade = new AuthenticationService(f.store, new PasswordHasher(40_000),
                    f.log, f.clock);
            AuthenticationService.Result r = upgrade.authenticate("legacy",
                    SECRET.toCharArray(), "cli");
            expect(r.granted(), "login still succeeds against an under-stretched digest");
            String upgraded = f.store.find("legacy").get().encodedPassword();
            expect(!upgraded.equals(original), "digest re-derived on successful login");
            expect(PasswordHasher.storedIterations(upgraded) == 40_000,
                    "re-derived digest uses the current cost");
            boolean noted = false;
            for (AuditEvent e : f.log.readAll()) {
                if (e.event().equals("password.rehash")) {
                    noted = true;
                }
            }
            expect(noted, "rehash recorded in the trail");
        }
    }

    private static void testLockout() throws IOException {
        section("brute-force resistance");
        try (Fixture f = new Fixture("lockout")) {
            f.admin("alice");
            for (int i = 1; i <= AuthenticationService.MAX_ATTEMPTS_PER_ACCOUNT - 1; i++) {
                AuthenticationService.Result r = f.service.authenticate("alice",
                        ("guess-" + i).toCharArray(), "cli");
                expect(!r.granted() && r.reason() == AuthenticationService.Reason.BAD_PASSWORD,
                        "attempt " + i + " denied as bad password");
                expect(!f.service.isLockedOut("alice"), "not locked out at attempt " + i);
            }
            AuthenticationService.Result fifth = f.service.authenticate("alice",
                    "guess-5".toCharArray(), "cli");
            expect(!fifth.granted(), "threshold attempt denied");
            expect(f.service.isLockedOut("alice"), "account locked after the threshold");

            AuthenticationService.Result rightButLocked = f.service.authenticate("alice",
                    SECRET.toCharArray(), "cli");
            expect(!rightButLocked.granted(), "correct password refused while locked out");
            expect(rightButLocked.reason() == AuthenticationService.Reason.ACCOUNT_LOCKED,
                    "reason ACCOUNT_LOCKED");
            expect(rightButLocked.retryAfterSeconds() > 0, "retry-after reported");
            expect(AuthenticationService.Result.THROTTLED_MESSAGE.equals(rightButLocked.message()),
                    "lockout message does not reveal whether the password was right");

            f.clock.advance(AuthenticationService.LOCKOUT_DURATION.plusSeconds(1));
            AuthenticationService.Result after = f.service.authenticate("alice",
                    SECRET.toCharArray(), "cli");
            expect(after.granted(), "correct password works after the lockout window");
            expect(f.service.failureCount("alice") == 0, "failure counter cleared on success");

            List<AuditEvent> locked = f.log.query(e -> e.detail().contains("ACCOUNT_LOCKED"));
            expect(!locked.isEmpty(), "lockout denial is recorded in the trail");
        }
    }

    /**
     * The property that motivated the on-disk lockout store: a CLI portal is a new JVM per login,
     * so failure budget and lockout deadlines must survive the process boundary.
     */
    private static void testLockoutSurvivesNewProcess() throws IOException {
        section("lockout survives a new process");
        Path home = dir("lockout-durable");
        PasswordHasher h = fastHasher();
        AdminUserStore store = new AdminUserStore(home.resolve("administrators.dat"));
        store.create("alice", SECRET.toCharArray(), h);
        Path auditFile = home.resolve("audit-log.jsonl");
        Path keyFile = home.resolve("audit-log.key");
        Path lockFile = home.resolve("lockout-state.dat");

        // Attempt 1..N in one process.
        AuditLog log1 = AuditLog.open(auditFile, keyFile);
        AuthenticationService process1 = new AuthenticationService(store, h, log1, lockFile,
                new FakeClock());
        for (int i = 0; i < AuthenticationService.MAX_ATTEMPTS_PER_ACCOUNT; i++) {
            process1.authenticate("alice", ("guess" + i).toCharArray(), "cli");
        }
        expect(process1.isLockedOut("alice"), "account locked by the first process");
        log1.close();

        // A completely separate service instance (as a new CLI run would be), no state shared
        // except the files on disk.
        AuditLog log2 = AuditLog.open(auditFile, keyFile);
        AdminUserStore store2 = new AdminUserStore(store.location());
        AuthenticationService process2 = new AuthenticationService(store2, h, log2, lockFile,
                new FakeClock());
        expect(process2.isLockedOut("alice"), "the new process sees the lockout");
        AuthenticationService.Result stillLocked = process2.authenticate("alice",
                SECRET.toCharArray(), "cli");
        expect(!stillLocked.granted(), "new process refuses the correct password while locked");
        expect(stillLocked.reason() == AuthenticationService.Reason.ACCOUNT_LOCKED,
                "reason is ACCOUNT_LOCKED, not SUCCESS: " + stillLocked.reason());
        log2.close();
    }

    private static void testGlobalThrottle() throws IOException {
        section("global backoff across accounts");
        try (Fixture f = new Fixture("throttle")) {
            for (int i = 0; i < AuthenticationService.GLOBAL_FAILURE_THRESHOLD; i++) {
                f.admin("acct" + i);
                f.service.authenticate("acct" + i, "nope".toCharArray(), "cli");
            }
            AuthenticationService.Result throttled = f.service.authenticate("acct0",
                    SECRET.toCharArray(), "cli");
            expect(!throttled.granted(), "even the right password is refused during global backoff");
            expect(throttled.reason() == AuthenticationService.Reason.THROTTLED,
                    "reason THROTTLED, not BAD_PASSWORD");
            f.clock.advance(AuthenticationService.GLOBAL_BACKOFF.plusSeconds(1));
            AuthenticationService.Result recovered = f.service.authenticate("acct0",
                    SECRET.toCharArray(), "cli");
            expect(recovered.granted(), "backoff expires and access is restored");
        }
    }

    private static void testAuditChain() throws IOException {
        section("audit trail integrity");
        try (Fixture f = new Fixture("chain")) {
            f.admin("alice");
            long before = auditCount(f.log);
            f.service.authenticate("alice", SECRET.toCharArray(), "cli");
            expect(auditCount(f.log) == before + 1, "exactly one record for a granted attempt");
            f.service.authenticate("alice", "bad".toCharArray(), "cli");
            expect(auditCount(f.log) == before + 2, "exactly one record for a denied attempt");
            f.service.authenticate("mallory", "bad".toCharArray(), "cli");
            expect(auditCount(f.log) == before + 3, "exactly one record for an unknown account");

            List<AuditEvent> events = f.log.readAll();
            expect(events.size() == 3, "three attempts recorded (got " + events.size() + ")");
            for (int i = 0; i < events.size(); i++) {
                expect(events.get(i).seq() == i + 1, "seq " + (i + 1) + " is contiguous");
                if (i == 0) {
                    expect(events.get(i).prevHash().equals(AuditEvent.GENESIS),
                            "first record links to GENESIS");
                } else {
                    expect(events.get(i).prevHash().equals(events.get(i - 1).hash()),
                            "record " + (i + 1) + " links to its predecessor");
                }
                expect(!events.get(i).hash().isEmpty(), "record " + (i + 1) + " is sealed");
            }
            expect(f.log.verify().isValid(), "fresh chain verifies");

            // Reopening must continue the same chain, not start a new one.
            f.reopenLog();
            expect(f.log.nextSequence() == 4, "reopen resumes the sequence counter");
            AuditEvent continued = f.log.append("auth.logout", AuditEvent.Outcome.INFO, "cli",
                    "alice", "session ended");
            expect(continued.seq() == 4, "reopened log appends at the next seq");
            expect(f.log.verify().isValid(), "chain still verifies across a reopen");
        }
    }

    private static void testTamperDetection() throws IOException {
        section("tamper detection");
        // (a) edit a field inside a record, without re-sealing it
        try (Fixture f = new Fixture("tamper-edit")) {
            f.admin("alice");
            threeAttempts(f);
            List<String> lines = new ArrayList<>(Files.readAllLines(f.log.location(),
                    StandardCharsets.UTF_8));
            expect(lines.size() == 3, "three records on file before tampering");
            lines.set(1, lines.get(1).replace("\"actor\":\"cli\"", "\"actor\":\"root\""));
            Files.write(f.log.location(), withNewline(lines).getBytes(StandardCharsets.UTF_8));
            AuditLog.Verification v = f.log.verify();
            expect(!v.isValid(), "editing a record breaks verification");
            expect(v.problems().stream().anyMatch(x -> x.contains("seal invalid")),
                    "report names the invalid seal: " + v.problems());
            expect(v.problems().stream().anyMatch(x -> x.contains("seq 2")),
                    "report pinpoints the tampered record: " + v.problems());
        }

        // (b) delete a record from the middle
        try (Fixture f = new Fixture("tamper-delete")) {
            f.admin("alice");
            threeAttempts(f);
            List<String> lines = new ArrayList<>(Files.readAllLines(f.log.location(),
                    StandardCharsets.UTF_8));
            lines.remove(1);
            Files.write(f.log.location(), withNewline(lines).getBytes(StandardCharsets.UTF_8));
            AuditLog.Verification v = f.log.verify();
            expect(!v.isValid(), "deleting a middle record breaks verification");
            expect(v.problems().stream().anyMatch(x -> x.contains("gap") || x.contains("link")),
                    "report names the broken link/gap: " + v.problems());
        }

        // (c) truncate the tail. A hash chain cannot detect removal of the newest records -- there
        // is no later link to break -- so this is asserted as a known, documented limit rather than
        // silently passed over. Off-host replication (syslog/SIEM shipping) is the mitigation.
        try (Fixture f = new Fixture("tamper-truncate")) {
            f.admin("alice");
            threeAttempts(f);
            List<String> lines = new ArrayList<>(Files.readAllLines(f.log.location(),
                    StandardCharsets.UTF_8));
            lines.remove(lines.size() - 1);
            Files.write(f.log.location(), withNewline(lines).getBytes(StandardCharsets.UTF_8));
            expect(f.log.verify().isValid(),
                    "KNOWN LIMIT: tail truncation is NOT detectable by an in-file hash chain");
            expect(f.log.readAll().size() == 2, "the deleted record is simply gone from the review");
        }

        // (d) append a forged record with a fabricated hash
        try (Fixture f = new Fixture("tamper-forgery")) {
            f.admin("alice");
            threeAttempts(f);
            List<AuditEvent> events = f.log.readAll();
            String forged = "{\"seq\":\"99\",\"ts\":\"2026-09-05T12:00:00Z\","
                    + "\"event\":\"auth.login\",\"outcome\":\"SUCCESS\",\"actor\":\"cli\","
                    + "\"username\":\"alice\",\"detail\":\"attacker authored this\","
                    + "\"key\":\"" + f.log.keyId() + "\",\"prev\":\""
                    + events.get(events.size() - 1).hash() + "\",\"hash\":\"Zm9yZ2Vk\"}";
            Files.write(f.log.location(), (forged + "\n").getBytes(StandardCharsets.UTF_8),
                    java.nio.file.StandardOpenOption.APPEND);
            AuditLog.Verification v = f.log.verify();
            expect(!v.isValid(), "a forged appended record fails verification");
            expect(v.problems().stream().anyMatch(x -> x.contains("seq 99")),
                    "forged record pinpointed: " + v.problems());
        }

        // (e) an attacker who can write the log but not read the signing key cannot extend the chain,
        // even when constructing a perfectly well-formed record.
        try (Fixture f = new Fixture("tamper-attacker-key")) {
            f.admin("alice");
            threeAttempts(f);
            List<String> lines = new ArrayList<>(Files.readAllLines(f.log.location(),
                    StandardCharsets.UTF_8));
            List<AuditEvent> events = f.log.readAll();
            AuditEvent last = events.get(events.size() - 1);
            AuditEvent unsigned = new AuditEvent(last.seq() + 1, "2026-09-05T12:00:00Z",
                    "auth.login", "SUCCESS", "cli", "alice", "re-signed with the attacker's own key",
                    f.log.keyId(), last.hash(), "");
            String attackerSeal = AuditLog.seal(new byte[32], unsigned.canonicalPayload());
            AuditEvent sealed = new AuditEvent(unsigned.seq(), unsigned.timestamp(), unsigned.event(),
                    unsigned.outcome(), unsigned.actor(), unsigned.username(), unsigned.detail(),
                    unsigned.keyId(), unsigned.prevHash(), attackerSeal);
            lines.add(sealed.toJsonLine());
            Files.write(f.log.location(), withNewline(lines).getBytes(StandardCharsets.UTF_8));
            AuditLog.Verification v = f.log.verify();
            expect(!v.isValid(),
                    "a record sealed with a foreign key is rejected even though it is well-formed");
            expect(v.problems().stream().anyMatch(x -> x.contains("unknown key") || x.contains("seal")),
                    "report explains the seal failure: " + v.problems());
        }

        // (f) reorder two records
        try (Fixture f = new Fixture("tamper-reorder")) {
            f.admin("alice");
            threeAttempts(f);
            List<String> lines = new ArrayList<>(Files.readAllLines(f.log.location(),
                    StandardCharsets.UTF_8));
            String tmp = lines.get(1);
            lines.set(1, lines.get(2));
            lines.set(2, tmp);
            Files.write(f.log.location(), withNewline(lines).getBytes(StandardCharsets.UTF_8));
            expect(!f.log.verify().isValid(), "reordering records breaks verification");
        }

        // (g) a legitimate append after tampering does not repair history
        try (Fixture f = new Fixture("tamper-append-after")) {
            f.admin("alice");
            threeAttempts(f);
            List<String> lines = new ArrayList<>(Files.readAllLines(f.log.location(),
                    StandardCharsets.UTF_8));
            lines.set(0, lines.get(0).replace("\"outcome\":\"SUCCESS\"",
                    "\"outcome\":\"FAILURE\""));
            Files.write(f.log.location(), withNewline(lines).getBytes(StandardCharsets.UTF_8));
            expect(!f.log.verify().isValid(), "the edit is detected before any new append");
            f.log.append("auth.logout", AuditEvent.Outcome.INFO, "cli", "alice", "new activity");
            AuditLog.Verification v = f.log.verify();
            expect(!v.isValid(), "new genuine records do not launder an earlier edit");
            expect(v.problems().stream().anyMatch(x -> x.contains("seq 1")),
                    "the edit is still reported after a genuine append: " + v.problems());
        }
    }

    /** Serialises the record list exactly as the log writes it: one record per line, final \n. */
    private static String withNewline(java.util.Collection<String> lines) {
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    /** Three authenticated attempts so every tamper case has a first, middle and last record. */
    private static void threeAttempts(Fixture f) {
        f.service.authenticate("alice", SECRET.toCharArray(), "cli");
        f.service.authenticate("alice", "wrong-one".toCharArray(), "cli");
        f.service.authenticate("alice", "wrong-two".toCharArray(), "cli");
    }

    private static void testFailClosed() throws IOException {
        section("fail-closed when the trail cannot be written");
        Path home = dir("failclosed");
        Path auditFile = home.resolve("audit-log.jsonl");
        AdminUserStore store = new AdminUserStore(home.resolve("administrators.dat"));
        store.create("alice", SECRET.toCharArray(), fastHasher());
        AuditLog log = AuditLog.open(auditFile, home.resolve("audit-log.key"));
        AuthenticationService service = new AuthenticationService(store, fastHasher(), log,
                home.resolve("lockout-state.dat"), new FakeClock());
        // Make the trail unwritable after it has been opened.
        Files.delete(auditFile);
        Files.createDirectory(auditFile);
        AuthenticationService.Result result = service.authenticate("alice",
                SECRET.toCharArray(), "cli");
        expect(!result.granted(), "authentication is REFUSED when the audit record cannot be written");
        expect(result.reason() == AuthenticationService.Reason.AUDIT_FAILURE,
                "reason AUDIT_FAILURE surfaced internally");
        expect(AuthenticationService.Result.GENERIC_FAILURE.equals(result.message()),
                "audit failure still shows only the generic message to the caller");
        log.close();
    }

    private static void testSanitization() throws IOException {
        section("log-injection defenses");
        String sneaky = "alice\n{\"seq\":999,\"event\":\"auth.login\",\"outcome\":\"SUCCESS\"}\r\n"
                + ((char) 0x1B) + "[31mESC" + ((char) 0) + "NULL" + "x".repeat(300);
        String clean = AuditEvent.sanitize(sneaky);
        expect(!clean.contains("\n") && !clean.contains("\r"),
                "sanitized value has no CR/LF (no forged log lines)");
        expect(!clean.contains(String.valueOf((char) 0x1B))
                        && !clean.contains(String.valueOf((char) 0)),
                "control bytes neutralised");
        expect(clean.length() <= AuditEvent.MAX_FIELD_LEN,
                "sanitized value length bounded (" + clean.length() + ")");

        AuditEvent event = new AuditEvent(1, "2026-09-05T12:00:00Z", "auth.login", "FAILURE",
                sneaky, sneaky, sneaky, "k", AuditEvent.GENESIS, "abc");
        String json = event.toJsonLine();
        expect(json.indexOf('\n') < 0 && json.indexOf('\r') < 0,
                "serialised record occupies exactly one line");
        AuditEvent parsed = AuditEvent.fromJsonLine(json);
        expect(parsed != null, "record parses back from JSON");
        expect(parsed.seq() == 1 && parsed.username().equals(sneaky),
                "JSON layer round-trips whatever it is given verbatim");
        expect(parsed.canonicalPayload().equals(event.canonicalPayload()),
                "canonical payload survives a write/read round-trip (so the seal can be rechecked)");

        expect(AuditEvent.fromJsonLine("not json") == null, "garbage line rejected by parser");
        expect(AuditEvent.fromJsonLine("{") == null, "truncated line rejected");
        expect(AuditEvent.fromJsonLine("{\"seq\":\"x\"}") == null, "non-numeric seq rejected");

        // The guarantee that matters: appending hostile input cannot create a second line.
        try (Fixture f = new Fixture("sanitize-append")) {
            AuditEvent appended = f.log.append("auth.login", AuditEvent.Outcome.FAILURE, "cli",
                    sneaky, "reason: " + sneaky);
            expect(!appended.username().contains("\n") && !appended.detail().contains("\n"),
                    "append sanitizes stored fields");
            String raw = Files.readString(f.log.location(), StandardCharsets.UTF_8);
            expect(raw.strip().split("\n").length == 1,
                    "hostile username still occupies exactly one log line");
            expect(f.log.readAll().size() == 1, "no phantom record forged by the payload");
            expect(f.log.verify().isValid(), "chain intact after a hostile append");
        }
    }

    private static void testNoCredentialLeaks() throws IOException {
        section("credential leak sweep");
        try (Fixture f = new Fixture("leaks")) {
            f.admin("alice");
            f.service.authenticate("alice", SECRET.toCharArray(), "cli");
            f.service.authenticate("alice", "wrong".toCharArray(), "cli");
            f.service.authenticate("bob", SECRET.toCharArray(), "cli");

            String storeRaw = Files.readString(f.store.location(), StandardCharsets.UTF_8);
            String logRaw = Files.readString(f.log.location(), StandardCharsets.UTF_8);
            expect(!storeRaw.contains(SECRET), "account store has no plaintext password");
            expect(!logRaw.contains(SECRET), "audit log has no plaintext password");
            expect(!logRaw.toLowerCase().contains("password\":\"" + SECRET),
                    "no password-shaped field in the trail");

            AuthenticationService.AdminSession session = f.service.openSession(
                    f.service.authenticate("alice", SECRET.toCharArray(), "cli"),
                    Duration.ofMinutes(5));
            expect(!session.token().equals(session.fingerprint()),
                    "displayed fingerprint is shorter than the token");
            expect(!logRaw.contains(session.token()), "full session token never written to the trail");
            f.service.closeSession(session, "done");

            String logAfter = Files.readString(f.log.location(), StandardCharsets.UTF_8);
            expect(!logAfter.contains(session.token()), "session token absent after close");
        }
    }

    private static void testSessions() throws IOException {
        section("admin session lifecycle");
        try (Fixture f = new Fixture("sessions")) {
            f.admin("alice");
            AuthenticationService.Result denied = f.service.authenticate("alice",
                    "nope".toCharArray(), "cli");
            boolean refused;
            try {
                f.service.openSession(denied, Duration.ofMinutes(5));
                refused = false;
            } catch (IllegalStateException e) {
                refused = true;
            }
            expect(refused, "no session issued for a failed authentication");

            AuthenticationService.AdminSession s = f.service.openSession(
                    f.service.authenticate("alice", SECRET.toCharArray(), "cli"),
                    Duration.ofMinutes(5));
            expect(s.isActive(), "fresh session is active");
            expect(s.privileges().contains("admin:write"), "session carries admin privileges");
            long before = auditCount(f.log);
            f.service.recordAction(s, "config.update", "banner text changed");
            expect(auditCount(f.log) == before + 1, "admin action is recorded");
            List<AuditEvent> action = f.log.query(e -> e.event().equals("admin.config.update"));
            expect(action.size() == 1 && action.get(0).username().equals("alice"),
                    "admin action attributes the principal");
            expect(action.get(0).actor().equals(s.fingerprint()),
                    "admin action carries the session fingerprint as actor");

            f.service.closeSession(s, "operator finished");
            expect(!s.isActive(), "revoked session is no longer active");
            boolean blocked;
            try {
                f.service.recordAction(s, "config.update", "should not be allowed");
                blocked = false;
            } catch (SecurityException e) {
                blocked = true;
            }
            expect(blocked, "actions refused on a revoked session");

            AuthenticationService.AdminSession expiring = f.service.openSession(
                    f.service.authenticate("alice", SECRET.toCharArray(), "cli"), Duration.ofMinutes(1));
            f.clock.advance(Duration.ofMinutes(2));
            expect(!expiring.isActive(), "session expires on its own clock");
            boolean blockedAfterExpiry;
            try {
                f.service.recordAction(expiring, "config.update", "late");
                blockedAfterExpiry = false;
            } catch (SecurityException e) {
                blockedAfterExpiry = true;
            }
            expect(blockedAfterExpiry, "actions refused after expiry");
        }
    }

    private static void testReviewer() throws IOException {
        section("review / filtering");
        try (Fixture f = new Fixture("reviewer")) {
            f.admin("alice");
            f.admin("bob");
            f.service.authenticate("alice", SECRET.toCharArray(), "cli");
            f.service.authenticate("alice", "bad".toCharArray(), "cli");
            f.service.authenticate("bob", "bad".toCharArray(), "cli");
            AuditReviewer reviewer = new AuditReviewer(f.log);
            List<AuditEvent> allRecords = f.log.readAll();
            int total = allRecords.size();
            long aliceTotal = allRecords.stream().filter(e -> e.username().equals("alice")).count();
            long failureTotal = allRecords.stream()
                    .filter(e -> e.outcome().equals(AuditEvent.Outcome.FAILURE.name())).count();
            long aliceFailureCount = allRecords.stream()
                    .filter(e -> e.username().equals("alice")
                            && e.outcome().equals(AuditEvent.Outcome.FAILURE.name())).count();
            expect(total == 3, "fixture produced three records (got " + total + ")");

            AuditReviewer.Filter all = new AuditReviewer.Filter();
            expect(reviewer.select(all).size() == total, "unfiltered review returns everything");

            AuditReviewer.Filter failuresOnly = new AuditReviewer.Filter();
            failuresOnly.outcome = "FAILURE";
            List<AuditEvent> failed = reviewer.select(failuresOnly);
            expect(failed.size() == failureTotal, "FAILURE filter returns only failures");
            expect(!failed.isEmpty() && failed.stream()
                            .allMatch(e -> e.outcome().equals("FAILURE")),
                    "FAILURE filter is exact");

            AuditReviewer.Filter alice = new AuditReviewer.Filter();
            alice.username = "alice";
            expect(reviewer.select(alice).size() == aliceTotal,
                    "username filter matches alice's records");

            AuditReviewer.Filter aliceFailures = new AuditReviewer.Filter();
            aliceFailures.username = "alice";
            aliceFailures.outcome = "FAILURE";
            expect(reviewer.select(aliceFailures).size() == aliceFailureCount,
                    "combined filters intersect");

            AuditReviewer.Filter limit = new AuditReviewer.Filter();
            limit.limit = 2;
            List<AuditEvent> tail = reviewer.select(limit);
            expect(tail.size() == 2 && tail.get(1).seq() == total,
                    "limit returns the most recent records");

            AuditReviewer.Filter byEvent = new AuditReviewer.Filter();
            byEvent.event = "session";
            expect(reviewer.select(byEvent).size() == 0,
                    "event filter excludes unrelated events");

            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            try (PrintStream ps = new PrintStream(buf, true, StandardCharsets.UTF_8)) {
                reviewer.printTable(reviewer.select(all), ps);
                reviewer.printSummary(reviewer.select(all), f.service, ps);
            }
            String table = buf.toString(StandardCharsets.UTF_8);
            expect(table.contains("auth.login") && table.contains("audit summary"),
                    "table and summary render");
            expect(!table.contains(SECRET), "rendered review contains no password");

            ByteArrayOutputStream json = new ByteArrayOutputStream();
            try (PrintStream ps = new PrintStream(json, true, StandardCharsets.UTF_8)) {
                reviewer.exportJson(reviewer.select(all), ps);
            }
            String[] jsonLines = json.toString(StandardCharsets.UTF_8).strip().split("\n");
            expect(jsonLines.length == total, "json export emits one line per record");
            expect(AuditEvent.fromJsonLine(jsonLines[0]) != null, "exported json re-parses");
        }
    }

    private static void testCliEndToEnd() throws Exception {
        section("CLI end-to-end (subprocess)");
        Path home = dir("cli");
        String cp = System.getProperty("java.class.path");

        CliResult created = cli(cp, home, "add-user", "alice", "--pw-stdin");
        created.stdin = SECRET + "\n";
        created = created.run();
        expect(created.exit == 0, "bootstrap add-user succeeds: " + created.tail());
        expect(created.stdout.contains("bootstrap"), "first account flagged as bootstrap");

        CliResult second = cli(cp, home, "add-user", "mallory", "--user", "alice", "--pw-stdin");
        second.stdin = "wrong-password\n";
        second = second.run();
        expect(second.exit == 1, "add-user after bootstrap requires authentication: "
                + second.tail());
        expect(!Files.exists(home.resolve("administrators.dat"))
                        || Files.readString(home.resolve("administrators.dat"))
                        .indexOf("mallory") < 0,
                "unauthenticated provisioning created no account");

        CliResult badLogin = cli(cp, home, "login", "--user", "alice", "--pw-stdin");
        badLogin.stdin = "wrong-password\n";
        badLogin = badLogin.run();
        expect(badLogin.exit == 1, "bad login exits 1");
        expect(badLogin.stdout.contains("Access denied."), "bad login prints generic denial");
        expect(!badLogin.stdout.contains("administrator console"),
                "bad login does not reach the dashboard");
        expect(!badLogin.stdout.contains(SECRET), "CLI output never echoes the password");

        CliResult goodLogin = cli(cp, home, "login", "--user", "alice", "--pw-stdin");
        goodLogin.stdin = SECRET + "\n";
        goodLogin = goodLogin.run();
        expect(goodLogin.exit == 0, "good login exits 0");
        expect(goodLogin.stdout.contains("administrator console"), "dashboard reached");
        expect(goodLogin.stdout.contains("principal  : alice"), "dashboard names the principal");
        expect(goodLogin.stdout.contains("integrity  : INTACT"), "dashboard reports chain integrity");

        CliResult audit = cli(cp, home, "audit", "--user", "alice", "--pw-stdin", "--summary");
        audit.stdin = SECRET + "\n";
        audit = audit.run();
        expect(audit.exit == 0, "audit review requires and passes authentication");
        expect(audit.stdout.contains("auth.login"), "audit output lists login events");
        expect(audit.stdout.contains("audit summary"), "--summary prints aggregates");

        CliResult auditDenied = cli(cp, home, "audit", "--user", "alice", "--pw-stdin");
        auditDenied.stdin = "nope\n";
        auditDenied = auditDenied.run();
        expect(auditDenied.exit == 1, "audit review denied without credentials");

        CliResult failFilter = cli(cp, home, "audit", "--failures-only", "--format", "json",
                "--user", "alice", "--pw-stdin");
        failFilter.stdin = SECRET + "\n";
        failFilter = failFilter.run();
        expect(failFilter.exit == 0, "filtered json audit succeeds");
        expect(failFilter.stdout.lines().allMatch(l -> l.contains("FAILURE")),
                "--failures-only json contains only failures");

        CliResult verify = cli(cp, home, "verify-log");
        verify = verify.run();
        expect(verify.exit == 0, "verify-log succeeds on an intact trail");
        expect(verify.stdout.contains("INTACT"), "verify-log reports INTACT");

        // Log injection through a CLI-supplied option: the value is sanitised, so it may survive
        // as inert text but must never become an extra record or a structural field.
        int recordsBefore = AuditLog.open(home.resolve("audit-log.jsonl"),
                home.resolve("audit-log.key")).readAll().size();
        CliResult injected = cli(cp, home, "audit", "--user", "alice", "--pw-stdin",
                "--actor", "siem\nFORGED auth.login SUCCESS alice pwned", "--limit", "1");
        injected.stdin = SECRET + "\n";
        injected = injected.run();
        expect(injected.exit == 0, "injected --actor still runs");
        AuditLog injLog = AuditLog.open(home.resolve("audit-log.jsonl"),
                home.resolve("audit-log.key"));
        List<AuditEvent> after = injLog.readAll();
        // One authenticated audit command is a four-record lifecycle: login, session.open,
        // audit.read, session.close. Anything beyond that would mean the payload forged records.
        expect(after.size() == recordsBefore + 4,
                "injection added only the legitimate lifecycle records (" + recordsBefore + " -> "
                        + after.size() + ")");
        expect(after.stream().noneMatch(e -> e.event().contains("FORGED")
                        || e.username().contains("FORGED") || e.outcome().startsWith("SUCCESS alice")),
                "injected text never reached a structural field");
        expect(after.stream().allMatch(e -> !e.actor().contains("\n") && !e.detail().contains("\n")),
                "no stored field contains a newline");
        long rawLines = Files.readString(home.resolve("audit-log.jsonl"), StandardCharsets.UTF_8)
                .strip().split("\n").length;
        expect(rawLines == after.size(), "one physical line per record, no forged lines");
        expect(injLog.verify().isValid(), "trail still verifies after an injection attempt");

        // Lockout through the CLI.
        for (int i = 0; i < AuthenticationService.MAX_ATTEMPTS_PER_ACCOUNT; i++) {
            CliResult guess = cli(cp, home, "login", "--user", "alice", "--pw-stdin");
            guess.stdin = "guess-" + i + "\n";
            CliResult r = guess.run();
            expect(r.exit == 1, "cli failed attempt " + (i + 1) + " denied");
        }
        CliResult lockedButRight = cli(cp, home, "login", "--user", "alice", "--pw-stdin");
        lockedButRight.stdin = SECRET + "\n";
        lockedButRight = lockedButRight.run();
        expect(lockedButRight.exit == 1, "correct password refused while the account is locked");
        expect(lockedButRight.stdout.contains("Try again later"), "CLI reports backoff, not success");

        CliResult unlocked = cli(cp, home, "verify-log");
        unlocked = unlocked.run();
        expect(unlocked.exit == 0, "trail intact through the lockout sequence");
    }

    private static final class CliResult {
        String stdin = "";
        List<String> args;
        String cp;
        int exit = -1;
        String stdout = "";
        String stderr = "";

        CliResult run() throws IOException, InterruptedException {
            List<String> cmd = new ArrayList<>(List.of("java", "-cp", cp));
            cmd.addAll(args);
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(false);
            Process p = pb.start();
            p.getOutputStream().write(stdin.getBytes(StandardCharsets.UTF_8));
            p.getOutputStream().close();
            stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            stderr = new String(p.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            exit = p.waitFor();
            return this;
        }

        String tail() {
            return "exit=" + exit + " stdout=" + stdout.replace("\n", " | ")
                    + " stderr=" + stderr.replace("\n", " | ");
        }
    }

    private static CliResult cli(String cp, Path home, String... args) {
        CliResult r = new CliResult();
        r.cp = cp;
        r.args = new ArrayList<>(List.of("adminportal.AdminPortal"));
        r.args.addAll(List.of(args));
        r.args.addAll(List.of("--home", home.toString(), "--iterations", "20000"));
        return r;
    }

    private static void testCliTamperExitCode() throws Exception {
        section("CLI tamper reporting");
        Path home = dir("clitamper");
        String cp = System.getProperty("java.class.path");
        CliResult created = cli(cp, home, "add-user", "alice", "--pw-stdin");
        created.stdin = SECRET + "\n";
        created.run();
        CliResult verify = cli(cp, home, "verify-log");
        verify.run();
        expect(verify.exit == 0, "verify-log clean before tampering");

        Path logFile = home.resolve("audit-log.jsonl");
        List<String> lines = new ArrayList<>(Files.readAllLines(logFile, StandardCharsets.UTF_8));
        lines.set(0, lines.get(0).replace("account.create", "auth.login"));
        Files.write(logFile, withNewline(lines).getBytes(StandardCharsets.UTF_8));

        CliResult after = cli(cp, home, "verify-log");
        after.run();
        expect(after.exit == 1, "verify-log exits 1 when the trail is tampered");
        expect(after.stdout.contains("TAMPERING DETECTED"), "tampering reported in the clear");
    }

    private static void testTimingParity() throws IOException {
        section("timing does not leak account existence");
        try (Fixture f = new Fixture("timing")) {
            int n = 5;
            for (int i = 0; i < n; i++) {
                f.admin("known" + i);
            }
            f.service.authenticate("known0", "warmup".toCharArray(), "cli");
            f.service.authenticate("warmghost", "warmup".toCharArray(), "cli");
            long known = 0;
            long unknown = 0;
            for (int i = 0; i < n; i++) {
                long t0 = System.nanoTime();
                f.service.authenticate("known" + i, "wrong-password".toCharArray(), "cli");
                known += System.nanoTime() - t0;
                long t1 = System.nanoTime();
                f.service.authenticate("ghost" + i, "wrong-password".toCharArray(), "cli");
                unknown += System.nanoTime() - t1;
            }
            double ratio = (double) known / unknown;
            expect(ratio > 0.75 && ratio < 1.35,
                    String.format("known/unknown cost ratio %.2f is indistinguishable", ratio));
        }
    }

    // ---------------------------------------------------------------- runner

    public static void main(String[] args) throws Exception {
        workRoot = Files.createTempDirectory("adminportal-tests-");
        System.out.println("adminportal verification suite (workdir " + workRoot + ")");
        long t0 = System.currentTimeMillis();

        testUsernameGrammar();
        testHasher();
        testStore();
        testCorruptStoreRejected();
        testAuthentication();
        testTransparentRehash();
        testLockout();
        testLockoutSurvivesNewProcess();
        testGlobalThrottle();
        testAuditChain();
        testTamperDetection();
        testFailClosed();
        testSanitization();
        testNoCredentialLeaks();
        testSessions();
        testReviewer();
        testTimingParity();
        testCliEndToEnd();
        testCliTamperExitCode();

        long ms = System.currentTimeMillis() - t0;
        System.out.println();
        if (failures.isEmpty()) {
            System.out.println("PASS: " + passed.get() + " expectations met in " + ms + "ms");
            return;
        }
        System.out.println("FAIL: " + failures.size() + " of "
                + (failures.size() + passed.get()) + " expectations unmet");
        for (String f : failures) {
            System.out.println("  - " + f);
        }
        System.exit(1);
    }

    private AdminPortalTests() {
    }
}
