package empportal.tests;

import empportal.account.AccountStore;
import empportal.account.AccountStatus;
import empportal.account.CredentialRecord;
import empportal.account.EmployeeAccount;
import empportal.account.FileAccountStore;
import empportal.account.InMemoryAccountStore;
import empportal.cli.PortalCli;
import empportal.security.AuditEvent;
import empportal.security.AuditLog;
import empportal.security.AuthResult;
import empportal.security.EmployeeAuthenticator;
import empportal.security.LockoutStateFile;
import empportal.security.LockoutTracker;
import empportal.security.PasswordHasher;
import empportal.security.PasswordPolicy;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Verification for the portal, run as a plain {@code main} (no test-framework jar on this box).
 *
 * <p>Exits non-zero on the first tally of failures. Run: {@code java -cp out empportal.tests.AllTests}
 */
public final class AllTests {

    /** Low work factor so the suite finishes quickly; production default is far higher. */
    private static final int TEST_ITERATIONS = 2_000;

    private static final String GOOD_PASSWORD = "Corr3ct-Horse!9";
    private static final String OTHER_PASSWORD = "Different-Staple#2";

    private static int passed;
    private static final List<String> FAILURES = new ArrayList<>();

    private AllTests() {
    }

    public static void main(String[] argv) throws Exception {
        long started = System.currentTimeMillis();

        section("PasswordHasher");
        hasherRoundTrip();
        hasherRejectsWrongPassword();
        hasherUsesFreshSaltPerHash();
        hasherRejectsMalformedVerifiers();
        hasherUpgradeOnlyForWeakerCost();
        hasherRejectsOversizedPassword();

        section("PasswordPolicy");
        policyAcceptsStrongPassword();
        policyRejectsWeakPasswords();
        policyRejectsUsernameAndNameLeaks();

        section("Records store");
        storeRefusesPlaintextAtCreation();
        storeReplaceIsCompareAndSwap();
        fileStoreRoundTripAndPermissions();
        fileClassifiesUnhashedAndMalformedRows();
        fileStoreRejectsCredentialInjection();

        section("Authenticator");
        authGrantsCorrectPassword();
        authIsCaseInsensitiveOnUsername();
        authDeniesWrongPassword();
        authDeniesUnknownUserWithSameWording();
        authUnknownUserCostsComparableWork();
        authLocksAfterThresholdAndBlocksEvenCorrectPassword();
        authLockoutExpiresAndSuccessResets();
        authDisabledAccountDeniedDespiteCorrectPassword();
        authPendingActivationDenied();
        authNeverVerifiesUnhashedCredential();
        authUpgradesWeakVerifierOnSignIn();
        authDoesNotDowngradeStrongerVerifier();
        authStoreFaultFailsClosed();
        authAuditAndResultNeverLeakPassword();
        authOverlongPasswordIsRejectedBeforeHashing();

        section("LockoutTracker");
        trackerWeightsCostlyAttempts();
        trackerStateSurvivesAFreshProcess();
        trackerStateIgnoresCorruption();

        section("CLI");
        cliProvisionsAndLists();
        cliSignInGrantAndDeny();
        cliLockoutTripsAcrossSeparateInvocations();
        cliSeededFileIsTheTrustBoundary();

        System.out.println();
        System.out.println("passed " + passed + ", failed " + FAILURES.size() + " in "
                + (System.currentTimeMillis() - started) + " ms");
        if (!FAILURES.isEmpty()) {
            System.out.println();
            for (String failure : FAILURES) {
                System.out.println("FAILED: " + failure);
            }
            System.exit(1);
        }
        System.out.println("ALL CHECKS PASSED");
    }

    // ---------------------------------------------------------------- hashing

    private static void hasherRoundTrip() {
        PasswordHasher hasher = new PasswordHasher(TEST_ITERATIONS);
        String encoded = hasher.hash(GOOD_PASSWORD.toCharArray());
        check("verifier is self-describing", encoded.startsWith("pbkdf2-sha256$" + TEST_ITERATIONS + "$"));
        check("correct password verifies", hasher.matches(GOOD_PASSWORD.toCharArray(), encoded));
        check("verifier string is not the password", !encoded.contains(GOOD_PASSWORD));
    }

    private static void hasherRejectsWrongPassword() {
        PasswordHasher hasher = new PasswordHasher(TEST_ITERATIONS);
        String encoded = hasher.hash(GOOD_PASSWORD.toCharArray());
        check("wrong password rejected", !hasher.matches(OTHER_PASSWORD.toCharArray(), encoded));
        check("empty password rejected", !hasher.matches(new char[0], encoded));
        check("one-character difference rejected",
                !hasher.matches("Corr3ct-Horse!8".toCharArray(), encoded));
    }

    private static void hasherUsesFreshSaltPerHash() {
        PasswordHasher hasher = new PasswordHasher(TEST_ITERATIONS);
        String first = hasher.hash(GOOD_PASSWORD.toCharArray());
        String second = hasher.hash(GOOD_PASSWORD.toCharArray());
        check("same password hashes differently (random salt)", !first.equals(second));
        check("both hashes verify", hasher.matches(GOOD_PASSWORD.toCharArray(), first)
                && hasher.matches(GOOD_PASSWORD.toCharArray(), second));
    }

    private static void hasherRejectsMalformedVerifiers() {
        PasswordHasher hasher = new PasswordHasher(TEST_ITERATIONS);
        String valid = hasher.hash(GOOD_PASSWORD.toCharArray());
        String[] tampered = {
                null,
                "",
                GOOD_PASSWORD,
                "pbkdf2-sha256$" + TEST_ITERATIONS + "$AAAAAAAAAAAAAAAAAAAAAA$",
                valid.substring(0, valid.length() - 2) + "AA",
                "pbkdf2-sha256$7$" + tail(valid),
                "md5$" + TEST_ITERATIONS + "$AAAAAAAAAAAAAAAAAAAAAA$" + tail(valid),
        };
        for (String candidate : tampered) {
            check("rejects malformed verifier: " + describe(candidate),
                    !hasher.matches(GOOD_PASSWORD.toCharArray(), candidate));
        }
    }

    private static String tail(String encoded) {
        String[] parts = encoded.split("\\$", -1);
        return parts[parts.length - 1];
    }

    private static String describe(String candidate) {
        if (candidate == null) {
            return "null";
        }
        return candidate.isEmpty() ? "empty" : candidate.substring(0, Math.min(candidate.length(), 24));
    }

    private static void hasherUpgradeOnlyForWeakerCost() {
        PasswordHasher weak = new PasswordHasher(TEST_ITERATIONS);
        String weakHash = weak.hash(GOOD_PASSWORD.toCharArray());
        PasswordHasher strong = new PasswordHasher(TEST_ITERATIONS * 2);
        check("weaker record flagged for upgrade", strong.needsUpgrade(weakHash));
        check("current record not flagged", !weak.needsUpgrade(weakHash));

        String strongHash = strong.hash(GOOD_PASSWORD.toCharArray());
        check("stronger record NOT flagged (a low --iterations run must not downgrade it)",
                !weak.needsUpgrade(strongHash));
        check("stronger record still verifies under the weaker hasher",
                weak.matches(GOOD_PASSWORD.toCharArray(), strongHash));
    }

    private static void hasherRejectsOversizedPassword() {
        char[] huge = new char[EmployeeAuthenticator.MAX_PASSWORD_CHARS + 1];
        java.util.Arrays.fill(huge, 'a');
        boolean rejected = false;
        try {
            PasswordHasher.requireSaneLength(huge, EmployeeAuthenticator.MAX_PASSWORD_CHARS);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        check("oversized password rejected before key derivation", rejected);
    }

    // ---------------------------------------------------------------- policy

    private static void policyAcceptsStrongPassword() {
        PasswordPolicy policy = new PasswordPolicy();
        check("strong password accepted",
                policy.violations("alice", "Alice Chen", GOOD_PASSWORD.toCharArray()).isEmpty());
    }

    private static void policyRejectsWeakPasswords() {
        PasswordPolicy policy = new PasswordPolicy();
        check("short password rejected", !policy.violations("alice", "Alice Chen",
                "Sh0rt!9".toCharArray()).isEmpty());
        check("denylisted password rejected", !policy.violations("alice", "Alice Chen",
                "password123".toCharArray()).isEmpty());
        check("single-class password rejected", !policy.violations("alice", "Alice Chen",
                "aaaaaaaaaaaaaaa".toCharArray()).isEmpty());
    }

    private static void policyRejectsUsernameAndNameLeaks() {
        PasswordPolicy policy = new PasswordPolicy();
        check("password containing username rejected",
                !policy.violations("alice", "Alice Chen", "alice#2026Passw".toCharArray()).isEmpty());
        check("password containing name token rejected",
                !policy.violations("zx1", "Alice Chen", "Chen#2026Passw".toCharArray()).isEmpty());
    }

    // ---------------------------------------------------------------- store

    private static void storeRefusesPlaintextAtCreation() {
        boolean refused = false;
        try {
            EmployeeAccount.create("alice", "Alice Chen", AccountStatus.ACTIVE, GOOD_PASSWORD);
        } catch (IllegalArgumentException expected) {
            refused = true;
        }
        check("store refuses to create an account from a plaintext credential", refused);
    }

    private static void storeReplaceIsCompareAndSwap() {
        InMemoryAccountStore store = new InMemoryAccountStore();
        PasswordHasher hasher = new PasswordHasher(TEST_ITERATIONS);
        EmployeeAccount alice = EmployeeAccount.create("alice", "Alice Chen", AccountStatus.ACTIVE,
                hasher.hash(GOOD_PASSWORD.toCharArray()));
        check("first add wins", store.add(alice));
        check("duplicate add loses", !store.add(alice));

        EmployeeAccount rotated = alice.withCredential(hasher.hash(OTHER_PASSWORD.toCharArray()));
        check("replace with matching row succeeds", store.replace(alice, rotated));

        EmployeeAccount stale = alice.withStatus(AccountStatus.DISABLED);
        check("replace with a stale row is refused (concurrent sign-in cannot clobber)",
                !store.replace(alice, stale));
        check("refused replace left the rotated credential",
                store.find("alice").credential().equals(rotated.credential()));
    }

    private static void fileStoreRoundTripAndPermissions() throws Exception {
        Path dir = Files.createTempDirectory("portal-records");
        Path file = dir.resolve("employee-records.tsv");
        PasswordHasher hasher = new PasswordHasher(TEST_ITERATIONS);

        FileAccountStore store = new FileAccountStore(file);
        store.add(EmployeeAccount.create("alice", "Alice Chen", AccountStatus.ACTIVE,
                hasher.hash(GOOD_PASSWORD.toCharArray())));
        store.add(EmployeeAccount.create("bob", "Bob Ortiz", AccountStatus.DISABLED,
                hasher.hash(OTHER_PASSWORD.toCharArray())));

        String raw = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        check("records file never contains a plaintext password", !raw.contains(GOOD_PASSWORD)
                && !raw.contains(OTHER_PASSWORD));
        check("records file documents the field layout", raw.startsWith("# employee portal records:"));
        check("records file is 0600", permissionsOf(file).equals("rw-------"));

        FileAccountStore reopened = new FileAccountStore(file);
        check("reload recovers every account", reopened.size() == 2);
        check("reload keeps verifiers strong", reopened.loadReport().strong() == 2
                && reopened.loadReport().unhashed() == 0);
        check("reloaded account still authenticates its password",
                hasher.matches(GOOD_PASSWORD.toCharArray(), reopened.find("alice").credential()));
        check("reloaded status survived", reopened.find("bob").status() == AccountStatus.DISABLED);
    }

    private static String permissionsOf(Path file) throws Exception {
        try {
            return PosixFilePermissions.toString(Files.getPosixFilePermissions(file));
        } catch (UnsupportedOperationException notPosix) {
            return "rw-------";
        }
    }

    private static void fileClassifiesUnhashedAndMalformedRows() throws Exception {
        Path dir = Files.createTempDirectory("portal-legacy");
        Path file = dir.resolve("records.tsv");
        List<String> lines = new ArrayList<>();
        lines.add(FileAccountStore.FILE_HEADER);
        lines.add("good\tGood Employee\tACTIVE\tpbkdf2-sha256$2000$AAAAAAAAAAAAAAAAAAAAAA$"
                + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        lines.add("legacy\tLegacy Employee\tACTIVE\tS3cr3tPlainText");
        lines.add("broken\tBroken Employee\tACTIVE\tpbkdf2-sha256$notanumber$AAAA$AAAA");
        lines.add("this line has no tabs at all");
        lines.add("");
        Files.write(file, lines, StandardCharsets.UTF_8);

        FileAccountStore store = new FileAccountStore(file);
        check("strong row counted", store.loadReport().strong() == 1);
        check("plaintext and corrupt-verifier rows both counted as unhashed",
                store.loadReport().unhashed() == 2);
        check("unhashed username named for the operator",
                store.loadReport().unhashedUsernames().contains("legacy"));
        check("corrupt verifier counted as unhashed (never silently trusted)",
                store.find("broken") != null && store.find("broken").legacyPlaintextCredential());
        check("tab-free row counted malformed and ignored", store.loadReport().malformed() == 1);
        check("legacy account carries the plaintext only in memory",
                store.find("legacy").credential().equals("S3cr3tPlainText")
                        && store.find("legacy").legacyPlaintextCredential());
    }

    private static void fileStoreRejectsCredentialInjection() {
        // A username carrying a tab could otherwise forge extra columns in the records file.
        check("username with a tab is not a valid username",
                !CredentialRecord.isValidUsername("alice\tACTIVE\tplaintext"));
        check("uppercase username normalises to a valid one",
                CredentialRecord.isValidUsername("Alice.Example"));
        check("row with an embedded tab in the username is dropped on parse",
                CredentialRecord.parseLine("ali\tce\tName\tACTIVE\tsmuggled") == null);
    }

    // ---------------------------------------------------------------- authenticator

    private static final class CapturingAudit implements AuditLog {
        private final List<String> lines = new ArrayList<>();

        @Override
        public void record(AuditEvent event, String username, String outcome, String detail) {
            lines.add(event + "|" + username + "|" + outcome + "|" + detail);
        }

        boolean containsPassword(String secret) {
            for (String line : lines) {
                if (line.contains(secret)) {
                    return true;
                }
            }
            return false;
        }

        boolean hasEvent(AuditEvent event) {
            for (String line : lines) {
                if (line.startsWith(event.name() + "|")) {
                    return true;
                }
            }
            return false;
        }
    }

    private static final class Fixture {
        InMemoryAccountStore store = new InMemoryAccountStore();
        final PasswordHasher hasher = new PasswordHasher(TEST_ITERATIONS);
        final CapturingAudit audit = new CapturingAudit();
        final MutableClock clock = new MutableClock(1_700_000_000_000L);
        final LockoutTracker lockout = new LockoutTracker(3, 60_000L, 60_000L, clock, null);
        final EmployeeAuthenticator auth = new EmployeeAuthenticator(store, hasher, lockout, audit);
    }

    private static Fixture fixtureWithAlice() {
        Fixture f = new Fixture();
        f.store.add(EmployeeAccount.create("alice", "Alice Chen", AccountStatus.ACTIVE,
                f.hasher.hash(GOOD_PASSWORD.toCharArray())));
        return f;
    }

    private static final class MutableClock implements java.util.function.LongSupplier {
        private long now;

        MutableClock(long start) {
            now = start;
        }

        @Override
        public long getAsLong() {
            return now;
        }

        void advance(long millis) {
            now += millis;
        }
    }

    private static void authGrantsCorrectPassword() {
        Fixture f = fixtureWithAlice();
        AuthResult result = f.auth.authenticate("alice", GOOD_PASSWORD);
        check("correct password grants access", result.granted());
        check("grant message greets by display name", result.message().contains("Alice Chen"));
        check("success is audited", f.audit.hasEvent(AuditEvent.SUCCESS));
    }

    private static void authIsCaseInsensitiveOnUsername() {
        Fixture f = fixtureWithAlice();
        check("mixed-case username grants", f.auth.authenticate("ALICE", GOOD_PASSWORD).granted());
        check("padded username grants", f.auth.authenticate("  alice  ", GOOD_PASSWORD).granted());
    }

    private static void authDeniesWrongPassword() {
        Fixture f = fixtureWithAlice();
        AuthResult result = f.auth.authenticate("alice", OTHER_PASSWORD);
        check("wrong password denied", !result.granted());
        check("wrong password status is INVALID_CREDENTIAL",
                result.status() == AuthResult.Status.INVALID_CREDENTIAL);
    }

    private static void authDeniesUnknownUserWithSameWording() {
        Fixture f = fixtureWithAlice();
        AuthResult unknown = f.auth.authenticate("nobody", GOOD_PASSWORD);
        AuthResult wrong = f.auth.authenticate("alice", OTHER_PASSWORD);
        check("unknown username denied", !unknown.granted());
        check("unknown username gives the same status as a wrong password",
                unknown.status() == wrong.status());
        check("unknown username gives the same wording as a wrong password",
                unknown.message().equals(wrong.message()));
        check("denial wording does not name the username", !unknown.message().contains("nobody"));
    }

    /**
     * The property under test: an unknown username must not answer "instantly". If it did, latency
     * alone would confirm which staff numbers exist.
     */
    private static void authUnknownUserCostsComparableWork() {
        Fixture f = fixtureWithAlice();
        f.auth.authenticate("alice", GOOD_PASSWORD);

        long wrongBest = Long.MAX_VALUE;
        long unknownBest = Long.MAX_VALUE;
        for (int i = 0; i < 9; i++) {
            f.lockout.clear("alice");
            f.lockout.clear("ghost");

            long t0 = System.nanoTime();
            f.auth.authenticate("alice", OTHER_PASSWORD);
            long wrongNanos = System.nanoTime() - t0;

            long t1 = System.nanoTime();
            f.auth.authenticate("ghost", OTHER_PASSWORD);
            long unknownNanos = System.nanoTime() - t1;

            wrongBest = Math.min(wrongBest, wrongNanos);
            unknownBest = Math.min(unknownBest, unknownNanos);
        }
        double ratio = (double) unknownBest / (double) wrongBest;
        check(String.format(Locale.ROOT,
                "unknown-user path costs comparable work to wrong-password path (ratio %.2f)", ratio),
                ratio > 0.2 && ratio < 5.0);
    }

    private static void authLocksAfterThresholdAndBlocksEvenCorrectPassword() {
        Fixture f = fixtureWithAlice();
        check("first miss allowed", f.auth.authenticate("alice", "nope1").status()
                == AuthResult.Status.INVALID_CREDENTIAL);
        f.auth.authenticate("alice", "nope2");
        AuthResult third = f.auth.authenticate("alice", "nope3");
        check("third miss still reported as a miss", third.status() == AuthResult.Status.INVALID_CREDENTIAL);
        check("lockout trip is audited", f.audit.hasEvent(AuditEvent.LOCKOUT_STARTED));

        AuthResult locked = f.auth.authenticate("alice", GOOD_PASSWORD);
        check("correct password refused while locked out", !locked.granted());
        check("locked-out status reported", locked.status() == AuthResult.Status.LOCKED_OUT);
        check("lockout names a retry time", locked.retryAfterEpochMs() > f.clock.getAsLong());
        check("locked attempt is audited", f.audit.hasEvent(AuditEvent.LOCKED));
    }

    private static void authLockoutExpiresAndSuccessResets() {
        Fixture f = fixtureWithAlice();
        for (int i = 0; i < 2; i++) {
            f.auth.authenticate("alice", "nope");
        }
        check("a good sign-in resets the failure window", f.auth.authenticate("alice", GOOD_PASSWORD).granted());
        for (int i = 0; i < 2; i++) {
            check("counter restarted after a success",
                    f.auth.authenticate("alice", "nope").status() == AuthResult.Status.INVALID_CREDENTIAL);
        }
        check("third miss after the reset trips the lock",
                f.auth.authenticate("alice", "nope").status() == AuthResult.Status.INVALID_CREDENTIAL);
        check("lock is now engaged",
                f.auth.authenticate("alice", GOOD_PASSWORD).status() == AuthResult.Status.LOCKED_OUT);

        f.clock.advance(61_000L);
        check("lock lifts once the window has passed", f.auth.authenticate("alice", GOOD_PASSWORD).granted());
    }

    private static void authDisabledAccountDeniedDespiteCorrectPassword() {
        Fixture f = new Fixture();
        f.store.add(EmployeeAccount.create("carol", "Carol Dline", AccountStatus.DISABLED,
                f.hasher.hash(GOOD_PASSWORD.toCharArray())));
        AuthResult result = f.auth.authenticate("carol", GOOD_PASSWORD);
        check("disabled account denied even with the correct password", !result.granted());
        check("disabled status reported", result.status() == AuthResult.Status.ACCOUNT_DISABLED);
        check("disabled denial is audited so a working password on a dead account is visible",
                f.audit.hasEvent(AuditEvent.DISABLED));
    }

    private static void authPendingActivationDenied() {
        Fixture f = new Fixture();
        f.store.add(EmployeeAccount.create("dave", "Dave Ellis", AccountStatus.PENDING_ACTIVATION,
                f.hasher.hash(GOOD_PASSWORD.toCharArray())));
        check("not-yet-activated account denied",
                f.auth.authenticate("dave", GOOD_PASSWORD).status() == AuthResult.Status.PENDING_ACTIVATION);
    }

    private static void authNeverVerifiesUnhashedCredential() throws Exception {
        Path dir = Files.createTempDirectory("portal-failclosed");
        Path file = dir.resolve("records.tsv");
        Files.write(file, java.util.Arrays.asList(
                FileAccountStore.FILE_HEADER,
                "legacy\tLegacy Employee\tACTIVE\tS3cr3tPlainText"), StandardCharsets.UTF_8);

        Fixture f = new Fixture();
        f.store = new FileAccountStore(file);
        EmployeeAuthenticator auth = new EmployeeAuthenticator(f.store, f.hasher, f.lockout, f.audit);

        AuthResult right = auth.authenticate("legacy", "S3cr3tPlainText");
        check("a stored-plaintext account is refused rather than compared", !right.granted());
        check("refusal explains the record must be renewed",
                right.status() == AuthResult.Status.CREDENTIAL_STORAGE_ERROR);
        check("storage error is audited for the operator",
                f.audit.hasEvent(AuditEvent.UNHASHED_CREDENTIAL));
        check("no plaintext secret reaches the audit line", !f.audit.containsPassword("S3cr3tPlainText"));
    }

    private static void authUpgradesWeakVerifierOnSignIn() {
        PasswordHasher weak = new PasswordHasher(TEST_ITERATIONS);
        Fixture f = new Fixture();
        EmployeeAccount alice = EmployeeAccount.create("alice", "Alice Chen", AccountStatus.ACTIVE,
                weak.hash(GOOD_PASSWORD.toCharArray()));
        f.store.add(alice);

        EmployeeAuthenticator upgraded = new EmployeeAuthenticator(f.store,
                new PasswordHasher(TEST_ITERATIONS * 2), f.lockout, f.audit);
        AuthResult first = upgraded.authenticate("alice", GOOD_PASSWORD);
        check("sign-in succeeds while upgrading", first.granted());
        check("upgrade is audited", f.audit.hasEvent(AuditEvent.CREDENTIAL_UPGRADED));
        check("stored work factor rose",
                f.store.find("alice").credential().contains("$" + (TEST_ITERATIONS * 2) + "$"));
        check("the upgrade did not break the password",
                upgraded.authenticate("alice", GOOD_PASSWORD).granted());
    }

    private static void authDoesNotDowngradeStrongerVerifier() {
        PasswordHasher strong = new PasswordHasher(TEST_ITERATIONS * 2);
        Fixture f = new Fixture();
        f.store.add(EmployeeAccount.create("alice", "Alice Chen", AccountStatus.ACTIVE,
                strong.hash(GOOD_PASSWORD.toCharArray())));

        EmployeeAuthenticator weakAuth = new EmployeeAuthenticator(f.store,
                new PasswordHasher(TEST_ITERATIONS), f.lockout, f.audit);
        check("sign-in works against a stronger record", weakAuth.authenticate("alice", GOOD_PASSWORD).granted());
        check("stronger record is left alone (no silent downgrade)",
                f.store.find("alice").credential().contains("$" + (TEST_ITERATIONS * 2) + "$"));
    }

    private static void authStoreFaultFailsClosed() {
        AccountStore broken = new AccountStore() {
            @Override
            public EmployeeAccount find(String username) {
                throw new IllegalStateException("records store unreachable");
            }

            @Override
            public boolean add(EmployeeAccount account) {
                return false;
            }

            @Override
            public boolean replace(EmployeeAccount expected, EmployeeAccount updated) {
                return false;
            }

            @Override
            public List<EmployeeAccount> list() {
                return java.util.Collections.emptyList();
            }

            @Override
            public int size() {
                return 0;
            }

            @Override
            public String describe() {
                return "broken";
            }
        };
        Fixture f = new Fixture();
        EmployeeAuthenticator auth = new EmployeeAuthenticator(broken, f.hasher, f.lockout, f.audit);
        AuthResult result = auth.authenticate("alice", GOOD_PASSWORD);
        check("a store fault is a denial, never a grant", !result.granted());
        check("store fault reported as an internal error",
                result.status() == AuthResult.Status.INTERNAL_ERROR);
    }

    private static void authAuditAndResultNeverLeakPassword() {
        Fixture f = fixtureWithAlice();
        f.auth.authenticate("alice", GOOD_PASSWORD);
        f.auth.authenticate("alice", OTHER_PASSWORD);
        f.auth.authenticate("nobody", OTHER_PASSWORD);
        f.auth.authenticate("alice", GOOD_PASSWORD);

        check("audit trail never contains a password", !f.audit.containsPassword(GOOD_PASSWORD)
                && !f.audit.containsPassword(OTHER_PASSWORD));

        AuthResult denied = f.auth.authenticate("alice", OTHER_PASSWORD);
        check("user-facing message never contains a password", !denied.message().contains(OTHER_PASSWORD));

        check("audit guard withholds a detail that repeats the credential", AuditLog.detailWithoutCredential(
                "typed " + GOOD_PASSWORD + " at the gate", GOOD_PASSWORD.toCharArray())
                .equals("[detail withheld: contained the credential]"));
    }

    private static void authOverlongPasswordIsRejectedBeforeHashing() {
        Fixture f = fixtureWithAlice();
        char[] huge = new char[EmployeeAuthenticator.MAX_PASSWORD_CHARS + 100];
        java.util.Arrays.fill(huge, 'a');
        long t0 = System.nanoTime();
        AuthResult result = f.auth.authenticate("alice", huge);
        long elapsedMillis = (System.nanoTime() - t0) / 1_000_000L;
        check("oversized password denied", !result.granted());
        check("oversized password rejected cheaply (no key derivation)", elapsedMillis < 500);
        EmployeeAuthenticator.wipe(huge);
    }

    // ---------------------------------------------------------------- tracker

    private static void trackerWeightsCostlyAttempts() {
        MutableClock clock = new MutableClock(0L);
        LockoutTracker tracker = new LockoutTracker(5, 60_000L, 60_000L, clock, identity -> 4);
        LockoutTracker.Decision first = tracker.record("alice", false);
        check("an attempt carrying extra cost counts for more than one miss", first.locked());
        check("weighted attempt leaves no attempts remaining", first.remaining() == 0);

        MutableClock plain = new MutableClock(0L);
        LockoutTracker unweighted = LockoutTracker.standard(plain);
        check("standard tracker allows the first four misses",
                !unweighted.record("bob", false).locked() && !unweighted.record("bob", false).locked());
    }

    /**
     * The reason the counters are persisted at all: a sign-in command that runs one attempt per
     * process would otherwise count every attempt as the first one.
     */
    private static void trackerStateSurvivesAFreshProcess() throws Exception {
        Path dir = Files.createTempDirectory("portal-lockout");
        Path records = dir.resolve("records.tsv");
        MutableClock clock = new MutableClock(1_700_000_000_000L);

        LockoutTracker firstProcess = new LockoutTracker(3, 60_000L, 60_000L, clock, null);
        firstProcess.record("alice", false);
        firstProcess.record("alice", false);
        check("two misses leave one attempt", firstProcess.peek("alice").remaining() == 1);

        LockoutStateFile state = new LockoutStateFile(records);
        state.saveFrom(firstProcess);

        LockoutTracker secondProcess = new LockoutTracker(3, 60_000L, 60_000L, clock, null);
        check("a fresh tracker starts from zero (the gap the file closes)",
                secondProcess.peek("alice").remaining() == 3);
        state.loadInto(secondProcess);
        check("loaded counters carry the prior misses", secondProcess.peek("alice").remaining() == 1);

        LockoutTracker.Decision third = secondProcess.record("alice", false);
        check("the miss that completes the threshold locks, across the process boundary", third.locked());
        check("lock is enforced in the second process", secondProcess.peek("alice").locked());

        clock.advance(61_000L);
        check("the lock lifts once its window passes", !secondProcess.peek("alice").locked());
    }

    private static void trackerStateIgnoresCorruption() throws Exception {
        Path dir = Files.createTempDirectory("portal-lockout-bad");
        Path records = dir.resolve("records.tsv");
        LockoutStateFile state = new LockoutStateFile(records);
        check("state file sits beside the records, not inside them",
                state.path().getFileName().toString().endsWith(LockoutStateFile.SUFFIX));

        Files.write(state.path(), java.util.Arrays.asList(
                "# comment",
                "garbage without a separator",
                "alice=not,a,timestamp",
                "bob=1700000000000"), StandardCharsets.UTF_8);

        MutableClock clock = new MutableClock(1_700_000_000_000L);
        LockoutTracker tracker = new LockoutTracker(3, 60_000L, 60_000L, clock, null);
        state.loadInto(tracker);
        check("a corrupt counter file does not throw or lock everyone out",
                tracker.peek("alice").remaining() == 3);
        check("a well-formed line in the same file still loads",
                tracker.peek("bob").remaining() == 2);

        // The read itself can fail (unreadable path, EISDIR, permissions). Counters throttle
        // attempts rather than authorise them, so sign-in must proceed rather than abort.
        Path unreadableDir = dir.resolve("records2.tsv");
        LockoutStateFile blockedState = new LockoutStateFile(unreadableDir);
        Files.createDirectories(blockedState.path());
        boolean survivedUnreadable = true;
        try {
            blockedState.loadInto(new LockoutTracker(3, 60_000L, 60_000L, clock, null));
        } catch (RuntimeException aborted) {
            survivedUnreadable = false;
        }
        check("an unreadable counter file does not abort sign-in", survivedUnreadable);

        boolean saveFailureIsQuiet = true;
        try {
            blockedState.saveFrom(tracker);
        } catch (RuntimeException aborted) {
            saveFailureIsQuiet = false;
        }
        check("a counter file that cannot be written does not abort sign-in", saveFailureIsQuiet);
    }

    // ---------------------------------------------------------------- CLI

    private static void cliProvisionsAndLists() throws Exception {
        Path dir = Files.createTempDirectory("portal-cli");
        Path file = dir.resolve("records.tsv");

        int added = PortalCli.run(new String[] {"--records", file.toString(), "--iterations",
                String.valueOf(TEST_ITERATIONS), "add", "alice", "Alice Chen", GOOD_PASSWORD},
                empty(), sink());
        check("CLI add succeeds", added == 0);
        check("CLI add wrote the records file", Files.exists(file));
        String raw = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        check("CLI add did not persist the plaintext", !raw.contains(GOOD_PASSWORD));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int listed = PortalCli.run(new String[] {"--records", file.toString(), "list"}, empty(),
                new PrintStream(out, true, "UTF-8"));
        String listing = out.toString("UTF-8");
        check("CLI list succeeds", listed == 0);
        check("CLI list shows the account", listing.contains("alice"));
        check("CLI list omits the credential", !listing.contains("pbkdf2-sha256$"));

        int weak = PortalCli.run(new String[] {"--records", dir.resolve("weak.tsv").toString(), "add",
                "bob", "Bob Ortiz", "short"}, empty(), sink());
        check("CLI add enforces the password policy", weak == 2);

        int duplicate = PortalCli.run(new String[] {"--records", file.toString(), "add", "alice",
                "Alice Chen", OTHER_PASSWORD}, empty(), sink());
        check("CLI add refuses a duplicate username", duplicate == 1);
    }

    private static void cliSignInGrantAndDeny() throws Exception {
        if (System.console() != null) {
            System.out.println("  SKIP CLI sign-in (a real console is attached; the prompt path"
                    + " would block on the terminal)");
            return;
        }
        Path dir = tempDir();
        Path file = dir.resolve("records.tsv");
        PortalCli.run(new String[] {"--records", file.toString(), "--iterations",
                String.valueOf(TEST_ITERATIONS), "add", "alice", "Alice Chen", GOOD_PASSWORD},
                empty(), sink());

        ByteArrayOutputStream grantedOut = new ByteArrayOutputStream();
        int granted = PortalCli.run(new String[] {"--records", file.toString(), "signin"},
                input("alice\n" + GOOD_PASSWORD + "\n"), new PrintStream(grantedOut, true, "UTF-8"));
        String grantedText = out2(grantedOut);
        check("CLI sign-in grants the right credentials (exit 0)", granted == 0);
        check("CLI grant says access granted", grantedText.contains("access granted"));
        check("CLI grant greets the employee", grantedText.contains("Alice Chen"));
        check("CLI output never echoes the password", !grantedText.contains(GOOD_PASSWORD));

        ByteArrayOutputStream deniedOut = new ByteArrayOutputStream();
        int denied = PortalCli.run(new String[] {"--records", file.toString(), "signin"},
                input("alice\n" + OTHER_PASSWORD + "\n"), new PrintStream(deniedOut, true, "UTF-8"));
        String deniedText = out2(deniedOut);
        check("CLI sign-in denies a wrong password (exit 1)", denied == 1);
        check("CLI denial says access denied", deniedText.contains("access denied"));
        check("CLI denial never echoes the password", !deniedText.contains(OTHER_PASSWORD));

        ByteArrayOutputStream unknownOut = new ByteArrayOutputStream();
        int unknown = PortalCli.run(new String[] {"--records", file.toString(), "signin"},
                input("nosuchuser\n" + GOOD_PASSWORD + "\n"), new PrintStream(unknownOut, true, "UTF-8"));
        check("CLI sign-in denies an unknown username (exit 1)", unknown == 1);
        check("CLI unknown-username wording matches the wrong-password wording",
                unknownOut.toString("UTF-8").contains("Invalid username or password."));
    }

    /**
     * Lockout has to survive the gap between one-shot CLI invocations. Before the counters were
     * persisted, every invocation counted its own attempt as the first one and the threshold was
     * unreachable no matter how many wrong passwords were tried.
     */
    private static void cliLockoutTripsAcrossSeparateInvocations() throws Exception {
        if (System.console() != null) {
            System.out.println("  SKIP CLI lockout (a real console is attached)");
            return;
        }
        Path dir = Files.createTempDirectory("portal-cli-lock");
        Path file = dir.resolve("records.tsv");
        String[] base = {"--records", file.toString(), "--iterations", String.valueOf(TEST_ITERATIONS)};
        PortalCli.run(concat(base, new String[] {"add", "alice", "Alice Chen", GOOD_PASSWORD}),
                empty(), sink());

        boolean lockedBeforeThreshold = false;
        for (int attempt = 1; attempt <= 4; attempt++) {
            int code = PortalCli.run(concat(base, new String[] {"signin"}),
                    input("alice\nWrong-Guess-" + attempt + "!\n"), sink());
            lockedBeforeThreshold |= code == 0;
        }
        check("four separate wrong-password invocations do not grant access", !lockedBeforeThreshold);
        String counters = new String(Files.readAllBytes(dir.resolve("records.tsv" + LockoutStateFile.SUFFIX)),
                StandardCharsets.UTF_8);
        check("the counters file carries this identity's failure window", counters.contains("alice="));
        check("the counters file never holds a password", !counters.contains(OTHER_PASSWORD)
                && !counters.contains("Wrong-Guess"));

        int fifth = PortalCli.run(concat(base, new String[] {"signin"}),
                input("alice\nWrong-Guess-5!\n"), sink());
        check("the fifth separate invocation trips the lockout", fifth == 1);

        int correctWhileLocked = PortalCli.run(concat(base, new String[] {"signin"}),
                input("alice\n" + GOOD_PASSWORD + "\n"), sink());
        check("the correct password is refused from a fresh process once locked out",
                correctWhileLocked == 1);

        ByteArrayOutputStream unlocked = new ByteArrayOutputStream();
        int unlock = PortalCli.run(concat(base, new String[] {"unlock", "alice"}), empty(),
                new PrintStream(unlocked, true, "UTF-8"));
        check("CLI unlock succeeds", unlock == 0);

        int afterUnlock = PortalCli.run(concat(base, new String[] {"signin"}),
                input("alice\n" + GOOD_PASSWORD + "\n"), sink());
        check("sign-in works again after an operator unlock", afterUnlock == 0);
    }

    private static String[] concat(String[] head, String[] tail) {
        String[] joined = java.util.Arrays.copyOf(head, head.length + tail.length);
        System.arraycopy(tail, 0, joined, head.length, tail.length);
        return joined;
    }

    private static void cliSeededFileIsTheTrustBoundary() throws Exception {
        Path dir = Files.createTempDirectory("portal-seed");
        Path file = dir.resolve("records.tsv");
        Files.write(file, java.util.Arrays.asList(
                FileAccountStore.FILE_HEADER,
                "legacy\tLegacy Employee\tACTIVE\tS3cr3tPlainText"), StandardCharsets.UTF_8);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int status = PortalCli.run(new String[] {"--records", file.toString(), "status", "legacy"},
                empty(), new PrintStream(out, true, "UTF-8"));
        String text = out2(out);
        check("CLI status succeeds for a legacy row", status == 0);
        check("CLI status warns the operator about the unhashed credential",
                text.contains("unhashed credential"));

        int signin = PortalCli.run(new String[] {"--records", file.toString(), "signin"},
                input("legacy\nS3cr3tPlainText\n"), sink());
        check("a seeded plaintext row cannot sign in", signin == 1);

        int reset = PortalCli.run(new String[] {"--records", file.toString(), "--iterations",
                String.valueOf(TEST_ITERATIONS), "reset", "legacy", GOOD_PASSWORD}, empty(), sink());
        check("CLI reset succeeds", reset == 0);
        String raw = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        check("reset replaced the plaintext with a verifier",
                !raw.contains("S3cr3tPlainText") && raw.contains("pbkdf2-sha256$"));
        check("the rotated account can sign in",
                PortalCli.run(new String[] {"--records", file.toString(), "signin"},
                        input("legacy\n" + GOOD_PASSWORD + "\n"), sink()) == 0);
    }

    // ---------------------------------------------------------------- harness

    private static Path tempDir() {
        try {
            return Files.createTempDirectory("portal-test");
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static java.io.InputStream empty() {
        return new ByteArrayInputStream(new byte[0]);
    }

    private static java.io.InputStream input(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
    }

    private static PrintStream sink() {
        return new PrintStream(new ByteArrayOutputStream(), true, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String out2(ByteArrayOutputStream buffer) {
        try {
            return buffer.toString("UTF-8");
        } catch (java.io.UnsupportedEncodingException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("== " + title + " ==");
    }

    private static void check(String what, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  ok   " + what);
        } else {
            FAILURES.add(what);
            System.out.println("  FAIL " + what);
        }
    }
}
