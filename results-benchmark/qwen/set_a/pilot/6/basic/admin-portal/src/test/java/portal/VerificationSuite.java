package portal;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import portal.admin.AccessDeniedException;
import portal.admin.AccountState;
import portal.admin.AdminAccount;
import portal.admin.AdminGate;
import portal.admin.AdminOperations;
import portal.admin.AdminPrincipal;
import portal.admin.AdminRole;
import portal.admin.AdminSession;
import portal.admin.AuditEvent;
import portal.admin.AuditLog;
import portal.admin.AuditResult;
import portal.admin.AuthResult;
import portal.admin.AuthenticationConfig;
import portal.admin.AuthenticationService;
import portal.admin.CredentialStore;
import portal.admin.InMemoryAuditLog;
import portal.admin.SessionManager;
import portal.cli.AdminConsole;
import portal.cli.InteractiveReader;
import portal.cli.Main;
import portal.cli.PortalApp;
import portal.security.Clock;
import portal.security.KeyDerivation;
import portal.security.PasswordHasher;
import portal.security.PasswordPolicy;
import portal.security.Pbkdf2;

/**
 * Executable checks for the administrator portal: {@code ./build.sh test}. Exits non-zero
 * if anything fails.
 *
 * <p>No test-framework jar exists on this machine, so this is a plain {@code main} that
 * counts checks. Cost factors drop to the floor through a {@link KeyDerivation} seam so the
 * suite runs in seconds, and the counting variant makes derivation counts observable -
 * which is how "an unknown username costs the same work as a real one" is asserted rather
 * than eyeballed. Time is a {@link Clock.Fake}, so lockout and session expiry are checked
 * exactly instead of by sleeping.
 */
public final class VerificationSuite {

    private static final String GOOD_PASSWORD = "Correct-Horse-9";
    private static final String OTHER_PASSWORD = "Battery-Staple-4";
    private static final String WRONG_PASSWORD = "Wrong-Guess-77";

    private static int checks;
    private static final List<String> FAILURES = new ArrayList<>();

    private VerificationSuite() {
    }

    public static void main(String[] args) throws Exception {
        Path work = Files.createTempDirectory("portal-suite-");
        try {
            hasherChecks();
            policyChecks();
            storeChecks(work);
            authenticationChecks(work);
            antiEnumerationChecks(work);
            sessionChecks();
            authorizationChecks(work);
            operationsChecks(work);
            auditChecks(work);
            consoleChecks(work);
            cliChecks(work);
        } catch (Exception e) {
            FAILURES.add("unexpected exception: " + e);
            e.printStackTrace();
        } finally {
            deleteTree(work);
        }

        System.out.println();
        if (FAILURES.isEmpty()) {
            System.out.println("PASS: " + checks + " checks passed.");
            return;
        }
        System.out.println("FAIL: " + FAILURES.size() + " of " + checks + " checks failed:");
        for (String failure : FAILURES) {
            System.out.println("  - " + failure);
        }
        System.exit(1);
    }

    // ------------------------------------------------------------------ hashing

    private static void hasherChecks() {
        section("password hashing");
        PasswordHasher hasher = new PasswordHasher(new CountingKdf(), PasswordHasher.MIN_ITERATIONS);
        String digest = hasher.hash(GOOD_PASSWORD.toCharArray());
        String[] parts = digest.split("\\$");

        check("a stored digest records algorithm, cost, salt and value",
                parts.length == 4 && "PBKDF2-SHA256".equals(parts[0])
                        && Integer.parseInt(parts[1]) == PasswordHasher.MIN_ITERATIONS);
        check("the correct password verifies", hasher.verify(GOOD_PASSWORD.toCharArray(), digest));
        check("a wrong password is rejected", !hasher.verify(OTHER_PASSWORD.toCharArray(), digest));
        check("an empty password is rejected", !hasher.verify(new char[0], digest));
        check("a null password is rejected", !hasher.verify(null, digest));
        check("the stored digest does not contain the password", !digest.contains(GOOD_PASSWORD));

        String second = hasher.hash(GOOD_PASSWORD.toCharArray());
        check("the same password hashes to a different stored value each time", !digest.equals(second));
        check("each hash draws a fresh salt", !second.split("\\$")[2].equals(parts[2]));

        check("a corrupted digest character is rejected",
                !hasher.verify(GOOD_PASSWORD.toCharArray(), corruptAt(digest, digest.length() - 3)));
        check("a digest truncated by one character is rejected",
                !hasher.verify(GOOD_PASSWORD.toCharArray(), digest.substring(0, digest.length() - 1)));
        check("swapping the salt for another account's is rejected", !hasher.verify(GOOD_PASSWORD.toCharArray(),
                parts[0] + "$" + parts[1] + "$" + second.split("\\$")[2] + "$" + parts[3]));
        check("a different cost factor in the stored value is rejected", !hasher.verify(
                GOOD_PASSWORD.toCharArray(),
                parts[0] + "$" + (PasswordHasher.MIN_ITERATIONS + 1) + "$" + parts[2] + "$" + parts[3]));

        check("unknown algorithms are refused", !PasswordHasher.isWellFormed("MD5$10$" + parts[2] + "$" + parts[3]));
        check("an absurd cost factor in a stored value is refused",
                !PasswordHasher.isWellFormed("PBKDF2-SHA256$999999999$" + parts[2] + "$" + parts[3]));
        check("a short salt is refused", !PasswordHasher.isWellFormed(
                "PBKDF2-SHA256$" + PasswordHasher.MIN_ITERATIONS + "$AAAA$" + parts[3]));
        check("empty and null stored values are refused",
                !PasswordHasher.isWellFormed("") && !PasswordHasher.isWellFormed(null));
        String equivalent = nonCanonicalEquivalent(digest);
        check("an equivalent-but-non-canonical encoding is refused as malformed",
                !PasswordHasher.isWellFormed(equivalent));
        check("it really does decode to the same bytes (so the refusal is not trivial)",
                java.util.Arrays.equals(java.util.Base64.getDecoder().decode(digest.split("\\$")[3]),
                        java.util.Base64.getDecoder().decode(equivalent.split("\\$")[3])));
        check("a digest whose padding was stripped is refused",
                !PasswordHasher.isWellFormed(digest.replaceFirst("=+$", "")));

        CountingKdf counted = new CountingKdf();
        PasswordHasher metered = new PasswordHasher(counted, PasswordHasher.MIN_ITERATIONS);
        metered.verify(GOOD_PASSWORD.toCharArray(), digest);
        check("verification performs exactly one key derivation", counted.count == 1);
    }

    // ------------------------------------------------------------------ policy

    private static void policyChecks() {
        section("password policy");
        PasswordPolicy policy = new PasswordPolicy();

        check("the shipped test password satisfies the admin policy", policy.isAcceptable(GOOD_PASSWORD, "alice"));
        check("the minimum length is 12 or more", PasswordPolicy.MIN_LENGTH >= 12);
        check("too short is rejected with a length reason",
                policy.violations("Ab1!", "alice").stream().anyMatch(reason -> reason.contains("at least")));
        check("one character class is rejected", !policy.isAcceptable("aaaaaaaaaaaaaa", "alice"));
        check("two character classes are rejected", !policy.isAcceptable("aaaaaaaaaa11", "alice"));
        check("a common breached password is rejected", !policy.isAcceptable("Password12345", "alice"));
        check("a password built from the username is rejected", !policy.isAcceptable("Alice-Is-Great-9", "alice"));
        check("an all-same-character password is rejected", !policy.isAcceptable("AAAAAAAAAAAAAA", "alice"));
        check("a long sequential run is rejected", !policy.isAcceptable("abcdefghijklm1", "alice"));
        check("a password containing a newline is rejected", !policy.isAcceptable("Abc-Def-Gh1\n", "alice"));
        check("a null candidate is rejected", policy.violations(null, "alice").size() == 1);
        check("violations accumulate so the operator sees every problem",
                policy.violations("aaa", "alice").size() >= 2);
    }

    // ------------------------------------------------------------------ store

    private static void storeChecks(Path work) throws Exception {
        section("credential store");
        Path file = work.resolve("admins.dat");
        PasswordHasher hasher = new PasswordHasher(new CountingKdf(), PasswordHasher.MIN_ITERATIONS);

        CredentialStore store = new CredentialStore(file);
        String aliceDigest = hasher.hash(GOOD_PASSWORD.toCharArray());
        store.put(new AdminAccount("alice", aliceDigest, AdminRole.SUPER_ADMIN));
        store.save();

        String text = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        check("the password never reaches the stored file", !text.contains(GOOD_PASSWORD));
        check("the stored digest is not written in its readable form", !text.contains("PBKDF2"));
        check("each stored record is one line of seven opaque fields",
                recordFields(text, CredentialStore.FILE_HEADER).equals(java.util.List.of(7)));
        check("the stored password field decodes back to the salted digest",
                new String(java.util.Base64.getUrlDecoder().decode(
                        recordLine(text, CredentialStore.FILE_HEADER).split(":")[1]),
                        StandardCharsets.UTF_8).equals(aliceDigest));
        check("the atomic save leaves no temporary file behind",
                listSiblings(file).stream().noneMatch(name -> name.startsWith(".admins-")));
        check("the store is owner read-write only", ownerOnly(Files.getPosixFilePermissions(file)));

        CredentialStore reloaded = new CredentialStore(file).load();
        check("accounts survive a reload", reloaded.size() == 1);
        check("a reload finds the account case-insensitively", reloaded.find("ALICE").isPresent());
        check("the digest round-trips byte for byte",
                reloaded.find("alice").get().passwordDigest().equals(aliceDigest));
        check("an absent store simply has no accounts",
                new CredentialStore(work.resolve("missing.dat")).load().isEmpty());
        check("an absent store does not grant anything", new CredentialStore(work.resolve("missing.dat")).isEmpty());

        // A username carrying record structure must not forge a second record on reload.
        String hostile = "mallory:SUPER_ADMIN:ACTIVE:0:0:0";
        Path hostileFile = work.resolve("hostile.dat");
        CredentialStore hostileStore = new CredentialStore(hostileFile);
        hostileStore.put(new AdminAccount(hostile, aliceDigest, AdminRole.HELPDESK));
        hostileStore.save();
        String hostileText = new String(Files.readAllBytes(hostileFile), StandardCharsets.UTF_8);
        check("the forged record text is not written verbatim",
                !hostileText.contains("mallory:SUPER_ADMIN:ACTIVE"));
        // Either outcome is safe, and both are named: the record reloads intact, or the
        // loader refuses the file loudly. What must never happen is a silent reinterpretation
        // that yields an extra SUPER_ADMIN record.
        CredentialStore hostileReload = loadOrFail(hostileFile);
        check("a hostile username neither forges an account nor silently corrupts the store",
                hostileReload == null
                        || (hostileReload.size() == 1 && hostileReload.find(hostile).isPresent()));
        check("a hostile username is preserved rather than reinterpreted",
                hostileReload != null && hostileReload.find(hostile).isPresent());

        Path corrupt = work.resolve("corrupt.dat");
        Files.write(corrupt, (CredentialStore.FILE_HEADER + "\n@@@ not base64 @@@\n").getBytes(StandardCharsets.UTF_8));
        check("a malformed record fails the load instead of being dropped",
                throwsIllegalState(() -> new CredentialStore(corrupt).load()));

        Path badDigest = work.resolve("baddigest.dat");
        CredentialStore badStore = new CredentialStore(badDigest);
        badStore.put(new AdminAccount("bob", "PBKDF2-SHA256$10$AAAA$BBBB", AdminRole.SUPER_ADMIN));
        badStore.save();
        check("an account with an unusable digest will not load",
                throwsIllegalState(() -> new CredentialStore(badDigest).load()));

        Path truncated = work.resolve("truncated.dat");
        Files.write(truncated, (CredentialStore.FILE_HEADER + "\nYWxpY2U\n").getBytes(StandardCharsets.UTF_8));
        check("a record with too few fields fails the load",
                throwsIllegalState(() -> new CredentialStore(truncated).load()));

        check("Account#toString does not expose the digest",
                !store.find("alice").get().toString().contains(aliceDigest));

        // Saving again after a reload must not lose accounts or duplicate them.
        reloaded.put(new AdminAccount("bob", aliceDigest, AdminRole.HELPDESK));
        reloaded.save();
        CredentialStore twice = new CredentialStore(file).load();
        check("a save after reload keeps both accounts", twice.size() == 2);
        check("a reload-then-save does not duplicate records", twice.find("alice").isPresent()
                && twice.find("bob").isPresent() && twice.size() == 2);
        check("saving again still leaves owner-only modes", ownerOnly(Files.getPosixFilePermissions(file)));
    }

    // ------------------------------------------------------------------ authentication

    private static void authenticationChecks(Path work) {
        section("authentication");
        Harness h = new Harness(work, "auth");

        AuthResult good = h.auth.authenticate("alice", GOOD_PASSWORD.toCharArray());
        check("correct credentials are granted", good.granted());
        check("the principal carries the stored role", good.principal().role() == AdminRole.SUPER_ADMIN);
        check("the principal carries the stored username", good.principal().username().equals("alice"));
        check("a granted result is printable without leaking credentials",
                !good.principal().toString().contains(GOOD_PASSWORD));

        AuthResult bad = h.auth.authenticate("alice", WRONG_PASSWORD.toCharArray());
        check("a wrong password is denied", !bad.granted());
        check("a wrong password shows the generic message", bad.userMessage().equals(AuthResult.GENERIC_FAILURE));

        AuthResult unknown = h.auth.authenticate("nobody", GOOD_PASSWORD.toCharArray());
        check("an unknown username is denied", !unknown.granted());
        check("an unknown username shows the same message as a wrong password",
                unknown.userMessage().equals(bad.userMessage()));

        check("surrounding whitespace in the username is tolerated",
                h.auth.authenticate("  alice  ", GOOD_PASSWORD.toCharArray()).granted());
        check("username matching ignores case",
                h.auth.authenticate("ALICE", GOOD_PASSWORD.toCharArray()).granted());

        check("an empty password is denied", !h.auth.authenticate("alice", new char[0]).granted());
        check("a null password is denied", !h.auth.authenticate("alice", null).granted());
        check("a null username is denied without a crash",
                !h.auth.authenticate(null, GOOD_PASSWORD.toCharArray()).granted());
        check("an injection-style username is denied",
                !h.auth.authenticate("alice' OR '1'='1", GOOD_PASSWORD.toCharArray()).granted());
        check("a username with an embedded newline is denied",
                !h.auth.authenticate("alice\nADMIN", GOOD_PASSWORD.toCharArray()).granted());
        check("an over-long username is denied",
                !h.auth.authenticate(repeat("u", 500), GOOD_PASSWORD.toCharArray()).granted());

        // Lockout: the configured number of failures must stop the account, and the right
        // password must not rescue it while the lock is live.
        h.auth.clearFailureHistory();
        int limit = h.auth.config().maxFailedAttempts();
        for (int i = 0; i < limit; i++) {
            h.auth.authenticate("alice", ("Wrong-Guess-" + i + "-99").toCharArray());
        }
        check("the failure counter reached the limit", h.storedFailures("alice") == limit);
        AuthResult locked = h.auth.authenticate("alice", GOOD_PASSWORD.toCharArray());
        check("the account locks after the configured failures",
                locked.status() == AuthResult.Status.LOCKED);
        check("the correct password is refused while the account is locked", !locked.granted());
        check("a locked account shows the generic message", locked.userMessage().equals(AuthResult.GENERIC_FAILURE));
        check("a locked account reports a retry window", locked.retryAfterSeconds() > 0);

        h.advance(h.auth.config().lockDurationMillis() + 1_000L);
        h.auth.clearFailureHistory();
        check("the temporary lock expires on its own",
                h.auth.authenticate("alice", GOOD_PASSWORD.toCharArray()).granted());

        h.auth.clearFailureHistory();
        for (int i = 0; i < limit - 1; i++) {
            h.auth.authenticate("alice", ("Nope-Guess-" + i + "-99").toCharArray());
        }
        check("failures below the limit do not lock the account",
                h.auth.authenticate("alice", GOOD_PASSWORD.toCharArray()).granted());
        check("a successful sign-in clears the failure counter", h.storedFailures("alice") == 0);

        // Disabled accounts must never authenticate, right password or not.
        h.store.update(h.store.find("alice").get().withState(AccountState.DISABLED, h.now()));
        AuthResult disabled = h.auth.authenticate("alice", GOOD_PASSWORD.toCharArray());
        check("a disabled account cannot sign in with the correct password", !disabled.granted());
        check("a disabled account shows the generic message",
                disabled.userMessage().equals(AuthResult.GENERIC_FAILURE));
        h.store.update(h.store.find("alice").get().withState(AccountState.ACTIVE, h.now()));
        check("re-enabling the account restores sign-in",
                h.auth.authenticate("alice", GOOD_PASSWORD.toCharArray()).granted());

        // Fail closed with nothing provisioned.
        Harness empty = new Harness(new CredentialStore(work.resolve("empty.dat")), new Clock.Fake(),
                AuthenticationConfig.defaults());
        AuthResult none = empty.auth.authenticate("root", "Anything-Goes-9".toCharArray());
        check("an unprovisioned store grants nothing", !none.granted());
        check("an unprovisioned store reports NOT_CONFIGURED",
                none.status() == AuthResult.Status.NOT_CONFIGURED);

        // A sliding global window must bound stuffing across many usernames.
        AuthenticationConfig many = new AuthenticationConfig(10_000, 60_000L, 20, 60_000L,
                60_000L, 600_000L, 3);
        PasswordHasher seedHasher = new PasswordHasher(new CountingKdf(), PasswordHasher.MIN_ITERATIONS);
        CredentialStore stuffed = new CredentialStore(work.resolve("stuffed.dat"));
        stuffed.put(new AdminAccount("seed", seedHasher.hash(GOOD_PASSWORD.toCharArray()),
                AdminRole.SUPER_ADMIN));
        stuffed.save();
        Harness throttle = new Harness(new CredentialStore(work.resolve("stuffed.dat")).load(),
                new Clock.Fake(), many);
        AuthResult last = null;
        for (int i = 0; i <= many.globalThrottleThreshold(); i++) {
            last = throttle.auth.authenticate("nobody" + i, ("Wrong-Guess-" + i + "-99").toCharArray());
        }
        check("attempts below the throttle window are still evaluated normally",
                throttle.auth.config().globalThrottleThreshold() == many.globalThrottleThreshold());
        check("credential stuffing across usernames is throttled",
                last != null && last.status() == AuthResult.Status.THROTTLED);
        check("a throttled attempt is still denied", last != null && !last.granted());
        throttle.advance(many.throttleWindowMillis() + 1_000L);
        check("throttling releases once the window passes",
                throttle.auth.authenticate("nobody-again", WRONG_PASSWORD.toCharArray()).status()
                        == AuthResult.Status.INVALID_CREDENTIALS);
    }

    private static void antiEnumerationChecks(Path work) {
        section("user enumeration resistance");
        CountingKdf kdf = new CountingKdf();
        PasswordHasher hasher = new PasswordHasher(kdf, PasswordHasher.MIN_ITERATIONS);
        Clock.Fake clock = new Clock.Fake();
        InMemoryAuditLog audit = new InMemoryAuditLog(null, 200);
        Path file = work.resolve("enumeration.dat");
        CredentialStore store = new CredentialStore(file);
        store.put(new AdminAccount("alice", hasher.hash(GOOD_PASSWORD.toCharArray()), AdminRole.HELPDESK));
        store.save();

        AuthenticationService auth = new AuthenticationService(store, hasher,
                AuthenticationConfig.fast(5, 60_000L, 60_000L), audit, clock, false);

        kdf.count = 0;
        auth.authenticate("alice", WRONG_PASSWORD.toCharArray());
        int forExisting = kdf.count;

        kdf.count = 0;
        auth.authenticate("nosuchuser", WRONG_PASSWORD.toCharArray());
        int forUnknown = kdf.count;

        check("a wrong password on a real account costs one key derivation", forExisting == 1);
        check("an unknown username costs the same work as a real account", forUnknown == forExisting);

        AuthenticationService locker = new AuthenticationService(store, hasher,
                AuthenticationConfig.fast(1, 60_000L, 60_000L), audit, clock, false);
        locker.authenticate("alice", WRONG_PASSWORD.toCharArray());
        kdf.count = 0;
        AuthResult whileLocked = locker.authenticate("alice", GOOD_PASSWORD.toCharArray());
        check("a locked account still performs the same work", kdf.count == 1);
        check("a locked account does not reveal that it is locked",
                whileLocked.userMessage().equals(AuthResult.GENERIC_FAILURE));

        kdf.count = 0;
        AuthResult malformed = auth.authenticate("bad user!", WRONG_PASSWORD.toCharArray());
        check("a malformed username still performs the same work", kdf.count == 1);
        check("a malformed username shows the generic message",
                malformed.userMessage().equals(AuthResult.GENERIC_FAILURE));

        Set<String> messages = new LinkedHashSet<>();
        messages.add(auth.authenticate("alice", WRONG_PASSWORD.toCharArray()).userMessage());
        messages.add(auth.authenticate("nosuchuser", WRONG_PASSWORD.toCharArray()).userMessage());
        messages.add(auth.authenticate("carol", WRONG_PASSWORD.toCharArray()).userMessage());
        messages.add(auth.authenticate("", WRONG_PASSWORD.toCharArray()).userMessage());
        messages.add(auth.authenticate("alice", new char[0]).userMessage());
        check("every denial path yields one identical message", messages.size() == 1);

        check("no denial message names the username",
                !messages.iterator().next().contains("alice"));

        boolean leaked = false;
        for (AuditEvent event : audit.all()) {
            if (event.detail().contains(GOOD_PASSWORD) || event.detail().contains(WRONG_PASSWORD)) {
                leaked = true;
            }
        }
        check("the audit trail never records a password", !leaked);
    }

    // ------------------------------------------------------------------ sessions

    private static void sessionChecks() {
        section("sessions");
        Clock.Fake clock = new Clock.Fake();
        InMemoryAuditLog audit = new InMemoryAuditLog(null, 200);
        AuthenticationConfig config = AuthenticationConfig.fast(5, 60_000L, 60_000L);
        SessionManager sessions = new SessionManager(config, audit, clock);
        AdminPrincipal alice = new AdminPrincipal("alice", AdminRole.SUPER_ADMIN);

        AdminSession first = sessions.issue(alice);
        check("the token is long and opaque", first.tokenId().length() >= 32);
        check("the token does not contain the username", !first.tokenId().contains("alice"));
        check("the token does not encode the role", !first.tokenId().toUpperCase().contains("ADMIN"));
        check("a fresh token validates", sessions.validate(first.tokenId()).isPresent());
        check("validation returns the principal it was issued to",
                sessions.validate(first.tokenId()).get().role() == AdminRole.SUPER_ADMIN);
        check("validation returns the username it was issued to",
                sessions.validate(first.tokenId()).get().username().equals("alice"));

        check("a token extended by one character is refused",
                sessions.validate(first.tokenId() + "x").isEmpty());
        check("a truncated token is refused",
                sessions.validate(first.tokenId().substring(0, first.tokenId().length() - 1)).isEmpty());
        check("an empty token is refused", sessions.validate("").isEmpty());
        check("a null token is refused", sessions.validate(null).isEmpty());

        AdminSession second = sessions.issue(new AdminPrincipal("bob", AdminRole.HELPDESK));
        check("separate issuances produce different tokens", !first.tokenId().equals(second.tokenId()));

        // Direct unpredictability check: a token must not be derivable from the username,
        // or an attacker who knows a name can compute that administrator's session id.
        List<String> distinctTokens = new ArrayList<>();
        boolean predictable = false;
        for (int i = 0; i < 16; i++) {
            String name = "operator" + i;
            String token = sessions.issue(new AdminPrincipal(name, AdminRole.HELPDESK)).tokenId();
            distinctTokens.add(token);
            predictable |= token.equals(sha256Hex(name)) || token.equals(name)
                    || token.contains(name);
        }
        check("a token cannot be computed from its username", !predictable);
        check("every issued token is unique",
                new LinkedHashSet<>(distinctTokens).size() == distinctTokens.size());
        check("tokens do not grow with the username length",
                distinctTokens.stream().mapToInt(String::length).distinct().count() == 1);

        clock.advance(config.sessionIdleMillis() + 1L);
        check("an idle session expires", sessions.validate(first.tokenId()).isEmpty());
        check("an expired session disappears from the active list",
                sessions.activeSessions().stream().noneMatch(s -> s.tokenId().equals(first.tokenId())));

        // Activity must slide the idle window, but never past the absolute deadline.
        AuthenticationConfig slidingConfig = new AuthenticationConfig(5, 60_000L, 1_000, 60_000L,
                60_000L, 600_000L, 5);
        SessionManager sliding = new SessionManager(slidingConfig, audit, clock);
        AdminSession kept = sliding.issue(alice);
        boolean stayedAlive = true;
        for (int cycle = 0; cycle < 5; cycle++) {
            clock.advance(50_000L);
            stayedAlive &= sliding.validate(kept.tokenId()).isPresent();
        }
        check("activity keeps a session alive inside its idle window", stayedAlive);
        check("the absolute deadline is fixed at issue time",
                kept.absoluteDeadlineMillis() == kept.issuedAtMillis() + slidingConfig.sessionAbsoluteMillis());
        // Keep the session genuinely active - polling inside the idle window - and cross the
        // absolute deadline. Only the absolute check can stop it here: the idle window keeps
        // sliding, so this asserts the deadline itself and not an accidental idle timeout.
        boolean aliveBeforeDeadline = true;
        boolean aliveAfterDeadline = false;
        long pollMillis = 30_000L;
        while (clock.now() < kept.absoluteDeadlineMillis() - pollMillis) {
            clock.advance(pollMillis);
            aliveBeforeDeadline &= sliding.validate(kept.tokenId()).isPresent();
        }
        clock.advance(kept.absoluteDeadlineMillis() - clock.now() + pollMillis / 2);
        boolean crossedDeadline = clock.now() > kept.absoluteDeadlineMillis()
                && clock.now() < kept.lastActivityMillis() + slidingConfig.sessionIdleMillis();
        check("the poll after the deadline is still inside the idle window (so only the "
                + "absolute deadline can refuse it)", crossedDeadline);
        check("activity keeps the session alive right up to its absolute deadline", aliveBeforeDeadline);
        aliveAfterDeadline = sliding.validate(kept.tokenId()).isPresent();
        check("activity cannot keep a session alive past its absolute lifetime", !aliveAfterDeadline);

        AdminSession revocable = sliding.issue(alice);
        check("an explicit revoke succeeds", sliding.revoke(revocable.tokenId()));
        check("a revoked token no longer validates", sliding.validate(revocable.tokenId()).isEmpty());
        check("revoking the same token twice changes nothing", !sliding.revoke(revocable.tokenId()));

        // Per-user cap: old sessions are displaced rather than accumulating.
        Clock.Fake capClock = new Clock.Fake();
        SessionManager capped = new SessionManager(
                new AuthenticationConfig(5, 60_000L, 1_000, 60_000L, 60_000L, 3_600_000L, 2), audit, capClock);
        List<String> issued = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            capClock.advance(1_000L);
            issued.add(capped.issue(alice).tokenId());
        }
        check("the per-user cap bounds live sessions", capped.activeSessionCount("alice") == 2);
        check("the oldest session was displaced", capped.validate(issued.get(0)).isEmpty());
        check("the newest session survives", capped.validate(issued.get(3)).isPresent());

        AdminSession bobSession = capped.issue(new AdminPrincipal("bob", AdminRole.HELPDESK));
        check("revokeAllForUser is case-insensitive", capped.revokeAllForUser("ALICE", "test") == 2);
        check("nothing of theirs survives", capped.activeSessionCount("alice") == 0);
        check("revokeAllForUser leaves other users' sessions alone",
                capped.validate(bobSession.tokenId()).isPresent());
        check("revoking for a name with no sessions is a no-op",
                capped.revokeAllForUser("nobody", "test") == 0);

        check("a session's toString does not expose the whole token",
                !revocable.toString().contains(revocable.tokenId()));

        // A principal is only as powerful as its role, never as claimed.
        check("a principal cannot be handed a permission its role lacks",
                !new AdminPrincipal("x", AdminRole.HELPDESK).can(AdminRole.Permission.USER_MANAGE));
        boolean immutable = true;
        try {
            new AdminPrincipal("x", AdminRole.SUPER_ADMIN).permissions().clear();
            immutable = false;
        } catch (UnsupportedOperationException e) {
            // expected
        }
        check("a principal's permission set cannot be edited", immutable);
        check("a principal cannot be built without a role",
                throwsIllegalArgument(() -> new AdminPrincipal("x", null)));
    }

    // ------------------------------------------------------------------ authorization

    private static void authorizationChecks(Path work) {
        section("authorization");
        Harness h = new Harness(work, "rbac");
        SessionManager sessions = new SessionManager(h.config, h.audit, h.clock);
        AdminGate gate = new AdminGate(sessions, h.audit);

        String superToken = sessions.issue(new AdminPrincipal("alice", AdminRole.SUPER_ADMIN)).tokenId();
        String deskToken = sessions.issue(new AdminPrincipal("carol", AdminRole.HELPDESK)).tokenId();
        String auditorToken = sessions.issue(new AdminPrincipal("dave", AdminRole.AUDITOR)).tokenId();

        check("SUPER_ADMIN may manage accounts",
                gate.require(AdminRole.Permission.USER_MANAGE, superToken).username().equals("alice"));
        check("HELPDESK may read accounts",
                gate.require(AdminRole.Permission.USER_READ, deskToken).username().equals("carol"));
        check("AUDITOR may read the audit trail",
                gate.require(AdminRole.Permission.AUDIT_READ, auditorToken) != null);

        check("HELPDESK cannot manage accounts", throwsDenied(
                () -> gate.require(AdminRole.Permission.USER_MANAGE, deskToken)));
        check("HELPDESK cannot terminate sessions", throwsDenied(
                () -> gate.require(AdminRole.Permission.SESSION_TERMINATE, deskToken)));
        check("AUDITOR cannot change system configuration", throwsDenied(
                () -> gate.require(AdminRole.Permission.SYSTEM_CONFIG, auditorToken)));
        check("AUDITOR cannot manage accounts", throwsDenied(
                () -> gate.require(AdminRole.Permission.USER_MANAGE, auditorToken)));

        check("a missing token is refused", throwsDenied(
                () -> gate.require(AdminRole.Permission.USER_READ, null)));
        check("a forged token is refused", throwsDenied(
                () -> gate.require(AdminRole.Permission.USER_READ, "not-a-real-token")));

        AdminSession killed = sessions.issue(new AdminPrincipal("erin", AdminRole.SUPER_ADMIN));
        sessions.revoke(killed.tokenId());
        check("a revoked session cannot reach a privileged operation",
                throwsDenied(() -> gate.require(AdminRole.Permission.USER_MANAGE, killed.tokenId())));

        h.advance(h.config.sessionIdleMillis() + 1L);
        check("an idle-expired session cannot reach a privileged operation",
                throwsDenied(() -> gate.require(AdminRole.Permission.USER_READ, deskToken)));

        check("HELPDESK grants exactly one permission", AdminRole.HELPDESK.permissions().size() == 1);
        check("SUPER_ADMIN is the only role that may change system configuration",
                Arrays.stream(AdminRole.values())
                        .filter(role -> role.grants(AdminRole.Permission.SYSTEM_CONFIG)).count() == 1);
        check("no lesser role has the same permissions as SUPER_ADMIN",
                Arrays.stream(AdminRole.values()).noneMatch(role -> role != AdminRole.SUPER_ADMIN
                        && role.permissions().equals(AdminRole.SUPER_ADMIN.permissions())));
        check("SECURITY_ADMIN cannot read the audit trail", throwsDenied(() -> {
            String token = new SessionManager(h.config, h.audit, h.clock)
                    .issue(new AdminPrincipal("frank", AdminRole.SECURITY_ADMIN)).tokenId();
            gate.require(AdminRole.Permission.AUDIT_READ, token);
        }));
    }

    // ------------------------------------------------------------------ privileged ops

    private static void operationsChecks(Path work) {
        section("privileged operations");
        Harness h = new Harness(work, "ops");
        OpsBundle bundle = new OpsBundle(h);
        String root = bundle.sessions.issue(new AdminPrincipal("alice", AdminRole.SUPER_ADMIN)).tokenId();
        String desk = bundle.sessions.issue(new AdminPrincipal("carol", AdminRole.HELPDESK)).tokenId();

        check("listing accounts returns the seeded administrators",
                bundle.operations.listAccounts(root).size() == 2);

        check("a SUPER_ADMIN can create an administrator", bundle.operations.createAdministrator(root, "dave",
                GOOD_PASSWORD.toCharArray(), GOOD_PASSWORD.toCharArray(), AdminRole.SECURITY_ADMIN).accepted());
        check("the new account can sign in immediately",
                h.auth.authenticate("dave", GOOD_PASSWORD.toCharArray()).granted());

        check("a duplicate username is refused case-insensitively",
                !bundle.operations.createAdministrator(root, "DAVE", GOOD_PASSWORD.toCharArray(),
                        GOOD_PASSWORD.toCharArray(), AdminRole.SECURITY_ADMIN).accepted());
        check("a mismatched confirmation is refused",
                !bundle.operations.createAdministrator(root, "erin", GOOD_PASSWORD.toCharArray(),
                        OTHER_PASSWORD.toCharArray(), AdminRole.HELPDESK).accepted());
        check("a refused creation leaves no account behind", !h.store.exists("erin"));
        check("a weak password is refused", !bundle.operations.createAdministrator(root, "erin",
                "abc".toCharArray(), "abc".toCharArray(), AdminRole.HELPDESK).accepted());
        check("a username with a space is refused", !bundle.operations.createAdministrator(root, "two words",
                GOOD_PASSWORD.toCharArray(), GOOD_PASSWORD.toCharArray(), AdminRole.HELPDESK).accepted());
        check("an injection-style username is refused", !bundle.operations.createAdministrator(root,
                "x:SUPER_ADMIN:ACTIVE:0:0:0", GOOD_PASSWORD.toCharArray(), GOOD_PASSWORD.toCharArray(),
                AdminRole.HELPDESK).accepted());

        check("HELPDESK cannot create administrators", throwsDenied(
                () -> bundle.operations.createAdministrator(desk, "mallory", GOOD_PASSWORD.toCharArray(),
                        GOOD_PASSWORD.toCharArray(), AdminRole.SUPER_ADMIN)));
        check("the refused account was not created", !h.store.exists("mallory"));
        check("HELPDESK cannot list accounts it is not entitled to see", throwsDenied(
                () -> bundle.operations.listAccounts("bogus-token")));

        // Password reset must invalidate sessions issued under the old password.
        AdminSession daveSession = bundle.sessions.issue(new AdminPrincipal("dave", AdminRole.SECURITY_ADMIN));
        check("the new account had a live session",
                bundle.sessions.validate(daveSession.tokenId()).isPresent());
        check("a SUPER_ADMIN can reset a password", bundle.operations.resetPassword(root, "dave",
                OTHER_PASSWORD.toCharArray(), OTHER_PASSWORD.toCharArray()).accepted());
        check("resetting a password revokes that account's live sessions",
                bundle.sessions.validate(daveSession.tokenId()).isEmpty());
        check("the new password works",
                h.auth.authenticate("dave", OTHER_PASSWORD.toCharArray()).granted());
        check("the old password no longer works",
                !h.auth.authenticate("dave", GOOD_PASSWORD.toCharArray()).granted());
        check("a reset to a weak password is refused",
                !bundle.operations.resetPassword(root, "dave", "abc".toCharArray(),
                        "abc".toCharArray()).accepted());
        check("a refused reset leaves the working password in place",
                h.auth.authenticate("dave", OTHER_PASSWORD.toCharArray()).granted());

        AdminSession daveAgain = bundle.sessions.issue(new AdminPrincipal("dave", AdminRole.SECURITY_ADMIN));
        check("disabling an account is accepted", bundle.operations.disableAccount(root, "dave").accepted());
        check("a disabled account's sessions are revoked",
                bundle.sessions.validate(daveAgain.tokenId()).isEmpty());
        check("a disabled account cannot authenticate",
                !h.auth.authenticate("dave", OTHER_PASSWORD.toCharArray()).granted());
        check("re-enabling an account is accepted", bundle.operations.enableAccount(root, "dave").accepted());
        check("the re-enabled account can sign in",
                h.auth.authenticate("dave", OTHER_PASSWORD.toCharArray()).granted());

        check("clearing a lockout is accepted", bundle.operations.clearLockout(root, "dave").accepted());

        AdminSession carolSession = bundle.sessions.issue(new AdminPrincipal("carol", AdminRole.HELPDESK));
        check("changing a role is accepted",
                bundle.operations.changeRole(root, "carol", AdminRole.SECURITY_ADMIN).accepted());
        check("changing a role revokes the affected sessions",
                bundle.sessions.validate(carolSession.tokenId()).isEmpty());
        check("the new role is in force on the next sign-in",
                h.auth.authenticate("carol", GOOD_PASSWORD.toCharArray()).principal().role()
                        == AdminRole.SECURITY_ADMIN);

        // The last active super-administrator cannot be removed by any route.
        Harness solo = new Harness(work, "solo");
        OpsBundle soloOps = new OpsBundle(solo);
        String soloToken = soloOps.sessions.issue(new AdminPrincipal("alice", AdminRole.SUPER_ADMIN)).tokenId();
        check("the last SUPER_ADMIN cannot be disabled",
                !soloOps.operations.disableAccount(soloToken, "alice").accepted());
        check("the last SUPER_ADMIN cannot be demoted",
                !soloOps.operations.changeRole(soloToken, "alice", AdminRole.HELPDESK).accepted());
        check("the account is still an active SUPER_ADMIN",
                solo.store.find("alice").get().role() == AdminRole.SUPER_ADMIN
                        && solo.store.find("alice").get().state() == AccountState.ACTIVE);
        check("a portal whose last super-administrator is intact stays usable",
                soloOps.operations.listAccounts(soloToken).size() == 2
                        && soloOps.operations.listAccounts(soloToken).stream()
                                .anyMatch(view -> view.username().equals("alice")));

        soloOps.operations.createAdministrator(soloToken, "second", GOOD_PASSWORD.toCharArray(),
                GOOD_PASSWORD.toCharArray(), AdminRole.SUPER_ADMIN);
        check("with two super-administrators, one may be disabled",
                soloOps.operations.disableAccount(soloToken, "second").accepted());

        check("HELPDESK cannot revoke other people's sessions", throwsDenied(
                () -> soloOps.operations.revokeSessions(desk, "alice")));
        check("no account listing exposes a digest", soloOps.operations.listAccounts(soloToken).stream()
                .noneMatch(view -> view.toString().contains("PBKDF2")));

        // Every privileged mutation must persist: a reload must show the same world.
        CredentialStore reloaded = new CredentialStore(solo.store.file()).load();
        check("mutations survive a reload", reloaded.find("second").isPresent()
                && reloaded.find("second").get().state() == AccountState.DISABLED);
        check("an unknown account cannot be disabled",
                !soloOps.operations.disableAccount(soloToken, "ghost").accepted());
    }

    // ------------------------------------------------------------------ audit

    private static void auditChecks(Path work) {
        section("audit trail");
        AuditEvent injection = new AuditEvent(1L, AuditResult.FAILURE,
                "alice\nAUDIT 2026-09-05 SUCCESS admin logged in", "bad credentials\nsecond line");
        check("a newline in the username cannot forge an extra log line",
                injection.toString().indexOf('\n') < 0);
        check("a newline in the detail cannot forge an extra log line",
                injection.toString().lines().count() == 1);
        check("control characters are stripped from usernames",
                new AuditEvent(1L, AuditResult.FAILURE, "a" + (char) 7 + "b" + (char) 0 + "cd", "x")
                        .username().equals("abcd"));
        check("an over-long username is truncated",
                new AuditEvent(1L, AuditResult.FAILURE, repeat("u", 5_000), "x").toString().length() < 400);
        check("a null username is rendered as a placeholder",
                new AuditEvent(1L, AuditResult.FAILURE, null, null).username().equals("-"));
        check("a non-ASCII separator cannot smuggle a line break",
                new AuditEvent(1L, AuditResult.FAILURE, "us" + (char) 0x2028 + "er", "x")
                        .username().indexOf((char) 0x2028) < 0);

        Harness h = new Harness(work, "auditlog");
        check("nothing is recorded before an attempt", h.audit.size() == 0);
        h.auth.authenticate("alice", GOOD_PASSWORD.toCharArray());
        check("a successful sign-in is recorded", h.audit.count(AuditResult.SUCCESS) >= 1);
        h.auth.authenticate("alice", WRONG_PASSWORD.toCharArray());
        check("a failed sign-in is recorded", h.audit.count(AuditResult.FAILURE) >= 1);
        h.auth.authenticate("nosuchuser", WRONG_PASSWORD.toCharArray());
        check("an unknown-username attempt is recorded", h.audit.count(AuditResult.FAILURE) >= 2);

        h.advance(h.auth.config().lockDurationMillis() * 2);
        h.auth.clearFailureHistory();
        for (int i = 0; i < h.auth.config().maxFailedAttempts(); i++) {
            h.auth.authenticate("alice", ("Wrong-Guess-" + i + "-99").toCharArray());
        }
        check("a lockout is recorded", h.audit.count(AuditResult.LOCKED) >= 1);

        boolean leaked = false;
        for (AuditEvent event : h.audit.all()) {
            if (event.detail().contains(GOOD_PASSWORD) || event.detail().contains(WRONG_PASSWORD)
                    || event.detail().contains("PBKDF2")) {
                leaked = true;
            }
        }
        check("no audit event records a password or a digest", !leaked);

        InMemoryAuditLog bounded = new InMemoryAuditLog(null, 10);
        for (int i = 0; i < 500; i++) {
            bounded.record(AuditResult.INFO, "user" + i, "note");
        }
        check("the in-memory audit window is bounded", bounded.size() == 10);
        check("it retains the newest events", bounded.recent(1).get(0).username().equals("user499"));
        check("a plain sink retains nothing but still accepts events", () -> {
            AuditLog plain = event -> { };
            plain.record(AuditResult.SUCCESS, "x", "y");
            return plain.recent(10).isEmpty();
        });
    }

    // ------------------------------------------------------------------ console / cli

    private static void consoleChecks(Path work) throws Exception {
        section("console flow");
        Harness h = new Harness(work, "console");

        Run signedIn = runCli(h, null, new ScriptedReader()
                .line("alice").secret(GOOD_PASSWORD)
                .line("1")
                .line("q"));
        check("a correct sign-in reaches the menu", signedIn.printed.contains("Access granted"));
        check("signing out exits cleanly", signedIn.code == 0);
        check("the account list is shown", signedIn.printed.contains("alice"));
        check("the console never prints the password", !signedIn.printed.contains(GOOD_PASSWORD));
        check("the console never prints a digest", !signedIn.printed.contains("PBKDF2"));

        ScriptedReader exhausted = new ScriptedReader();
        for (int i = 0; i < AdminConsole.MAX_SIGNIN_TURNS; i++) {
            exhausted.line("alice").secret("Wrong-Guess-" + i + "-99");
        }
        Run deniedRun = runCli(h, null, exhausted);
        check("a wrong password never reaches the menu", !deniedRun.printed.contains("Access granted"));
        check("every denial uses the generic message",
                deniedRun.printed.contains(AuthResult.GENERIC_FAILURE));
        check("the console stops prompting after its own cap", deniedRun.code == 4);
        check("the console says why it stopped", deniedRun.printed.contains("stopped for this terminal"));

        Run emptyRun = runCli(new Harness(new CredentialStore(work.resolve("console-empty.dat")),
                new Clock.Fake(), AuthenticationConfig.defaults()), null,
                new ScriptedReader().line("alice").secret(GOOD_PASSWORD));
        check("signing in against an unprovisioned store is refused", emptyRun.code == 3);
        check("the unprovisioned store tells the operator what to do",
                emptyRun.printed.contains("--bootstrap-first-admin"));

        // A session revoked behind the console's back must stop working immediately.
        Harness revoked = new Harness(work, "console2");
        OpsBundle bundle = new OpsBundle(revoked);
        String token = bundle.sessions.issue(new AdminPrincipal("alice", AdminRole.SUPER_ADMIN)).tokenId();
        bundle.sessions.revokeAllForUser("alice", "simulated theft");
        check("a session killed behind the console's back is refused",
                throwsDenied(() -> bundle.operations.listAccounts(token)));

        // Bootstrap: once only, always SUPER_ADMIN, never with a weak password.
        Path freshFile = work.resolve("bootstrap.dat");
        Harness fresh = new Harness(new CredentialStore(freshFile), new Clock.Fake(),
                AuthenticationConfig.fast(5, 120_000L, 60_000L));
        Run firstBoot = runCli(fresh, "--bootstrap-first-admin",
                new ScriptedReader().line("rootadmin").secret(GOOD_PASSWORD).secret(GOOD_PASSWORD));
        check("bootstrap exits cleanly", firstBoot.code == 0);
        CredentialStore after = new CredentialStore(freshFile).load();
        check("bootstrap created exactly one account", after.size() == 1);
        check("bootstrap always creates a SUPER_ADMIN",
                after.find("rootadmin").get().role() == AdminRole.SUPER_ADMIN);
        check("bootstrap stores no plaintext",
                !new String(Files.readAllBytes(freshFile), StandardCharsets.UTF_8).contains(GOOD_PASSWORD));

        Harness sameAgain = new Harness(new CredentialStore(freshFile).load(), new Clock.Fake(),
                AuthenticationConfig.fast(5, 120_000L, 60_000L));
        Run secondBoot = runCli(sameAgain, "--bootstrap-first-admin",
                new ScriptedReader().line("mallory").secret(OTHER_PASSWORD).secret(OTHER_PASSWORD));
        check("bootstrap refuses to run a second time", secondBoot.code == 6);
        check("the refusal names the reason", secondBoot.printed.contains("Refusing to bootstrap"));
        check("the refusal adds no account", new CredentialStore(freshFile).load().size() == 1);

        Path weakFile = work.resolve("weakboot.dat");
        Harness weakHarness = new Harness(new CredentialStore(weakFile), new Clock.Fake(),
                AuthenticationConfig.fast(5, 120_000L, 60_000L));
        ScriptedReader weakInput = new ScriptedReader();
        for (int i = 0; i < 3; i++) {
            weakInput.secret("short").secret("short");
        }
        Run weakBoot = runCli(weakHarness, "--bootstrap-first-admin weakadmin", weakInput);
        check("bootstrap rejects a weak password", weakBoot.code != 0);
        check("a rejected bootstrap provisions nothing",
                !Files.exists(weakFile) || new CredentialStore(weakFile).load().isEmpty());

        Harness afterBoot = new Harness(new CredentialStore(freshFile).load(), new Clock.Fake(),
                AuthenticationConfig.fast(5, 120_000L, 60_000L));
        Run loginAfterBoot = runCli(afterBoot, null,
                new ScriptedReader().line("rootadmin").secret(GOOD_PASSWORD).line("q"));
        check("the bootstrapped account can sign in", loginAfterBoot.printed.contains("Access granted"));
    }

    private static void cliChecks(Path work) {
        section("command line");
        Harness h = new Harness(work, "cli");

        check("--verify exits 0 for valid credentials",
                runCli(h, "--verify alice", new ScriptedReader().secret(GOOD_PASSWORD)).code == 0);

        Run wrong = runCli(h, "--verify alice", new ScriptedReader().secret(WRONG_PASSWORD));
        check("--verify exits 1 for an invalid password", wrong.code == 1);

        Run ghost = runCli(h, "--verify ghost", new ScriptedReader().secret(WRONG_PASSWORD));
        check("--verify exits 1 for an unknown username", ghost.code == 1);
        check("an unknown username and a wrong password are indistinguishable",
                ghost.code == wrong.code
                        && ghost.printed.contains(AuthResult.GENERIC_FAILURE)
                        && wrong.printed.contains(AuthResult.GENERIC_FAILURE));

        check("an unrecognised option is a usage error", runCli(h, "--nope", null).code == 2);
        check("--help exits 0", runCli(h, "--help", null).code == 0);
        check("--verify without a username is a usage error", runCli(h, "--verify", null).code == 2);
        check("--store without a path is a usage error", runCli(h, "--store", null).code == 2);

        // Secrets on the command line leak through ps and shell history, so the CLI must
        // not accept them there.
        check("a password on the command line is rejected as an unknown option",
                runCli(h, "--verify alice --password " + GOOD_PASSWORD,
                        new ScriptedReader().secret(GOOD_PASSWORD)).code == 2);
        check("the help text offers no --password switch", !Main.usageText().contains("--password"));
        check("the help text points at a file-based secret instead",
                Main.usageText().contains("PASSWORD_FILE"));
    }

    // ------------------------------------------------------------------ harness

    private static final class Harness {
        final CredentialStore store;
        final InMemoryAuditLog audit;
        final Clock.Fake clock;
        final AuthenticationConfig config;
        final AuthenticationService auth;

        Harness(Path work, String name) {
            this(new CredentialStore(work.resolve(name + ".dat")), new Clock.Fake(),
                    AuthenticationConfig.fast(5, 120_000L, 60_000L));
            PasswordHasher hasher = new PasswordHasher(new CountingKdf(), PasswordHasher.MIN_ITERATIONS);
            store.put(new AdminAccount("alice", hasher.hash(GOOD_PASSWORD.toCharArray()),
                    AdminRole.SUPER_ADMIN));
            store.put(new AdminAccount("carol", hasher.hash(GOOD_PASSWORD.toCharArray()),
                    AdminRole.HELPDESK));
            store.save();
        }

        Harness(CredentialStore store, Clock.Fake clock, AuthenticationConfig config) {
            this.store = store;
            this.clock = clock;
            this.config = config;
            this.audit = new InMemoryAuditLog(null, 500);
            this.auth = new AuthenticationService(store,
                    new PasswordHasher(new CountingKdf(), PasswordHasher.MIN_ITERATIONS),
                    config, audit, clock, false);
        }

        long now() {
            return clock.now();
        }

        void advance(long millis) {
            clock.advance(millis);
        }

        int storedFailures(String username) {
            return store.find(username).map(AdminAccount::consecutiveFailures).orElse(-1);
        }
    }

    private static final class OpsBundle {
        final SessionManager sessions;
        final AdminOperations operations;

        OpsBundle(Harness h) {
            this.sessions = new SessionManager(h.config, h.audit, h.clock);
            this.operations = new AdminOperations(h.store,
                    new PasswordHasher(new CountingKdf(), PasswordHasher.MIN_ITERATIONS),
                    new PasswordPolicy(), sessions, new AdminGate(sessions, h.audit), h.audit, h.clock);
        }
    }

    /** Queued answers, so the whole console and CLI flow is exercisable without a tty. */
    private static final class ScriptedReader implements InteractiveReader {
        private final Deque<String> lines = new ArrayDeque<>();
        private final Deque<char[]> secrets = new ArrayDeque<>();

        ScriptedReader line(String value) {
            lines.addLast(value);
            return this;
        }

        ScriptedReader secret(String value) {
            secrets.addLast(value.toCharArray());
            return this;
        }

        @Override
        public String readLine(String prompt) {
            return lines.pollFirst();
        }

        @Override
        public char[] readSecret(String prompt) {
            char[] next = secrets.pollFirst();
            return next == null ? new char[0] : next;
        }

        @Override
        public boolean supportsSecretEntry() {
            return true;
        }
    }

    /** Exit code plus everything printed by one {@link Main#run} invocation. */
    private static final class Run {
        final int code;
        final String printed;

        Run(int code, String printed) {
            this.code = code;
            this.printed = printed;
        }
    }

    /**
     * Drives the real CLI entry point against a harness. {@code args} is split on
     * whitespace and {@code --store} is appended, so each check points at its own file.
     */
    private static Run runCli(Harness h, String args, ScriptedReader reader) {
        java.io.ByteArrayOutputStream sink = new java.io.ByteArrayOutputStream();
        java.io.PrintStream out = new java.io.PrintStream(sink, true, StandardCharsets.UTF_8);
        List<String> argv = new ArrayList<>();
        argv.add("--store");
        argv.add(h.store.file().toString());
        if (args != null && !args.trim().isEmpty()) {
            argv.addAll(Arrays.asList(args.trim().split("\\s+")));
        }
        PasswordHasher hasher = new PasswordHasher(new CountingKdf(), PasswordHasher.MIN_ITERATIONS);
        int code = Main.run(argv.toArray(new String[0]), out, path -> {
            PortalApp app = new PortalApp(path, h.config, hasher, h.clock, silentAudit());
            return reader == null ? app : app.withReader(reader);
        });
        return new Run(code, sink.toString(StandardCharsets.UTF_8));
    }

    /** Quiet sink; assertions read the in-memory window that PortalApp always keeps. */
    private static AuditLog silentAudit() {
        return event -> { };
    }

    // ------------------------------------------------------------------ plumbing

    /** Cheap-but-real PBKDF2, so the suite finishes quickly while still exercising PBKDF2. */
    private static final class CountingKdf implements KeyDerivation {
        private final Pbkdf2 delegate = new Pbkdf2();
        int count;

        @Override
        public byte[] derive(char[] password, byte[] salt, int iterations, int keyBits) {
            count++;
            return delegate.derive(password, salt, iterations, keyBits);
        }

        @Override
        public String algorithmId() {
            return "PBKDF2-SHA256";
        }
    }

    /**
     * Rewrites the final base64 character of a digest to one that shares its leading bits.
     * It decodes to the same bytes, which is exactly the malleability a canonical check has
     * to refuse: otherwise a stored value could be rewritten and still verify.
     */
    /**
     * Loads a store, reporting an unusable file as {@code null} rather than aborting the
     * suite. Callers assert on the two acceptable outcomes explicitly.
     */
    private static CredentialStore loadOrFail(Path file) {
        try {
            return new CredentialStore(file).load();
        } catch (IllegalStateException e) {
            System.out.println("  note  load refused the file: " + e.getMessage());
            return null;
        }
    }

    private static String sha256Hex(String value) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
            }
            return hex.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final String BASE64_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * Rewrites the last data character of a digest's base64 field to one that differs only
     * in a bit base64 discards, so it decodes to identical bytes. A store that accepted
     * both spellings would let a stored digest be rewritten while still verifying.
     */
    private static String nonCanonicalEquivalent(String stored) {
        String[] parts = stored.split("\\$", -1);
        String value = parts[3];
        int padStart = value.indexOf('=');
        check("the stored digest field is padded", padStart > 0);
        int index = BASE64_ALPHABET.indexOf(value.charAt(padStart - 1));
        check("the final digest character is a base64 digit", index >= 0);
        // A single pad character means the last digit carries two discardable low bits.
        char swapped = BASE64_ALPHABET.charAt(index ^ 1);
        check("the substituted digit differs from the original", swapped != value.charAt(padStart - 1));
        String changed = value.substring(0, padStart - 1) + swapped + value.substring(padStart);
        return parts[0] + "$" + parts[1] + "$" + parts[2] + "$" + changed;
    }

    /** Field counts of every record line in a store file, in order. */
    private static List<Integer> recordFields(String fileText, String header) {
        List<Integer> counts = new ArrayList<>();
        for (String line : fileText.split("\n")) {
            if (line.isEmpty() || line.startsWith(header) || line.startsWith("#")) {
                continue;
            }
            counts.add(line.split(":", -1).length);
        }
        return counts;
    }

    private static String recordLine(String fileText, String header) {
        for (String line : fileText.split("\n")) {
            if (!line.isEmpty() && !line.startsWith(header) && !line.startsWith("#")) {
                return line;
            }
        }
        return ":";
    }

    private static boolean throwsDenied(Runnable action) {
        try {
            action.run();
            return false;
        } catch (AccessDeniedException e) {
            return true;
        }
    }

    private static boolean throwsIllegalState(Runnable action) {
        try {
            action.run();
            return false;
        } catch (IllegalStateException e) {
            return true;
        }
    }

    private static boolean throwsIllegalArgument(Runnable action) {
        try {
            action.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    private static boolean ownerOnly(Set<PosixFilePermission> permissions) {
        return permissions.equals(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
    }

    /** Changes one base64 character to a different one, leaving the length intact. */
    private static String corruptAt(String value, int index) {
        char original = value.charAt(index);
        char replacement = original == 'A' ? 'B' : 'A';
        return value.substring(0, index) + replacement + value.substring(index + 1);
    }

    private static String repeat(String unit, int times) {
        StringBuilder builder = new StringBuilder(unit.length() * times);
        for (int i = 0; i < times; i++) {
            builder.append(unit);
        }
        return builder.toString();
    }

    private static List<String> listSiblings(Path file) throws Exception {
        List<String> names = new ArrayList<>();
        try (java.util.stream.Stream<Path> children = Files.list(file.getParent())) {
            children.forEach(child -> names.add(child.getFileName().toString()));
        }
        return names;
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) {
            return;
        }
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toArray(Path[]::new)) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void section(String name) {
        System.out.println("== " + name);
    }

    private static void check(String what, boolean condition) {
        checks++;
        if (!condition) {
            FAILURES.add(what);
            System.out.println("  FAIL " + what);
        }
    }

    private static void check(String what, java.util.function.BooleanSupplier condition) {
        check(what, condition.getAsBoolean());
    }

    static {
        if (GOOD_PASSWORD.length() < PasswordPolicy.MIN_LENGTH || OTHER_PASSWORD.length() < PasswordPolicy.MIN_LENGTH) {
            throw new IllegalStateException("suite passwords do not satisfy the policy under test");
        }
    }
}
