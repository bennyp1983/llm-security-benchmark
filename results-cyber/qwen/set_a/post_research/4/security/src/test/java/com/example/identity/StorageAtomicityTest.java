package com.example.identity;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.note;
import static com.example.identity.Harness.section;

/**
 * Check-then-act atomicity (Rule 7) and the re-validation of everything the database hands back.
 *
 * <p>Two half-suites in one file, because they are the same claim seen from opposite ends:
 * <ul>
 *   <li><b>Writing.</b> The account cap, the registration budgets and the per-account session cap
 *     are all decisions of the form "count, then act". Outside one transaction they are a race that
 *     hands out more accounts or more sessions than configured. Timed tests cannot falsify an
 *     atomic decision - two threads interleaving is not something you can make happen on demand, and
 *     a test that passes for broken code is worse than no test - so each property is asserted two
 *     ways: the <em>observable invariant</em> under real concurrency, and a <em>structural</em>
 *     guard on the statement that does the counting. The structural guard is what actually fails
 *     when someone replaces the single {@code DELETE} with a count followed by a truncate.</li>
 *   <li><b>Reading.</b> Rule 1 says the database is attacker-controlled: whoever can write the file
 *     or talk to a SQL console can install a row this program would never have written. Every such
 *     row is installed here with {@link Harness#rawExecute} - a second connection, deliberately
 *     bypassing the application's writers - and asserted to be refused rather than repaired,
 *     echoed, or believed.</li>
 * </ul>
 */
public final class StorageAtomicityTest {

    private StorageAtomicityTest() {
    }

    public static void run() throws Exception {
        accountCapCannotBeRaced();
        sessionCapCannotBeExceeded();
        duplicateClassification();
        corruptRowsAreRefused();
        sqlInjectionShapes();
        structuralGuards();
    }

    // ------------------------------------------------------------------ Rule 7: writes

    private static void accountCapCannotBeRaced() throws Exception {
        section("The account cap holds under concurrent registration");
        Harness.Overrides o = Harness.overrides();
        o.maxAccounts = 3;
        Harness.Fixture f = Harness.fixture("cap-race", o);
        try (Harness.Bundle b = Harness.openApi(f)) {
            int threads = 10;
            AtomicInteger created = new AtomicInteger();
            AtomicInteger capRefusals = new AtomicInteger();
            CountDownLatch ready = new CountDownLatch(threads);
            CountDownLatch go = new CountDownLatch(1);
            List<Thread> pool = new ArrayList<>();
            List<String> otherReasons = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                final int n = i;
                Thread t = new Thread(() -> {
                    ready.countDown();
                    try {
                        go.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    String user = "racer" + n;
                    AuthResult r;
                    try {
                        r = b.api.register(user + "@example.com", user, Harness.chars(Harness.P1),
                                SourceId.LOCAL);
                    } catch (IdentityStoreException e) {
                        synchronized (otherReasons) {
                            otherReasons.add(e.reason().name());
                        }
                        return;
                    }
                    if (r.reason() == Reason.ACCOUNT_CREATED) {
                        created.incrementAndGet();
                    } else if (r.reason() == Reason.ACCOUNT_CAP_REACHED) {
                        capRefusals.incrementAndGet();
                    } else {
                        synchronized (otherReasons) {
                            otherReasons.add(r.reason().name());
                        }
                    }
                }, "reg-" + n);
                pool.add(t);
                t.start();
            }
            ready.await();
            go.countDown();
            for (Thread t : pool) {
                t.join(120_000L);
            }
            check("no registration aborted with an unexpected outcome", otherReasons.isEmpty());
            checkEquals("exactly maxAccounts registrations succeeded", 3, created.get());
            checkEquals("the rest were refused by the cap, not by anything else", 7, capRefusals.get());
            checkEquals("the stored row count equals the cap, never cap+1", 3, Harness.rawCount(f, "account"));
            checkEquals("the API's own count agrees with the table", 3, b.api.accountCount());
            note("10 threads, cap 3, " + created.get() + " created / " + capRefusals.get()
                    + " refused");
        }

        section("A cap refusal is a capacity answer, not a rate-limit answer (rollback discipline)");
        Harness.Overrides o2 = Harness.overrides();
        o2.maxAccounts = 1;
        o2.regGlobalMax = 100;
        o2.regSourceMax = 100;
        Harness.Fixture f2 = Harness.fixture("cap-rollback", o2);
        try (Harness.Bundle b = Harness.openApi(f2)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            int bucketsAfterSuccess = Harness.rawCount(f2, "auth_throttle");
            check("a successful registration charged its budget rows", bucketsAfterSuccess > 0);
            for (int i = 0; i < 5; i++) {
                AuthResult r = b.api.register("extra" + i + "@example.com", "extra" + i,
                        Harness.chars(Harness.P2), SourceId.LOCAL);
                check("attempt " + i + " is refused by the cap", r.reason() == Reason.ACCOUNT_CAP_REACHED);
            }
            checkEquals("refused registrations are rolled back and charge no budget (a full database"
                            + " must not convert a capacity limit into a lockout for everyone)",
                    bucketsAfterSuccess, Harness.rawCount(f2, "auth_throttle"));
            check("the cap is still reported as the cap after five attempts (not as throttling)",
                    b.api.register(Harness.E2, "latecomer", Harness.chars(Harness.P3), SourceId.LOCAL)
                            .reason() == Reason.ACCOUNT_CAP_REACHED);
        }
    }

    private static void sessionCapCannotBeExceeded() throws Exception {
        section("The per-account session cap converges, sequentially and concurrently");
        Harness.Overrides o = Harness.overrides();
        o.maxSessions = 2;
        Harness.Fixture f = Harness.fixture("sess-cap", o);
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            List<String> tokens = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                AuthResult r = b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL);
                check("login " + i + " succeeded", r.isSuccess());
                tokens.add(r.token().value());
                // Distinct created_at per session, so "newest wins" is a defined ordering rather
                // than a tie the engine may break arbitrarily.
                f.clock.advanceSeconds(1);
            }
            checkEquals("the table holds exactly maxSessionsPerAccount rows", 2,
                    Harness.rawCount(f, "session"));
            checkEquals("the API's live count matches", 2, b.api.liveSessionCount());
            check("the two newest sessions are live",
                    b.api.checkSession(tokens.get(3)).isSuccess()
                            && b.api.checkSession(tokens.get(4)).isSuccess());
            check("the three evicted sessions are gone, not merely judged dead on read",
                    Harness.rawCount(f, "session") == 2
                            && !b.api.checkSession(tokens.get(0)).isSuccess()
                            && !b.api.checkSession(tokens.get(1)).isSuccess()
                            && !b.api.checkSession(tokens.get(2)).isSuccess());
            check("an evicted token cannot be resurrected by presenting it again",
                    !b.api.checkSession(tokens.get(0)).isSuccess());
        }

        section("Concurrent session creation never leaves more than the cap live");
        Harness.Fixture f2 = Harness.fixture("sess-cap-race", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f2)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            // Driven through the store, not signIn, and the reason is the shed above: AuthApi allows
            // only one verification in flight per account (DecisionGuard, which is what stops K
            // sockets buying K guesses per window), so eight concurrent logins against one account
            // would mostly be refused before reaching the insert. The cap itself is a check-then-act
            // inside createSession's transaction, so that is the operation that has to race.
            SqlIdentityStore.Account account = b.store.findByCanonicalIdentity(
                    Identity.parseClientUsername(Harness.U1));
            int threads = 8;
            int cap = Harness.overrides().maxSessions;
            CountDownLatch go = new CountDownLatch(1);
            AtomicInteger created = new AtomicInteger();
            List<Thread> pool = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                Thread t = new Thread(() -> {
                    try {
                        go.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    try {
                        b.store.createSession(account.id(),
                                SessionToken.generate(new java.security.SecureRandom()),
                                f2.clock.nowEpochSeconds());
                        created.incrementAndGet();
                    } catch (IdentityStoreException e) {
                        // a refusal is the expected outcome past the cap
                    }
                }, "session-" + i);
                pool.add(t);
                t.start();
            }
            go.countDown();
            for (Thread t : pool) {
                t.join(120_000L);
            }
            long live = Harness.rawCount(f2, "session");
            check("the session table never exceeds the per-account cap", live <= cap);
            checkEquals("and it is not under-filled either", (long) cap, live);
            checkEquals("every creator succeeded, because the cap is enforced by evicting the oldest"
                            + " session rather than by refusing a signed-in user - so the atomic"
                            + " property to test is that the prune and the insert never interleave"
                            + " into a table with more rows than the cap",
                    threads, created.get());
            checkEquals("no creator wrote a row that another one did not account for, so the row"
                            + " count is exactly the cap rather than cap plus a lost prune",
                    (long) cap, live);
            note(threads + " racing creators, cap " + cap + ", " + live + " rows, "
                    + created.get() + " reported success");
        }
    }

    // ------------------------------------------------------------------ duplicate classification

    private static void duplicateClassification() throws Exception {
        section("A collision is classified against the right column, but reported identically");
        Harness.Fixture f = Harness.fixture("dup-class", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            AuthResult sameName = b.api.register(Harness.E2, Harness.U1, Harness.chars(Harness.P3),
                    SourceId.LOCAL);
            AuthResult sameMail = b.api.register(Harness.E1, "someoneelse", Harness.chars(Harness.P3),
                    SourceId.LOCAL);
            // Two layers, and the difference between them is the control: the store classifies which
            // column collided (an operator investigating a ticket needs that), the API collapses both
            // collisions into one reason. Asserting only the shared *message* left the enum itself
            // carrying the answer - a front end can branch on it, serialise it, or echo it in a
            // header - so the collision stayed enumerable one getter away from the caller.
            String storedHash = Harness.rawColumn(f, "SELECT password FROM account").get(0);
            SqlIdentityStore.Outcome rawName = b.store.register(Harness.U1,
                    Identity.parseClientUsername(Harness.U1), Identity.parseClientEmail(Harness.E2),
                    Harness.E2, storedHash, SourceId.local());
            SqlIdentityStore.Outcome rawMail = b.store.register("someoneelse",
                    Identity.parseClientUsername("someoneelse"), Identity.parseClientEmail(Harness.E1),
                    Harness.E1, storedHash, SourceId.local());
            check("the store classifies the username collision by column",
                    rawName.reason() == Reason.USERNAME_TAKEN);
            check("the store classifies the email collision by column",
                    rawMail.reason() == Reason.EMAIL_TAKEN);
            check("both collapse to the one caller-facing reason",
                    rawName.callerReason() == Reason.REGISTRATION_DUPLICATE
                            && rawMail.callerReason() == rawName.callerReason());
            check("so what the API returned distinguishes nothing",
                    sameName.reason() == Reason.REGISTRATION_DUPLICATE
                            && sameMail.reason() == Reason.REGISTRATION_DUPLICATE);
            check("the collision probe read our own canonical column and found the real row",
                    Harness.rawColumn(f, "SELECT username_canon FROM account WHERE username_canon = 'alice'")
                            .equals(List.of("alice")));
            check("yet the caller cannot tell them apart",
                    sameName.userMessage().equals(sameMail.userMessage()));
            check("the collision probe did not create a row",
                    Harness.rawCount(f, "account") == 1);
            check("the case-folded spelling collides too (canonical columns are the unique ones)",
                    b.api.register("ALICE@EXAMPLE.COM", "ALICE", Harness.chars(Harness.P4), SourceId.LOCAL)
                            .reason() != Reason.ACCOUNT_CREATED);
            check("so the fold happens before the unique index, not after it",
                    Harness.rawCount(f, "account") == 1);
            check("the display form is what is stored, the canonical form is what is unique",
                    Harness.rawColumn(f, "SELECT username FROM account").equals(List.of(Harness.U1)));
            check("a username differing only by a trailing dot is a *different* canonical value and"
                    + " must therefore be refused by the grammar, not by the index",
                    b.api.register(Harness.E3, "alice.", Harness.chars(Harness.P4), SourceId.LOCAL)
                            .reason() == Reason.INVALID_USERNAME);
        }
    }

    // ------------------------------------------------------------------ untrusted reads

    private static void corruptRowsAreRefused() throws Exception {
        section("A stored row this program would never write is refused, not repaired");
        Harness.Fixture f = Harness.fixture("corrupt-read", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            Harness.register(b, Harness.E2, Harness.U2, Harness.P2);

            check("both accounts authenticate before we start breaking them",
                    b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());

            // 1. An email column that is no longer an address. The username still matches, so the
            //    row is still reachable - only re-validation stands between it and an outcome.
            Harness.rawExecute(f, "UPDATE account SET email_canon = 'not an address'"
                    + " WHERE username_canon = 'alice'");
            AuthResult viaBadEmail = b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL);
            check("a row whose email fails validation cannot be authenticated into",
                    !viaBadEmail.isSuccess());
            check("and the refusal is the generic one",
                    viaBadEmail.userMessage().equals(Reason.BAD_CREDENTIAL.genericUserMessage()));
            check("no session was issued", viaBadEmail.token() == null);
            check("the API surfaces it as a refusal rather than an exception",
                    viaBadEmail.reason() == Reason.BAD_CREDENTIAL);
            check("the broken row was not silently normalised back into shape",
                    Harness.rawColumn(f, "SELECT email_canon FROM account WHERE username_canon = 'alice'")
                            .equals(List.of("not an address")));
            check("the store itself reports the row corrupt (the detail the caller never sees)",
                    storeReportsCorrupt(b));

            // 2. A credential encoding that decodes to nothing usable.
            Harness.rawExecute(f, "UPDATE account SET password = 'v1$pbkdf2-sha256$99$AAA$BBB'"
                    + " WHERE username_canon = 'bob'");
            AuthResult viaBadCred = b.api.signIn(Harness.U2, Harness.chars(Harness.P2), SourceId.LOCAL);
            check("an under-costed or malformed credential is refused", !viaBadCred.isSuccess());
            check("with the same message as any other sign-in refusal",
                    viaBadCred.userMessage().equals(viaBadEmail.userMessage()));

            // 3. A status the CHECK constraint does not allow: the engine refuses it too, so the
            //    value can never reach the Java-side comparison by any route.
            int refusedByConstraint = 0;
            try {
                Harness.rawExecute(f, "UPDATE account SET status = 'superuser'"
                        + " WHERE username_canon = 'bob'");
            } catch (java.sql.SQLException constrained) {
                refusedByConstraint = 1;
            }
            check("the database itself refuses a status the application does not know",
                    refusedByConstraint == 1);
            check("so 'status = anything else grants access' is not reachable even with SQL write"
                    + " access",
                    Harness.rawColumn(f, "SELECT status FROM account WHERE username_canon = 'bob'")
                            .equals(List.of("active")));

            // 4. Widths: a VARCHAR narrower than the validator's maximum would truncate on write
            //    and hand back a *different* identity than the one that was registered. COALESCE
            //    because information_schema reports a NULL length for every non-character column,
            //    and in H2 `'NAME:' || NULL` is NULL - which arrives as a null list element and made
            //    the scan below throw before it reported a single width.
            List<String> widths = Harness.rawColumn(f,
                    "SELECT column_name || ':' || COALESCE(character_maximum_length, 0)"
                            + " FROM information_schema.columns WHERE table_name = 'ACCOUNT'");
            check("the width probe really saw the account table", widths.size() >= 5);
            check("username column is at least the validator's 32 code points", widthOf(widths, "USERNAME") >= 32);
            check("username_canon too", widthOf(widths, "USERNAME_CANON") >= 32);
            check("email columns are at least the 254-code-point address limit",
                    widthOf(widths, "EMAIL") >= 254 && widthOf(widths, "EMAIL_CANON") >= 254);
            check("the credential column fits the widest encoding the writer can emit",
                    widthOf(widths, "PASSWORD") >= 256);
            check("the stored encoding is the shape we claim, straight from the column",
                    storedEncodingShapeOk(f));
        }

        section("Two rows reachable by one identifier is a corrupt store, not a coin flip");
        Harness.Fixture f2 = Harness.fixture("dup-row", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f2)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            String live = b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).token().value();
            check("the account works first", b.api.checkSession(live).isSuccess());
            // The lookup is `email_canon = ? OR username_canon = ?`. The unique indexes make a
            // second username match impossible, so the only way to get two rows is to forge an
            // email_canon that is not an address - which itself proves the store was edited outside
            // the application. Either branch of the guard (two rows, or an invalid stored email)
            // must refuse; neither may pick a row arbitrarily.
            Harness.rawExecute(f2, "INSERT INTO account (username, username_canon, email, email_canon,"
                    + " password, status, created_epoch_s) VALUES ('zed','zed','alice','alice',"
                    + "'v1$pbkdf2-sha256$100000$AAAAAAAAAAA$AAAAAAAAAAA', 'active', 1700000000)");
            AuthResult ambiguous = b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL);
            check("an identifier that resolves to two rows authenticates nobody", !ambiguous.isSuccess());
            check("with the generic message",
                    ambiguous.userMessage().equals(Reason.BAD_CREDENTIAL.genericUserMessage()));
            check("and no session is issued for either row", ambiguous.token() == null);
            check("the legitimate row's own session is still honoured on read (revocation is not a"
                    + " side effect of a refused lookup)", b.api.checkSession(live).isSuccess());
            note("an address always contains '@' and a username never may, so the two canonical"
                    + " domains are disjoint and this ambiguity is unreachable through the"
                    + " application - only through a hand-edited table");
        }
    }

    private static boolean storeReportsCorrupt(Harness.Bundle b) {
        try {
            b.store.findByCanonicalIdentity(Identity.parseClientUsername(Harness.U1));
            return false;
        } catch (IdentityStoreException e) {
            return e.reason() == Reason.CORRUPT_RECORD;
        }
    }

    private static int widthOf(List<String> widths, String column) {
        for (String w : widths) {
            if (w.startsWith(column + ":")) {
                return Integer.parseInt(w.substring(column.length() + 1));
            }
        }
        return -1;
    }

    private static boolean storedEncodingShapeOk(Harness.Fixture f) throws Exception {
        // Read the row this section left intact. 'bob' was overwritten above with the deliberately
        // malformed encoding that check 2 needs, so sampling it here reported the fixture's own
        // breakage as a defect in the writer.
        List<String> rows = Harness.rawColumn(f,
                "SELECT password FROM account WHERE username_canon = 'alice'");
        if (rows.size() != 1) {
            return false;
        }
        String enc = rows.get(0);
        String[] parts = enc.split("\\$", -1);
        return parts.length == 5 && parts[0].equals("v1") && parts[1].equals("pbkdf2-sha256")
                && Integer.parseInt(parts[2]) >= PasswordHasher.minAcceptedIterations()
                && parts[3].length() == 24 && parts[4].length() == 44
                && enc.length() <= 256;
    }

    // ------------------------------------------------------------------ injection shapes

    private static void sqlInjectionShapes() throws Exception {
        section("Nothing a caller types can be a statement");
        Harness.Fixture f = Harness.fixture("injection", Harness.overrides());
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            int accounts = Harness.rawCount(f, "account");
            int sessions = Harness.rawCount(f, "session");
            check("the fixture itself starts with no session to lose", sessions == 0);
            List<String> payloads = List.of(
                    "a' OR '1'='1",
                    "' or 1=1--",
                    "alice'); DROP TABLE account;--",
                    "admin\";--",
                    "1;DELETE FROM session",
                    "alice@example.com'; UPDATE account SET status='active'",
                    "%' OR username_canon LIKE '%",
                    "alice\\'@example.com",
                    "' UNION SELECT id,username,email,password FROM account--",
                    "Robert'); DROP TABLE students;--");
            for (String p : payloads) {
                AuthResult reg = b.api.register(p, p, Harness.chars(Harness.P1), SourceId.LOCAL);
                check("registration refuses the payload <" + p + ">",
                        reg.reason() == Reason.INVALID_EMAIL || reg.reason() == Reason.INVALID_USERNAME);
                AuthResult in = b.api.signIn(p, Harness.chars(Harness.P1), SourceId.LOCAL);
                check("sign-in refuses the payload <" + p + "> without saying why",
                    !in.isSuccess() && in.userMessage().equals(Reason.BAD_CREDENTIAL.genericUserMessage()));
            }
            checkEquals("no statement executed: the account table is untouched", accounts,
                    Harness.rawCount(f, "account"));
            checkEquals("the session table is untouched", sessions, Harness.rawCount(f, "session"));
            check("every table the schema declares still exists",
                    Harness.rawCount(f, "account") >= 0 && Harness.rawCount(f, "auth_throttle") >= 0
                            && Harness.rawCount(f, "session") >= 0 && Harness.rawCount(f, "meta") >= 0);
            check("the legitimate account still authenticates afterwards",
                    b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());
            check("and that is the first session the payload loop ever failed to prevent"
                    + " (a payload that signed in would have added rows here instead)",
                    Harness.rawCount(f, "session") == sessions + 1);
            check("the payloads are all refused by the *grammar*, i.e. no quote can ever reach SQL",
                    payloads.stream().noneMatch(StorageAtomicityTest::couldBeAcceptedIdentity));
            note("defence is layered: every value is a bound parameter, and the accepted character"
                    + " set for an identity excludes ' ; \\ - before a space anyway");
        }
    }

    private static boolean couldBeAcceptedIdentity(String p) {
        return Identity.parseClientUsername(p) != null || Identity.parseClientEmail(p) != null;
    }

    // ------------------------------------------------------------------ structural guards

    private static void structuralGuards() {
        section("Structural: the counting and the acting are one statement");
        String src = Harness.stripJavaComments(Harness.sourceOf("SqlIdentityStore"));
        check("the source under guard is real Java, not a stub", src.contains("class SqlIdentityStore"));

        String register = Harness.methodBody(src, "register");
        check("the registration body was located", register.length() > 200);
        int lockAt = register.indexOf("FOR UPDATE");
        int capReadAt = register.indexOf("countAll(\"account\")");
        check("registration takes an explicit row lock", lockAt >= 0);
        check("the cap is counted only after the lock is held", lockAt >= 0 && capReadAt > lockAt);
        check("the budgets are read after the lock too",
                register.indexOf("readBudget(") > lockAt);
        check("a missing serialisation row fails closed instead of running unsynchronised",
                register.contains("registration serialisation row is missing"));
        check("the transaction is committed only after both budgets are charged",
                register.indexOf("chargeBudget(") < register.indexOf("connection.commit()"));
        check("no caller value is concatenated into the insert",
                !register.contains("+ username") && !register.contains("+ email")
                        && !register.contains("+ passwordHash"));

        String createSession = Harness.methodBody(src, "createSession");
        check("the session cap is one self-converging DELETE",
                createSession.contains("NOT IN") && createSession.contains("FETCH FIRST"));
        check("it does not count sessions first (which would be a race)",
                !createSession.contains("countSessions("));
        check("the insert and the prune are in one transaction",
                createSession.indexOf("connection.commit()") > createSession.indexOf("DELETE FROM session"));

        String charge = Harness.methodBody(src, "chargeFailure");
        check("the failure counter is incremented by the statement that reads it",
                charge.contains("SET failures = CASE WHEN"));
        check("the window roll-forward is in the same UPDATE as the increment",
                charge.indexOf("first_at_epoch_s = CASE WHEN") > charge.indexOf("SET failures = CASE WHEN"));

        String find = Harness.methodBody(src, "findByCanonicalIdentity");
        check("the lookup asks for both canonical forms in one bound statement",
                find.contains("email_canon = ? OR username_canon = ?"));

        check("the JDBC URL is assembled in code, never read from configuration",
                src.contains("\"jdbc:h2:file:\"") && !src.contains("jdbcUrl")
                        && !src.contains("getProperty(\"jdbc"));
        check("the driver is loaded by name through this class's own loader",
                src.contains("Class.forName(\"org.h2.Driver\", true, SqlIdentityStore.class.getClassLoader())"));
        check("the connection disables the H2 auto-server (no listening port)",
                src.contains("AUTO_SERVER=FALSE"));
        check("unique violations are classified on SQLState, never on message text",
                src.contains("startsWith(\"23\")") && !src.contains("getMessage().contains("));
    }
}
