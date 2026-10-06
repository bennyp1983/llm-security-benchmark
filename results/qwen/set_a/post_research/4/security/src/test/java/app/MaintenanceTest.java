package app;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The sweep that keeps the tables this feature fills from growing forever.
 *
 * <p>Two properties matter and they pull against each other. A sweep must actually delete - an
 * operator who runs the program a thousand times must not watch {@code throttle_bucket} grow by a
 * thousand rows - and a sweep must never be an escape from a control that is in force. If deleting a
 * spent budget were eligible while the denial it imposed was still live, one program run would be a
 * rate-limit reset for whoever happened to trigger it.
 *
 * <p>So every section pairs a bound with a survival: rows go away <em>and</em> the refusal that was
 * in force is still in force afterwards. The audit interaction is covered too, because the sweep
 * records an event and a trail it cannot write must not turn housekeeping into an outage.
 */
public final class MaintenanceTest {

    private static final String EMAIL = "sweep@corp.example";
    private static final String NAME = "sweep-user";

    /** A canonical credential at the floor cost, so rows can be inserted without hashing. */
    private static final String FLOOR_HASH = "$argon2id$v=19$m=" + Harness.TEST_MEMORY_KIB + ",t="
        + Harness.TEST_ITERATIONS + ",p=" + Harness.TEST_PARALLELISM + "$" + "A".repeat(22)
        + "$" + "A".repeat(43);

    public static void main(String[] argv) throws Exception {
        liveStateSurvives(Harness.freshFixture("maint-live"));
        deadSessionsAreDeleted(Harness.freshFixture("maint-sessions"));
        elapsedBucketsAreBounded(Harness.freshFixture("maint-buckets"));
        bucketWindowComesFromTheRow(Harness.freshFixture("maint-bucket-window"));
        oldGuardRowsAreBounded(Harness.freshFixture("maint-guards"));
        retiredGuardHistoryStillAllowsAccess(Harness.freshFixture("maint-retired"));
        liveLockoutSurvivesRetirement(Harness.freshFixture("maint-live-lockout"));
        unwritableTrailStillSweeps(Harness.freshFixture("maint-audit"));
        sweepRunsOnEveryInvocation(Harness.freshFixture("maint-cli"));

        System.exit(Harness.report("MaintenanceTest"));
    }

    private static void liveStateSurvives(Harness.Fixture fixture) throws Exception {
        Harness.section("a sweep cannot reset a denial that is currently in force");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-m");

        // Spend the source budget against mailboxes that do not exist, so nothing below can be
        // attributed to the per-account counter.
        for (int attempt = 0; attempt < Throttle.SOURCE_MAX_ATTEMPTS; attempt++) {
            Harness.check(Harness.loginFrom(fixture, "probe" + attempt + "@corp.example",
                    Harness.PW_WRONG, "one-source").status() != AuthService.Status.THROTTLED,
                "attempt " + attempt + " is served while the source budget lasts");
        }
        Harness.equal(AuthService.Status.THROTTLED,
            Harness.loginFrom(fixture, "probe-late@corp.example", Harness.PW_WRONG, "one-source").status(),
            "the spent source budget refuses the next attempt");

        // Lock the account, one distinct source per strike, so the account counter is what locks it.
        for (int strike = 0; strike < Throttle.ACCOUNT_MAX_FAILURES; strike++) {
            Harness.loginFrom(fixture, EMAIL, Harness.PW_WRONG, "strike-" + strike);
        }
        Harness.equal(AuthService.Status.THROTTLED,
            Harness.loginFrom(fixture, EMAIL, Harness.PW_ONE, "owner-m").status(),
            "the account is locked after the burst");

        int removed = new Maintenance(fixture.sessions(), fixture.throttle(), fixture.gate()).run();
        Harness.equal((long) removed, 0L,
            "nothing is eligible for deletion while the windows are still running - this sweep is a no-op");

        Harness.equal(AuthService.Status.THROTTLED,
            Harness.loginFrom(fixture, EMAIL, Harness.PW_ONE, "owner-m").status(),
            "the lockout still holds after a sweep - deleting rows is not a way out of it");
        Harness.equal(AuthService.Status.THROTTLED,
            Harness.loginFrom(fixture, "probe-more@corp.example", Harness.PW_WRONG, "one-source").status(),
            "and the spent source budget still refuses");
        Harness.check(!joined(fixture).contains("MAINTENANCE_RUN"),
            "a sweep that removed nothing is not written up as work done");

        // Only once the bucket's window has elapsed - and the refill the throttle would have applied
        // at that moment - is the row stale enough to delete.
        fixture.clock().advanceSeconds(Throttle.SOURCE_WINDOW_SECONDS + 1L);
        int swept = new Maintenance(fixture.sessions(), fixture.throttle(), fixture.gate()).run();
        Harness.atLeast((long) swept, 1L,
            "once a source window has fully elapsed its bucket is eligible, which is exactly when the"
                + " next attempt would refill it anyway");
        Harness.check(joined(fixture).contains("MAINTENANCE_RUN"), "a sweep that removed rows is recorded");
        String record = lastRecord(fixture, "MAINTENANCE_RUN");
        Harness.check(record.contains("\"sessions\"") && record.contains("\"throttle\""),
            "the record names what it removed and nothing else: " + record);
        Harness.check(!record.contains(Harness.PW_ONE) && !record.contains(EMAIL),
            "the sweep record carries counts, not a password or an address");
        fixture.close();
    }

    private static void deadSessionsAreDeleted(Harness.Fixture fixture) throws Exception {
        Harness.section("expired or revoked sessions are deleted; live ones are never touched");
        long accountId = register(fixture);
        String live = fixture.sessions().issue(accountId).token();

        int removed = new Maintenance(fixture.sessions(), fixture.throttle(), fixture.gate()).run();
        Harness.equal((long) removed, 0L, "a session inside its lifetime is never swept");
        Harness.check(fixture.sessions().resolve(live) != null, "and it still validates");

        fixture.clock().advanceSeconds(SessionStore.SESSION_LIFETIME_SECONDS);
        int expired = new Maintenance(fixture.sessions(), fixture.throttle(), fixture.gate()).run();
        Harness.atLeast((long) expired, 1L, "a session past its lifetime is deleted, not merely refused");
        Harness.equal(rows(fixture, "SELECT COUNT(*) FROM sessions"), 0L,
            "the row is gone, so the store does not accumulate dead sessions");

        // A revoked session is dead state at once, not at expiry: the sweep must reclaim it now, or
        // the table would keep rows for bearer tokens that can never be honoured.
        String kept = fixture.sessions().issue(accountId).token();
        String revoked = fixture.sessions().issue(accountId).token();
        fixture.sessions().revoke(revoked);
        Harness.equal(rows(fixture, "SELECT COUNT(*) FROM sessions"), 2L,
            "two live rows are in the table before the sweep, so the deletion below proves something");
        Harness.check(fixture.sessions().resolve(revoked) == null, "the revoked token no longer validates");
        int revokedSwept = new Maintenance(fixture.sessions(), fixture.throttle(), fixture.gate()).run();
        Harness.equal((long) revokedSwept, 1L,
            "exactly the revoked session is reclaimed immediately, not at expiry");
        Harness.equal(rows(fixture, "SELECT COUNT(*) FROM sessions"), 1L,
            "the live session's row survives - the sweep took the token that can never be honoured"
                + " again and left the one that can");
        Harness.check(fixture.sessions().resolve(kept) != null,
            "and the surviving row is the live session, not the revoked one");
        fixture.close();
    }

    private static void elapsedBucketsAreBounded(Harness.Fixture fixture) throws Exception {
        Harness.section("the bucket table stays bounded however many sources appear");
        int rounds = 6;
        int perRound = 6;
        for (int round = 0; round < rounds; round++) {
            for (int index = 0; index < perRound; index++) {
                Harness.loginFrom(fixture, "probe" + round + "-" + index + "@corp.example",
                    Harness.PW_WRONG, "src-round-" + round + "-" + index);
            }
            fixture.clock().advanceSeconds(Throttle.SOURCE_WINDOW_SECONDS);
        }
        int live = fixture.throttle().bucketRowCount();
        Harness.atLeast((long) live, (long) rounds * perRound,
            "every distinct source that appeared wrote a bucket - unbounded growth is real");
        Harness.note("the bucket table reached " + live + " rows from " + (rounds * perRound)
            + " distinct sources");

        int removed = new Maintenance(fixture.sessions(), fixture.throttle(), fixture.gate()).run();
        Harness.atLeast((long) removed, (long) rounds * perRound - perRound,
            "every bucket whose window had elapsed was deleted");
        int after = fixture.throttle().bucketRowCount();
        Harness.atMost((long) after, (long) perRound,
            "only buckets whose window still runs remain, so the table is bounded by the window"
                + " rather than by how long the program has been up");
        Harness.note("after one sweep the bucket table holds " + after + " rows instead of " + live);
        fixture.close();
    }

    /**
     * The sweep must judge each bucket by the window written in that row, which is the same column
     * the refill test reads.
     *
     * <p>Every bucket this program writes stores the same window, so today a constant and the column
     * cannot disagree - which is exactly the situation a reviewer's finding lives in: the day a
     * migration, a schema default or a hand-edited row widens a window, a sweep keyed to a constant
     * starts deleting budgets the decision still regards as live, and the sweep becomes the
     * rate-limit reset this suite exists to rule out. The row is therefore widened to a value the
     * schema's own {@code CHECK} allows but no code path produces, and the refusal it carries must
     * survive the sweep.
     */
    private static void bucketWindowComesFromTheRow(Harness.Fixture fixture) throws Exception {
        Harness.section("a sweep judges each bucket by the window stored in that row");
        String source = "wide-window-src";
        for (int attempt = 0; attempt < Throttle.SOURCE_MAX_ATTEMPTS; attempt++) {
            Harness.loginFrom(fixture, "not an identifier !!", Harness.PW_WRONG, source);
        }
        Harness.equal(AuthService.Status.THROTTLED,
            Harness.loginFrom(fixture, "not an identifier !!", Harness.PW_WRONG, source).status(),
            "the source budget is spent, so a further attempt is refused before any work at all");

        Harness.equal(1L, widenBucketWindow(fixture, Throttle.SOURCE_WINDOW_SECONDS * 12),
            "the one bucket that exists now carries a window wider than the sweep's constant, a"
                + " state the schema permits");
        // Past the constant's window, still inside the row's own: the only point at which the two
        // readings differ, which is where a sweep that used the constant would delete a budget that
        // the decision still regards as spent.
        fixture.clock().advanceSeconds(Throttle.SOURCE_WINDOW_SECONDS + 100);
        Harness.equal(0L, (long) fixture.throttle().purgeStaleState(1),
            "the sweep leaves a bucket alone while its own window runs, although the constant window"
                + " elapsed long ago");
        Harness.equal(AuthService.Status.THROTTLED,
            Harness.loginFrom(fixture, "not an identifier !!", Harness.PW_WRONG, source).status(),
            "the sweep did not hand the spent source back a fresh budget");

        fixture.clock().advanceSeconds(Throttle.SOURCE_WINDOW_SECONDS * 11 - 100);
        Harness.equal(1L, (long) fixture.throttle().purgeStaleState(1),
            "once the row's own window has elapsed the sweep does remove it, so the table is still"
                + " bounded and not merely preserved");
        Harness.equal(AuthService.Status.INVALID_CREDENTIALS,
            Harness.loginFrom(fixture, "not an identifier !!", Harness.PW_WRONG, source).status(),
            "the source can be refused for its input again, which is what proves the row was really"
                + " gone rather than kept and refilled");
        fixture.close();
    }

    /**
     * Guard rows are inserted directly rather than accumulated through failed sign-ins: the point
     * under test is the retention rule over {@code accounts}, and 20 000 Argon2 derivations would
     * say nothing the rule does not already say. A row with {@code window_start = 0} is one whose
     * failure window is long over, which is the only state it can be retired in.
     *
     * <p>The rule is exercised at a small retention window through {@code purgeStaleState}, which is
     * the method that implements it, and the shipped window is then pinned separately: proving
     * "10 000 recent accounts keep their history" by creating 10 003 accounts would cost an hour of
     * hashing to confirm a constant.
     */
    private static void oldGuardRowsAreBounded(Harness.Fixture fixture) throws Exception {
        Harness.section("per-account guard rows are kept only for the recent population");
        int keep = 5;
        Harness.atLeast((long) Maintenance.RECENT_ACCOUNTS_TO_KEEP, 1_000L,
            "the shipped retention window is generous enough that a real deployment never loses a"
                + " recent account's history");

        int accounts = keep + 3;
        for (int index = 0; index < accounts; index++) {
            insertAccount(fixture, "old" + index + "@corp.example", "old-user-" + index);
            insertGuard(fixture, index);
        }
        Harness.equal(rows(fixture, "SELECT COUNT(*) FROM accounts"), (long) accounts,
            "every account was created, so the guard rows below are not an artifact of failed sign-ups");
        Harness.equal((long) fixture.throttle().guardRowCount(), (long) accounts,
            "each account has a guard row before the sweep");

        int removed = fixture.throttle().purgeStaleState(keep);
        Harness.equal((long) removed, 3L,
            "the guard rows outside the retention window were deleted");
        Harness.equal((long) fixture.throttle().guardRowCount(), (long) keep,
            "exactly the most recent accounts keep their failure history");
        Harness.note("guard rows went from " + accounts + " to " + keep
            + " with a retention window of " + keep + "; the shipped window is "
            + Maintenance.RECENT_ACCOUNTS_TO_KEEP);

        Harness.equal(rows(fixture, "SELECT COUNT(*) FROM accounts"), (long) accounts,
            "the sweep deleted throttle state only - not one account row was touched");

        // The shipped window, through the method the program actually calls: with 5 guard rows left,
        // a retention of one would have deleted four. Zero removed proves run() passes the large
        // constant, not a small one chosen to make this test cheap.
        int withShippedWindow = new Maintenance(fixture.sessions(), fixture.throttle(), fixture.gate()).run();
        Harness.equal((long) withShippedWindow, 0L,
            "run() keeps every guard row inside the shipped retention window");
        Harness.equal((long) fixture.throttle().guardRowCount(), (long) keep,
            "and they are all still there afterwards");

        Harness.equal(oldestRetainedGuard(fixture), (long) accounts - keep + 1L,
            "the guards that survived belong to the most recently created accounts, not to an"
                + " arbitrary subset the sweep happened to reach");

        // Last, because a refused sign-in re-creates the account's guard row and would move the
        // identity check above.
        Harness.check(Harness.loginFrom(fixture, "old0@corp.example", Harness.PW_ONE, "owner-old0")
                .status() != AuthService.Status.THROTTLED,
            "a retained guard row is not a lock - the account is still served an ordinary answer");
        fixture.close();
    }

    /**
     * The same retention rule at the other end: once an account falls out of the window <em>and</em>
     * its own failure window has decayed, its history goes, and signing in afterwards must still
     * work - the deletion costs history, never access.
     *
     * <p>The decay step is not decoration. A guard whose window is still running holds a live budget,
     * so the sweep must leave it alone; only the elapsed row is retired. Both halves are asserted so
     * a mutant that drops the liveness clause is caught here as well as in
     * {@link #liveLockoutSurvivesRetirement}.
     */
    private static void retiredGuardHistoryStillAllowsAccess(Harness.Fixture fixture) throws Exception {
        Harness.section("losing guard history never costs access");
        for (int index = 0; index < 3; index++) {
            Harness.registerStatus(fixture, "old" + index + "@corp.example", "old-user-" + index,
                Harness.PW_ONE, "src-old-" + index);
            Harness.loginFrom(fixture, "old" + index + "@corp.example", Harness.PW_WRONG,
                "old-strike-" + index);
        }
        Harness.equal((long) fixture.throttle().guardRowCount(), 3L,
            "each account recorded a failed attempt");

        // Every strike just happened, so every window is live: a sweep must retire none of them,
        // even though two of the three accounts are outside the retention window.
        Harness.equal((long) fixture.throttle().purgeStaleState(1), 0L,
            "a guard whose failure window is still running is never deleted for being old");
        Harness.equal((long) fixture.throttle().guardRowCount(), 3L,
            "and all three rows are still there because each still holds a live budget");

        fixture.clock().advanceSeconds(Throttle.ACCOUNT_WINDOW_SECONDS + 1L);
        fixture.throttle().purgeStaleState(1);
        Harness.equal((long) fixture.throttle().guardRowCount(), 1L,
            "once the window has decayed, all but the newest account lost its guard row");
        Harness.check(Harness.loginFrom(fixture, "old0@corp.example", Harness.PW_ONE, "owner-old0")
                .authenticated(),
            "the oldest account still signs in - a deleted guard row cannot lock anybody out");
        Harness.equal(rows(fixture, "SELECT COUNT(*) FROM accounts"), 3L,
            "and the account itself is untouched");
        fixture.close();
    }

    /**
     * The boundary the retention rule must not cross: an account whose lockout is still in force can
     * never be reset by falling out of the recent-accounts window.
     *
     * <p>This is the case a bare "recency" rule gets wrong. The victim is created first, so a small
     * retention window places it outside the rows a sweep is allowed to keep. If deletion keyed only
     * on recency, the sweep would drop the victim's guard mid-lockout; the next sign-in would then
     * rebuild a zeroed guard and hand the account back to whoever is attacking it. So the test drives
     * the real lockout to exhaustion, pushes the account out of retention, sweeps, and requires the
     * lock to still bite - and pins <em>why</em> by reading the surviving row's {@code blocked_until}.
     */
    private static void liveLockoutSurvivesRetirement(Harness.Fixture fixture) throws Exception {
        Harness.section("a lockout in force survives the account aging out of retention");
        Harness.registerStatus(fixture, "victim@corp.example", "victim-user", Harness.PW_ONE,
            "src-victim");
        Harness.check(AuthService.Status.THROTTLED
                != Harness.loginFrom(fixture, "victim@corp.example", Harness.PW_WRONG, "vs0").status(),
            "the first strike is served normally");

        for (int strike = 1; strike < Throttle.ACCOUNT_MAX_FAILURES; strike++) {
            Harness.loginFrom(fixture, "victim@corp.example", Harness.PW_WRONG, "vs" + strike);
        }
        Harness.equal(AuthService.Status.THROTTLED,
            Harness.loginFrom(fixture, "victim@corp.example", Harness.PW_ONE, "victim-check").status(),
            "the account is locked, and the correct password is still refused");

        long victimBlockedUntil = rows(fixture,
            "SELECT blocked_until FROM auth_guard WHERE account_id ="
                + " (SELECT id FROM accounts WHERE username = 'victim-user')");
        Harness.atLeast(victimBlockedUntil, fixture.clock().instant().getEpochSecond() + 1L,
            "the lockout deadline is in the future, so the guard row holds a live denial");

        // A newer account with a failed attempt of its own, so the newest id is NOT the victim's and
        // a retention window of one makes the victim a deletion candidate. The guard row is created
        // by the failed sign-in (registration itself never writes one).
        Harness.registerStatus(fixture, "newer@corp.example", "newer-user", Harness.PW_ONE, "src-newer");
        Harness.loginFrom(fixture, "newer@corp.example", Harness.PW_WRONG, "newer-strike");
        Harness.equal((long) fixture.throttle().guardRowCount(), 2L,
            "the locked victim and the fresh account each have a guard row before the sweep");

        int removed = fixture.throttle().purgeStaleState(1);
        Harness.equal((long) removed, 0L,
            "the sweep keeps the victim's guard even though a newer account exists, because the"
                + " lockout has not expired");
        Harness.equal((long) fixture.throttle().guardRowCount(), 2L,
            "and the live guard row is still there afterwards");

        Harness.equal(AuthService.Status.THROTTLED,
            Harness.loginFrom(fixture, "victim@corp.example", Harness.PW_ONE, "victim-check-2").status(),
            "the lockout is still enforced after the sweep - falling out of retention is not a pardon");

        long stillBlockedUntil = rows(fixture,
            "SELECT blocked_until FROM auth_guard WHERE account_id ="
                + " (SELECT id FROM accounts WHERE username = 'victim-user')");
        Harness.equal(stillBlockedUntil, victimBlockedUntil,
            "the same row with the same deadline survived: it was preserved, not deleted and"
                + " silently re-created as a clean slate by the sign-in above");
        fixture.close();
    }

    private static void unwritableTrailStillSweeps(Harness.Fixture fixture) throws Exception {
        Harness.section("housekeeping failure is reported and never denies the feature");
        long accountId = register(fixture);
        fixture.sessions().issue(accountId);
        fixture.clock().advanceSeconds(SessionStore.SESSION_LIFETIME_SECONDS);

        Path trail = fixture.audit().path();
        Files.deleteIfExists(trail);
        Files.createDirectory(trail);
        int removed = new Maintenance(fixture.sessions(), fixture.throttle(), fixture.gate()).run();
        Harness.atLeast((long) removed, 1L,
            "the sweep still deleted the expired session while the trail was unwritable");
        Harness.equal(0L, rows(fixture, "SELECT COUNT(*) FROM sessions"),
            "the deletion committed - an unrecorded sweep is still a sweep");

        Files.delete(trail);
        Harness.check(Harness.login(fixture, EMAIL, Harness.PW_ONE).authenticated(),
            "and the feature itself is unaffected by a sweep that could not be recorded");

        // The audit guard must not latch either: recording works again once the trail is healthy.
        Files.deleteIfExists(fixture.audit().path());
        Files.createDirectory(trail);
        int nothingEligible = new Maintenance(fixture.sessions(), fixture.throttle(), fixture.gate()).run();
        Harness.equal(0L, (long) nothingEligible,
            "with nothing eligible the sweep returns zero even with an unwritable trail");
        Files.delete(trail);
        Harness.check(fixture.sessions().issue(accountId) != null,
            "session issuing, which does require the trail, works again once it is restored");
        fixture.close();
    }

    /**
     * The production wiring, not the component. A purge method nothing calls is the same as no purge
     * at all, so this drives {@link Main#run} and checks the sweep happened <em>before</em> the
     * command, by leaving stale state and an expired session behind for the real invocation.
     */
    private static void sweepRunsOnEveryInvocation(Harness.Fixture fixture) throws Exception {
        Path dataDir = fixture.dataDir();
        long accountId = register(fixture);
        fixture.sessions().issue(accountId);
        fixture.clock().advanceSeconds(SessionStore.SESSION_LIFETIME_SECONDS);
        Harness.equal(1L, rows(fixture, "SELECT COUNT(*) FROM sessions"),
            "the fixture leaves one expired session row behind");
        List<String> before = Files.readAllLines(dataDir.resolve("audit.log"), StandardCharsets.UTF_8);
        Harness.check(!String.join("\n", before).contains("MAINTENANCE_RUN"),
            "no sweep has been recorded yet");
        fixture.close();

        int status = Main.run(new String[] {"revoke-sessions"}, environment(dataDir),
            new ByteArrayInputStream((NAME + "\n").getBytes(StandardCharsets.UTF_8)),
            new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8),
            new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8));
        Harness.equal((long) status, (long) Main.OK, "the real command completed");

        try (java.sql.Connection check = reopen(dataDir);
            Statement read = check.createStatement();
            ResultSet found = read.executeQuery("SELECT COUNT(*) FROM sessions")) {
            found.next();
            Harness.equal(0L, found.getLong(1),
                "the expired session row was swept at start-up, before the command ran");
        }
        List<String> after = Files.readAllLines(dataDir.resolve("audit.log"), StandardCharsets.UTF_8);
        Harness.check(String.join("\n", after).contains("MAINTENANCE_RUN"),
            "the sweep the CLI ran is recorded");
        Harness.atLeast((long) after.size(), (long) before.size() + 1L,
            "the trail grew by that record");
        Harness.check(after.stream().allMatch(line -> line.startsWith("{") && line.endsWith("}")),
            "every trail line is still one JSON object");
    }

    // ------------------------------------------------------------------ helpers

    private static long register(Harness.Fixture fixture)
        throws SQLException, AuditLog.AuditException, InputPolicy.ValidationException {
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "src-reg");
        return fixture.accounts().findByEmail(EMAIL).id();
    }

    private static void insertAccount(Harness.Fixture fixture, String email, String username)
        throws SQLException {
        String sql = "INSERT INTO accounts (email, username, password_hash, kdf, kdf_memory_kib,"
            + " kdf_iterations, kdf_parallelism, created_at, password_updated_at)"
            + " VALUES (?, ?, ?, 'argon2id', ?, ?, ?, ?, ?)";
        try (PreparedStatement insert = fixture.db().connection().prepareStatement(sql)) {
            insert.setString(1, email);
            insert.setString(2, username);
            insert.setString(3, FLOOR_HASH);
            insert.setInt(4, Harness.TEST_MEMORY_KIB);
            insert.setInt(5, Harness.TEST_ITERATIONS);
            insert.setInt(6, Harness.TEST_PARALLELISM);
            insert.setLong(7, fixture.clock().instant().getEpochSecond());
            insert.setLong(8, fixture.clock().instant().getEpochSecond());
            insert.executeUpdate();
            fixture.db().connection().commit();
        } catch (SQLException rejected) {
            fixture.db().connection().rollback();
            throw rejected;
        }
    }

    private static void insertGuard(Harness.Fixture fixture, int ordinal) throws SQLException {
        String sql = "INSERT INTO auth_guard (account_id, failures, window_start, window_seconds,"
            + " max_failures, blocked_until, version) SELECT id, 0, 0, ?, ?, 0, 0 FROM accounts"
            + " WHERE username = ?";
        try (PreparedStatement insert = fixture.db().connection().prepareStatement(sql)) {
            insert.setInt(1, Throttle.ACCOUNT_WINDOW_SECONDS);
            insert.setInt(2, Throttle.ACCOUNT_MAX_FAILURES);
            insert.setString(3, "old-user-" + ordinal);
            insert.executeUpdate();
            fixture.db().connection().commit();
        } catch (SQLException rejected) {
            fixture.db().connection().rollback();
            throw rejected;
        }
    }

    /**
     * Rewrites every bucket's window and returns how many rows it changed, so the caller knows it
     * really modified the state under test rather than nothing at all.
     */
    private static long widenBucketWindow(Harness.Fixture fixture, int seconds) throws SQLException {
        String sql = "UPDATE throttle_bucket SET window_seconds = ?";
        try (PreparedStatement widen = fixture.db().connection().prepareStatement(sql)) {
            widen.setInt(1, seconds);
            long changed = widen.executeUpdate();
            fixture.db().connection().commit();
            return changed;
        } catch (SQLException rejected) {
            fixture.db().connection().rollback();
            throw rejected;
        }
    }

    private static Map<String, String> values(Path dataDir) {
        Map<String, String> values = new HashMap<>();
        values.put(Config.ENV_DATA_DIR, dataDir.toString());
        values.put(Config.ENV_DB_PASSWORD, Harness.DB_PASSWORD);
        values.put(Config.ENV_ARGON2_MEMORY, Integer.toString(Harness.TEST_MEMORY_KIB));
        values.put(Config.ENV_ARGON2_ITERATIONS, Integer.toString(Harness.TEST_ITERATIONS));
        values.put(Config.ENV_ARGON2_PARALLELISM, Integer.toString(Harness.TEST_PARALLELISM));
        return values;
    }

    private static Function<String, String> environment(Path dataDir) {
        return values(dataDir)::get;
    }

    private static java.sql.Connection reopen(Path dataDir) throws SQLException {
        java.util.Properties props = new java.util.Properties();
        props.setProperty("user", "app");
        props.setProperty("password", Harness.DB_PASSWORD);
        return java.sql.DriverManager.getConnection("jdbc:h2:file:" + dataDir.resolve("accounts")
            + ";DB_CLOSE_ON_EXIT=FALSE;AUTO_SERVER=FALSE;TRACE_LEVEL_FILE=0", props);
    }

    private static String joined(Harness.Fixture fixture) throws IOException {
        return String.join("\n", Harness.auditLines(fixture));
    }

    private static String lastRecord(Harness.Fixture fixture, String event) throws IOException {
        return Harness.auditLines(fixture).stream().filter(line -> line.contains(event))
            .reduce((first, second) -> second).orElse("");
    }

    /**
     * Smallest account id that still has a guard row. Because ids are issued in creation order, this
     * says <em>which</em> rows survived, not merely how many - a sweep that deleted the newest rows
     * and kept the oldest would satisfy a bare count.
     */
    private static long oldestRetainedGuard(Harness.Fixture fixture) throws SQLException {
        String sql = "SELECT MIN(g.account_id) FROM auth_guard g";
        try (PreparedStatement read = fixture.db().connection().prepareStatement(sql);
             ResultSet found = read.executeQuery()) {
            found.next();
            long oldest = found.getLong(1);
            fixture.db().connection().commit();
            return oldest;
        } catch (SQLException failed) {
            fixture.db().connection().rollback();
            throw failed;
        }
    }

    private static long rows(Harness.Fixture fixture, String sql) throws SQLException {
        try (PreparedStatement count = fixture.db().connection().prepareStatement(sql);
             ResultSet found = count.executeQuery()) {
            found.next();
            long rows = found.getLong(1);
            fixture.db().connection().commit();
            return rows;
        } catch (SQLException failed) {
            fixture.db().connection().rollback();
            throw failed;
        }
    }
}
