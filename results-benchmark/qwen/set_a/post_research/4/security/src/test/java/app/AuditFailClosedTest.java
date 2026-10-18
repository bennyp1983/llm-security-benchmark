package app;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.EnumSet;
import java.util.List;

/**
 * Fail-closed behaviour of the audit trail.
 *
 * <p>{@link Gate} exists so a security decision is never returned before its record was written.
 * That claim is only meaningful if the write can actually be made to fail on demand, so this suite
 * removes the attacker's options one at a time - replace the log with a directory, widen its
 * permissions, replace it with a symlink - and asserts on each that the operation is refused, that
 * <em>nothing</em> was committed, and that service resumes once the trail is healthy again. A
 * guard that latches after the first failure would be a denial-of-service bug of its own, so
 * recovery is asserted as well.
 */
public final class AuditFailClosedTest {

    private static final String EMAIL = "audit@corp.example";
    private static final String NAME = "audit-user";

    public static void main(String[] argv) throws Exception {
        registrationNeedsTheTrail(Harness.freshFixture("audit-reg"));
        loginNeedsTheTrail(Harness.freshFixture("audit-login"));
        logoutNeedsTheTrail(Harness.freshFixture("audit-logout"));
        tamperOptionsRefused(Harness.freshFixture("audit-tamper"));
        startupRefusesAWideLog(Harness.freshFixture("audit-startup"));
        budgetKeepsServiceAvailable(Harness.freshFixture("audit-budget"));
        startupRotatesAnOversizedTrail(Harness.freshFixture("audit-oversize"));

        System.exit(Harness.report("AuditFailClosedTest"));
    }

    private static void registrationNeedsTheTrail(Harness.Fixture fixture) throws Exception {
        Harness.section("a registration whose record cannot be written is rolled back");
        Harness.equal(AccountStore.RegisterStatus.CREATED,
            Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-ok"),
            "with a healthy trail, registration succeeds");
        Harness.equal(1L, accountRows(fixture), "the healthy registration committed one row");

        makeUnwritable(fixture);
        boolean threw = false;
        AccountStore.RegisterStatus status = null;
        try {
            status = Harness.registerStatus(fixture, "second@corp.example", "second-user",
                Harness.PW_TWO, "reg-bad");
        } catch (AuditLog.AuditException refused) {
            threw = true;
        }
        Harness.check(threw, "the registration threw an audit failure instead of reporting success");
        Harness.check(status != AccountStore.RegisterStatus.CREATED,
            "no CREATED outcome while the trail is unwritable (saw " + status + ")");
        Harness.equal(1L, accountRows(fixture),
            "the account row was rolled back with the record - no unaccounted-for account exists");

        restore(fixture);
        Harness.equal(AccountStore.RegisterStatus.CREATED,
            Harness.registerStatus(fixture, "third@corp.example", "third-user", Harness.PW_THREE, "reg-fixed"),
            "the guard does not latch: registration works again once the trail is writable");
        Harness.equal(2L, accountRows(fixture), "the recovered registration committed its row");
        Harness.check(String.join("\n", Harness.auditLines(fixture)).contains("REGISTRATION_ACCEPTED"),
            "the recovered registration is recorded");
        fixture.close();
    }

    private static void loginNeedsTheTrail(Harness.Fixture fixture) throws Exception {
        Harness.section("a sign-in that cannot record its success issues no session");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-l");
        Harness.check(Harness.login(fixture, EMAIL, Harness.PW_ONE).authenticated(),
            "with a healthy trail, sign-in yields a session");
        long liveBefore = sessionRows(fixture);
        Harness.atLeast(liveBefore, 1L, "the healthy sign-in committed a session row");

        makeUnwritable(fixture);
        AuthService.Result blocked = Harness.login(fixture, EMAIL, Harness.PW_ONE);
        Harness.equal(AuthService.Status.UNAVAILABLE, blocked.status(),
            "the sign-in is refused outright, not merely unrecorded");
        Harness.check(blocked.session() == null, "no session was issued");
        Harness.equal(blocked.message(), AuthService.INTERNAL_MESSAGE,
            "the client sees the generic unavailability sentence");
        Harness.equal(liveBefore, sessionRows(fixture),
            "the session insert rolled back with the record - the count did not grow");


        restore(fixture);
        AuthService.Result recovered = Harness.login(fixture, EMAIL, Harness.PW_ONE);
        Harness.check(recovered.authenticated(), "sign-in recovers once the trail is healthy");
        Harness.check(recovered.session() != null
                && fixture.sessions().resolve(recovered.session().token()) != null,
            "and the recovered session really validates");
        fixture.close();
    }

    /**
     * The sign-out path is where fail-closed matters most and where it is easiest to get wrong:
     * reporting "signed out" when the store never confirmed it leaves a captured bearer token live
     * while its owner believes it is dead. So an unwritable trail must (a) prevent the revocation
     * from committing at all, since its record is written inside the same transaction, and (b) be
     * reported as unconfirmed rather than as one of the two client-indistinguishable outcomes.
     */
    private static void logoutNeedsTheTrail(Harness.Fixture fixture) throws Exception {
        Harness.section("a sign-out whose record cannot be written revokes nothing and says so");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-lo");
        String token = Harness.login(fixture, EMAIL, Harness.PW_ONE).session().token();
        Harness.check(fixture.sessions().resolve(token) != null,
            "the session is live before the trail is tampered with");

        makeUnwritable(fixture);
        AuthService.LogoutStatus whileBroken = fixture.auth().logout(token);
        Harness.equal(AuthService.LogoutStatus.UNAVAILABLE, whileBroken,
            "an unconfirmable revocation is not reported as REVOKED or as NO_LIVE_SESSION");
        Harness.check(fixture.sessions().resolve(token) != null,
            "the revocation rolled back with its record - no state changed that nobody can account for");

        restore(fixture);
        Harness.equal(AuthService.LogoutStatus.REVOKED, fixture.auth().logout(token),
            "the guard does not latch: the same token revokes once the trail is healthy");
        Harness.check(fixture.sessions().resolve(token) == null, "and the session really is ended now");
        // Read once, now that the trail is a file again: exactly one revocation is claimed for the
        // two attempts made above, so the unconfirmable one recorded nothing.
        long claimed = Harness.auditLines(fixture).stream()
            .filter(line -> line.contains("SESSION_REVOKED")).count();
        Harness.equal(1L, claimed,
            "exactly one revocation is on record - the attempt whose record could not be written"
                + " claimed nothing, and the one that took effect is recorded");
        fixture.close();
    }

    private static void tamperOptionsRefused(Harness.Fixture fixture) throws Exception {
        Harness.section("replacing the trail cannot make events unrecorded");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-t");

        Path log = fixture.audit().path();

        // 1. widened permissions.
        Files.setPosixFilePermissions(log, EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OTHERS_READ));
        Harness.check(refusedAppend(fixture), "a trail that is not owner-only refuses to accept records");
        Files.setPosixFilePermissions(log, Harness.OWNER_ONLY);

        // 2. symlink in place of the file.
        Files.delete(log);
        Path decoy = fixture.dataDir().resolve("decoy.log");
        Files.writeString(decoy, "");
        Files.setPosixFilePermissions(decoy, Harness.OWNER_ONLY);
        Files.createSymbolicLink(log, decoy);
        Harness.check(refusedAppend(fixture),
            "a symlinked trail is refused - records cannot be redirected to another file");
        Files.delete(log);

        // 3. a plain file with the wrong mode, freshly created by someone else.
        Files.writeString(log, "pre-existing\n");
        Files.setPosixFilePermissions(log, EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_WRITE));
        Harness.check(refusedAppend(fixture), "a group-writable trail is refused");

        restore(fixture);
        Harness.check(!refusedAppend(fixture), "recording resumes after the real file is restored");
        Harness.check(fixture.audit().readAll().stream()
                .allMatch(line -> line.startsWith("{") && line.endsWith("}")),
            "every trail line is still one JSON object, including after the recovery");
        fixture.close();
    }

    private static void startupRefusesAWideLog(Harness.Fixture fixture) throws Exception {
        Harness.section("configuration also inspects the trail before anything is written");
        Path log = fixture.audit().path();
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-c");
        Harness.check(Files.exists(log), "the first recorded event created the trail file");
        Files.setPosixFilePermissions(log, EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OTHERS_READ));
        Harness.check(refusedByConfig(fixture), "a world-readable audit log stops startup");
        Files.setPosixFilePermissions(log, Harness.OWNER_ONLY);

        Path directory = fixture.dataDir().resolve("asdir.log");
        Files.createDirectory(directory);
        Files.setPosixFilePermissions(directory, Harness.OWNER_ONLY);
        Harness.check(refusedByDirectoryConfig(directory),
            "an audit log replaced by a directory stops startup rather than failing at first write");

        List<String> healthy = Harness.auditLines(fixture);
        Harness.check(!healthy.isEmpty(), "the fixture trail has content to reason about");
        fixture.close();
    }

    /**
     * The size budget is the one audit condition that must not deny. Anyone who can trigger refusals
     * can fill a trail, so a budget that refused would convert a nuisance into a permanent outage for
     * every later sign-in and registration. Retiring the oldest records is the only behaviour that
     * keeps the feature available - provided the cut is loud and a fresh record still lands.
     */
    private static void budgetKeepsServiceAvailable(Harness.Fixture fixture) throws Exception {
        Harness.section("a full audit trail retires old records instead of refusing the feature");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-b");
        Path log = fixture.audit().path();
        Harness.atLeast((long) fixture.audit().readAll().size(), 1L,
            "the trail already holds records worth retiring");

        long filledTo = fillToBudget(fixture);
        Harness.atMost(filledTo, AuditLog.MAX_BYTES,
            "an append never takes the file over its budget, however the records are sized");
        Harness.note("the audit budget is " + AuditLog.MAX_BYTES + " bytes; the trail was filled to "
            + filledTo);

        // Startup must still accept a trail that is exactly at budget - only going over is a problem.
        Harness.check(!refusedByConfig(fixture),
            "a trail sitting at its budget does not stop startup - the budget is not a denial lever");

        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream previous = System.err;
        String operatorSaw;
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            Harness.equal(AccountStore.RegisterStatus.CREATED,
                Harness.registerStatus(fixture, "after-budget@corp.example", "after-budget",
                    Harness.PW_TWO, "reg-after"),
                "a registration still succeeds once the trail is full - the control retired history"
                    + " rather than refusing the account");
            Harness.check(Harness.login(fixture, EMAIL, Harness.PW_ONE).authenticated(),
                "and a sign-in still issues a session under the same condition");
        } finally {
            System.setErr(previous);
            operatorSaw = captured.toString(StandardCharsets.UTF_8);
        }

        Harness.check(operatorSaw.contains("budget") && operatorSaw.contains("retired"),
            "the retirement is announced to the operator, not silent: <" + operatorSaw.trim() + ">");
        Harness.note(operatorSaw.trim());

        List<String> survivors = fixture.audit().readAll();
        Harness.atLeast((long) survivors.size(), 2L,
            "the fresh trail holds the records written after the retirement");
        String joined = String.join("\n", survivors);
        Harness.check(joined.contains("REGISTRATION_ACCEPTED") && joined.contains("LOGIN_SUCCESS"),
            "both post-retirement security events are present, so the audit control is still working");
        Harness.check(survivors.get(0).contains("\"" + AuditLog.Event.TRAIL_RETURED.name() + "\""),
            "the retirement itself is written INSIDE the trail, not only on the terminal: a reader of"
                + " the file alone can tell history was cut, rather than that nothing ever happened"
                + " (first line: " + survivors.get(0) + ")");
        Harness.check(survivors.get(0).contains("retired_bytes")
                && survivors.get(0).contains(Long.toString(filledTo)),
            "the marker records how much was retired, so the gap is quantified, not just flagged");
        Harness.check(survivors.stream().allMatch(line -> line.startsWith("{") && line.endsWith("}")),
            "the restarted trail is still one JSON object per line");
        Harness.check(!joined.contains(Harness.PW_ONE) && !joined.contains(Harness.PW_TWO)
                && !joined.contains(EMAIL),
            "the fresh trail carries no credential or identifier");
        Harness.atMost(Files.size(log), AuditLog.MAX_BYTES,
            "and the file is back inside its budget");
        fixture.close();
    }

    /**
     * A trail larger than the budget can only appear from outside (someone else appended to it), and
     * startup must restart it rather than keep an unbounded file that is no longer owner-inspected.
     */
    private static void startupRotatesAnOversizedTrail(Harness.Fixture fixture) throws Exception {
        Harness.section("a trail that overran its budget is restarted at startup");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-o");
        Path log = fixture.audit().path();
        byte[] bulk = new byte[(int) (AuditLog.MAX_BYTES + 1024L - Files.size(log))];
        java.util.Arrays.fill(bulk, (byte) 'x');
        Files.write(log, bulk, StandardOpenOption.APPEND);
        Harness.atLeast(Files.size(log), AuditLog.MAX_BYTES + 1L,
            "the trail now exceeds its budget, as it could only do from outside the program");

        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream previous = System.err;
        boolean accepted;
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            accepted = !refusedByConfig(fixture);
        } finally {
            System.setErr(previous);
        }
        Harness.check(accepted, "startup accepts the situation rather than refusing to run");
        Harness.check(captured.toString(StandardCharsets.UTF_8).contains("budget"),
            "and says what it did about it");
        Harness.atMost(Files.size(log), AuditLog.MAX_BYTES, "the trail is inside its budget again");
        Harness.equal("rw-------", Harness.permissionString(log),
            "the restarted trail is owner-only, not the umask default");
        Harness.check(!refusedAppend(fixture), "recording continues on the restarted trail");
        fixture.close();
    }

    /**
     * Fills the trail to one byte short of its budget, so the next record of <em>any</em> size must
     * trip the guard - leaving "about a record" of slack would depend on the next record being longer
     * than the slack, which is a fact about the formatter rather than about the budget.
     *
     * <p>The filler is not JSON. Its content is irrelevant: every filler byte is retired by the very
     * record whose arrival is under test, and the assertions afterwards are about what survived.
     */
    private static long fillToBudget(Harness.Fixture fixture) throws IOException {
        Path log = fixture.audit().path();
        long room = AuditLog.MAX_BYTES - 1L - Files.size(log);
        Harness.atLeast(room, 1L, "the fixture trail starts far below its budget");

        int chunkSize = 1 << 20;
        byte[] filler = new byte[chunkSize];
        java.util.Arrays.fill(filler, (byte) 'x');
        try (var out = Files.newOutputStream(log, StandardOpenOption.APPEND)) {
            long remaining = room;
            while (remaining >= chunkSize) {
                out.write(filler);
                remaining -= chunkSize;
            }
            out.write(filler, 0, (int) remaining);
        }
        long filled = Files.size(log);
        Harness.equal(filled, AuditLog.MAX_BYTES - 1L,
            "the trail now has exactly one byte of room left");
        return filled;
    }

    // ------------------------------------------------------------------ helpers

    private static void makeUnwritable(Harness.Fixture fixture) throws IOException {
        Path log = fixture.audit().path();
        Files.deleteIfExists(log);
        Files.createDirectory(log);
    }

    private static void restore(Harness.Fixture fixture) throws IOException {
        Path log = fixture.audit().path();
        if (Files.isDirectory(log)) {
            Files.delete(log);
        } else {
            Files.deleteIfExists(log);
        }
        // A fresh append re-creates the file itself at 0600.
    }

    private static boolean refusedAppend(Harness.Fixture fixture) {
        try {
            fixture.audit().record(AuditLog.Event.SESSION_REJECTED, "session", "probe");
            return false;
        } catch (AuditLog.AuditException refused) {
            return true;
        }
    }

    private static boolean refusedByConfig(Harness.Fixture fixture) {
        try {
            Config.ensureAuditLogWithinBudget(fixture.audit().path());
            return false;
        } catch (Config.ConfigException refused) {
            return true;
        }
    }

    private static boolean refusedByDirectoryConfig(Path directory) {
        try {
            Config.ensureAuditLogWithinBudget(directory);
            return false;
        } catch (Config.ConfigException refused) {
            return true;
        }
    }

    private static long accountRows(Harness.Fixture fixture) throws SQLException {
        return count(fixture, "SELECT COUNT(*) FROM accounts");
    }

    private static long sessionRows(Harness.Fixture fixture) throws SQLException {
        return count(fixture, "SELECT COUNT(*) FROM sessions");
    }

    /**
     * Reads a count on the connection and ends the transaction it implicitly started. Autocommit is
     * off, so leaving the read open would hold the store monitor's transaction across the next
     * assertion and make a later failure ambiguous.
     */
    private static long count(Harness.Fixture fixture, String sql) throws SQLException {
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
