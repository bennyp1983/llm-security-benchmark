package app;

import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

/**
 * Bearer-session lifecycle. The claims under test: the presented token is high-entropy and
 * generated only here; only its SHA-256 reaches the database; validation happens against
 * server-side state (never from the token's own contents); malformed tokens are refused before
 * any query; and revocation, expiry and purge all actually end access.
 */
public final class SessionStoreTest {

    private static final String EMAIL = "sessions@corp.example";
    private static final String NAME = "sessions-user";
    private static final String OTHER_EMAIL = "other-sessions@corp.example";
    private static final String OTHER_NAME = "other-user";

    public static void main(String[] argv) throws Exception {
        issueAndResolve(Harness.freshFixture("sess-issue"));
        malformedTokens(Harness.freshFixture("sess-malformed"));
        expiryAndPurge(Harness.freshFixture("sess-expiry"));
        revocation(Harness.freshFixture("sess-revoke"));
        trailHoldsNoBearerMaterial(Harness.freshFixture("sess-trail"));

        System.exit(Harness.report("SessionStoreTest"));
    }

    private static void issueAndResolve(Harness.Fixture fixture) throws Exception {
        Harness.section("a session is issued only for a real account and resolves from stored state");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-i");
        AccountStore.Account account = fixture.accounts().findByEmail(EMAIL);

        SessionStore.Session session = fixture.sessions().issue(account.id());
        Harness.equal(session.token().length(), SessionStore.TOKEN_CHARS, "the token is 64 characters");
        Harness.check(SessionStore.isWellFormedToken(session.token()),
            "the token is lower-case hex - every octet is a legal cookie-value character");
        Harness.check(session.expiresAt() - Harness.BASE_EPOCH == SessionStore.SESSION_LIFETIME_SECONDS,
            "the expiry is the fixed lifetime from issue time, with no client influence");
        Harness.equal(Long.valueOf(account.id()), fixture.sessions().resolve(session.token()),
            "the token resolves to the account id read back from the row, not from the token");

        String stored = storedTokenHash(fixture, account.id());
        Harness.equal(Digests.sha256Hex(session.token().getBytes(StandardCharsets.US_ASCII)), stored,
            "the database holds the SHA-256 of the token");
        Harness.check(!session.token().equals(stored),
            "the presented token itself is never the stored value");

        // A session must not be issuable for an account that does not exist.
        boolean refusedUnknown = false;
        try {
            fixture.sessions().issue(999_999L);
        } catch (SQLException refused) {
            refusedUnknown = true;
        }
        Harness.check(refusedUnknown, "issuing for an unknown account id is refused");
        Harness.equal(1L, countSessions(fixture), "the refused issue committed nothing");

        // An orphan session row must be rejected by the schema even through raw SQL.
        Harness.equal("fk-violation", attemptRawOrphan(fixture),
            "a raw insert of a session for a missing account is rejected by the foreign key");

        SessionStore.Session second = fixture.sessions().issue(account.id());
        Harness.check(!second.token().equals(session.token()),
            "two issues never produce the same token");
        Harness.equal(2L, (long) fixture.sessions().liveSessionCount(account.id()),
            "both sessions are live");
        fixture.close();
    }

    private static void malformedTokens(Harness.Fixture fixture) throws Exception {
        Harness.section("a malformed token is refused before the store is consulted");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-m");
        AccountStore.Account account = fixture.accounts().findByEmail(EMAIL);
        SessionStore.Session live = fixture.sessions().issue(account.id());

        List<String> malformed = List.of(
            "",
            "f".repeat(63),
            "f".repeat(65),
            "F".repeat(64),
            "g".repeat(64),
            "f".repeat(63) + " ",
            "f".repeat(63) + ";",
            "portal_session=" + "f".repeat(64),
            " " + live.token());
        Harness.requireNotEmpty(malformed, "the malformed-token capture");
        for (String candidate : malformed) {
            boolean rejected = false;
            try {
                rejected = fixture.sessions().resolve(candidate) == null;
            } catch (SQLException | AuditLog.AuditException escaped) {
                rejected = false;
            }
            Harness.check(rejected, "resolve refuses a token of the wrong shape: <"
                + describe(candidate) + '>');
            boolean revokeRefused = false;
            try {
                revokeRefused = !fixture.sessions().revoke(candidate);
            } catch (SQLException | AuditLog.AuditException escaped) {
                revokeRefused = false;
            }
            Harness.check(revokeRefused, "revoke refuses a token of the wrong shape: <"
                + describe(candidate) + '>');
        }
        Harness.equal(Long.valueOf(account.id()), fixture.sessions().resolve(live.token()),
            "the real token still resolves - the rejections above were not blanket refusals");
        fixture.close();
    }

    private static void expiryAndPurge(Harness.Fixture fixture) throws Exception {
        Harness.section("a session dies at its absolute expiry and purge removes the row");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-e");
        AccountStore.Account account = fixture.accounts().findByEmail(EMAIL);
        SessionStore.Session session = fixture.sessions().issue(account.id());

        fixture.clock().advanceSeconds(SessionStore.SESSION_LIFETIME_SECONDS - 1);
        Harness.equal(Long.valueOf(account.id()), fixture.sessions().resolve(session.token()),
            "the session is live for its whole configured lifetime");

        fixture.clock().advanceSeconds(1);
        Harness.check(fixture.sessions().resolve(session.token()) == null,
            "the second past the absolute expiry is refused - no sliding extension");
        Harness.equal(0L, (long) fixture.sessions().liveSessionCount(account.id()),
            "the expired session is not live");
        Harness.equal(1L, (long) fixture.sessions().purgeExpired(), "the purge removes the dead row");
        Harness.equal(0L, countSessions(fixture), "the row is gone from the table");

        Harness.note("session lifetime is " + SessionStore.SESSION_LIFETIME_SECONDS
            + "s (" + SessionStore.SESSION_LIFETIME_SECONDS / 3600 + "h), token entropy 256 bits");
        fixture.close();
    }

    private static void revocation(Harness.Fixture fixture) throws Exception {
        Harness.section("revocation ends access exactly for the sessions it names");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-r");
        Harness.registerStatus(fixture, OTHER_EMAIL, OTHER_NAME, Harness.PW_TWO, "reg-r2");
        AccountStore.Account first = fixture.accounts().findByEmail(EMAIL);
        AccountStore.Account second = fixture.accounts().findByEmail(OTHER_EMAIL);

        SessionStore.Session a1 = fixture.sessions().issue(first.id());
        SessionStore.Session a2 = fixture.sessions().issue(first.id());
        SessionStore.Session b1 = fixture.sessions().issue(second.id());

        Harness.check(fixture.sessions().revoke(a1.token()), "revoking a live session reports success");
        Harness.check(fixture.sessions().resolve(a1.token()) == null, "the revoked token no longer resolves");
        Harness.check(!fixture.sessions().revoke(a1.token()),
            "revoking an already-revoked session reports no change (same client answer either way)");

        Harness.equal(1, fixture.sessions().revokeAllForAccount(first.id()),
            "revoke-all ends exactly the one remaining session of that account");
        Harness.check(fixture.sessions().resolve(a2.token()) == null, "the swept token is dead");
        Harness.equal(0, fixture.sessions().revokeAllForAccount(first.id()),
            "a second sweep finds nothing to do");
        Harness.equal(Long.valueOf(second.id()), fixture.sessions().resolve(b1.token()),
            "another account's session is untouched by this account's sweep");
        fixture.close();
    }

    private static void trailHoldsNoBearerMaterial(Harness.Fixture fixture) throws Exception {
        Harness.section("the trail tags a session; it never holds the bearer token or its lookup hash");
        Harness.registerStatus(fixture, EMAIL, NAME, Harness.PW_ONE, "reg-t");
        AuthService.Result login = Harness.login(fixture, EMAIL, Harness.PW_ONE);
        Harness.check(login.authenticated(), "the fixture signs in and receives a session");
        String token = login.session().token();
        String tokenHash = Digests.sha256Hex(token.getBytes(StandardCharsets.US_ASCII));

        Harness.check(AuthService.LogoutStatus.REVOKED == fixture.auth().logout(token),
            "sign-out reports that it revoked the session");
        Harness.check(AuthService.LogoutStatus.NO_LIVE_SESSION == fixture.auth().logout(token),
            "a second sign-out on the same token reports no live session, not a revocation - the "
                + "tri-state distinguishes 'ended one' from 'there was none'");
        List<String> lines = Harness.auditLines(fixture);
        Harness.requireNotEmpty(lines, "the session audit trail");
        String trail = String.join("\n", lines);
        Harness.check(trail.contains("SESSION_ISSUED"), "issuance is recorded");
        Harness.check(trail.contains("SESSION_REVOKED"), "revocation is recorded");
        Harness.check(!trail.contains(token), "the bearer token never appears in the trail");
        Harness.check(!trail.contains(tokenHash),
            "even the SHA-256 stored in the table is absent - the trail cannot be replayed");
        Harness.check(!trail.contains(Harness.PW_ONE), "the password used to obtain the session is absent");
        Harness.check(fixture.auth().resolveSession(token) == null,
            "the logged-out token is dead, and the rejection is itself recorded");
        fixture.close();
    }

    // ------------------------------------------------------------------ helpers

    private static long countSessions(Harness.Fixture fixture) throws SQLException {
        try (PreparedStatement count = fixture.db().connection()
            .prepareStatement("SELECT COUNT(*) FROM sessions");
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

    private static String storedTokenHash(Harness.Fixture fixture, long accountId) throws SQLException {
        try (PreparedStatement read = fixture.db().connection()
            .prepareStatement("SELECT token_hash FROM sessions WHERE account_id = ?");) {
            read.setLong(1, accountId);
            try (ResultSet found = read.executeQuery()) {
                found.next();
                String hash = found.getString(1);
                fixture.db().connection().commit();
                return hash;
            }
        } catch (SQLException failed) {
            fixture.db().connection().rollback();
            throw failed;
        }
    }

    /** Runs an orphan session insert and rolls it back; the outcome is the point, not the row. */
    private static String attemptRawOrphan(Harness.Fixture fixture) {
        String sql = "INSERT INTO sessions (token_hash, account_id, issued_at, expires_at, revoked_at)"
            + " VALUES (?, ?, ?, ?, NULL)";
        try (PreparedStatement insert = fixture.db().connection().prepareStatement(sql)) {
            insert.setString(1, "a".repeat(64));
            insert.setLong(2, 999_999L);
            insert.setLong(3, Harness.BASE_EPOCH);
            insert.setLong(4, Harness.BASE_EPOCH + 60);
            insert.executeUpdate();
            fixture.db().connection().rollback();
            return "accepted";
        } catch (SQLException rejected) {
            try {
                fixture.db().connection().rollback();
            } catch (SQLException ignore) {
                // Nothing to undo; the constraint already ended the statement.
            }
            String state = rejected.getSQLState();
            return state != null && state.startsWith("23") ? "fk-violation" : "other:" + state;
        }
    }

    private static String describe(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.length() > 72 ? out.substring(0, 32) + "..." + out.substring(out.length() - 32)
            : out.toString();
    }
}
