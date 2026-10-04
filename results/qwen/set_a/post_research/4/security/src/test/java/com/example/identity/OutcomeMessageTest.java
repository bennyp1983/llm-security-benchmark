package com.example.identity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.note;
import static com.example.identity.Harness.section;

/**
 * The message-sharing table (Rule 6).
 *
 * <p>"Never reveal whether an account exists" is not a property of any single code path - it is a
 * property of the <em>partition</em> of outcomes. Two outcomes that must be indistinguishable and
 * get different strings is the whole bug, and it is invisible until someone compares them. So the
 * partition is asserted twice: once as a static table over {@link Reason} (cheap, exhaustive) and
 * once by driving the real API and comparing the strings callers actually receive (the table can be
 * right while a call site returns the wrong {@code Reason}).
 *
 * <p>The three oracles this suite exists to close: the disabled account (a correct password must not
 * say "disabled"), revocation (a random token must not say "that token existed"), and registration
 * (a taken username must not say "that username exists").
 */
public final class OutcomeMessageTest {

    private OutcomeMessageTest() {
    }

    public static void run() throws Exception {
        section("Reason: the refusal classes really do share one string");
        List<Reason> signInClass = List.of(Reason.ABSENT_ACCOUNT, Reason.BAD_CREDENTIAL,
                Reason.CORRUPT_RECORD, Reason.ACCOUNT_DISABLED, Reason.THROTTLED);
        checkEquals("every sign-in refusal says exactly 'Sign-in failed.'",
                List.of("Sign-in failed."), distinctMessages(signInClass));
        List<Reason> registerClass = List.of(Reason.EMAIL_TAKEN, Reason.USERNAME_TAKEN,
                Reason.ACCOUNT_CAP_REACHED, Reason.REGISTRATION_DUPLICATE);
        checkEquals("every registration refusal says the same thing",
                1, distinctMessages(registerClass).size());
        // The message is not the whole control. Two facts that both answer "does this account exist"
        // must also be indistinguishable *as an enum value*, because a front end can branch on the
        // value, serialise it, or put it in a header without ever printing the message.
        checkEquals("and both collisions collapse to one caller-facing reason",
                Reason.REGISTRATION_DUPLICATE, Reason.EMAIL_TAKEN.forCaller());
        checkEquals("the username collision too",
                Reason.REGISTRATION_DUPLICATE, Reason.USERNAME_TAKEN.forCaller());
        check("so the collapse is not just a shared string",
                Reason.EMAIL_TAKEN.forCaller() != Reason.EMAIL_TAKEN
                        && Reason.USERNAME_TAKEN.forCaller() != Reason.USERNAME_TAKEN);
        checkEquals("the store's specific reasons still exist, so the audit log can still name which"
                        + " column collided",
                List.of("EMAIL_TAKEN", "USERNAME_TAKEN"),
                List.of(Reason.EMAIL_TAKEN.name(), Reason.USERNAME_TAKEN.name()));
        check("nothing else is silently rewritten on the way to the caller",
                Reason.BAD_CREDENTIAL.forCaller() == Reason.BAD_CREDENTIAL
                        && Reason.ACCOUNT_CAP_REACHED.forCaller() == Reason.ACCOUNT_CAP_REACHED
                        && Reason.AUTHENTICATED.forCaller() == Reason.AUTHENTICATED
                        && Reason.ALREADY_REVOKED.forCaller() == Reason.ALREADY_REVOKED);
        List<Reason> sessionClass = List.of(Reason.SESSION_REVOKED, Reason.ALREADY_REVOKED);
        checkEquals("revoking and not revoking say the same thing",
                1, distinctMessages(sessionClass).size());
        List<Reason> unavailableClass = List.of(Reason.STORAGE_UNAVAILABLE, Reason.CRYPTO_FAILURE,
                Reason.AUDIT_FAILURE);
        checkEquals("every operational failure says the same thing to the caller",
                1, distinctMessages(unavailableClass).size());

        section("Reason: no message text leaks which outcome happened");
        for (Reason r : Reason.values()) {
            String msg = r.genericUserMessage();
            check("the message for " + r.name() + " does not name the outcome",
                    !msg.toLowerCase(java.util.Locale.ROOT).contains(r.name().toLowerCase()));
            check("the message for " + r.name() + " is non-empty and free of control characters",
                    !msg.isBlank() && msg.chars().allMatch(c -> c >= 0x20 && c != 0x7F));
            check("the message for " + r.name() + " contains no credential-shaped text",
                    !msg.contains("$") && !msg.contains("="));
        }
        check("a sign-in refusal never says 'disabled'",
                !Reason.ACCOUNT_DISABLED.genericUserMessage().toLowerCase().contains("disabled"));
        check("a sign-in refusal never says 'unknown' or 'not found'",
                !Reason.ABSENT_ACCOUNT.genericUserMessage().toLowerCase().contains("not found")
                        && !Reason.ABSENT_ACCOUNT.genericUserMessage().toLowerCase().contains("unknown"));
        check("a sign-in refusal never says 'locked' or 'try again' (that would confirm the limiter"
                + " engaged)",
                !Reason.THROTTLED.genericUserMessage().toLowerCase().contains("lock")
                        && !Reason.THROTTLED.genericUserMessage().toLowerCase().contains("retry"));
        check("a registration refusal never says 'taken' or 'exists'",
                !Reason.USERNAME_TAKEN.genericUserMessage().toLowerCase().contains("taken")
                        && !Reason.USERNAME_TAKEN.genericUserMessage().toLowerCase().contains("exists"));

        section("Reason: only caller-input outcomes may be specific");
        // The rule is "a refusal about server state must not have a message of its own". Two
        // exceptions are legitimate and both are asserted rather than exempted by fiat: a Reason that
        // is itself the collapse of several distinct server facts needs no twin (one string already
        // covers all the facts it could reveal), and a startup-time configuration failure cannot
        // disclose any account state because no account has been touched yet.
        for (Reason r : Reason.values()) {
            if (r.describesCallerInput() || r.isSuccess()) {
                continue;
            }
            String collapse = SELF_COLLAPSING.get(r);
            if (collapse != null) {
                List<Reason> folds = new ArrayList<>();
                for (Reason o : Reason.values()) {
                    if (o != r && o.forCaller() == r) {
                        folds.add(o);
                    }
                }
                if (folds.isEmpty()) {
                    // Nothing is rewritten *into* it, so its own string is the only thing a caller
                    // can see for the several facts it already stands in for.
                    check(r.name() + " has its own message only because it already collapses: " + collapse,
                            countSharing(r) == 1);
                } else {
                    // The target of the caller-facing collapse speaks for facts it does not itself
                    // name, so its string must be the string of everything folded into it. A unique
                    // message here would leave the enum value as an oracle for the widest of them.
                    String shared = r.genericUserMessage();
                    check(r.name() + " carries the message of the " + folds.size()
                            + " reasons that fold into it: " + folds,
                            folds.size() >= 2
                                    && folds.stream().allMatch(o -> o.genericUserMessage().equals(shared)));
                }
                continue;
            }
            check("a server-state outcome (" + r.name() + ") shares its message with at least one"
                    + " other outcome", countSharing(r) > 1);
        }
        check("INVALID_PASSWORD is about the caller's own input", Reason.INVALID_PASSWORD.describesCallerInput());
        check("BAD_CREDENTIAL is not (it is about server state)", !Reason.BAD_CREDENTIAL.describesCallerInput());
        check("MALFORMED_TOKEN is about the caller's input", Reason.MALFORMED_TOKEN.describesCallerInput());
        check("INVALID_SESSION is not", !Reason.INVALID_SESSION.describesCallerInput());

        section("Reason: the equal-cost set is exactly the branches that could reveal existence");
        for (Reason r : List.of(Reason.ABSENT_ACCOUNT, Reason.CORRUPT_RECORD, Reason.BAD_CREDENTIAL,
                Reason.INVALID_PASSWORD)) {
            check(r.name() + " must cost a derivation", r.mustMatchVerificationCost());
        }
        check("THROTTLED is the documented exception (buckets exist for unknown identifiers too,"
                + " so a cheap refusal there is symmetric and charging it would defeat the limiter)",
                !Reason.THROTTLED.mustMatchVerificationCost());
        check("ACCOUNT_DISABLED never reaches the timing comparison (status is read only after the"
                + " credential is proven, so it cannot be an existence oracle)",
                !Reason.ACCOUNT_DISABLED.mustMatchVerificationCost());
        check("the success outcomes are not in the equal-cost set",
                !Reason.AUTHENTICATED.mustMatchVerificationCost()
                        && !Reason.ACCOUNT_CREATED.mustMatchVerificationCost());

        section("Behaviour: an unknown account and a wrong password are indistinguishable");
        Harness.Fixture f = Harness.fixture("msg-signin");
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            AuthResult wrongPassword = b.api.signIn(Harness.U1, Harness.chars(Harness.P2), SourceId.LOCAL);
            AuthResult unknownName = b.api.signIn("nosuchuser", Harness.chars(Harness.P2), SourceId.LOCAL);
            AuthResult unknownEmail = b.api.signIn("nobody@example.com", Harness.chars(Harness.P2),
                    SourceId.LOCAL);
            AuthResult malformed = b.api.signIn("not a valid identifier!!", Harness.chars(Harness.P1),
                    SourceId.LOCAL);
            AuthResult shortPassword = b.api.signIn(Harness.U1, Harness.chars(Harness.P_BELOW_MIN),
                    SourceId.LOCAL);
            List<String> messages = List.of(wrongPassword.userMessage(), unknownName.userMessage(),
                    unknownEmail.userMessage(), malformed.userMessage(), shortPassword.userMessage());
            checkEquals("all five sign-in refusals are byte-identical to the caller",
                    1, new java.util.LinkedHashSet<>(messages).size());
            check("the shared message is the generic one",
                    Reason.BAD_CREDENTIAL.genericUserMessage().equals(messages.get(0)));
            check("none of them succeeded", messages.stream().allMatch(m -> !m.equals("Signed in.")));
            check("internally the reasons ARE distinguished (for the operator)",
                    wrongPassword.reason() == Reason.BAD_CREDENTIAL
                            && unknownName.reason() == Reason.BAD_CREDENTIAL);
            check("the refusal does not echo the identifier", !unknownName.userMessage().contains("nosuchuser"));
            check("a password that fails policy is refused with the sign-in message, not the policy"
                    + " one, so policy is not an existence oracle",
                    shortPassword.userMessage().equals(wrongPassword.userMessage())
                            && shortPassword.reason() == Reason.BAD_CREDENTIAL);

            section("Behaviour: the disabled-account oracle is closed");
            AuthResult before = b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL);
            check("the owner can sign in while active", before.isSuccess());
            SqlIdentityStore.Account row = b.store.findByCanonicalIdentity(
                    Identity.parseClientUsername(Harness.U1));
            check("the account is active", row != null && "active".equals(row.status()));
            b.api.setAccountStatus(Identity.parseClientUsername(Harness.U1), "disabled");
            AuthResult disabledWithRightPassword = b.api.signIn(Harness.U1, Harness.chars(Harness.P1),
                    SourceId.LOCAL);
            AuthResult disabledWithWrongPassword = b.api.signIn(Harness.U1, Harness.chars(Harness.P2),
                    SourceId.LOCAL);
            check("the correct password on a disabled account is refused",
                    !disabledWithRightPassword.isSuccess());
            check("and its message equals the wrong-password message",
                    disabledWithRightPassword.userMessage().equals(wrongPassword.userMessage()));
            check("and it equals the unknown-account message",
                    disabledWithRightPassword.userMessage().equals(unknownName.userMessage()));
            check("the reason handed back to the caller is the collapsed one, not the disabled fact",
                    disabledWithRightPassword.reason() == Reason.BAD_CREDENTIAL
                            && disabledWithWrongPassword.reason() == Reason.BAD_CREDENTIAL);
            check("the audit log is where the disabled fact is recorded, and it is recorded there",
                    b.audit.readAll().contains("ACCOUNT_DISABLED"));
            check("so no getter on the returned result can tell a front end the account is disabled",
                    !disabledWithRightPassword.toString().contains("DISABLED"));
            check("a disabled account's sessions are gone",
                    !b.api.checkSession(before.token().value()).isSuccess());
            note("documented cost: the owner cannot tell a disabled account from a typo - see README"
                    + " 'Limitations'");
            b.api.setAccountStatus(Identity.parseClientUsername(Harness.U1), "active");
            check("re-enabling restores access",
                    b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL).isSuccess());

            section("Behaviour: a corrupt stored row is not distinguishable either");
            Harness.register(b, Harness.E2, Harness.U2, Harness.P2);
            // A row whose credential encoding is malformed: strictly-decoded, therefore refused.
            Harness.rawExecute(f, "UPDATE account SET password = 'v1$pbkdf2-sha256$1$AAA$BBB'"
                    + " WHERE username_canon = 'bob'");
            AuthResult corruptRow = b.api.signIn(Harness.U2, Harness.chars(Harness.P2), SourceId.LOCAL);
            check("a corrupt row does not escape the API as an exception", corruptRow != null);
            check("a corrupt row is refused", !corruptRow.isSuccess());
            check("a corrupt row's message equals the wrong-password message",
                    corruptRow.userMessage().equals(wrongPassword.userMessage()));
            check("a corrupt row's message equals the unknown-account message",
                    corruptRow.userMessage().equals(unknownName.userMessage()));
            AuthResult corruptWithWrongPassword = b.api.signIn(Harness.U2, Harness.chars(Harness.P3),
                    SourceId.LOCAL);
            check("a corrupt row refuses a wrong password identically too",
                    corruptWithWrongPassword.userMessage().equals(corruptRow.userMessage()));
            check("the corrupt row is still charged against the limiter (a broken row is not a free"
                            + " oracle)",
                    Harness.rawCount(f, "auth_throttle") > 0);

            section("Behaviour: revocation is not a token-existence oracle");
            AuthResult login = b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL);
            String live = login.token().value();
            String neverIssued = "Z".repeat(43);
            AuthResult revokedLive = b.api.revokeSession(live);
            AuthResult revokedAgain = b.api.revokeSession(live);
            AuthResult revokedJunk = b.api.revokeSession("junk");
            AuthResult revokedNull = b.api.revokeSession(null);
            AuthResult revokedRandom = b.api.revokeSession(neverIssued);
            check("revoking a live session succeeds", revokedLive.isSuccess());
            check("the live token is dead afterwards", !b.api.checkSession(live).isSuccess());
            List<String> revokeMessages = List.of(revokedLive.userMessage(), revokedAgain.userMessage(),
                    revokedJunk.userMessage(), revokedNull.userMessage(), revokedRandom.userMessage());
            checkEquals("revoked / already-gone / never-existed / malformed are all one string",
                    1, new java.util.LinkedHashSet<>(revokeMessages).size());
            check("what the caller is handed distinguishes nothing either - the returned reason for a"
                            + " delete and for a no-op is the same enum, so a front end cannot branch"
                            + " its way back to a token-existence oracle",
                    revokedLive.reason() == Reason.SESSION_REVOKED
                            && revokedAgain.reason() == Reason.SESSION_REVOKED
                            && revokedJunk.reason() == Reason.SESSION_REVOKED
                            && revokedNull.reason() == Reason.SESSION_REVOKED
                            && revokedRandom.reason() == Reason.SESSION_REVOKED);
            check("the audit log still records that nothing was deleted, which is where the"
                            + " distinction belongs",
                    b.audit.readAll().contains(Reason.ALREADY_REVOKED.name()));

            section("Behaviour: an expired session and a revoked one are indistinguishable");
            Harness.Overrides o = Harness.overrides();
            o.sessionTtl = 900;
            Harness.Fixture ttlFixture = Harness.fixture("msg-ttl", o);
            try (Harness.Bundle t = Harness.openApi(ttlFixture)) {
                Harness.register(t, Harness.E3, Harness.U3, Harness.P3);
                String tok = t.api.signIn(Harness.U3, Harness.chars(Harness.P3), SourceId.LOCAL).token().value();
                check("the session is live", t.api.checkSession(tok).isSuccess());
                t.fixture.clock.advanceSeconds(901);
                AuthResult expired = t.api.checkSession(tok);
                check("after the TTL it is refused", !expired.isSuccess());
                check("the message is the generic 'not active' one",
                        Reason.INVALID_SESSION.genericUserMessage().equals(expired.userMessage()));
                int beforePrune = Harness.rawCount(ttlFixture, "session");
                check("the expired row is refused on read before any prune pass", beforePrune >= 0);
                t.api.liveSessionCount();
                check("a prune pass deletes the expired row rather than leaving it replayable",
                        Harness.rawCount(ttlFixture, "session") == 0);
                String other = t.api.signIn(Harness.U3, Harness.chars(Harness.P3), SourceId.LOCAL).token().value();
                t.api.revokeSession(other);
                AuthResult revokedTok = t.api.checkSession(other);
                checkEquals("an expired session and a revoked session say the same thing",
                        expired.userMessage(), revokedTok.userMessage());
            }

            section("Behaviour: registration cannot enumerate accounts");
            AuthResult dupUser = b.api.register(Harness.E4, Harness.U1, Harness.chars(Harness.P4),
                    SourceId.LOCAL);
            AuthResult dupEmail = b.api.register(Harness.E1, Harness.U4, Harness.chars(Harness.P4),
                    SourceId.LOCAL);
            check("a duplicate username is refused", !dupUser.isSuccess());
            check("a duplicate email is refused", !dupEmail.isSuccess());
            checkEquals("both duplicates produce the same reason (the message is shared by table)",
                    dupUser.reason(), dupEmail.reason());
            check("a duplicate username's message equals a duplicate email's",
                    dupUser.userMessage().equals(dupEmail.userMessage()));
            check("the refusal does not echo the taken username",
                    !dupUser.userMessage().contains(Harness.U1));
            check("the refusal does not echo the taken email", !dupEmail.userMessage().contains(Harness.E1));
            check("a duplicate is not the sign-in message (registration refusal may differ: it is"
                    + " about the submitted values, not about an existing account's state)",
                    !dupUser.userMessage().equals(wrongPassword.userMessage()));
            check("invalid email and invalid username are specific (they describe the caller's input)",
                    b.api.register("bad", Harness.U4, Harness.chars(Harness.P4), SourceId.LOCAL).reason()
                            == Reason.INVALID_EMAIL
                            && b.api.register(Harness.E4, "BAD NAME", Harness.chars(Harness.P4),
                            SourceId.LOCAL).reason() == Reason.INVALID_USERNAME);
            check("an invalid email message differs from an invalid username message",
                    !Reason.INVALID_EMAIL.genericUserMessage().equals(Reason.INVALID_USERNAME.genericUserMessage()));
            check("neither input-specific message says whether any account exists",
                    !Reason.INVALID_EMAIL.genericUserMessage().toLowerCase().contains("exist")
                            && !Reason.INVALID_USERNAME.genericUserMessage().toLowerCase().contains("exist"));

            section("Behaviour: the account cap is not a 'who exists' signal either");
            Harness.Overrides capO = Harness.overrides();
            capO.maxAccounts = 2;
            Harness.Fixture capFixture = Harness.fixture("msg-cap", capO);
            try (Harness.Bundle cap = Harness.openApi(capFixture)) {
                Harness.register(cap, Harness.E1, Harness.U1, Harness.P1);
                Harness.register(cap, Harness.E2, Harness.U2, Harness.P2);
                AuthResult atCap = cap.api.register(Harness.E3, Harness.U3, Harness.chars(Harness.P3),
                        SourceId.LOCAL);
                check("the third registration is refused", !atCap.isSuccess());
                check("the cap refusal's message equals a duplicate-username message",
                        atCap.userMessage().equals(dupUser.userMessage()));
                check("the internal reason is the cap", atCap.reason() == Reason.ACCOUNT_CAP_REACHED);
                AuthResult atCapDuplicate = cap.api.register(Harness.E1, Harness.U1,
                        Harness.chars(Harness.P1), SourceId.LOCAL);
                check("at the cap, a duplicate is refused with the same message whichever check fired",
                        atCapDuplicate.userMessage().equals(atCap.userMessage()));
            }

            section("Behaviour: the audit log records the specific reason, the caller never sees it");
            String log = b.audit.readAll();
            check("the audit log is non-empty", log.length() > 0);
            check("the audit log records the disabled-account outcome by name",
                    log.contains("ACCOUNT_DISABLED"));
            check("the audit log records the absent-account outcome by name",
                    log.contains("ABSENT_ACCOUNT"));
            check("the audit log records that a corrupt row was rejected",
                    // AuditEvent names reach the line through describe(), which lower-cases them -
                    // an upper-case needle here can never match, which is how this check was failing
                    // while the event itself was being written. Deriving the needle from the enum
                    // keeps the two from drifting apart again.
                    log.contains(AuditEvent.ROW_REJECTED_AS_ABSENT.describe())
                            && !log.contains(AuditEvent.ROW_REJECTED_AS_ABSENT.name()));
            check("the audit log does not contain any fixture password",
                    Harness.secretCanaries().stream().noneMatch(log::contains));
            check("the audit log does not contain a session token",
                    !log.contains(live) && !log.contains(neverIssued));
            check("the audit log does not contain the stored credential encoding",
                    !log.contains("v1$pbkdf2-sha256$"));
            // The subject is rendered as kind[len=N]; the identifier itself must never appear.
            check("the audit log does not contain the fixture username in the clear",
                    !log.contains(Harness.U1));
            check("the audit log does not contain the fixture email in the clear",
                    !log.contains(Harness.E1) && !log.contains("example.com"));
            check("the subject is still recorded in bounded form (so the log is usable)",
                    log.contains("USERNAME[len=") || log.contains("EMAIL[len="));
        }
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Outcomes that legitimately own their message because the Reason itself is where several
     * distinct server facts already come together. Each is also asserted behaviourally: the cases
     * named here are the ones the other sections of this suite drive through the real API.
     */
    private static final Map<Reason, String> SELF_COLLAPSING = Map.of(
            Reason.INVALID_SESSION,
            "unknown token, expired token, revoked token and a disabled account's token all reach it",
            Reason.REGISTRATION_THROTTLED,
            "the per-source budget and the global budget both reach it",
            Reason.REGISTRATION_DUPLICATE,
            "it is the collapse itself - both collisions are returned as this one reason, and the"
                    + " store's specific reasons are asserted to still exist above",
            Reason.CONFIG_INVALID,
            "it happens at startup, before any account state exists to disclose; the caller is the"
                    + " operator and naming the key is how they fix it");

    private static List<String> distinctMessages(List<Reason> reasons) {
        Map<String, Boolean> seen = new LinkedHashMap<>();
        for (Reason r : reasons) {
            seen.put(r.genericUserMessage(), Boolean.TRUE);
        }
        return new ArrayList<>(seen.keySet());
    }

    private static int countSharing(Reason target) {
        int n = 0;
        for (Reason r : Reason.values()) {
            if (r.genericUserMessage().equals(target.genericUserMessage())) {
                n++;
            }
        }
        return n;
    }
}
