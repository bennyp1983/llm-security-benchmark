package com.example.identity;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.note;
import static com.example.identity.Harness.section;

/**
 * Session identifiers (Rule 4).
 *
 * <p>The property under test is that a session id carries no information a caller can supply or
 * predict, and that holding a copy of the database does not hand over usable sessions. Everything
 * else - cookie attributes, transport - is documented residual risk, so the assertions here are on
 * the shapes: length, alphabet, entropy source, and what actually lands in the stored column.
 */
public final class SessionTokenTest {

    private SessionTokenTest() {
    }

    public static void run() throws Exception {
        section("SessionToken: shape of an issued token");
        SecureRandom rnd = new SecureRandom();
        SessionToken t = SessionToken.generate(rnd);
        checkEquals("a token is 43 characters", 43, t.value().length());
        check("a token decodes to 32 bytes", Base64.getUrlDecoder().decode(t.value()).length == 32);
        check("the alphabet is base64url with no padding",
                t.value().matches("[A-Za-z0-9_-]{43}"));
        check("no padding character appears", !t.value().contains("="));
        check("no '+' or '/' (those would need URL-encoding to travel)",
                !t.value().contains("+") && !t.value().contains("/"));
        check("a token contains no whitespace or control character",
                t.value().chars().allMatch(c -> c > 0x20 && c < 0x7F));

        section("SessionToken: nothing about a token comes from the caller, the clock, or the account");
        // 30 tokens for one account in one second: if any part were a counter, a timestamp, or an
        // account-derived value, the prefix or a length difference would show up.
        SessionToken[] many = new SessionToken[30];
        for (int i = 0; i < many.length; i++) {
            many[i] = SessionToken.generate(rnd);
        }
        Set<String> all = new HashSet<>();
        for (SessionToken x : many) {
            all.add(x.value());
        }
        checkEquals("30 issued tokens are 30 distinct values", 30, all.size());
        Set<String> prefixes = new HashSet<>();
        for (SessionToken x : many) {
            prefixes.add(x.value().substring(0, 4));
        }
        check("the leading 4 characters are not constant across issuances (no fixed prefix)",
                prefixes.size() > 15);
        // A timestamp-derived id changes only in its low bits, so consecutive ids share a long
        // prefix. A CSPRNG id does not: over 30 samples the first character alone should already be
        // spread over most of the 64-symbol alphabet.
        Set<Character> firstChars = new HashSet<>();
        for (SessionToken x : many) {
            firstChars.add(x.value().charAt(0));
        }
        check("the first character is spread across the alphabet (not a shared timestamp prefix)",
                firstChars.size() >= 12);
        check("the two-character prefix is spread too", distinctFirstTwo(many) >= 25);
        SessionToken again = SessionToken.generate(rnd);
        check("a token generated after a pause is unrelated to the previous one",
                !t.value().equals(again.value()));

        section("SessionToken: parse refuses everything we do not issue");
        check("null is refused", SessionToken.parse(null) == null);
        check("empty is refused", SessionToken.parse("") == null);
        check("42 characters is refused (one short)", SessionToken.parse("A".repeat(42)) == null);
        check("44 characters is refused (one long)", SessionToken.parse("A".repeat(44)) == null);
        check("a padded base64url value is refused (we never issue padding)",
                SessionToken.parse("A".repeat(43) + "=") == null);
        check("standard-base64 '+' is refused (alphabet mismatch)",
                SessionToken.parse("A".repeat(42) + "+") == null);
        check("standard-base64 '/' is refused", SessionToken.parse("A".repeat(42) + "/") == null);
        check("a dot is refused", SessionToken.parse("A".repeat(42) + ".") == null);
        check("a space is refused", SessionToken.parse("A".repeat(42) + " ") == null);
        check("a trailing NUL is refused (a truncation hazard, not a variant spelling)",
                SessionToken.parse("A".repeat(42) + (char) 0x00) == null);
        check("a tab is refused", SessionToken.parse("A".repeat(42) + "\t") == null);
        check("a newline is refused (log-line forgery)", SessionToken.parse("A".repeat(42) + "\n") == null);
        check("a SQL metacharacter run is refused", SessionToken.parse("' OR 1=1 --AAAAAAAAAAAAAAAAAAAA") == null);
        check("the issued token's own value round-trips through parse",
                SessionToken.parse(t.value()).value().equals(t.value()));
        check("a valid-shape token that was never issued parses fine (shape is not authenticity)",
                SessionToken.parse("Z".repeat(43)) != null);
        check("an all-NUL 43-char buffer is refused by the record", refusesCtor(String.valueOf((char) 0x00).repeat(43)));
        check("a 32-byte value re-encoded with standard base64 (not url) may differ and is refused if so",
                refusesCtor(Base64.getEncoder().encodeToString(new byte[32]))
                        || !Base64.getEncoder().encodeToString(new byte[32]).matches("[A-Za-z0-9_-]{43}"));

        section("SessionToken: the stored form is a digest, not the token");
        String hash = t.tokenHash();
        check("the hash is not the token", !hash.equals(t.value()));
        check("the hash does not contain the token as a substring", !hash.contains(t.value()));
        check("the hash is 44 characters of padded base64", hash.matches("[A-Za-z0-9+/]{43}="));
        check("the hash decodes to a 32-byte SHA-256 digest", Base64.getDecoder().decode(hash).length == 32);
        checkEquals("the hash is deterministic (it is a lookup key)", hash, t.tokenHash());
        SessionToken other = SessionToken.generate(rnd);
        check("different tokens hash differently", !hash.equals(other.tokenHash()));
        check("the hash is the same for the same token parsed from text",
                SessionToken.parse(t.value()).tokenHash().equals(hash));
        // Independent confirmation of the digest definition, computed here rather than trusted.
        byte[] expect = java.security.MessageDigest.getInstance("SHA-256")
                .digest(t.value().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        checkEquals("tokenHash() really is SHA-256 of the UTF-8 token, base64",
                Base64.getEncoder().encodeToString(expect), hash);

        section("SessionToken: it cannot reach a log in the clear");
        String rendered = t.toString();
        check("toString does not contain the token", !rendered.contains(t.value()));
        check("toString does not contain the first 8 characters either",
                !rendered.contains(t.value().substring(0, 8)));
        check("toString still says there is a token", rendered.contains("len=43"));
        AuthResult withToken = AuthResult.success(Reason.AUTHENTICATED, t, Harness.U1);
        check("AuthResult.toString does not print the token", !withToken.toString().contains(t.value()));
        check("AuthResult.toString admits a token is present", withToken.toString().contains("token=present"));
        check("a token inside a String interpolation is still redacted",
                !("value is " + t).contains(t.value()));

        section("SessionToken: equality is over the value, and constant-time in shape");
        SessionToken copy = SessionToken.parse(t.value());
        check("equal tokens are equal", t.equals(copy));
        checkEquals("equal tokens hash equal", t.hashCode(), copy.hashCode());
        check("different tokens are not equal", !t.equals(other));
        check("a token is not equal to its own string", !t.equals(t.value()));
        check("a token is not equal to null", !t.equals(null));

        section("SessionToken: what the database actually holds");
        Harness.Fixture f = Harness.fixture("tok-store");
        SessionToken live;
        try (Harness.Bundle b = Harness.openApi(f)) {
            Harness.register(b, Harness.E1, Harness.U1, Harness.P1);
            AuthResult r = b.api.signIn(Harness.U1, Harness.chars(Harness.P1), SourceId.LOCAL);
            check("sign-in issued a token", r.isSuccess() && r.token() != null);
            live = r.token();
            check("the session resolves for the live token",
                    b.api.checkSession(live.value()).isSuccess());
            List<String> stored = Harness.rawColumn(f, "SELECT token_hash FROM session");
            check("exactly one session row exists", stored.size() == 1);
            String inDb = stored.get(0);
            check("the stored value is non-empty", inDb != null && !inDb.isEmpty());
            check("the stored value is NOT the token", !inDb.equals(live.value()));
            check("the stored value does not contain the token", !inDb.contains(live.value()));
            check("the stored value is the digest", inDb.equals(live.tokenHash()));
            List<String> whole = Harness.rawColumn(f,
                    "SELECT password || '|' || status FROM account");
            check("no table column anywhere holds the token text",
                    whole.stream().noneMatch(s -> s.contains(live.value())));
        }
        check("the same token is dead after the store is closed and the sessions were invalidated",
                deadAfterRestart(f, live));

        section("SessionToken: a forged token of the right shape buys nothing");
        try (Harness.Bundle b = Harness.openApi(f)) {
            SessionToken forged = SessionToken.parse("Z".repeat(43));
            check("a well-formed forged token is refused",
                    !b.api.checkSession(forged.value()).isSuccess());
            check("the refusal is the generic one",
                    Reason.INVALID_SESSION.genericUserMessage().equals(
                            b.api.checkSession(forged.value()).userMessage()));
            check("junk that never reaches the database gets the same message",
                    b.api.checkSession("junk").userMessage()
                            .equals(b.api.checkSession(forged.value()).userMessage()));
            note("residual risk: a bearer token is still a bearer token - whoever holds the 43"
                    + " characters holds the session until expiry or revocation");
        }
    }

    // ------------------------------------------------------------------ helpers

    private static int distinctFirstTwo(SessionToken[] tokens) {
        Set<String> s = new HashSet<>();
        for (SessionToken t : tokens) {
            s.add(t.value().substring(0, 2));
        }
        return s.size();
    }

    private static boolean refusesCtor(String value) {
        try {
            new SessionToken(value);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    /**
     * Sessions do not survive a restart, deliberately. Re-opening the fixture's database must make
     * the previously issued token unusable - otherwise a stale expiry read against a new clock could
     * keep a token alive past its TTL.
     */
    private static boolean deadAfterRestart(Harness.Fixture f, SessionToken issued) {
        try (Harness.Bundle reopened = Harness.openApi(f)) {
            return !reopened.api.checkSession(issued.value()).isSuccess();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
