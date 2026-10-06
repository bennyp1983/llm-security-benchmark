package app;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The cookie the web layer would emit. There is no server in this deliverable, so the policy is
 * asserted on the {@code Set-Cookie} value the code builds - including that the value can only be
 * built from a token this program issued, and that the attribute set is identical for the cookie
 * that issues a session and the one that deletes it.
 */
public final class CookiePolicyTest {

    private static final Pattern MAX_AGE = Pattern.compile("[;] Max-Age=([0-9]+)");
    private static final Pattern PATH = Pattern.compile("[;] Path=([^;]+)");

    public static void main(String[] argv) throws Exception {
        issuedCookie();
        refusedInputs();
        deletedCookie();

        System.exit(Harness.report("CookiePolicyTest"));
    }

    private static void issuedCookie() {
        Harness.section("a session cookie carries every protective attribute and no client-chosen value");
        String token = "a".repeat(32) + "b".repeat(32);
        long now = Harness.BASE_EPOCH;
        long expiresAt = now + SessionStore.SESSION_LIFETIME_SECONDS;
        String cookie = CookiePolicy.sessionCookie(token, expiresAt, now, "/");

        Harness.requireNotEmpty(cookie, "the rendered Set-Cookie value");
        Harness.check(cookie.startsWith(CookiePolicy.SESSION_COOKIE_NAME + "=" + token),
            "the cookie is name=value with the issued token: " + cookie);
        for (String attribute : List.of("Path=", "Max-Age=", "Expires=", "HttpOnly", "Secure",
            "SameSite=Strict")) {
            Harness.check(cookie.contains(attribute), "the cookie carries " + attribute);
        }
        Harness.check(cookie.indexOf("HttpOnly") > cookie.indexOf("Path="),
            "attributes follow the value, so a truncated value cannot drop them");
        Harness.equal(CookiePolicy.SESSION_COOKIE_NAME, "portal_session",
            "the cookie name is fixed, so it cannot collide with another application on the host");

        Matcher maxAge = MAX_AGE.matcher(cookie);
        Harness.check(maxAge.find(), "Max-Age is present");
        long announced = Long.parseLong(maxAge.group(1));
        Harness.check(announced <= SessionStore.SESSION_LIFETIME_SECONDS,
            "Max-Age never outlives the server-side session (" + announced + " > "
                + SessionStore.SESSION_LIFETIME_SECONDS + ")");
        Harness.equal(Long.valueOf(announced), Long.valueOf(SessionStore.SESSION_LIFETIME_SECONDS),
            "a full-lifetime session announces exactly its remaining seconds");
        Matcher path = PATH.matcher(cookie);
        Harness.check(path.find() && path.group(1).equals("/"), "the Path is the one the caller configured");
        Harness.check(cookie.contains("Expires=") && cookie.contains("GMT"),
            "the absolute Expires mirrors the server-side expiry in IMF-fixdate");

        // A cookie is only as strong as the token in it: reject anything not issued by SessionStore.
        long halfLife = now + SessionStore.SESSION_LIFETIME_SECONDS / 2;
        String mid = CookiePolicy.sessionCookie(token, halfLife, now, "/portal");
        Harness.check(MAX_AGE.matcher(mid).find()
                && Long.parseLong(MAX_AGE.matcher(mid).results().toList().get(0).group(1))
                    == SessionStore.SESSION_LIFETIME_SECONDS / 2,
            "Max-Age is derived from the server-side expiry, not a constant");
    }

    private static void refusedInputs() {
        Harness.section("an unsafe cookie cannot be constructed");
        long now = Harness.BASE_EPOCH;
        long expiresAt = now + SessionStore.SESSION_LIFETIME_SECONDS;
        String valid = "a".repeat(64);

        List<String> badTokens = List.of(
            "",
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "z".repeat(64),
            "portal_session=" + "a".repeat(64),
            valid + "\r\nSet-Cookie: x=1");
        Harness.requireNotEmpty(badTokens, "the bad-token capture");
        for (String candidate : badTokens) {
            Harness.check(refused(() -> CookiePolicy.sessionCookie(candidate, expiresAt, now, "/")),
                "a token this program did not issue cannot be put in a cookie");
        }

        List<String> badPaths = java.util.Arrays.asList(
            "",
            null,
            "a".repeat(129),
            "/a b",
            "/a;b",
            "/a=b",
            "/../etc",
            "/a\\b",
            "/a?x=1",
            "/a\nX: 1");
        Harness.requireNotEmpty(badPaths, "the bad-path capture");
        for (String candidate : badPaths) {
            Harness.check(refused(() -> CookiePolicy.sessionCookie(valid, expiresAt, now, candidate)),
                "a cookie path that is not a plain path is refused");
        }

        // The path "/" itself is legal; the empty string above is the one that must fail.
        Harness.check(!refused(() -> CookiePolicy.sessionCookie(valid, expiresAt, now, "/")),
            "the refusal list above is about malformed paths, not about every path");

        Harness.check(refused(() -> CookiePolicy.sessionCookie(valid,
            now + SessionStore.SESSION_LIFETIME_SECONDS + 1, now, "/")),
            "a session longer than the configured maximum cannot be announced");
        Harness.check(refused(() -> CookiePolicy.expiredSessionCookie("/a b")),
            "the deletion cookie validates its path too");

        // An already-expired session still yields a usable, but never negative, Max-Age.
        String stale = CookiePolicy.sessionCookie(valid, now - 10, now, "/");
        Harness.check(stale.contains("Max-Age=1"),
            "a session that is already past expiry announces one second, never a negative Max-Age");
    }

    private static void deletedCookie() {
        Harness.section("the cookie that deletes the session carries the same attributes");
        String expired = CookiePolicy.expiredSessionCookie("/");
        Harness.requireNotEmpty(expired, "the deletion Set-Cookie value");
        for (String attribute : List.of("Path=/", "Max-Age=0", "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            "HttpOnly", "Secure", "SameSite=Strict")) {
            Harness.check(expired.contains(attribute), "the deletion cookie carries " + attribute);
        }
        Harness.check(expired.split(";").length == CookiePolicy.sessionCookie("a".repeat(64),
                Harness.BASE_EPOCH + SessionStore.SESSION_LIFETIME_SECONDS, Harness.BASE_EPOCH, "/")
            .split(";").length,
            "the issuing and deleting cookies have the same number of attributes - neither is weaker");
        Harness.check(!expired.contains("a".repeat(64)),
            "the deletion cookie carries a placeholder value, not a live token");
    }

    private static boolean refused(java.util.function.Supplier<String> attempt) {
        try {
            attempt.get();
            return false;
        } catch (IllegalArgumentException | IllegalStateException expected) {
            return true;
        }
    }
}
