package com.acme.portal.session;

import com.acme.portal.testapp.ProbeVerifier;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Verification harness for the session-handoff component.
 *
 * <p>No test framework is available on this machine (no Maven repository access from the build), so
 * this is a plain {@code main} with an explicit assertion counter. Every check is an assertion with a
 * name, and any failure makes the process exit non-zero, so a mutated source that weakens a guard
 * turns a red line rather than a shrug.
 *
 * <p>Assertions about cookie <i>attributes</i> here are made against the {@link Cookie} object the
 * component hands the container. That proves what the component asked for; {@code TomcatE2E} proves
 * what a real container then puts on the wire, which is the only thing a browser actually sees.
 */
public final class Harness {

    private static int checks;
    private static int failures;
    private static final List<String> FAILED = new ArrayList<String>();
    private static String section = "";

    /** Scratch directory, scoped to this process so concurrent runs cannot corrupt each other. */
    static Path scratch;

    public static void main(String[] args) throws Exception {
        scratch = Files.createTempDirectory("portal-handoff-test-" + ProcessHandle.current().pid() + '-');
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                deleteRecursively(scratch.toFile());
            }
        });

        run("validation", Harness::validation);
        run("masking", Harness::masking);
        run("generation", Harness::generation);
        run("policy", Harness::policy);
        run("writer", Harness::writer);
        run("service", Harness::service);
        run("limiter", Harness::limiter);
        run("clientAddress", Harness::clientAddress);
        run("settings", Harness::settings);
        run("responseBody", Harness::responseBody);
        run("servlet", Harness::servlet);
        run("hygiene", Harness::hygiene);
        run("timing", Harness::timing);

        System.out.println();
        System.out.println("SUMMARY checks=" + checks + " failures=" + failures);
        if (failures > 0) {
            for (String name : FAILED) {
                System.out.println("FAILED  " + name);
            }
            System.exit(1);
        }
    }

    private interface Section {
        void run() throws Exception;
    }

    /**
     * Runs one section. A section that dies part way through is recorded as a failure of its own,
     * which does two things: the checks that already ran still get reported, and the crash is
     * attributed to a section instead of arriving as an anonymous stack trace. A build tool that
     * only sees "exit 1, no failure line" cannot tell a weakened guard from a broken harness.
     */
    private static void run(String name, Section section) {
        try {
            section.run();
        } catch (Throwable aborted) {
            ok("section " + name + " ran to completion (aborted with "
                    + aborted.getClass().getName() + ": " + aborted.getMessage() + ')', false);
        }
    }

    // ------------------------------------------------------------------ assertions

    private static void begin(String name) {
        section = name;
        System.out.println();
        System.out.println("== " + name);
    }

    private static void ok(String what, boolean condition) {
        checks++;
        if (condition) {
            System.out.println("  PASS  " + what);
        } else {
            failures++;
            FAILED.add(section + " / " + what);
            System.out.println("  FAIL  " + what);
        }
    }

    private static void eq(String what, Object expected, Object actual) {
        boolean same = expected == null ? actual == null : expected.equals(actual);
        if (!same) {
            ok(what + " (expected <" + expected + "> got <" + actual + ">)", false);
        } else {
            ok(what, true);
        }
    }

    private static void throwsIae(String what, Runnable body) {
        try {
            body.run();
            ok(what + " (no exception thrown)", false);
        } catch (IllegalArgumentException expected) {
            ok(what, true);
        } catch (RuntimeException other) {
            ok(what + " (wrong exception " + other.getClass().getSimpleName() + ')', false);
        }
    }

    // ------------------------------------------------------------------ validation

    /**
     * 43-character fixture (19 distinct characters, includes the uppercase letter, '-' and '_' that
     * the allowlist permits), so it is indistinguishable in shape from a generated identifier.
     */
    private static final String GOOD = "a13b1d1e7e19005f693f249531276986e2ca227Q_-9";

    /** Valid value of exactly {@link SessionId#MAX_LENGTH} (86 + 42 = 128); 129 would exceed it. */
    private static final String LONGEST = GOOD + GOOD + GOOD.substring(0, 42);

    /** Valid value of exactly {@link SessionId#MIN_LENGTH}; 31 would fall short. */
    private static final String SHORTEST = "a13b1d1e7e19005f693f249531276986";

    private static void validation() {
        begin("VALIDATION of the externally supplied identifier");
        eq("fixture is 43 characters", 43, GOOD.length());
        eq("longest fixture is 128 characters", 128, LONGEST.length());
        eq("shortest fixture is 32 characters", 32, SHORTEST.length());
        try {
            SessionId accepted = SessionId.fromTrustedComponent(GOOD);
            eq("valid identifier accepted", GOOD, accepted.value());
        } catch (InvalidSessionIdentifierException unexpectedlyRejected) {
            ok("valid identifier accepted (rejected: " + unexpectedlyRejected.rejection() + ')', false);
        }

        ok("null rejected", SessionId.inspect(null) == SessionId.Rejection.ABSENT);
        ok("empty rejected", SessionId.inspect("") == SessionId.Rejection.TOO_SHORT);
        ok("31 characters rejected",
                SessionId.inspect(SHORTEST.substring(0, 31)) == SessionId.Rejection.TOO_SHORT);
        ok("exactly 32 characters accepted", SessionId.inspect(SHORTEST) == SessionId.Rejection.NONE);
        ok("129 characters rejected",
                SessionId.inspect(LONGEST + 'z') == SessionId.Rejection.TOO_LONG);
        ok("exactly 128 characters accepted", SessionId.inspect(LONGEST) == SessionId.Rejection.NONE);

        // Every character outside the single allowlist, including the ones a sloppy validator eats.
        String[] illegal = {" ", "\t", "\n", "\r", "\0", "\u000B", "\u001B", "\u0085", "\u00A0",
                ";", "=", "\"", "'", ",", "\\", "/", "+", "%", "&", "?", "#", "@", "!", "|", "`",
                "\u007F", "\u00E9", "\u4E2D", "\uD83D\uDE00"};
        for (String c : illegal) {
            String candidate = GOOD.substring(0, 40) + c + GOOD.substring(41);
            ok("rejects embedded " + describe(c),
                    SessionId.inspect(candidate) == SessionId.Rejection.ILLEGAL_CHARACTER);
        }

        // Character diversity is deliberately NOT a request-path check: it is not a
        // type/length/charset/range property, it is an invented entropy test, and the authoritative
        // store has already vouched for the value. A value that only trips the heuristic -- about one
        // hex identifier in 59, measured on the real 16-character alphabet -- would lock a legitimate
        // user out over a rule nobody wrote down. It survives as selfTest(), a tripwire on THIS
        // component's own CSPRNG output, where low diversity can only mean a broken generator and the
        // false-rejection rate is 8.0e-22 rather than 1.7%.
        eq("a low-alphabet value is ACCEPTED by the request path", SessionId.Rejection.NONE,
                SessionId.inspect(repeat('a', 43)));
        eq("a two-character repetition is ACCEPTED by the request path", SessionId.Rejection.NONE,
                SessionId.inspect("ab".repeat(22)));
        eq("a real 32-char hex identifier is accepted", SessionId.Rejection.NONE,
                SessionId.inspect("9f8e7d6c5b4a30129f8e7d6c5b4a3012"));
        eq("the identical value is still refused as CSPRNG output",
                SessionId.Rejection.LOW_CHAR_DIVERSITY, SessionId.selfTest(repeat('a', 43)));
        eq("a full-alphabet hex identifier clears the self-test (16 distinct symbols)",
                SessionId.Rejection.NONE,
                SessionId.selfTest("9f8e7d6c5b4a30129f8e7d6c5b4a3012"));
        eq("a hex identifier built from eight symbols is refused as CSPRNG output",
                SessionId.Rejection.LOW_CHAR_DIVERSITY,
                SessionId.selfTest("9f8e7d6c9f8e7d6c9f8e7d6c9f8e7d6c"));
        eq("and the generator's own output clears the self-test", SessionId.Rejection.NONE,
                SessionId.selfTest(SessionId.generate().value()));
        eq("and the self-test still delegates the shape checks", SessionId.Rejection.TOO_SHORT,
                SessionId.selfTest("too-short-to-be-an-identifier"));

        // Normalisation is the failure mode that folds two inputs onto one session.
        ok("leading space is refused, not trimmed",
                SessionId.inspect(" " + GOOD) == SessionId.Rejection.ILLEGAL_CHARACTER);
        ok("trailing space is refused, not trimmed",
                SessionId.inspect(GOOD + " ") == SessionId.Rejection.ILLEGAL_CHARACTER);
        ok("trailing tab is refused, not trimmed",
                SessionId.inspect(GOOD + "\t") == SessionId.Rejection.ILLEGAL_CHARACTER);
        ok("trailing NUL is refused, not trimmed",
                SessionId.inspect(GOOD + "\0") == SessionId.Rejection.ILLEGAL_CHARACTER);
        ok("uppercase is preserved rather than folded",
                SessionId.inspect(GOOD.toUpperCase(Locale.ROOT)) == SessionId.Rejection.NONE);
        SessionId upper = null;
        SessionId lower = null;
        try {
            upper = SessionId.fromTrustedComponent(GOOD);
            lower = SessionId.fromTrustedComponent(GOOD.toLowerCase(Locale.ROOT));
        } catch (InvalidSessionIdentifierException e) {
            ok("case variants both valid", false);
        }
        ok("case variants produce different fingerprints",
                upper != null && lower != null && !upper.fingerprint().equals(lower.fingerprint()));
    }

    /** Compact, printable label for a candidate that is deliberately malformed. */
    private static String shortLabel(String value) {
        if (value == null) {
            return "null";
        }
        String head = value.substring(0, Math.min(10, value.length()))
                .replace('\r', 'R').replace('\n', 'N').replace('\0', '0').replace(' ', '_');
        return "len=" + value.length() + " head=" + head;
    }

    private static String describe(String c) {
        StringBuilder text = new StringBuilder("U+");
        for (int i = 0; i < c.length(); i++) {
            if (i > 0) {
                text.append('+');
            }
            text.append(String.format(Locale.ROOT, "%04X", Integer.valueOf(c.charAt(i))));
        }
        return text.toString();
    }

    // ------------------------------------------------------------------ masking

    private static void masking() {
        begin("MASKING of the identifier in every text path");
        SessionId id = null;
        try {
            id = SessionId.fromTrustedComponent(GOOD);
        } catch (InvalidSessionIdentifierException impossible) {
            ok("fixture valid", false);
            return;
        }
        ok("toString hides the value", !id.toString().contains(GOOD));
        ok("toString carries a 12-hex fingerprint",
                id.toString().matches("SessionId\\([0-9a-f]{12}\\)"));
        ok("fingerprint is stable across calls", id.fingerprint().equals(id.fingerprint()));
        ok("fingerprint is 12 lower-hex characters", id.fingerprint().matches("[0-9a-f]{12}"));
        ok("fingerprint differs for different identifiers",
                !id.fingerprint().equals(SessionId.generate().fingerprint()));

        InvalidSessionIdentifierException rejection = null;
        try {
            SessionId.fromTrustedComponent("short");
        } catch (InvalidSessionIdentifierException expected) {
            rejection = expected;
        }
        ok("rejection exception exists", rejection != null);
        if (rejection != null) {
            ok("rejection message is a reason class only",
                    rejection.getMessage().equals("session identifier rejected: too-short"));
            ok("rejection toString hides any value", !rejection.toString().contains("short"));
            ok("rejection toString names the reason", rejection.toString().endsWith("TOO_SHORT"));
        }
        ok("no accessor other than value() yields the raw string",
                !id.toString().contains(GOOD) && !rejectionReasonsOf(id).contains(GOOD));
    }

    private static String rejectionReasonsOf(SessionId id) {
        return id.toString() + '|' + AttemptLimiter.Decision.ALLOWED + '|' + id.fingerprint();
    }

    // ------------------------------------------------------------------ generation

    private static void generation() {
        begin("GENERATION by this code's own CSPRNG");
        Set<String> seen = new TreeSet<String>();
        boolean allValid = true;
        boolean allLength = true;
        int minDistinct = 99;
        for (int i = 0; i < 200; i++) {
            SessionId id = SessionId.generate();
            seen.add(id.value());
            if (SessionId.inspect(id.value()) != SessionId.Rejection.NONE) {
                allValid = false;
            }
            if (id.value().length() != 43) {
                allLength = false;
            }
            Set<Character> chars = new java.util.HashSet<Character>();
            for (int c = 0; c < id.value().length(); c++) {
                chars.add(id.value().charAt(c));
            }
            minDistinct = Math.min(minDistinct, chars.size());
        }
        ok("200 generated identifiers are all distinct", seen.size() == 200);
        ok("all generated identifiers pass validation", allValid);
        ok("all generated identifiers are 43 characters (256 bits, base64url)", allLength);
        ok("minimum distinct characters observed clears the generator self-test with margin",
                minDistinct >= SessionId.SELF_TEST_MIN_DISTINCT_CHARS + 2);
        byte[] decoded = java.util.Base64.getUrlDecoder().decode(seen.iterator().next());
        eq("decoded material is 32 bytes", 32, decoded.length);
    }

    // ------------------------------------------------------------------ policy

    private static void policy() {
        begin("COOKIE POLICY validation and invariants");
        SessionCookiePolicy defaults = SessionCookiePolicy.of(null, null, null);
        eq("default name", "__Host-PORTAL_SESSION", defaults.name());
        eq("default path", "/", defaults.path());
        eq("default SameSite", "Strict", defaults.sameSite());
        ok("Secure is an invariant", defaults.secure());
        ok("HttpOnly is an invariant", defaults.httpOnly());
        ok("cookie is host-only", defaults.domain() == null);
        eq("session cookie (no expiry)", 0, defaults.maxAge());
        ok("empty string falls back to defaults",
                SessionCookiePolicy.of("", "", "").name().equals("__Host-PORTAL_SESSION"));

        ok("Lax is accepted case-insensitively",
                "Lax".equals(SessionCookiePolicy.of(null, null, "lax").sameSite()));
        ok("STRICT is accepted case-insensitively",
                "Strict".equals(SessionCookiePolicy.of(null, null, "STRICT").sameSite()));
        ok("a custom host-only-compatible name is accepted",
                "__Secure-PORTAL_SESSION".equals(
                        SessionCookiePolicy.of("__Secure-PORTAL_SESSION", null, null).name()));

        throwsIae("rejects a name containing ';'", () -> SessionCookiePolicy.of("a;b", null, null));
        throwsIae("rejects a name containing CR", () -> SessionCookiePolicy.of("a\rb", null, null));
        throwsIae("rejects a name containing LF", () -> SessionCookiePolicy.of("a\nb", null, null));
        throwsIae("rejects a name containing a space", () -> SessionCookiePolicy.of("a b", null, null));
        throwsIae("rejects a non-ASCII name", () -> SessionCookiePolicy.of("s\u00E9ss", null, null));
        throwsIae("rejects a name starting with a digit", () -> SessionCookiePolicy.of("9x", null, null));
        throwsIae("rejects an over-long name",
                () -> SessionCookiePolicy.of(repeat('a', 65), null, null));
        throwsIae("rejects the reserved name 'Path'", () -> SessionCookiePolicy.of("Path", null, null));
        throwsIae("rejects the reserved name 'set-cookie'",
                () -> SessionCookiePolicy.of("Set-Cookie", null, null));
        throwsIae("rejects a whitespace-only name rather than trimming it",
                () -> SessionCookiePolicy.of("   ", null, null));

        throwsIae("rejects a path without a leading slash",
                () -> SessionCookiePolicy.of(null, "app", null));
        throwsIae("rejects a path containing ';'", () -> SessionCookiePolicy.of(null, "/a;Domain=x", null));
        throwsIae("rejects a path containing a dot segment",
                () -> SessionCookiePolicy.of(null, "/a/../../etc", null));
        throwsIae("rejects a path containing '//'", () -> SessionCookiePolicy.of(null, "/a//b", null));
        throwsIae("rejects a path containing a space", () -> SessionCookiePolicy.of(null, "/a b", null));
        throwsIae("rejects a path containing CR", () -> SessionCookiePolicy.of(null, "/a\rb", null));
        throwsIae("rejects an over-long path", () -> SessionCookiePolicy.of(null, repeat('a', 129), null));
        throwsIae("rejects a whitespace-only path rather than trimming it",
                () -> SessionCookiePolicy.of(null, "   ", null));
        throwsIae("rejects ' /app' rather than trimming the leading space",
                () -> SessionCookiePolicy.of(null, " /app", null));
        ok("a legitimate subpath is accepted",
                "/portal".equals(SessionCookiePolicy.of("__Secure-P", "/portal", null).path()));
        throwsIae("rejects __Host- name combined with a subpath",
                () -> SessionCookiePolicy.of("__Host-P", "/portal", null));

        throwsIae("refuses SameSite=None", () -> SessionCookiePolicy.of(null, null, "None"));
        throwsIae("refuses a SameSite typo", () -> SessionCookiePolicy.of(null, null, "LAXX"));
        throwsIae("refuses 'Strict ' with a trailing space",
                () -> SessionCookiePolicy.of(null, null, "Strict "));
        throwsIae("refuses an empty-looking SameSite of one space",
                () -> SessionCookiePolicy.of(null, null, " "));
        ok("policy toString contains only attribute names",
                defaults.toString().contains("sameSite=Strict") && defaults.toString().contains("Secure")
                        || defaults.toString().contains("secure=true"));
    }

    // ------------------------------------------------------------------ writer

    private static void writer() throws Exception {
        begin("COOKIE WRITER output and second validation gate");
        SessionCookiePolicy policy = SessionCookiePolicy.of(null, null, null);
        SessionCookieWriter writer = new SessionCookieWriter(policy);
        Recording response = Recording.create();
        SessionId id = SessionId.fromTrustedComponent(GOOD);
        writer.writeSessionCookie(id, response.proxy());

        eq("exactly one Set-Cookie emitted", 1, response.cookies.size());
        Cookie cookie = response.cookies.get(0);
        eq("cookie name", "__Host-PORTAL_SESSION", cookie.getName());
        eq("cookie value is the identifier", GOOD, cookie.getValue());
        eq("cookie path", "/", cookie.getPath());
        ok("cookie is HttpOnly", cookie.isHttpOnly());
        ok("cookie is Secure", cookie.getSecure());
        eq("cookie carries no expiry attribute", -1, cookie.getMaxAge());
        ok("cookie has no Domain attribute", cookie.getDomain() == null);
        eq("SameSite rendered by the component", "Strict", cookie.getAttribute("SameSite"));
        eq("Cache-Control set to no-store", "no-store, max-age=0",
                response.header("Cache-Control"));
        eq("Pragma set to no-cache", "no-cache", response.header("Pragma"));
        ok("no cookie attribute is settable by the caller",
                response.cookies.size() == 1 && cookie.getValue().equals(GOOD));

        Recording nullResponse = Recording.create();
        try {
            writer.writeSessionCookie(null, nullResponse.proxy());
            ok("null identifier refused", false);
        } catch (InvalidSessionIdentifierException expected) {
            eq("null identifier refused", SessionId.Rejection.ABSENT, expected.rejection());
        }
        ok("no cookie written for a null identifier", nullResponse.cookies.isEmpty());

        // Second gate: build a SessionId whose payload is junk, bypassing the public factory, to
        // prove the writer does not rely on the caller having validated.
        Constructor<SessionId> tailgate = SessionId.class.getDeclaredConstructor(String.class);
        tailgate.setAccessible(true);
        // A well-formed but degenerate value (43 identical characters) is deliberately NOT in this
        // list: it is legal input (see the VALIDATION section), and the writer's job is to refuse what
        // is malformed, not to keep a private entropy policy that the validator no longer has. Each
        // shape below is malformed in exactly one way -- and each is something a caller could plausibly
        // have failed to catch, which is why the writer checks again at the point of emission.
        String[] junk = {GOOD.substring(0, 42) + "=", "short", GOOD + "; Domain=evil",
                repeat('a', 200), GOOD.substring(0, 42) + " "};
        for (String candidate : junk) {
            SessionId smuggled = tailgate.newInstance(candidate);
            Recording guarded = Recording.create();
            try {
                writer.writeSessionCookie(smuggled, guarded.proxy());
                ok("writer blocks a smuggled value " + shortLabel(candidate), false);
            } catch (InvalidSessionIdentifierException blocked) {
                ok("writer blocks a smuggled value " + shortLabel(candidate) + " ("
                        + blocked.rejection() + ')', true);
            }
            ok("no cookie written for the smuggled value " + shortLabel(candidate),
                    guarded.cookies.isEmpty());
        }
        throwsIae("writer refuses a null response", () -> {
            try {
                writer.writeSessionCookie(id, null);
            } catch (InvalidSessionIdentifierException impossible) {
                throw new IllegalStateException(impossible);
            }
        });
        ok("writer exposes its policy", writer.policy() == policy);
    }

    // ------------------------------------------------------------------ service

    private static void service() throws Exception {
        begin("HANDOFF DECISION: fail closed, uniform refusal, budget fairness");
        SessionCookiePolicy policy = SessionCookiePolicy.of(null, null, null);
        CountingVerifier store = new CountingVerifier(GOOD);
        AttemptLimiter generous = new AttemptLimiter(60, 100, 1000, 1000);
        SessionHandoffService service = new SessionHandoffService(policy, store, generous);

        SessionHandoffService.Decision granted = service.handle(
                new SessionHandoffService.Request(GOOD, ClientAddress.parse("203.0.113.7")));
        eq("valid asserted identifier is issued", SessionHandoffService.Outcome.ISSUED, granted.outcome());
        eq("issued decision carries the identifier", GOOD, granted.sessionIdentifier().value());
        eq("store was consulted exactly once", 1, store.calls);

        SessionHandoffService noVerifier = new SessionHandoffService(policy, null,
                new AttemptLimiter(60, 100, 1000, 1000));
        eq("a missing verifier fails closed", SessionHandoffService.Outcome.REFUSED_UNAUTHENTICATED,
                noVerifier.handle(new SessionHandoffService.Request(GOOD,
                        ClientAddress.parse("203.0.113.7"))).outcome());

        SessionHandoffService throwingStore = new SessionHandoffService(policy,
                new SessionHandoffService.SessionStateVerifier() {
                    @Override
                    public boolean isSessionValid(String sessionId) {
                        throw new IllegalStateException("datastore down");
                    }
                }, new AttemptLimiter(60, 100, 1000, 1000));
        eq("a verifier that throws is treated as 'no'",
                SessionHandoffService.Outcome.REFUSED_UNAUTHENTICATED,
                throwingStore.handle(new SessionHandoffService.Request(GOOD,
                        ClientAddress.parse("203.0.113.7"))).outcome());

        CountingVerifier unknownSessionStore = new CountingVerifier("Other-Session-Id-That-Is-Long-Enough-Xx9");
        SessionHandoffService unknown = new SessionHandoffService(policy, unknownSessionStore,
                new AttemptLimiter(60, 100, 1000, 1000));
        eq("a well-formed identifier the store does not know is refused",
                SessionHandoffService.Outcome.REFUSED_UNAUTHENTICATED,
                unknown.handle(new SessionHandoffService.Request(GOOD,
                        ClientAddress.parse("203.0.113.7"))).outcome());

        CountingVerifier untouched = new CountingVerifier(GOOD);
        SessionHandoffService budgetService = new SessionHandoffService(policy, untouched,
                new AttemptLimiter(60, 100, 1000, 1000));
        for (String malformed : new String[]{null, "", "short", repeat('a', 129), GOOD + "\t"}) {
            eq("malformed assertion is refused before any lookup",
                    SessionHandoffService.Outcome.REFUSED_INVALID_ASSERTION,
                    budgetService.handle(new SessionHandoffService.Request(malformed,
                            ClientAddress.parse("203.0.113.8"))).outcome());
        }
        eq("a malformed assertion never reaches the session store", 0, untouched.calls);
        // The four above are absent, too short, too long and carrying an illegal character: the four
        // things rule 1 asks about. A well-formed value that merely looks degenerate is none of them,
        // so it is decided where the evidence is -- the store -- rather than by a guess about entropy
        // that would also have refused about one legitimate hex identifier in 59.
        eq("a well-formed but degenerate assertion is decided by the store, not the shape check",
                SessionHandoffService.Outcome.REFUSED_UNAUTHENTICATED,
                budgetService.handle(new SessionHandoffService.Request(repeat('a', 43),
                        ClientAddress.parse("203.0.113.9"))).outcome());
        eq("and it was the store that refused it", 1, untouched.calls);

        // Flooding garbage must not spend a legitimate client's allowance.
        AttemptLimiter oneShot = new AttemptLimiter(60, 1, 1000, 1000);
        SessionHandoffService tight = new SessionHandoffService(policy, new CountingVerifier(GOOD), oneShot);
        ClientAddress victim = ClientAddress.parse("198.51.100.9");
        for (int i = 0; i < 50; i++) {
            tight.handle(new SessionHandoffService.Request("garbage", victim));
        }
        eq("50 malformed requests did not consume the victim's single allowance",
                SessionHandoffService.Outcome.ISSUED,
                tight.handle(new SessionHandoffService.Request(GOOD, victim)).outcome());

        // Rate limiting, and the shape of the limited outcome.
        AttemptLimiter singleUse = new AttemptLimiter(60, 1, 1000, 1000);
        SessionHandoffService limited = new SessionHandoffService(policy, new CountingVerifier(GOOD),
                singleUse);
        ClientAddress floodSource = ClientAddress.parse("192.0.2.55");
        eq("first handoff allowed", SessionHandoffService.Outcome.ISSUED,
                limited.handle(new SessionHandoffService.Request(GOOD, floodSource)).outcome());
        SessionHandoffService.Decision second =
                limited.handle(new SessionHandoffService.Request(GOOD, floodSource));
        eq("second handoff from the same source is limited",
                SessionHandoffService.Outcome.LIMITED_SOURCE, second.outcome());
        ok("a limited refusal carries a positive Retry-After", second.retryAfterSeconds() >= 1);
        eq("a different source is unaffected by one source's limit",
                SessionHandoffService.Outcome.ISSUED,
                limited.handle(new SessionHandoffService.Request(GOOD,
                        ClientAddress.parse("192.0.2.56"))).outcome());

        eq("a null request is refused", SessionHandoffService.Outcome.REFUSED_UNAVAILABLE,
                service.handle(null).outcome());
        ok("decision toString names the outcome only",
                granted.toString().equals("Decision[ISSUED]") && !granted.toString().contains(GOOD));
        ok("service toString carries no identifier", !service.toString().contains(GOOD));
        ok("request without a source uses the unknown bucket",
                service.handle(new SessionHandoffService.Request(GOOD, null)).outcome()
                        == SessionHandoffService.Outcome.ISSUED);
    }

    // ------------------------------------------------------------------ limiter

    private static void limiter() throws Exception {
        begin("ATTEMPT LIMITER: atomicity, fairness, bounded state");
        MutableClock clock = new MutableClock(1_000L);
        AttemptLimiter limiter = new AttemptLimiter(60, 3, 1000, 1000, clock);
        ClientAddress source = ClientAddress.parse("203.0.113.1");
        for (int i = 1; i <= 3; i++) {
            eq("attempt " + i + " of 3 allowed", AttemptLimiter.Decision.ALLOWED, limiter.tryAcquire(source));
        }
        eq("attempt 4 is limited", AttemptLimiter.Decision.LIMITED_PER_SOURCE, limiter.tryAcquire(source));
        clock.advance(59_000L);
        eq("still limited 59 s later", AttemptLimiter.Decision.LIMITED_PER_SOURCE, limiter.tryAcquire(source));
        clock.advance(2_000L);
        eq("allowed again after the window rolls", AttemptLimiter.Decision.ALLOWED, limiter.tryAcquire(source));
        ok("a denied attempt did not consume allowance", limiter.trackedSources() == 1);

        // Global saturation must not spend the source's own allowance.
        MutableClock globalClock = new MutableClock(0L);
        AttemptLimiter globalTight = new AttemptLimiter(60, 10, 2, 1000, globalClock);
        eq("first global slot", AttemptLimiter.Decision.ALLOWED,
                globalTight.tryAcquire(ClientAddress.parse("203.0.113.10")));
        eq("second global slot", AttemptLimiter.Decision.ALLOWED,
                globalTight.tryAcquire(ClientAddress.parse("203.0.113.11")));
        eq("third request hits the global lane", AttemptLimiter.Decision.LIMITED_GLOBALLY,
                globalTight.tryAcquire(ClientAddress.parse("203.0.113.12")));
        // 198.51.100.1 has never requested; it must see the global wall, not a personal one, and the
        // decision must be the distinguishable global one so the response can be honest.
        eq("a brand new source also sees the global wall, not a personal block",
                AttemptLimiter.Decision.LIMITED_GLOBALLY,
                globalTight.tryAcquire(ClientAddress.parse("198.51.100.1")));

        // Concurrency: 16 threads hammering one bucket must not exceed the ceiling by one.
        for (int round = 0; round < 3; round++) {
            final AttemptLimiter race = new AttemptLimiter(600, 100, 100000, 10000);
            final ClientAddress shared = ClientAddress.parse("203.0.113.99");
            final int threads = 16;
            final int perThread = 40;
            final CountDownLatch ready = new CountDownLatch(threads);
            final CountDownLatch go = new CountDownLatch(1);
            final AtomicInteger allowed = new AtomicInteger();
            final AtomicInteger errors = new AtomicInteger();
            Thread[] workers = new Thread[threads];
            for (int t = 0; t < threads; t++) {
                workers[t] = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        ready.countDown();
                        try {
                            go.await();
                            for (int i = 0; i < perThread; i++) {
                                if (race.tryAcquire(shared) == AttemptLimiter.Decision.ALLOWED) {
                                    allowed.incrementAndGet();
                                }
                            }
                        } catch (InterruptedException lost) {
                            errors.incrementAndGet();
                        } catch (RuntimeException broken) {
                            errors.incrementAndGet();
                        }
                    }
                });
                workers[t].start();
            }
            ready.await();
            go.countDown();
            for (Thread worker : workers) {
                worker.join();
            }
            eq("round " + round + ": no worker failed", 0, errors.get());
            eq("round " + round + ": exactly the ceiling admitted across " + (threads * perThread)
                    + " racing requests", 100, allowed.get());
        }

        // Unknown source shares one reduced lane: 4x stricter than a named source.
        MutableClock unknownClock = new MutableClock(0L);
        AttemptLimiter unknownLimiter = new AttemptLimiter(60, 8, 1000, 1000, unknownClock);
        int unknownAllowed = 0;
        for (int i = 0; i < 40; i++) {
            if (unknownLimiter.tryAcquire(ClientAddress.UNKNOWN) == AttemptLimiter.Decision.ALLOWED) {
                unknownAllowed++;
            }
        }
        eq("unknown-source allowance is max(1, perSource/4)", 2, unknownAllowed);

        // Bucket growth is capped and sheds instead of exhausting memory.
        MutableClock capClock = new MutableClock(0L);
        AttemptLimiter capped = new AttemptLimiter(60, 1000, 100000, 5, capClock);
        for (int i = 0; i < 5; i++) {
            capped.tryAcquire(ClientAddress.parse("203.0.113." + (i + 1)));
        }
        eq("cap reached", 5, capped.trackedSources());
        eq("a sixth distinct source is shed, not tracked",
                AttemptLimiter.Decision.LIMITED_TRACKING_SATURATED,
                capped.tryAcquire(ClientAddress.parse("198.51.100.77")));
        eq("tracking stayed at the cap", 5, capped.trackedSources());
        capClock.advance(61_000L);
        eq("after the window rolls, shed buckets are evicted to admit a new source",
                AttemptLimiter.Decision.ALLOWED, capped.tryAcquire(ClientAddress.parse("198.51.100.78")));

        // Bounded work, not merely bounded memory. A saturation check that scanned the whole map made
        // every new source pay for the crowd ahead of it: measured at the shipped cap that was 42 ms
        // worst case, spent inside one monitor that every concurrent client is queueing on, so one
        // client's stall became everyone else's 429 -- the component's own limit turned into the
        // lockout weapon rule 3 explicitly forbids. A spoofed swarm, or a CDN egress pool, reaches
        // 200k distinct sources inside one window by arriving, so fullness is the normal state, not an
        // edge case. The reclaim hand inspects a bounded number of candidates instead, which makes a
        // refused admission cost about the same as an admitted one however full the map is.
        MutableClock pinnedClock = new MutableClock(0L);
        AttemptLimiter pinned = new AttemptLimiter(3600, 1000, 100000, 20000, pinnedClock);
        for (int i = 0; i < 20000; i++) {
            pinned.tryAcquire(ClientAddress.parse("203.0." + (i / 256) + "." + (i % 256)));
        }
        eq("the map is pinned at its cap", 20000, pinned.trackedSources());
        long refusedNanos = timeNewSourceAdmissions(pinned, 2000);
        long admittedNanos = timeNewSourceAdmissions(
                new AttemptLimiter(3600, 1000, 100000, 20000, new MutableClock(0L)), 2000);
        // Printed so the claim in the README is a number a reader can find in the log rather than a
        // number an author once saw. The assertion below is the gate; this line is the evidence.
        System.out.println("      new source at a full map p50=" + (refusedNanos / 1000L)
                + " us   into an empty map p50=" + (admittedNanos / 1000L) + " us");
        ok("a refused admission at a full map is bounded work, not a map scan",
                refusedNanos <= 60_000L && refusedNanos <= admittedNanos * 50L + 30_000L);

        ok("Retry-After is always at least one second", capped.retryAfterSeconds(null) >= 1
                && capped.retryAfterSeconds(ClientAddress.parse("203.0.113.1")) >= 1);

        throwsIae("refuses a zero window rather than reading it as unlimited",
                () -> new AttemptLimiter(0, 10, 100, 100));
        throwsIae("refuses a zero per-source ceiling", () -> new AttemptLimiter(60, 0, 100, 100));
        throwsIae("refuses a zero global ceiling", () -> new AttemptLimiter(60, 10, 0, 100));
        throwsIae("refuses a zero bucket cap", () -> new AttemptLimiter(60, 10, 100, 0));
        throwsIae("refuses an over-long window", () -> new AttemptLimiter(999999, 10, 100, 100));
        throwsIae("refuses an over-large per-source ceiling",
                () -> new AttemptLimiter(60, 100000, 100000, 100));
        throwsIae("refuses a negative window", () -> new AttemptLimiter(-5, 10, 100, 100));
        ok("limiter toString carries no client address",
                !limiter.toString().contains("203.0.113") && limiter.toString().contains("perSource=3"));
    }

    // ------------------------------------------------------------------ client address

    /**
     * Best-round mean nanoseconds per attempt to admit a fresh source. Best of three rounds so a GC
     * pause cannot impersonate a map scan: the assertion this feeds is about work per call, and the
     * difference being measured is two orders of magnitude.
     */
    private static long timeNewSourceAdmissions(AttemptLimiter limiter, int attempts) {
        long best = Long.MAX_VALUE;
        for (int round = 0; round < 3; round++) {
            long start = System.nanoTime();
            for (int i = 0; i < attempts; i++) {
                limiter.tryAcquire(ClientAddress.parse("198.51." + (i / 250) + "." + (i % 250)));
            }
            best = Math.min(best, (System.nanoTime() - start) / attempts);
        }
        return best;
    }

    /** Mean nanoseconds per parse, best of five rounds. */
    private static long timeParses(String[] inputs) {
        long best = Long.MAX_VALUE;
        for (int round = 0; round < 5; round++) {
            long start = System.nanoTime();
            for (int n = 0; n < 400; n++) {
                ClientAddress.parse(inputs[n % inputs.length]);
            }
            best = Math.min(best, (System.nanoTime() - start) / (400L * inputs.length));
        }
        return best;
    }

    /**
     * The characters ClientAddress's allowlist permits, spelled out here as well on purpose: the sweep
     * that proves the allowlist is redundant has to describe the allowlist independently of the code
     * under test, or a change to one silently moves the other.
     */
    private static boolean isAddressTextChar(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
                || c == '.' || c == ':';
    }

    /** The bare character, plus every seed with the character inserted at every position. */
    private static String[] insertedAtEveryPosition(String[] seeds, char foreign) {
        java.util.List<String> forms = new java.util.ArrayList<String>();
        forms.add(String.valueOf(foreign));
        for (String seed : seeds) {
            for (int at = 0; at <= seed.length(); at++) {
                forms.add(seed.substring(0, at) + foreign + seed.substring(at));
            }
        }
        return forms.toArray(new String[0]);
    }

    private static void clientAddress() {
        begin("CLIENT ADDRESS canonicalisation (fair buckets, no DNS, no injection)");
        eq("::1 and its long form share a bucket",
                ClientAddress.parse("0:0:0:0:0:0:0:1").key(), ClientAddress.parse("::1").key());
        eq("uppercase IPv6 shares a bucket", ClientAddress.parse("2001:DB8::1").key(),
                ClientAddress.parse("2001:db8::1").key());
        eq("an IPv4-mapped address joins its IPv4 bucket",
                ClientAddress.parse("127.0.0.1").key(), ClientAddress.parse("::ffff:127.0.0.1").key());
        eq("an IPv4-mapped address in either hex case joins the same bucket",
                ClientAddress.parse("::ffff:127.0.0.1").key(),
                ClientAddress.parse("::FFFF:127.0.0.1").key());
        // The fold above is the only one, and the only mixed spelling admitted inside a compressed
        // address. The IPv4-compatible form (obsoleted by RFC 4291) used to be folded as well, which
        // made "::1" the bucket key "0.0.0.1/32": an IPv6 peer asserting an IPv4 identity, merged with
        // a host string that never appears on a wire, into the lane of a machine a loopback client has
        // nothing to do with. It is refused outright rather than canonicalised on a guess.
        ok("the obsolete IPv4-compatible form is refused outright",
                ClientAddress.parse("::127.0.0.1") == ClientAddress.UNKNOWN);
        ok("a compressed mixed form that is not ::ffff: is refused",
                ClientAddress.parse("2001:db8::1.2.3.4") == ClientAddress.UNKNOWN);
        ok("::1 keeps a v6 lane and never asserts an IPv4 identity",
                !ClientAddress.parse("::1").key().equals(ClientAddress.parse("0.0.0.1").key()));
        eq("two addresses inside one /64 share a bucket",
                ClientAddress.parse("2001:db8:0:1::11").key(),
                ClientAddress.parse("2001:db8:0:1:abcd::ff").key());
        ok("different /64 prefixes are separate buckets",
                !ClientAddress.parse("2001:db8:0:1::11").key()
                        .equals(ClientAddress.parse("2001:db8:0:2::11").key()));
        eq("a plain IPv4 address is canonical", "203.0.113.7", ClientAddress.parse("203.0.113.7").key()
                .split("/")[0]);
        ok("a named source is not flagged unknown", !ClientAddress.parse("203.0.113.7").isUnknown());
        ok("the fallback is flagged unknown", ClientAddress.UNKNOWN.isUnknown());

        // The three forms below are the ones a lenient parser would happily accept, so they are
        // listed separately from the generic garbage: each one names the guard it depends on.
        // InetAddress.getByName("517996801") yields 30.224.1.1 and getByName("localhost") performs a
        // lookup and yields 127.0.0.1, so if the shape check ever stops running, one host can open a
        // private rate-limit lane by how it is written -- and a request becomes a DNS query.
        ok("a decimal-integer address never becomes its own bucket",
                ClientAddress.parse("517996801") == ClientAddress.UNKNOWN);
        ok("a hostname is never resolved and never becomes its own bucket",
                ClientAddress.parse("localhost") == ClientAddress.UNKNOWN);
        // "Contains a colon" is not a shape check. Every value below is built only from characters the
        // allowlist permits, and InetAddress.getByName would hand each one to the operating-system
        // resolver as a hostname -- measured here at 14-41 us per attempt against 3 us for a real
        // literal, charged on every request before any throttle has been consulted. That is an
        // attacker-chosen amount of resolver work per packet, which is a second amplifier behind the
        // one the limiter already had to be rebuilt to remove.
        for (String colonForm : new String[]{"a:b", "1234:5678", "dead:beef:cafe", "1:2",
                "abcd:ef01:2345:6789:abcd:ef01:2345", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:",
                "::1:2:3:4:5:6:7:8", "1::2::3", "12345::", ":::1", "::1:", "2001:db8:::1"}) {
            ok("a non-literal colon form is refused without a lookup: [" + colonForm + ']',
                    ClientAddress.parse(colonForm) == ClientAddress.UNKNOWN);
        }
        // Cost, not just outcome: these must be refused by the grammar, not by failing a lookup. If
        // the shape gate is ever weakened the same inputs stay unparseable and these asserts still
        // pass on their return value, so the bound below is what reports the resolver being reached.
        long literalNanos = timeParses(new String[]{"203.0.113.9", "2001:db8:0:1:1:1:1:1"});
        long refusedNanos = timeParses(new String[]{"a:b", "1234:5678", "dead:beef:cafe", "1:2",
                "1:2:3:4:5:6:7:8:9", "12345::"});
        ok("a refused colon form is refused cheaply, not by paying for a lookup",
                refusedNanos <= literalNanos * 8L + 6_000L);
        // The character allowlist is the only thing between a container-supplied string and
        // InetAddress's tolerance of numeric interface scope ids: getByName("fe80::1%9") succeeds,
        // and every distinct suffix would then be its own unlimited-looking lane.
        for (String scoped : new String[]{"fe80::1%9", "1:2:3:4:5:6:7:8%1", "fe80::%eth0",
                "fe80::1%25", "%3a%3a%31"}) {
            ok("an interface-scope or percent-encoded form shares the unknown bucket: [" + scoped + ']',
                    ClientAddress.parse(scoped) == ClientAddress.UNKNOWN);
        }

        // The character allowlist is defence in depth rather than the load-bearing gate: the IPv6
        // grammar already admits nothing but hex digits, dot and colon, so nothing that fails the
        // allowlist can reach InetAddress at all. That is a checkable claim, so it is checked. Every
        // string below is one the allowlist refuses; the two grammar predicates are asked, by
        // reflection, whether they would have let it through. If the grammar is ever loosened the sweep
        // fails HERE, instead of leaving the allowlist as the only thing standing between a request and
        // the JDK's tolerance for scope ids and shorthand. This is also the answer to the battery's
        // ADDR-allowlist mutant, which survives because removing the loop changes no outcome: the
        // survival is only harmless while this sweep holds.
        java.lang.reflect.Method isDottedQuad;
        java.lang.reflect.Method isIpv6Literal;
        try {
            isDottedQuad = ClientAddress.class.getDeclaredMethod("isDottedQuad", String.class);
            isIpv6Literal = ClientAddress.class.getDeclaredMethod("isIpv6Literal", String.class);
            isDottedQuad.setAccessible(true);
            isIpv6Literal.setAccessible(true);
        } catch (ReflectiveOperationException gateMissing) {
            throw new IllegalStateException("the address grammar changed shape: " + gateMissing,
                    gateMissing);
        }
        String[] seeds = {"203.0.113.7", "1.2.3.4", "fe80::1", "::1", "::ffff:203.0.113.7",
                "0:0:0:0:0:0:0:1", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
                "1234:5678", "a:b", "abc.def.ghi.jkl"};
        int examined = 0;
        int throughGrammar = 0;
        String firstThrough = "";
        for (int cp = 0; cp <= 0x7F; cp++) {
            char foreign = (char) cp;
            if (isAddressTextChar(foreign)) {
                continue;
            }
            for (String candidate : insertedAtEveryPosition(seeds, foreign)) {
                examined++;
                if (!ClientAddress.parse(candidate).isUnknown()) {
                    throughGrammar++;
                    firstThrough = "[" + candidate + "] reached a bucket";
                }
            }
        }
        // Short strings over an alphabet that mixes grammar characters with the usual offenders, so a
        // form that needs two foreign characters before the grammar would let it through is covered
        // too. Only strings containing at least one character the allowlist refuses are of interest --
        // "::" is a legal address and is allowed to parse.
        char[] alphabet = {'0', ':', '.', 'f', '%', '-', 'g', ' '};
        for (int length = 1; length <= 4; length++) {
            int combinations = 1;
            for (int scale = 0; scale < length; scale++) {
                combinations *= alphabet.length;
            }
            for (int index = 0; index < combinations; index++) {
                StringBuilder text = new StringBuilder(length);
                int rest = index;
                boolean hasForeignChar = false;
                for (int position = 0; position < length; position++) {
                    char c = alphabet[rest % alphabet.length];
                    hasForeignChar |= !isAddressTextChar(c);
                    text.append(c);
                    rest /= alphabet.length;
                }
                if (!hasForeignChar) {
                    continue;
                }
                String candidate = text.toString();
                examined++;
                boolean accepted;
                try {
                    accepted = candidate.indexOf(':') >= 0
                            ? (Boolean) isIpv6Literal.invoke(null, candidate)
                            : (Boolean) isDottedQuad.invoke(null, candidate);
                } catch (ReflectiveOperationException predicateThrew) {
                    accepted = true;
                    firstThrough = "[" + candidate + "] made a grammar predicate throw: "
                            + predicateThrew.getCause();
                }
                if (accepted) {
                    throughGrammar++;
                }
            }
        }
        // An empty corpus would satisfy the zero below, so the size is asserted first -- the same
        // mistake as asserting a captured log is clean when nothing was ever captured. The bound is
        // set below the measured size of this corpus (20 564 strings) rather than at it, so trimming a
        // seed shortens the sweep visibly here instead of silently narrowing the proof.
        ok("the allowlist sweep covered a real corpus (" + examined + " refused strings)",
                examined > 15000);
        eq("nothing the character allowlist refuses gets past the address grammars"
                        + (firstThrough.isEmpty() ? "" : " -- " + firstThrough),
                0, Integer.valueOf(throughGrammar));

        String[] garbage = {null, "", " ", "not-an-address", "evil.example.com", "localhost",
                "999.1.1.1", "1.2.3.4.5", "203.0.113.7; Domain=evil", "203.0.113.7 rm",
                "203.0.113.7\n", "203.0.113.\0", "[203.0.113.7]", "fe80::1%eth0", "0x7f000001",
                "517996801", repeat('9', 70), "2001:db8:::1", ":::", "%203.0.113.7"};
        for (String candidate : garbage) {
            String label = candidate == null ? "null"
                    : candidate.length() > 24 ? "oversized(" + candidate.length() + ')' : candidate;
            ok("unparseable address degrades to the shared unknown bucket: [" + label + ']',
                    ClientAddress.parse(candidate) == ClientAddress.UNKNOWN);
        }
        ok("the unknown bucket is stable", ClientAddress.parse("zzz").key()
                .equals(ClientAddress.parse("yyy").key()));
        eq("the unknown bucket key is the shared one", "unknown/0", ClientAddress.parse("zzz").key());
        eq("a null source is bucketed as unknown, never skipped", ClientAddress.UNKNOWN,
                ClientAddress.parse(null));
    }

    // ------------------------------------------------------------------ settings

    private static void settings() {
        begin("SETTINGS from the environment: validated, ranged, no permissive default");
        Map<String, String> empty = new LinkedHashMap<String, String>();
        SessionHandoffSettings defaults = SessionHandoffSettings.load(mapLookup(empty));
        eq("default window", 60, defaults.windowSeconds());
        eq("default per-window", 30, defaults.maxPerWindow());
        eq("default global per-window", 2000, defaults.globalMaxPerWindow());
        eq("default assertion attribute", "com.acme.portal.session.assertedId",
                defaults.assertionAttribute());
        eq("cookie policy built from defaults", "__Host-PORTAL_SESSION",
                defaults.cookiePolicy().name());

        Map<String, String> custom = new LinkedHashMap<String, String>();
        custom.put(SessionHandoffSettings.WINDOW_SECONDS_ENV, "15");
        custom.put(SessionHandoffSettings.MAX_PER_WINDOW_ENV, "5");
        custom.put(SessionHandoffSettings.GLOBAL_MAX_PER_WINDOW_ENV, "500");
        custom.put(SessionHandoffSettings.SAME_SITE_ENV, "lax");
        custom.put(SessionHandoffSettings.COOKIE_PATH_ENV, "/portal");
        custom.put(SessionHandoffSettings.COOKIE_NAME_ENV, "__Secure-PORTAL_SESSION");
        custom.put(SessionHandoffSettings.ASSERTION_ATTRIBUTE_ENV, "com.example.myAssertion");
        SessionHandoffSettings loaded = SessionHandoffSettings.load(mapLookup(custom));
        eq("window override", 15, loaded.windowSeconds());
        eq("per-window override", 5, loaded.maxPerWindow());
        eq("global override", 500, loaded.globalMaxPerWindow());
        eq("SameSite override", "Lax", loaded.cookiePolicy().sameSite());
        eq("path override", "/portal", loaded.cookiePolicy().path());
        eq("assertion attribute override", "com.example.myAssertion", loaded.assertionAttribute());

        ok("a limiter can be built from validated settings", loaded.limiter() != null);
        ok("settings summary has no identifier material", !loaded.toString().contains(GOOD));

        throwsIae("rejects a non-numeric window",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.WINDOW_SECONDS_ENV, "60s"))));
        throwsIae("rejects a zero window",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.WINDOW_SECONDS_ENV, "0"))));
        throwsIae("rejects a negative ceiling",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.MAX_PER_WINDOW_ENV, "-1"))));
        throwsIae("rejects an out-of-range ceiling",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.MAX_PER_WINDOW_ENV, "100000"))));
        throwsIae("rejects a per-source ceiling above the global one",
                () -> SessionHandoffSettings.load(mapLookup(pair(
                        SessionHandoffSettings.MAX_PER_WINDOW_ENV, "50",
                        SessionHandoffSettings.GLOBAL_MAX_PER_WINDOW_ENV, "10"))));
        throwsIae("rejects a float",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.WINDOW_SECONDS_ENV, "60.5"))));
        throwsIae("rejects an integer with a trailing space",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.WINDOW_SECONDS_ENV, "60 "))));
        throwsIae("rejects a setting containing CR (header injection shape)",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.COOKIE_NAME_ENV, "A\r\nSet-Cookie: x=y"))));
        throwsIae("rejects a setting containing NUL",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.COOKIE_NAME_ENV, "A\0B"))));
        throwsIae("rejects a non-ASCII setting",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.COOKIE_NAME_ENV, "P\u00F6rtal"))));
        throwsIae("rejects SameSite=None coming from the environment",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.SAME_SITE_ENV, "None"))));
        throwsIae("rejects an assertion attribute in a reserved namespace",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.ASSERTION_ATTRIBUTE_ENV, "jakarta.servlet.foo"))));
        throwsIae("rejects an assertion attribute that is not identifier-shaped",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.ASSERTION_ATTRIBUTE_ENV, "1bad"))));
        throwsIae("rejects an assertion attribute containing a semicolon",
                () -> SessionHandoffSettings.load(mapLookup(one(
                        SessionHandoffSettings.ASSERTION_ATTRIBUTE_ENV, "a;b"))));
        throwsIae("a null lookup is refused rather than defaulting everything",
                () -> SessionHandoffSettings.load(null));
    }

    private static Map<String, String> one(String key, String value) {
        Map<String, String> single = new LinkedHashMap<String, String>();
        single.put(key, value);
        return single;
    }

    private static Map<String, String> pair(String k1, String v1, String k2, String v2) {
        Map<String, String> two = new LinkedHashMap<String, String>();
        two.put(k1, v1);
        two.put(k2, v2);
        return two;
    }

    private static java.util.function.Function<String, String> mapLookup(final Map<String, String> values) {
        return new java.util.function.Function<String, String>() {
            @Override
            public String apply(String name) {
                return values.get(name);
            }
        };
    }

    // ------------------------------------------------------------------ bodies

    private static void responseBody() {
        begin("RESPONSE BODIES: constant refusal, no echoed credential, escaped output");
        SessionCookiePolicy policy = SessionCookiePolicy.of(null, null, null);
        String granted = ResponseBody.granted(policy);
        ok("granted body names the cookie", granted.contains("__Host-PORTAL_SESSION"));
        ok("granted body never contains the session identifier", !granted.contains(GOOD));
        ok("refusal body is a fixed string", ResponseBody.REFUSAL.contains("could not complete sign-in"));
        String[] leakWords = {"admin", "identifier", "token", "exists", "expired", "unknown", "invalid",
                "password", "exception", "session id", "null"};
        for (String word : leakWords) {
            ok("refusal body does not mention '" + word + '\'',
                    !ResponseBody.REFUSAL.toLowerCase(Locale.ROOT).contains(word));
        }
        eq("HTML escaping neutralises markup", "&lt;script&gt;&amp;&#39;&quot;",
                ResponseBody.escapeHtml("<script>&'\""));
        String control = ResponseBody.escapeHtml("a" + (char) 0x01 + "b" + (char) 0x00 + "c");
        ok("control characters become spaces, never survive",
                control.equals("a b c") && control.indexOf((char) 0) < 0 && control.indexOf((char) 1) < 0);
        // The bound is on what the escaper EMITS. Bounding the input instead let 256 quote characters
        // out as 1 536 bytes of &quot;, on a page whose own guard had just reported itself satisfied.
        ok("the escaped output respects the bound whatever the characters are",
                ResponseBody.escapeHtml(repeat('a', 1000)).length() <= 256
                        && ResponseBody.escapeHtml(repeat('"', 1000)).length() <= 256
                        && ResponseBody.escapeHtml(repeat('&', 1000)).length() <= 256
                        && ResponseBody.escapeHtml("<>'\"".repeat(300)).length() <= 256);
        ok("the bound is a real bound, not a stub that stops early",
                ResponseBody.escapeHtml(repeat('a', 1000)).length() >= 200);
        ok("an entity at the edge is whole or absent, never cut in half",
                ResponseBody.escapeHtml(repeat('"', 1000)).endsWith("&quot;")
                        && ResponseBody.escapeHtml(repeat('&', 1000)).endsWith("&amp;")
                        && ResponseBody.escapeHtml(repeat('a', 250) + "<<<").length() <= 256);
        eq("null escapes to empty", "", ResponseBody.escapeHtml(null));
        byte[] refusalBytes = ResponseBody.REFUSAL.getBytes(StandardCharsets.UTF_8);
        ok("refusal body is ASCII and small", refusalBytes.length < 400
                && new String(refusalBytes, StandardCharsets.US_ASCII).equals(ResponseBody.REFUSAL));
    }

    // ------------------------------------------------------------------ servlet

    private static void servlet() throws Exception {
        begin("HTTP LAYER: status codes, headers, method handling, fail-closed wiring");
        SessionCookiePolicy policy = SessionCookiePolicy.of(null, null, null);
        CountingVerifier store = new CountingVerifier(GOOD);
        SessionHandoffServlet serving = new SessionHandoffServlet();
        serving.configure(new SessionHandoffService(policy, store, new AttemptLimiter(60, 100, 1000, 1000)),
                new SessionCookieWriter(policy),
                new RequestAttributeAssertionSource("com.acme.test.assertedId"));
        ok("a fully wired servlet serves", serving.isServing());

        Recording grantedResponse = Recording.create();
        serving.doGet(FakeRequest.get("203.0.113.5", "com.acme.test.assertedId", GOOD).proxy(),
                grantedResponse.proxy());
        eq("granted status", 200, grantedResponse.status);
        eq("one cookie on grant", 1, grantedResponse.cookies.size());
        eq("cookie value", GOOD, grantedResponse.cookies.get(0).getValue());
        eq("no-store on grant", "no-store, max-age=0", grantedResponse.header("Cache-Control"));
        eq("nosniff on grant", "nosniff", grantedResponse.header("X-Content-Type-Options"));
        ok("granted body says signed in", grantedResponse.body().contains("Signed in"));
        ok("granted body does not contain the identifier", !grantedResponse.body().contains(GOOD));
        ok("no Set-Cookie in the body", !grantedResponse.body().toLowerCase(Locale.ROOT)
                .contains("set-cookie"));

        // Uniform refusals: identical bytes for every reason.
        Map<String, Recording> refusals = new LinkedHashMap<String, Recording>();
        SessionHandoffServlet noAssertion = newSessionServlet(policy, new CountingVerifier(GOOD),
                new RequestAttributeAssertionSource("com.acme.test.assertedId"));
        Recording silent = Recording.create();
        noAssertion.doGet(FakeRequest.get("203.0.113.6", "com.acme.test.assertedId", null).proxy(),
                silent.proxy());
        refusals.put("no assertion", silent);
        eq("no assertion -> 403", 403, silent.status);
        ok("no assertion -> no cookie", silent.cookies.isEmpty());

        Recording malformed = Recording.create();
        noAssertion.doGet(FakeRequest.get("203.0.113.6", "com.acme.test.assertedId", "junk").proxy(),
                malformed.proxy());
        refusals.put("malformed assertion", malformed);
        eq("malformed assertion -> 403", 403, malformed.status);
        ok("malformed assertion -> no cookie", malformed.cookies.isEmpty());

        Recording unknownSession = Recording.create();
        newSessionServlet(policy, new CountingVerifier("Different-Session-Identifier-Value-Ab12"),
                new RequestAttributeAssertionSource("com.acme.test.assertedId"))
                .doGet(FakeRequest.get("203.0.113.6", "com.acme.test.assertedId", GOOD).proxy(),
                        unknownSession.proxy());
        refusals.put("unknown session", unknownSession);
        eq("unknown session -> 403", 403, unknownSession.status);
        ok("unknown session -> no cookie", unknownSession.cookies.isEmpty());

        Recording storeDown = Recording.create();
        newSessionServlet(policy, new SessionHandoffService.SessionStateVerifier() {
            @Override
            public boolean isSessionValid(String sessionId) {
                throw new IllegalStateException("connection string jdbc:h2:mem:secret");
            }
        }, new RequestAttributeAssertionSource("com.acme.test.assertedId"))
                .doGet(FakeRequest.get("203.0.113.6", "com.acme.test.assertedId", GOOD).proxy(),
                        storeDown.proxy());
        refusals.put("store throws", storeDown);
        eq("a throwing store -> 403 (fail closed)", 403, storeDown.status);
        ok("a throwing store leaks nothing into the body",
                !storeDown.body().contains("jdbc") && !storeDown.body().contains("secret"));

        Recording limited = Recording.create();
        SessionHandoffServlet tight = newSessionServlet(policy, new CountingVerifier(GOOD),
                new RequestAttributeAssertionSource("com.acme.test.assertedId"),
                new AttemptLimiter(60, 1, 1000, 1000));
        tight.doGet(FakeRequest.get("192.0.2.31", "com.acme.test.assertedId", GOOD).proxy(),
                limited.proxy());
        Recording second = Recording.create();
        tight.doGet(FakeRequest.get("192.0.2.31", "com.acme.test.assertedId", GOOD).proxy(),
                second.proxy());
        refusals.put("rate limited", second);
        eq("first request allowed", 200, limited.status);
        eq("second request -> 429", 429, second.status);
        ok("429 carries Retry-After", Integer.parseInt(second.header("Retry-After")) >= 1);
        ok("429 carries no cookie", second.cookies.isEmpty());
        ok("429 body is the same generic page", second.body().equals(ResponseBody.REFUSAL));
        // The wording has to match the grant's, not merely avoid the forbidden words. The throttle
        // and the grant differ in status alone; a Cache-Control that drifts on the throttled page
        // lets an intermediary hold a 429 and hand it to whoever arrives next on that cache key, so
        // one noisy source can make its neighbours look throttled when they are not. Equality with
        // the grant from the same servlet is the assertion SRV-shape-drift dies on -- it adds
        // "Cache-Control: public, max-age=60" to this path and nothing else observable changes.
        eq("throttle cache wording matches the grant's", limited.header("Cache-Control"),
                second.header("Cache-Control"));
        eq("throttle pragma matches the grant's", limited.header("Pragma"),
                second.header("Pragma"));
        eq("throttle forbids sniffing like the grant", limited.header("X-Content-Type-Options"),
                second.header("X-Content-Type-Options"));
        eq("throttle declares the same media type as the grant", limited.header("Content-Type"),
                second.header("Content-Type"));
        // The last cell of the GET/HEAD matrix. A throttled HEAD must describe the document the same
        // request would have written as a GET, or "did I get a length back?" separates throttled from
        // refused without reading a body -- the same oracle SRV-head-length used against the 403. The
        // comparison is against the bytes the GET actually wrote, not a constant, so it also catches
        // the two methods drifting to describe different documents.
        Recording limitedHead = Recording.create();
        FakeRequest headFlood = FakeRequest.get("192.0.2.31", "com.acme.test.assertedId", GOOD);
        headFlood.method = "HEAD";
        tight.doHead(headFlood.proxy(), limitedHead.proxy());
        eq("a throttled HEAD is still 429", 429, limitedHead.status);
        eq("a throttled HEAD describes the document its GET wrote",
                second.body().getBytes(StandardCharsets.UTF_8).length,
                Integer.parseInt(limitedHead.header("Content-Length")));
        ok("a throttled HEAD writes no body", limitedHead.body().isEmpty());
        ok("a throttled HEAD issues no cookie", limitedHead.cookies.isEmpty());

        Recording notServing = Recording.create();
        SessionHandoffServlet broken = unwiredServlet();
        ok("an unwired servlet refuses to serve", !broken.isServing());
        // The other half of the same fail-closed contract, checked through the entry point that
        // enforces it: handing configure() any partial set of collaborators must leave the servlet
        // refusing, not serving with a null where a decision-maker belongs.
        SessionCookiePolicy wirePolicy = SessionCookiePolicy.of(null, null, null);
        SessionCookieWriter realWriter = new SessionCookieWriter(wirePolicy);
        TrustedSessionAssertionSource realSource =
                new RequestAttributeAssertionSource("com.acme.test.assertedId");
        SessionHandoffService realService = new SessionHandoffService(wirePolicy,
                new CountingVerifier(GOOD), new AttemptLimiter(60, 100, 1000, 1000));
        String[] partialNames = {"no service", "no cookie writer", "no assertion source"};
        SessionHandoffService[] services = {null, realService, realService};
        SessionCookieWriter[] writers = {realWriter, null, realWriter};
        TrustedSessionAssertionSource[] sources = {realSource, realSource, null};
        for (int i = 0; i < partialNames.length; i++) {
            SessionHandoffServlet partial = new SessionHandoffServlet();
            partial.configure(services[i], writers[i], sources[i]);
            ok("configure() with " + partialNames[i] + " still refuses to serve", !partial.isServing());
            Recording partialResponse = Recording.create();
            partial.doGet(FakeRequest.get("203.0.113.66", "com.acme.test.assertedId", GOOD).proxy(),
                    partialResponse.proxy());
            eq("a partially wired servlet answers 503 (" + partialNames[i] + ')', 503,
                    partialResponse.status);
            ok("a partially wired servlet issues no cookie (" + partialNames[i] + ')',
                    partialResponse.cookies.isEmpty());
        }
        LogCapture requestLog = new LogCapture(SessionHandoffServlet.class);
        try {
            broken.doGet(FakeRequest.get("203.0.113.6", "com.acme.test.assertedId", GOOD).proxy(),
                    notServing.proxy());
        } finally {
            requestLog.stop();
        }
        refusals.put("not serving", notServing);
        eq("unwired servlet -> 503", 503, notServing.status);
        ok("503 carries Retry-After", Integer.parseInt(notServing.header("Retry-After")) >= 1);
        ok("unwired servlet issues no cookie", notServing.cookies.isEmpty());
        // The status alone cannot tell this guard apart from the catch-all below: with the guard
        // deleted, the null collaborator throws and the same 503 comes back. What is different --
        // and what has to stay different -- is that a refusal by decision logs nothing, while a
        // refusal that came from an unexpected exception logs a SEVERE per request. Losing the
        // guard would turn every request into a logged server error, which is both a false alarm
        // for the operator and a log-volume amplifier an attacker can drive at will.
        eq("the not-serving refusal is a decision, not a swallowed exception", 0,
                Integer.valueOf(requestLog.severeCount()));
        // Same capture, positive control: a SEVERE really does reach the handler, so the zero above
        // is a finding rather than an uninstrumented logger.
        LogCapture control = new LogCapture(SessionHandoffServlet.class);
        java.util.logging.Logger.getLogger(SessionHandoffServlet.class.getName())
                .log(java.util.logging.Level.SEVERE, "log capture self test");
        control.stop();
        eq("the log capture does see a SEVERE record", 1, Integer.valueOf(control.severeCount()));

        String baseline = ResponseBody.REFUSAL;
        for (Map.Entry<String, Recording> refusal : refusals.entrySet()) {
            ok("refusal body is byte-identical for '" + refusal.getKey() + '\''
                            + (refusal.getValue().body().equals(baseline) ? "" : " but is different"),
                    refusal.getValue().body().equals(baseline));
        }
        Set<String> distinctBodies = new TreeSet<String>();
        for (Recording refusal : refusals.values()) {
            distinctBodies.add(refusal.body());
        }
        eq("every refusal path renders exactly one distinct body", 1, distinctBodies.size());

        // Conditional request on a grant must still deliver the cookie, never a 304 without one.
        Recording conditional = Recording.create();
        FakeRequest withEtag = FakeRequest.get("203.0.113.70", "com.acme.test.assertedId", GOOD);
        withEtag.headers.put("If-None-Match", "\"whatever-the-client-claims\"");
        newSessionServlet(policy, new CountingVerifier(GOOD),
                new RequestAttributeAssertionSource("com.acme.test.assertedId"))
                .doGet(withEtag.proxy(), conditional.proxy());
        eq("a conditional grant is a full 200, not a 304", 200, conditional.status);
        eq("a conditional grant still carries the cookie", 1, conditional.cookies.size());

        // HEAD: same headers, no body, no cookie.
        Recording head = Recording.create();
        SessionHandoffServlet headServlet = newSessionServlet(policy, new CountingVerifier(GOOD),
                new RequestAttributeAssertionSource("com.acme.test.assertedId"));
        FakeRequest headRequest = FakeRequest.get("203.0.113.71", "com.acme.test.assertedId", GOOD);
        headRequest.method = "HEAD";
        headServlet.doHead(headRequest.proxy(), head.proxy());
        eq("HEAD with an assertion is 200", 200, head.status);
        ok("HEAD writes no body", head.body().isEmpty());
        ok("HEAD issues no cookie", head.cookies.isEmpty());
        eq("HEAD declares exactly the byte length GET would have written",
                ResponseBody.granted(policy).getBytes(StandardCharsets.UTF_8).length,
                Integer.parseInt(head.header("Content-Length")));
        // A cache in front of the endpoint that sees a HEAD with no freshness directive may satisfy a
        // later GET from its own store, and the GET would have carried a different cookie decision. So
        // the HEAD answer has to carry the same wording as the GET, not merely the same status: the
        // length describes a body that must never be reused, and the type says what it describes.
        eq("HEAD grant is uncacheable like the GET", "no-store, max-age=0",
                head.header("Cache-Control"));
        eq("HEAD grant says what its length describes", "text/html;charset=UTF-8",
                head.header("Content-Type"));
        eq("HEAD grant forbids sniffing like the GET", "nosniff",
                head.header("X-Content-Type-Options"));

        // The refusals have to answer a HEAD exactly as they answer a GET. This is the case the shared
        // measure-the-body step exists for: the grant is the one path that could plausibly be handed a
        // Content-Length while every refusal was left with none, and that difference alone would let a
        // client that sent HEAD instead of GET read the decision off the header set -- the same side
        // channel as a differing body, reached without ever looking at a byte.
        Recording headDenied = Recording.create();
        FakeRequest headDeniedRequest = FakeRequest.get("203.0.113.74", "com.acme.test.assertedId",
                "0123456789abcdef0123456789abcdef");
        headDeniedRequest.method = "HEAD";
        headServlet.doHead(headDeniedRequest.proxy(), headDenied.proxy());
        eq("HEAD without a known session is 403", 403, headDenied.status);
        eq("HEAD refusal declares the length its GET would have written",
                ResponseBody.REFUSAL.getBytes(StandardCharsets.UTF_8).length,
                Integer.parseInt(headDenied.header("Content-Length")));
        eq("HEAD refusal cache wording matches the grant's", head.header("Cache-Control"),
                headDenied.header("Cache-Control"));
        eq("HEAD refusal type wording matches the grant's", head.header("Content-Type"),
                headDenied.header("Content-Type"));
        eq("HEAD refusal sniffing wording matches the grant's", head.header("X-Content-Type-Options"),
                headDenied.header("X-Content-Type-Options"));
        ok("HEAD refusal issues no cookie", headDenied.cookies.isEmpty());
        ok("HEAD refusal writes no body", headDenied.body().isEmpty());
        Recording headDown = Recording.create();
        FakeRequest headDownRequest = FakeRequest.get("203.0.113.75", "com.acme.test.assertedId", GOOD);
        headDownRequest.method = "HEAD";
        new SessionHandoffServlet().doHead(headDownRequest.proxy(), headDown.proxy());
        eq("HEAD against an unwired servlet is 503", 503, headDown.status);
        eq("unwired HEAD declares the refusal length as well",
                ResponseBody.REFUSAL.getBytes(StandardCharsets.UTF_8).length,
                Integer.parseInt(headDown.header("Content-Length")));
        eq("unwired HEAD cache wording matches the grant's", head.header("Cache-Control"),
                headDown.header("Cache-Control"));
        ok("unwired HEAD issues no cookie", headDown.cookies.isEmpty());

        // Methods that must not exist.
        for (String method : new String[]{"Post", "Put", "Delete", "Options"}) {
            Recording refusedMethod = Recording.create();
            invokeDoMethod(serving, method, FakeRequest.get("203.0.113.72", "k", GOOD).proxy(),
                    refusedMethod.proxy());
            eq(method.toUpperCase(Locale.ROOT) + " -> 405", 405, refusedMethod.status);
            eq(method.toUpperCase(Locale.ROOT) + " advertises only GET and HEAD", "GET, HEAD",
                    refusedMethod.header("Allow"));
            ok(method.toUpperCase(Locale.ROOT) + " issues no cookie", refusedMethod.cookies.isEmpty());
        }
        Recording trace = Recording.create();
        invokeDoMethod(serving, "Trace", FakeRequest.get("203.0.113.73", "k", GOOD).proxy(),
                trace.proxy());
        eq("TRACE -> 501", 501, trace.status);
        ok("TRACE does not echo request data", trace.body().isEmpty());

        // An assertion source that misbehaves must degrade to "no assertion", never to a grant.
        Recording sourceFailed = Recording.create();
        newSessionServlet(policy, new CountingVerifier(GOOD), new TrustedSessionAssertionSource() {
            @Override
            public String assertedSessionId(HttpServletRequest request) {
                throw new IllegalStateException("assertion source exploded");
            }
        }).doGet(FakeRequest.get("203.0.113.74", "com.acme.test.assertedId", GOOD).proxy(),
                sourceFailed.proxy());
        eq("a broken assertion source -> 403", 403, sourceFailed.status);
        ok("a broken assertion source issues no cookie", sourceFailed.cookies.isEmpty());

        // An attribute holding something that is not a String must not be stringified and issued.
        Recording wrongType = Recording.create();
        FakeRequest attributeIsAnObject = FakeRequest.get("203.0.113.75", null, null);
        attributeIsAnObject.attributes.put("com.acme.test.assertedId", Integer.valueOf(1));
        newSessionServlet(policy, new CountingVerifier(GOOD),
                new RequestAttributeAssertionSource("com.acme.test.assertedId"))
                .doGet(attributeIsAnObject.proxy(), wrongType.proxy());
        eq("a non-String assertion attribute -> 403", 403, wrongType.status);
        ok("a non-String assertion attribute issues no cookie", wrongType.cookies.isEmpty());

        // A cookie the client sends must never be the source of the issued value.
        Recording withClientCookie = Recording.create();
        FakeRequest clientOffersCookie = FakeRequest.get("203.0.113.76", "com.acme.test.assertedId", GOOD);
        clientOffersCookie.cookies = new Cookie[]{new Cookie("__Host-PORTAL_SESSION",
                "AttackerChosenSessionIdentifierValue-Ab1")};
        newSessionServlet(policy, new CountingVerifier("AttackerChosenSessionIdentifierValue-Ab1"),
                new RequestAttributeAssertionSource("com.acme.test.assertedId"))
                .doGet(clientOffersCookie.proxy(), withClientCookie.proxy());
        eq("a request with no assertion but an offered cookie is 403", 403, withClientCookie.status);
        ok("an offered client cookie is never echoed back", withClientCookie.cookies.isEmpty());
        ok("the component never reads the request's cookies",
                !withClientCookie.body().contains("AttackerChosen"));

        ok("servlet toString leaks no identifier", !serving.toString().contains(GOOD));
    }

    private static SessionHandoffServlet newSessionServlet(SessionCookiePolicy policy,
                                                           SessionHandoffService.SessionStateVerifier store,
                                                           TrustedSessionAssertionSource assertions) {
        return newSessionServlet(policy, store, assertions, new AttemptLimiter(60, 100, 1000, 1000));
    }

    /**
     * A servlet in the state the fail-closed wiring path leaves it in: nothing was ever configured,
     * exactly as after {@code serveNothing()}. Deliberately not built by calling {@code configure}
     * with nulls -- a test that constructs the refusal through the very entry point it is testing
     * stays green when that entry point stops refusing, because the nulls then arrive as an
     * exception instead of as a decision.
     */
    private static SessionHandoffServlet unwiredServlet() {
        return new SessionHandoffServlet();
    }

    private static SessionHandoffServlet newSessionServlet(SessionCookiePolicy policy,
                                                           SessionHandoffService.SessionStateVerifier store,
                                                           TrustedSessionAssertionSource assertions,
                                                           AttemptLimiter limiter) {
        SessionHandoffServlet servlet = new SessionHandoffServlet();
        servlet.configure(new SessionHandoffService(policy, store, limiter),
                new SessionCookieWriter(policy), assertions);
        return servlet;
    }

    private static void invokeDoMethod(Object target, String method, HttpServletRequest request,
                                       HttpServletResponse response) throws Exception {
        Method doMethod = target.getClass().getDeclaredMethod("do" + method,
                HttpServletRequest.class, HttpServletResponse.class);
        doMethod.setAccessible(true);
        try {
            doMethod.invoke(target, request, response);
        } catch (java.lang.reflect.InvocationTargetException wrapped) {
            Throwable cause = wrapped.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw new RuntimeException(cause);
        }
    }

    // ------------------------------------------------------------------ hygiene

    private static void hygiene() throws Exception {
        begin("DEPLOYMENT HYGIENE: refuse to load code from a writable location");
        ok("this build's own code location passes the check",
                DeploymentHygiene.describeProblem(SessionHandoffServlet.class) == null);
        Path writableDir = Files.createTempDirectory(scratch, "world-writable-");
        // Simulate a shared/tmp classpath entry another local account could write.
        Path forged = writableDir.resolve("evil.jar");
        Files.write(forged, new byte[]{0, 1, 2, 3});
        Files.setPosixFilePermissions(writableDir,
                posix("rwxrwxrwx"));
        String original = System.getProperty("java.class.path");
        try {
            System.setProperty("java.class.path", original + java.io.File.pathSeparator + forged);
            String problem = DeploymentHygiene.describeProblem(SessionHandoffServlet.class);
            ok("a world-writable classpath entry is reported", problem != null);
            ok("the report names the location, not a secret",
                    problem != null && problem.contains("write"));
        } finally {
            System.setProperty("java.class.path", original);
        }
        ok("the check passes again once the entry is gone",
                DeploymentHygiene.describeProblem(SessionHandoffServlet.class) == null);
        Files.setPosixFilePermissions(writableDir, posix("rwx------"));
        try {
            System.setProperty("java.class.path", original + java.io.File.pathSeparator + forged);
            ok("a private directory passes",
                    DeploymentHygiene.describeProblem(SessionHandoffServlet.class) == null);
        } finally {
            System.setProperty("java.class.path", original);
        }
        // An entry that is simply not there must be reported, and reported as what it is. Silently
        // skipping it was the old behaviour, and falling through to the permission probe instead would
        // report a location "other users can write" that was never measured -- sending an operator to
        // chmod the wrong file while the real problem (an entry that points at nothing) stays.
        String absentEntry = "/absent-" + ProcessHandle.current().pid() + "-" + System.nanoTime() + ".jar";
        try {
            System.setProperty("java.class.path", original + java.io.File.pathSeparator + absentEntry);
            String missing = DeploymentHygiene.describeProblem(SessionHandoffServlet.class);
            ok("a classpath entry that is not present is reported, not skipped", missing != null);
            ok("and is reported as absent rather than as writable",
                    missing != null && missing.contains("not present")
                            && !missing.contains("other users can write"));
        } finally {
            System.setProperty("java.class.path", original);
        }
        // A path is the one string in a refusal reason that a packaging step influences, and a file
        // name may legally contain a newline. Without the strip, one such name lets anything write a
        // second line into the operator's log that looks exactly like this component wrote it.
        Path sneaky = Files.createFile(scratch.resolve("ev\nil.jar"));
        Files.setPosixFilePermissions(sneaky, posix("rw-rw-rw-"));
        try {
            System.setProperty("java.class.path", original + java.io.File.pathSeparator + sneaky);
            String forgedLine = DeploymentHygiene.describeProblem(SessionHandoffServlet.class);
            ok("a writable entry whose name carries control characters is still reported",
                    forgedLine != null && forgedLine.contains("write"));
            ok("and the refusal reason cannot forge a second log line",
                    forgedLine != null && forgedLine.indexOf('\n') < 0 && forgedLine.indexOf('\r') < 0
                            && forgedLine.contains("il.jar"));
        } finally {
            System.setProperty("java.class.path", original);
        }
        ok("a missing code owner is reported rather than skipped",
                DeploymentHygiene.describeProblem(new Class<?>[]{null}) != null);
        // The gate on a discovered verifier protects nothing if it runs after the code it judges, and
        // the ordering is invisible in the result: a candidate in a writable location yields null
        // whether it was refused before it ran or after it had already run. ServiceLoader.stream() plus
        // Provider#type() define a candidate without initialising it, where the older iterator()/next()
        // shape built the object -- so the check has to be pinned by observation, not by reading the
        // code and nodding. The probe leaves a marker the moment its class initialiser runs.
        Path probePrivate = Files.createTempDirectory(scratch, "probe-private-");
        Path probeWritable = Files.createTempDirectory(scratch, "probe-writable-");
        installProbe(probePrivate);
        installProbe(probeWritable);
        Files.setPosixFilePermissions(probeWritable, posix("rwxrwxrwx"));
        Path marker = scratch.resolve("probe-initialised.marker");
        System.setProperty("portal.probe.marker", marker.toString());
        try {
            // Positive control first, because the assertion that matters is an absence: if the probe
            // never loaded at all, "its code did not run" would pass for the wrong reason.
            Files.deleteIfExists(marker);
            SessionHandoffService.SessionStateVerifier accepted =
                    SessionStateVerifierProvider.load(probeLoader(probePrivate));
            ok("a verifier discovered from a private location is used", accepted != null);
            ok("and the probe's initialiser is observable when it does run", Files.exists(marker));
            Files.deleteIfExists(marker);
            SessionHandoffService.SessionStateVerifier refused =
                    SessionStateVerifierProvider.load(probeLoader(probeWritable));
            ok("a verifier discovered from a world-writable location is refused", refused == null);
            ok("and it is refused before any of its code has run", !Files.exists(marker));
        } finally {
            System.clearProperty("portal.probe.marker");
            Files.setPosixFilePermissions(probeWritable, posix("rwx------"));
        }
    }

    /** Puts a copy of the discovery probe, and the services entry naming it, into {@code dir}. */
    private static void installProbe(Path dir) throws Exception {
        Path target = dir.resolve("com/acme/portal/testapp/ProbeVerifier.class");
        Files.createDirectories(target.getParent());
        try (java.io.InputStream probe = ProbeVerifier.class.getResourceAsStream("ProbeVerifier.class")) {
            if (probe == null) {
                throw new IllegalStateException("the probe class file is not on the test classpath");
            }
            Files.copy(probe, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        Path services = dir.resolve("META-INF/services"
                + "/com.acme.portal.session.SessionHandoffService$SessionStateVerifier");
        Files.createDirectories(services.getParent());
        Files.write(services, "com.acme.portal.testapp.ProbeVerifier\n"
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    /**
     * A loader that takes the probe from {@code dir} instead of from the test classpath, so the class's
     * recorded code source is that directory and {@code DeploymentHygiene} judges the mode this test
     * set. Everything else, including the interface the probe implements, resolves through the parent.
     */
    private static ClassLoader probeLoader(Path dir) throws Exception {
        final java.net.URL dirUrl = dir.toUri().toURL();
        final Path classFile = dir.resolve("com/acme/portal/testapp/ProbeVerifier.class");
        return new java.net.URLClassLoader(new java.net.URL[]{dirUrl},
                ProbeVerifier.class.getClassLoader()) {
            private static final long serialVersionUID = 1L;

            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (!"com.acme.portal.testapp.ProbeVerifier".equals(name)) {
                    return super.loadClass(name, resolve);
                }
                Class<?> already = findLoadedClass(name);
                if (already != null) {
                    return already;
                }
                try {
                    byte[] bytes = Files.readAllBytes(classFile);
                    Class<?> defined = defineClass(name, bytes, 0, bytes.length,
                            new java.security.ProtectionDomain(
                                    new java.security.CodeSource(dirUrl,
                                            (java.security.cert.Certificate[]) null), null));
                    if (resolve) {
                        resolveClass(defined);
                    }
                    return defined;
                } catch (IOException cannotRead) {
                    throw new ClassNotFoundException(name, cannotRead);
                }
            }
        };
    }

    private static Set<java.nio.file.attribute.PosixFilePermission> posix(String bits) {
        Set<java.nio.file.attribute.PosixFilePermission> permissions =
                java.util.EnumSet.noneOf(java.nio.file.attribute.PosixFilePermission.class);
        String[] names = {"OWNER_READ", "OWNER_WRITE", "OWNER_EXECUTE", "GROUP_READ", "GROUP_WRITE",
                "GROUP_EXECUTE", "OTHERS_READ", "OTHERS_WRITE", "OTHERS_EXECUTE"};
        for (int i = 0; i < 9; i++) {
            if (bits.charAt(i) != '-') {
                permissions.add(java.nio.file.attribute.PosixFilePermission.valueOf(names[i]));
            }
        }
        return permissions;
    }

    // ------------------------------------------------------------------ timing

    private static void timing() {
        begin("TIMING: comparable work on every refusal, measured in microseconds");
        SessionCookiePolicy policy = SessionCookiePolicy.of(null, null, null);
        SessionHandoffServlet servlet = newSessionServlet(policy, new CountingVerifier(GOOD),
                new RequestAttributeAssertionSource("com.acme.test.assertedId"));
        SessionHandoffServlet unwired = unwiredServlet();

        // Warm every path so the JIT does not bias the first measurement.
        for (int i = 0; i < 400; i++) {
            measure(servlet, unwired, i % 5);
        }
        Map<String, Long> median = new LinkedHashMap<String, Long>();
        median.put("granted", measure(servlet, unwired, 0));
        median.put("no assertion", measure(servlet, unwired, 1));
        median.put("malformed assertion", measure(servlet, unwired, 2));
        median.put("unknown session", measure(servlet, unwired, 3));
        median.put("not serving", measure(servlet, unwired, 4));

        long slowest = 0;
        long fastest = Long.MAX_VALUE;
        for (Map.Entry<String, Long> sample : median.entrySet()) {
            System.out.println("      " + pad(sample.getKey()) + " p50=" + sample.getValue() + " us");
            slowest = Math.max(slowest, sample.getValue());
            fastest = Math.min(fastest, sample.getValue());
        }
        double spread = slowest / (double) Math.max(1L, fastest);
        System.out.println("      spread=" + String.format(Locale.ROOT, "%.2f", spread)
                + "x  equalizerCompressions=" + WorkEqualizer.compressions());

        long refusalFloor = Math.min(median.get("no assertion"),
                Math.min(median.get("malformed assertion"), median.get("unknown session")));
        long allFloor = Math.min(refusalFloor, Math.min(median.get("granted"), median.get("not serving")));

        // Calibrate the floor against the padding itself, measured in this run on this machine, rather
        // than against a hard-coded microsecond number. A fixed floor is machine-specific: it would
        // false-fail on hardware 20% faster (or after a JDK update) and tolerate padding that had
        // quietly shrunk on hardware 20% slower. Measuring the same call the servlet measures makes the
        // assertion hold wherever it runs: every outcome path must cost at least as much as the padding
        // alone, because that call is the only thing all five paths have in common.
        for (int i = 0; i < 2000; i++) {
            WorkEqualizer.apply();
        }
        long[] padSamples = new long[201];
        for (int i = 0; i < padSamples.length; i++) {
            long start = System.nanoTime();
            WorkEqualizer.apply();
            padSamples[i] = System.nanoTime() - start;
        }
        Arrays.sort(padSamples);
        long paddingAlone = padSamples[padSamples.length / 2] / 1000L;
        System.out.println("      padding alone          p50=" + paddingAlone + " us");

        ok("every outcome costs at least the padding it is supposed to do (floor "
                        + allFloor + " us vs padding " + paddingAlone + " us)",
                allFloor >= (long) (paddingAlone * 0.8d));
        // Absolute backstop, deliberately far below the measured cost (about 60 us at the shipped 160
        // compressions): it exists only to catch the padding being removed or reduced to a token
        // amount, not to pin a performance number to this machine.
        ok("the padding itself is still real work (>= 5 us)", paddingAlone >= 5L);
        // The other side of the same sizing argument. The padding is charged before every gate, so
        // whoever can grow it buys server time with a packet -- the mistake that made the store lookup
        // an amplifier in the first place. The count is a compile-time constant, so no request can grow
        // it; this bound is for the maintainer who answers a timing complaint by turning the padding up
        // until it is the most expensive thing a request does. Generous on purpose: a box under load
        // must not false-fail here, and 400 us is already seven times the shipped cost.
        ok("the padding has not become the cheapest denial-of-service lever (<= 400 us)",
                paddingAlone <= 400L);
        ok("all outcomes stay within 2x of each other", spread < 2.0d);
        ok("the availability refusal is padded too (it short-circuits before the others)",
                median.get("not serving") >= median.get("granted") * 0.5d);
        ok("a well-formed-but-unknown candidate is not cheaper than a malformed one",
                median.get("unknown session") >= median.get("malformed assertion") * 0.5d);
    }

    private static long measure(SessionHandoffServlet servlet, SessionHandoffServlet unwired, int path) {
        long[] samples = new long[201];
        for (int i = 0; i < samples.length; i++) {
            try {
                samples[i] = timeOnce(servlet, unwired, path);
            } catch (jakarta.servlet.ServletException | IOException shouldNotHappen) {
                failures++;
                FAILED.add("TIMING / unexpected " + shouldNotHappen.getClass().getName());
                samples[i] = Long.MAX_VALUE / 2;
            }
        }
        Arrays.sort(samples);
        return samples[samples.length / 2];
    }

    private static long timeOnce(SessionHandoffServlet servlet, SessionHandoffServlet unwired, int path)
            throws jakarta.servlet.ServletException, IOException {
        Recording response = Recording.create();
        String asserted;
        String address;
        SessionHandoffServlet target;
        switch (path) {
            case 0:
                asserted = GOOD;
                address = "203.0.113.1";
                target = servlet;
                break;
            case 1:
                asserted = null;
                address = "203.0.113.2";
                target = servlet;
                break;
            case 2:
                asserted = "junk";
                address = "203.0.113.3";
                target = servlet;
                break;
            case 3:
                asserted = GOOD + "Zz9";
                address = "203.0.113.4";
                target = servlet;
                break;
            default:
                asserted = GOOD;
                address = "203.0.113.5";
                target = unwired;
                break;
        }
        long start = System.nanoTime();
        target.doGet(FakeRequest.get(address, "com.acme.test.assertedId", asserted).proxy(),
                response.proxy());
        return (System.nanoTime() - start) / 1000L;
    }

    private static String pad(String text) {
        StringBuilder padded = new StringBuilder(text);
        while (padded.length() < 20) {
            padded.append(' ');
        }
        return padded.toString();
    }

    // ------------------------------------------------------------------ fakes

    /**
     * Counts SEVERE records published by one class's logger while it is attached. Used to tell a
     * refusal the component decided to make from a refusal that is really a swallowed server error:
     * both answer the same generic page, and only the log distinguishes them.
     */
    static final class LogCapture extends java.util.logging.Handler {
        private final java.util.logging.Logger target;
        private int severe;

        LogCapture(Class<?> owner) {
            target = java.util.logging.Logger.getLogger(owner.getName());
            target.addHandler(this);
        }

        @Override
        public void publish(java.util.logging.LogRecord record) {
            if (record != null && record.getLevel().intValue() >= java.util.logging.Level.SEVERE.intValue()) {
                synchronized (this) {
                    severe++;
                }
            }
        }

        synchronized int severeCount() {
            return severe;
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
            stop();
        }

        void stop() {
            target.removeHandler(this);
        }
    }

    static final class Recording {
        final List<Cookie> cookies = new ArrayList<Cookie>();
        final Map<String, String> headers = new LinkedHashMap<String, String>();
        final ByteArrayOutputStream bodyBytes = new ByteArrayOutputStream();
        final PrintWriter body = new PrintWriter(new java.io.OutputStreamWriter(bodyBytes,
                StandardCharsets.UTF_8));
        int status;
        int contentLength = -1;

        static Recording create() {
            return new Recording();
        }

        String header(String name) {
            return headers.get(name);
        }

        String body() {
            body.flush();
            try {
                return bodyBytes.toString("UTF-8");
            } catch (java.io.UnsupportedEncodingException impossible) {
                throw new IllegalStateException(impossible);
            }
        }

        HttpServletResponse proxy() {
            return (HttpServletResponse) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[]{HttpServletResponse.class}, new Handler(this));
        }

        private static final class Handler implements InvocationHandler {
            private final Recording owner;

            Handler(Recording owner) {
                this.owner = owner;
            }

            @Override
            public Object invoke(Object proxy, Method method, Object[] args) {
                String name = method.getName();
                if ("addCookie".equals(name)) {
                    owner.cookies.add((Cookie) args[0]);
                } else if ("setHeader".equals(name) || "setIntHeader".equals(name)) {
                    owner.headers.put((String) args[0], String.valueOf(args[1]));
                } else if ("setStatus".equals(name)) {
                    owner.status = ((Integer) args[0]).intValue();
                } else if ("setContentLengthLong".equals(name)) {
                    owner.contentLength = ((Long) args[0]).intValue();
                } else if ("setContentLength".equals(name)) {
                    owner.contentLength = ((Integer) args[0]).intValue();
                    owner.headers.put("Content-Length", String.valueOf(args[0]));
                } else if ("getWriter".equals(name)) {
                    return owner.body;
                } else if ("flushBuffer".equals(name)
                        || "setCharacterEncoding".equals(name) || "setBufferSize".equals(name)
                        || "containsHeader".equals(name)) {
                    // accepted, nothing to record
                } else if ("setContentType".equals(name)) {
                    // Recorded: a HEAD response that advertises a length must say what it is the
                    // length of, and the only way to assert that is to look at what was set.
                    owner.headers.put("Content-Type", String.valueOf(args[0]));
                } else if ("getContentType".equals(name) || "getCharacterEncoding".equals(name)) {
                    return null;
                } else if ("getBufferSize".equals(name)) {
                    return Integer.valueOf(8192);
                } else if ("isCommitted".equals(name)) {
                    return Boolean.FALSE;
                } else if ("toString".equals(name)) {
                    return "Recording";
                } else if ("hashCode".equals(name)) {
                    return Integer.valueOf(System.identityHashCode(proxy));
                } else if ("equals".equals(name)) {
                    return Boolean.valueOf(proxy == args[0]);
                }
                return method.getReturnType().isPrimitive() && !"void".equals(method.getName())
                        ? defaultValue(method) : null;
            }

            private Object defaultValue(Method method) {
                Class<?> type = method.getReturnType();
                if (type == boolean.class) {
                    return Boolean.FALSE;
                }
                if (type == int.class) {
                    return Integer.valueOf(0);
                }
                if (type == long.class) {
                    return Long.valueOf(0L);
                }
                return null;
            }
        }
    }

    static final class FakeRequest {
        String method = "GET";
        String remoteAddr = "203.0.113.1";
        final Map<String, String> headers = new LinkedHashMap<String, String>();
        final Map<String, Object> attributes = new LinkedHashMap<String, Object>();
        Cookie[] cookies;

        static FakeRequest get(String remoteAddr, String attributeName, String assertedValue) {
            FakeRequest request = new FakeRequest();
            request.remoteAddr = remoteAddr;
            request.attributes.put("host", "portal.example");
            if (attributeName != null) {
                request.attributes.put(attributeName, assertedValue);
            }
            return request;
        }

        HttpServletRequest proxy() {
            return (HttpServletRequest) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[]{HttpServletRequest.class}, new InvocationHandler() {
                        @Override
                        public Object invoke(Object proxy, Method invoked, Object[] args) {
                            String name = invoked.getName();
                            if ("getRemoteAddr".equals(name)) {
                                return remoteAddr;
                            }
                            if ("getMethod".equals(name)) {
                                return method;
                            }
                            if ("getHeader".equals(name)) {
                                return headers.get((String) args[0]);
                            }
                            if ("getCookies".equals(name)) {
                                return cookies;
                            }
                            if ("getAttribute".equals(name)) {
                                return attributes.get((String) args[0]);
                            }
                            if ("getRequestURI".equals(name)) {
                                return "/portal/login";
                            }
                            if ("getProtocol".equals(name)) {
                                return "HTTP/1.1";
                            }
                            if ("isSecure".equals(name)) {
                                return Boolean.TRUE;
                            }
                            if ("toString".equals(name)) {
                                return "FakeRequest";
                            }
                            if ("hashCode".equals(name)) {
                                return Integer.valueOf(System.identityHashCode(proxy));
                            }
                            if ("equals".equals(name)) {
                                return Boolean.valueOf(proxy == args[0]);
                            }
                            Class<?> type = invoked.getReturnType();
                            if (type == boolean.class) {
                                return Boolean.FALSE;
                            }
                            if (type == int.class) {
                                return Integer.valueOf(0);
                            }
                            if (type == long.class) {
                                return Long.valueOf(0L);
                            }
                            if (type == String[].class) {
                                return new String[0];
                            }
                            return null;
                        }
                    });
        }
    }

    static final class CountingVerifier implements SessionHandoffService.SessionStateVerifier {
        private final Set<String> live = new java.util.HashSet<String>();
        int calls;

        CountingVerifier(String... ids) {
            live.addAll(Arrays.asList(ids));
        }

        @Override
        public boolean isSessionValid(String sessionId) {
            calls++;
            return sessionId != null && live.contains(sessionId);
        }
    }

    static final class MutableClock implements AttemptLimiter.Clock {
        private long now;

        MutableClock(long start) {
            now = start;
        }

        @Override
        public long millis() {
            return now;
        }

        synchronized void advance(long delta) {
            now += delta;
        }
    }

    private static String repeat(char c, int times) {
        char[] buffer = new char[times];
        Arrays.fill(buffer, c);
        return new String(buffer);
    }

    private static void deleteRecursively(java.io.File file) {
        if (!file.exists()) {
            return;
        }
        java.io.File[] children = file.listFiles();
        if (children != null) {
            for (java.io.File child : children) {
                deleteRecursively(child);
            }
        }
        file.delete();
    }

    private Harness() {
    }
}
