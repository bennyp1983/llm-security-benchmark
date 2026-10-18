package com.portal.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What the network can see.
 *
 * <p>The decisive property is not that refusals are correct but that they are
 * <em>indistinguishable</em>: wrong password, unknown account, malformed field, spent
 * budget, bad CSRF token, oversized body and unparsable form must produce byte-identical
 * responses, because a response that differs in <em>any</em> observable way -- status, body
 * bytes, header names, a {@code Set-Cookie} that only one branch remembered -- is an
 * account-enumeration oracle no matter what the body says. So the tests below capture whole
 * responses and compare them for equality rather than checking each one against a
 * description of what it should look like.
 *
 * <p>Driven through {@link HttpExchangeView} so the assertions are about the handler's
 * decisions rather than about a socket, and so a hostile request can be replayed exactly.
 */
public final class HttpSuite {

    private static final String FORM = "application/x-www-form-urlencoded";
    private static final String PEER = "203.0.113.7";

    public static void main(String[] args) {
        shapeOfEveryDenial();
        routing();
        formParsing();
        csrfAtTheBoundary();
        sessionLifecycle();
        cookieShape();
        headerHardening();
        attributionOverHttp();
        System.exit(TestKit.report("http"));
    }

    // ---------------------------------------------------------------------- fixtures

    /** Records exactly what the handler asked the transport to send. */
    private static final class Exchange implements HttpExchangeView {
        private final String method;
        private final String path;
        private final Map<String, String> headers;
        private final byte[] body;
        private final String peer;

        int status = -1;
        byte[] responseBody;
        List<String> responseHeaders;
        int askedForBodyBytes = -1;

        Exchange(String method, String path, Map<String, String> headers, String body,
                 String peer) {
            this.method = method;
            this.path = path;
            this.headers = headers;
            this.body = body == null ? null : body.getBytes(StandardCharsets.UTF_8);
            this.peer = peer;
        }

        @Override
        public String method() {
            return method;
        }

        @Override
        public String rawPath() {
            return path;
        }

        @Override
        public String header(String name) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name)) {
                    return e.getValue();
                }
            }
            return null;
        }

        @Override
        public List<String> headers(String name) {
            List<String> out = new ArrayList<>();
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name)) {
                    out.add(e.getValue());
                }
            }
            return out;
        }

        @Override
        public byte[] readBodyBounded(int maxBytes) {
            askedForBodyBytes = maxBytes;
            if (body == null) {
                return HttpExchangeView.EMPTY;
            }
            // Faithful to the contract: never more than maxBytes + 1, so the caller can
            // tell "exactly at the cap" from "over it".
            int take = Math.min(body.length, maxBytes + 1);
            return Arrays.copyOf(body, take);
        }

        @Override
        public String peerAddress() {
            return peer;
        }

        @Override
        public void respond(int code, byte[] out, List<String> setCookies) {
            this.status = code;
            this.responseBody = out;
            this.responseHeaders = new ArrayList<>(setCookies);
        }

        String bodyText() {
            return responseBody == null ? "" : new String(responseBody, StandardCharsets.UTF_8);
        }

        /** The whole observable reply, as one string, for cross-cell equality. */
        String signature() {
            return status + "\n" + bodyText() + "\n" + String.join("\n", responseHeaders);
        }

        List<String> headerNames() {
            List<String> names = new ArrayList<>();
            for (String h : responseHeaders) {
                String name = h.substring(0, h.indexOf(':')).toLowerCase(java.util.Locale.ROOT);
                // Cookies and the redirect target are the legitimate per-outcome part of a
                // response. The security header block is the part that must never vary, so
                // that is what the cross-cell comparisons below compare.
                if (name.equals("set-cookie") || name.equals("location")) {
                    continue;
                }
                names.add(name);
            }
            java.util.Collections.sort(names);
            return names;
        }

        List<String> setCookies() {
            List<String> out = new ArrayList<>();
            for (String h : responseHeaders) {
                if (h.toLowerCase(java.util.Locale.ROOT).startsWith("set-cookie")) {
                    out.add(h);
                }
            }
            return out;
        }
    }

    private static final class Site {
        final Path dir;
        final AuditLog audit;
        final Ledger ledger;
        final EmployeeStore store;
        final SessionManager sessions;
        final ThrottleManager throttle;
        final PortalRuntime runtime;
        final PortalServer server;

        Site(String label, String trustedProxies) throws IOException {
            dir = TestKit.scratchDir(label);
            audit = new AuditLog(dir.resolve("audit.log"));
            PasswordHasher hasher = new PasswordHasher(TestKit.FAST_ITERATIONS);
            store = new EmployeeStore(dir.resolve("employees.dat"), hasher, audit);
            store.initialiseEmpty();
            ledger = new Ledger(dir.resolve("throttle.log"));
            throttle = new ThrottleManager(ledger);
            sessions = new SessionManager();
            Authenticator auth = new Authenticator(store, hasher, throttle, sessions, audit);
            runtime = new PortalRuntime(store, throttle, sessions, auth, audit);
            PortalConfig config = new PortalConfig(dir, TestKit.FAST_ITERATIONS, "127.0.0.1",
                    8443, null, null, trustedProxies, 31_536_000L);
            server = new PortalServer(runtime, config);
        }

        void add(String user, String pw) {
            TestKit.eq("fixture " + user, EmployeeStore.CreateResult.CREATED,
                    store.create(user, pw.toCharArray()));
        }

        Exchange ask(Exchange ex) {
            server.handle(ex);
            return ex;
        }

        Exchange get(String path) {
            return ask(new Exchange("GET", path, Map.of(), null, PEER));
        }

        Exchange post(String path, String body, String contentType, String cookieHeader) {
            Map<String, String> h = new LinkedHashMap<>();
            if (contentType != null) {
                h.put("Content-Type", contentType);
            }
            if (cookieHeader != null) {
                h.put("Cookie", cookieHeader);
            }
            return ask(new Exchange("POST", path, h, body, PEER));
        }

        /** Fetch the login page and pull the CSRF pair out of it, as a browser would. */
        String freshCsrf() {
            Exchange page = get("/login");
            return PortalServer.csrfTokenFrom(page.bodyText());
        }

        String form(String user, String pass, String csrf) {
            return "username=" + user + "&password=" + pass + "&csrf=" + csrf;
        }

        Exchange loginForm(String user, String pass, String csrf, String csrfCookie) {
            return post("/login", form(user, pass, csrf), FORM,
                    csrfCookie == null ? null : PortalServer.CSRF_COOKIE + "=" + csrfCookie);
        }

        Exchange login(String user, String pass) {
            String token = freshCsrf();
            return loginForm(user, pass, token, token);
        }

        void reset(String user, String source) {
            throttle.clearAccountForTesting(Crypto.idRef(user));
            throttle.clearAccountForTesting(SourceRef.ref(source));
        }
    }

    // ---------------------------------------------------- one byte-identical denial

    private static void shapeOfEveryDenial() {
        try {
            Site site = new Site("http-denial", "");
            site.add("alice", TestKit.PW_ALICE);
            String token = site.freshCsrf();

            Map<String, Exchange> cells = new LinkedHashMap<>();
            cells.put("wrong-password", site.loginForm("alice", "Wrong-Passw0rd-9!", token, token));
            site.reset("alice", PEER);
            String t2 = site.freshCsrf();
            cells.put("unknown-account", site.loginForm("no-such-user", TestKit.PW_WRONG, t2, t2));
            site.reset("no-such-user", PEER);
            String t3 = site.freshCsrf();
            cells.put("malformed-name", site.loginForm("bad name!", TestKit.PW_WRONG, t3, t3));
            String t4 = site.freshCsrf();
            cells.put("malformed-secret", site.loginForm("alice", "x", t4, t4));
            String t5 = site.freshCsrf();
            cells.put("oversized-secret",
                    site.loginForm("alice", "z".repeat(300), t5, t5));
            String t6 = site.freshCsrf();
            cells.put("bad-csrf-pair", site.loginForm("alice", TestKit.PW_ALICE, t6,
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
            site.reset("alice", PEER);
            String t7 = site.freshCsrf();
            cells.put("csrf-cookie-missing", site.loginForm("alice", TestKit.PW_ALICE, t7, null));
            site.reset("alice", PEER);
            String t8 = site.freshCsrf();
            cells.put("csrf-field-missing",
                    site.post("/login", "username=alice&password=" + TestKit.PW_ALICE
                            + "&other=" + t8, FORM, PortalServer.CSRF_COOKIE + "=" + t8));
            site.reset("alice", PEER);
            cells.put("unknown-form-key", site.post("/login",
                    "username=alice&password=" + TestKit.PW_ALICE + "&csrf=" + site.freshCsrf()
                            + "&admin=yes", FORM, null));
            cells.put("duplicate-form-key", site.post("/login",
                    "username=alice&username=bob&password=" + TestKit.PW_ALICE + "&csrf="
                            + site.freshCsrf(), FORM, null));
            cells.put("empty-body", site.post("/login", "", FORM, null));
            cells.put("oversized-body", site.post("/login",
                    "username=alice&password=" + "y".repeat(9000) + "&csrf=" + site.freshCsrf(),
                    FORM, null));
            cells.put("malformed-percent", site.post("/login",
                    "username=ali%00ce&password=" + TestKit.PW_ALICE + "&csrf="
                            + site.freshCsrf(), FORM, null));
            cells.put("truncated-escape", site.post("/login",
                    "username=alic%e&password=" + TestKit.PW_ALICE + "&csrf=" + site.freshCsrf(),
                    FORM, null));
            cells.put("no-session-logout", site.post("/logout",
                    "csrf=" + site.freshCsrf(), FORM, null));
            cells.put("forged-session-logout", site.post("/logout", "csrf=" + site.freshCsrf(),
                    FORM, PortalServer.SESSION_COOKIE + "="
                            + Crypto.randomUrlToken(InputPolicy.SESSION_TOKEN_BYTES)));

            String reference = null;
            String referenceName = null;
            for (Map.Entry<String, Exchange> e : cells.entrySet()) {
                Exchange ex = e.getValue();
                String route = e.getKey();
                // Routing refusals that happen before the body is examined are a different
                // (pre-authentication, caller-independent) family and asserted in routing().
                if (ex.status == 404 || ex.status == 405 || ex.status == 415) {
                    TestKit.ok(route + ": expected a 401 family answer but got " + ex.status,
                            false);
                    continue;
                }
                TestKit.eq(route + " is a 401", 401, ex.status);
                TestKit.eq(route + " body", PortalServer.DENIED_BODY, ex.bodyText());
                TestKit.ok(route + " sets no cookie at all", ex.setCookies().isEmpty());
                if (reference == null) {
                    reference = ex.signature();
                    referenceName = route;
                } else {
                    TestKit.eq(route + " is byte-identical to " + referenceName,
                            reference, ex.signature());
                }
            }
            TestKit.ok("the reference cell exists", reference != null);
            TestKit.ok("every cell was compared (" + cells.size() + ")", cells.size() >= 16);

            // And the secrets must not appear anywhere in what was sent back.
            for (Exchange ex : cells.values()) {
                String all = ex.bodyText() + String.join("|", ex.responseHeaders);
                TestKit.ok("no password in the reply", !all.contains(TestKit.PW_ALICE)
                        && !all.contains(TestKit.PW_WRONG));
                TestKit.ok("no csrf token echoed", !all.contains("csrf="));
            }
        } catch (IOException broken) {
            TestKit.ok("fixture: " + broken, false);
        }
    }

    // ------------------------------------------------------------------------ routing

    private static void routing() {
        try {
            Site site = new Site("http-route", "");
            site.add("alice", TestKit.PW_ALICE);
            for (String m : List.of("PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE",
                    "CONNECT", "get", "Post", "post", "", "NOTAMETHOD")) {
                Exchange ex = site.ask(new Exchange(m, "/login", Map.of(), "x=1", PEER));
                TestKit.eq("method [" + TestKit.show(m) + "] is 405", 405, ex.status);
                TestKit.ok("method [" + TestKit.show(m) + "] has no body",
                        ex.responseBody.length == 0);
            }
            for (String p : List.of("/login/", "/Login", "/LOGIN", "//login", "/login?x=1",
                    "/logout/", "/", "/admin", "/..%2f..%2fetc/passwd", "/session", "")) {
                TestKit.eq("GET " + TestKit.show(p) + " is 404", 404, site.get(p).status);
                Exchange ex = site.post(p, "username=alice&password=x&csrf=y", FORM, null);
                TestKit.eq("POST " + TestKit.show(p) + " is 404 (no auth attempted)", 404,
                        ex.status);
            }
            TestKit.eq("GET /login is the page", 200, site.get("/login").status);

            // Content type is checked before the body, so it cannot be an enumeration
            // channel: the answer does not depend on the credentials at all.
            for (String ct : List.of("text/plain", "application/json", "",
                    "multipart/form-data", "application/x-www-form-urlencodedx",
                    "application/x-form-urlencoded", "application/x-www-form-urlencoded;",
                    "x-application/x-www-form-urlencoded", "application/x-www-form-urlencode")) {
                Exchange ex = site.post("/login", "username=alice&password=x&csrf=y", ct, null);
                if (ct.equals("application/x-www-form-urlencoded;")) {
                    // The media type is what is compared, and it is complete here -- only an
                    // empty parameter follows. Refusing it would be a surprising 415.
                    TestKit.eq("a bare trailing semicolon still parses as the form type", 401,
                            ex.status);
                    continue;
                }
                TestKit.eq("content type [" + TestKit.show(ct) + "] is 415", 415, ex.status);
                TestKit.ok("content type [" + TestKit.show(ct) + "] has no body",
                        ex.responseBody.length == 0);
            }
            for (String ct : List.of("APPLICATION/X-WWW-FORM-URLENCODED",
                    "Application/X-Www-Form-Urlencoded")) {
                TestKit.eq("media type is case-insensitive [" + ct + "]", 401,
                        site.post("/login", "username=alice&password=x&csrf=y", ct, null).status);
            }
            for (String ct : List.of(FORM + "; charset=utf-8", FORM + ";charset=utf-8",
                    FORM + "; charset=UTF-8")) {
                Exchange ex = site.post("/login",
                        "username=alice&password=" + TestKit.PW_WRONG + "&csrf="
                                + site.freshCsrf(), ct, null);
                TestKit.eq("a charset parameter is accepted [" + ct + "]", 401, ex.status);
                TestKit.eq("and the wrong password still denies", "Access denied.",
                        ex.bodyText());
            }

            // 405/404/415 must be uniform within their family too: they leak only routing.
            Exchange a = site.ask(new Exchange("PUT", "/login", Map.of(), "x=1", PEER));
            Exchange b = site.ask(new Exchange("DELETE", "/admin", Map.of(), null, "1.2.3.4"));
            TestKit.eq("405 shape does not depend on path or caller", a.signature(),
                    b.signature());
            Exchange c = site.get("/nope");
            Exchange d = site.get("/login/../x");
            TestKit.eq("404 shape does not depend on the path", c.signature(), d.signature());
            // Null method and null path must be refused, never treated as "unspecified, so
            // allow" -- the route is an allowlist compared against literals.
            Exchange nullMethod = site.ask(new Exchange(null, "/login",
                    Map.of("Content-Type", FORM), "username=alice", PEER));
            TestKit.eq("a null method is 405", 405, nullMethod.status);
            Exchange nullPath = site.ask(new Exchange("POST", null,
                    Map.of("Content-Type", FORM), "username=alice", PEER));
            TestKit.eq("a null path is 404 and never reaches authentication", 404,
                    nullPath.status);
            TestKit.eq("no body is read for a null path", -1, nullPath.askedForBodyBytes);
        } catch (IOException broken) {
            TestKit.ok("fixture: " + broken, false);
        }
    }

    // ------------------------------------------------------------------ form parsing

    private static void formParsing() {
        TestKit.ok("a well-formed triple parses",
                PortalServer.FormFields.parse("username=alice&password=Secret-1a!x&csrf=abc")
                        != null);
        String[] hostile = {
                "", "&", "username", "username=", "=alice", "&username=alice",
                "username=alice&", "username=alice&&password=x", "username=alice&password",
                "admin=1", "username=alice&password=x",
                "username=alice&username=bob&password=x&csrf=y",
                "username=alice&password=x&csrf=y&csrf=z",
                "username=ali%00ce&password=x&csrf=y",
                "username=alic%e&password=x&csrf=y",
                "username=ali%ce&password=x&csrf=y",
                "username=alice&password=a%20b&csrf=y",
                "username=alice&password=a%0ab&csrf=y",
                "username=alice&password=a%FFb&csrf=y",
                "username=alice&password=" + "z".repeat(513) + "&csrf=y",
                "username=alice&password=x&csrf=y&%61dmin=1",
                "username=al\u00e9ce&password=x&csrf=y",
                "username=alice&password=x&csrf=y ",
        };
        for (String body : hostile) {
            TestKit.ok("refused [" + TestKit.show(body) + "]",
                    PortalServer.FormFields.parse(body) == null);
        }

        // A CSRF-only body is well-formed (it is what POST /logout sends) but must still be
        // refused end to end on the login route, which requires both credential fields. The
        // parse succeeding is not the security boundary -- the route's own requirement is.
        for (String csrfOnly : List.of("username=alice&csrf=x", "password=x&csrf=x",
                "csrf=x")) {
            TestKit.ok("parses as a form [" + TestKit.show(csrfOnly) + "]",
                    PortalServer.FormFields.parse(csrfOnly) != null);
        }
        try {
            Site site = new Site("http-fields", "");
            site.add("alice", TestKit.PW_ALICE);
            for (String csrfOnly : List.of("username=alice&csrf=TOKEN",
                    "password=" + TestKit.PW_ALICE + "&csrf=TOKEN", "csrf=TOKEN")) {
                String tok = site.freshCsrf();
                Exchange ex = site.post("/login", csrfOnly.replace("TOKEN", tok), FORM,
                        PortalServer.CSRF_COOKIE + "=" + tok);
                TestKit.eq("login route refuses a form without both credentials ["
                        + TestKit.show(csrfOnly) + "]", 401, ex.status);
                TestKit.eq("with the generic denial", PortalServer.DENIED_BODY, ex.bodyText());
                site.reset("alice", PEER);
            }
            TestKit.ok("and the missing-credential abuse is charged to the source",
                    site.throttle.failureCountForSource(SourceRef.ref(PEER)) >= 3);
        } catch (IOException broken) {
            TestKit.ok("fixture: " + broken, false);
        }
        // An encoded key that decodes onto an allowed name is still checked against the
        // allowlist after decoding, so this one parses -- pinning that decode-then-check
        // order matters (a check-then-decode order would let %61dmin through).
        TestKit.ok("an encoded key that decodes to an allowed name is accepted",
                PortalServer.FormFields.parse("%75sername=alice&password=x&csrf=y") != null);
        TestKit.ok("an encoded key that decodes to a disallowed name is refused",
                PortalServer.FormFields.parse("%61dmin=alice&password=x&csrf=y") == null);

        // Values are NOT plus-decoded, so a literal '+' in a password survives; the wire
        // form of a literal '%' is %25 and must round-trip.
        PortalServer.FormFields plus =
                PortalServer.FormFields.parse("username=alice&password=a+b&csrf=y");
        TestKit.ok("a literal plus in a value stays a plus",
                plus != null && new String(plus.asciiBytes("password"),
                        StandardCharsets.US_ASCII).equals("a+b"));
        PortalServer.FormFields pct =
                PortalServer.FormFields.parse("username=alice&password=a%2541b&csrf=y");
        TestKit.ok("%25 decodes to one percent sign",
                pct != null && new String(pct.asciiBytes("password"),
                        StandardCharsets.US_ASCII).equals("a%41b"));
        PortalServer.FormFields space =
                PortalServer.FormFields.parse("username=al%20ice&password=x&csrf=y");
        TestKit.ok("a decoded space in a value is refused, never substituted", space == null);

        try {
            Site site = new Site("http-plus", "");
            site.add("plususer", "Plus-Sign-9!x+y");
            TestKit.ok("a password containing a literal + signs in",
                    site.login("plususer", "Plus-Sign-9!x+y").status == 303);
            site.reset("plususer", PEER);
            String tok = site.freshCsrf();
            TestKit.ok("and the %2B wire form of it signs in identically",
                    site.loginForm("plususer", "Plus-Sign-9!x%2By", tok, tok).status == 303);
        } catch (IOException broken) {
            TestKit.ok("fixture: " + broken, false);
        }
    }

    // -------------------------------------------------------------------------- CSRF

    private static void csrfAtTheBoundary() {
        try {
            Site site = new Site("http-csrf", "");
            site.add("alice", TestKit.PW_ALICE);
            String token = site.freshCsrf();
            TestKit.ok("the page carries a well-formed token",
                InputPolicy.isCsrfToken(token));

            TestKit.eq("no cookie half", 401,
                    site.post("/login", site.form("alice", TestKit.PW_ALICE, token), FORM,
                            null).status);
            site.reset("alice", PEER);
            String t2 = site.freshCsrf();
            TestKit.eq("no field half", 401,
                    site.post("/login", "username=alice&password=" + TestKit.PW_ALICE, FORM,
                            PortalServer.CSRF_COOKIE + "=" + t2).status);
            site.reset("alice", PEER);
            String t3 = site.freshCsrf();
            TestKit.eq("halves that differ", 401,
                    site.loginForm("alice", TestKit.PW_ALICE, t3, "B".repeat(32)).status);
            site.reset("alice", PEER);

            String t4 = site.freshCsrf();
            TestKit.eq("a token we never issued", 401,
                    site.loginForm("alice", TestKit.PW_ALICE,
                            Crypto.randomUrlToken(InputPolicy.CSRF_TOKEN_BYTES),
                            Crypto.randomUrlToken(InputPolicy.CSRF_TOKEN_BYTES)).status);
            site.reset("alice", PEER);

            // Single use: the first correct submission succeeds, a replay of the same pair
            // cannot succeed even with the right credentials.
            String t5 = site.freshCsrf();
            TestKit.eq("first use succeeds", 303,
                    site.loginForm("alice", TestKit.PW_ALICE, t5, t5).status);
            site.reset("alice", PEER);
            TestKit.eq("replaying the same pair is refused", 401,
                    site.loginForm("alice", TestKit.PW_ALICE, t5, t5).status);
            site.reset("alice", PEER);

            // A cookie planted by the attacker is not a pair: the field half must also match
            // something we issued.
            String planted = Crypto.randomUrlToken(InputPolicy.CSRF_TOKEN_BYTES);
            TestKit.eq("an attacker-planted matching pair", 401,
                    site.loginForm("alice", TestKit.PW_ALICE, planted, planted).status);
            site.reset("alice", PEER);

            // A real browser never fails this check, so a failure is an automated client and
            // is charged to the source budget: repeated attempts must eventually cost the
            // attacker their own address rather than the account's availability.
            for (int i = 0; i < ThrottleManager.SOURCE_MAX_FAILURES; i++) {
                site.post("/login", "username=alice&password=x&csrf=" + planted, FORM, null);
            }
            TestKit.ok("the source is now blocked",
                    site.throttle.isSourceBlocked(SourceRef.ref(PEER)));
            String t6 = site.freshCsrf();
            TestKit.eq("so even a correct login from it is refused", 401,
                    site.loginForm("alice", TestKit.PW_ALICE, t6, t6).status);
        } catch (IOException broken) {
            TestKit.ok("fixture: " + broken, false);
        }
    }

    // ------------------------------------------------------------- session lifecycle

    private static void sessionLifecycle() {
        try {
            Site site = new Site("http-session", "");
            site.add("alice", TestKit.PW_ALICE);
            Exchange ok = site.login("alice", TestKit.PW_ALICE);
            TestKit.eq("correct credentials redirect", 303, ok.status);
            TestKit.ok("redirect to /login", ok.responseHeaders.contains("Location: /login"));
            TestKit.ok("no body on the redirect", ok.responseBody.length == 0);
            List<String> cookies = ok.setCookies();
            TestKit.eq("session and cleared csrf cookies", 2, cookies.size());
            String session = valueOf(cookies, PortalServer.SESSION_COOKIE);
            TestKit.ok("session id well-formed", InputPolicy.isSessionToken(session));
            TestKit.ok("csrf cookie is cleared",
                    valueOf(cookies, PortalServer.CSRF_COOKIE).isEmpty());
            TestKit.ok("the session resolves server-side", site.sessions.find(session)
                    .isPresent());

            // The session id is only a lookup key: logging out with it must work once.
            String csrfForLogout = site.freshCsrf();
            Exchange out = site.post("/logout", "csrf=" + csrfForLogout, FORM,
                    PortalServer.SESSION_COOKIE + "=" + session + "; "
                            + PortalServer.CSRF_COOKIE + "=" + csrfForLogout);
            TestKit.eq("logout with a live session", 200, out.status);
            TestKit.eq("says signed out", PortalServer.SIGNED_OUT_BODY, out.bodyText());
            TestKit.ok("session state deleted", site.sessions.find(session).isEmpty());
            TestKit.ok("clears the session cookie",
                    valueOf(out.setCookies(), PortalServer.SESSION_COOKIE).isEmpty());

            TestKit.eq("a second logout is the generic denial", 401,
                    site.post("/logout", "csrf=" + site.freshCsrf(), FORM,
                            PortalServer.SESSION_COOKIE + "=" + session).status);

            // Truncated / altered session cookies grant nothing, and the answer is the same
            // denial as any other unauthenticated request.
            String[] forged = {session.substring(0, 42), session + "A",
                    Crypto.randomUrlToken(InputPolicy.SESSION_TOKEN_BYTES),
                    PortalServer.SESSION_COOKIE, "null", flipLast(session), ""};
            for (String f : forged) {
                Exchange ex = site.post("/logout", "csrf=" + site.freshCsrf(), FORM,
                        PortalServer.SESSION_COOKIE + "=" + f);
                TestKit.eq("forged session [" + TestKit.show(f) + "] gets the denial", 401,
                        ex.status);
                TestKit.eq("forged session body", PortalServer.DENIED_BODY, ex.bodyText());
            }

            // A session id is only a lookup key, and only ever resolves to the identity the
            // server bound to it. Over HTTP the same id must stop resolving once the server
            // expires it, which is what bounds the damage of a cookie stolen from a browser.
            java.time.Instant issuedAt = AuditClock.instant();
            Exchange again = site.login("alice", TestKit.PW_ALICE);
            String stolen = again.status == 303
                    ? valueOf(again.setCookies(), PortalServer.SESSION_COOKIE) : null;
            TestKit.ok("re-issued", stolen != null && InputPolicy.isSessionToken(stolen));
            TestKit.ok("it works while live", site.sessions.find(stolen).isPresent());
            TestKit.fixedClockAt(issuedAt.plusSeconds(
                    SessionManager.IDLE_TIMEOUT.getSeconds() + 60));
            TestKit.eq("an idle session gets the same denial as a made-up one", 401,
                    site.post("/logout", "csrf=" + site.freshCsrf(), FORM,
                            PortalServer.SESSION_COOKIE + "=" + stolen).status);
            TestKit.ok("and it is really gone server-side", site.sessions.find(stolen).isEmpty());
            TestKit.systemClock();
        } catch (IOException broken) {
            TestKit.ok("fixture: " + broken, false);
        }
    }

    private static void cookieShape() {
        try {
            Site site = new Site("http-cookie", "");
            site.add("alice", TestKit.PW_ALICE);
            Exchange ok = site.login("alice", TestKit.PW_ALICE);
            for (String c : ok.setCookies()) {
                String lower = c.toLowerCase(java.util.Locale.ROOT);
                TestKit.ok("HttpOnly on [" + TestKit.show(c) + "]", lower.contains("httponly"));
                TestKit.ok("Secure on [" + TestKit.show(c) + "]", lower.contains("secure"));
                TestKit.ok("SameSite=Strict on [" + TestKit.show(c) + "]",
                        lower.contains("samesite=strict"));
                TestKit.ok("Path=/ on [" + TestKit.show(c) + "]", lower.contains("path=/"));
                TestKit.ok("Max-Age on [" + TestKit.show(c) + "]", lower.contains("max-age="));
                TestKit.ok("no Domain attribute (host-only cookie)", !lower.contains("domain="));
            }
            String session = valueOf(ok.setCookies(), PortalServer.SESSION_COOKIE);
            TestKit.ok("the session cookie is not the username", !session.contains("alice"));
            TestKit.ok("the session cookie is not a digest of the username",
                    !session.contains(Crypto.idRef("alice")));

            Exchange page = site.get("/login");
            String csrf = valueOf(page.setCookies(), PortalServer.CSRF_COOKIE);
            TestKit.ok("the page sets exactly one cookie", page.setCookies().size() == 1);
            TestKit.ok("csrf cookie value matches the hidden field",
                    csrf.equals(PortalServer.csrfTokenFrom(page.bodyText())));
            TestKit.eq("no session cookie before authenticating", null,
                    valueOf(page.setCookies(), PortalServer.SESSION_COOKIE));

            // The token is HTML-escaped on the way into the page even though the generator
            // cannot produce a character that needs it -- the escaping must not be removed.
            TestKit.ok("no raw angle bracket in the token area", !csrf.contains("<"));

            // Every login page is a fresh token; two pages must not share one.
            String first = site.freshCsrf();
            String second = site.freshCsrf();
            TestKit.ok("distinct tokens per page", !first.equals(second));
        } catch (IOException broken) {
            TestKit.ok("fixture: " + broken, false);
        }
    }

    private static void headerHardening() {
        try {
            Site site = new Site("http-header", "");
            site.add("alice", TestKit.PW_ALICE);
            Map<String, Exchange> responses = new LinkedHashMap<>();
            responses.put("page", site.get("/login"));
            responses.put("404", site.get("/nope"));
            responses.put("405", site.ask(new Exchange("PUT", "/login", Map.of(), "a=1", PEER)));
            responses.put("415", site.post("/login", "a=1", "text/plain", null));
            responses.put("401", site.login("alice", TestKit.PW_WRONG));
            site.reset("alice", PEER);
            responses.put("303", site.login("alice", TestKit.PW_ALICE));

            for (Map.Entry<String, Exchange> e : responses.entrySet()) {
                List<String> names = e.getValue().headerNames();
                TestKit.ok(e.getKey() + " sends cache-control no-store",
                        e.getValue().responseHeaders.contains("Cache-Control: no-store"));
                TestKit.ok(e.getKey() + " sends nosniff",
                        e.getValue().responseHeaders.contains("X-Content-Type-Options: nosniff"));
                TestKit.ok(e.getKey() + " frames denied",
                        e.getValue().responseHeaders.contains("X-Frame-Options: DENY"));
                TestKit.ok(e.getKey() + " no referrer",
                        e.getValue().responseHeaders.contains("Referrer-Policy: no-referrer"));
                TestKit.ok(e.getKey() + " has a CSP that allows no script",
                        e.getValue().responseHeaders.stream().anyMatch(h -> h.startsWith(
                                "Content-Security-Policy:") && h.contains("script-src 'none'")
                                && h.contains("default-src 'none'")));
                TestKit.ok(e.getKey() + " has no server banner",
                        e.getValue().responseHeaders.stream()
                                .noneMatch(h -> h.toLowerCase(java.util.Locale.ROOT).startsWith(
                                        "server:")));
                TestKit.ok(e.getKey() + " header set is " + names, names.size() >= 7);
            }
            // The header block is an outcome oracle: if any branch's block differs, an
            // attacker who cannot see the body can still classify the reply. So the claim is
            // not "each reply has the important headers" (each can have them while the sets
            // differ) -- every cell must carry the SAME set, including HSTS. Asserting HSTS
            // only on the 401 let the 404/405/415/500 replies omit it outright.
            List<String> shape = responses.get("page").headerNames();
            TestKit.ok("fixture: the page's header set is non-empty", !shape.isEmpty());
            for (Map.Entry<String, Exchange> e : responses.entrySet()) {
                TestKit.ok(e.getKey() + " sends HSTS",
                        e.getValue().responseHeaders.stream().anyMatch(
                                h -> h.startsWith("Strict-Transport-Security: max-age=")));
                TestKit.eq(e.getKey() + " header set is identical to the page's",
                        shape, e.getValue().headerNames());
            }
            TestKit.ok("the shared shape names at least the seven hardening headers",
                    shape.size() >= 7);
            TestKit.ok("HSTS max-age is the configured one",
                    responses.get("404").responseHeaders.stream()
                            .anyMatch(h -> h.equals("Strict-Transport-Security: max-age=31536000")));

            // Nothing identifies the caller's input in a reply.
            Exchange probe = site.login("probe-target", TestKit.PW_WRONG);
            TestKit.ok("the attempted username is not echoed",
                    !probe.bodyText().contains("probe-target")
                            && !String.join("|", probe.responseHeaders)
                            .contains("probe-target"));
            TestKit.ok("the denial never names a reason",
                    !probe.bodyText().toLowerCase(java.util.Locale.ROOT).matches(
                            ".*(not found|unknown|expired|locked|throttl|too many|invalid).*"));
        } catch (IOException broken) {
            TestKit.ok("fixture: " + broken, false);
        }
    }

    private static void attributionOverHttp() {
        try {
            Site direct = new Site("http-attr-direct", "");
            direct.add("alice", TestKit.PW_ALICE);
            // Without a trusted proxy configured, X-Forwarded-For is inert: an attacker
            // cannot choose the bucket their failures are counted in. Each attempt uses a
            // different forged address, so if the header were honoured the attempts would
            // spread across 30 buckets and none of them would ever trip the ceiling -- which
            // is precisely how a per-source limit becomes opt-out. Only clearing the account
            // keeps the source counter accumulating, as it must.
            for (int i = 0; i < ThrottleManager.SOURCE_MAX_FAILURES; i++) {
                Map<String, String> h = new LinkedHashMap<>();
                h.put("Content-Type", FORM);
                h.put("X-Forwarded-For", "8.8.8." + (i % 250));
                direct.ask(new Exchange("POST", "/login", h,
                        "username=alice&password=" + TestKit.PW_WRONG + "&csrf="
                                + direct.freshCsrf(), PEER));
                direct.throttle.clearAccountForTesting(Crypto.idRef("alice"));
            }
            TestKit.ok("all the forged-address attempts landed in the socket peer's bucket",
                    direct.throttle.isSourceBlocked(SourceRef.ref(PEER)));
            TestKit.ok("none of the forged addresses has its own bucket",
                    direct.throttle.failureCountForSource(SourceRef.ref("8.8.8.1")) == 0);

            Site proxied = new Site("http-attr-proxy", "10.0.0.0/8");
            proxied.add("alice", TestKit.PW_ALICE);
            Map<String, String> via = new LinkedHashMap<>();
            via.put("Content-Type", FORM);
            via.put("X-Forwarded-For", "198.51.100.20");
            proxied.ask(new Exchange("POST", "/login", via,
                    "username=alice&password=" + TestKit.PW_WRONG + "&csrf="
                            + proxied.freshCsrf(), "10.0.0.5"));
            TestKit.ok("the client behind a trusted proxy gets its own bucket",
                    proxied.throttle.failureCountForSource(SourceRef.ref("198.51.100.20")) == 1);
            TestKit.ok("and the proxy's own address is not charged for it",
                    proxied.throttle.failureCountForSource(SourceRef.ref("10.0.0.5")) == 0);

            Site spoof = new Site("http-attr-spoof", "10.0.0.0/8");
            spoof.add("alice", TestKit.PW_ALICE);
            Map<String, String> liar = new LinkedHashMap<>();
            liar.put("Content-Type", FORM);
            liar.put("X-Forwarded-For", "10.0.0.99");
            spoof.ask(new Exchange("POST", "/login", liar,
                    "username=alice&password=" + TestKit.PW_WRONG + "&csrf="
                            + spoof.freshCsrf(), PEER));
            TestKit.ok("an untrusted peer cannot claim a trusted address",
                    spoof.throttle.failureCountForSource(SourceRef.ref("10.0.0.99")) == 0);
            TestKit.ok("it is counted where it actually connected",
                    spoof.throttle.failureCountForSource(SourceRef.ref(PEER)) == 1);

            // One label, one bucket, whichever code path charged it. Password failures are
            // counted inside the Authenticator and CSRF abuse inside the router; if either
            // reduced the label to a reference a second time they would land in different
            // buckets and the address could spend the per-source budget twice over -- a
            // failure that shows up nowhere except in the ceiling being soft.
            Site shared = new Site("http-attr-shared", "");
            shared.add("alice", TestKit.PW_ALICE);
            String src = SourceRef.ref(PEER);
            int before = shared.throttle.failureCountForSource(src);
            for (int i = 0; i < 5; i++) {
                shared.login("alice", TestKit.PW_WRONG);          // charged by Authenticator
            }
            int afterLogins = shared.throttle.failureCountForSource(src);
            TestKit.ok("credential failures charge the source bucket",
                    afterLogins - before >= 1);
            shared.reset("alice", PEER);
            for (int i = 0; i < 4; i++) {
                shared.post("/login", "username=alice&password=x&csrf=not-a-token", FORM, null);
            }                                            // charged by the router
            int afterCsrf = shared.throttle.failureCountForSource(src);
            TestKit.ok("csrf abuse charges the same bucket rather than a parallel one",
                    afterCsrf > afterLogins);
            TestKit.ok("and the total stays inside one budget",
                    afterCsrf - before <= ThrottleManager.SOURCE_MAX_FAILURES);
        } catch (IOException broken) {
            TestKit.ok("fixture: " + broken, false);
        }
    }

    // ------------------------------------------------------------------------ helpers

    private static String valueOf(List<String> setCookies, String name) {
        for (String c : setCookies) {
            if (!c.toLowerCase(java.util.Locale.ROOT).startsWith("set-cookie: "
                    + name.toLowerCase(java.util.Locale.ROOT) + "=")) {
                continue;
            }
            String rest = c.substring(c.indexOf('=') + 1);
            int semi = rest.indexOf(';');
            return semi < 0 ? rest : rest.substring(0, semi);
        }
        return null;
    }

    private static String flipLast(String s) {
        char last = s.charAt(s.length() - 1);
        return s.substring(0, s.length() - 1) + (last == 'a' ? 'b' : 'a');
    }
}
