package com.example.auth;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Checks the session-cookie behaviour without a container: {@code HttpServletResponse} and
 * {@code HttpServletRequest} are {@link Proxy} doubles, and the double renders {@code Set-Cookie}
 * the way an RFC 6265 cookie processor does, so the header that the code would really emit is what
 * gets asserted.
 *
 * <p>Run with {@code ./run-tests.sh}. Exit code is non-zero if any check fails.
 */
public final class TestHarness {

    private static int checks;
    private static final List<String> FAILURES = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        System.setProperty("demo.username", "alice");
        System.setProperty("demo.password", "correct horse battery staple");

        cookieCarriesTheHardenedAttributes();
        headerRenderedByTheContainerIsAsserted();
        aContainerThatDropsSecureIsCaught();
        craftedIdentifiersNeverReachTheHeader();
        mintedIdentifiersAreStrongAndUnique();
        logoutOverwritesTheSameCookie();
        storeLifecycle();
        loginHappyPath();
        loginRejectsBadCredentialsWithoutSettingACookie();
        loginReplacesAnIdentifierPresentedBeforeAuthentication();
        whoamiFollowsTheCookie();
        logoutEndsTheSession();
        methodsThatMustNotChangeState();
        jsonEscapingHolds();

        System.out.println();
        if (FAILURES.isEmpty()) {
            System.out.println("OK  " + checks + " checks passed");
            return;
        }
        System.out.println("FAILED " + FAILURES.size() + " of " + checks + " checks:");
        for (String failure : FAILURES) {
            System.out.println("  - " + failure);
        }
        System.exit(1);
    }

    // ---------------------------------------------------------------- cookie shape

    private static void cookieCarriesTheHardenedAttributes() {
        Section section = new Section("cookie attributes");
        SessionCookieConfig config = SessionCookieConfig.defaults();
        Cookie cookie = SessionCookieIssuer.build("abcDEF123_-~.", config);

        section.equalsTo("name", SessionCookieConfig.DEFAULT_NAME, cookie.getName());
        section.equalsTo("value", "abcDEF123_-~.", cookie.getValue());
        section.equalsTo("path", "/", cookie.getPath());
        section.check("Secure is set", cookie.getSecure());
        section.check("HttpOnly is set", cookie.isHttpOnly());
        section.equalsTo("SameSite", "Lax", cookie.getAttribute("SameSite"));
        section.equalsTo("no Domain attribute", null, cookie.getDomain());
        section.equalsTo("browser-session lifetime", -1, cookie.getMaxAge());

        RecordingResponse response = new RecordingResponse();
        new SessionCookieIssuer(config).issue(response, SessionIdentifier.of("abcDEF123_-~."));
        String header = response.setCookieHeaders().get(0);
        section.check("header carries HttpOnly: " + header, header.contains("HttpOnly"));
        section.check("header carries Secure: " + header, header.contains("Secure"));
        section.check("header carries SameSite=Lax: " + header, header.contains("SameSite=Lax"));
        section.check("header pins Path: " + header, header.contains("Path=/"));
        section.check("header has no Domain: " + header, !header.contains("Domain"));
        section.check("header has no Max-Age: " + header, !header.contains("Max-Age"));
        section.equalsTo("exactly one cookie header", 1, response.setCookieHeaders().size());
    }

    private static void headerRenderedByTheContainerIsAsserted() {
        Section section = new Section("header integrity");
        RecordingResponse response = new RecordingResponse();
        SessionCookieIssuer issuer = new SessionCookieIssuer(SessionCookieConfig.defaults());
        try {
            issuer.issue(response, SessionIdentifier.generate());
            section.check("clean header passes", true);
        } catch (RuntimeException unexpected) {
            section.check("clean header passes, threw " + unexpected, false);
        }

        // A container that silently ignored Secure must be caught, not served.
        RecordingResponse broken = new RecordingResponse();
        broken.dropSecureAttribute = true;
        try {
            issuer.issue(broken, SessionIdentifier.generate());
            section.check("dropped Secure is rejected", false);
        } catch (IllegalStateException expected) {
            section.check("dropped Secure is rejected: " + expected.getMessage(),
                    expected.getMessage().contains("Secure"));
        }

        RecordingResponse injected = new RecordingResponse();
        injected.forgeHeaderOnAdd = "APPSESSION=abc\r\nSet-Cookie: admin=y";
        try {
            issuer.issue(injected, SessionIdentifier.generate());
            section.check("CRLF in an emitted header is rejected", false);
        } catch (IllegalStateException expected) {
            section.check("CRLF in an emitted header is rejected: " + expected.getMessage(),
                    expected.getMessage().contains("control character"));
        }
    }

    private static void aContainerThatDropsSecureIsCaught() {
        Section section = new Section("insecure configuration is refused early");
        try {
            SessionCookieConfig.builder().sameSite(SessionCookieConfig.SameSite.NONE).secure(false).build();
            section.check("SameSite=None without Secure is refused", false);
        } catch (IllegalArgumentException expected) {
            section.check("SameSite=None without Secure is refused: " + expected.getMessage(),
                    expected.getMessage().contains("Secure"));
        }
        expectThrows(section, "relative path",
                () -> SessionCookieConfig.builder().path("app").build());
        expectThrows(section, "cookie name with a separator",
                () -> SessionCookieConfig.builder().name("app session").build());
        expectThrows(section, "cookie name with CR",
                () -> SessionCookieConfig.builder().name("A\rB").build());
        section.equalsTo("a persistent lifetime is allowed", 1800,
                SessionCookieConfig.builder().maxAgeSeconds(1800).build().maxAgeSeconds());
        expectThrows(section, "a nonsensical negative lifetime",
                () -> SessionCookieConfig.builder().maxAgeSeconds(-2).build());
    }

    private static void craftedIdentifiersNeverReachTheHeader() {
        Section section = new Section("identifier validation");
        List<String> payloads = Arrays.asList(
                "",
                " ",
                "a b",
                "abc; Secure",
                "abc; Domain=attacker.example",
                "abc\r\nSet-Cookie: admin=y",
                "abc\nSet-Cookie: admin=y",
                "abc\rSet-Cookie: admin=y",
                "ab\"c",
                "abc,def",
                "abc=",
                "abc\u0085x",
                "abc\u0000x",
                "token/" + "x".repeat(200));
        for (String payload : payloads) {
            expectThrows(section, "rejects " + describe(payload),
                    () -> SessionIdentifier.of(payload));
        }
        section.check("a plain base64url token is accepted", SessionIdentifier.of(
                "dG9rZW4-1_A~z.0123456789ABCDEFGHIJKLM") != null);
        expectThrows(section, "null is rejected", () -> SessionIdentifier.of(null));

        // The rejection has to happen before the response is touched, so nothing partial is sent.
        RecordingResponse response = new RecordingResponse();
        SessionCookieIssuer issuer = new SessionCookieIssuer(SessionCookieConfig.defaults());
        try {
            issuer.issue(response, SessionIdentifier.of("abc; Domain=attacker.example"));
            section.check("crafted value cannot be issued", false);
        } catch (IllegalArgumentException expected) {
            section.equalsTo("crafted value throws before the response is written",
                    0, response.setCookieHeaders().size());
        }
    }

    private static void mintedIdentifiersAreStrongAndUnique() {
        Section section = new Section("minted identifiers");
        SessionIdentifier first = SessionIdentifier.generate();
        section.equalsTo("length", 43, first.value().length());
        section.check("url-safe token", first.value().matches("[A-Za-z0-9_-]{43}"));
        section.check("accepted by the validator", SessionIdentifier.of(first.value()) != null);
        section.equalsTo("cookie value is the identifier", first.value(), first.toCookieValue());
        section.check("matches itself", first.matches(first.value()));
        section.check("does not match a prefix", !first.matches(first.value().substring(0, 42)));
        section.check("does not match null", !first.matches(null));
        section.check("redacted in toString: " + first, !first.toString().contains(first.value()));
        section.check("fingerprint is not the identifier",
                !first.fingerprint().contains(first.value()) && first.fingerprint().length() <= 16);
        section.check("fingerprint is stable",
                first.fingerprint().equals(SessionIdentifier.of(first.value()).fingerprint()));

        java.util.Set<String> seen = new java.util.HashSet<>();
        for (int i = 0; i < 2000; i++) {
            seen.add(SessionIdentifier.generate().value());
        }
        section.equalsTo("2000 minted values are distinct", 2000, seen.size());
    }

    private static void logoutOverwritesTheSameCookie() {
        Section section = new Section("logout overwrite");
        SessionCookieConfig config = SessionCookieConfig.defaults();
        RecordingResponse response = new RecordingResponse();
        new SessionCookieIssuer(config).expire(response);
        String header = response.setCookieHeaders().get(0);
        section.check("same name as the login cookie: " + header,
                header.startsWith(config.name() + "="));
        section.check("same path, or the browser keeps the original: " + header,
                header.contains("Path=" + config.path()));
        section.check("expires immediately: " + header, header.contains("Max-Age=0"));
        section.check("still HttpOnly so it can be cleared: " + header, header.contains("HttpOnly"));
        section.check("still Secure: " + header, header.contains("Secure"));
        section.check("value is emptied: " + header, header.startsWith(config.name() + "=;"));
    }

    // ---------------------------------------------------------------- store

    private static void storeLifecycle() {
        Section section = new Section("session store");
        InMemorySessionStore store = new InMemorySessionStore();
        SessionUser user = new SessionUser("alice");
        AuthenticatedSession session = store.create(user, Duration.ofMinutes(30));

        section.check("the new identifier resolves",
                store.findLive(session.identifier().value()).isPresent());
        section.equalsTo("it names the right principal", "alice",
                store.findLive(session.identifier().value()).orElseThrow().user().username());
        section.check("an unknown identifier does not resolve", store.findLive("nope-nope-nope").isEmpty());
        section.check("a null identifier does not resolve", store.findLive(null).isEmpty());
        section.check("an empty identifier does not resolve", store.findLive("").isEmpty());
        section.check("a crafted identifier does not resolve",
                store.findLive("abc; Domain=attacker.example").isEmpty());
        section.check("a value that differs by one character does not resolve",
                store.findLive(session.identifier().value().substring(1)).isEmpty());
        section.equalsTo("one active session", 1, store.activeCount());

        store.remove(session.identifier().value());
        section.check("logout removes the session",
                store.findLive(session.identifier().value()).isEmpty());
        section.equalsTo("no active sessions", 0, store.activeCount());

        AuthenticatedSession stale = store.create(user, Duration.ofMillis(-1));
        section.check("a session past its deadline is refused even though it is stored",
                store.findLive(stale.identifier().value()).isEmpty());
    }

    // ---------------------------------------------------------------- servlets

    private static void loginHappyPath() throws Exception {
        Section section = new Section("POST /api/login");
        Fixture fixture = new Fixture();
        RecordingResponse response = new RecordingResponse();
        fixture.login("alice", "correct horse battery staple").service(request("POST", "/api/login",
                Map.of("username", "alice", "password", "correct horse battery staple"), List.of()), response);

        section.equalsTo("200", 200, response.status);
        String header = response.setCookieHeaders().get(0);
        section.check("Set-Cookie names the session identifier: " + header,
                header.startsWith("APPSESSION=") && header.length() > "APPSESSION=;".length());
        section.check("Set-Cookie is HttpOnly: " + header, header.contains("HttpOnly"));
        section.check("Set-Cookie is Secure: " + header, header.contains("Secure"));
        section.check("Set-Cookie is SameSite=Lax: " + header, header.contains("SameSite=Lax"));
        section.check("Set-Cookie is host-only: " + header, !header.contains("Domain"));
        section.equalsTo("exactly one Set-Cookie header", 1, response.setCookieHeaders().size());
        section.equalsTo("no JSESSIONID is minted", 0L,
                response.setCookieHeaders().stream().filter(h -> h.startsWith("JSESSIONID=")).count());
        section.equalsTo("no-store so the response is not cached with the session", "no-store",
                response.header("Cache-Control"));
        section.equalsTo("body is JSON", "application/json", response.contentType);

        String body = response.body();
        section.check("body says authenticated: " + body, body.contains("\"authenticated\":true"));
        section.check("body names the user: " + body, body.contains("\"user\":\"alice\""));
        section.check("body never repeats the identifier",
                !body.contains(header.substring("APPSESSION=".length()).split(";")[0]));

        String identifier = identifierOf(header);
        section.check("the cookie names a live session",
                fixture.store().findLive(identifier).isPresent());
    }

    private static void loginRejectsBadCredentialsWithoutSettingACookie() throws Exception {
        Section section = new Section("POST /api/login with wrong credentials");
        Fixture fixture = new Fixture();
        RecordingResponse response = new RecordingResponse();
        fixture.login("alice", "wrong").service(request("POST", "/api/login",
                Map.of("username", "alice", "password", "wrong"), List.of()), response);

        section.equalsTo("401", 401, response.status);
        section.equalsTo("no cookie is set on failure", 0, response.setCookieHeaders().size());
        section.check("the store stayed empty", fixture.store().activeCount() == 0);
        section.check("the reason is generic: " + response.body(),
                response.body().contains("invalid_credentials"));

        RecordingResponse unknownUser = new RecordingResponse();
        fixture.login("bob", "correct horse battery staple").service(request("POST", "/api/login",
                Map.of("username", "bob", "password", "correct horse battery staple"), List.of()), unknownUser);
        section.equalsTo("unknown user gets the same 401", 401, unknownUser.status);
        section.equalsTo("and the same body shape, so no user enumeration", response.body(),
                unknownUser.body());
    }

    private static void loginReplacesAnIdentifierPresentedBeforeAuthentication() throws Exception {
        Section section = new Section("session fixation");
        Fixture fixture = new Fixture();
        AuthenticatedSession preAuth = fixture.store().create(new SessionUser("ghost"), Duration.ofMinutes(30));
        String preAuthValue = preAuth.identifier().value();

        RecordingResponse response = new RecordingResponse();
        fixture.login("alice", "correct horse battery staple").service(request("POST", "/api/login",
                Map.of("username", "alice", "password", "correct horse battery staple"),
                List.of(new Cookie("APPSESSION", preAuthValue))), response);

        section.equalsTo("login succeeded", 200, response.status);
        section.check("the pre-authentication identifier no longer names anything",
                fixture.store().findLive(preAuthValue).isEmpty());
        String issued = identifierOf(response.setCookieHeaders().get(0));
        section.check("a different identifier was minted", !issued.equals(preAuthValue));
        section.check("the new identifier is live", fixture.store().findLive(issued).isPresent());
    }

    private static void whoamiFollowsTheCookie() throws Exception {
        Section section = new Section("GET /api/whoami");
        Fixture fixture = new Fixture();
        AuthenticatedSession session = fixture.store().create(new SessionUser("alice"), Duration.ofMinutes(30));

        RecordingResponse withCookie = new RecordingResponse();
        fixture.whoami().service(request("GET", "/api/whoami", Map.of(),
                List.of(new Cookie("APPSESSION", session.identifier().value()))), withCookie);
        section.equalsTo("the cookie alone is enough: 200", 200, withCookie.status);
        section.check("it names the principal: " + withCookie.body(),
                withCookie.body().contains("\"user\":\"alice\""));

        RecordingResponse anonymous = new RecordingResponse();
        fixture.whoami().service(request("GET", "/api/whoami", Map.of(), List.of()), anonymous);
        section.equalsTo("no cookie is anonymous", 401, anonymous.status);
        section.equalsTo("no cookie sets nothing", 0, anonymous.setCookieHeaders().size());

        RecordingResponse tampered = new RecordingResponse();
        fixture.whoami().service(request("GET", "/api/whoami", Map.of(),
                List.of(new Cookie("APPSESSION", session.identifier().value().substring(1)))), tampered);
        section.equalsTo("a tampered identifier is anonymous", 401, tampered.status);

        RecordingResponse crafted = new RecordingResponse();
        fixture.whoami().service(request("GET", "/api/whoami", Map.of(),
                List.of(new Cookie("APPSESSION", "abc; Domain=attacker.example"))), crafted);
        section.equalsTo("a crafted identifier is anonymous, not an error", 401, crafted.status);

        RecordingResponse wrongName = new RecordingResponse();
        fixture.whoami().service(request("GET", "/api/whoami", Map.of(),
                List.of(new Cookie("JSESSIONID", session.identifier().value()))), wrongName);
        section.equalsTo("only the configured cookie name is trusted", 401, wrongName.status);

        RecordingResponse shadowing = new RecordingResponse();
        fixture.whoami().service(request("GET", "/api/whoami", Map.of(), List.of(
                new Cookie("APPSESSION", session.identifier().value()),
                new Cookie("APPSESSION", "planted-by-another-path"))), shadowing);
        section.equalsTo("a duplicated cookie does not resolve to the real session", 401, shadowing.status);

        RecordingResponse expired = new RecordingResponse();
        AuthenticatedSession dead = fixture.store().create(new SessionUser("alice"), Duration.ofMillis(-1));
        fixture.whoami().service(request("GET", "/api/whoami", Map.of(),
                List.of(new Cookie("APPSESSION", dead.identifier().value()))), expired);
        section.equalsTo("a cookie whose session outlived its deadline is refused", 401, expired.status);
    }

    private static void logoutEndsTheSession() throws Exception {
        Section section = new Section("POST /api/logout");
        Fixture fixture = new Fixture();
        AuthenticatedSession session = fixture.store().create(new SessionUser("alice"), Duration.ofMinutes(30));

        RecordingResponse response = new RecordingResponse();
        fixture.logout().service(request("POST", "/api/logout", Map.of(),
                List.of(new Cookie("APPSESSION", session.identifier().value()))), response);

        section.equalsTo("204", 204, response.status);
        section.equalsTo("no body", "", response.body());
        section.check("the session is gone server-side",
                fixture.store().findLive(session.identifier().value()).isEmpty());
        String header = response.setCookieHeaders().get(0);
        section.check("the cookie is overwritten at the same path: " + header,
                header.startsWith("APPSESSION=;") && header.contains("Path=/") && header.contains("Max-Age=0"));

        RecordingResponse anonymousLogout = new RecordingResponse();
        fixture.logout().service(request("POST", "/api/logout", Map.of(), List.of()), anonymousLogout);
        section.equalsTo("logging out while anonymous looks identical", 204, anonymousLogout.status);
    }

    private static void methodsThatMustNotChangeState() throws Exception {
        Section section = new Section("method guards");
        Fixture fixture = new Fixture();

        RecordingResponse getOnLogin = new RecordingResponse();
        fixture.login(null, null).service(request("GET", "/api/login", Map.of(), List.of()), getOnLogin);
        section.equalsTo("GET /api/login is refused", 405, getOnLogin.status);
        section.equalsTo("and sets no cookie", 0, getOnLogin.setCookieHeaders().size());

        RecordingResponse getOnLogout = new RecordingResponse();
        fixture.logout().service(request("GET", "/api/logout", Map.of(), List.of()), getOnLogout);
        section.equalsTo("GET /api/logout is refused so a link cannot log anyone out", 405,
                getOnLogout.status);
    }

    private static void jsonEscapingHolds() {
        Section section = new Section("json escaping");
        section.equalsTo("quote", "\\\"", Json.escape("\""));
        section.equalsTo("backslash", "\\\\", Json.escape("\\"));
        section.equalsTo("newline", "\\n", Json.escape("\n"));
        section.equalsTo("line separator", "\\u2028", Json.escape(String.valueOf((char) 0x2028)));
        section.equalsTo("control character", "\\u001b", Json.escape(String.valueOf((char) 0x1B)));
        section.equalsTo("plain text", "alice", Json.escape("alice"));
    }

    // ---------------------------------------------------------------- fixtures

    /** Servlets wired to a fresh store, so one check cannot leak into the next. */
    private static final class Fixture {

        private final InMemorySessionStore store = new InMemorySessionStore();
        private final ServletContext context =
                (ServletContext) proxy(ServletContext.class, new ContextHandler(store));

        InMemorySessionStore store() {
            return store;
        }

        LoginServlet login(String ignoredUser, String ignoredPassword) throws Exception {
            return initialise(new LoginServlet());
        }

        WhoAmIServlet whoami() throws Exception {
            return initialise(new WhoAmIServlet());
        }

        LogoutServlet logout() throws Exception {
            return initialise(new LogoutServlet());
        }

        private <T extends jakarta.servlet.Servlet> T initialise(T servlet) throws Exception {
            ServletConfig config =
                    (ServletConfig) proxy(ServletConfig.class, new ConfigHandler(context));
            servlet.init(config);
            return servlet;
        }
    }

    private static final class ContextHandler implements InvocationHandler {

        private final Map<String, Object> attributes = new LinkedHashMap<>();
        private final InMemorySessionStore store;

        ContextHandler(InMemorySessionStore store) {
            this.store = store;
            attributes.put(AuthContextListener.SESSION_STORE_ATTRIBUTE, store);
            attributes.put(AuthContextListener.COOKIE_ISSUER_ATTRIBUTE,
                    new SessionCookieIssuer(SessionCookieConfig.defaults()));
            attributes.put(AuthContextListener.SESSION_TTL_ATTRIBUTE, Duration.ofMinutes(30));
            attributes.put(AuthContextListener.VERIFIER_ATTRIBUTE, new EnvironmentCredentialVerifier());
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "getAttribute":
                    return attributes.get((String) args[0]);
                case "setAttribute":
                    attributes.put((String) args[0], args[1]);
                    return null;
                case "removeAttribute":
                    attributes.remove((String) args[0]);
                    return null;
                case "getInitParameter":
                    return null;
                case "getMajorVersion":
                    return 6;
                case "getMinorVersion":
                    return 0;
                case "getEffectiveMajorVersion":
                    return 6;
                case "getEffectiveMinorVersion":
                    return 0;
                case "getContextPath":
                    return "/session-cookie";
                case "getVirtualServerName":
                    return "session-cookie";
                case "log":
                    return null;
                default:
                    return defaultValue(method.getReturnType());
            }
        }
    }

    /** No per-servlet init-params: every cookie setting must come out of the defaults. */
    private record ConfigHandler(ServletContext context) implements InvocationHandler {

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "getInitParameter":
                    return null;
                case "getInitParameterNames":
                    return java.util.Collections.emptyEnumeration();
                case "getServletContext":
                    return context;
                case "getServletName":
                    return "servlet-under-test";
                default:
                    return defaultValue(method.getReturnType());
            }
        }
    }

    /**
     * Stands in for {@code HttpServletResponse}. {@code addCookie} renders the header the way an
     * RFC 6265 cookie processor would, which is what lets the checks assert on the emitted text
     * rather than on the object graph. {@code dropSecureAttribute} and {@code forgeHeaderOnAdd}
     * simulate a container that misbehaves, to prove the post-issue assertion catches it.
     */
    private static final class RecordingResponse implements HttpServletResponse {

        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private final List<String> setCookie = new ArrayList<>();
        private final StringWriter body = new StringWriter();
        private final PrintWriter writer = new PrintWriter(body);
        private int status = 200;
        private String contentType = "";
        boolean dropSecureAttribute;
        String forgeHeaderOnAdd;

        /** The header lines as the container would have put them on the wire. */
        List<String> setCookieHeaders() {
            return setCookie;
        }

        String body() {
            writer.flush();
            return body.toString();
        }

        /** Convenience for the checks; identical to {@link #getHeader}. */
        String header(String name) {
            return getHeader(name);
        }

        /**
         * Renders a cookie the way a container's cookie processor does, so a missing attribute here
         * means a missing attribute on the wire.
         */
        private String render(Cookie cookie) {
            StringBuilder out = new StringBuilder();
            out.append(cookie.getName()).append('=').append(cookie.getValue() == null ? "" : cookie.getValue());
            if (cookie.getPath() != null) {
                out.append("; Path=").append(cookie.getPath());
            }
            if (cookie.getDomain() != null) {
                out.append("; Domain=").append(cookie.getDomain());
            }
            if (!dropSecureAttribute && cookie.getSecure()) {
                out.append("; Secure");
            }
            if (cookie.isHttpOnly()) {
                out.append("; HttpOnly");
            }
            String sameSite = cookie.getAttribute("SameSite");
            if (sameSite != null) {
                out.append("; SameSite=").append(sameSite);
            }
            if (cookie.getMaxAge() >= 0) {
                out.append("; Max-Age=").append(cookie.getMaxAge());
                out.append("; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
            }
            return out.toString();
        }

        @Override
        public void addCookie(Cookie cookie) {
            if (forgeHeaderOnAdd != null) {
                setCookie.add(forgeHeaderOnAdd);
                return;
            }
            // Rendered here, at the moment the container would have written it, so the post-issue
            // assertion and the checks both see wire text rather than the object graph.
            setCookie.add(render(cookie));
        }

        @Override
        public boolean containsHeader(String name) {
            return headers.containsKey(name);
        }

        @Override
        public String encodeURL(String url) {
            throw new UnsupportedOperationException("URL rewriting must not carry a session id");
        }

        @Override
        public String encodeRedirectURL(String url) {
            throw new UnsupportedOperationException("URL rewriting must not carry a session id");
        }

        @Override
        public void sendError(int status, String message) throws java.io.IOException {
            this.status = status;
            throw new IllegalStateException("sendError(" + status + ", " + message + ")");
        }

        @Override
        public void sendError(int status) throws java.io.IOException {
            sendError(status, null);
        }

        @Override
        public void sendRedirect(String location) throws java.io.IOException {
            throw new UnsupportedOperationException("sendRedirect");
        }

        @Override
        public void setDateHeader(String name, long timestamp) {
            setHeader(name, Long.toString(timestamp));
        }

        @Override
        public void addDateHeader(String name, long timestamp) {
            addHeader(name, Long.toString(timestamp));
        }

        @Override
        public void setHeader(String name, String value) {
            headers.put(name, new ArrayList<>(List.of(value)));
        }

        @Override
        public void addHeader(String name, String value) {
            headers.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
        }

        @Override
        public void setIntHeader(String name, int value) {
            setHeader(name, Integer.toString(value));
        }

        @Override
        public void addIntHeader(String name, int value) {
            addHeader(name, Integer.toString(value));
        }

        @Override
        public void setStatus(int status) {
            this.status = status;
        }

        @Override
        public int getStatus() {
            return status;
        }

        @Override
        public String getHeader(String name) {
            List<String> values = headers.get(name);
            return values == null || values.isEmpty() ? null : values.get(0);
        }

        @Override
        public Collection<String> getHeaders(String name) {
            if ("Set-Cookie".equals(name)) {
                return setCookieHeaders();
            }
            return headers.getOrDefault(name, List.of());
        }

        @Override
        public Collection<String> getHeaderNames() {
            List<String> names = new ArrayList<>(headers.keySet());
            if (!setCookie.isEmpty()) {
                names.add("Set-Cookie");
            }
            return names;
        }

        @Override
        public String getCharacterEncoding() {
            return "UTF-8";
        }

        @Override
        public String getContentType() {
            return contentType;
        }

        @Override
        public jakarta.servlet.ServletOutputStream getOutputStream() throws java.io.IOException {
            throw new UnsupportedOperationException("the servlets write through the character writer");
        }

        @Override
        public PrintWriter getWriter() {
            return writer;
        }

        @Override
        public void setCharacterEncoding(String charset) {
            // recorded only to prove the servlet declares UTF-8
        }

        @Override
        public void setContentLength(int len) {
        }

        @Override
        public void setContentLengthLong(long len) {
        }

        @Override
        public void setContentType(String type) {
            contentType = stripParameters(type);
        }

        @Override
        public void setBufferSize(int size) {
        }

        @Override
        public int getBufferSize() {
            return 8192;
        }

        @Override
        public void flushBuffer() {
            writer.flush();
        }

        @Override
        public void resetBuffer() {
        }

        @Override
        public boolean isCommitted() {
            return false;
        }

        @Override
        public void reset() {
        }

        @Override
        public void setLocale(Locale loc) {
        }

        @Override
        public Locale getLocale() {
            return Locale.getDefault();
        }

        private static String stripParameters(String value) {
            int semicolon = value == null ? -1 : value.indexOf(';');
            return semicolon < 0 ? value : value.substring(0, semicolon);
        }
    }

    private static HttpServletRequest request(String method, String path, Map<String, String> parameters,
                                              List<Cookie> cookies) {
        return (HttpServletRequest) proxy(HttpServletRequest.class,
                new RequestHandler(method, path, parameters, cookies));
    }

    private static final class RequestHandler implements InvocationHandler {

        private final String httpMethod;
        private final String path;
        private final Map<String, String> parameters;
        private final Cookie[] cookies;
        private final Map<String, Object> attributes = new LinkedHashMap<>();

        RequestHandler(String httpMethod, String path, Map<String, String> parameters, List<Cookie> cookies) {
            this.httpMethod = httpMethod;
            this.path = path;
            this.parameters = parameters;
            this.cookies = cookies.toArray(new Cookie[0]);
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "getMethod":
                    return httpMethod;
                case "getRequestURI":
                case "getServletPath":
                    return path;
                case "getContextPath":
                    return "/session-cookie";
                case "getParameter":
                    return parameters.get((String) args[0]);
                case "getParameterValues":
                    String value = parameters.get((String) args[0]);
                    return value == null ? null : new String[] { value };
                case "getParameterMap":
                    return parameters;
                case "getParameterNames":
                    return Collections.enumeration(parameters.keySet());
                case "getCookies":
                    return cookies;
                case "getHeader":
                    return null;
                case "getHeaders":
                    return List.of();
                case "getHeaderNames":
                    return List.of();
                case "getIntHeader":
                    return -1;
                case "getBooleanHeader":
                    return false;
                case "getDateHeader":
                    return -1L;
                case "getRequestedSessionId":
                    return null;
                case "isRequestedSessionIdValid":
                    return false;
                case "isRequestedSessionIdFromCookie":
                    return false;
                case "isRequestedSessionIdFromURL":
                    return false;
                case "isRequestedSessionIdFromUrl":
                    return false;
                case "getSession":
                    throw new IllegalStateException(
                            "the application must not use the container session");
                case "getScheme":
                    return "https";
                case "isSecure":
                    return true;
                case "getServerName":
                    return "localhost";
                case "getServerPort":
                    return 443;
                case "getRemoteAddr":
                    return "127.0.0.1";
                case "getRemoteUser":
                    return null;
                case "getUserPrincipal":
                    return null;
                case "getAuthType":
                    return null;
                case "getAttribute":
                    return attributes.get((String) args[0]);
                case "setAttribute":
                    attributes.put((String) args[0], args[1]);
                    return null;
                case "removeAttribute":
                    attributes.remove((String) args[0]);
                    return null;
                case "getAttributeNames":
                    return new ArrayList<>(attributes.keySet());
                case "getServletContext":
                    return null;
                case "changeSessionId":
                    return null;
                case "authenticate":
                    return false;
                case "getParts":
                    return List.of();
                case "getPart":
                    return null;
                case "getQueryString":
                    return null;
                case "getProtocol":
                    return "HTTP/1.1";
                case "getCharacterEncoding":
                    return "UTF-8";
                case "getContentType":
                    return null;
                case "getLocalAddr":
                    return "127.0.0.1";
                case "getLocale":
                    return Locale.getDefault();
                case "getLocales":
                    return Collections.singletonList(Locale.getDefault());
                case "getDispatcherType":
                    return jakarta.servlet.DispatcherType.REQUEST;
                default:
                    return defaultValue(method.getReturnType());
            }
        }
    }

    // ---------------------------------------------------------------- plumbing

    private static Object proxy(Class<?> iface, InvocationHandler handler) {
        return Proxy.newProxyInstance(TestHarness.class.getClassLoader(), new Class<?>[] { iface }, handler);
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == void.class) {
            return null;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == int.class || type == short.class || type == byte.class || type == char.class) {
            return 0;
        }
        if (type == double.class) {
            return 0d;
        }
        return 0f;
    }

    private static String identifierOf(String setCookieHeader) {
        String value = setCookieHeader.substring("APPSESSION=".length());
        int semicolon = value.indexOf(';');
        return semicolon < 0 ? value : value.substring(0, semicolon);
    }

    private static String describe(String payload) {
        return payload.isEmpty() ? "<empty>" : payload.replace("\r", "\\r").replace("\n", "\\n")
                .replace("\u0085", "\\u0085").replace("\u0000", "\\u0000");
    }

    private static void expectThrows(Section section, String what, Runnable action) {
        try {
            action.run();
            section.check(what + " should have been rejected", false);
        } catch (IllegalArgumentException expected) {
            section.check(what + " rejected: " + expected.getMessage(), true);
        }
    }

    /** One test's assertions, so a failure names the case it belongs to. */
    private static final class Section {

        private final String name;

        Section(String name) {
            this.name = name;
            System.out.println("== " + name);
        }

        void check(String what, boolean condition) {
            checks++;
            if (condition) {
                System.out.println("  ok   " + what);
            } else {
                System.out.println("  FAIL " + what);
                FAILURES.add(name + ": " + what);
            }
        }

        void equalsTo(String what, Object expected, Object actual) {
            checks++;
            boolean same = expected == null ? actual == null : expected.equals(actual);
            if (same) {
                System.out.println("  ok   " + what + " = " + actual);
            } else {
                System.out.println("  FAIL " + what + ": expected " + expected + " but was " + actual);
                FAILURES.add(name + ": " + what + " expected <" + expected + "> but was <" + actual + ">");
            }
        }
    }
}
