package com.acme.portal.testapp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * End-to-end assertions against a real, deployed container.
 *
 * <p>The in-process harness proves what the component asked the container to do; this proves what the
 * container actually put on the wire, which is the only thing a browser sees. Every assertion reads
 * raw HTTP: status line, header block, body. Nothing is inferred from the Java side.
 *
 * <p>Environment: {@code E2E_BASE} (for example {@code http://127.0.0.1:8399}) and {@code E2E_MODE}
 * of {@code default}, {@code limited} (tight rate-limit settings) or {@code noverifier} (deployed
 * without a session-state authority, where everything must be refused).
 *
 * <p>Hostile bytes are sent over a raw socket rather than {@link HttpClient}, because the JDK client
 * itself refuses CR and LF in a header value. A test that cannot put those bytes on the wire proves
 * nothing about the server, so it does not use the convenient client for those cases.
 */
public final class E2EClient {

    private static final String HANDOFF_PATH = "/session/handoff";
    private static final Pattern COOKIE_VALUE =
            Pattern.compile("^__Host-PORTAL_SESSION=([A-Za-z0-9_-]+)");
    private static final String WELL_FORMED_UNKNOWN = "a13b1d1e7e19005f693f249531276986e2ca227Q_-9";

    private static int checks;
    private static int failures;
    private static final List<String> FAILED = new ArrayList<String>();

    private final String base;
    private final String host;
    private final int port;
    private final String contextPath;
    private final HttpClient client;

    public E2EClient(String base) {
        this.base = base;
        URI uri = URI.create(base);
        this.host = uri.getHost();
        this.port = uri.getPort() == -1 ? 80 : uri.getPort();
        // The raw-socket helper writes its own request line, so it must carry the deployment's
        // context path itself. Omitting it aims every hostile byte at the host root instead of at
        // the servlet, and the container answers 404 -- which would look like a passed test.
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        this.contextPath = path;
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public static void main(String[] args) {
        String base = System.getenv("E2E_BASE");
        String mode = System.getenv("E2E_MODE");
        if (base == null || base.isEmpty()) {
            System.out.println("NOTE  E2E_BASE is not set; nothing was asserted");
            System.exit(2);
        }
        System.out.println("NOTE  target=" + base + " mode=" + mode);
        E2EClient client = new E2EClient(base);
        try {
            if ("limited".equals(mode)) {
                client.rateLimitAssertions();
            } else if ("noverifier".equals(mode)) {
                client.failClosedAssertions();
            } else {
                client.mainAssertions();
            }
        } catch (IOException | InterruptedException trouble) {
            System.out.println("ERROR target unreachable: " + trouble.getClass().getName() + ": "
                    + trouble.getMessage());
            System.exit(2);
        }
        System.out.println("SUMMARY checks=" + checks + " failures=" + failures);
        if (failures > 0) {
            for (String name : FAILED) {
                System.out.println("FAILED  " + name);
            }
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------ main suite

    private void mainAssertions() throws IOException, InterruptedException {
        String ticket = "e2e-ticket-" + System.nanoTime();
        Reply signIn = request("GET", ticket, null, null);
        ok("a sign-in request itself issues no cookie (no assertion exists yet)",
                signIn.setCookieHeaders().isEmpty() && signIn.status == 403,
                "status=" + signIn.status + " cookies=" + signIn.setCookieHeaders());

        Reply grant = request("GET", null, ticket, null);
        ok("the asserted handoff is granted", grant.status == 200, "status was " + grant.status);
        List<String> cookies = grant.setCookieHeaders();
        ok("exactly one Set-Cookie header", cookies.size() == 1, "got " + cookies);
        String cookie = cookies.isEmpty() ? "" : cookies.get(0);
        System.out.println("NOTE  Set-Cookie: " + cookie);

        Matcher value = COOKIE_VALUE.matcher(cookie);
        boolean shaped = value.find();
        ok("cookie name carries the __Host- prefix and a base64url value", shaped, cookie);
        String sessionId = shaped && value.group(1) != null ? value.group(1) : "";
        ok("cookie value is 43 characters of base64url (256 bits)", sessionId.length() == 43,
                "len=" + sessionId.length());
        ok("the issued value is not derived from the ticket the client sent",
                !sessionId.contains(ticket) && sessionId.length() != ticket.length());
        ok("SameSite is rendered into Set-Cookie by the container",
                containsAttribute(cookie, "samesite="), cookie);
        ok("SameSite is Strict", containsAttribute(cookie, "samesite=strict"), cookie);
        ok("HttpOnly is rendered", containsAttribute(cookie, "httponly"), cookie);
        ok("Secure is rendered", containsAttribute(cookie, "secure"), cookie);
        ok("Path=/ is rendered", containsAttribute(cookie, "path=/"), cookie);
        ok("no Domain attribute, so the cookie is host-only", !containsAttribute(cookie, "domain="),
                cookie);
        ok("no Max-Age attribute, so it is a browser-session cookie",
                !containsAttribute(cookie, "max-age="), cookie);
        ok("no Expires attribute, so it is a browser-session cookie",
                !containsAttribute(cookie, "expires="), cookie);
        ok("no 1970 expiry sneaked in by the container", !cookie.contains("1970") && !cookie.contains("1995"),
                cookie);
        ok("Cache-Control is no-store", grant.header("Cache-Control", "").contains("no-store"),
                String.valueOf(grant.headers));
        ok("X-Content-Type-Options is nosniff",
                "nosniff".equalsIgnoreCase(grant.header("X-Content-Type-Options", "")),
                String.valueOf(grant.headers));
        ok("the body names the cookie, never the credential",
                grant.body.contains("__Host-PORTAL_SESSION") && !grant.body.contains(sessionId));
        ok("the credential appears in Set-Cookie and nowhere else",
                !joinedHeadersExceptSetCookie(grant).contains(sessionId)
                        && !grant.body.contains(sessionId));
        ok("the container added no jsessionid anywhere",
                !grant.raw().toLowerCase(Locale.ROOT).contains("jsessionid"));
        ok("no Set-Cookie text appears inside the body",
                !grant.body.toLowerCase(Locale.ROOT).contains("set-cookie"));

        Reply repeated = request("GET", null, ticket, null);
        ok("the same ticket yields the same session value (a real session, not a new one per request)",
                sessionId.equals(valueOf(repeated)), "was " + valueOf(repeated));
        String other = "e2e-ticket-" + (System.nanoTime() + 1);
        request("GET", other, null, null);
        Reply distinctGrant = request("GET", null, other, null);
        ok("a different ticket yields a different session value",
                !sessionId.equals(valueOf(distinctGrant)), "both were " + sessionId);

        refusalAssertions(grant, sessionId);
        verifierGateAssertions();
        methodAssertions();
        injectionAssertions(ticket, sessionId);
        revocationAssertions(ticket);
        headAssertions();
        errorPageAssertions();
    }

    private void refusalAssertions(Reply grant, String sessionId) throws IOException, InterruptedException {
        Reply noAssertion = request("GET", null, null, null);
        ok("a request with no assertion is refused with 403", noAssertion.status == 403,
                "status was " + noAssertion.status);
        ok("a refusal sets no cookie", noAssertion.setCookieHeaders().isEmpty(),
                String.valueOf(noAssertion.setCookieHeaders()));
        ok("the refusal body is generic",
                noAssertion.body.contains("could not complete sign-in"), noAssertion.body);
        ok("the refusal body names no account and no reason",
                !noAssertion.body.toLowerCase(Locale.ROOT).contains("session identifier")
                        && !noAssertion.body.contains("expired"), noAssertion.body);

        Reply offeredCookie = requestWithClientCookie(WELL_FORMED_UNKNOWN);
        ok("a client-offered session cookie does not produce a handoff",
                offeredCookie.status == 403, "status was " + offeredCookie.status);
        ok("the offered cookie is not echoed back",
                !offeredCookie.raw().contains(WELL_FORMED_UNKNOWN),
                String.valueOf(offeredCookie.setCookieHeaders()));
        ok("a client-offered cookie never becomes a Set-Cookie",
                offeredCookie.setCookieHeaders().isEmpty(),
                String.valueOf(offeredCookie.setCookieHeaders()));

        ok("every refusal body is byte-identical",
                noAssertion.body.equals(offeredCookie.body), "bodies differ");
        ok("a refusal body is never the granted body", !noAssertion.body.equals(grant.body));
        ok("a refusal never leaks the credential that was granted to someone else",
                !noAssertion.raw().contains(sessionId));
    }

    /**
     * The integration mistake this component exists to survive: the trusted authenticator names an
     * identifier, and the session store must be the thing that decides.
     */
    private void verifierGateAssertions() throws IOException, InterruptedException {
        Reply unknown = request("GET", null, null, WELL_FORMED_UNKNOWN);
        ok("a well-formed identifier the store does not know is refused", unknown.status == 403,
                "status was " + unknown.status);
        ok("the unknown identifier never becomes a cookie", unknown.setCookieHeaders().isEmpty(),
                String.valueOf(unknown.setCookieHeaders()));
        ok("the unknown identifier is not echoed anywhere", !unknown.raw().contains(WELL_FORMED_UNKNOWN),
                unknown.raw());

        Reply malformed = request("GET", null, null, "junk");
        ok("a malformed assertion is refused", malformed.status == 403, "status was " + malformed.status);
        ok("a malformed assertion issues no cookie", malformed.setCookieHeaders().isEmpty(),
                String.valueOf(malformed.setCookieHeaders()));

        Reply emptyAssert = request("GET", null, null, "");
        ok("an empty assertion is refused", emptyAssert.status == 403,
                "status was " + emptyAssert.status);

        Reply longAssert = request("GET", null, null, WELL_FORMED_UNKNOWN + WELL_FORMED_UNKNOWN
                + WELL_FORMED_UNKNOWN + WELL_FORMED_UNKNOWN);
        ok("an over-long assertion is refused", longAssert.status == 403,
                "status was " + longAssert.status);
        ok("an over-long assertion issues no cookie", longAssert.setCookieHeaders().isEmpty(),
                String.valueOf(longAssert.setCookieHeaders()));

        ok("the refused-assertion bodies are identical to the no-assertion body",
                unknown.body.equals(malformed.body) && malformed.body.equals(longAssert.body),
                "bodies differ");
    }

    private void methodAssertions() throws IOException, InterruptedException {
        for (String method : new String[]{"POST", "PUT", "DELETE", "OPTIONS"}) {
            RawReply reply = rawSocket(method, null, null, null);
            ok(method + " is refused with 405", reply.status == 405, "status was " + reply.status);
            ok(method + " advertises only GET and HEAD",
                    reply.headerLine("Allow", "GET, HEAD"), reply.headersOnly());
            ok(method + " never issues a cookie", !reply.containsIgnoreCase("set-cookie"),
                    reply.text());
        }
        RawReply patch = rawSocket("PATCH", null, null, null);
        ok("PATCH is refused (405 or 501)", patch.status == 405 || patch.status == 501,
                "status was " + patch.status);
        ok("PATCH never issues a cookie", !patch.containsIgnoreCase("set-cookie"), patch.text());
        RawReply trace = rawSocket("TRACE", null, null, null);
        ok("TRACE is refused outright", trace.status == 501 || trace.status == 405 || trace.status == 400,
                "status was " + trace.status);
        ok("TRACE does not echo the request line", !trace.text().contains("TRACE /"), trace.text());
    }

    private void injectionAssertions(String ticket, String sessionId) throws IOException, InterruptedException {
        String[] hostile = {"leak\r\nSet-Cookie: evil=1", "leak\nSet-Cookie: evil=1",
                "leak\r\n\r\nGET /admin HTTP/1.1", "x; Domain=evil.example", "x\" ; path=/etc",
                "%0A%0DSet-Cookie%3A%20evil%3D1", "\u0001\u0002", " ".repeat(300),
                "<script>alert(1)</script>", "../WEB-INF/web.xml"};
        for (String candidate : hostile) {
            RawReply reply = rawSocket("GET", candidate, null, null);
            ok("a hostile login header cannot inject a second cookie (" + label(candidate) + ')',
                    countOccurrences(reply.headersOnly(), "set-cookie:") <= 0, reply.headersOnly());
            ok("a hostile login header never leaks its payload (" + label(candidate) + ')',
                    !reply.text().contains("evil=1") && !reply.text().contains("evil.example"),
                    reply.text());
        }

        // The dangerous ordering: an injected login header plus a legitimate ticket, so the request
        // does get granted and the injected bytes are competing with a real Set-Cookie.
        RawReply grantedAfter = rawSocket("GET", "leak\r\nSet-Cookie: evil=1", ticket, null);
        ok("a granted handoff after an injection attempt emits exactly one cookie",
                countOccurrences(grantedAfter.headersOnly(), "set-cookie:") == 1,
                grantedAfter.headersOnly());
        ok("the emitted cookie is the server-generated one",
                grantedAfter.text().contains("__Host-PORTAL_SESSION=" + sessionId),
                grantedAfter.headersOnly());
        ok("no injected cookie reached the wire", !grantedAfter.text().contains("evil=1"),
                grantedAfter.text());

        RawReply assertedInjection = rawSocket("GET", null, null,
                "abc\r\nSet-Cookie: evil=1");
        ok("an assertion containing CRLF is refused outright",
                assertedInjection.status == 403 || assertedInjection.status == 400,
                "status was " + assertedInjection.status);
        ok("an assertion containing CRLF never issues a cookie",
                countOccurrences(assertedInjection.headersOnly(), "set-cookie:") == 0,
                assertedInjection.headersOnly());
    }

    private void revocationAssertions(String ticket) throws IOException, InterruptedException {
        Reply live = control("/stub/control/live");
        ok("at least one session is live before revocation", live.body.trim().matches("[1-9][0-9]*"),
                live.body.trim());
        Reply expired = control("/stub/control/expire-oldest");
        ok("the scaffolding reports a session expired", "EXPIRED".equals(expired.body.trim()),
                expired.body.trim());
        Reply after = request("GET", null, ticket, null);
        ok("the identical request that produced a cookie now produces a refusal",
                after.status == 403, "status was " + after.status);
        ok("a revoked session produces no cookie", after.setCookieHeaders().isEmpty(),
                String.valueOf(after.setCookieHeaders()));
        ok("the revoked-session refusal body matches every other refusal body",
                after.body.equals(request("GET", null, null, null).body), "bodies differ");
    }

    private void headAssertions() throws IOException, InterruptedException {
        // Its own session: the revocation assertions deliberately kill the session this suite signed
        // in with first, so reusing that ticket here would assert against a known-dead identifier.
        String fresh = "head-ticket-" + System.nanoTime();
        request("GET", fresh, null, null);
        RawReply head = rawSocket("HEAD", null, fresh, null);
        ok("HEAD with a valid assertion answers 200", head.status == 200, "status was " + head.status);
        ok("HEAD issues no cookie", !head.containsIgnoreCase("set-cookie"), head.headersOnly());
        ok("HEAD carries no body", head.bodyBytes() == 0, "body bytes=" + head.bodyBytes());
        ok("HEAD declares a content length", head.headersOnly().toLowerCase(Locale.ROOT)
                .contains("content-length"), head.headersOnly());
    }

    private void errorPageAssertions() throws IOException, InterruptedException {
        Reply missing = get(base + "/nothing-here");
        ok("an unmapped path is a 404", missing.status == 404, "status was " + missing.status);
        ok("the error page discloses no stack trace or class name",
                !missing.body.contains(".java") && !missing.body.toLowerCase(Locale.ROOT)
                        .contains("jakarta") && !missing.body.contains("Exception"), missing.body);
        RawReply traversal = rawSocket("GET", null, null, null, "/session/../WEB-INF/web.xml");
        ok("a path traversal attempt does not return the deployment descriptor",
                !traversal.text().contains("web-app") && !traversal.text().contains("servlet-class"),
                "status " + traversal.status);
    }

    // ------------------------------------------------------------------ alt modes

    private void rateLimitAssertions() throws IOException, InterruptedException {
        // The deployment runs with a short window so the recovery behaviour is observable in seconds.
        // Both numbers come from the environment the container was started with, so the assertions
        // describe the configuration under test rather than assume it.
        int window = Integer.parseInt(System.getenv().getOrDefault("E2E_WINDOW_SECONDS", "3"));
        int perSource = Integer.parseInt(System.getenv().getOrDefault("E2E_PER_SOURCE", "3"));
        String ticket = "rl-ticket-" + System.nanoTime();
        request("GET", ticket, null, null);

        // Property one, the anti-lockout half: a request that never presented something worth
        // looking up is refused before the limiter is consulted, so an attacker cannot spend a
        // victim's allowance by sending garbage. Twice the allowance of free refusals first; the full
        // allowance must still be available afterwards.
        Reply[] free = new Reply[perSource * 2];
        for (int i = 0; i < free.length; i++) {
            free[i] = request("GET", null, null, i % 2 == 0 ? null : "junk");
            ok("free refusal " + (i + 1) + " is answered on its own merits (403, not 429)",
                    free[i].status == 403, "status was " + free[i].status);
        }
        Reply firstLimit = null;
        int granted = 0;
        for (int attempt = 1; attempt <= perSource + 1; attempt++) {
            Reply reply = request("GET", null, ticket, null);
            if (reply.status == 200) {
                granted++;
            } else if (reply.status == 429 && firstLimit == null) {
                firstLimit = reply;
            }
        }
        ok("garbage consumed nothing: the full allowance of handoffs is still granted",
                granted == perSource, "granted " + granted + " of " + perSource + " after "
                        + free.length + " free refusals");
        ok("the next handoff from the same source is refused with 429",
                firstLimit != null, "no 429 was seen");
        if (firstLimit != null) {
            String retryAfter = firstLimit.header("Retry-After", "");
            int seconds = retryAfter.trim().isEmpty() ? -1 : Integer.parseInt(retryAfter.trim());
            ok("the refusal carries a Retry-After inside the configured window",
                    seconds >= 1 && seconds <= window, String.valueOf(retryAfter));
            ok("the limited response sets no cookie", firstLimit.setCookieHeaders().isEmpty(),
                    String.valueOf(firstLimit.setCookieHeaders()));
            ok("the limited response body is the same generic refusal",
                    firstLimit.body.contains("could not complete sign-in"), firstLimit.body);
            ok("the limited response is uncacheable", firstLimit.header("Cache-Control", "")
                    .contains("no-store"), String.valueOf(firstLimit.headers));
        }

        // The window rolls, and property two, the half that stops the limiter being decorative: a
        // well-formed identifier *is* looked up, so it pays for its allowance even though it ends in
        // a refusal. Otherwise an attacker could probe the session store for free all day.
        Thread.sleep((window + 1L) * 1_100L);
        Reply probe = request("GET", null, null, WELL_FORMED_UNKNOWN);
        ok("a well-formed identifier the store does not know is refused with 403",
                probe.status == 403, "status was " + probe.status);
        int grantedAfterProbe = 0;
        for (int attempt = 1; attempt <= perSource + 1; attempt++) {
            if (request("GET", null, ticket, null).status == 200) {
                grantedAfterProbe++;
            }
        }
        ok("a refused-but-looked-up attempt paid for itself: one grant fewer this window",
                grantedAfterProbe == perSource - 1,
                "granted " + grantedAfterProbe + " of " + perSource);

        // And the throttle is temporary, never a permanent lockout of a legitimate user.
        Thread.sleep((window + 1L) * 1_100L);
        Reply recovered = request("GET", null, ticket, null);
        ok("the allowance returns when the window rolls (throttling is not lockout)",
                recovered.status == 200, "status was " + recovered.status);
        ok("the recovered handoff issues a cookie", !recovered.setCookieHeaders().isEmpty(),
                String.valueOf(recovered.setCookieHeaders()));
    }

    /** Deployed with no session-state authority at all: the component must refuse everything. */
    private void failClosedAssertions() throws IOException, InterruptedException {
        String ticket = "nf-ticket-" + System.nanoTime();
        request("GET", ticket, null, null);
        Reply[] attempts = {request("GET", null, ticket, null), request("GET", null, null, null),
                request("GET", null, null, WELL_FORMED_UNKNOWN), request("GET", ticket, ticket, null)};
        for (int i = 0; i < attempts.length; i++) {
            ok("attempt " + (i + 1) + " is refused with 503 while nothing can be verified",
                    attempts[i].status == 503, "status was " + attempts[i].status);
            ok("attempt " + (i + 1) + " issues no cookie", attempts[i].setCookieHeaders().isEmpty(),
                    String.valueOf(attempts[i].setCookieHeaders()));
        }
        ok("the 503 body is the same generic refusal as an authentication failure",
                attempts[0].body.contains("could not complete sign-in"), attempts[0].body);
        ok("the 503 carries Retry-After", !attempts[0].header("Retry-After", "").isEmpty(),
                String.valueOf(attempts[0].headers));
        ok("the 503 discloses nothing about the missing integration",
                !attempts[0].body.toLowerCase(Locale.ROOT).contains("verifier")
                        && !attempts[0].body.contains("Exception"), attempts[0].body);
    }

    // ------------------------------------------------------------------ HTTP plumbing

    private static void ok(String what, boolean condition) {
        ok(what, condition, "");
    }

    private static void ok(String what, boolean condition, String detail) {
        checks++;
        if (condition) {
            System.out.println("  PASS  " + what);
        } else {
            failures++;
            FAILED.add(what);
            System.out.println("  FAIL  " + what + (detail.isEmpty() ? "" : " -> " + firstLine(detail)));
        }
    }

    private Reply request(String method, String loginTicket, String assertionTicket, String asserted)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(base + HANDOFF_PATH))
                .timeout(Duration.ofSeconds(15));
        if (loginTicket != null) {
            builder.header("X-Stub-Login", loginTicket);
        }
        if (assertionTicket != null) {
            builder.header("X-Stub-Ticket", assertionTicket);
        }
        if (asserted != null) {
            builder.header("X-Stub-Assert", asserted);
        }
        builder.method(method, HttpRequest.BodyPublishers.noBody());
        return new Reply(client.send(builder.build(), HttpResponse.BodyHandlers.ofString()));
    }

    private Reply requestWithClientCookie(String cookieValue) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + HANDOFF_PATH))
                .header("Cookie", "__Host-PORTAL_SESSION=" + cookieValue)
                .timeout(Duration.ofSeconds(15)).GET().build();
        return new Reply(client.send(request, HttpResponse.BodyHandlers.ofString()));
    }

    private Reply get(String url) throws IOException, InterruptedException {
        return new Reply(client.send(HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(15)).GET().build(), HttpResponse.BodyHandlers.ofString()));
    }

    private Reply control(String path) throws IOException, InterruptedException {
        return new Reply(client.send(HttpRequest.newBuilder(URI.create(base + path))
                .timeout(Duration.ofSeconds(15))
                .method("POST", HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString()));
    }

    /** Sends bytes exactly as given, so CRLF and other forbidden header characters really arrive. */
    private RawReply rawSocket(String method, String loginTicket, String assertionTicket, String asserted)
            throws IOException, InterruptedException {
        return rawSocket(method, loginTicket, assertionTicket, asserted, HANDOFF_PATH);
    }

    private RawReply rawSocket(String method, String loginTicket, String assertionTicket, String asserted,
                               String path) throws IOException, InterruptedException {
        StringBuilder request = new StringBuilder();
        request.append(method).append(' ').append(contextPath).append(path).append(" HTTP/1.1\r\n");
        request.append("Host: ").append(host).append(':').append(port).append("\r\n");
        request.append("Connection: close\r\n");
        if (loginTicket != null) {
            request.append("X-Stub-Login: ").append(loginTicket).append("\r\n");
        }
        if (assertionTicket != null) {
            request.append("X-Stub-Ticket: ").append(assertionTicket).append("\r\n");
        }
        if (asserted != null) {
            request.append("X-Stub-Assert: ").append(asserted).append("\r\n");
        }
        request.append("\r\n");

        Socket socket = new Socket();
        try {
            socket.connect(new java.net.InetSocketAddress(host, port), 5000);
            socket.setSoTimeout(10000);
            OutputStream out = socket.getOutputStream();
            out.write(request.toString().getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            InputStream in = socket.getInputStream();
            ByteArrayOutputStream collected = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) != -1) {
                collected.write(buffer, 0, read);
                if (collected.size() > 1_000_000) {
                    break;
                }
            }
            return new RawReply(new String(collected.toByteArray(), StandardCharsets.ISO_8859_1),
                    collected.size());
        } finally {
            socket.close();
        }
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        String text = haystack.toLowerCase(Locale.ROOT);
        String target = needle.toLowerCase(Locale.ROOT);
        for (int from = 0; ; ) {
            int found = text.indexOf(target, from);
            if (found < 0) {
                return count;
            }
            count++;
            from = found + target.length();
        }
    }

    private static boolean containsAttribute(String cookie, String attribute) {
        return cookie.toLowerCase(Locale.ROOT).contains(attribute);
    }

    private static String valueOf(Reply reply) {
        List<String> cookies = reply.setCookieHeaders();
        if (cookies.isEmpty()) {
            return "";
        }
        Matcher matcher = COOKIE_VALUE.matcher(cookies.get(0));
        return matcher.find() ? matcher.group(1) : "";
    }

    private static String joinedHeadersExceptSetCookie(Reply reply) {
        StringBuilder text = new StringBuilder();
        for (String header : reply.headers) {
            if (!header.toLowerCase(Locale.ROOT).startsWith("set-cookie")) {
                text.append(header).append('\n');
            }
        }
        return text.toString();
    }

    private static String label(String value) {
        if (value.length() > 24) {
            return "len=" + value.length();
        }
        return value.replace("\r", "\\r").replace("\n", "\\n").replace("\u0001", "\\x01")
                .replace("\u0002", "\\x02");
    }

    private static String firstLine(String text) {
        int newline = text.indexOf('\n');
        return newline < 0 ? text : text.substring(0, newline);
    }

    /** Flattened view of a client-library response. */
    private static final class Reply {
        private final int status;
        private final List<String> headers;
        private final String body;

        Reply(HttpResponse<String> response) {
            this.status = response.statusCode();
            this.body = response.body();
            List<String> flattened = new ArrayList<String>();
            response.headers().map().forEach((name, values) -> {
                for (String value : values) {
                    flattened.add(name + ": " + value);
                }
            });
            this.headers = flattened;
        }

        List<String> setCookieHeaders() {
            List<String> found = new ArrayList<String>();
            for (String header : headers) {
                if (header.toLowerCase(Locale.ROOT).startsWith("set-cookie")) {
                    found.add(header.substring(header.indexOf(':') + 1).trim());
                }
            }
            return found;
        }

        String header(String name, String fallback) {
            for (String header : headers) {
                if (header.regionMatches(true, 0, name, 0, name.length())
                        && header.charAt(name.length()) == ':') {
                    return header.substring(name.length() + 1).trim();
                }
            }
            return fallback;
        }

        String raw() {
            StringBuilder text = new StringBuilder("HTTP ").append(status).append('\n');
            for (String header : headers) {
                text.append(header).append('\n');
            }
            return text.append(body).toString();
        }
    }

    /** Raw bytes off the socket, split the way HTTP splits them. */
    private static final class RawReply {
        private final String text;
        private final int status;
        private final int totalBytes;

        RawReply(String text, int totalBytes) {
            this.text = text;
            this.totalBytes = totalBytes;
            this.status = parseStatus(text);
        }

        private static int parseStatus(String text) {
            if (!text.regionMatches(true, 0, "HTTP/", 0, 5)) {
                return 0;
            }
            int end = text.indexOf("\r\n");
            String line = end < 0 ? text : text.substring(0, end);
            String[] parts = line.split(" ");
            if (parts.length < 2) {
                return 0;
            }
            try {
                return Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException brokenStatusLine) {
                return 0;
            }
        }

        String headersOnly() {
            int end = text.indexOf("\r\n\r\n");
            return end < 0 ? text : text.substring(0, end);
        }

        int bodyBytes() {
            int end = text.indexOf("\r\n\r\n");
            return end < 0 ? 0 : totalBytes - (end + 4);
        }

        boolean headerLine(String name, String expected) {
            return headersOnly().toLowerCase(Locale.ROOT)
                    .contains((name + ": " + expected).toLowerCase(Locale.ROOT));
        }

        boolean containsIgnoreCase(String needle) {
            return text.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
        }

        String text() {
            return text;
        }
    }
}
