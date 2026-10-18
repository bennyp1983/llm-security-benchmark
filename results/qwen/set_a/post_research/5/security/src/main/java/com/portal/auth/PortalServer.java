package com.portal.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The HTTPS front end.
 *
 * <p>Every rule below is a refusal, and refusals never vary with the caller's secret:
 *
 * <ol>
 *   <li><b>HTTPS only.</b> There is no HTTP listener and no fallback: without a keystore
 *       this refuses to start. A credential posted over cleartext is a leaked credential,
 *       so "we also serve plain HTTP for convenience" is not an available configuration.
 *       </li>
 *   <li><b>Method allowlist, pinned content type, no chunked bodies.</b> Anything else is a
 *       405/415 whose shape does not depend on the caller's credentials.</li>
 *   <li><b>Hard body cap.</b> Read in bounded chunks and abandoned the moment it is
 *       exceeded, so a 10 GB POST costs us 8 KiB.</li>
 *   <li><b>Form keys are an allowlist</b> ({@code username}, {@code password},
 *       {@code csrf}); an unknown key or a repeated key refuses the whole request. Extra
 *       keys are how mass-assignment gets into an authentication form, and a repeated key
 *       lets the client pick which of two values the server sees.</li>
 *   <li><b>CSRF token pair required on every state-changing request.</b> Both halves must
 *       be present, well-formed, equal to each other and match a pair we issued; the pair
 *       is consumed either way so it cannot be replayed.</li>
 *   <li><b>One response for every authentication denial.</b> Unknown user, wrong password,
 *       malformed input, spent budget, bad CSRF, missing or oversized body, oversized
 *       header: same status, same bytes, same header names and values, same
 *       {@code Content-Length}. The distinction exists only in the audit log.</li>
 *   <li><b>Cookies are {@code HttpOnly; Secure; SameSite=Strict; Path=/}.</b> The session
 *       cookie is minted only after a verified password match and is never accepted as
 *       anything but a lookup key.</li>
 *   <li><b>Source attribution.</b> The socket peer decides the per-source budget.
 *       {@code X-Forwarded-For} is ignored unless the peer is inside the configured trusted
 *       proxy set, and then only by walking right-to-left (see
 *       {@link SourceRef#resolvePeer}).</li>
 * </ol>
 *
 * <h2>A known, accepted shape difference</h2>
 * {@code HEAD} cannot carry a body, and the JDK server omits {@code Content-Length} on
 * {@code HEAD} responses. Only the method-level 405 is affected: {@code HEAD} is not in the
 * allowlist and never reaches the authentication logic, so what such a request can learn is
 * which methods exist -- which it already knew from the request it just sent.
 */
public final class PortalServer {

    public static final int MAX_BODY_BYTES = 8 * 1024;
    public static final int MAX_HEADER_BYTES = 8 * 1024;

    public static final String SESSION_COOKIE = "PORTAL_SESSION";
    public static final String CSRF_COOKIE = "portal_csrf";
    public static final String DENIED_BODY = "Access denied.";
    /** Ceiling for one decoded form field; anything longer is a refusal, not a truncation. */
    static final int MAX_FIELD = 512;
    public static final String SIGNED_OUT_BODY = "Signed out.";

    private static final String LOGIN_PATH = "/login";
    private static final String LOGOUT_PATH = "/logout";

    private final PortalRuntime runtime;
    private final PortalConfig config;
    private final List<SourceRef.Cidr> trustedProxies;
    private final AuditLog audit;

    public PortalServer(PortalRuntime runtime, PortalConfig config) {
        this.runtime = runtime;
        this.config = config;
        this.trustedProxies = SourceRef.parseCidrList(config.trustedProxyCsv());
        this.audit = runtime.audit();
    }

    /** Entry point shared by the listener and the tests. */
    public void handle(HttpExchangeView ex) {
        try {
            route(ex);
        } catch (IOException clientWentAway) {
            // A broken pipe is not a security event and there is nobody left to answer.
        } catch (RuntimeException unexpected) {
            // Generic response, details in the log. Never echo the exception: its message
            // can name a file, a class or a value.
            audit.systemFailure("http", "-", "-", unexpected);
            try {
                ex.respond(500, HttpExchangeView.EMPTY, securityHeaders());
            } catch (IOException ignored) {
                // Nothing further to do.
            }
        }
    }

    private void route(HttpExchangeView ex) throws IOException {
        String method = ex.method() == null ? "" : ex.method();
        String path = ex.rawPath() == null ? "" : ex.rawPath();

        if (!method.equals("GET") && !method.equals("POST")) {
            ex.respond(405, HttpExchangeView.EMPTY, securityHeaders());
            return;
        }
        if (method.equals("GET")) {
            if (path.equals(LOGIN_PATH)) {
                showLoginPage(ex);
            } else {
                ex.respond(404, HttpExchangeView.EMPTY, securityHeaders());
            }
            return;
        }
        if (!path.equals(LOGIN_PATH) && !path.equals(LOGOUT_PATH)) {
            ex.respond(404, HttpExchangeView.EMPTY, securityHeaders());
            return;
        }
        if (!hasFormContentType(ex)) {
            ex.respond(415, HttpExchangeView.EMPTY, securityHeaders());
            return;
        }
        byte[] body = readBody(ex);
        if (body == null) {
            denied(ex);
            return;
        }
        FormFields fields = FormFields.parse(new String(body, StandardCharsets.UTF_8));
        Crypto.wipe(body);
        if (fields == null) {
            denied(ex);
            return;
        }
        if (!csrfAcceptable(ex, fields)) {
            String csrfSource = sourceHexOf(ex);
            runtime.throttle().consumeSourceBudget(csrfSource);
            audit.event("csrf", "-", csrfSource, "denied", "token-mismatch");
            denied(ex);
            return;
        }
        if (path.equals(LOGOUT_PATH)) {
            logout(ex);
            return;
        }
        login(ex, fields);
    }

    /** Periodic housekeeping for a long-lived listener; correctness does not depend on it. */
    public void purgeExpiredSessions() {
        runtime.sessions().purgeExpired();
    }

    // ---------------------------------------------------------------- login page

    private void showLoginPage(HttpExchangeView ex) throws IOException {
        String token = Crypto.randomUrlToken(InputPolicy.CSRF_TOKEN_BYTES);
        runtime.sessions().issueCsrfToken(token, token);

        StringBuilder html = new StringBuilder(1024);
        html.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width\">")
                .append("<title>Employee portal sign in</title></head><body>")
                .append("<h1>Employee portal</h1>")
                .append("<form method=\"post\" action=\"/login\" autocomplete=\"off\">")
                .append("<label for=\"u\">Username</label>")
                .append("<input id=\"u\" name=\"username\" maxlength=\"")
                .append(InputPolicy.USERNAME_MAX).append("\" required>")
                .append("<label for=\"p\">Password</label>")
                .append("<input id=\"p\" name=\"password\" type=\"password\" maxlength=\"")
                .append(InputPolicy.PASSWORD_MAX).append("\" required>")
                .append("<input type=\"hidden\" name=\"csrf\" value=\"").append(htmlEscape(token))
                .append("\"><button type=\"submit\">Sign in</button></form>")
                .append("</body></html>");
        byte[] page = html.toString().getBytes(StandardCharsets.UTF_8);

        List<String> headers = securityHeaders();
        headers.add(csrfCookie(token));
        ex.respond(200, page, headers);
    }

    // ------------------------------------------------------------------- actions

    private void login(HttpExchangeView ex, FormFields fields) throws IOException {
        // The label, not the reference: authenticate() performs the one reduction this
        // request gets, and sharing a bucket with the CSRF-abuse counter depends on it.
        String sourceLabel = sourceLabelOf(ex);

        byte[] userBytes = fields.asciiBytes(FormFields.USERNAME);
        byte[] passBytes = fields.asciiBytes(FormFields.PASSWORD);
        if (userBytes == null || passBytes == null) {
            Crypto.wipe(passBytes);
            // A form with no credential field is not an authentication attempt, so it is
            // charged to the source directly rather than through the Authenticator -- but
            // into the same bucket the Authenticator would have used.
            runtime.throttle().consumeSourceBudget(SourceRef.normalizeForLedger(sourceLabel));
            denied(ex);
            return;
        }
        String username = new String(userBytes, StandardCharsets.US_ASCII);
        Crypto.wipe(userBytes);
        char[] password = charsFromBytes(passBytes);
        Crypto.wipe(passBytes);

        Authenticator.Result result =
                runtime.authenticator().authenticate(username, password, sourceLabel);
        // authenticate() clears the array on every path; this reference is now inert.
        if (!result.isSuccess()) {
            denied(ex);
            return;
        }
        List<String> headers = securityHeaders();
        headers.add(sessionCookie(result.sessionId()));
        headers.add(clearedCsrfCookie());
        headers.add("Location: /login");
        ex.respond(303, HttpExchangeView.EMPTY, headers);
    }

    private void logout(HttpExchangeView ex) throws IOException {
        Optional<String> presented = CookieParser.value(ex.header("Cookie"), SESSION_COOKIE);
        if (presented.isEmpty() || runtime.sessions().find(presented.get()).isEmpty()) {
            // Nothing to revoke, and the answer is the same generic denial every
            // unauthenticated request gets. A session-id probe cannot tell "expired" from
            // "never existed" from "made up".
            denied(ex);
            return;
        }
        runtime.sessions().logout(presented.get());
        List<String> headers = securityHeaders();
        headers.add(clearedSessionCookie());
        headers.add(clearedCsrfCookie());
        ex.respond(200, SIGNED_OUT_BODY.getBytes(StandardCharsets.UTF_8), headers);
    }

    // ------------------------------------------------------------------ responses

    /** The single denial response. Every caller of this produces byte-identical output. */
    private void denied(HttpExchangeView ex) throws IOException {
        ex.respond(401, DENIED_BODY.getBytes(StandardCharsets.UTF_8), securityHeaders());
    }

    /**
     * The response headers every reply carries, so a denial cannot be distinguished from
     * another denial by a header that only one branch remembered to set.
     *
     * <p>There is deliberately no variant flag. An earlier version omitted
     * {@code Strict-Transport-Security} on the 404/405/415/500 replies and sent it on the
     * authentication replies, which contradicted this comment and made the header block
     * itself differ by branch -- the exact shape difference this method exists to prevent.
     * Sending it everywhere is also the only useful choice: the first response a browser
     * gets from a host is often a 404 on a stale bookmark, and a policy published only on
     * pages the user has not reached yet protects nothing.
     *
     * <p>{@code no-store} is not decoration: a cached 401 or a cached login page in a shared
     * browser is a credential and CSRF-token leak.
     */
    private List<String> securityHeaders() {
        List<String> h = new ArrayList<>(10);
        h.add("Cache-Control: no-store");
        h.add("Pragma: no-cache");
        h.add("X-Content-Type-Options: nosniff");
        h.add("X-Frame-Options: DENY");
        h.add("Referrer-Policy: no-referrer");
        h.add("Content-Security-Policy: default-src 'none'; script-src 'none'; style-src 'self';"
                + " img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        h.add("Vary: Cookie");
        h.add("Strict-Transport-Security: max-age=" + config.hstsMaxAgeSeconds());
        return h;
    }

    // ------------------------------------------------------------------- cookies

    /**
     * {@code HttpOnly} on both cookies. The login form's CSRF value is rendered into the
     * page as a hidden field, so nothing needs script access, and keeping the cookie
     * unreadable to script means injected script cannot plant a matching pair.
     */
    private String sessionCookie(String id) {
        return "Set-Cookie: " + SESSION_COOKIE + "=" + id
                + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age="
                + SessionManager.ABSOLUTE_TIMEOUT.getSeconds();
    }

    private String clearedSessionCookie() {
        return "Set-Cookie: " + SESSION_COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Strict;"
                + " Max-Age=0";
    }

    private String csrfCookie(String token) {
        return "Set-Cookie: " + CSRF_COOKIE + "=" + token
                + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age="
                + SessionManager.CSRF_TIMEOUT.getSeconds();
    }

    private String clearedCsrfCookie() {
        return "Set-Cookie: " + CSRF_COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Strict;"
                + " Max-Age=0";
    }

    // -------------------------------------------------------------------- bodies

    /** @return the body, or null when it is missing, empty or over the cap. */
    private byte[] readBody(HttpExchangeView ex) throws IOException {
        byte[] raw = ex.readBodyBounded(MAX_BODY_BYTES);
        if (raw == null || raw.length == 0 || raw.length > MAX_BODY_BYTES) {
            return null;
        }
        return raw;
    }

    private boolean hasFormContentType(HttpExchangeView ex) {
        String ct = ex.header("Content-Type");
        if (ct == null || ct.length() > 200) {
            return false;
        }
        int semi = ct.indexOf(';');
        String media = semi >= 0 ? ct.substring(0, semi) : ct;
        return media.equalsIgnoreCase("application/x-www-form-urlencoded");
    }

    /**
     * Consumes the CSRF pair. Charged to the source budget on failure: a real browser
     * never fails this check, so a failure is an automated client.
     */
    private boolean csrfAcceptable(HttpExchangeView ex, FormFields fields) {
        String cookie = CookieParser.value(ex.header("Cookie"), CSRF_COOKIE).orElse(null);
        byte[] hidden = fields.asciiBytes(FormFields.CSRF);
        if (hidden == null) {
            return false;
        }
        String hiddenValue = new String(hidden, StandardCharsets.US_ASCII);
        Crypto.wipe(hidden);
        return runtime.sessions().consumeCsrfToken(cookie, hiddenValue);
    }

    /**
     * The resolved client <em>label</em> for this request: a literal address, or
     * {@code "unknown"}. Not a ledger key -- see {@link #sourceHexOf}.
     */
    private String sourceLabelOf(HttpExchangeView ex) {
        return SourceRef.resolvePeer(ex.peerAddress(), ex.header("X-Forwarded-For"),
                trustedProxies);
    }

    /**
     * The ledger and audit key for this request.
     *
     * <p>The reduction from label to reference happens <b>exactly once</b> per request, and
     * which call site owns it matters: {@link Authenticator} reduces whatever label it is
     * handed, so this class must pass it the label rather than an already-reduced reference.
     * Doing it twice is not an error that announces itself -- {@code ref(ref(x))} is a valid
     * key, just a <em>different</em> one -- so the symptom was that CSRF abuse and password
     * failures for one address were counted in two separate buckets, each of which throttled
     * on its own. An address could therefore spend roughly twice the documented per-source
     * budget, and the operator's per-source count under-reported login failures.
     */
    private String sourceHexOf(HttpExchangeView ex) {
        return SourceRef.ref(sourceLabelOf(ex));
    }

    static char[] charsFromBytes(byte[] printableAscii) {
        char[] out = new char[printableAscii.length];
        for (int i = 0; i < printableAscii.length; i++) {
            out[i] = (char) (printableAscii[i] & 0xFF);
        }
        return out;
    }

    private static String htmlEscape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Test helper: pull the CSRF value out of a rendered login page. */
    static String csrfTokenFrom(String html) {
        int at = html.indexOf("name=\"csrf\" value=\"");
        if (at < 0) {
            return null;
        }
        int start = at + "name=\"csrf\" value=\"".length();
        int end = html.indexOf('"', start);
        return end < 0 ? null : html.substring(start, end);
    }

    /**
     * Strict {@code application/x-www-form-urlencoded} parser; see the class note for the
     * rules and why each exists. A value that decodes to anything outside printable ASCII is
     * refused rather than substituted, so this boundary never invents a credential.
     */
    static final class FormFields {

        static final String USERNAME = "username";
        static final String PASSWORD = "password";
        static final String CSRF = "csrf";
        private static final List<String> ALLOWED = List.of(USERNAME, PASSWORD, CSRF);

        private final java.util.Map<String, byte[]> values = new java.util.HashMap<>();

        /**
         * Requires the syntax, the allowlist and the CSRF field -- the one field every
         * route needs.
         *
         * <p>It deliberately does <em>not</em> require {@code username} and
         * {@code password}: this parser is shared with {@code POST /logout}, which carries
         * only the CSRF pair, so requiring the credential fields here made the logout
         * endpoint unreachable -- every sign-out attempt was refused as a malformed form and
         * the only way a session ended was to wait for it to expire, which contradicts what
         * {@link SessionManager} promises about revocation. Which fields a route requires is
         * the route's decision: {@link #login} refuses when a credential field is absent.
         */
        static FormFields parse(String body) {
            if (body.isEmpty() || body.length() > MAX_BODY_BYTES) {
                return null;
            }
            FormFields out = new FormFields();
            for (String pair : body.split("&")) {
                if (pair.isEmpty()) {
                    return null;
                }
                int eq = pair.indexOf('=');
                if (eq <= 0 || eq == pair.length() - 1) {
                    return null;
                }
                String key = percentDecode(pair.substring(0, eq), true);
                if (key == null || !ALLOWED.contains(key) || out.values.containsKey(key)) {
                    return null;
                }
                byte[] value = percentDecodeBytes(pair.substring(eq + 1));
                if (value == null || value.length == 0 || value.length > MAX_FIELD) {
                    return null;
                }
                out.values.put(key, value);
            }
            if (!out.values.containsKey(CSRF)) {
                return null;
            }
            return out;
        }

        byte[] asciiBytes(String key) {
            byte[] raw = values.get(key);
            return raw == null ? null : Arrays.copyOf(raw, raw.length);
        }
    }

    private static String percentDecode(String s, boolean plusIsSpace) {
        byte[] d = percentDecodeBytes(s);
        if (d == null) {
            return null;
        }
        String decoded = new String(d, StandardCharsets.US_ASCII);
        Crypto.wipe(d);
        if (plusIsSpace) {
            decoded = decoded.replace('+', ' ');
        }
        return decoded;
    }

    /**
     * Decodes percent-escapes, requiring every resulting byte to be printable ASCII
     * ({@code 0x21..0x7E}). Anything else -- a control byte, a space escape, a non-ASCII
     * UTF-8 sequence, a truncated escape -- returns null.
     */
    private static byte[] percentDecodeBytes(String s) {
        if (s.length() > MAX_FIELD * 3 + 8) {
            return null;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%') {
                if (i + 2 >= s.length()) {
                    return null;
                }
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi < 0 || lo < 0) {
                    return null;
                }
                int v = (hi << 4) | lo;
                if (v < 0x21 || v > 0x7E) {
                    return null;
                }
                out.write(v);
                i += 2;
                continue;
            }
            if (c < 0x21 || c > 0x7E) {
                return null;
            }
            out.write(c);
        }
        return out.toByteArray();
    }
}
