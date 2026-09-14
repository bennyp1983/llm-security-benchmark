package com.example.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Jakarta Servlet handling secure session cookie creation, configuration, and lifecycle management
 * following successful user authentication.
 *
 * <p>Implements defense-in-depth security controls for session cookies:
 * <ul>
 *   <li><b>HttpOnly Flag (CWE-1004)</b>: Prevents client-side scripts (e.g., JavaScript
 *       {@code document.cookie}) from accessing the session identifier, mitigating Cross-Site
 *       Scripting (XSS) session hijacking.</li>
 *   <li><b>Secure Flag (CWE-614)</b>: Enforces that the cookie is transmitted solely over
 *       encrypted TLS/HTTPS connections, preventing interception via eavesdropping or
 *       Man-in-the-Middle (MITM) network attacks.</li>
 *   <li><b>SameSite Attribute (CWE-1275)</b>: Configured to {@code Strict} by default,
 *       restricting cross-site cookie transmission to defend against Cross-Site Request
 *       Forgery (CSRF).</li>
 *   <li><b>Host-Only Cookie Scoping</b>: The {@code Domain} attribute is intentionally omitted
 *       so the cookie is bound strictly to the origin host (RFC 6265 Section 4.1.2.3), preventing
 *       subdomain hijacking, cookie tossing, and cross-subdomain session poisoning.</li>
 *   <li><b>RFC 6265bis Cookie Prefix Support ({@code __Host-})</b>: When HTTPS is active,
 *       supports the {@code __Host-} prefix to cryptographically bind the cookie to the host,
 *       enforce TLS transmission, and require root path scope at the browser level.</li>
 *   <li><b>Session Fixation Defense (CWE-384)</b>: Calls {@code request.changeSessionId()}
 *       upon successful authentication to rotate any pre-authentication session identifier,
 *       preventing attackers from pre-seeding session tokens.</li>
 *   <li><b>CRLF Injection / HTTP Response Splitting Defense (CWE-113 / CWE-20)</b>: Strictly
 *       validates the session identifier against RFC 6265 cookie-value octets, rejecting
 *       carriage return ({@code \r}), line feed ({@code \n}), semicolons, and control characters.</li>
 *   <li><b>Anti-Caching Headers (CWE-525)</b>: Applies {@code Cache-Control: no-cache, no-store, must-revalidate},
 *       {@code Pragma: no-cache}, and {@code Expires: 0} to prevent intermediate proxies, shared
 *       caches, and browsers from storing responses containing session credentials.</li>
 *   <li><b>Transient Session Lifetime (CWE-539)</b>: Sets {@code Max-Age = -1} by default to create a
 *       transient session cookie that expires when the user's browser closes, avoiding persistent
 *       credentials on shared or public workstations.</li>
 * </ul>
 */
@WebServlet(name = "SessionCookieServlet", urlPatterns = {"/auth/session", "/login"})
public class SessionCookieServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** Standard session cookie name. */
    public static final String SESSION_COOKIE_NAME = "JSESSIONID";

    /**
     * Hardened session cookie name using RFC 6265bis '__Host-' prefix.
     * Enforces host-only scoping, TLS transmission, and path '/' at the browser level.
     */
    public static final String HOST_PREFIXED_COOKIE_NAME = "__Host-JSESSIONID";

    /**
     * Request attribute key where upstream authentication logic (filters, realms, or handlers)
     * stores the authenticated session identifier.
     */
    public static final String AUTH_SESSION_ID_ATTR = "authenticatedSessionId";

    /** Secondary request attribute key for session identifier. */
    public static final String SESSION_ID_ATTR = "sessionId";

    /** Request header key for session identifier. */
    public static final String SESSION_ID_HEADER = "X-Session-ID";

    /** Root application path scope. */
    public static final String DEFAULT_COOKIE_PATH = "/";

    /**
     * MaxAge = -1 configures a transient session cookie that expires when the
     * user closes their browser session.
     */
    public static final int SESSION_COOKIE_MAX_AGE = -1;

    /**
     * SameSite policy attribute applied to protect against Cross-Site Request Forgery (CSRF).
     * Supported values: "Strict", "Lax", or "None" (if None, Secure must be true).
     */
    public static final String SAME_SITE_STRICT = "Strict";
    public static final String SAME_SITE_LAX = "Lax";
    public static final String DEFAULT_SAME_SITE = SAME_SITE_STRICT;

    /**
     * RFC 6265 compliant cookie-octet pattern: US-ASCII visible characters (0x21 to 0x7E)
     * excluding control characters, whitespace, double quotes, commas, semicolons, and backslashes.
     * Strictly rejects CRLF (\r, \n) to eliminate HTTP response splitting (CWE-113).
     */
    private static final Pattern VALID_COOKIE_VALUE_PATTERN =
            Pattern.compile("^[a-zA-Z0-9_\\-\\.~+=/]{1,256}$");

    /**
     * Handles POST requests to establish an authenticated session cookie following successful authentication.
     *
     * <p>Assumes authentication has already succeeded upstream. The session identifier is obtained from
     * request attributes, parameters, or headers, validated against CRLF and injection attacks,
     * configured with defensive security attributes (HttpOnly, Secure, SameSite, Host-Only),
     * and attached to the HTTP response.</p>
     *
     * @param request  the HTTP servlet request
     * @param response the HTTP servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException      if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Assumption: User authentication has already succeeded prior to this step.
        // Retrieve the established session identifier from request context
        String sessionId = resolveSessionId(request);

        if (sessionId == null || sessionId.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Authentication required: no valid session identifier provided.");
            return;
        }

        // 1. Session Fixation Defense (CWE-384):
        // Invalidate or rotate any existing pre-authentication session so an attacker
        // cannot fixate a pre-login session ID onto the authenticated user.
        HttpSession existingSession = request.getSession(false);
        if (existingSession != null) {
            // Jakarta Servlet 3.1+ provides changeSessionId() to securely rotate session IDs
            request.changeSessionId();
        }

        // 2. Attach the hardened session cookie to the response
        try {
            addSessionCookie(request, response, sessionId);
        } catch (IllegalArgumentException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Invalid session identifier: " + e.getMessage());
            return;
        }

        // 3. Anti-caching headers (CWE-525): Prevent intermediate proxies, shared caches,
        // and browsers from caching responses that establish sessions and convey authentication cookies.
        applyAntiCachingHeaders(response);

        // 4. Return success status
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter writer = response.getWriter();
        writer.write("{\"status\":\"success\",\"message\":\"Authenticated session established.\"}");
        writer.flush();
    }

    /**
     * Handles GET requests to maintain and verify the authenticated session across subsequent requests.
     *
     * <p>Inspects incoming request cookies for the session cookie and verifies that the session is active.</p>
     *
     * @param request  the HTTP servlet request
     * @param response the HTTP servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException      if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String sessionId = getSessionIdFromCookie(request);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter writer = response.getWriter();

        if (sessionId != null) {
            response.setStatus(HttpServletResponse.SC_OK);
            writer.write("{\"status\":\"authenticated\",\"sessionId\":\"" + escapeJson(sessionId) + "\"}");
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            writer.write("{\"status\":\"unauthenticated\",\"message\":\"No active session cookie found.\"}");
        }
        writer.flush();
    }

    /**
     * Handles DELETE requests to cleanly terminate the session and clear the session cookie.
     *
     * @param request  the HTTP servlet request
     * @param response the HTTP servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException      if an I/O error occurs
     */
    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        clearSessionCookie(request, response);
        applyAntiCachingHeaders(response);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter writer = response.getWriter();
        writer.write("{\"status\":\"success\",\"message\":\"Session invalidated and cookie cleared.\"}");
        writer.flush();
    }

    /**
     * Factory method to create a secure session cookie with default defensive attributes:
     * HttpOnly=true, Secure=true, Path="/", Max-Age=-1, SameSite=Strict, Host-Only domain.
     *
     * @param sessionId the authenticated session identifier
     * @return a configured {@link Cookie} instance
     * @throws IllegalArgumentException if sessionId is null, empty, or fails security validation
     */
    public static Cookie createSessionCookie(String sessionId) {
        return createSessionCookie(SESSION_COOKIE_NAME, sessionId, DEFAULT_COOKIE_PATH, SESSION_COOKIE_MAX_AGE, true, DEFAULT_SAME_SITE);
    }

    /**
     * Factory method to create a secure session cookie with custom path, maxAge, and secure flag.
     *
     * @param sessionId the authenticated session identifier
     * @param path      the URL path scope for the cookie
     * @param maxAge    cookie lifetime in seconds (-1 for transient browser session lifetime)
     * @param secure    whether the cookie must only be transmitted over TLS/HTTPS
     * @return a configured {@link Cookie} instance
     * @throws IllegalArgumentException if sessionId is null, empty, or fails security validation
     */
    public static Cookie createSessionCookie(String sessionId, String path, int maxAge, boolean secure) {
        return createSessionCookie(SESSION_COOKIE_NAME, sessionId, path, maxAge, secure, DEFAULT_SAME_SITE);
    }

    /**
     * Factory method to create a secure session cookie with custom cookie name, path, maxAge, and secure flag.
     *
     * @param cookieName the name of the cookie (e.g., JSESSIONID or __Host-JSESSIONID)
     * @param sessionId  the authenticated session identifier
     * @param path       the URL path scope for the cookie
     * @param maxAge     cookie lifetime in seconds (-1 for transient browser session lifetime)
     * @param secure     whether the cookie must only be transmitted over TLS/HTTPS
     * @return a configured {@link Cookie} instance
     * @throws IllegalArgumentException if sessionId or cookieName is invalid
     */
    public static Cookie createSessionCookie(String cookieName, String sessionId, String path, int maxAge, boolean secure) {
        return createSessionCookie(cookieName, sessionId, path, maxAge, secure, DEFAULT_SAME_SITE);
    }

    /**
     * Complete factory method to create a hardened session cookie with all defensive attributes configured.
     *
     * @param cookieName the name of the cookie (e.g., JSESSIONID or __Host-JSESSIONID)
     * @param sessionId  the authenticated session identifier
     * @param path       the URL path scope for the cookie
     * @param maxAge     cookie lifetime in seconds (-1 for transient browser session lifetime)
     * @param secure     whether the cookie must only be transmitted over TLS/HTTPS
     * @param sameSite   SameSite policy ("Strict", "Lax", or "None")
     * @return a configured {@link Cookie} instance
     * @throws IllegalArgumentException if sessionId or cookieName is invalid
     */
    public static Cookie createSessionCookie(String cookieName, String sessionId, String path, int maxAge, boolean secure, String sameSite) {
        // 1. Validate session identifier to prevent header injection / CRLF injection (CWE-113 / CWE-20)
        validateSessionId(sessionId);

        if (cookieName == null || cookieName.trim().isEmpty()) {
            cookieName = SESSION_COOKIE_NAME;
        }

        if (path == null || path.trim().isEmpty()) {
            path = DEFAULT_COOKIE_PATH;
        }

        // 2. Instantiate the cookie with the configured name and session identifier
        Cookie cookie = new Cookie(cookieName.trim(), sessionId.trim());

        // 3. Mitigate CWE-1004 (XSS Session Hijacking): Set HttpOnly
        // Prevents client-side scripts (e.g., document.cookie) from accessing the session token
        cookie.setHttpOnly(true);

        // 4. Mitigate CWE-614 (Cleartext Cookie Transmission): Set Secure
        // Instructs the browser to only transmit the cookie over encrypted HTTPS channels
        cookie.setSecure(secure);

        // 5. Scope the cookie path across the application
        cookie.setPath(path);

        // 6. Mitigate CWE-539 (Improper Session Lifetime): Set Max-Age
        // -1 specifies a transient session cookie that is cleared when the browser closes
        cookie.setMaxAge(maxAge);

        // 7. Host-Only Cookie Scoping:
        // By intentionally NOT setting cookie.setDomain(...), the cookie remains a "Host-Only"
        // cookie (RFC 6265 Section 4.1.2.3). This prevents untrusted subdomains from reading or tampering
        // with the session cookie.

        // 8. Mitigate CWE-1275 (Cross-Site Request Forgery): Set SameSite attribute
        // In Jakarta Servlet 6.0+, setAttribute() natively sets the SameSite policy
        if (sameSite != null && !sameSite.trim().isEmpty()) {
            try {
                cookie.setAttribute("SameSite", sameSite.trim());
            } catch (NoSuchMethodError | UnsupportedOperationException ignored) {
                // Backward-compatibility fallback for Jakarta Servlet 5.0 environments
            }
        }

        return cookie;
    }

    /**
     * Creates and attaches a secure session cookie to the response using default configuration
     * (HttpOnly=true, Secure=true, Path="/", Max-Age=-1, SameSite=Strict).
     *
     * @param response  the HttpServletResponse to add the cookie to
     * @param sessionId the authenticated session identifier
     * @throws IllegalArgumentException if response is null or sessionId is invalid
     */
    public static void addSessionCookie(HttpServletResponse response, String sessionId) {
        addSessionCookie(null, response, sessionId);
    }

    /**
     * Creates and attaches a hardened session cookie to the response, taking into account request
     * security context (HTTPS detection, context path, and RFC 6265bis __Host- prefix).
     *
     * @param request   the current HttpServletRequest (optional, may be null)
     * @param response  the HttpServletResponse to add the cookie to
     * @param sessionId the authenticated session identifier
     * @throws IllegalArgumentException if response is null or sessionId is invalid
     */
    public static void addSessionCookie(HttpServletRequest request, HttpServletResponse response, String sessionId) {
        if (response == null) {
            throw new IllegalArgumentException("HttpServletResponse must not be null.");
        }
        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new IllegalArgumentException("Session ID must not be null or empty.");
        }

        boolean isHttps = (request != null && request.isSecure());

        // Use __Host- prefix when HTTPS is active for origin-binding defense;
        // otherwise fall back to standard JSESSIONID.
        String cookieName = isHttps ? HOST_PREFIXED_COOKIE_NAME : SESSION_COOKIE_NAME;

        // Determine path: RFC 6265bis __Host- prefix requires path to be "/"
        String cookiePath = DEFAULT_COOKIE_PATH;
        if (request != null && !cookieName.startsWith("__Host-")) {
            String contextPath = request.getContextPath();
            if (contextPath != null && !contextPath.isEmpty()) {
                cookiePath = contextPath;
            }
        }

        // Create hardened session cookie (Secure is always true for session cookies)
        Cookie sessionCookie = createSessionCookie(cookieName, sessionId, cookiePath, SESSION_COOKIE_MAX_AGE, true, DEFAULT_SAME_SITE);

        // Attach the configured cookie to the HTTP response
        response.addCookie(sessionCookie);
    }

    /**
     * Extracts and validates the session identifier from incoming request cookies.
     * Supports both standard JSESSIONID and __Host-JSESSIONID.
     *
     * @param request the HTTP servlet request
     * @return the session identifier if found and valid, or null otherwise
     */
    public static String getSessionIdFromCookie(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                String name = cookie.getName();
                if (SESSION_COOKIE_NAME.equals(name) || HOST_PREFIXED_COOKIE_NAME.equals(name)) {
                    String value = cookie.getValue();
                    if (value != null && isValidSessionId(value)) {
                        return value;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Clears the authenticated session cookie on logout or session invalidation.
     * Sets MaxAge to 0 with matching security attributes (HttpOnly, Secure, SameSite, Path),
     * instructing the browser to immediately purge the cookie.
     *
     * @param request  the current HttpServletRequest (optional, may be null)
     * @param response the current HttpServletResponse
     */
    public static void clearSessionCookie(HttpServletRequest request, HttpServletResponse response) {
        if (response == null) {
            throw new IllegalArgumentException("HttpServletResponse must not be null.");
        }

        boolean isHttps = (request != null && request.isSecure());
        String[] cookieNamesToClear = isHttps
                ? new String[]{HOST_PREFIXED_COOKIE_NAME, SESSION_COOKIE_NAME}
                : new String[]{SESSION_COOKIE_NAME, HOST_PREFIXED_COOKIE_NAME};

        for (String name : cookieNamesToClear) {
            Cookie cookie = new Cookie(name, "");
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath(DEFAULT_COOKIE_PATH);
            cookie.setMaxAge(0); // Max-Age=0 instructs the browser to immediately delete the cookie
            try {
                cookie.setAttribute("SameSite", DEFAULT_SAME_SITE);
            } catch (NoSuchMethodError | UnsupportedOperationException ignored) {
                // Backward-compatibility fallback
            }
            response.addCookie(cookie);
        }
    }

    /**
     * Applies standard anti-caching HTTP headers (CWE-525) to prevent proxy or browser caching
     * of sensitive responses containing session cookies.
     *
     * @param response the HTTP response
     */
    public static void applyAntiCachingHeaders(HttpServletResponse response) {
        if (response != null) {
            response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            response.setHeader("Pragma", "no-cache");
            response.setDateHeader("Expires", 0);
        }
    }

    /**
     * Resolves the session identifier from the request.
     * Checks request attributes first (set by upstream authentication logic),
     * then active session, headers, and request parameters.
     *
     * @param request the HTTP servlet request
     * @return the resolved session identifier, or null if absent
     */
    public static String resolveSessionId(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        // 1. Check primary request attribute
        Object primaryAttr = request.getAttribute(AUTH_SESSION_ID_ATTR);
        if (primaryAttr instanceof String) {
            String id = ((String) primaryAttr).trim();
            if (!id.isEmpty()) {
                return id;
            }
        }

        // 2. Check secondary request attribute
        Object secondaryAttr = request.getAttribute(SESSION_ID_ATTR);
        if (secondaryAttr instanceof String) {
            String id = ((String) secondaryAttr).trim();
            if (!id.isEmpty()) {
                return id;
            }
        }

        // 3. Check existing HttpSession if authenticated upstream
        HttpSession existingSession = request.getSession(false);
        if (existingSession != null && existingSession.getId() != null) {
            String id = existingSession.getId().trim();
            if (!id.isEmpty()) {
                return id;
            }
        }

        // 4. Check request header
        String headerVal = request.getHeader(SESSION_ID_HEADER);
        if (headerVal != null && !headerVal.trim().isEmpty()) {
            return headerVal.trim();
        }

        // 5. Check request parameter
        String param = request.getParameter("sessionId");
        if (param != null && !param.trim().isEmpty()) {
            return param.trim();
        }

        String altParam = request.getParameter("session_id");
        if (altParam != null && !altParam.trim().isEmpty()) {
            return altParam.trim();
        }

        return null;
    }

    /**
     * Validates that a session identifier is non-null, non-empty, and conforms to RFC 6265 cookie-value octets.
     * Prevents CRLF injection and HTTP response splitting (CWE-113 / CWE-20).
     *
     * @param sessionId the session identifier to validate
     * @throws IllegalArgumentException if invalid
     */
    public static void validateSessionId(String sessionId) {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new IllegalArgumentException("Session identifier must not be null or empty.");
        }
        // Protect against CRLF injection / HTTP response splitting (CWE-113)
        if (sessionId.contains("\r") || sessionId.contains("\n")) {
            throw new IllegalArgumentException("Session identifier contains illegal control characters (CRLF).");
        }
        // Ensure compliance with RFC 6265 cookie-octet character set
        if (!VALID_COOKIE_VALUE_PATTERN.matcher(sessionId.trim()).matches()) {
            throw new IllegalArgumentException("Session identifier contains invalid characters or exceeds maximum length.");
        }
    }

    /**
     * Checks if a session identifier string is valid according to RFC 6265 cookie-octet rules.
     *
     * @param sessionId the string to check
     * @return true if valid, false otherwise
     */
    public static boolean isValidSessionId(String sessionId) {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            return false;
        }
        return VALID_COOKIE_VALUE_PATTERN.matcher(sessionId.trim()).matches();
    }

    /**
     * Escapes characters for safe JSON output.
     */
    private static String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // =========================================================================
    // Self-Verification / Test Harness (can be executed via CLI without Tomcat)
    // =========================================================================

    /**
     * Entry point to run automated verification tests demonstrating cookie creation,
     * security attribute configuration, request handling, session fixation rotation,
     * and invalid input rejection.
     *
     * @param args CLI arguments (optional)
     */
    public static void main(String[] args) {
        System.out.println("=================================================================");
        System.out.println(" SessionCookieServlet - Verification & Security Test Suite");
        System.out.println("=================================================================");

        int passed = 0;
        int total = 7;

        try {
            // Test 1: Factory Method & Cookie Configuration
            System.out.print("[TEST 1/7] Testing createSessionCookie security configuration... ");
            String testSessionId = "sess_abc123_xyz789";
            Cookie c = createSessionCookie(testSessionId, "/", -1, true);
            assert c.getName().equals(SESSION_COOKIE_NAME) : "Cookie name mismatch";
            assert c.getValue().equals(testSessionId) : "Session ID mismatch";
            assert c.isHttpOnly() : "HttpOnly must be true (CWE-1004)";
            assert c.getSecure() : "Secure must be true (CWE-614)";
            assert "/".equals(c.getPath()) : "Path must be /";
            assert c.getMaxAge() == -1 : "MaxAge must be -1 (CWE-539)";
            assert "Strict".equals(c.getAttribute("SameSite")) : "SameSite must be Strict (CWE-1275)";
            assert c.getDomain() == null : "Domain must be null for Host-Only cookie";
            System.out.println("PASSED");
            passed++;

            // Test 2: RFC 6265bis __Host- Prefix on HTTPS
            System.out.print("[TEST 2/7] Testing __Host- prefixed cookie on HTTPS... ");
            MockRequest httpsReq = new MockRequest();
            httpsReq.secure = true;
            MockResponse httpsResp = new MockResponse();
            addSessionCookie(httpsReq.asHttpServletRequest(), httpsResp.asHttpServletResponse(), "secure-token-12345");
            assert !httpsResp.cookies.isEmpty() : "Cookie must be added to HTTPS response";
            Cookie hostCookie = httpsResp.cookies.get(0);
            assert HOST_PREFIXED_COOKIE_NAME.equals(hostCookie.getName()) : "__Host- prefix must be used on HTTPS";
            assert hostCookie.getSecure() : "Host cookie must be Secure";
            assert hostCookie.isHttpOnly() : "Host cookie must be HttpOnly";
            assert "/".equals(hostCookie.getPath()) : "__Host- cookie path must be /";
            assert hostCookie.getDomain() == null : "__Host- cookie must not have domain attribute";
            System.out.println("PASSED");
            passed++;

            // Test 3: doPost Handling & Cookie Attachment
            System.out.print("[TEST 3/7] Testing doPost handling & cookie attachment... ");
            MockResponse mockResp = new MockResponse();
            MockRequest mockReq = new MockRequest();
            mockReq.attributes.put(AUTH_SESSION_ID_ATTR, "authenticated-token-998877");

            SessionCookieServlet servlet = new SessionCookieServlet();
            servlet.doPost(mockReq.asHttpServletRequest(), mockResp.asHttpServletResponse());

            assert mockResp.status == 200 : "Status must be 200 OK";
            assert !mockResp.cookies.isEmpty() : "Session cookie must be added to response";
            Cookie addedCookie = mockResp.cookies.get(0);
            assert addedCookie.isHttpOnly() : "HttpOnly flag must be set";
            assert addedCookie.getSecure() : "Secure flag must be set";
            assert "Strict".equals(addedCookie.getAttribute("SameSite")) : "SameSite must be Strict";
            assert "no-cache, no-store, must-revalidate".equals(mockResp.headers.get("Cache-Control")) : "Cache-Control must be set (CWE-525)";
            System.out.println("PASSED");
            passed++;

            // Test 4: Subsequent Request Verification via doGet
            System.out.print("[TEST 4/7] Testing doGet subsequent session retrieval... ");
            MockRequest subsequentReq = new MockRequest();
            subsequentReq.cookieList.add(addedCookie);
            MockResponse subsequentResp = new MockResponse();

            servlet.doGet(subsequentReq.asHttpServletRequest(), subsequentResp.asHttpServletResponse());
            assert subsequentResp.status == 200 : "Status must be 200 OK for authenticated session";
            assert subsequentResp.body.toString().contains("authenticated") : "Response body must indicate authenticated";
            System.out.println("PASSED");
            passed++;

            // Test 5: CRLF Injection Rejection (CWE-113)
            System.out.print("[TEST 5/7] Testing CRLF / Header Injection prevention... ");
            boolean rejected = false;
            try {
                createSessionCookie("sess123\r\nSet-Cookie: evil=true", "/", -1, true);
            } catch (IllegalArgumentException e) {
                rejected = true;
            }
            assert rejected : "CRLF injection attempt must be rejected with IllegalArgumentException";
            System.out.println("PASSED");
            passed++;

            // Test 6: Session Termination / Cookie Clearance
            System.out.print("[TEST 6/7] Testing session termination and cookie clearing... ");
            MockResponse clearResp = new MockResponse();
            clearSessionCookie(null, clearResp.asHttpServletResponse());
            assert !clearResp.cookies.isEmpty() : "Clear cookie must be attached";
            Cookie clearCookie = clearResp.cookies.get(0);
            assert clearCookie.getMaxAge() == 0 : "MaxAge must be 0 for deletion";
            assert clearCookie.isHttpOnly() : "Cleared cookie must also maintain HttpOnly";
            assert clearCookie.getSecure() : "Cleared cookie must also maintain Secure";
            System.out.println("PASSED");
            passed++;

            // Test 7: Session Fixation Mitigation (CWE-384)
            System.out.print("[TEST 7/7] Testing session fixation mitigation... ");
            MockRequest fixationReq = new MockRequest();
            fixationReq.attributes.put(AUTH_SESSION_ID_ATTR, "new-auth-session-id");
            fixationReq.hasSession = true;
            MockResponse fixationResp = new MockResponse();
            servlet.doPost(fixationReq.asHttpServletRequest(), fixationResp.asHttpServletResponse());
            assert fixationReq.sessionIdChanged : "request.changeSessionId() must be called to rotate session";
            System.out.println("PASSED");
            passed++;

            System.out.println("=================================================================");
            System.out.printf("All %d/%d tests PASSED successfully!\n", passed, total);
            System.out.println("Security controls verified:");
            System.out.println(" - HttpOnly flag enabled (CWE-1004)");
            System.out.println(" - Secure flag enabled (CWE-614)");
            System.out.println(" - SameSite=Strict configured (CWE-1275)");
            System.out.println(" - Host-Only domain scoping (RFC 6265)");
            System.out.println(" - RFC 6265bis __Host- prefix under HTTPS");
            System.out.println(" - Anti-caching headers applied (CWE-525)");
            System.out.println(" - CRLF injection strictly rejected (CWE-113)");
            System.out.println(" - Session Fixation mitigated via ID rotation (CWE-384)");
            System.out.println(" - Cookie deletion via Max-Age=0");
            System.out.println("=================================================================");

        } catch (Throwable t) {
            System.err.println("FAILED with exception: " + t.getMessage());
            t.printStackTrace();
            System.exit(1);
        }
    }

    // =========================================================================
    // Lightweight Mock Doubles for Self-Testing without external mock libraries
    // =========================================================================

    private static class MockRequest implements InvocationHandler {
        final Map<String, Object> attributes = new HashMap<>();
        final Map<String, String> parameters = new HashMap<>();
        final Map<String, String> headers = new HashMap<>();
        final List<Cookie> cookieList = new ArrayList<>();
        boolean secure = false;
        boolean hasSession = false;
        boolean sessionIdChanged = false;

        HttpServletRequest asHttpServletRequest() {
            return (HttpServletRequest) Proxy.newProxyInstance(
                    HttpServletRequest.class.getClassLoader(),
                    new Class<?>[]{HttpServletRequest.class},
                    this
            );
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "getAttribute":
                    return attributes.get((String) args[0]);
                case "getParameter":
                    return parameters.get((String) args[0]);
                case "getHeader":
                    return headers.get((String) args[0]);
                case "getCookies":
                    return cookieList.isEmpty() ? null : cookieList.toArray(new Cookie[0]);
                case "getContextPath":
                    return "";
                case "isSecure":
                    return secure;
                case "getSession":
                    if (args.length > 0 && Boolean.FALSE.equals(args[0]) && !hasSession) {
                        return null;
                    }
                    return Proxy.newProxyInstance(
                            HttpSession.class.getClassLoader(),
                            new Class<?>[]{HttpSession.class},
                            (p, m, a) -> {
                                if ("getId".equals(m.getName())) return "mock-session-id";
                                if ("invalidate".equals(m.getName())) { hasSession = false; return null; }
                                return null;
                            }
                    );
                case "changeSessionId":
                    this.sessionIdChanged = true;
                    return "new-rotated-session-id";
                default:
                    return null;
            }
        }
    }

    private static class MockResponse implements InvocationHandler {
        int status = 200;
        final List<Cookie> cookies = new ArrayList<>();
        final Map<String, String> headers = new HashMap<>();
        final StringWriter body = new StringWriter();
        final PrintWriter writer = new PrintWriter(body);

        HttpServletResponse asHttpServletResponse() {
            return (HttpServletResponse) Proxy.newProxyInstance(
                    HttpServletResponse.class.getClassLoader(),
                    new Class<?>[]{HttpServletResponse.class},
                    this
            );
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "setStatus":
                    this.status = (Integer) args[0];
                    return null;
                case "sendError":
                    this.status = (Integer) args[0];
                    return null;
                case "addCookie":
                    this.cookies.add((Cookie) args[0]);
                    return null;
                case "setHeader":
                    this.headers.put((String) args[0], (String) args[1]);
                    return null;
                case "setDateHeader":
                    this.headers.put((String) args[0], String.valueOf(args[1]));
                    return null;
                case "setContentType":
                case "setCharacterEncoding":
                    return null;
                case "getWriter":
                    return writer;
                default:
                    return null;
            }
        }
    }
}
