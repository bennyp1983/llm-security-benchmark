package com.employee.portal.security;

import com.employee.portal.security.config.SecurityConfig;
import com.employee.portal.security.crypto.PasswordHasher;
import com.employee.portal.security.crypto.SecureTokenGenerator;
import com.employee.portal.security.logging.AuditLogger;
import com.employee.portal.security.ratelimit.RateLimiter;
import com.employee.portal.security.repository.FileEmployeeRepository;
import com.employee.portal.security.service.AuthenticationService;
import com.employee.portal.security.session.SessionManager;
import com.employee.portal.security.web.PortalServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Rule 4, 6 & 8: HTTP Portal Endpoints and Cookie Security Tests")
class PortalHttpHandlerTest {

    @TempDir
    Path tempDir;

    private PortalServer portalServer;
    private int port;
    private HttpClient httpClient;
    private AuthenticationService authService;

    @BeforeEach
    void setUp() throws IOException {
        SecurityConfig config = new SecurityConfig(
                5, 10,
                15 * 60_000L,
                15 * 60_000L,
                15 * 60_000L,
                480 * 60_000L,
                5, 1000,
                100000,
                tempDir
        );
        FileEmployeeRepository repository = new FileEmployeeRepository(tempDir.resolve("employees.db"));
        PasswordHasher hasher = new PasswordHasher(100000, 32, 256);
        RateLimiter rateLimiter = new RateLimiter(config);
        SessionManager sessionManager = new SessionManager(config);
        AuditLogger auditLogger = new AuditLogger(tempDir.resolve("audit.log"), false);

        authService = new AuthenticationService(
                config, repository, hasher, rateLimiter, sessionManager, auditLogger, false);

        authService.enrollEmployee("alice", "AliceSecurePass#2026".toCharArray(), "HR_MANAGER");

        // Start server on port 0 for random free port
        portalServer = new PortalServer(0, authService, false);
        portalServer.start();
        port = portalServer.getPort();

        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    @AfterEach
    void tearDown() {
        if (portalServer != null) {
            portalServer.stop();
        }
    }

    @Test
    void testLoginSuccessSetsSecureCookieAndAllowsDashboardAccess() throws Exception {
        String formBody = "username=alice&password=AliceSecurePass%232026";
        HttpRequest loginReq = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody))
                .build();

        HttpResponse<String> loginRes = httpClient.send(loginReq, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, loginRes.statusCode());
        assertTrue(loginRes.body().contains("\"status\":\"success\""));

        // Verify security response headers
        assertEquals("nosniff", loginRes.headers().firstValue("X-Content-Type-Options").orElse(""));
        assertEquals("DENY", loginRes.headers().firstValue("X-Frame-Options").orElse(""));
        assertTrue(loginRes.headers().firstValue("Content-Security-Policy").orElse("").contains("default-src 'none'"));

        // Verify Set-Cookie header compliance with Rule 4
        String setCookie = loginRes.headers().firstValue("Set-Cookie").orElse("");
        assertFalse(setCookie.isEmpty());
        assertTrue(setCookie.contains("HttpOnly"));
        assertTrue(setCookie.contains("SameSite=Strict"));
        assertTrue(setCookie.contains("Path=/"));

        // Extract cookie value for subsequent authenticated dashboard request
        String cookieVal = setCookie.split(";")[0];

        HttpRequest dashReq = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/dashboard"))
                .header("Cookie", cookieVal)
                .GET()
                .build();

        HttpResponse<String> dashRes = httpClient.send(dashReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, dashRes.statusCode());
        assertTrue(dashRes.body().contains("\"status\":\"active\""));
        assertTrue(dashRes.body().contains("alice"));
        assertTrue(dashRes.body().contains("HR_MANAGER"));
    }

    @Test
    void testLoginFailureReturns401WithGenericMessage() throws Exception {
        String formBody = "username=alice&password=WrongPassword%21%21";
        HttpRequest loginReq = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody))
                .build();

        HttpResponse<String> loginRes = httpClient.send(loginReq, HttpResponse.BodyHandlers.ofString());

        assertEquals(401, loginRes.statusCode());
        assertTrue(loginRes.body().contains("\"status\":\"error\""));
        assertTrue(loginRes.body().contains("Invalid username or password or account temporarily restricted"));
    }

    @Test
    void testDashboardWithoutCookieFailsWith401() throws Exception {
        HttpRequest dashReq = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/dashboard"))
                .GET()
                .build();

        HttpResponse<String> dashRes = httpClient.send(dashReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, dashRes.statusCode());
    }

    @Test
    void testLogoutRevokesSessionAndInvalidatesCookie() throws Exception {
        // Step 1: Login
        String formBody = "username=alice&password=AliceSecurePass%232026";
        HttpRequest loginReq = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody))
                .build();
        HttpResponse<String> loginRes = httpClient.send(loginReq, HttpResponse.BodyHandlers.ofString());
        String setCookie = loginRes.headers().firstValue("Set-Cookie").orElseThrow();
        String cookieVal = setCookie.split(";")[0];

        // Step 2: Logout
        HttpRequest logoutReq = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/logout"))
                .header("Cookie", cookieVal)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> logoutRes = httpClient.send(logoutReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, logoutRes.statusCode());
        String logoutSetCookie = logoutRes.headers().firstValue("Set-Cookie").orElse("");
        assertTrue(logoutSetCookie.contains("Max-Age=0"));

        // Step 3: Access dashboard with former session cookie must now be rejected
        HttpRequest dashReq = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/dashboard"))
                .header("Cookie", cookieVal)
                .GET()
                .build();
        HttpResponse<String> dashRes = httpClient.send(dashReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, dashRes.statusCode());
    }
}
