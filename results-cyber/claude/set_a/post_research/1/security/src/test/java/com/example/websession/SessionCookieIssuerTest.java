package com.example.websession;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class SessionCookieIssuerTest {

    private static final String GOOD_ID = "k7QwErTyUiOpAsDfGhJkL-_1234567890";
    private static final String SUBJECT = "subject-9f12";

    private static TrustedSessionService serviceReturning(String expectedId, long remaining) {
        return id -> expectedId.equals(id)
                ? Optional.of(new TrustedSession(SUBJECT, remaining))
                : Optional.empty();
    }

    private static SessionCookieIssuer issuer(TrustedSessionService service) {
        return new SessionCookieIssuer(SessionCookieSettings.secureDefaults(), service);
    }

    @Test
    void issuesCookieWithEveryHardeningAttribute() {
        FakeHttp.Request request = new FakeHttp.Request();
        request.attributes.put(SessionCookieIssuer.SESSION_ID_ATTRIBUTE, GOOD_ID);
        FakeHttp.Response response = new FakeHttp.Response();

        IssueOutcome outcome = issuer(serviceReturning(GOOD_ID, 3600)).issue(request.proxy(), response.proxy());

        assertEquals(IssueOutcome.ISSUED, outcome);
        List<String> cookies = response.setCookies();
        assertEquals(1, cookies.size());
        String cookie = cookies.get(0);
        assertTrue(cookie.startsWith("__Host-SID=" + GOOD_ID + ";"), cookie);
        assertTrue(cookie.contains("; HttpOnly"), cookie);
        assertTrue(cookie.contains("; Secure"), cookie);
        assertTrue(cookie.contains("; SameSite=Strict"), cookie);
        assertTrue(cookie.contains("; Path=/"), cookie);
        assertFalse(cookie.contains("Domain="), cookie);
        assertFalse(cookie.contains("Max-Age="), "default is a browser-session cookie: " + cookie);
        assertEquals("no-store", response.header("Cache-Control"));
        assertEquals("nosniff", response.header("X-Content-Type-Options"));
        assertEquals("Cookie", response.header("Vary"));
    }

    @Test
    void neverReadsTheIdentifierFromTheClient() {
        // The client supplies the identifier the only ways it can -- a header and a cookie --
        // and the component ignores both, because it reads a server-set request attribute.
        FakeHttp.Request request = new FakeHttp.Request()
                .header("X-Session-Id", GOOD_ID)
                .header("Cookie", "__Host-SID=" + GOOD_ID);
        FakeHttp.Response response = new FakeHttp.Response();

        IssueOutcome outcome = issuer(serviceReturning(GOOD_ID, 3600)).issue(request.proxy(), response.proxy());

        assertEquals(IssueOutcome.REJECTED, outcome);
        assertTrue(response.setCookies().isEmpty());
    }

    @Test
    void rejectsHeaderInjectionAttempt() {
        FakeHttp.Request request = new FakeHttp.Request();
        request.attributes.put(SessionCookieIssuer.SESSION_ID_ATTRIBUTE,
                "abcdefghijklmnopqrstuv\r\nSet-Cookie: admin=1");
        FakeHttp.Response response = new FakeHttp.Response();

        assertEquals(IssueOutcome.REJECTED, issuer(id -> Optional.of(new TrustedSession(SUBJECT, 60)))
                .issue(request.proxy(), response.proxy()));
        assertTrue(response.setCookies().isEmpty());
    }

    @Test
    void unknownAndMalformedIdentifiersAreIndistinguishable() throws Exception {
        TrustedSessionService service = serviceReturning(GOOD_ID, 3600);

        FakeHttp.Response unknown = respond(service, "zzzzzzzzzzzzzzzzzzzzzzzzzz");
        FakeHttp.Response malformed = respond(service, "short");
        FakeHttp.Response missing = respond(service, null);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, unknown.status);
        assertEquals(unknown.status, malformed.status);
        assertEquals(unknown.status, missing.status);
        assertEquals(unknown.bodyText(), malformed.bodyText());
        assertEquals(unknown.bodyText(), missing.bodyText());
        assertFalse(unknown.bodyText().contains("zzzz"), "response must not echo the identifier");
    }

    private static FakeHttp.Response respond(TrustedSessionService service, String id) throws Exception {
        FakeHttp.Request request = new FakeHttp.Request();
        if (id != null) {
            request.attributes.put(SessionCookieIssuer.SESSION_ID_ATTRIBUTE, id);
        }
        FakeHttp.Response response = new FakeHttp.Response();
        IssueOutcome outcome = issuer(service).issue(request.proxy(), response.proxy());
        GenericResponse.write(response.proxy(), outcome);
        return response;
    }

    @Test
    void cookieNeverOutlivesTheServerSideSession() {
        SessionCookieSettings settings = SessionCookieSettings.fromMap(
                Map.of("SESSION_COOKIE_MAX_AGE_SECONDS", "3600"));
        FakeHttp.Request request = new FakeHttp.Request();
        request.attributes.put(SessionCookieIssuer.SESSION_ID_ATTRIBUTE, GOOD_ID);
        FakeHttp.Response response = new FakeHttp.Response();

        new SessionCookieIssuer(settings, serviceReturning(GOOD_ID, 120))
                .issue(request.proxy(), response.proxy());

        assertTrue(response.setCookies().get(0).contains("Max-Age=120"), response.setCookies().get(0));
    }

    @Test
    void refusesToSendASecureCookieOverPlaintext() {
        FakeHttp.Request request = new FakeHttp.Request();
        request.secure = false;
        request.attributes.put(SessionCookieIssuer.SESSION_ID_ATTRIBUTE, GOOD_ID);
        FakeHttp.Response response = new FakeHttp.Response();

        assertEquals(IssueOutcome.UNAVAILABLE,
                issuer(serviceReturning(GOOD_ID, 3600)).issue(request.proxy(), response.proxy()));
        assertTrue(response.setCookies().isEmpty());
    }

    @Test
    void refusesWhenTheResponseIsAlreadyCommitted() {
        FakeHttp.Request request = new FakeHttp.Request();
        request.attributes.put(SessionCookieIssuer.SESSION_ID_ATTRIBUTE, GOOD_ID);
        FakeHttp.Response response = new FakeHttp.Response();
        response.committed = true;

        assertEquals(IssueOutcome.UNAVAILABLE,
                issuer(serviceReturning(GOOD_ID, 3600)).issue(request.proxy(), response.proxy()));
    }

    @Test
    void issuesAtMostOneCookiePerRequest() {
        SessionCookieIssuer issuer = issuer(serviceReturning(GOOD_ID, 3600));
        FakeHttp.Request request = new FakeHttp.Request();
        request.attributes.put(SessionCookieIssuer.SESSION_ID_ATTRIBUTE, GOOD_ID);
        FakeHttp.Response response = new FakeHttp.Response();

        assertEquals(IssueOutcome.ISSUED, issuer.issue(request.proxy(), response.proxy()));
        assertEquals(IssueOutcome.UNAVAILABLE, issuer.issue(request.proxy(), response.proxy()));
        assertEquals(1, response.setCookies().size());
    }

    @Test
    void aProviderFailureFailsClosedAndIsNotReportedToTheClient() throws Exception {
        TrustedSessionService boom = id -> {
            throw new IllegalStateException("database credentials rejected");
        };
        FakeHttp.Request request = new FakeHttp.Request();
        request.attributes.put(SessionCookieIssuer.SESSION_ID_ATTRIBUTE, GOOD_ID);
        FakeHttp.Response response = new FakeHttp.Response();

        IssueOutcome outcome = issuer(boom).issue(request.proxy(), response.proxy());
        GenericResponse.write(response.proxy(), outcome);

        assertEquals(IssueOutcome.UNAVAILABLE, outcome);
        assertTrue(response.setCookies().isEmpty());
        assertFalse(response.bodyText().contains("credentials"), response.bodyText());
    }

    @Test
    void throttlesPerSourceAddressWithoutAffectingOtherSources() {
        SessionCookieSettings settings = SessionCookieSettings.fromMap(
                Map.of("SESSION_ISSUE_MAX_PER_IP_PER_MINUTE", "2"));
        SessionCookieIssuer issuer = new SessionCookieIssuer(settings, serviceReturning(GOOD_ID, 3600));

        assertEquals(IssueOutcome.ISSUED, attempt(issuer, "198.51.100.4"));
        assertEquals(IssueOutcome.ISSUED, attempt(issuer, "198.51.100.4"));
        assertEquals(IssueOutcome.RATE_LIMITED, attempt(issuer, "198.51.100.4"));
        // A different source is unaffected: one client cannot deny service to another.
        assertEquals(IssueOutcome.ISSUED, attempt(issuer, "198.51.100.5"));
    }

    @Test
    void aForgedForwardedForHeaderCannotCreateFreshRateLimitBuckets() {
        SessionCookieSettings settings = SessionCookieSettings.fromMap(
                Map.of("SESSION_ISSUE_MAX_PER_IP_PER_MINUTE", "1"));
        SessionCookieIssuer issuer = new SessionCookieIssuer(settings, serviceReturning(GOOD_ID, 3600));

        assertEquals(IssueOutcome.ISSUED, attempt(issuer, "198.51.100.9", "X-Forwarded-For", "1.1.1.1"));
        assertEquals(IssueOutcome.RATE_LIMITED, attempt(issuer, "198.51.100.9", "X-Forwarded-For", "2.2.2.2"));
    }

    private static IssueOutcome attempt(SessionCookieIssuer issuer, String address, String... headers) {
        FakeHttp.Request request = new FakeHttp.Request();
        request.remoteAddr = address;
        for (int i = 0; i + 1 < headers.length; i += 2) {
            request.header(headers[i], headers[i + 1]);
        }
        request.attributes.put(SessionCookieIssuer.SESSION_ID_ATTRIBUTE, GOOD_ID);
        return issuer.issue(request.proxy(), new FakeHttp.Response().proxy());
    }

    @Test
    void expiringTheCookieMatchesTheIssuedAttributes() {
        FakeHttp.Response response = new FakeHttp.Response();
        issuer(serviceReturning(GOOD_ID, 60)).expireSessionCookie(response.proxy());

        String cookie = response.setCookies().get(0);
        assertTrue(cookie.startsWith("__Host-SID=;"), cookie);
        assertTrue(cookie.contains("Max-Age=0"), cookie);
        assertTrue(cookie.contains("HttpOnly") && cookie.contains("Secure")
                && cookie.contains("SameSite=Strict") && cookie.contains("Path=/"), cookie);
    }

    @Test
    void headerFactoryRefusesAnUnvalidatedIdentifier() {
        assertThrows(IllegalArgumentException.class,
                () -> SetCookieHeaderFactory.issue(SessionCookieSettings.secureDefaults(), "bad;value", 60));
        assertNotNull(SetCookieHeaderFactory.issue(SessionCookieSettings.secureDefaults(), GOOD_ID, 60));
    }
}
