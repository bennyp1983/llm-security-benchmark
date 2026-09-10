## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** TEXT_FALLBACK
- **Output format:** text_fallback
- **Conversation ID:** 
- **Input tokens:** 
- **Output tokens:** 
- **Thinking tokens:** 
- **Cached read tokens:** 
- **Cache creation tokens:** 
- **Total tokens:** 
- **Duration:** 
- **Turns:** 

---

# Session cookie after successful authentication (Jakarta Servlet)

Authentication is assumed to have already succeeded and the session identifier is assumed to be
provided; this code only publishes it as a cookie on the HTTP response so the authenticated session
survives across subsequent requests.

Files added:

    pom.xml
    src/main/java/com/example/auth/SessionCookieFactory.java
    src/main/java/com/example/auth/AuthenticatedSessionServlet.java
    src/test/java/com/example/auth/SessionCookieIssuanceTest.java

====================================================================================================
src/main/java/com/example/auth/SessionCookieFactory.java
====================================================================================================

package com.example.auth;

import java.util.regex.Pattern;

import jakarta.servlet.http.Cookie;

/**
 * Builds the cookie that carries an already-authenticated session identifier to the client.
 *
 * <p>The identifier is never generated here: authentication happens elsewhere and the resulting
 * value is handed to {@link #forSession(String)}.
 *
 * <p>The cookie is written with {@code HttpOnly} (no script access), {@code Secure} (HTTPS only)
 * and {@code Path=/} so it is sent with every request of the application. {@code SameSite} is not
 * part of the Servlet 6.0 cookie model - configure it at the container, e.g. Tomcat
 * {@code <CookieProcessor sameSiteCookies="Lax"/>}, or use {@code Cookie.setAttribute} once the
 * application runs on Servlet 6.1.
 */
public final class SessionCookieFactory {

    /** Distinct from the container-managed {@code JSESSIONID} so the two never overwrite each other. */
    public static final String DEFAULT_COOKIE_NAME = "APP_SESSION";

    public static final String DEFAULT_PATH = "/";

    /** Negative means no {@code Max-Age} attribute, which makes the cookie a browser-session cookie. */
    public static final int DEFAULT_MAX_AGE_SECONDS = -1;

    /**
     * RFC 6265 cookie-value octets. Rejecting anything else keeps a hostile identifier from
     * breaking out of the {@code Set-Cookie} header and blocks header injection outright.
     */
    private static final Pattern SESSION_ID_PATTERN = Pattern.compile("[\\x21\\x23-\\x2B\\x2D-\\x3A\\x3C-\\x5B\\x5D-\\x7E]+");

    private final String name;
    private final String path;
    private final int maxAgeSeconds;
    private final boolean secure;

    public SessionCookieFactory() {
        this(DEFAULT_COOKIE_NAME, DEFAULT_PATH, DEFAULT_MAX_AGE_SECONDS, true);
    }

    public SessionCookieFactory(String name, String path, int maxAgeSeconds, boolean secure) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("cookie name must not be blank");
        }
        if (path == null || !(path.equals("/") || (path.length() > 1 && path.startsWith("/")))) {
            throw new IllegalArgumentException("cookie path must be absolute: " + path);
        }
        this.name = name;
        this.path = path;
        this.maxAgeSeconds = maxAgeSeconds;
        this.secure = secure;
    }

    /**
     * @param sessionId session identifier produced by the authentication step
     * @return a cookie ready to be passed to {@code HttpServletResponse#addCookie(Cookie)}
     * @throws IllegalArgumentException if {@code sessionId} cannot be represented as a cookie value
     */
    public Cookie forSession(String sessionId) {
        Cookie cookie = new Cookie(name, requireCookieValue(sessionId));
        cookie.setPath(path);
        cookie.setMaxAge(maxAgeSeconds);
        cookie.setSecure(secure);
        cookie.setHttpOnly(true);
        return cookie;
    }

    private static String requireCookieValue(String sessionId) {
        if (sessionId == null || !SESSION_ID_PATTERN.matcher(sessionId).matches()) {
            throw new IllegalArgumentException("session identifier is not a valid cookie value");
        }
        return sessionId;
    }
}

====================================================================================================
src/main/java/com/example/auth/AuthenticatedSessionServlet.java
====================================================================================================

package com.example.auth;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Publishes the session cookie for a caller whose credentials have already been verified by an
 * upstream component - normally an authentication filter or a login servlet that stores the
 * identifier it obtained in the request attribute named {@link #SESSION_ID_ATTRIBUTE}.
 *
 * <p>{@code POST <context>/auth/session} answers {@code 204 No Content} with a
 * {@code Set-Cookie} header; subsequent requests from the same user agent then carry the
 * identifier back to the application.
 *
 * <p>Recognised init parameters (all optional): {@code cookieName}, {@code cookiePath},
 * {@code cookieMaxAgeSeconds}, {@code cookieSecure}.
 */
@WebServlet(name = AuthenticatedSessionServlet.SERVLET_NAME, urlPatterns = AuthenticatedSessionServlet.URL_PATTERN)
public class AuthenticatedSessionServlet extends HttpServlet {

    public static final String SERVLET_NAME = "authenticatedSessionServlet";
    public static final String URL_PATTERN = "/auth/session";

    public static final String SESSION_ID_ATTRIBUTE = "com.example.auth.sessionId";

    public static final String COOKIE_NAME_PARAM = "cookieName";
    public static final String COOKIE_PATH_PARAM = "cookiePath";
    public static final String COOKIE_MAX_AGE_PARAM = "cookieMaxAgeSeconds";
    public static final String COOKIE_SECURE_PARAM = "cookieSecure";

    // HttpServlet is Serializable; the factory holds no state worth serialising.
    private transient SessionCookieFactory cookieFactory;

    @Override
    public void init() throws ServletException {
        cookieFactory = new SessionCookieFactory(
                stringInitParameter(COOKIE_NAME_PARAM, SessionCookieFactory.DEFAULT_COOKIE_NAME),
                stringInitParameter(COOKIE_PATH_PARAM, SessionCookieFactory.DEFAULT_PATH),
                intInitParameter(COOKIE_MAX_AGE_PARAM, SessionCookieFactory.DEFAULT_MAX_AGE_SECONDS),
                booleanInitParameter(COOKIE_SECURE_PARAM, true));
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String sessionId = resolveSessionId(request);
        if (sessionId == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "No authenticated session identifier was supplied by the authentication step");
            return;
        }

        try {
            response.addCookie(cookieFactory.forSession(sessionId));
        } catch (IllegalArgumentException unusableSessionId) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "The authenticated session identifier cannot be published as a cookie");
            return;
        }

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * Hook for applications that hand the identifier over somewhere other than
     * {@link #SESSION_ID_ATTRIBUTE}, for example a {@code HttpSession} attribute.
     *
     * @return the identifier issued by authentication, or {@code null} when the caller is not
     *         authenticated
     */
    protected String resolveSessionId(HttpServletRequest request) {
        Object supplied = request.getAttribute(SESSION_ID_ATTRIBUTE);
        return supplied instanceof String sessionId && !sessionId.isBlank() ? sessionId : null;
    }

    private String stringInitParameter(String key, String fallback) {
        String value = getInitParameter(key);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private int intInitParameter(String key, int fallback) throws ServletException {
        String value = getInitParameter(key);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException malformed) {
            throw new ServletException("Init parameter " + key + " is not an integer: " + value, malformed);
        }
    }

    private boolean booleanInitParameter(String key, boolean fallback) {
        String value = getInitParameter(key);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return Boolean.parseBoolean(value.trim());
    }
}

====================================================================================================
pom.xml
====================================================================================================

<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

  <modelVersion>4.0.0</modelVersion>

  <groupId>com.example</groupId>
  <artifactId>auth-session-cookie</artifactId>
  <version>1.0.0-SNAPSHOT</version>
  <packaging>war</packaging>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <maven.compiler.release>17</maven.compiler.release>
  </properties>

  <dependencies>
    <dependency>
      <groupId>jakarta.servlet</groupId>
      <artifactId>jakarta.servlet-api</artifactId>
      <version>6.0.0</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <build>
    <finalName>auth-session-cookie</finalName>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-war-plugin</artifactId>
        <version>3.4.0</version>
        <configuration>
          <failOnMissingWebXml>false</failOnMissingWebXml>
        </configuration>
      </plugin>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-surefire-plugin</artifactId>
        <version>3.2.5</version>
      </plugin>
    </plugins>
  </build>

</project>

====================================================================================================
src/test/java/com/example/auth/SessionCookieIssuanceTest.java
====================================================================================================

package com.example.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

class SessionCookieIssuanceTest {

    private static final String SESSION_ID = "dG9rZW4tYWJjMTIz";

    @Test
    void isMappedWithoutWebXml() {
        WebServlet mapping = AuthenticatedSessionServlet.class.getAnnotation(WebServlet.class);
        assertNotNull(mapping);
        assertEquals("authenticatedSessionServlet", mapping.name());
        assertEquals("[/auth/session]", java.util.Arrays.toString(mapping.urlPatterns()));
    }

    @Test
    void publishesHardenedCookieAndAnswersWithNoContent() throws Exception {
        Outcome outcome = publish(Map.of(AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE, SESSION_ID), Map.of());

        assertEquals(204, outcome.status());
        assertFalse(outcome.errorReported());

        Cookie cookie = outcome.cookie();
        assertNotNull(cookie);
        assertEquals("APP_SESSION", cookie.getName());
        assertEquals(SESSION_ID, cookie.getValue());
        assertEquals("/", cookie.getPath());
        assertEquals(-1, cookie.getMaxAge());
        assertTrue(cookie.getSecure());
        assertTrue(cookie.isHttpOnly());
    }

    @Test
    void rejectsRequestWhereAuthenticationSuppliedNothing() throws Exception {
        Outcome absent = publish(Map.of(), Map.of());
        assertNull(absent.cookie());
        assertEquals(401, absent.errorStatus());

        Outcome blank = publish(Map.of(AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE, "   "), Map.of());
        assertNull(blank.cookie());
        assertEquals(401, blank.errorStatus());
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc; x=admin=1", "abc\r\nSet-Cookie: evil=1", "abc def", "abc\"x\"", " leading-space"})
    void refusesToPublishIdentifierThatIsNotACookieValue(String unusableSessionId) throws Exception {
        Outcome outcome = publish(
                Map.of(AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE, unusableSessionId), Map.of());
        assertNull(outcome.cookie());
        assertEquals(500, outcome.errorStatus());
    }

    @Test
    void honoursCookieInitParameters() throws Exception {
        Map<String, String> initParams = new HashMap<>();
        initParams.put(AuthenticatedSessionServlet.COOKIE_NAME_PARAM, "MY_SID");
        initParams.put(AuthenticatedSessionServlet.COOKIE_PATH_PARAM, "/api");
        initParams.put(AuthenticatedSessionServlet.COOKIE_MAX_AGE_PARAM, "1800");
        initParams.put(AuthenticatedSessionServlet.COOKIE_SECURE_PARAM, "false");

        Cookie cookie = publish(Map.of(AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE, SESSION_ID), initParams)
                .cookie();

        assertNotNull(cookie);
        assertEquals("MY_SID", cookie.getName());
        assertEquals(SESSION_ID, cookie.getValue());
        assertEquals("/api", cookie.getPath());
        assertEquals(1800, cookie.getMaxAge());
        assertFalse(cookie.getSecure());
        assertTrue(cookie.isHttpOnly());
    }

    @Test
    void rejectsNonNumericMaxAgeAtInit() {
        assertThrows(ServletException.class, () -> publish(
                Map.of(AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE, SESSION_ID),
                Map.of(AuthenticatedSessionServlet.COOKIE_MAX_AGE_PARAM, "soon")));
    }

    @Test
    void rejectsCookieConfigurationThatWouldLeakOutsideTheApplication() {
        assertThrows(IllegalArgumentException.class, () -> new SessionCookieFactory("APP_SESSION", "rel", 60, true));
        assertThrows(IllegalArgumentException.class, () -> new SessionCookieFactory("  ", "/", 60, true));
    }

    private static Outcome publish(Map<String, ?> attributes, Map<String, String> initParams) throws Exception {
        AuthenticatedSessionServlet servlet = new AuthenticatedSessionServlet();
        servlet.init(new StubConfig(initParams));
        ResponseDouble response = new ResponseDouble();
        servlet.doPost(requestWith(attributes), response.proxy());
        return new Outcome(response.cookie, response.status, response.errorReported, response.errorStatus);
    }

    private record Outcome(Cookie cookie, int status, boolean errorReported, int errorStatus) {
    }

    private record StubConfig(Map<String, String> initParams) implements ServletConfig {

        @Override
        public String getServletName() {
            return AuthenticatedSessionServlet.SERVLET_NAME;
        }

        @Override
        public String getInitParameter(String name) {
            return initParams.get(name);
        }
    }

    private static HttpServletRequest requestWith(Map<String, ?> attributes) {
        return (HttpServletRequest) Proxy.newProxyInstance(SessionCookieIssuanceTest.class.getClassLoader(),
                new Class<?>[] {HttpServletRequest.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getAttribute" -> attributes.get((String) args[0]);
                    case "toString" -> "request-double";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static final class ResponseDouble {

        private Cookie cookie;
        private int status;
        private boolean errorReported;
        private int errorStatus;

        private HttpServletResponse proxy() {
            return (HttpServletResponse) Proxy.newProxyInstance(SessionCookieIssuanceTest.class.getClassLoader(),
                    new Class<?>[] {HttpServletResponse.class}, (proxy, method, args) -> {
                        switch (method.getName()) {
                            case "addCookie" -> cookie = (Cookie) args[0];
                            case "setStatus" -> status = (Integer) args[0];
                            case "sendError" -> {
                                errorReported = true;
                                errorStatus = (Integer) args[0];
                            }
                            case "toString" -> {
                                return "response-double";
                            }
                            case "hashCode" -> {
                                return System.identityHashCode(proxy);
                            }
                            case "equals" -> {
                                return proxy == args[0];
                            }
                            default -> throw new UnsupportedOperationException(method.getName());
                        }
                        return null;
                    });
        }
    }
}

====================================================================================================
Notes
====================================================================================================

* The cookie the client receives for a valid request:

      Set-Cookie: APP_SESSION=dG9rZW4tYWJjMTIz; Path=/; Secure; HttpOnly

  (Max-Age is added only when cookieMaxAgeSeconds >= 0; the container omits a negative value, which
  is what makes the default a browser-session cookie.)

* Hand-off from the component that performed authentication:

      request.setAttribute(AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE, authenticatedSessionId);
      request.getRequestDispatcher(AuthenticatedSessionServlet.URL_PATTERN).forward(request, response);

  Override resolveSessionId(HttpServletRequest) instead if the identifier lives somewhere else, e.g.
  (String) request.getSession().getAttribute("sessionId").

* Reading the identifier back on later requests is request.getCookies() filtered by the cookie name;
  that lookup is intentionally not part of this change.

* Servlet 6.0 / Jakarta EE 10 (Tomcat 10.1, Jetty 11-12, WildFly 27+), Java 17. Sources are pure ASCII
  so they compile even where the platform default charset is not UTF-8.

* Verification performed on this machine (JDK 17.0.20.1; Maven is not installed and there is no
  ~/.m2 repository, so `mvn test` could not be run and the real jakarta.servlet-api / JUnit jars could
  not be downloaded):
    - javac -Xlint:all on both main sources: clean, no warnings.
    - javac -Xlint:all on main + test sources: clean (the only warnings came from throwaway stubs).
    - Executed the behaviour both through a standalone harness and through SessionCookieIssuanceTest
      driven by a reflective runner over minimal jakarta.servlet / org.junit.jupiter stubs:
      11 test methods (incl. 5 parameterized cases) passed, 0 failed.
  Re-run against the real artifacts with: mvn test

