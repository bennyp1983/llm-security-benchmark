package com.example.auth;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.time.Duration;

/**
 * Creates the one store, the one cookie configuration and the one issuer for the application and
 * publishes them on the {@link ServletContext}, so servlets share state without statics.
 *
 * <p>Registered in {@code WEB-INF/web.xml}. All settings are {@code context-param}s there:
 * <ul>
 *   <li>{@code sessionTtlMinutes} - server-side session lifetime (default 30).</li>
 *   <li>{@code cookieName}, {@code cookiePath}, {@code secureCookie}, {@code httpOnlyCookie},
 *       {@code sameSite}, {@code maxAgeSeconds} - see
 *       {@link SessionCookieConfig#fromInitParams}.</li>
 * </ul>
 *
 * <p>Configuring the cookie <em>here</em> rather than per servlet is deliberate: login sets the
 * cookie and logout overwrites it, and an overwrite only deletes a cookie whose name <em>and</em>
 * path match exactly. Two independent copies of those settings is how a logout ends up silently
 * failing to clear anything.
 */
public class AuthContextListener implements ServletContextListener {

    public static final String SESSION_STORE_ATTRIBUTE = "com.example.auth.sessionStore";
    public static final String COOKIE_CONFIG_ATTRIBUTE = "com.example.auth.cookieConfig";
    public static final String COOKIE_ISSUER_ATTRIBUTE = "com.example.auth.cookieIssuer";
    public static final String SESSION_TTL_ATTRIBUTE = "com.example.auth.sessionTtl";
    public static final String VERIFIER_ATTRIBUTE = "com.example.auth.credentialVerifier";

    /** Request attribute holding the resolved {@link AuthenticatedSession}, absent when anonymous. */
    public static final String REQUEST_SESSION_ATTRIBUTE = "com.example.auth.session";

    @Override
    public void contextInitialized(ServletContextEvent event) {
        ServletContext context = event.getServletContext();
        SessionCookieConfig cookieConfig = SessionCookieConfig.fromInitParams(context::getInitParameter);
        context.setAttribute(COOKIE_CONFIG_ATTRIBUTE, cookieConfig);
        context.setAttribute(COOKIE_ISSUER_ATTRIBUTE, new SessionCookieIssuer(cookieConfig));
        context.setAttribute(SESSION_STORE_ATTRIBUTE, new InMemorySessionStore());
        context.setAttribute(SESSION_TTL_ATTRIBUTE, Duration.ofMinutes(intParam(context, "sessionTtlMinutes", 30)));
        context.setAttribute(VERIFIER_ATTRIBUTE, new EnvironmentCredentialVerifier());
    }

    private static int intParam(ServletContext context, String key, int fallback) {
        String raw = context.getInitParameter(key);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        int value = Integer.parseInt(raw.trim());
        if (value <= 0) {
            throw new IllegalArgumentException(key + " must be positive");
        }
        return value;
    }
}
