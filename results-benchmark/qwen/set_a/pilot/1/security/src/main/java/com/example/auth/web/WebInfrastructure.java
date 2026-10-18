package com.example.auth.web;

import com.example.auth.session.InMemorySessionRegistry;
import com.example.auth.session.SessionCookieConfig;
import com.example.auth.session.SessionCookieConfig.SameSite;
import com.example.auth.session.SessionRegistry;
import jakarta.servlet.ServletContext;
import java.time.Duration;

/**
 * Resolves the collaborators the auth servlets need, so they keep the no-arg constructor the servlet
 * spec requires while still being replaceable from the outside.
 *
 * <p>An application can bind a {@link SessionRegistry} or {@link SessionCookieConfig} as a
 * {@code ServletContext} attribute (from a {@code ServletContextListener}, a CDI producer, Spring,
 * ...) and that instance wins. Otherwise sensible defaults are built here, with the usual knobs
 * exposed as {@code <context-param>}:
 *
 * <pre>{@code
 * <context-param>
 *   <param-name>auth.cookie.sameSite</param-name>
 *   <param-value>Strict</param-value>
 * </context-param>
 * <context-param>
 *   <param-name>auth.session.ttlSeconds</param-name>
 *   <param-value>1800</param-value>
 * </context-param>
 * }</pre>
 *
 * The knobs narrow the cookie (name, path, SameSite, {@code __Host-} prefix, Max-Age). They cannot
 * drop {@code Secure} or {@code HttpOnly}, and {@code SameSite=None} still requires {@code Secure}:
 * configuration is allowed to harden the cookie, never to weaken it below what
 * {@link SessionCookieConfig} accepts.
 */
public final class WebInfrastructure {

    public static final String SESSION_REGISTRY_ATTRIBUTE = "com.example.auth.sessionRegistry";
    public static final String COOKIE_CONFIG_ATTRIBUTE = "com.example.auth.sessionCookieConfig";

    public static final String COOKIE_NAME_PARAM = "auth.cookie.name";
    public static final String COOKIE_PATH_PARAM = "auth.cookie.path";
    public static final String COOKIE_SAME_SITE_PARAM = "auth.cookie.sameSite";
    public static final String COOKIE_HOST_PREFIX_PARAM = "auth.cookie.hostPrefix";
    public static final String COOKIE_MAX_AGE_PARAM = "auth.cookie.maxAgeSeconds";
    public static final String SESSION_TTL_PARAM = "auth.session.ttlSeconds";

    private static final Duration DEFAULT_SESSION_TTL = Duration.ofMinutes(30);

    private WebInfrastructure() {
    }

    public static SessionRegistry sessionRegistry(ServletContext context) {
        Object bound = context.getAttribute(SESSION_REGISTRY_ATTRIBUTE);
        if (bound instanceof SessionRegistry registry) {
            return registry;
        }
        // Shared through the context so every servlet in this web application sees one store.
        synchronized (context) {
            Object concurrent = context.getAttribute(SESSION_REGISTRY_ATTRIBUTE);
            if (concurrent instanceof SessionRegistry registry) {
                return registry;
            }
            SessionRegistry created = new InMemorySessionRegistry();
            context.setAttribute(SESSION_REGISTRY_ATTRIBUTE, created);
            return created;
        }
    }

    public static SessionCookieConfig sessionCookieConfig(ServletContext context) {
        Object bound = context.getAttribute(COOKIE_CONFIG_ATTRIBUTE);
        if (bound instanceof SessionCookieConfig config) {
            return config;
        }
        String name = initParam(context, COOKIE_NAME_PARAM, SessionCookieConfig.DEFAULT_NAME);
        String path = initParam(context, COOKIE_PATH_PARAM, "/");
        SameSite sameSite = sameSite(initParam(context, COOKIE_SAME_SITE_PARAM, SameSite.LAX.name()));
        boolean hostPrefix = Boolean.parseBoolean(initParam(context, COOKIE_HOST_PREFIX_PARAM, "false"));
        int maxAgeSeconds = intParam(context, COOKIE_MAX_AGE_PARAM, -1);
        return new SessionCookieConfig(name, path, null, maxAgeSeconds, true, true, sameSite, hostPrefix);
    }

    public static Duration sessionTtl(ServletContext context) {
        return Duration.ofSeconds(intParam(context, SESSION_TTL_PARAM, (int) DEFAULT_SESSION_TTL.toSeconds()));
    }

    private static String initParam(ServletContext context, String name, String fallback) {
        String value = context.getInitParameter(name);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static int intParam(ServletContext context, String name, int fallback) {
        String value = context.getInitParameter(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException("context-param " + name + " is not a number: " + value, e);
        }
    }

    private static SameSite sameSite(String value) {
        try {
            return SameSite.valueOf(value.toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("unsupported " + COOKIE_SAME_SITE_PARAM + ": " + value, e);
        }
    }
}
