package com.acme.portal.session;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Validated runtime settings for the handoff component.
 *
 * <p>Environment variables are configuration, and configuration is attacker-influenced in the
 * general case: a sidecar, a Helm value, a {@code .env} file or a CI variable can all change them
 * without anyone reviewing Java code. Every value read here is therefore validated for type, length
 * and range before use, and an invalid value aborts startup.
 *
 * <p>Defaults exist only for the availability knobs, and every default is the stricter choice
 * (short window, low ceiling) rather than a permissive one. Nothing security-relevant is defaulted:
 * {@code Secure}, {@code HttpOnly}, host-only scope and session-cookie lifetime are invariants of
 * {@link SessionCookiePolicy} and cannot be turned off from here.
 *
 * <p>No secret is read, held or derivable from this class. There is no signing key because a
 * session cookie carries an opaque identifier that the authoritative store resolves, so nothing needs
 * to be proven by a MAC; adding one would add a secret to protect for no security gain.
 */
public final class SessionHandoffSettings {

    public static final String COOKIE_NAME_ENV = "PORTAL_COOKIE_NAME";
    public static final String COOKIE_PATH_ENV = "PORTAL_COOKIE_PATH";
    public static final String SAME_SITE_ENV = "PORTAL_COOKIE_SAME_SITE";
    public static final String WINDOW_SECONDS_ENV = "PORTAL_HANDOFF_WINDOW_SECONDS";
    public static final String MAX_PER_WINDOW_ENV = "PORTAL_HANDOFF_MAX_PER_WINDOW";
    public static final String GLOBAL_MAX_PER_WINDOW_ENV = "PORTAL_HANDOFF_GLOBAL_MAX_PER_WINDOW";
    public static final String MAX_TRACKED_SOURCES_ENV = "PORTAL_HANDOFF_MAX_TRACKED_SOURCES";
    public static final String ASSERTION_ATTRIBUTE_ENV = "PORTAL_ASSERTION_ATTRIBUTE";

    public static final int DEFAULT_WINDOW_SECONDS = 60;
    public static final int DEFAULT_MAX_PER_WINDOW = 30;
    public static final int DEFAULT_GLOBAL_MAX_PER_WINDOW = 2000;
    public static final int DEFAULT_MAX_TRACKED_SOURCES = 200000;

    /** Servlet request attribute the trusted authenticator is expected to set. */
    public static final String DEFAULT_ASSERTION_ATTRIBUTE = "com.acme.portal.session.assertedId";

    private static final int MAX_ATTRIBUTE_NAME_LENGTH = 100;

    private final SessionCookiePolicy cookiePolicy;
    private final int windowSeconds;
    private final int maxPerWindow;
    private final int globalMaxPerWindow;
    private final int maxTrackedSources;
    private final String assertionAttribute;

    private SessionHandoffSettings(SessionCookiePolicy cookiePolicy, int windowSeconds, int maxPerWindow,
                                   int globalMaxPerWindow, int maxTrackedSources, String assertionAttribute) {
        this.cookiePolicy = cookiePolicy;
        this.windowSeconds = windowSeconds;
        this.maxPerWindow = maxPerWindow;
        this.globalMaxPerWindow = globalMaxPerWindow;
        this.maxTrackedSources = maxTrackedSources;
        this.assertionAttribute = assertionAttribute;
    }

    /** Reads the process environment. */
    public static SessionHandoffSettings fromEnvironment() {
        return load(new java.util.function.Function<String, String>() {
            @Override
            public String apply(String name) {
                return System.getenv(name);
            }
        });
    }

    /**
     * @param lookup returns the value of a named setting, or {@code null} when unset. Injection
     *               keeps the class loadable in tests and in a Spring/Kubernetes ConfigMap adapter
     *               without changing validation.
     * @throws IllegalArgumentException if any setting is malformed or out of range. The message names
     *               the setting and the violated property, never a value read from the environment.
     */
    public static SessionHandoffSettings load(java.util.function.Function<String, String> lookup) {
        if (lookup == null) {
            throw new IllegalArgumentException("settings lookup is required");
        }
        SessionCookiePolicy policy;
        try {
            policy = SessionCookiePolicy.of(lookup.apply(COOKIE_NAME_ENV), lookup.apply(COOKIE_PATH_ENV),
                    lookup.apply(SAME_SITE_ENV));
        } catch (IllegalArgumentException weakPolicy) {
            throw new IllegalArgumentException("cookie settings are not safe to serve: "
                    + weakPolicy.getMessage());
        }
        int windowSeconds = readInt(WINDOW_SECONDS_ENV, lookup, DEFAULT_WINDOW_SECONDS,
                1, AttemptLimiter.MAX_WINDOW_SECONDS);
        int maxPerWindow = readInt(MAX_PER_WINDOW_ENV, lookup, DEFAULT_MAX_PER_WINDOW,
                1, AttemptLimiter.MAX_PER_SOURCE);
        int globalMax = readInt(GLOBAL_MAX_PER_WINDOW_ENV, lookup, DEFAULT_GLOBAL_MAX_PER_WINDOW,
                1, AttemptLimiter.MAX_GLOBAL);
        int maxTracked = readInt(MAX_TRACKED_SOURCES_ENV, lookup, DEFAULT_MAX_TRACKED_SOURCES,
                1, AttemptLimiter.MAX_TRACKED_SOURCES);
        String attribute = validateAttributeName(read(ASSERTION_ATTRIBUTE_ENV, lookup), DEFAULT_ASSERTION_ATTRIBUTE);
        // The per-source ceiling must never exceed the global one, or the global lane would silently
        // become the binding limit and an operator's widening of one knob would do nothing.
        if (maxPerWindow > globalMax) {
            throw new IllegalArgumentException(MAX_PER_WINDOW_ENV + " must not exceed "
                    + GLOBAL_MAX_PER_WINDOW_ENV);
        }
        return new SessionHandoffSettings(policy, windowSeconds, maxPerWindow, globalMax, maxTracked, attribute);
    }

    private static String read(String name, java.util.function.Function<String, String> lookup) {
        String value;
        try {
            value = lookup.apply(name);
        } catch (RuntimeException lookupFailed) {
            throw new IllegalArgumentException("setting " + name + " could not be read");
        }
        if (value == null) {
            return null;
        }
        // Reject non-printable bytes outright: an embedded CR or LF in an environment variable is
        // either a broken deployment or an injection attempt, and neither belongs in a header value.
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x21 || c > 0x7E) {
                throw new IllegalArgumentException("setting " + name + " contains a non-printable character");
            }
        }
        return value;
    }

    private static int readInt(String name, java.util.function.Function<String, String> lookup,
                               int fallback, int minimum, int maximum) {
        String raw = read(name, lookup);
        if (raw == null || raw.isEmpty()) {
            return fallback;
        }
        int value;
        try {
            value = Integer.parseInt(raw);
        } catch (NumberFormatException notAnInteger) {
            throw new IllegalArgumentException("setting " + name + " is not an integer");
        }
        if (value < minimum || value > maximum) {
            throw new IllegalArgumentException("setting " + name + " must be between " + minimum + " and "
                    + maximum);
        }
        return value;
    }

    /** Java-identifier shaped, because it becomes a {@code ServletRequest} attribute key. */
    private static String validateAttributeName(String raw, String fallback) {
        if (raw == null || raw.isEmpty()) {
            return fallback;
        }
        if (raw.length() > MAX_ATTRIBUTE_NAME_LENGTH) {
            throw new IllegalArgumentException("setting " + ASSERTION_ATTRIBUTE_ENV + " is too long");
        }
        char first = raw.charAt(0);
        if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || first == '_')) {
            throw new IllegalArgumentException("setting " + ASSERTION_ATTRIBUTE_ENV
                    + " must start with a letter or underscore");
        }
        for (int i = 1; i < raw.length(); i++) {
            char c = raw.charAt(i);
            boolean allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '_' || c == '.';
            if (!allowed) {
                throw new IllegalArgumentException("setting " + ASSERTION_ATTRIBUTE_ENV
                        + " may contain only letters, digits, '_' and '.'");
            }
        }
        // Reserved by the Servlet and Jakarta namespaces; colliding with one would let a framework
        // filter overwrite the assertion, or let us overwrite somebody else's attribute.
        String reserved = "jakarta. servlet. javax. java. sun. com.sun.";
        for (String prefix : reserved.split(" ")) {
            if (raw.startsWith(prefix)) {
                throw new IllegalArgumentException("setting " + ASSERTION_ATTRIBUTE_ENV
                        + " must not use a reserved namespace prefix");
            }
        }
        return raw;
    }

    public SessionCookiePolicy cookiePolicy() {
        return cookiePolicy;
    }

    public int windowSeconds() {
        return windowSeconds;
    }

    public int maxPerWindow() {
        return maxPerWindow;
    }

    public int globalMaxPerWindow() {
        return globalMaxPerWindow;
    }

    public int maxTrackedSources() {
        return maxTrackedSources;
    }

    public String assertionAttribute() {
        return assertionAttribute;
    }

    /** An {@link AttemptLimiter} matching these settings. */
    public AttemptLimiter limiter() {
        return new AttemptLimiter(windowSeconds, maxPerWindow, globalMaxPerWindow, maxTrackedSources);
    }

    /** Setting names and validated values. No secret can appear here; none is read. */
    @Override
    public String toString() {
        Map<String, String> summary = new LinkedHashMap<String, String>();
        summary.put("cookie", cookiePolicy.toString());
        summary.put("windowSeconds", Integer.toString(windowSeconds));
        summary.put("maxPerWindow", Integer.toString(maxPerWindow));
        summary.put("globalMaxPerWindow", Integer.toString(globalMaxPerWindow));
        summary.put("maxTrackedSources", Integer.toString(maxTrackedSources));
        summary.put("assertionAttribute", assertionAttribute);
        return Collections.unmodifiableMap(summary).toString();
    }
}
