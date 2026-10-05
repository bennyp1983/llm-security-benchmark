package com.example.auth.web;

import com.example.auth.InMemoryUserStore;
import com.example.auth.InMemoryUserStore.SeedAccount;
import com.example.auth.PasswordService;
import com.example.auth.SessionStore;
import com.example.auth.UserStore;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.ServletContext;

/**
 * The application's collaborators, built once at startup from {@code context.xml} parameters and
 * reachable from every servlet and filter through the {@link ServletContext}.
 *
 * <p>Seed accounts are read from {@code context-param} entries shaped like
 * {@code seed.user.alice = Secret123! | admin,user}. {@code seed.user.<name>} names the user;
 * the part before the pipe is the password, the part after it the roles. Never put a real password
 * in there: set the PBKDF2 cost high in production and move the accounts into a database.
 */
public final class AuthContext {

    public static final String ATTRIBUTE = AuthContext.class.getName();

    public static final String COOKIE_NAME = "app_session";
    public static final String CSRF_FIELD = "csrf_token";

    private static final String PARAM_PREFIX = "auth.";
    private static final String SEED_PREFIX = "seed.user.";

    private final PasswordService passwords;
    private final SessionStore sessions;
    private final UserStore users;
    private final LoginThrottle throttle;

    private AuthContext(PasswordService passwords, SessionStore sessions, UserStore users,
                        LoginThrottle throttle) {
        this.passwords = passwords;
        this.sessions = sessions;
        this.users = users;
        this.throttle = throttle;
    }

    public static AuthContext of(ServletContext context) {
        Object existing = context.getAttribute(ATTRIBUTE);
        if (existing instanceof AuthContext authContext) {
            return authContext;
        }
        throw new IllegalStateException("AuthContext was never initialised - "
                + "the AuthContextListener must be mapped as a ServletContextListener");
    }

    /** Builds the context from init parameters and registers it under {@link #ATTRIBUTE}. */
    public static AuthContext install(ServletContext context) {
        int iterations = intParam(context, PARAM_PREFIX + "pbkdf2.iterations", 240_000);
        PasswordService passwords = new PasswordService(iterations);
        SessionStore sessions = new SessionStore(
                durationParam(context, PARAM_PREFIX + "session.idle.timeout", Duration.ofMinutes(30)),
                durationParam(context, PARAM_PREFIX + "session.absolute.timeout", Duration.ofHours(8)));
        UserStore users = seedUsers(context, passwords);
        LoginThrottle throttle = new LoginThrottle(
                intParam(context, PARAM_PREFIX + "login.max.failures", 10),
                durationParam(context, PARAM_PREFIX + "login.failure.window", Duration.ofMinutes(15)),
                durationParam(context, PARAM_PREFIX + "login.lockout", Duration.ofMinutes(15)));
        AuthContext authContext = new AuthContext(passwords, sessions, users, throttle);
        context.setAttribute(ATTRIBUTE, authContext);
        return authContext;
    }

    public PasswordService passwords() {
        return passwords;
    }

    public SessionStore sessions() {
        return sessions;
    }

    public UserStore users() {
        return users;
    }

    public LoginThrottle throttle() {
        return throttle;
    }

    private static UserStore seedUsers(ServletContext context, PasswordService passwords) {
        Map<String, SeedAccount> seed = new LinkedHashMap<>();
        // getInitParameterNames returns an Enumeration, not an Iterable - copy it out first.
        for (String name : java.util.Collections.list(context.getInitParameterNames())) {
            if (!name.startsWith(SEED_PREFIX)) {
                continue;
            }
            String username = name.substring(SEED_PREFIX.length()).trim();
            if (username.isEmpty()) {
                continue;
            }
            String[] spec = String.valueOf(context.getInitParameter(name)).split("\\|", -1);
            String password = spec[0].trim();
            Set<String> roles = spec.length > 1 ? splitRoles(spec[1]) : Set.of("user");
            seed.put(username, new SeedAccount(password.toCharArray(), roles));
        }
        if (seed.isEmpty()) {
            throw new IllegalStateException("no seed.user.* accounts configured; refusing to start "
                    + "an authentication demo nobody can sign in to");
        }
        return InMemoryUserStore.seed(passwords, seed);
    }

    private static Set<String> splitRoles(String raw) {
        return java.util.Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(role -> !role.isEmpty())
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    private static int intParam(ServletContext context, String name, int fallback) {
        String raw = context.getInitParameter(name);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException("init parameter " + name + " is not a number: " + raw, e);
        }
    }

    private static Duration durationParam(ServletContext context, String name, Duration fallback) {
        String raw = context.getInitParameter(name);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        String value = raw.trim();
        try {
            if (value.endsWith("ms")) {
                return Duration.ofMillis(Long.parseLong(value.substring(0, value.length() - 2).trim()));
            }
            if (value.endsWith("h")) {
                return Duration.ofHours(Long.parseLong(value.substring(0, value.length() - 1).trim()));
            }
            if (value.endsWith("m")) {
                return Duration.ofMinutes(Long.parseLong(value.substring(0, value.length() - 1).trim()));
            }
            if (value.endsWith("s")) {
                return Duration.ofSeconds(Long.parseLong(value.substring(0, value.length() - 1).trim()));
            }
        } catch (NumberFormatException e) {
            throw new IllegalStateException("init parameter " + name + " is not a duration: " + raw, e);
        }
        throw new IllegalStateException("init parameter " + name + " is not a duration: " + raw
                + " (use a suffix of ms, s, m or h)");
    }
}
