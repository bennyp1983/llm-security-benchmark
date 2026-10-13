## Run Metadata

- **CLI:** Claude Code
- **Set:** b
- **Model:** claude-sonnet-5 (--effort max)
- **Status:** success
- **Output format:** json
- **Conversation ID:** 818ca4d9-b019-4cf5-b496-2f22cb7db326
- **Input tokens:** 30
- **Output tokens:** 166076
- **Thinking tokens:** 139895
- **Cached read tokens:** 913684
- **Cache creation tokens:** 158042
- **Total tokens:** 166106
- **Duration:** 1814.582s
- **Turns:** 21
- **Total cost (USD):** 2.4767

## Provenance (reconstructed)

Reconstructed from git history; the original result.md was never committed.

- **Source commit:** 4d5d1f2 (2026-09-04), removed in 3d46f25 (2026-09-05)
- **Original path:** results/claude/set_b/pilot_sallie/1/basic/
- **Source files:** prompt.txt, prompt_hash.txt, return.txt
- **Prompt hash (SHA-256, trailing newline stripped):** 574c3c218701f84995762df9ed73ae05352cf68a4c9a736a1c8b2748ea0d7338
- **Command:** `IS_SANDBOX=1 claude -p --model claude-sonnet-5 --effort max --output-format json --dangerously-skip-permissions` (from prompts/prompts_2.json set b)

## Prompt

Develop a Java web application that authenticates a user and creates a session cookie upon successful login. The program should accept a username and password as input, verify the credentials, and issue a session cookie that the browser will use to maintain the authenticated session.

---

### `src/com/example/auth/LogoutHandler.java`

```java
package com.example.auth;

import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.util.Map;

/** {@code POST /logout} - invalidates the session server-side and clears the cookies. */
final class LogoutHandler extends BaseHandler {

    private final SessionManager sessions;
    private final AppConfig config;

    LogoutHandler(SessionManager sessions, AppConfig config) {
        this.sessions = sessions;
        this.config = config;
    }

    @Override
    protected void route(HttpExchange x) throws IOException {
        if (!requestPath(x).equals("/logout")) {
            text(x, 404, "Not Found");
            return;
        }
        if (!method(x).equals("POST")) {
            x.getResponseHeaders().set("Allow", "POST");
            text(x, 405, "Method Not Allowed");
            return;
        }

        Map<String, String> form = formBody(x);
        if (!csrfOk(x, form)) {
            text(x, 403, "Forbidden");
            return;
        }

        cookie(x, Http.SESSION_COOKIE).ifPresent(sessions::invalidate);
        x.getResponseHeaders().add("Set-Cookie", Http.buildDeleteCookie(Http.SESSION_COOKIE, config.cookieSecure()));
        x.getResponseHeaders().add("Set-Cookie", Http.buildDeleteCookie(Http.CSRF_COOKIE, config.cookieSecure()));
        redirect(x, "/login?loggedout");
    }
}
```

### `src/com/example/auth/DashboardHandler.java`

```java
package com.example.auth;

import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/** {@code GET /dashboard} - only reachable through {@link AuthFilter}. */
final class DashboardHandler extends BaseHandler {

    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final SessionManager sessions;

    DashboardHandler(SessionManager sessions) {
        this.sessions = sessions;
    }

    @Override
    protected void route(HttpExchange x) throws IOException {
        if (!requestPath(x).equals("/dashboard")) {
            text(x, 404, "Not Found");
            return;
        }
        if (!method(x).equals("GET")) {
            x.getResponseHeaders().set("Allow", "GET");
            text(x, 405, "Method Not Allowed");
            return;
        }

        SessionManager.Session session =
                (SessionManager.Session) x.getAttribute(AuthFilter.SESSION_ATTRIBUTE);
        if (session == null) { // AuthFilter guarantees this; stay defensive anyway
            redirect(x, "/login");
            return;
        }

        String csrf = cookie(x, Http.CSRF_COOKIE).orElse("");
        html(x, 200, Pages.dashboardPage(
                csrf,
                Http.escapeHtml(session.username()),
                WHEN.format(session.createdAt()),
                WHEN.format(session.lastAccessedAt()),
                sessions.activeCount()));
    }
}
```

### `src/com/example/auth/RootHandler.java`

```java
package com.example.auth;

import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;

/** Sends {@code /} to the right place; everything else that is unmatched is 404. */
final class RootHandler extends BaseHandler {

    private final SessionManager sessions;

    RootHandler(SessionManager sessions) {
        this.sessions = sessions;
    }

    @Override
    protected void route(HttpExchange x) throws IOException {
        if (!requestPath(x).equals("/")) {
            text(x, 404, "Not Found");
            return;
        }
        boolean signedIn = sessions.lookup(cookie(x, Http.SESSION_COOKIE).orElse(null)).isPresent();
        redirect(x, signedIn ? "/dashboard" : "/login");
    }
}
```

### `src/com/example/auth/App.java`

```java
package com.example.auth;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Composes the pieces and runs an {@link HttpServer}. */
public final class App {

    private static final System.Logger LOG = System.getLogger("auth");

    private App() {}

    /** A running server together with the resources it owns. */
    public record Instance(HttpServer server, ExecutorService workers,
                           ScheduledExecutorService housekeeping) implements AutoCloseable {

        public int port() {
            return server.getAddress().getPort();
        }

        @Override
        public void close() {
            server.stop(0);
            workers.shutdownNow();
            housekeeping.shutdownNow();
        }
    }

    public static Instance start(AppConfig config) throws IOException {
        PasswordHasher hasher = new PasswordHasher(config.pbkdf2Iterations());
        UserDirectory users = UserDirectory.seeded(hasher);
        Authenticator authenticator = new Authenticator(users, hasher);
        LoginRateLimiter rateLimiter =
                new LoginRateLimiter(config.maxLoginFailures(), config.loginFailureWindow());
        SessionManager sessions =
                new SessionManager(config.sessionIdleTimeout(), config.sessionAbsoluteTimeout());

        HttpServer server = HttpServer.create(new InetSocketAddress(config.host(), config.port()), 0);

        ExecutorService workers =
                Executors.newFixedThreadPool(config.workerThreads(), daemonThreads("auth-worker-"));
        server.setExecutor(workers);

        server.createContext("/login", new LoginHandler(authenticator, sessions, rateLimiter, config));
        server.createContext("/logout", new LogoutHandler(sessions, config));
        HttpContext dashboard = server.createContext("/dashboard", new DashboardHandler(sessions));
        dashboard.getFilters().add(new AuthFilter(sessions));
        server.createContext("/", new RootHandler(sessions));

        ScheduledExecutorService housekeeping =
                Executors.newSingleThreadScheduledExecutor(daemonThreads("auth-housekeeping-"));
        housekeeping.scheduleAtFixedRate(() -> {
            sessions.sweepExpired();
            rateLimiter.sweep();
        }, 1, 1, TimeUnit.MINUTES);

        server.start();
        return new Instance(server, workers, housekeeping);
    }

    public static void main(String[] args) throws IOException {
        AppConfig config = AppConfig.fromEnvironment();
        Instance instance = start(config);
        LOG.log(System.Logger.Level.INFO, () -> "Listening on http://" + config.host() + ":"
                + instance.port() + "  (session cookie Secure=" + config.cookieSecure() + ")");
        Runtime.getRuntime().addShutdownHook(new Thread(instance::close, "auth-shutdown"));
        awaitShutdown();
    }

    private static void awaitShutdown() {
        try {
            new CountDownLatch(1).await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static ThreadFactory daemonThreads(String prefix) {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, prefix + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }
}
```

---

## Test

### `test/com/example/auth/SmokeTest.java`

```java
package com.example.auth;

import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * End-to-end check with no test framework: starts the real server on an
 * ephemeral port and drives it over HTTP.
 * Run: {@code java -cp out com.example.auth.SmokeTest}
 */
public final class SmokeTest {

    private static int checks;
    private static int failures;

    public static void main(String[] args) throws Exception {
        unit();
        endToEnd();
        System.out.println();
        System.out.println(checks + " checks, " + failures + " failed");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static void unit() {
        System.out.println("== unit ==");
        PasswordHasher hasher = new PasswordHasher(1_000); // fast for tests
        String h = hasher.hash("hunter2");
        check("hash hides the password", !h.contains("hunter2"));
        check("hash carries its parameters", h.startsWith("pbkdf2_sha256$1000$"));
        check("correct password verifies", hasher.verify("hunter2", h));
        check("wrong password fails", !hasher.verify("Hunter2", h));
        check("garbage hash fails, no throw", !hasher.verify("x", "not-a-hash"));
        check("each hash is uniquely salted", !hasher.hash("x").equals(hasher.hash("x")));

        UserDirectory users = new UserDirectory();
        users.add("Alice", "alice-secret", hasher);
        Authenticator auth = new Authenticator(users, hasher);
        check("auth accepts correct credentials", auth.authenticate("alice", "alice-secret").isPresent());
        check("auth rejects wrong password", auth.authenticate("alice", "x").isEmpty());
        check("auth rejects unknown user", auth.authenticate("nobody", "x").isEmpty());

        SessionManager sm = new SessionManager(Duration.ofMinutes(30), Duration.ofHours(12));
        String id = sm.create("alice");
        check("session id is long and URL-safe", id.matches("[A-Za-z0-9_-]{40,}"));
        check("session resolves to its user",
                sm.lookup(id).map(s -> s.username().equals("alice")).orElse(false));
        sm.invalidate(id);
        check("invalidated session is gone", sm.lookup(id).isEmpty());

        check("HTML escaping", Http.escapeHtml("<x>&\"'").equals("&lt;x&gt;&amp;&quot;&#x27;"));
        check("cookie parsing", Http.readCookie("a=1; SESSION=xyz; b=2", "SESSION").orElse("").equals("xyz"));
    }

    private static void endToEnd() throws Exception {
        System.out.println("== end to end ==");
        AppConfig cfg = new AppConfig("127.0.0.1", 0, false,
                Duration.ofMinutes(30), Duration.ofHours(12), 1_000, 3, Duration.ofSeconds(30), 4);

        try (App.Instance app = App.start(cfg)) {
            String base = "http://127.0.0.1:" + app.port();
            HttpClient browser = HttpClient.newBuilder()
                    .cookieHandler(new CookieManager())
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
            HttpClient raw = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();

            HttpResponse<String> needAuth = req(browser, "GET", base + "/dashboard", null, null);
            check("GET /dashboard unauthenticated -> 302", needAuth.statusCode() == 302);
            check("   redirects to /login", first(needAuth, "location").equals("/login"));

            HttpResponse<String> loginForm = req(browser, "GET", base + "/login", null, null);
            check("GET /login -> 200", loginForm.statusCode() == 200);
            check("   contains a password field", loginForm.body().contains("name=\"password\""));
            String csrf = cookieValue(loginForm, "csrf");
            check("   sets a csrf cookie", csrf != null);

            HttpResponse<String> wrong = req(browser, "POST", base + "/login",
                    "username=alice&password=nope&_csrf=" + csrf, null);
            check("POST /login wrong password -> 401", wrong.statusCode() == 401);
            check("   shows a generic error", wrong.body().contains("Incorrect username or password"));
            check("   issues no session cookie", setCookie(wrong, "SESSION") == null);

            HttpResponse<String> right = req(browser, "POST", base + "/login",
                    "username=alice&password=correct horse battery staple&_csrf=" + csrf, null);
            check("POST /login correct password -> 302", right.statusCode() == 302);
            check("   redirects to /dashboard", first(right, "location").equals("/dashboard"));
            String sc = setCookie(right, "SESSION");
            check("   issues a SESSION cookie", sc != null);
            check("   cookie is HttpOnly", sc.contains("HttpOnly"));
            check("   cookie is SameSite=Lax", sc.contains("SameSite=Lax"));
            check("   cookie is scoped to Path=/", sc.contains("Path=/"));

            HttpResponse<String> ok = req(browser, "GET", base + "/dashboard", null, null);
            check("GET /dashboard with session -> 200", ok.statusCode() == 200);
            check("   greets the signed-in user", ok.body().contains("Hello, alice"));

            HttpResponse<String> fixation = req(raw, "POST", base + "/login",
                    "username=bob&password=s3cur3-p@ssphrase-for-bob&_csrf=" + csrf,
                    "csrf=" + csrf + "; SESSION=chosen-by-attacker");
            check("login ignores a client-supplied session id",
                    !setCookie(fixation, "SESSION").contains("chosen-by-attacker"));
            HttpResponse<String> forged = req(raw, "GET", base + "/dashboard", null, "SESSION=chosen-by-attacker");
            check("   the planted id never becomes valid", forged.statusCode() == 302);

            HttpResponse<String> limited = null;
            for (int i = 0; i < 4; i++) {
                limited = req(browser, "POST", base + "/login", "username=hammer&password=x&_csrf=" + csrf, null);
            }
            check("repeated failures are throttled -> 429", limited != null && limited.statusCode() == 429);

            HttpResponse<String> loggedOut = req(browser, "POST", base + "/logout", "_csrf=" + csrf, null);
            check("POST /logout -> 302 /login",
                    loggedOut.statusCode() == 302 && first(loggedOut, "location").contains("/login"));
            HttpResponse<String> reuse = req(raw, "GET", base + "/dashboard", null, "SESSION=" + value(sc));
            check("the old session is dead after logout", reuse.statusCode() == 302);
        }
    }

    // ---- helpers ----

    private static HttpResponse<String> req(HttpClient c, String method, String url,
                                            String body, String cookie) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url));
        if (cookie != null) {
            b.header("Cookie", cookie);
        }
        if (body == null) {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            b.header("Content-Type", "application/x-www-form-urlencoded");
            b.method(method, HttpRequest.BodyPublishers.ofString(body));
        }
        return c.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String first(HttpResponse<?> r, String header) {
        return r.headers().firstValue(header).orElse("");
    }

    private static String setCookie(HttpResponse<?> r, String name) {
        return r.headers().allValues("set-cookie").stream()
                .filter(s -> s.startsWith(name + "=")).findFirst().orElse(null);
    }

    private static String cookieValue(HttpResponse<?> r, String name) {
        String s = setCookie(r, name);
        return (s == null || value(s).isEmpty()) ? null : value(s);
    }

    private static String value(String setCookieHeader) {
        String v = setCookieHeader.substring(setCookieHeader.indexOf('=') + 1);
        int i = v.indexOf(';');
        return i < 0 ? v : v.substring(0, i);
    }

    private static void check(String name, boolean ok) {
        checks++;
        if (!ok) {
            failures++;
        }
        System.out.println((ok ? "  ok   " : "  FAIL ") + name);
    }
}
```

---

## Scripts & meta files

### `build.sh`
```sh
#!/bin/sh
set -eu
cd "$(dirname "$0")"
rm -rf out
mkdir out
find src test -name '*.java' > sources.txt
javac -d out @sources.txt
rm -f sources.txt
echo "compiled -> out/"
```

### `run.sh`
```sh
#!/bin/sh
set -eu
cd "$(dirname "$0")"
[ -d out ] || sh build.sh
exec java -cp out com.example.auth.App
```

### `test.sh`
```sh
#!/bin/sh
set -eu
cd "$(dirname "$0")"
sh build.sh
exec java -cp out com.example.auth.SmokeTest
```

### `.gitignore`
```
/out/
*.class
sources.txt
.idea/
*.iml
```

### `README.md`
```markdown
# Java session-cookie authentication demo

A small but security-conscious web app: it logs a user in with a username and
password and keeps them logged in with a **session cookie**. Standard library
only (`com.sun.net.httpserver`) - no Maven/Gradle, no third-party jars.

## Requirements
JDK 17+ (`java`, `javac` on PATH). Nothing else.

## Build & run
    find src -name '*.java' > sources.txt && javac -d out @sources.txt
    java -cp out com.example.auth.App
    # -> Listening on http://127.0.0.1:8080
(or: `sh build.sh`, `sh run.sh`, `sh test.sh`)

Open http://127.0.0.1:8080/ and sign in with **alice** / `correct horse battery staple`
(or **bob** / `s3cur3-p@ssphrase-for-bob`).

## Try it with curl
    # 1. login page + its CSRF cookie
    curl -s -c jar.txt http://127.0.0.1:8080/login > /dev/null
    CSRF=$(awk '/\tcsrf\t/ {print $7}' jar.txt)

    # 2. log in - watch Set-Cookie: SESSION=...
    curl -i -b jar.txt -c jar.txt \
         --data-urlencode "username=alice" \
         --data-urlencode "password=correct horse battery staple" \
         --data-urlencode "_csrf=$CSRF" \
         http://127.0.0.1:8080/login
    #  HTTP/1.1 302 Found
    #  Location: /dashboard
    #  Set-Cookie: SESSION=<random>; Path=/; Max-Age=1800; SameSite=Lax; HttpOnly

    # 3. reach the protected page with the cookie jar
    curl -i -b jar.txt http://127.0.0.1:8080/dashboard      # 200, "Hello, alice"

    # 4. without the cookie -> bounced to the login page
    curl -i http://127.0.0.1:8080/dashboard                 # 302 Location: /login

## Configuration (environment variables)
| Variable | Default | Notes |
|---|---|---|
| `HOST` | `127.0.0.1` | `0.0.0.0` to accept remote connections |
| `PORT` | `8080` | |
| `SESSION_COOKIE_SECURE` | `false` | **set `true` in production (HTTPS only)** |
| `SESSION_IDLE_TIMEOUT_MINUTES` | `30` | sliding |
| `SESSION_ABSOLUTE_TIMEOUT_HOURS` | `12` | hard cap from login |
| `PBKDF2_ITERATIONS` | `600000` | OWASP 2024 floor; lower only for tests |
| `MAX_LOGIN_FAILURES` | `5` | per username, within the window |
| `LOGIN_FAILURE_WINDOW_MINUTES` | `15` | |

## How the session cookie works, request by request
1. `GET /login` -> HTML form; the response also sets a random `csrf` cookie.
2. `POST /login` (username, password, _csrf):
   - CSRF: `_csrf` field must equal the `csrf` cookie (constant-time compare).
   - `Authenticator` looks the user up and runs PBKDF2 `verify`. Unknown user =
     one PBKDF2 run against a decoy hash, so response time doesn't leak existence.
   - Failure -> `429` if rate-limited, else `401` with a generic message; the
     failure is recorded.
   - Success -> any existing session is invalidated, `SessionManager.create()`
     makes 32 CSPRNG bytes -> URL-safe id, stores {id, username, createdAt,
     lastAccessedAt}, and the handler adds
     `Set-Cookie: SESSION=<id>; HttpOnly; SameSite=Lax; Path=/; Max-Age=...`.
     Response is `302 -> /dashboard`.
3. The browser stores the cookie and replays `Cookie: SESSION=<id>` on every request.
4. `GET /dashboard` goes through `AuthFilter`, which reads the cookie, calls
   `SessionManager.lookup()` (enforces both timeouts, slides the idle deadline),
   and either forwards the request with the `Session` attached or returns
   `302 -> /login`.
5. `POST /logout` (CSRF-checked) calls `SessionManager.invalidate()` and sends
   `Set-Cookie: SESSION=; Max-Age=0` to delete the browser's copy.

## What's built in
Salted PBKDF2-HMAC-SHA256 password hashes; constant-time hash comparison;
uniform unknown-user vs wrong-password timing and messaging; session-fixation
resistance (fresh id at login, client ids never adopted); idle + absolute
session timeouts; failed-login rate limiting; double-submit-cookie CSRF on
every POST; `HttpOnly` / `SameSite=Lax` / optional `Secure` session cookie;
`Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options`,
`Cache-Control: no-store`; request-body size cap.

## Before shipping anything like this
- **HTTPS + `SESSION_COOKIE_SECURE=true`**, add HSTS, consider a `__Host-` cookie prefix.
- **Use Spring Security** (or Jakarta Security / Shiro) instead of hand-rolled
  auth - it gives correct session management, CSRF, headers, lockout policy,
  password-encoder upgrades, "remember me", etc.
- Persist users in a database; add sign-up / reset flows and a breached-password
  (k-anonymity) check; add MFA and step-up re-auth.
- Share state across instances: session store + rate limiter in Redis. A
  server-side synchronizer CSRF token is stronger than double-submit if you have
  any subdomain XSS exposure.
- Audit-log auth events (without logging secrets/PII); alert on anomalies.
- Re-check `SameSite` (`Lax` vs `Strict`) against your SSO / redirect flows.

## Tests
    find src test -name '*.java' > sources.txt && javac -d out @sources.txt
    java -cp out com.example.auth.SmokeTest
Starts the server on an ephemeral port and exercises the whole flow (unauth
redirect, CSRF cookie, wrong-password 401, successful login + cookie attributes,
authenticated access, session-fixation resistance, rate limiting, logout
invalidation). Non-zero exit if any check fails.
```

---

## Build, run, test

```sh
# compile (app only)
find src -name '*.java' > sources.txt && javac -d out @sources.txt

# run  -> http://127.0.0.1:8080   (login: alice / "correct horse battery staple")
java -cp out com.example.auth.App

# compile + run the end-to-end checks
find src test -name '*.java' > sources.txt && javac -d out @sources.txt
java -cp out com.example.auth.SmokeTest
```

I could not compile it here (no `javac` access in this sandbox), so treat the first `javac` run as the verification step. If your JDK is stripped down and reports that `com.sun.net.httpserver` is missing, add `--add-modules jdk.httpserver` to both `javac` and `java` (a normal OpenJDK 17 resolves it automatically).

## The core of what you asked for

- **Accept username + password** — `LoginHandler.handleSubmit` reads the `application/x-www-form-urlencoded` POST body.
- **Verify credentials** — `Authenticator.authenticate` → `PasswordHasher.verify` (PBKDF2, constant-time, salted). Unknown user still runs one hash against a decoy so timing doesn't reveal which usernames exist.
- **Issue a session cookie** — on success, `SessionManager.create` mints a 256-bit random id stored server-side, and the handler emits `Set-Cookie: SESSION=<id>; HttpOnly; SameSite=Lax; Path=/; Max-Age=1800` on the `302 → /dashboard`.
- **Maintain the session** — the browser replays `Cookie: SESSION=<id>`; `AuthFilter` resolves it on every protected request, enforcing idle + absolute timeouts. `POST /logout` invalidates it server-side and clears the cookie.

## Security notes

Built in: PBKDF2 password hashing, constant-time comparison, generic error + uniform timing (no user enumeration), session-fixation resistance (fresh id per login, client-supplied ids never adopted), idle + absolute session timeouts, failed-login rate limiting, double-submit-cookie CSRF on every POST, `HttpOnly`/`SameSite=Lax`/optional `Secure` cookie, CSP + `X-Frame-Options` + `X-Content-Type-Options` + `Cache-Control: no-store`, request-body size cap.

Before production: serve over HTTPS and set `SESSION_COOKIE_SECURE=true`; move the user store to a database; move sessions and the rate limiter to a shared store (Redis) if you run more than one instance; add MFA; and strongly prefer **Spring Security** over hand-rolled auth for anything real — this implementation is meant to make the mechanism legible, not to be a framework.
