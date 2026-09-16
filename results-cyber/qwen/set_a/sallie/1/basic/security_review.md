# Security Review: session-cookie-auth-demo (Jakarta Servlet cookie-session authentication demo)

## 1. Executive Summary

This is a hand-written Java 17 / Jakarta Servlet 6 demo that authenticates users with a server-side session store behind an `app_session` cookie, deployed as a WAR on Tomcat 10.1. Reviewed as a whole, the *application logic* is unusually careful: session ids are 256-bit `SecureRandom` values, session fixation is closed by invalidating the pre-login record and minting a fresh id, every secret comparison goes through `MessageDigest.isEqual`, a single-use 256-bit CSRF token is bound to the session record, the auth filter is default-deny over `/*`, and the login path deliberately spends the full PBKDF2 cost even for unknown usernames so the endpoint cannot be used to enumerate accounts. Section 6 lists these.

The findings are concentrated in the **deployment and configuration layer**, not the servlet code. The most serious issues are:

- The deployment descriptor ships **plaintext passwords for an admin account** (`web.xml:60-68`), and they are repeated in the README, `run-demo.sh` and the end-to-end tests. Anything that can read the WAR — or the git history — holds a domain-admin-equivalent credential.
- Nothing in the application or the generated Tomcat configuration **forces TLS**. The session cookie is marked `Secure` only "if this particular request happened to arrive over TLS", the plain HTTP connector is the one the demo and the tests actually use, and there is no HSTS anywhere. `tests/end-to-end.sh` asserts the insecure behaviour as intended ("over plain HTTP the cookie is deliberately not marked Secure"). Over any network an attacker can observe, the session id travels in cleartext.
- `POST /login` performs **240,000 PBKDF2 iterations for every request from anyone**, and the only gate in front of it — the login throttle — is keyed on `(client IP, username)`. Because the username is attacker-chosen and never validated before the key is formed, an attacker gets an effectively **unbounded number of full-cost stretching operations** by varying the username, saturating the 32-thread executor with a handful of sockets and growing the throttle map without limit.

Everything else is Medium or Low: absent browser-protection headers (clickjacking, MIME sniffing, no CSP), log injection through an unvalidated username, a lockout design that neither stops distributed spraying nor survives a reverse proxy, a PBKDF2 iteration floor of 1,000, and a set of demo-hygiene problems (hardcoded `changeit` keystore password, session ids and passwords written to disk and to the process command line, unauthenticated disclosure of the password and lockout policy).

None of these are exploitable *on localhost with no data behind them*, which is the demo's stated scope — but every one of them is a real vulnerability if the code is lifted into a deployment that carries anything worth stealing, and the README lists most of them as known gaps rather than as solved controls. Findings are reported at the severity they would have in that deployment.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/main/webapp/WEB-INF/web.xml` | Deployment descriptor: all tunables as `context-param` | Sets PBKDF2 iterations (240000), idle/absolute session timeouts, lockout policy, and **two plaintext seed passwords including an `admin` account** (`:60-68`). Session config sets `http-only` and `tracking-mode COOKIE` but no `<transport-guarantee>` and no `<secure>` (`:75-81`) |
| `src/main/java/com/example/auth/web/AuthContext.java` | Builds the app's singletons from init params | Parses the `seed.user.<name> = password \| roles` params into the user store (`:88-108`); defaults iterations to 240 000 (`:57`) |
| `src/main/java/com/example/auth/web/AuthContextListener.java` | Context lifecycle hook | Constructs `AuthContext` at startup; fails fast if no seed account exists |
| `src/main/java/com/example/auth/SessionStore.java` | Server-side session records (the identity source of truth) | 256-bit ids, 256-bit per-session CSRF token, idle + absolute expiry, CAS `touch`, single-use token consumption, background reaper |
| `src/main/java/com/example/auth/InMemoryUserStore.java` | Username → stored-password/roles map | Clones and wipes `char[]` material; no persistence |
| `src/main/java/com/example/auth/PasswordService.java` | PBKDF2-HMAC-SHA256 hashing and verification | `MIN_ITERATIONS = 1_000` (`:25`), `MAX_ITERATIONS = 5_000_000`; constant-time verify that zeroes the digest; `chargeRefusedAttempt` that does **not** (`:137-140`); strict record parsing |
| `src/main/java/com/example/auth/UserStore.java`, `AuthenticatedUser.java` | Interface and immutable principal | Role set is unmodifiable |
| `src/main/java/com/example/auth/web/AuthFilter.java` | Default-deny gate on `/*` | `OPEN_PATHS = {/login, /logout, /status, /favicon.ico}` (`:36`); unknown paths are denied by default; refuses with JSON echoing the request path (`:74-76`) |
| `src/main/java/com/example/auth/web/LoginServlet.java` | Credential verification and session (re)mint | Throttle check → CSRF burn → lookup → equal-cost verify → `finishLogin`; logs the raw username on every rejection (`:113-115`); invalidates the pre-login session before minting (`:130-137`) |
| `src/main/java/com/example/auth/web/LogoutServlet.java` | Ends the session | `POST` only, `GET` → 405 + `Allow`; deletes the record and clears the cookie; **no CSRF token check of its own** |
| `src/main/java/com/example/auth/web/AccountServlet.java` | The protected page | Re-validates via `touch()` even though the filter already did; escapes all dynamic values |
| `src/main/java/com/example/auth/web/StatusServlet.java` | Unauthenticated status JSON | Publishes KDF algorithm, iteration count, session timeouts, cookie flags, and the full lockout policy (`:36-49`) |
| `src/main/java/com/example/auth/web/LoginThrottle.java` | Brute-force throttle | Key is `remoteAddr + "\n" + username` (`:66-68`); 5 failures / 15 min window / 15 min lockout; purge once a minute |
| `src/main/java/com/example/auth/web/Cookies.java` | Cookie read/write | `HttpOnly`, `SameSite=Lax`, `Path=<contextPath>`, **`Secure` only when `request.isSecure()`** (`:51-63`); validates the incoming id against a strict shape before any map lookup |
| `src/main/java/com/example/auth/web/Responses.java` | Response writers | `no-store` on every auth page; JSON gets `nosniff`; **HTML gets no `X-Content-Type-Options`, `X-Frame-Options`, CSP, HSTS or `Referrer-Policy`** (`:17-33`) |
| `src/main/java/com/example/auth/web/Html.java`, `Json.java` | Output encoding | Escapes `& < > " '` for HTML/text and attributes; JSON escapes quotes and control characters |
| `tools/tomcat-env.sh` | Provisions a throwaway Tomcat and its `server.xml` | Generates a 2-day self-signed cert with the **hardcoded password `changeit`** (`:59-62`); cleartext keystore password in the generated file (`:83`); plain HTTP connector with only `redirectPort` (`:78-79`); access log records `%r` |
| `run-demo.sh` | Scripted `curl` walkthrough | Sends the **password as a command-line argument** (`:73`), prints it (`:91`), writes the cookie jar and raw `Set-Cookie` dumps under `build/` (`:24`, `:52`, `:61`) |
| `build.sh` | `javac` + `jar` | Compiles with `-Xlint:all -Werror`; no secrets; not security-relevant beyond that |
| `tests/java/UnitChecks.java`, `tests/unit-checks.sh`, `tests/end-to-end.sh` | Test harnesses | Assert single-use tokens, forged-id rejection, timing equalisation, lockout scoping; **also assert the cleartext-cookie behaviour as intended**, and carry the plaintext passwords |
| `README.md` | Documentation | Repeats both demo passwords; states that real TLS, a real account store, shared session storage, Argon2id, edge rate limiting, CSP and an audit trail are still needed |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router — read every source file first to establish what the code actually does, then selected the specialised skills below by matching that behaviour against the skill library.
- `performing-cryptographic-audit-of-application`: applied to `PasswordService.java` and `SessionStore.java` — KDF choice and iteration bounds, salt/hash lengths, CSPRNG usage, constant-time comparison, and the "Hardcoded Secrets — keys/passwords in source code" class that covers `web.xml:60-68` and `tools/tomcat-env.sh:59-62`.
- `implementing-secret-scanning-with-gitleaks`: applied to the repository as a credential store — the seed passwords, the `changeit` keystore password, and the cookie jars written under `build/` are exactly the patterns a `gitleaks detect --source .` gate is meant to fail on.
- `testing-api-authentication-weaknesses`: applied to `LoginServlet`/`LogoutServlet`/`SessionStore` — token validation and lifecycle, session fixation, enumeration resistance, and Step 6's password-policy and enumeration-by-response-difference checks.
- `testing-for-broken-access-control`: applied to `AuthFilter`/`AccountServlet`/`StatusServlet` — default-deny mapping, path derivation (`pathOf`), open-path inventory, and the horizontal/vertical privilege matrix for the four endpoints.
- `performing-security-headers-audit`: applied to `Responses.java` and the generated `server.xml` — HSTS, HTTP→HTTPS redirect, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options`, `Referrer-Policy`, cache directives, and the cookie-attribute audit.
- `configuring-tls-1-3-for-secure-communications`: applied to `tools/tomcat-env.sh`'s connector and certificate setup — certificate trust, key exchange, and the step that mandates an HSTS header alongside the TLS listener.
- `implementing-api-rate-limiting-and-throttling`: applied to `LoginThrottle.java` and `LoginServlet.doPost` — the distinction between a per-account *failure* limit and a per-IP *request* limit, global limits, and the rule that rate limiting must not be the sole defence.
- `performing-csrf-attack-simulation`: applied to `LoginServlet`, `LogoutServlet` and the `AccountServlet` sign-out form — state-changing inventory, single-use token binding, cross-user token reuse, and `SameSite`/Origin validation as the remaining defence on `/logout`.
- `testing-for-xss-vulnerabilities`: applied to `Html.java`, `Json.java`, `Responses.java` and `AuthFilter.refuse` — output-context analysis of the username, the scraped page title, and the reflected request path in the JSON refusal.
- `testing-for-sensitive-data-exposure`: applied to `StatusServlet` and `LogoutServlet`'s clearing cookie, and to the artifacts `run-demo.sh` leaves on disk (`demo-cookies.txt`, `demo-login.hdr`, `demo-bad.hdr`).

Reviewed against general OWASP Top 10 / CWE knowledge because no skill in the library matched the behaviour: **log forging through unsanitised values written to a logger** (`Logging` without output encoding, CWE-117), **residual sensitive material left unzeroed in memory** (`char[]`/`byte[]` hygiene beyond `Arrays.fill` on the verify path, CWE-226), **secrets exposed in a process command line** (`/proc`-visible argv, CWE-214), and **unbounded growth of an attacker-keyed in-process map** as a memory-exhaustion vector (CWE-770/CWE-400, the growth half of SEC-03).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Plaintext administrator password hardcoded in the deployment descriptor | High | CWE-798 | `src/main/webapp/WEB-INF/web.xml:60-68` |
| SEC-02 | Session cookie transmitted in cleartext: TLS is never enforced and HSTS is absent | High | CWE-319 | `src/main/java/com/example/auth/web/Cookies.java:51-63` |
| SEC-03 | Unauthenticated CPU and memory exhaustion: full PBKDF2 cost per request, throttle bypassable by varying the username | High | CWE-400 | `src/main/java/com/example/auth/web/LoginServlet.java:76-108` |
| SEC-04 | HTML responses carry no `X-Frame-Options`, CSP, `X-Content-Type-Options` or `Referrer-Policy`; no HSTS | Medium | CWE-693 | `src/main/java/com/example/auth/web/Responses.java:17-33` |
| SEC-05 | Log forging: unvalidated, length-unbounded username written to the application log | Medium | CWE-117 | `src/main/java/com/example/auth/web/LoginServlet.java:112-115` |
| SEC-06 | Lockout keyed only on (IP, username): distributed spraying is unthrottled, and a shared source IP is a lockout DoS | Medium | CWE-307 | `src/main/java/com/example/auth/web/LoginThrottle.java:66-68` |
| SEC-07 | PBKDF2 iteration floor of 1,000 accepted for stored password records | Low | CWE-916 | `src/main/java/com/example/auth/PasswordService.java:25-26` |
| SEC-08 | Hardcoded TLS keystore password and untrusted certificate in the Tomcat provisioning script | Low | CWE-259 | `tools/tomcat-env.sh:59-62` |
| SEC-09 | Session identifiers persisted on disk and the password exposed in process arguments | Low | CWE-313 | `run-demo.sh:24-24` |
| SEC-10 | Unauthenticated `/status` publishes the KDF and lockout policy, tuning an attack | Low | CWE-200 | `src/main/java/com/example/auth/web/StatusServlet.java:36-49` |
| SEC-11 | Derived key from the refused-attempt path is never zeroed | Low | CWE-226 | `src/main/java/com/example/auth/PasswordService.java:137-140` |

## 5. Detailed Findings

### SEC-01: Plaintext administrator password hardcoded in the deployment descriptor

- **Severity:** High

- **CWE:** CWE-798: Use of Hard-coded Credentials

- **Location:** `src/main/webapp/WEB-INF/web.xml:60-68`

**Vulnerable code:**

```xml
// src/main/webapp/WEB-INF/web.xml:60-68
  <context-param>
    <param-name>seed.user.alice</param-name>
    <param-value>Alice!2345 | admin,user</param-value>
  </context-param>

  <context-param>
    <param-name>seed.user.bob</param-name>
    <param-value>B0b-the-Builder | user</param-value>
  </context-param>
```

`AuthContext.seedUsers` consumes these verbatim — the literal *is* the credential; it is hashed only after being read out of the descriptor (`src/main/java/com/example/auth/web/AuthContext.java:99-102`):

```java
// src/main/java/com/example/auth/web/AuthContext.java:99-102
            String[] spec = String.valueOf(context.getInitParameter(name)).split("\\|", -1);
            String password = spec[0].trim();
            Set<String> roles = spec.length > 1 ? splitRoles(spec[1]) : Set.of("user");
            seed.put(username, new SeedAccount(password.toCharArray(), roles));
```

**Why it is a problem:** `Alice!2345` is not a placeholder — it satisfies the project's own candidate rules and carries the `admin` role, and it is committed in a file that is packaged into `session-cookie-auth-demo.war`. Everything that can read the artifact therefore holds an administrator credential: anyone with read access to the repository or its git history (the value survives any later edit), anyone who can pull a build artifact or container image, anyone who can read CI output or a startup failure that echoes init parameters. The same literal is repeated at `run-demo.sh:73` and `run-demo.sh:91` and in `tests/end-to-end.sh`, so it also reaches shell history, process listings and test logs. Because the credential is compiled into the deployment, rotating it means rebuilding and redeploying the WAR — in practice it never rotates, and it cannot differ per environment. That is the whole of the hard-coded-credential failure mode: unrotatable, unscoped, unrevocable. The comment at `web.xml:57-58` ("throwaway credentials for a demo on localhost") states intent, not risk; the README presents this code as a pattern to copy, and a copied descriptor carries the credential with it.

**Fix:** Keep the descriptor as *policy* and move the secret out, so the committed file names a source rather than a value. Refuse to start when the secret is absent — a fail-open default is how this bug survives its own fix.

```xml
<!-- src/main/webapp/WEB-INF/web.xml (corrected) -->
  <!-- Names where the credential comes from; contains no secret. -->
  <context-param>
    <param-name>seed.user.alice.source</param-name>
    <param-value>SEED_PASSWORD_ALICE</param-value>
  </context-param>
  <context-param>
    <param-name>seed.user.alice.roles</param-name>
    <param-value>admin,user</param-value>
  </context-param>
```

```java
// src/main/java/com/example/auth/web/AuthContext.java (corrected)
        for (String username : seedUsernames) {
            String source = String.valueOf(
                    context.getInitParameter("seed.user." + username + ".source"));
            String password = System.getenv(source);   // or the platform secret-manager SDK
            if (password == null || password.isBlank()) {
                // No literal default: a missing secret stops startup, it does not fall back.
                throw new IllegalStateException(
                        "Seed account '" + username + "' has no credential in " + source);
            }
            Set<String> roles = splitRoles(
                    context.getInitParameter("seed.user." + username + ".roles"));
            seed.put(username, new SeedAccount(password.toCharArray(), roles));
        }
```

Then: rotate both passwords (assume them compromised), replace the literals in `run-demo.sh` and `tests/end-to-end.sh` with environment lookups, rewrite history with `git filter-repo --replace-text` if the repository was ever shared, and add a gate so it cannot recur:

```bash
# build.sh (append)
gitleaks detect --source . --redact || { echo "secrets committed"; exit 1; }
```

### SEC-02: Session cookie transmitted in cleartext: TLS is never enforced and HSTS is absent

- **Severity:** High

- **CWE:** CWE-319: Authentication of a Security-Critical Channel with Passing of Sensitive Information in Cleartext

- **Location:** `src/main/java/com/example/auth/web/Cookies.java:51-63`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/web/Cookies.java:51-63
    static void writeSessionId(HttpServletResponse response, String sessionId, Duration maxAge,
                               boolean secure, String path) {
        Cookie cookie = new Cookie(AuthContext.COOKIE_NAME, sessionId);
        cookie.setPath(path);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setAttribute("SameSite", "Lax");
        if (maxAge != null) {
            long seconds = Math.max(maxAge.getSeconds(), 0L);
            cookie.setMaxAge(seconds > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) seconds);
        }
        response.addCookie(cookie);
    }
```

Every caller passes the scheme of whichever request happens to be answering, so a session minted over HTTP is issued without `Secure`: `LoginServlet.java:137-139`, `LoginServlet.java:153`, `AccountServlet.java:49-50`, `LogoutServlet.java:34`. The descriptor does not compensate — no `<secure>` element and no `<transport-guarantee>` anywhere in the session config (`src/main/webapp/WEB-INF/web.xml:75-81`):

```xml
// src/main/webapp/WEB-INF/web.xml:75-81
  <session-config>
    <session-timeout>30</session-timeout>
    <cookie-config>
      <http-only>true</http-only>
    </cookie-config>
    <tracking-mode>COOKIE</tracking-mode>
  </session-config>
```

**Why it is a problem:** `Secure` is the only cookie attribute that keeps a session id out of a cleartext request, and here it is derived from the transport an attacker can influence rather than from policy. Nothing marks the application's URLs confidential, so the container never redirects: `redirectPort` in the generated `server.xml` (`tools/tomcat-env.sh:78-79`) only applies to traffic the Servlet spec classifies as transport-protected, and with no `<transport-guarantee>` the plain HTTP connector simply serves the application. That is the path the demo exercises — `run-demo.sh:20` uses the HTTP `BASE_URL`, and `tests/end-to-end.sh` asserts that "over plain HTTP the cookie is deliberately not marked Secure", which makes the weakness load-bearing in the test suite. The consequence is total: any on-path party on a shared network (public Wi-Fi, a compromised router, an ARP or TLS-stripping position) reads `app_session=<id>` from `GET /account` and replays it verbatim — full hijack of any account including the `admin` from SEC-01, with no password involved and the login throttle irrelevant. HSTS, the one mechanism that would stop an HTTPS→HTTP downgrade, appears nowhere: `Responses.java:17-33` emits only cache headers and the connector block (`tools/tomcat-env.sh:80-86`) sets no `StrictHostConfig`/HSTS, so a single stripped request is enough. The session id itself is otherwise well built — 256 bits from `SecureRandom`, strictly shape-validated on read (`Cookies.java:20-21`, `:41`) — but cryptographic strength does not survive transmission in the clear.

**Fix:** Decide the policy in configuration and make the code unable to violate it: mark the cookie Secure unconditionally, let the container own the redirect, and add HSTS.

```xml
<!-- src/main/webapp/WEB-INF/web.xml (corrected) -->
  <session-config>
    <session-timeout>30</session-timeout>
    <cookie-config>
      <http-only>true</http-only>
      <secure>true</secure>
    </cookie-config>
    <tracking-mode>COOKIE</tracking-mode>
  </session-config>

  <!-- The container owns the redirect; nobody has to be lucky enough to type https. -->
  <security-constraint>
    <web-resource-collection>
      <web-resource-name>all</web-resource-name>
      <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
      <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
  </security-constraint>
```

```java
// src/main/java/com/example/auth/web/Cookies.java (corrected)
    static void writeSessionId(HttpServletResponse response, String sessionId, Duration maxAge,
                               String path) {
        Cookie cookie = new Cookie(AuthContext.COOKIE_NAME, sessionId);
        cookie.setPath(path);
        cookie.setHttpOnly(true);
        // Policy, not observation: never mint a cookie that a stripping attack could carry.
        cookie.setSecure(true);
        cookie.setAttribute("SameSite", "Lax");
        if (maxAge != null) {
            long seconds = Math.max(maxAge.getSeconds(), 0L);
            cookie.setMaxAge(seconds > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) seconds);
        }
        response.addCookie(cookie);
    }
```

Remove the `secure` parameter from all four call sites and invert the assertion in `tests/end-to-end.sh` so the insecure path is not merely unused but impossible. Behind a TLS-terminating proxy, derive "was the client's own connection TLS" from a configured, trusted proxy header rather than any header the client sends, and still emit HSTS at the edge: `Strict-Transport-Security: max-age=31536000; includeSubDomains`.

### SEC-03: Unauthenticated CPU and memory exhaustion: full PBKDF2 cost per request, throttle bypassable by varying the username

- **Severity:** High

- **CWE:** CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')

- **Location:** `src/main/java/com/example/auth/web/LoginServlet.java:76-108`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/web/LoginServlet.java:73-76
        String username = trimToEmpty(request.getParameter("username"));
        char[] password = passwordChars(request.getParameter("password"));
        boolean remember = "on".equals(request.getParameter("remember"));
        String throttleKey = LoginThrottle.keyFor(request.getRemoteAddr(), username);
```

```java
// src/main/java/com/example/auth/web/LoginServlet.java:97-110
            Optional<PasswordService.StoredPassword> stored = usernameValid(username)
                    ? context.users().findPassword(username)
                    : Optional.empty();
            boolean credentialsOk = false;
            if (!PasswordService.isUsableCandidate(password)) {
                // A candidate that cannot be verified unambiguously still costs a full stretch, so
                // refusing it is not a fast lane through the endpoint.
                context.passwords().chargeRefusedAttempt(password);
            } else if (stored.isEmpty()) {
                // Same here: "no such user" must not come back instantly.
                context.passwords().chargeRefusedAttempt(password);
            } else {
                credentialsOk = context.passwords().verify(password, stored.get());
            }
```

The throttle that gates this path is keyed on the pair formed above (`src/main/java/com/example/auth/web/LoginThrottle.java:66-68`), and the stretch itself is 240 000 PBKDF2-HMAC-SHA256 iterations (`web.xml:17-20` → `AuthContext.java:57`), served by a 32-thread executor (`tools/tomcat-env.sh:77`).

**Why it is a problem:** The equal-cost design at `:101-107` is correct as anti-enumeration engineering — every request pays the same price so timing cannot reveal whether an account exists — but it means `POST /login` is a fixed-cost CPU bomb available to anyone who can open a socket, and the *only* thing in front of it is a limit whose key the attacker chooses. `keyFor(request.getRemoteAddr(), username)` includes an attacker-supplied username that is never validated before the key is built: `trimToEmpty` (`:187-189`) is the only transformation, and the `USERNAME` pattern at `:36` is consulted later, at `:97`/`:184`, only to decide whether to look the account up. So `alice`, `alice.`, `alice_`, `alice-`, `a` + 63 arbitrary characters each get their **own** five-failure budget, and the failure budget never fills. A few hundred concurrent connections with distinct usernames pin all 32 executor threads in stretching and the site stops serving anyone — permanent self-DoS at trivial client cost, from a single IP, with zero failures recorded. Two amplifiers compound it: the key length is unbounded, so each map entry's *size* is attacker-chosen (a 2 KiB username is accepted here even though `MAX_PASSWORD_CHARS = 1_024` bounds the password at `:38`); and every `GET /login` mints a fresh `SessionStore` record plus a CSRF token and a `Set-Cookie` (`:148-155`), a second unauthenticated allocation path with no limit at all. The throttle map is bounded in *lifetime* — `purgeStale` (`:122-132`) drops entries older than window + lockout, roughly 30 minutes, at most once a minute — so this is exhaustion by cardinality and key size inside that window, not an unbounded leak; that is still enough, because the CPU cost, not the memory, is what takes the site down first. `recordFailure` is already `compute`-atomic (`:94-100`), so none of this is a counter race; it is a missing limit in front of an intentionally expensive operation.

**Fix:** Limit *requests*, not failures, and key the limit on something the attacker does not control. Per-account failure counting stays (it is what stops password guessing), but it can never be the throttle that protects CPU:

```java
// src/main/java/com/example/auth/web/LoginServlet.java (corrected)
        String username = trimToEmpty(request.getParameter("username"));
        // Normalise and bound BEFORE the value is used as a cache/throttle key or logged.
        String subject = LoginThrottle.normaliseUsername(username);   // lowercase, <= 64, else ""
        String throttleKey = LoginThrottle.keyFor(callerAddress(request), subject);

        // Cost guard, independent of the failure budget: no attacker-chosen string can
        // mint an unlimited number of full-cost stretching operations.
        if (!context.limiter().allowLoginAttempt(callerAddress(request))) {
            Responses.doNotCache(response);
            response.setIntHeader("Retry-After", LoginThrottle.RETRY_AFTER_SECONDS);
            Responses.html(response, HttpServletResponse.SC_TOO_MANY_REQUESTS,
                    formHtml(GENERIC_FAILURE, "", false, token, prefix(request)));
            return;
        }
```

```java
// src/main/java/com/example/auth/web/LoginThrottle.java (corrected)
    /** Fixed-length, normalised identity: `Alice.` and `alice_` must not mint separate budgets. */
    public static String normaliseUsername(String username) {
        if (username == null || !USERNAME.matcher(username).matches()) {
            return "";
        }
        return username.toLowerCase(java.util.Locale.ROOT);
    }

    /** Two limits: a per-caller request rate and a global ceiling that protects the KDF pool. */
    public boolean allowLoginAttempt(String callerAddress) {
        Instant now = Instant.now();
        boolean perCaller = tryAcquire(callerKey(callerAddress), LOGIN_ATTEMPTS_PER_MINUTE, now);
        boolean global = globalAdmissions.tryAcquire(now);
        return perCaller && global;   // either exhausted => refuse before any stretching happens
    }
```

Also: bound the throttle map's cardinality (fixed-size LRU, or count keys and shed when the cap is hit) rather than relying only on age; validate the username against `USERNAME` *before* keying anything on it; and put the first line of defence at the edge (WAF/LB connection and request-rate limits), because an in-process limiter is itself a target and dies with the process that needs protecting. Apply the same request limit to `GET /login`, which currently allocates a session per hit.

### SEC-04: HTML responses carry no `X-Frame-Options`, CSP, `X-Content-Type-Options` or `Referrer-Policy`; no HSTS

- **Severity:** Medium

- **CWE:** CWE-693: Protection Mechanism Failure

- **Location:** `src/main/java/com/example/auth/web/Responses.java:17-33`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/web/Responses.java:17-33
    static void doNotCache(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0L);
    }

    static void html(HttpServletResponse response, int status, String bodyHtml) throws IOException {
        doNotCache(response);
        response.setStatus(status);
        response.setContentType("text/html;charset=UTF-8");
        try (PrintWriter out = response.getWriter()) {
            out.print("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n");
            out.print("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
            out.print("<title>" + Html.escape(pageTitle(bodyHtml)) + "</title>\n");
            out.print(STYLE + "</head>\n<body>\n" + bodyHtml + "\n</body>\n</html>\n");
        }
    }
```

**Why it is a problem:** `no-store` is the only header the HTML path sets. The JSON path at least adds `X-Content-Type-Options: nosniff` (`:39`), which shows the omission on the HTML side is an oversight rather than a decision. The practical gaps on a cookie-authenticated login page are: no `X-Frame-Options: DENY` and no CSP `frame-ancestors 'none'`, so any origin can frame `/login` and run a clickjacking or drag-and-drop credential-capture attack against a signed-out victim, with `SameSite=Lax` no protection because the framed request is a same-site top-level navigation from the *victim's* browser; no CSP at all, so there is no defence-in-depth if an escaping bug ever appears in the `Html.escape`/`Html.attribute` sinks (there is no finding against them today — see §6 — but CSP is what makes the next such bug non-exploitable); no `X-Content-Type-Options`, which matters if the container ever serves an uploaded or error-generated document with a sniffable type; and no `Strict-Transport-Security`, which is the downgrade-protection half of SEC-02. The page reflects the submitted username back into the document (`LoginServlet.formHtml`), so this is a page an attacker's content reaches, not a static one. `Referrer-Policy` is absent too: a link out of `/account` leaks the session-bearing URL path to third parties. Individually each header is a hardening layer, which is why this is Medium rather than High; collectively, an authenticated application serving HTML with only cache headers has no browser-side safety net at all.

**Fix:** Set the whole set once, in the single writer, so no new endpoint can forget it:

```java
// src/main/java/com/example/auth/web/Responses.java (corrected)
    static void doNotCache(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0L);
    }

    /** Browser-side protections for every HTML document this application serves. */
    static void securityHeaders(HttpServletResponse response, boolean overTls) {
        // The page embeds one inline <style> block (STYLE above) and loads nothing else.
        response.setHeader("Content-Security-Policy",
                "default-src 'none'; script-src 'none'; frame-ancestors 'none'; "
                        + "base-uri 'none'; form-action 'self'; style-src 'unsafe-inline'");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");               // legacy browsers
        response.setHeader("Referrer-Policy", "same-origin");
        response.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
        if (overTls) {
            response.setHeader("Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains");
        }
    }

    static void html(HttpServletResponse response, int status, String bodyHtml, boolean overTls)
            throws IOException {
        doNotCache(response);
        securityHeaders(response, overTls);
        // ... unchanged body writing ...
    }
```

Add `nosniff` to `json()` as well (already present at `:39`) and emit HSTS from the TLS connector or edge proxy as in SEC-02, so the header exists even for responses this class does not write.

### SEC-05: Log forging: unvalidated, length-unbounded username written to the application log

- **Severity:** Medium

- **CWE:** CWE-117: Improper Output Neutralization for Logs

- **Location:** `src/main/java/com/example/auth/web/LoginServlet.java:112-115`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/web/LoginServlet.java:112-115
            if (!credentialsOk) {
                context.throttle().recordFailure(throttleKey, Instant.now());
                LOG.log(Level.FINE, "Rejected sign-in for user ''{0}'' from {1}",
                        new Object[] {username, request.getRemoteAddr()});
```

**Why it is a problem:** `username` is attacker-controlled and reaches the logger without validation: `trimToEmpty` (`:187-189`) strips outer whitespace and nothing else, and the `USERNAME` check at `:97` decides only whether to *look up* the account — it never stops the value being logged, because the refusal branch at `:101-107` falls through to this line for invalid usernames too. `MessageFormat` quoting (`''{0}''`) protects the message pattern, not the log line. Consequences, in increasing order of cost: a CR/LF in the parameter forges additional log entries with attacker-chosen timestamps and text, letting someone fabricate sign-in attempts for an innocent account or hide a real attack in noise; a quote or bracket breaks whatever parser sits downstream of the appender; there is no length bound on the value at all, so a single request can write an arbitrarily large record into the log pipeline; and because log files are commonly rendered in SIEM dashboards, greps and web UIs, an attacker who later obtains any reflected view of the log gets an injection point there. The Tomcat access log has a companion weakness — `tools/tomcat-env.sh:89-90` records `%r`, the raw request line, and Tomcat's quoting of control characters there is the container's, not this code's — so the same username arrives unsanitised through a second channel. Note this is the integrity-of-evidence problem, not a disclosure one: nothing here leaks a secret, which is why it is Medium.

**Fix:** Log the *validated* identity and nothing else, and bound what you do log:

```java
// src/main/java/com/example/auth/web/LoginServlet.java (corrected)
            if (!credentialsOk) {
                context.throttle().recordFailure(throttleKey, Instant.now());
                // Only a value that matched USERNAME is ever written out; everything else is
                // replaced by a fixed token, so no attacker byte reaches the log stream.
                String logName = usernameValid(username) ? username : "<rejected>";
                LOG.log(Level.FINE, "Rejected sign-in for user ''{0}'' from {1}",
                        new Object[] {logName, request.getRemoteAddr()});
```

```java
// src/main/java/com/example/auth/web/LoginServlet.java (corrected, username intake)
    private static String trimToEmpty(String value) {
        if (value == null) {
            return "";
        }
        // Bound the value before it is used as a key, a log field, or a form value.
        String trimmed = value.trim();
        return trimmed.length() > MAX_USERNAME_CHARS ? trimmed.substring(0, MAX_USERNAME_CHARS)
                                                     : trimmed;
    }
```

Additionally, configure the appender for the deployment's log format (or use a JSON appender that escapes structurally rather than by convention), and treat the access log as untrusted input in dashboards because `%r` reflects the request line.

### SEC-06: Lockout keyed only on (IP, username): distributed spraying is unthrottled, and a shared source IP is a lockout DoS

- **Severity:** Medium

- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts

- **Location:** `src/main/java/com/example/auth/web/LoginThrottle.java:66-68`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/web/LoginThrottle.java:65-68
    /** A key that identifies one caller chasing one account name. */
    public static String keyFor(String remoteAddr, String username) {
        return remoteAddr + "\n" + username;
    }
```

The state behind that key is per-process (`:44`) and pruned only by age, with a single sweep allowed per minute (`:48`, `:121-133`):

```java
// src/main/java/com/example/auth/web/LoginThrottle.java:44-48
    private final Map<String, Attempt> attempts = new ConcurrentHashMap<>();
    private final int maxFailures;
    private final Duration window;
    private final Duration lockout;
    private volatile Instant lastPurgeAt = Instant.now();
```

**Why it is a problem:** The design protects the *pair*, which is the wrong subject for both of the threats a lockout exists to handle. For the attacker: the pair space is enormous, so a spray over many usernames from many source addresses never accumulates five failures against any single key — an adversary holding 500 hosts and one target account can try thousands of passwords with each attempt still arriving at a fresh budget. (The username-variation half of the same weakness is SEC-03, where the payoff is CPU rather than credentials.) For the legitimate user: the same keying makes the lockout trivially weaponisable against the site — anyone behind a shared egress address (corporate NAT, campus, university, mobile carrier CGNAT, a large VPN pool) can lock their neighbours out of *their own* accounts simply by failing five logons as `victim@example.com`, and `verdictFor` (`:70-82`) then returns 429 for everyone else sharing `remoteAddr` for the next 15 minutes. That is denial of service against authentication that an unauthenticated stranger can trigger at will. Two structural problems remain: state lives in one JVM's `ConcurrentHashMap`, so behind a load balancer an attacker sprays per-node budgets and a restart erases every lockout, and `remoteAddr` is `request.getRemoteAddr()` (`LoginServlet.java:76`), which is the immediate socket peer — the attacker's chosen source IP when there is no trusted proxy, and trivially rotated when there is one.

**Fix:** Split the two limits, put one on the account and one on the caller, and use a signal the attacker cannot rotate for free:

```java
// src/main/java/com/example/auth/web/LoginThrottle.java (corrected)
    /** Account-facing limit: keyed on the normalised username only, and enforced cluster-wide. */
    public static String accountKey(String normalisedUsername) {
        return "acct:" + normalisedUsername;
    }

    /** Caller-facing request limit: keyed on the trusted network identity, not on a username
     *  the caller invented, and never used to deny a *different* user's own sign-in. */
    public static String callerKey(String callerAddress) {
        return "ip:" + (isIpv6(callerAddress)
                ? prefix64(callerAddress)          // one /64 is one subscriber, one /32 one host
                : callerAddress);
    }
```

```java
// src/main/java/com/example/auth/web/LoginServlet.java (corrected)
        // Per-account lockout is a shared-state decision: a second instance must see it, and a
        // restart must not erase it. Redis/memcached/DB, not an in-process map.
        if (!context.throttle().accountLockedOut(subject)) {
            // A per-caller *rate* limit is not an account lockout: it throttles the source, it
            // never locks an innocent neighbour out of their own account.
            ...
        }
```

Then: never lock an account solely because of a shared source IP — instead escalate friction (CAPTCHA, step-up, notification to the account holder) and lock the *account* on its own failure history with alerting; back the counters with shared storage; derive the caller address only from a configured trusted-proxy hop; and treat this throttle as one layer behind edge rate limiting, per the rule that rate limiting must not be the sole defence.

---

### SEC-07: PBKDF2 iteration floor of 1,000 accepted for stored password records

- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/example/auth/PasswordService.java:25-26`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/PasswordService.java:21-26
    static final String PBKDF2_SHA256 = "pbkdf2-sha256";
    private static final String KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    static final int MIN_ITERATIONS = 1_000;
    static final int MAX_ITERATIONS = 5_000_000;
```

**Why it is a problem:** The parameters used for *new* hashes are sound — PBKDF2-HMAC-SHA256, a 16-byte `SecureRandom` salt (`:23`, `:28`), a 32-byte derived key (`:24`), and an iteration count configured at 240,000 (`web.xml:17-20`, read at `AuthContext.java:57`). The weakness is in what the verifier is willing to *accept*. A stored record carries its own iteration count inside the serialised string, and `parse` (`:197-208`) plus `StoredPassword`'s constructor (`:172-181`) validate only that the count lies between `MIN_ITERATIONS` and `MAX_ITERATIONS`. A floor of 1,000 therefore means a record written as `pbkdf2-sha256$1000$…` is a structurally valid credential that `verify` will happily check, and stretching 1,000 rounds is roughly 240× cheaper than this deployment's own policy — a GPU fleet that gets 240 seconds against a 240,000-round record gets one second against this one. That matters the moment a record can arrive from anywhere other than `hash()`: an import from an older system, a hand-edited fixture, a corrupted store, or a database restored from a backup taken before the cost parameter was raised. It is also the exact mechanism by which an iteration-count downgrade becomes invisible — there is no warning, no metric, and no rejection, because 1,000 is inside the accepted band by design. The band is otherwise doing real work at the top end (the 5,000,000 ceiling stops a hostile record from spending unbounded CPU per verify), so the bound is not ignored; it is simply set 240× too low at the bottom, which inverts the protection for any record that lands on the floor. Severity is Low rather than higher because every record in this tree's `InMemoryUserStore` is produced by `hash()` at the configured 240,000, so there is no live 1,000-iteration credential today; the finding is about the acceptance boundary, not about a currently crackable hash.

**Fix:** Make the floor the policy, and handle genuine migration by upgrading on login rather than by widening the accepted band:

```java
// src/main/java/com/example/auth/PasswordService.java (corrected)
    // The floor is the policy. A record below it is not a legacy format to tolerate, it is a
    // downgrade, and accepting it silently buys the attacker a 240x cheaper offline crack.
    static final int MIN_ITERATIONS = 240_000;
    static final int MAX_ITERATIONS = 5_000_000;

    /** True when a valid stored record is below today's cost target and should be re-hashed. */
    public boolean needsRehash(StoredPassword stored) {
        return stored == null || stored.iterations() < MIN_ITERATIONS;
    }
```

Then re-derive on the way out of a successful sign-in, which is the only place the plaintext is available:

```java
// src/main/java/com/example/auth/web/LoginServlet.java (corrected, inside the success branch)
        if (context.users().verify(subject, candidate)) {
            StoredPassword stored = context.users().storedPassword(subject);
            if (context.passwords().needsRehash(stored)) {
                context.users().setPassword(subject, context.passwords().hash(candidate));
            }
            completeSession(request, response, context, subject);
```

When the cost parameter is raised later, bump `MIN_ITERATIONS` with it, keep `MAX_ITERATIONS` only as a hostile-record guard, and leave the accepted band's lower edge equal to the current policy so the migration story is "re-hash on next login", never "accept anything above some historical minimum".

---

### SEC-08: Hardcoded TLS keystore password and untrusted certificate in the Tomcat provisioning script

- **Severity:** Low
- **CWE:** CWE-259: Use of Hard-coded Password
- **Location:** `tools/tomcat-env.sh:59-62`

**Vulnerable code:**

```sh
# tools/tomcat-env.sh:58-62
  local keystore="$CATALINA_BASE/demo.jks"
  keytool -genkeypair -alias demo -keyalg RSA -keysize 2048 \
          -dname "CN=localhost, O=throwaway demo, C=US" \
          -validity 2 -storepass changeit -keypass changeit \
          -keystore "$keystore" -storetype PKCS12 >/dev/null 2>&1
```

**Why it is a problem:** The private key that terminates the demo's TLS listener is protected by a passphrase that is written into the script, and the same literal is pasted again into the generated `server.xml` at `tools/tomcat-env.sh:83` (`certificateKeystorePassword="changeit"`). Anyone who can read the keystore can therefore decrypt it: `changeit` is the Tomcat documentation's example password, it is in the file the operator edits, and it never changes between runs, so the passphrase provides no protection at all against the only threat a keystore password exists to address. The script's own comment at `:54-57` makes the certificate deliberately throwaway — regenerated each run, `CN=localhost`, valid for 2 days — which is good hygiene for the *key material* while leaving the *protection of that material* permanently constant. The failure mode that matters is reuse: this file is the template an operator reaches for when the demo becomes a staging environment, and the diff between the two is deleting a comment, not rotating a password nobody ever set. A second, related weakness sits in the same lines: the trust story is not verified anywhere. `tests/end-to-end.sh` reaches the HTTPS connector with `curl -k`, which switches certificate validation off wholesale rather than pinning the throwaway certificate, so every TLS assertion in this repository is made under disabled verification, and nothing checks the protocol floor at all — `:80-86` configures `SSLEnabled="true"` with no `tlsMinVersion` and no cipher-suite preference, inheriting whatever the local JVM defaults to. The practical consequence is that `tests/end-to-end.sh` can prove "a TLS session established" but can never prove "a safe TLS session established", which is the claim a reviewer would otherwise rely on when SEC-02's `Secure` cookie is being delivered over that channel.

**Fix:** Generate the passphrase per run, hand it to `keytool` through a file descriptor rather than the command line, pass it to Tomcat by environment substitution rather than by pasting it into XML, and pin the certificate in tests instead of disabling verification:

```sh
# tools/tomcat-env.sh (corrected)
  local keystore="$CATALINA_BASE/demo.jks"
  local passfile="$CATALINA_BASE/demo-keystore.pass"
  umask 077
  openssl rand -hex 16 > "$passfile" 2>/dev/null || {
    echo "warning: no entropy source for the keystore password; skipping HTTPS setup" >&2
    return 0
  }
  chmod 600 "$passfile"
  keytool -genkeypair -alias demo -keyalg RSA -keysize 2048 \
          -dname "CN=localhost, O=throwaway demo, C=US" \
          -validity 2 -storepass:file "$passfile" -keypass:file "$passfile" \
          -keystore "$keystore" -storetype PKCS12 >/dev/null 2>&1
  # server.xml reads it back by substitution, so the literal never appears in a file:
  #   certificateKeystorePassword="${env.DEMO_KEYSTORE_PASSWORD}"
  export DEMO_KEYSTORE_PASSWORD="$(cat "$passfile")"
```

```xml
      <!-- tools/tomcat-env.sh (corrected): pin the protocol floor while we are here -->
      <Connector port="$HTTPS_PORT" protocol="org.apache.coyote.http11.Http11NioProtocol"
                 executor="demo" SSLEnabled="true" scheme="https" secure="true"
                 tlsMinVersion="1.2" useServerCipherSuiteOrder="true">
        <SSLHostConfig>
          <Certificate certificateKeystoreFile="$keystore"
                       certificateKeystorePassword="${env.DEMO_KEYSTORE_PASSWORD}"
                       type="RSA"/>
        </SSLHostConfig>
      </Connector>
```

```sh
# tests/end-to-end.sh (corrected) - trust the throwaway cert explicitly, do not disable checks
keytool -exportcert -alias demo -rfc -keystore "$KEYSTORE" \
        -storepass:file "$CATALINA_BASE/demo-keystore.pass" > "$WORK/demo.pem"
run curl -sS --cacert "$WORK/demo.pem" "https://localhost:$HTTPS_PORT/$CONTEXT/status"
```

And for anything that outlives a demo run, do not carry the pattern forward: issue a real certificate (`certbot --nginx -d auth.example.com --redirect`) or use the platform's managed TLS termination. If the certificate must stay self-signed, pin it (`--cacert`, or an OS trust-store import) instead of adding `-k`, so the suite keeps testing certificate validation rather than opting out of it.

---

### SEC-09: Session identifiers persisted on disk and the password exposed in process arguments

- **Severity:** Low
- **CWE:** CWE-313: Cleartext Storage in a File or on Disk
- **Location:** `run-demo.sh:24-24`

**Vulnerable code:**

```sh
# run-demo.sh:24-25, 72-73
JAR="$BUILD_DIR/demo-cookies.txt"
rm -f "$JAR"
# …
show "$(curl -sS -o /dev/null -D - -c "$JAR" -b "$JAR" -X POST "$BASE_URL/login" \
    -d 'username=alice' --data-urlencode 'password=Alice!2345' \
```

**Why it is a problem:** The demo writes live credentials into the repository and leaves them there. `JAR` points inside `$BUILD_DIR` (`:24`), so the curl cookie jar — which holds the freshly minted 256-bit session identifier in cleartext — is written to `build/demo-cookies.txt`, and the `rm -f` at `:25` removes it *before* the run rather than after, so it survives on disk indefinitely once the script exits; the directory listing of this folder already shows `demo-cookies.txt`, `demo-login.hdr` and `demo-bad.hdr` sitting next to the WAR. Those two `.hdr` files are the raw response headers at `:52` and `:61`, so the full `Set-Cookie` line — the complete identifier, not a truncated preview — is on disk three times, in a tree whose normal fate is to be committed, packaged, archived, or pasted into an issue. A session identifier is a bearer credential: anyone who reads that file is signed in as `alice` for the remainder of the idle timeout, with no password and no second factor, and `:58` even prints the identifier's first twelve characters to the terminal as part of the demo narrative. The `--keep-open` path makes it worse rather than better: `:89-93` leaves the server running with the jar still on disk, and `:91` prints the account password to stdout (`Sign in as alice / Alice!2345, then stop it with:`), so a demonstration of session security ends by putting the credential in scrollback and in any captured CI log. The second half is CWE-214: `--data-urlencode 'password=…'` (`:63`, `:73`) puts the secret in the argument vector, where every other user on the host can read it from `/proc/<pid>/cmdline` or `ps` for the whole lifetime of the request — which, given the 240,000-iteration stretch this design deliberately charges every attempt, is a window of a few hundred milliseconds per attempt, and an attacker with a `ps` loop does not need to be root. `tests/end-to-end.sh` shows the intended discipline with `WORK=$(mktemp -d …)`, so this is an inconsistency between the two harnesses rather than an unavoidable constraint of the task.

**Fix:** Keep all session artifacts in a mode-700 temporary directory that is deleted on exit, and never put the password or the full identifier on a command line or in stdout:

```sh
# run-demo.sh (corrected)
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sallie-demo.XXXXXX")" || exit 1
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT INT TERM
JAR="$WORK/cookies.txt"
printf '%s' "${DEMO_PASSWORD:?set DEMO_PASSWORD instead of hardcoding it}" > "$WORK/pw"
chmod 600 "$WORK/pw"

show "$(curl -sS -o /dev/null -D "$WORK/login.hdr" -c "$JAR" -b "$JAR" -X POST "$BASE_URL/login" \
    -d 'username=alice' --data-urlencode "password@$WORK/pw" \
    --data-urlencode "csrf_token=$TOKEN" | tr -d '\r' | grep -E '^HTTP/|^Location:')"
```

`--data-urlencode "password@$WORK/pw"` is the curl form that reads the value from a file instead of from argv, which removes the `/proc` exposure without changing the request. For the display at `:55` and `:58`, print a truncated, explicitly labelled preview of the *identifier* only if the demonstration requires it, and print the password nowhere:

```sh
# run-demo.sh (corrected): point at the credential, do not print it
printf 'Sign in as alice (password in %s, not shown here), then stop it with:\n' \
    "$PROJECT_DIR/tests/end-to-end.sh"
```

If a header dump genuinely has to land under `build/` for inspection, redact the value on write (`sed -E 's/(app_session=)[^;]*/\1<redacted>/'`) and add `build/*.hdr build/*cookies*` to `.gitignore` — but note the two files already in this tree need deleting from history, not just ignoring, once they have been committed.

---

### SEC-10: Unauthenticated `/status` publishes the KDF and lockout policy, tuning an attack

- **Severity:** Low
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `src/main/java/com/example/auth/web/StatusServlet.java:36-49`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/web/StatusServlet.java:36-49
        Responses.json(response, HttpServletResponse.SC_OK, Json.object(
                Json.field("application", "session-cookie-auth-demo"),
                Json.field("signedIn", signedIn),
                Json.field("passwordAlgorithm", context.passwords().algorithm()),
                Json.field("passwordIterations", context.passwords().iterations()),
                Json.field("sessionIdleTimeoutSeconds", sessions.idleTimeout().toSeconds()),
                Json.field("sessionAbsoluteTimeoutSeconds", sessions.absoluteTimeout().toSeconds()),
                Json.field("cookieName", AuthContext.COOKIE_NAME),
                Json.field("cookieHttpOnly", true),
                Json.field("cookieSameSite", "Lax"),
                Json.field("cookieSecure", request.isSecure()),
                Json.field("loginMaxFailures", context.throttle().maxFailures()),
                Json.field("loginFailureWindowSeconds", context.throttle().window().toSeconds()),
                Json.field("loginLockoutSeconds", context.throttle().lockout().toSeconds())));
```

**Why it is a problem:** `/status` is one of the three paths the filter is configured to refuse to guard (`AuthFilter.java:36`), so this whole object is readable by anyone who can reach the port. Nothing in it is a credential, which is why the severity is Low — but it is a precise statement of the defensive parameters an attacker would otherwise have to spend effort measuring. `loginMaxFailures`, `loginFailureWindowSeconds` and `loginLockoutSeconds` together describe the entire throttle: the maximum number of guesses available per key per window and exactly how long a locked key stays shut. Discovering that budget by probing costs a real attacker attempts they might otherwise want to keep, and probing wrong risks tripping the lockout early; here the answer is printed, so the attacker sizes the campaign to land just under the ceiling and knows the lockout is a 15-minute inconvenience rather than a barrier. `sessionIdleTimeoutSeconds` and `sessionAbsoluteTimeoutSeconds` state the validity window of any identifier the attacker obtains, which is the planning input for a hijack that has to wait for the victim to go idle. `cookieName` names the header to forge or plant, `cookieSecure: request.isSecure()` confirms which leg of the deployment they are talking to — free confirmation of the SEC-02 downgrade opportunity — and `passwordAlgorithm` plus `passwordIterations` state the offline-cracking cost of a stolen store before the store has even been stolen, including the SEC-07 fact that the accepted band starts far below the advertised 240,000. The design intent is clearly demonstrative — the page exists so a reviewer can see the cookie flags the server just set — but `/status` is served by the same code path in the same WAR that the SEC-01 credential ships in, and a demonstration endpoint that summarises the security configuration is exactly what an unauthenticated scan collects first.

**Fix:** Keep the liveness signal, drop the policy. Everything below the application name is either attacker-useful or derivable by the attacker from a request they can already make:

```java
// src/main/java/com/example/auth/web/StatusServlet.java (corrected)
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        AuthContext context = authContext;
        SessionStore sessions = context.sessions();
        boolean signedIn = sessions.resolve(Cookies.readSessionId(request)).isPresent();
        // Liveness and "is my cookie working" only. KDF parameters, session lifetimes, the cookie
        // name and the lockout budget are the defender's tuning numbers: publishing them hands an
        // unauthenticated caller the exact shape of the throttle and the validity window of a
        // stolen identifier.
        Responses.json(response, HttpServletResponse.SC_OK, Json.object(
                Json.field("application", "session-cookie-auth-demo"),
                Json.field("status", "ok"),
                Json.field("signedIn", signedIn)));
    }
```

If the fuller diagnostics genuinely have to remain reachable for the demo, move them off the open path — remove `"/status"` from `AuthFilter.OPEN_PATHS` (`AuthFilter.java:36`) so only a signed-in caller sees them, and gate the security-sensitive subset on a role rather than on any session (`if (!request.isUserInRole("monitor")) { response.sendError(SC_FORBIDDEN); return; }`). Either way, `tests/end-to-end.sh` currently asserts `"passwordIterations":240000` in the `/status` body, so that assertion has to be retired with the field rather than left to fail — the same class of change SEC-02's fix requires, and the reason to fix the test in the same commit as the code.

---

### SEC-11: Derived key from the refused-attempt path is never zeroed

- **Severity:** Low
- **CWE:** CWE-226: Sensitive Information in Resource Not Removed Before Reuse
- **Location:** `src/main/java/com/example/auth/PasswordService.java:137-140`

**Vulnerable code:**

```java
// src/main/java/com/example/auth/PasswordService.java:137-140
    public void chargeRefusedAttempt(char[] password) {
        Objects.requireNonNull(password, "password");
        derive(password, timingReference.salt(), timingReference.iterations());
    }
```

**Why it is a problem:** `derive` (`:142-153`) returns a freshly allocated 32-byte array containing the PBKDF2 output — real key material — and this call site drops it on the floor. The sibling call site does not: `verify` captures the same return value and wipes it in a `finally` (`:118-125`, `Arrays.fill(digest, (byte) 0)` at `:123`). So the discipline exists in this file, is documented by its own comment at `:134-135` ("the result is thrown away"), and is simply not applied here. The array survives until the garbage collector reclaims it, which in a long-lived Tomcat process with a roomy heap can be minutes or longer, and it is reachable by the same three artifacts as any other heap residue: a core dump, an onOutOfMemory heap dump, or swap. The reason this is worth a finding rather than a style note is that the refusal path is the *only* place in this design where a value derived from a submitted password outlives the request. Everywhere else the class is careful: the request parameter is read as `char[]` and wiped in a `finally` (`LoginServlet.java:108`, `:123`), the `PBEKeySpec` is cleared in `derive`'s own `finally` (`:151`), `InMemoryUserStore` zeroes its working copy (`InMemoryUserStore.java:32-37`), and `verify` zeroes its digest. A reader auditing this class would reasonably conclude no password-derived byte survives the request; the discarded return value at `:139` is the exception, and it is reached on *every* refused attempt — the very traffic that dominates a brute-force run — so a hostile load is what maximises the residue. Scope it honestly: the value is the stretch of the *candidate* password under the timing reference's salt and iteration count (`:139`), not the stored record's digest, so it cannot be replayed as a verifier against the user store, and reading it requires process-memory access that is itself a serious compromise. That is why this is Low and ranked last: it is a defense-in-depth gap in an otherwise unusually careful class, not a path to a credential.

**Fix:** Wipe the discarded value exactly as `verify` wipes its own, in a `finally` so the clear happens on every exit path including the `null` the method returns when the key factory fails (`:147-149`):

```java
// src/main/java/com/example/auth/PasswordService.java (corrected)
    public void chargeRefusedAttempt(char[] password) {
        Objects.requireNonNull(password, "password");
        byte[] digest = derive(password, timingReference.salt(), timingReference.iterations());
        try {
            // The value is not the point; paying the cost is. But it is still derived key
            // material, so it gets the same cleanup verify() gives its digest at :121-124.
        } finally {
            if (digest != null) {
                Arrays.fill(digest, (byte) 0);
            }
        }
    }
```

The structural version of the same fix is to stop handing out arrays that callers must remember to clear: give `derive` a caller-supplied destination buffer (`derive(char[] password, byte[] salt, int iterations, byte[] into)`) or an internal helper that takes a `java.util.function.Consumer<byte[]>` and zeroes the buffer itself, so neither call site can forget. Both approaches carry the same caveat, and it is worth stating once in the code: wiping heap arrays in Java is best available practice, not a guarantee — the JIT may elide a store into an object that is provably dead, and a copying collector can leave the original bytes behind — so if this class ever guards material whose exposure is a real incident, the key should live in a `java.security.Key` held by a provider-backed keystore rather than in a `byte[]` at all.

---

## 6. Verified Controls and Checks With No Finding

The following were examined and found correct, several of them unusually well done for a demonstration component. They are recorded because each one is a plausible finding that a shallower pass would have raised, and because most of them are what keeps the findings above at their current severities.

- **Session identifier entropy** — `SessionStore.java:30-31` (a shared `SecureRandom` and `randomToken()`), `:39` (base64url, no padding), `:66-67` and `:86-87` (identifiers and form tokens). Every identifier and token is 32 cryptographically random bytes, so no identifier is guessable, sequential, time-derived, or `java.util.Random`-derived; I found no `Math.random`, `Random`, `UUID.nameUUIDFromBytes`, or counter-based id anywhere in the request path.
- **Session fixation** — `LoginServlet.java:132` invalidates the pre-login record *before* `newSessionId()` is called at `:133`, so a pre-auth identifier can never become a post-auth one, and `showForm` mints a fresh identifier for every form (`:151`). This is the correct ordering, and it is the control most hand-rolled session implementations get wrong; the demo's own narration at `run-demo.sh:75` asserts it.
- **Logout deletes server state** — `LogoutServlet.java:33` invalidates the record, then `:34` clears the cookie, so the cookie clear is a courtesy rather than the security control. `run-demo.sh:86-87` demonstrates the surviving identifier is dead server-side.
- **Cookie value validated before the store** — `Cookies.java:20-21` (`ID_PATTERN = [A-Za-z0-9_-]{32,128}`) is applied inside `readSessionId` at `:41`, so a hostile, over-long, or non-matching `app_session` is discarded before `SessionStore` is consulted. This is also why SEC-03's unbounded-growth concern is confined to usernames rather than extending to cookie values.
- **Constant-time comparison of every secret** — `MessageDigest.isEqual` at `PasswordService.java:120` (derived digest), `:217-218` (stored-record equality) and `SessionStore.java:139` (form token). No `String.equals`, `==`, `Arrays.equals` or `startsWith` on secret material anywhere in the request path, and no length- or prefix-based early return.
- **CSRF on sign-in** — a 256-bit single-use token, bound to the session record in `showForm` (`LoginServlet.java:151-153`), consumed before any password handling at `:91`, and re-minted on every refusal, so it cannot be replayed across attempts. Store-side consumption requires the presented token to match the record's under a constant-time compare (`SessionStore.java:128-139`), and `run-demo.sh:51-55` plus `tests/end-to-end.sh:136-141` assert the single-use property. No separate token is needed on `/logout` because that endpoint requires the session cookie and the cookie is `SameSite=Lax` (`Cookies.java:57`), so a cross-site POST cannot carry it.
- **Cache discipline on session-bearing pages** — `Responses.doNotCache` (`Responses.java:17-21`) sets `Cache-Control: no-store`, `Pragma: no-cache` and `Expires: 0`, and it is called on the login page (`LoginServlet.java:47`), the account page (`AccountServlet.java:38`), both 401 paths (`AccountServlet.java:41`, `AuthFilter.java:69`), both logout paths (`LogoutServlet.java:31`, `:40`) and `/status` (`StatusServlet.java:24`). I traced every render path that can carry a session-bound value and found none that omits it; `X-Content-Type-Options: nosniff` is set on every JSON response (`Responses.java:39`).
- **Default-deny authorization** — the filter is mapped to `/*` (`web.xml:84-86`) and refuses anything that does not resolve to a live session (`AuthFilter.java:60-64`), with the allowlist held to an exact-match set of three non-sensitive paths (`:36`, `:91-93`) rather than a prefix match, so `/account/anything` cannot ride an open prefix. `AccountServlet` independently returns 401 with `WWW-Authenticate` if the session is gone (`AccountServlet.java:39-46`) rather than trusting the filter, and `touch` (`:39`) enforces both idle and absolute expiry on every request. The refusals themselves are safe: `no-cache` first (`AuthFilter.java:69`), a redirect only for `Accept: text/html` (`:80-89`), and a JSON 401 whose only reflected value is the request path through `Json.quote` (`:74-76`).
- **Method discipline** — `LogoutServlet.java:39-44` answers `GET /logout` with 405, `Allow: POST` and no-cache instead of performing the logout, closing the image-tag and link-prefetch logout vector. No other servlet mutates state from a safe method.
- **Enumeration resistance in both message and timing** — one generic string for every refusal outcome (`GENERIC_FAILURE`, `LoginServlet.java:16`, returned at `:116`), no username echo in any response body, and the timing channel closed deliberately: `chargeRefusedAttempt` (`:101-107`, `PasswordService.java:137-140`) makes an unknown-username request cost the same 240,000 iterations as a real one, which is a level of care rarely seen. The only surviving enumeration signal is the log asymmetry reported as SEC-05; `tests/end-to-end.sh` measures the timing claim across six samples with a 45% tolerance.
- **Password record integrity** — the stored form is `pbkdf2-sha256$iters$b64salt$b64digest` with a 16-byte salt and 32-byte digest, and both the compact constructor (`PasswordService.java:172-181`) and `parse` (`:197-208`) re-check algorithm name, salt length, digest length and iteration bounds, so neither a truncated nor an algorithm-swapped record can be constructed or parsed. `toString()` redacts salt and digest (`:227`), which is what keeps a `StoredPassword` out of a log line. The only weakness in this area is the accepted-iteration floor (SEC-07).
- **Passwords are not Strings, and are wiped** — `LoginServlet.java:108` reads the parameter into a `char[]` (`:178-182`) and clears it in a `finally` at `:123`; `derive` clears the `PBEKeySpec` (`PasswordService.java:151`); `InMemoryUserStore` clears its working copy (`InMemoryUserStore.java:32-37`, `:46`). No `String` password is interned anywhere in the login path. The one gap in this otherwise complete story is SEC-11.
- **Output encoding coverage** — `Html.escape` (`Html.java:13-29`) and `Html.attribute` (`:36`) cover `& < > " '`; `Json.quote` (`Json.java:13-25`) escapes `"`, `\`, `/` and control characters; `Json.field(String,String)` rejects null instead of emitting the literal `null` (`Json.java:24`); `Content-Type` always declares `charset=UTF-8` (`Responses.java:28`, `:37`). Every dynamic value reaching a response goes through one of these encoders (`AccountServlet.java:63`, `:66`, `:70`; `AuthFilter.java:75`), and I found no concatenation of request data into HTML or JSON that bypasses one, no request data inside a `<script>` or `<style>` context, and no unquoted attribute. No XSS finding.
- **Session store bounds** — the constructor rejects a configuration whose `absoluteTimeout` is shorter than `idleTimeout` (`SessionStore.java:45-54`) and caps the form-token TTL at `MAX_FORM_TOKEN_TTL` and the idle timeout, so a mistyped `web.xml` fails loudly at startup instead of issuing identifiers that outlive their own session.
- **Build and test hygiene** — `build.sh` compiles with `-Xlint:all -Werror --release 17` and verifies the WAR layout after packaging, and `tests/unit-checks.sh` compiles its checks with `-Werror` as well as running them under `java -ea`, so a new unchecked or deprecated call fails the build rather than warning quietly. `tests/end-to-end.sh` asserts the single-use form token, refusal of a forged identifier, the equal-cost refusal path, and that the lockout binds only the attempted username. Two of its assertions nonetheless encode current weaknesses as expected behaviour (the "no `Secure` over HTTP" check in SEC-02 and the `"passwordIterations":240000` check in SEC-10), so they must be inverted with the fixes rather than left behind.
- **Harness isolation** — `tools/tomcat-env.sh` builds an isolated `CATALINA_BASE` with its own shutdown port on every run, precisely so a leaked server cannot hold the port and answer for the next run, and the throwaway certificate is regenerated each time (`:54-65`). `tests/end-to-end.sh` works from `mktemp -d` and cleans up, which is the pattern SEC-09 asks `run-demo.sh` to adopt.

Scope and method note: this review read every file in the tree and made no code changes beyond writing this report. The WAR was not rebuilt and neither test suite was executed as part of the review, so behavioural claims are read from the code and from the assertions in `tests/end-to-end.sh` and `tests/unit-checks.sh` rather than re-measured here. `build/` contains output from an earlier run of the harness and was consulted only as on-disk evidence for SEC-09.
