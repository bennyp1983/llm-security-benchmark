## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 3c545a4d-9818-4708-bfdb-c9be092ed854
- **Input tokens:** 4539395
- **Output tokens:** 38501
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 4577896
- **Duration:** 15m 47.668s
- **Turns:** 30

---

`create()` calls `sweep(now)` before put — good (I mis-stated earlier). So expired sessions are reaped on each login, so unbounded growth only during a single login burst; reap requires a login to happen. Fine — Low/Informational. Also, there's no max-size cap. Keep SEC-09 as Low but honest: growth bounded by login rate; the only reap trigger is a new login or an `activeCount()` call, so a store can retain expired records indefinitely after the last login. Fine.

`fingerprint()` lines 111-120 (grep says 107 doc, 111 `public String fingerprint()`). Location: SessionIdentifier.java:111. Digest over US_ASCII. Note: 8 bytes = 64 bits output. Fix: HMAC-SHA-256 with a server-side key.

Now let me write the report. It'll be long but that's expected. Let me carefully produce exact code excerpts.

Excerpts needed:

SEC-01 (LoginServlet.java:35-40):
```java
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
```
Wait line 34 is `@Override`, 35 is `protected void doPost(...)`. Location: LoginServlet.java:35. Excerpt lines 35-38:
```java
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
```
Hmm, 4 lines. Include through line 40 (`CredentialVerifier verifier = verifier();`)? Fine, I'll do 35-40.

Fix for SEC-01: add a limiter. I'll show:
```java
    private static final int MAX_ATTEMPTS_PER_WINDOW = 5;
    private static final Duration WINDOW = Duration.ofMinutes(15);
    private static final ConcurrentHashMap<String, AttemptWindow> ATTEMPTS = new ConcurrentHashMap<>();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // Bound the oracle before anything else: same account or same client address, sliding window,
        // and a failed attempt costs as much as a successful one.
        String clientKey = clientKey(username, request.getRemoteAddr());
        long retryAfter = ATTEMPTS.computeIfAbsent(clientKey, k -> new AttemptWindow()).secondsUntilOpen();
        if (retryAfter > 0) {
            response.setHeader("Retry-After", Long.toString(retryAfter));
            respondError(response, 429, "too_many_attempts", "too many attempts, try again later");
            return;
        }
        ... unchanged verification ...
        if (principal.isEmpty()) {
            ATTEMPTS.get(clientKey).recordFailure(WINDOW);   // failures count, successes reset
            respondError(response, HttpServletResponse.SC_UNAUTHORIZED, "invalid_credentials",
                    "username or password is not correct");
            return;
        }
        ATTEMPTS.remove(clientKey);
```
plus the AttemptWindow class with synchronized logic. Keep it tight but complete. And note in prose: in a multi-node deployment back it with Redis.

SEC-02 (EnvironmentCredentialVerifier.java:50-56):
```java
    private static String configured(String property, String environmentVariable) {
        String value = System.getProperty(property);
        if (value == null || value.isEmpty()) {
            value = System.getenv(environmentVariable);
        }
        return value == null ? "" : value;
    }
```
and 32-33:
```java
        boolean userMatches = constantTimeEquals(expectedUser(), username);
        boolean passwordMatches = constantTimeEquals(expectedPassword(), password);
```
I'll show 22-34? Keep excerpt focused: lines 32-33 + 50-56 would be non-contiguous. The template says "the vulnerable code copied exactly" — one block. I'll copy lines 30-34 & 50-56? Non-contiguous is awkward; I'll copy the contiguous 46-56 block (expectedPassword + configured) and reference line 32-33 in prose. Better: copy 22-34 (verify method) since that's where the plaintext comparison happens, then mention lines 50-56 in prose. Location: `EnvironmentCredentialVerifier.java:32-33` (and :50-56). I'll put `- **Location:** \`src/main/java/com/example/auth/EnvironmentCredentialVerifier.java:32-33\`` and mention 50-56 in prose. Excerpt = lines 29-34:

```java
        if (username == null || password == null) {
            return Optional.empty();
        }
        boolean userMatches = constantTimeEquals(expectedUser(), username);
        boolean passwordMatches = constantTimeEquals(expectedPassword(), password);
        return userMatches && passwordMatches ? Optional.of(new SessionUser(username)) : Optional.empty();
```

Fix: new verifier verifying against a salted Argon2id/bcrypt hash from a store, secret material from a file/vault:
```java
public final class PasswordStoreCredentialVerifier implements CredentialVerifier {

    private final Map<String, PasswordHash> hashByUser;   // PHC strings from a 0400 file or a vault
    private final PasswordHasher hasher = PasswordHashers.argon2id();  // Argon2id via a vetted library

    @Override
    public Optional<SessionUser> verify(String username, String password) {
        if (username == null || password == null) {
            return Optional.empty();
        }
        // One hash for every username, known or not: an unknown account costs the same as a wrong
        // password, so the endpoint is not an enumeration or timing oracle.
        PasswordHash stored = hashByUser.getOrDefault(username, DUMMY_HASH);
        return hasher.verify(stored, password)
                .map(ignored -> new SessionUser(username));
    }
}
```

SEC-03 (SecurityHeadersFilter.java:36-37):
```java
            http.setHeader("Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'");
```
Fix adds frame-ancestors 'none' + X-Frame-Options DENY.

SEC-04 (SessionIdentifier.java:111-116):
```java
    public String fingerprint() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(java.util.Arrays.copyOf(digest, 8));
```
Fix: HMAC-SHA-256 with a per-instance secret key from config, truncated to 16 bytes.

SEC-05 (AuthenticatedSessionServlet.java:59-72) — presentedIdentifier whole method. Fix: fail closed on >1 distinct value:
```java
    protected String presentedIdentifier(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        String name = issuer().config().name();
        String found = null;
        int matches = 0;
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                matches++;
                found = cookie.getValue();
            }
        }
        if (matches > 1) {
            // Request cookies expose only name and value, so Path cannot be inspected here: refuse to
            // guess which one the user agent meant instead of trusting cookie order.
            return null;
        }
        return found;
    }
```
Note: this makes LoginServlet's fixation-removal still work (single cookie).

SEC-06 (SessionCookieIssuer.java:149-157) — the three checks. Fix adds SameSite check:
```java
        if (!hasAttributeWithPrefix(header, "Path=")) {
            throw new IllegalStateException("container dropped the Path attribute for " + cookie.getName());
        }
        String requestedSameSite = cookie.getAttribute("SameSite");
        if (requestedSameSite != null && !hasAttributeWithPrefix(header, "SameSite=")) {
            throw new IllegalStateException("container dropped the SameSite attribute for " + cookie.getName());
        }
```
`Cookie.getAttribute` exists in Servlet 6 ✓ (setAttribute used at line 102).

SEC-07 (Json.java:24-32) — the default branch. Fix: escape `<`, `>`, `&` as \u003c etc.
```java
                default -> {
                    // U+2028/U+2029 terminate a JavaScript literal, and this body may be embedded in a
                    // script tag by a template that trusts it, so the HTML-significant characters are
                    // escaped for that context too rather than left for the template to remember.
                    if (c < 0x20 || c == 0x2028 || c == 0x2029 || c == '<' || c == '>' || c == '&') {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
```

SEC-08 (web.xml:104-112) — session-config block with no user-data-constraint. Fix adds:
```xml
  <session-config>
    ...
  </session-config>

  <!-- The container must refuse to serve the login path over cleartext, not merely hope the operator
       configured TLS. Without this the Secure cookie is the only thing standing between a wrong
       deployment and credentials on the wire. -->
  <security-constraint>
    <web-resource-collection>
      <web-resource-name>everything</web-resource-name>
      <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
      <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
  </security-constraint>
```

SEC-09 (InMemorySessionStore.java:33-40) create + note reap only on login. Location InMemorySessionStore.java:33. Excerpt lines 33-40. Fix: cap + scheduled reap... simplest fix: reject new sessions beyond a cap and remove expired on every access path:
```java
    private static final int MAX_LIVE_SESSIONS = 100_000;

    public AuthenticatedSession create(SessionUser user, Duration ttl) {
        Instant now = Instant.now();
        sweep(now);
        if (sessions.size() >= MAX_LIVE_SESSIONS) {
            // Refuse rather than grow without bound: the map is not evictable and an OOM takes the
            // whole container down with every other user's session in it.
            throw new IllegalStateException("session store is at capacity");
        }
        AuthenticatedSession session =
                new AuthenticatedSession(SessionIdentifier.generate(), user, now, now.plus(ttl));
        sessions.put(session.identifier().value(), session);
        return session;
    }
```
And in findLive: `if (session != null && !session.isLive(Instant.now())) { sessions.remove(identifier.value()); return Optional.empty(); }`.

SEC-10 (LoginServlet.java:73-78) — fixation removal + create; no cap on concurrent sessions for one user, no idle timeout. Fix: revoke prior sessions of the same user (or cap), and store lastSeen for idle timeout:
```java
        String presented = presentedIdentifier(request);
        if (presented != null) {
            store().remove(presented);
        }
        // A new login must not leave the previous ones alive: revoke everything this principal had,
        // so a stolen identifier from an earlier session dies when the user signs in again.
        store().removeAllFor(principal.get());
        AuthenticatedSession session = store().create(principal.get(), ttl());
```
plus `removeAllFor` in store. And note absolute TTL 30min only; add idle timeout check in findLive (AuthenticatedSession needs lastSeen). Keep the store method as the corrected block.

SEC-11 (SecurityHeadersFilter.java:31-35) — Informational: add Permissions-Policy; and __Host- prefix note; and Server token masking (confidential).
Location: SecurityHeadersFilter.java:31. Excerpt lines 31-35. Fix: add Permissions-Policy header + config note for cookie name `__Host-APPSESSION` and server.xml server removal.

Hmm, careful: `__Host-APPSESSION` requires the name to be a valid token — underscore-hyphen fine, and SessionCookieConfig's name validation requires token chars — `__Host-APPSESSION` valid. And Path must be `/` ✓, Secure ✓, no Domain ✓. Good, it qualifies. But TestHarness asserts name APPSESSION — that's a test change; mention in prose.

Now write the report. Executive summary: mention it's a well-hardened cookie layer, 11 findings (2 High/2 Medium/6 Low/1 Informational), none is a direct session-theft or auth-bypass; the two Highs are the authentication layer the code itself flags as a placeholder, plus general header/transport hardening gaps.

§3 Skills applied bullets — each with a short note of what it covered. Plus the "general knowledge" note.

Let me write it now. Keep tables tidy. Also I must ensure only ONE `#` heading. Section 3 title is "Skills Applied". Good.

For the Scope table, 24 files → long but required ("| File | Purpose | Security-relevant behaviour |"). I'll include all source, config, scripts, README, tests, and note the harness txt files excluded. Actually including prompt.txt etc. in the table as "not application code" is cleaner for completeness. I'll add a line under the table instead.

Let me write the file.
</think>

Now I have everything verified. Writing the report.
