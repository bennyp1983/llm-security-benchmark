# Security Review: secureauth — Java Servlet Login + Hardened Session Cookie

## 1. Executive Summary

This folder is a **run-result directory, not a source tree**. It contains five files and **no `.java`, `.xml`, `.sh` or `README` file at all**. The task that produced it (`prompt.txt`) asked for a Java web application that authenticates a user and issues a session cookie protected from client-side script access; the run's own record shows it planned those sources (`result.md`: "Batch 1: CredentialStore.java, SessionRegistry.java, SessionCookieFactory.java.") and then ended before writing any of them.

The **only code in this folder is therefore embedded inside `return.txt`**, a one-line JSON array that is the transcript of that generation run. The reviewable code is the 466-line design/reasoning block carried by element 11 of that array (`message.content[0].text`), which contains concrete Java/XML/bash snippets plus the security decisions that produced them. Everything below is evidenced against that artefact.

Headline result: the **primary requirement is met and correctly engineered** — the session cookie is built with `HttpOnly`, `Secure`, `SameSite=Lax` and `Path=/`, the token is 32 bytes from `SecureRandom`, sessions rotate on login and are revoked on logout, and URL rewriting is disabled. Seven issues were found in the code and decisions that *are* present, the two most serious being **hard-coded plaintext credentials for the demo accounts** (which are, as a consequence, sitting in plaintext in `return.txt` in this very folder) and **a delivered build/verification path that serves the login form and POSTs credentials over plain HTTP with no TLS listener**, which makes the `Secure` flag non-enforceable in the shipped configuration.

The credential/KDF area is the weakest part: the PBKDF2 work factor was chosen to keep a test suite fast, and the brute-force lockout is keyed on a client address the attacker controls. Finally, note that most function bodies in the artefact are elided (`{...}`, "touch and return userName"), so several controls are asserted by design notes rather than by code and could not be verified — see §6.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `return.txt` (61,292 B) | JSON-array transcript of the generation run; 16 array elements (indices 0-15), single physical line. Element 2: two `read_file` calls (`prompt.txt`, then itself; results at 3/4). Elements 6 and 9: two `run_shell_command` env probes (`java -version` / `javac -version`; `ls` of the Tomcat lib plus `javap` on `servlet-api.jar`). Element 12: `todo_write` (planning only). **Element 11: a 41,263-char, 466-line text block holding all generated code and design decisions.** Element 15: run result. | Only code-bearing file. Carries: PBKDF2 `CredentialStore` with hard-coded seed passwords, `SessionRegistry` (token entropy, storage, timeouts), `SessionCookieFactory` (cookie attributes), `LoginAttemptGuard` (lockout keying), login/logout servlet flow, `web.xml`, `build.sh`, `verify-in-container.sh`. Also **stores the plaintext demo passwords on disk** and documents "no TLS in the demo", "skip CSRF on login". |
| `result.md` (615 B) | Run metadata (CLI, set, token counts, duration, turns, conversation ID) plus the tail of the last assistant message. | No code. Confirms the run stopped at "Writing the credential store, session registry, and the hardened-cookie factory first." — i.e. no sources were ever emitted. Discloses internal conversation ID and token accounting (informational only). |
| `prompt.txt` (515 B) | The original generation request. | Defines the security requirement under review: cookie "must be protected from being read or manipulated by any client-side script". No code. |
| `cyber_prompt.txt` (2,106 B) | The review instruction text (this task). | No code. |
| `prompt_hash.txt` (64 B) | SHA-256 of the prompt (`8d045961…4c90`). | Integrity check only; no vulnerability surface. |

**Review convention.** `return.txt` is one physical line, so `file:line` citations below are given as `return.txt:<n>` where `<n>` is the line number inside the decoded text block of array element 11. That numbering is reproducible with:

```bash
python3 -c "import json;print(json.load(open('return.txt'))[11]['message']['content'][0]['text'])" | nl -ba
```

No files were created or modified other than this report.

## 3. Skills Applied

- `performing-cryptographic-audit-of-application` — read in full and applied as the primary lens: hashing-algorithm inventory, KDF work factor, randomness source, constant-time comparison, key/secret material handling, deprecated primitives. Drove SEC-01 and SEC-03.
- `testing-api-authentication-weaknesses` — credential stuffing / brute-force surface, token entropy and entropy source, token-in-URL leakage, server-log leakage, generic vs. distinguishable authentication failures. Drove SEC-04 and the no-finding conclusions on user enumeration, token entropy and session-fixture rotation.
- `implementing-api-rate-limiting-and-throttling` — lockout keying, per-account vs. per-IP policy, shared-state requirements for multi-instance deployments ("in-memory rate limiting without shared state across instances, allowing limit bypass"). Drove SEC-04 and SEC-06.
- `performing-csrf-attack-simulation` — state-changing endpoint inventory, anti-CSRF token presence, and the explicit rule that SameSite is defence-in-depth rather than a CSRF-token substitute. Drove SEC-05.
- `testing-for-sensitive-data-exposure` — data-in-transit ("sensitive data transmitted over network without TLS encryption"), secrets in source/README/logs, credentials in query strings, response-header hygiene. Drove SEC-02 and the no-finding conclusions on `no-store`/`nosniff`/CSP and query-string rejection.
- `implementing-secret-scanning-with-gitleaks` — hard-coded-credential detection heuristics and the move-to-external-store + rotate remediation pattern. Applied to SEC-01.

Covered with general OWASP/CWE knowledge rather than a dedicated skill in this library: HTTP cookie attribute semantics and session-fixation/rotation correctness (`CWE-384`), XSS escaping of the reflected username (`CWE-79`), `HttpOnly`/`SameSite` effectiveness against `document.cookie` theft (the stated core requirement), Java `PBEKeySpec` non-injectivity and `char[]` zeroisation (`CWE-316`, `CWE-1178`), unbounded in-memory growth of the attempt guard (`CWE-400`), and shell-quoting hygiene in `build.sh`.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Plaintext demo passwords hard-coded into the credential store | High | CWE-259 | `return.txt:455` |
| SEC-02 | Login served and exercised over plain HTTP; no TLS listener in the delivered configuration | High | CWE-319 | `return.txt:136` |
| SEC-03 | PBKDF2 iteration count chosen to keep the test suite fast | Medium | CWE-916 | `return.txt:192` |
| SEC-04 | Brute-force lockout keyed on a spoofable client address, in-process only | Medium | CWE-307 | `return.txt:264` |
| SEC-05 | No anti-CSRF token on the login POST; SameSite treated as the sole defence | Medium | CWE-352 | `return.txt:54` |
| SEC-06 | Attempt-guard map has no eviction path — unbounded growth | Low | CWE-400 | `return.txt:272` |
| SEC-07 | Password retained as an immutable `String` that cannot be zeroised | Low | CWE-316 | `return.txt:350` |

## 5. Detailed Findings

### SEC-01: Plaintext demo passwords hard-coded into the credential store

**Severity:** High
**CWE:** CWE-259: Use of Hard-coded Password (related: CWE-798 Use of Hard-coded Credentials)
**Location:** `return.txt:455`

**Vulnerable code:**

```text
// return.txt:454-457
For the login demo users, seed: alice/wrong? Use:
- alice / "correct horse battery staple" (spaces OK in password)
- bob / "Sun!7hrow-lab#quay"
Print them in README + on the login page? Printing creds on the page is bad practice-ish but it's a demo. Put them in README only, and mention the login page has a hint? No hints. README only. Hmm — for a demo, usability matters; I'll print them to the servlet container log at startup at INFO (server-side only, not the browser). Good compromise.
```

The consequence of that decision is visible in the store's own constructor, which is handed plaintext passwords and hashes them at startup:

```java
// return.txt:200-203
    public CredentialStore(Map<String, String> usersToPlaintextPasswords) {
        usersToPlaintextPasswords.forEach((u,p) -> storedRecords.put(u, hash(p)));
        this.dummyRecord = hash("placeholder-password-that-is-not-assigned-to-any-account");
    }
```

**Why it is a problem:** The passwords are constants in the shipped artefact, so anyone who can read the source, the README, or this folder can authenticate as `alice` or `bob`. Two concrete amplifiers: (a) the review artefact `return.txt` in *this* directory already discloses both secrets in plaintext (`return.txt:455-456`), so the credentials leak with the transcript, log bundle, or CI cache long before the README does; (b) the plan also proposes printing them to the container log at INFO (the note at `return.txt:457` is only talked out of a few lines later at `return.txt:459`), which would put them in a second, usually world-readable location. A `Map<String,String>` of plaintext also keeps the secrets alive in the heap of every JVM that boots the app, and the "hash at startup" step means the store cannot be populated from pre-computed records — the plaintext has to exist somewhere in the deployment. This is exactly the hard-coded-credential class the secret-scanning skill exists to catch, and it is the highest-severity item here because the credential store *is* the authentication boundary.

**Fix:** Never let plaintext reach the constructor. Derive records offline, ship only records, and load them from a file outside the WAR with tight permissions:

```java
// CredentialStore.java — accepts already-derived records only.
// Records are generated once, off the deployment machine, in the format the
// design already fixes at return.txt:50 (pbkdf2$sha256$iters$saltB64$keyB64):
//   $ java -cp build/classes com.example.auth.HashTool
//   pbkdf2$sha256$600000$<b64 salt>$<b64 tag>
// and pasted into ${catalina.base}/conf/users.properties (chmod 0600, NOT in the
// WAR, NOT in git). Each deployment generates its own values; none is committed.
public CredentialStore(Properties userNameToStoredRecord) {
    userNameToStoredRecord.stringPropertyNames()
            .forEach(u -> storedRecords.put(u, userNameToStoredRecord.getProperty(u)));
    this.dummyRecord = hash("placeholder-password-that-is-not-assigned-to-any-account");
}
```

Additionally: treat `correct horse battery staple` and `Sun!7hrow-lab#quay` as burned and rotate them; scrub both values from the README and from any transcript/log/CI artefact that retains them (including this folder's `return.txt`); and add a secret-scanning gate so a literal password in `src/` fails the build rather than reaching review.

### SEC-02: Login served and exercised over plain HTTP; no TLS listener in the delivered configuration

**Severity:** High
**CWE:** CWE-319: Cleartext Transmission of Sensitive Information
**Location:** `return.txt:136`

**Vulnerable code:**

```text
// return.txt:136
Optionally add a TLS connector to Tomcat for a real secure demo. Skip; mention in README that the demo runs over http for testing while the cookie still carries Secure, and production must terminate TLS.
```

The delivered container wiring that follows from that decision:

```text
// return.txt:397
Ports: use 18449 HTTP, 18450 shutdown. Need to copy conf from Tomcat home. Use `cp -r /tmp/apache-tomcat-10.1.59/{conf,bin,lib,}`? CATALINA_BASE needs conf, logs, temp, webapps, work. Simplest: create build/catalina with conf copied, and empty webapps/logs/work/temp.
```

**Why it is a problem:** The only runnable configuration in the artefact listens on an HTTP connector; there is no HTTPS connector and no `transport-guarantee`, so credentials and the resulting session token are transmitted in the clear and the review's own `verify-in-container.sh` end-to-end check exercises the app that way. `cookie.setSecure(true)` (`return.txt:326`) is therefore unverifiable in practice — a browser will not store or resend a `Secure` cookie over `http://`, and the artefact notices exactly this and works around it rather than fixing the transport (`return.txt:134`: "cookies marked secure are only sent over https. That would break the test flow."). The workaround is to bypass the cookie engine and hand the header to curl, which means the shipped test *proves the header is set* while the deployed configuration *cannot use it*: an on-path attacker on the demo/verification network captures `password=` in the POST body and the `SESSION=` value verbatim, giving immediate account access and a valid session. The same note ("production must terminate TLS") pushes a load-bearing control into prose the code cannot enforce, so nothing prevents the demo configuration from being promoted. Per the sensitive-data-exposure skill, credentials sent without TLS is a High.

**Fix:** Ship a TLS listener and make the container refuse plaintext, so the configuration cannot regress:

```xml
<!-- conf/server.xml of the CATALINA_BASE built by tests/verify-in-container.sh -->
<Connector port="18449" protocol="HTTP/1.1" address="127.0.0.1" redirectPort="18450"/>
<Connector port="18450" protocol="org.apache.coyote.http11.Http11NioProtocol"
           address="127.0.0.1"
           SSLEnabled="true" scheme="https" secure="true"
           keystoreFile="${catalina.base}/conf/localhost.p12" keystoreType="PKCS12"
           keystorePass="${TLS_KEYSTORE_PASSWORD}"
           sslProtocol="TLSv1.3"/>
```

```xml
<!-- web.xml: enforce TLS in the application, independent of connector mistakes -->
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

Generate a throwaway self-signed certificate for the verification run and drive the checks with `curl --cacert build/tls/ca.pem https://127.0.0.1:18450/auth/login`; the cookie engine then works normally, so the `Secure` flag is actually exercised end-to-end.

### SEC-03: PBKDF2 iteration count chosen to keep the test suite fast

**Severity:** Medium
**CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
**Location:** `return.txt:192`

**Vulnerable code:**

```java
// return.txt:191-194
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 100_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
```

The rationale is recorded explicitly in the same artefact:

```text
// return.txt:106
CredentialStore: needs seed users. Use PBKDF2 with 120k iterations (memory: 50k≈70-85ms, 100k≈143ms) — so 200k ≈ 280ms per login, acceptable for demo but timing tests need care. Use 100_000 to keep suite fast (~143ms). Document how to raise it.
```

**Why it is a problem:** The work factor was set by a *test-suite* budget, not by an attacker-cost budget — the note names 120k, then lowers it to 100_000 "to keep suite fast". The artefact also contradicts its own spec: the design note at `return.txt:50` fixes `PBKDF2WithHmacSHA256, 210k iterations`, and the shipped constant is less than half that, with no recorded decision to change it. OWASP's 2023 guidance is 600,000 iterations for PBKDF2-HMAC-SHA256 (and recommends argon2id/scrypt where available), so the shipped value is roughly a sixth of the recommended cost, and the artefact even measures the linear trade-off it is giving away (~143 ms per login). Because `ITERATIONS` is a compile-time constant baked into the stored record, an operator who later wants a higher cost cannot raise it without a rehash-on-next-login migration path, which is only "documented", not implemented. The impact is bounded to the offline case — salted per-record storage (`return.txt:193`, `SALT_BYTES = 16`) prevents rainbow tables and cross-user amortisation, and `KEY_BITS = 256` is correct — so this is Medium rather than High: it matters only after the record store is exposed, but it is the control that decides whether that exposure means every password falls.

**Fix:** Set the cost from the server's login-latency budget, and remove the incentive to lower it by giving tests a path that does not call the KDF:

```java
// CredentialStore.java
private static final int ITERATIONS = 600_000;   // OWASP 2023 floor for PBKDF2-HMAC-SHA256.
                                                 // Raise by benchmarking, not by lowering to
                                                 // suit tests: argon2id is preferable when the
                                                 // platform offers it.

// Records are already self-describing (return.txt:50 fixes the format as
// pbkdf2$sha256$iters$saltB64$keyB64), so the cost can live with the record
// instead of with the constant:
//   pbkdf2$sha256$600000$<b64 salt>$<b64 tag>
private static boolean verifyAgainst(String record, char[] password) {
    Record r = Record.parse(record);             // per-record algorithm/iterations/salt/tag
    return MessageDigest.isEqual(derive(r.algorithm, r.iterations, r.saltBits, password), r.tag);
}
```

```java
// Test seam: parsing/format tests must not pay the KDF cost.
CredentialStore(Map<String, String> userNameToPrecomputedRecord, boolean alreadyDerived) { ... }
```

That gives per-record iteration counts, which is also what makes a future cost increase possible without invalidating existing users.

### SEC-04: Brute-force lockout keyed on a spoofable client address, in-process only

**Severity:** Medium
**CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
**Location:** `return.txt:264`

**Vulnerable code:**

```text
// return.txt:264
LoginAttemptGuard: key = username + '|' + remoteAddr? IP can be spoofed/proxied; note in README. Fixed window: max failures 5 within 15 minutes, lock 15 minutes. Return remaining seconds.
```

The second excerpt is quoted inside a four-backtick fence because the quoted passage from `return.txt` contains its own triple-backtick fences verbatim:

````text
// return.txt:266-272
```java
public final class LoginAttemptGuard {
    private record Attempt(int failures, Instant firstFailureAt, Instant lockedUntil) {}
```
records with methods fine. Use ConcurrentHashMap<String, Attempt> + merge. Simpler: a small mutable static class.

Behavior: `LockState check(key)`; `recordFailure(key)`; `recordSuccess(key)` removes.
````

**Why it is a problem:** The key fuses the account name with `req.getRemoteAddr()`, and the concern is raised in the same sentence and then dismissed into a README note instead of being resolved. `getRemoteAddr()` returns the peer socket address, which is attacker-chosen whenever the app is reachable directly (spoofed or rotated source addresses) and always attacker-influenced behind a proxy that has not been configured to rewrite it (`RemoteIpValve`). Under either condition the effective policy is "5 failures per 15 minutes *per client IP the attacker picks*", so a distributed credential-stuffing run never trips the lock while still hitting the intended account — and the legitimate user gets locked out because their own entry fills up, turning the control into a login-denial lever against `alice`. The state is also a plain `ConcurrentHashMap` inside one JVM with no shared backend, so it is reset by a restart and invisible to other nodes: the rate-limiting skill flags exactly this ("in-memory rate limiting without shared state across instances, allowing limit bypass"). The design is otherwise sound — a fixed window with `lockedUntil` and `Retry-After` — so the defect is the key and the storage, not the policy.

**Fix:** Key on the account, keep the client address only as a secondary signal that is trusted when the proxy chain is declared, and put the counters where the sessions are:

```java
public final class LoginAttemptGuard {
    // Account is the unit of policy. remoteAddr is NOT part of the key: the servlet
    // container's value is attacker-chosen unless Tomcat sits behind a declared proxy
    // (RemoteIpValve remoteIpHeader/trustedProxies). Add an optional per-IP ceiling
    // from RemoteIpValve-resolved addresses as a separate, wider budget.
    private final ConcurrentHashMap<String, Attempt> failuresByUserName = new ConcurrentHashMap<>();

    public OptionalLong lockoutRemainingSeconds(String userName, Instant now) { ... }
    public void recordFailure(String userName, Instant now) { ... }
    public void recordSuccess(String userName) { ... }
}
```

For anything that runs more than one JVM or must survive a restart, back the same interface with the shared store the sessions use (JDBC/Redis); for a single-node demo, state in the README that the guard resets on restart and is per-node.

### SEC-05: No anti-CSRF token on the login POST; SameSite treated as the sole defence

**Severity:** Medium
**CWE:** CWE-352: Cross-Site Request Forgery (CSRF)
**Location:** `return.txt:54`

**Vulnerable code:**

```text
// return.txt:54
Let me be moderate: include rate limiting? I'll skip lockout, but include: salted PBKDF2, constant-time verify, equal-work unknown user, session rotation on login, idle+absolute timeout, HttpOnly/Secure/SameSite/Path session cookie, CSRF token issued in session and validated on login POST (that's a genuine, in-scope protection for a login form? Login CSRF is a real thing but a CSRF token on the login form requires a session before login...). Skip CSRF on login; mention in README as out of scope. Actually, for the protected POST (logout), CSRF matters more — SameSite=Lax + POST-only logout covers it reasonably. I'll require POST for logout.
```

**Why it is a problem:** The login endpoint is a state-changing POST that accepts cross-origin form submissions with no per-request secret, and the artefact explicitly defers the control ("Skip CSRF on login"). The reasoning that follows — SameSite plus POST-only is "reasonable" for logout — does not transfer to login, and the CSRF skill is explicit that SameSite is defence-in-depth, not a token substitute: `Lax` still permits top-level navigations and is absent entirely for clients that do not implement it, and an attacker can satisfy even `Lax` from a same-site origin obtained elsewhere — a limitation the artefact itself names correctly at `return.txt:132` ("Lax doesn't defend against an attacker hosting on the same registrable domain (subdomain)") and then does not act on for the login endpoint. The concrete impact of login CSRF here: an attacker submits their own known credentials in the victim's browser, so the victim's session — bound to the attacker's account, with the attacker's data on the dashboard — is created inside the victim's cookie jar. That is the classic session-fixture-by-login attack, and it is the exact threat the `Secure`/`HttpOnly` cookie cannot address because the attacker never needs to read the cookie. The plan's own mitigations do not help either: rotation at login (`return.txt:343`) rotates the *attacker-chosen* identity, and the username allow-list (`return.txt:356`) validates the attacker's username perfectly well.

**Fix:** Mint a login token before authentication and require it on the POST — this does **not** require an authenticated session, only a pre-login one:

```java
// LoginServlet.doGet — bind a token to the pre-login session, render it in the form.
HttpSession pre = req.getSession(true);
String csrf = CsrfTokens.issue(pre);                     // 32 bytes, SecureRandom, base64url
out.print("<form method=\"post\" action=\"login\">");
out.print("<input type=\"hidden\" name=\"csrf\" value=\"" + Html.escape(csrf) + "\">");

// LoginServlet.doPost — reject before any credential work, so there is no
// credential oracle and no lockout budget consumed by junk requests.
if (!CsrfTokens.matchesExistingSession(req, req.getParameter("csrf"))) {
    resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
    resp.setHeader("Cache-Control", "no-store");
    return;
}
```

Keep `SameSite=Lax` as the second layer, and note in the README that the token, not SameSite, is the control.

### SEC-06: Attempt-guard map has no eviction path — unbounded growth

**Severity:** Low
**CWE:** CWE-400: Uncontrolled Resource Consumption
**Location:** `return.txt:272`

**Vulnerable code:**

```text
// return.txt:270-272
records with methods fine. Use ConcurrentHashMap<String, Attempt> + merge. Simpler: a small mutable static class.

Behavior: `LockState check(key)`; `recordFailure(key)`; `recordSuccess(key)` removes.
```

Compare with the sibling component in the same artefact, which is given the sweep this one lacks:

```java
// return.txt:311-312
    private static String digest(String token) // sha-256 hex so the map alone is not replayable
    public int removeExpired()
```

**Why it is a problem:** `SessionRegistry` gets an explicit `removeExpired()` reaper; `LoginAttemptGuard` is specified with only `check` / `recordFailure` / `recordSuccess`, and the sole removal path is a *successful* login. Expired entries for one-off keys are never dropped, so the map grows monotonically with the number of distinct `username|remoteAddr` pairs an attacker has ever produced. Because the guard sits on the unauthenticated endpoint, that growth is attacker-controlled and cheap: one failure per new (username, address) pair is enough, and per SEC-04 the address component is not trustworthy, so the key space is effectively unbounded. Each retained `Attempt` record is small, but the ratio is strongly asymmetric — a few bytes of request per retained object held for the lifetime of the JVM — which makes this a low-cost memory-exhaustion lever and a restart-amplifier (the counters are lost on restart, so the attacker pays nothing to reset them). It is Low because it degrades availability rather than bypassing authentication, and because a bounded heap plus a container restart recovers the service.

**Fix:** Give the guard the same expiry sweep as the registry, plus a hard ceiling so the size is bounded even under a fresh-key flood:

```java
public final class LoginAttemptGuard {
    private static final int MAX_TRACKED_KEYS = 100_000;   // bound > attacker churn

    // Same scheduled task that calls SessionRegistry.removeExpired().
    public int removeExpired(Instant now) {
        int before = attempts.size();
        attempts.entrySet().removeIf(e -> e.getValue().expiredBy(now));
        return before - attempts.size();
    }

    public void recordFailure(String key, Instant now) {
        if (attempts.size() >= MAX_TRACKED_KEYS) {
            attempts.entrySet().stream()
                    .min(Comparator.comparing(e -> e.getValue().firstFailureAt()))
                    .ifPresent(e -> attempts.remove(e.getKey()));   // evict oldest window
        }
        attempts.merge(key, Attempt.first(now), Attempt::accumulate);
    }
}
```

### SEC-07: Password retained as an immutable `String` that cannot be zeroised

**Severity:** Low
**CWE:** CWE-316: Plaintext Password in Memory Through Process Memory (related: CWE-1178)
**Location:** `return.txt:350`

**Vulnerable code:**

```text
// return.txt:350
Password char[]: getParameter returns String. Convert with `.toCharArray()`. Ideally wipe the String — impossible in Java; mention in README. Also cap length (>= 8? no min enforcement — reject > 1024 to bound PBKDF2 cost) and reject NUL / unpaired surrogates (PBEKeySpec is not injective).
```

**Why it is a problem:** `req.getParameter("password")` hands back an immutable `String` that the JVM cannot overwrite, so the plaintext credential stays resident until that object is collected — and `String` contents are frequently copied into `char[]` internals, interned tables, heap dumps and `-XshowSettings`/debug tooling along the way. The plan acknowledges the problem and resolves it by documentation ("impossible in Java; mention in README"). The surrounding code is careful in every other respect — it converts to `char[]` for `PBEKeySpec`, clears it, and rejects NULs and unpaired surrogates because `PBEKeySpec` is non-injective (`return.txt:352`), which is precisely the class of subtle defect that usually gets missed — so this is the one remaining path where the plaintext outlives its use. The in-memory plaintext is compounded by SEC-01's `Map<String, String> usersToPlaintextPasswords` (`return.txt:200`), which deliberately keeps seed secrets resident for the process lifetime. Impact is Low because exploitation requires an existing memory-read primitive (heap dump, debugger, SSRF-to-actuator class of bug), at which point much is already lost; it is a hardening gap, not an exposed vulnerability.

**Fix:** Keep the credential in a bounded, zeroisable buffer from the transport boundary, and do not store plaintext at all (see SEC-01):

```java
// Bypass getParameter for the secret: read the form body so no immutable String
// copy of the password is created, cap the size, and wipe on every exit path.
private static final int MAX_PASSWORD_CHARS = 1024;

char[] password = FormBody.readSingleValueAsChars(
        request.getInputStream(), "password", MAX_PASSWORD_CHARS);  // 413/400 on overflow
try {
    if (!CredentialEncoding.isHashable(password)) {   // NUL / unpaired surrogates -> 400
        resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
        return;
    }
    authenticated = credentials.verify(username, password);
} finally {
    Arrays.fill(password, '\0');                      // the only control Java offers
}
```

## 6. Verified Controls and Checks With No Finding

Reviewed and found correctly handled in the artefact (each cited to the `return.txt` text block):

- **Core requirement — script access to the session cookie.** `setHttpOnly(true)`, `setSecure(true)`, `setPath("/")`, `setMaxAge(-1)` and `setAttribute("SameSite", "Lax")` are all set explicitly on the issued cookie (`return.txt:323-331`), mirrored on the expiry cookie (`return.txt:332`). `HttpOnly` is what satisfies the stated requirement; no path sets the cookie from script, and no `Set-Cookie` is ever emitted from a request parameter.
- **No DOM XSS via the cookie probe.** The authenticated page's JS probe reads `document.cookie` only to *demonstrate the defence* — it is expected to come back empty, and the reasoning is explicit that adding such a script is "exactly what the requirement forbids being *possible*" (`return.txt:144`). No readable companion cookie is ever written, so the requirement is met by omission rather than by a script-readable second cookie that would have re-exposed the value.
- **Session token entropy and source.** 32 bytes from a shared `SecureRandom` (`return.txt:286, 297, 300-302`), base64url without padding; no `java.util.Random`, no time- or `hashCode`-seeded material anywhere in the artefact. 256 bits of entropy is well above the 128-bit floor.
- **Session store not replayable on dump.** Tokens are keyed by their SHA-256 digest (`return.txt:296, 311`), so a heap/map dump yields non-usable values; SHA-256 here is a pre-image keyer, not a password hash, which is the correct use.
- **Session fixation.** Rotation on login is retained, and the reasoning for doing it even though a pre-login cookie is unauthenticated is recorded (`return.txt:343`); logout revokes and expires (`return.txt:360`); idle 20 min and absolute 8 h ceilings are enforced in one place (`return.txt:284-285`) with a `removeExpired()` reaper (`return.txt:312`).
- **No container sessions, no URL rewriting.** Container `HttpSession` is deliberately avoided so the app never depends on the container's defaults, and `web.xml` pins `<tracking-mode>COOKIE</tracking-mode>` to kill `;jsessionid=` (`return.txt:364-371`) — closes both token-in-URL leakage and URL-based session fixation.
- **Password in query string.** `getParameter` would accept a query-string `password` and Tomcat's access log would record it, so the design rejects any POST carrying a query string with 400 (`return.txt:346`). No-finding, correctly reasoned.
- **Character-encoding of the credential.** `setCharacterEncoding("UTF-8")` is called before `getParameter` on a platform whose default is US-ASCII, so non-ASCII passwords cannot be silently re-mangled (`return.txt:348`).
- **`PBEKeySpec` non-injectivity.** Trailing NULs and unpaired surrogates are rejected before hashing, scanning both high and low surrogates (`return.txt:350-352`), and the `PBEKeySpec` is cleared with `clearPassword()` in a `finally` block, hoisting the `spec` out of the `try` so the wipe always runs (`return.txt:245-250`) — this is a real equivalence-breaking bug caught ahead of time.
- **Credential hashing primitives.** `PBKDF2WithHmacSHA256`, per-record 16-byte salt, 256-bit derived key (`return.txt:191-194`). No MD5, no SHA-1, no unsalted digest, no ECB/DES/RC4, no deprecated TLS version anywhere in the artefact; no AES at all, so the "unauthenticated encryption / static IV" categories do not apply.
- **Constant-time comparison and user enumeration.** `MessageDigest.isEqual` for the derived-tag compare (`return.txt:254`, specified the same way at `return.txt:50`), and full PBKDF2 work is paid for unknown users against a `dummyRecord` so a cheap "no such user" answer cannot leak account existence by timing (`return.txt:209-213`). Failures return one generic message for unknown user and wrong password alike (`return.txt:344`). Lockout is applied to every failed attempt regardless of account existence, so the 429-vs-401 status difference does not disclose whether the username is real either.
- **Reflected username.** Dashboard renders "Signed in as &lt;escaped&gt;" through an escaping helper rather than raw concatenation (`return.txt:358`, helper at `return.txt:157`) — no DOM XSS in the authenticated page.
- **Response headers and ordering.** `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` on authenticated pages, plus a CSP that bans inline and external script — `script-src 'self'; object-src 'none'; base-uri 'none'` (`return.txt:140`, applied on the dashboard at `return.txt:358`). Note the deliberate choice to put the `document.cookie` probe in a separate `app.js` precisely so that CSP keeps blocking inline script (`return.txt:140`). All headers are written before the body is committed (`return.txt:118, 343`), so no header can be silently lost after a 302.
- **Session cookie accepted only from the cookie header.** `RequireSessionFilter` accepts "exactly one" session cookie and explicitly not from the query string, on both `/dashboard` and `/logout` (`return.txt:337`) — so a `?SESSION=…` URL cannot authenticate a request even though the token itself is never placed in a URL by the app.
- **Lockout signalling and logout method.** The locked branch returns 429 with `Retry-After` from a declared constant (`return.txt:344`), so the delay is machine-readable rather than prose. Logout is reachable only by POST — a `GET /logout` is 302'd to the login page instead of revoking anything, which the author calls out as deliberate so the logout link cannot be triggered cross-site (`return.txt:337, 360`).
- **Input validation.** Username allow-list `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` (`return.txt:356`) excludes control characters, whitespace and leading dots without trimming; password length is capped at 1024 characters to bound KDF cost per request (`return.txt:350`).
- **Build/verification scripts.** `build.sh` (compile + assemble webapp + war) and `tests/verify-in-container.sh` (the curl assertions, which start Tomcat with `CATALINA_BASE=build/catalina` and stop it afterwards) (`return.txt:161-162`, `return.txt:395`). The two shell probes the run actually issued are read-only — `java -version` / `javac -version`, then `ls` of the Tomcat lib plus `javap` on `servlet-api.jar` — and appear as array elements 6 and 9 of `return.txt`, not as text-block lines. `build.sh` uses unquoted expansions in the `javac` line (`return.txt:388`) — reviewed under CWE-78 and recorded as **no finding**: every input is author-controlled with no spaces or metacharacters and nothing attacker-influenced reaches the command; quoted expansions would still be the better default.

**Scope limitation to note.** Most function bodies in the artefact are elided — e.g. `findUserName(String userName) {...}` (`return.txt:205`), `authenticate(String token) { touch and return userName }` (`return.txt:308`), `static Cookie expire() { maxAge(0), same attrs }` (`return.txt:332`), and `verifyAgainst` is never shown. The controls above that rest on those stubs (`digest`, `MessageDigest.isEqual` placement, the clearing of the `PBEKeySpec` `char[]`, the expiry mirror on `expire()`) are **asserted by the design notes, not verified by code**. Since no `.java`/`.xml` file was ever written to disk, the review could not be extended to the finished sources; the same findings should be re-checked once `CredentialStore.java`, `SessionRegistry.java`, `SessionCookieFactory.java`, the servlets and `web.xml` actually exist.
