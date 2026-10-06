# Security Review: ACME Portal Session Handoff Component (Jakarta Servlet 6.0)

## 1. Executive Summary

The reviewed code is a post-authentication Jakarta Servlet 6.0 component (`com.acme.portal.session`,
16 classes, ~2 725 lines) whose single job is to take a session identifier that an upstream trusted
component already created and validated server-side, re-verify it against the authoritative session
store, and return it to the browser in one hardened `Set-Cookie` header. It also ships a deployment
descriptor, test scaffolding (an in-process harness, an end-to-end HTTP client and stand-in
authenticator/store/verifier), a build script and a mutation-testing tool.

The component is unusually well hardened for generated code. The session identifier is validated
reject-only against a base64url allowlist that makes cookie-attribute and header injection
structurally impossible (`SessionId.java:181-187`), `Secure`/`HttpOnly`/host-only/session-lifetime are
class invariants rather than configuration (`SessionCookiePolicy.java:171-188`), `SameSite=None` is
refused at startup (`SessionCookiePolicy.java:142-148`), refusal bodies are a single compile-time
constant so no response discloses which gate refused (`ResponseBody.java:19-24`), the verifier is
fail-closed when absent or ambiguous (`SessionStateVerifierProvider.java:76-85`), rate limiting is
atomic under one monitor with bounded state (`AttemptLimiter.java:175-207`), and client-controlled
`X-Forwarded-For`-style headers are never read. No hardcoded secrets, no SQL, no deserialization, no
command execution and no file reads exist on the request path.

Six issues were found, none critical. The most important are:

- **SEC-01 (Medium, CWE-319):** nothing in the code or the descriptor requires HTTPS. The servlet will
  emit the session identifier in a `Set-Cookie` header over plaintext HTTP, and no HSTS header is sent.
- **SEC-02 (Medium, CWE-489):** the unauthenticated test control servlet and a header-driven
  "assert any session id" filter are compiled into deployable WAR artifacts by `build.sh`.
- **SEC-03 (Medium, CWE-732):** the deployment-hygiene gate that exists to stop foreign verifier code
  being loaded only inspects the POSIX *other*-write bit, so a group-writable classpath entry passes.
- SEC-04/05/06 (Low): an unkeyed session-identifier digest in logs, missing anti-framing/referrer
  headers on the HTML responses, and a per-source throttle that collapses to one shared bucket when the
  component is deployed behind a reverse proxy.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/acme/portal/session/SessionHandoffServlet.java` | HTTP adapter: method dispatch, decision routing, response shaping | Reads `getRemoteAddr()`, logs session fingerprints, sets all response headers, catch-all exception handling, no transport (HTTPS) check |
| `src/main/java/com/acme/portal/session/SessionHandoffService.java` | Container-free security decision (validate → throttle → verify) | Gate ordering, fail-closed `DENY_ALL` verifier, verifier exceptions treated as "not valid" |
| `src/main/java/com/acme/portal/session/SessionId.java` | Opaque bearer identifier: validation, minting, log masking | Base64url allowlist, 32–128 length bounds, `SecureRandom` minting, truncated SHA-256 fingerprint, package-private `value()` |
| `src/main/java/com/acme/portal/session/SessionCookiePolicy.java` | Validated cookie attribute policy | `Secure`/`HttpOnly`/host-only/session-only invariants, `__Host-` prefix consistency, `SameSite=None` refused, name/path allowlists |
| `src/main/java/com/acme/portal/session/SessionCookieWriter.java` | Emits `Set-Cookie` plus anti-caching headers | Second independent identifier gate before mutating the response, `addCookie` rather than raw `setHeader` |
| `src/main/java/com/acme/portal/session/SessionHandoffSettings.java` | Reads and validates environment configuration | Non-printable byte rejection, integer range bounds, request-attribute name allowlist and reserved-namespace refusal |
| `src/main/java/com/acme/portal/session/AttemptLimiter.java` | Fixed-window per-source and global throttle | Atomic check-and-increment under one monitor, bounded bucket map, O(1) reclamation, monotonic clock |
| `src/main/java/com/acme/portal/session/ClientAddress.java` | Canonicalises `getRemoteAddr()` into a rate-limit key | Strict IPv4/IPv6 literal grammars so no attacker-chosen name reaches the resolver; degrades to a shared restricted bucket |
| `src/main/java/com/acme/portal/session/DeploymentHygiene.java` | Startup check that code locations are not writable by other accounts | POSIX permission inspection of classpath entries and code sources; fail-closed on unknown |
| `src/main/java/com/acme/portal/session/SessionStateVerifierProvider.java` | `ServiceLoader` discovery of the session-state authority | Refuses zero or multiple providers; runs the hygiene gate before instantiating foreign code |
| `src/main/java/com/acme/portal/session/RequestAttributeAssertionSource.java` | Reads the upstream assertion from a request attribute | String-typed only; never reads cookies, headers, query or body |
| `src/main/java/com/acme/portal/session/TrustedSessionAssertionSource.java` | Trust-boundary interface for the assertion | Documents that implementations must not read client-supplied data |
| `src/main/java/com/acme/portal/session/ResponseBody.java` | The only two response bodies | Constant refusal body (no oracle), HTML output encoding with a bounded escaper |
| `src/main/java/com/acme/portal/session/CacheSupport.java` | SHA-256 helper for fingerprints | Digests a bearer credential in chunks, zeroes intermediate arrays |
| `src/main/java/com/acme/portal/session/WorkEqualizer.java` | Fixed per-request SHA-256 padding | Timing side-channel mitigation applied before every gate; constant input, no secret |
| `src/main/java/com/acme/portal/session/InvalidSessionIdentifierException.java` | Checked rejection signal | Message and `toString()` carry only the rejection enum, never the value |
| `deploy/web.xml` | Deployment descriptor an integrator copies | `tracking-mode=COOKIE`, hardened container cookie config, generic error pages; **no** `security-constraint`/`transport-guarantee` |
| `deploy/web.test-only.xml` | Test-only descriptor fragment | Maps an unauthenticated control servlet and a header-driven stand-in authenticator |
| `deploy/WEB-INF/static/error.html` | Generic error page | Static, no request data, no scriptlets |
| `src/test/java/com/acme/portal/session/Harness.java` | 1 987-line in-process assertion harness | Manipulates POSIX permissions in temp dirs, feeds control characters through the component |
| `src/test/java/com/acme/portal/testapp/E2EClient.java` | Real-HTTP assertion client | Plain HTTP to `127.0.0.1` only; no TLS trust overrides |
| `src/test/java/com/acme/portal/testapp/StubAuthenticatorFilter.java` | Stand-in trusted authenticator | Establishes the asserted session id from request headers (`X-Stub-Login/Ticket/Assert`) |
| `src/test/java/com/acme/portal/testapp/StubControlServlet.java` | Test control endpoint | Unauthenticated; expires the oldest live session and reports a live count |
| `src/test/java/com/acme/portal/testapp/StubSessionStore.java` | Stand-in session store | Mints identifiers with its own `SecureRandom`; static JVM-wide maps |
| `src/test/java/com/acme/portal/testapp/StubSessionVerifier.java` | Stand-in verifier registered via `META-INF/services` | The authority the component loads in the e2e run |
| `src/test/java/com/acme/portal/testapp/ProbeVerifier.java` | Harness probe with a side-effecting static initialiser | Writes a marker file to prove the hygiene gate precedes class initialisation |
| `build.sh` | Build, harness, WAR assembly, throwaway Tomcat e2e | Pinned SHA-1 + SHA-512 integrity gates on third-party artifacts; copies stub classes into the WARs |
| `tools/mutants.py` | 44-mutant mutation battery | Subprocess invocation (`shell=` derived from argument type), recursive tree deletion under `build/` |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router skill; drove the per-file behaviour inventory in section 2 and the skill selection below.
- `performing-security-headers-audit`: applied to `SessionHandoffServlet.applyStandardHeaders`, `SessionCookieWriter.writeSessionCookie` and `SessionCookiePolicy` — cookie attributes (`Secure`, `HttpOnly`, `SameSite`, `__Host-` prefix, `Path`, absent `Domain`/`Max-Age`), cache directives, `X-Content-Type-Options`, and the absence of HSTS, CSP/`frame-ancestors`, `X-Frame-Options` and `Referrer-Policy` (SEC-01, SEC-05).
- `testing-for-sensitive-data-exposure`: applied to every path a bearer session identifier can take — `toString()` masking, package-private `value()`, log statements in `SessionHandoffServlet`/`SessionHandoffService`/`SessionStateVerifierProvider`, exception messages, response bodies, and the cleartext-transport question (SEC-01, SEC-04).
- `performing-cryptographic-audit-of-application`: applied to `SessionId.generate()`, `CacheSupport`, `WorkEqualizer` and the `build.sh` integrity gates — RNG choice and seeding, SHA-256 usage class (fingerprint vs MAC vs KDF), truncation width, salting/keying, key material (none exists), and artifact hash pinning (SEC-04).
- `implementing-api-rate-limiting-and-throttling`: applied to `AttemptLimiter` and `ClientAddress` — fixed-window correctness, atomic check-and-act, per-source vs global separation, bucket-key derivation and cardinality bounds, `429` + `Retry-After` behaviour, lockout and amplification analysis (SEC-06).
- `testing-for-broken-access-control`: applied to `SessionHandoffService.handle` ordering, `RequestAttributeAssertionSource`, `SessionStateVerifierProvider` fail-closed behaviour, servlet method dispatch (`TRACE`/`POST`/`PUT`/`DELETE`/`OPTIONS` refusals) and the test-only `StubControlServlet` mapping (SEC-02).
- `testing-for-xss-vulnerabilities`: applied to `ResponseBody.granted`/`escapeHtml` and `deploy/WEB-INF/static/error.html` — the only interpolated value is a validated cookie name, escaped in HTML text context, with a bound computed on escaped output (no finding).
- Reviewed against general OWASP Top 10 / CWE knowledge where no library skill matched: Java memory-visibility and concurrency correctness of the `volatile` wire-once collaborators and the limiter monitor (A04/CWE-362, CWE-367); `ServiceLoader`-based code discovery and local filesystem permission semantics (CWE-732, CWE-427); `ServletRequest` attribute trust boundaries and session-fixation reasoning (CWE-384); timing side channels (CWE-208); shell/subprocess usage and third-party artifact integrity in `build.sh` and `tools/mutants.py` (CWE-78, CWE-494); and leftover debug/test functionality in build artifacts (CWE-489).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Session identifier is emitted over plaintext HTTP: no transport check, no `transport-guarantee`, no HSTS | Medium | CWE-319 | `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:251-259` |
| SEC-02 | Unauthenticated test control servlet and header-driven assertion filter are packaged into deployable WARs | Medium | CWE-489 | `build.sh:117-119` |
| SEC-03 | Deployment-hygiene gate ignores group-writable code locations | Medium | CWE-732 | `src/main/java/com/acme/portal/session/DeploymentHygiene.java:144-148` |
| SEC-04 | Session identifier is logged as an unkeyed truncated SHA-256 digest | Low | CWE-532 | `src/main/java/com/acme/portal/session/SessionId.java:246-250` |
| SEC-05 | HTML responses lack anti-framing, CSP and `Referrer-Policy` headers | Low | CWE-1021 | `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:385-391` |
| SEC-06 | Per-source throttle collapses to a single shared bucket behind a reverse proxy | Low | CWE-307 | `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:256` |

## 5. Detailed Findings

### SEC-01: Session identifier is emitted over plaintext HTTP: no transport check, no `transport-guarantee`, no HSTS

- **Severity:** Medium
- **CWE:** CWE-319: Cleartext Transmission of Sensitive Information
- **Location:** `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:251-259` (decision path, no transport check), `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:385-391` (no HSTS header), `deploy/web.xml:17-19` and `deploy/web.xml:21-77` (no `security-constraint`/`transport-guarantee`)

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/session/SessionHandoffServlet.java:251-259
            if (!serving) {
                respondUnavailable(response, writeBody);
                return;
            }

            ClientAddress source = ClientAddress.parse(request.getRemoteAddr());
            String assertedId = readAssertion(request);
            SessionHandoffService.Decision decision =
                    service.handle(new SessionHandoffService.Request(assertedId, source));
```

```xml
<!-- deploy/web.xml:17-19 -->
  There is no transport-guarantee element. Enforcing HTTPS is the deployment's job (a TLS terminator
  plus HSTS), and claiming it here without a keystore configured would be decoration. The cookie is
  always Secure regardless, so a plain-HTTP deployment simply stops working rather than leaking.
```

**Why it is a problem:** `request.isSecure()` and `request.getScheme()` appear nowhere in
`src/main/java` (verified by grep), and the descriptor declares no `security-constraint` with
`<transport-guarantee>CONFIDENTIAL</transport-guarantee>`. If the component is reached over plain HTTP
— a misconfigured connector, an HTTP listener left open next to the HTTPS one, a TLS terminator whose
backend hop is plaintext, or a victim following an `http://` link — the servlet still runs the full
grant path and `SessionCookieWriter` still emits
`Set-Cookie: __Host-PORTAL_SESSION=<identifier>; ...` in the response. The descriptor's argument that
"a plain-HTTP deployment simply stops working rather than leaking" is only half true: the `Secure`
attribute and the `__Host-` prefix stop the *browser* from storing and replaying the cookie, but they
do nothing about the response that already carried the identifier in cleartext across the network. A
passive network observer on that hop harvests a live bearer credential for a session the authoritative
store has just confirmed — the strongest possible value — and can replay it to the real HTTPS endpoint.
No `Strict-Transport-Security` header is emitted either, so a browser that reached the endpoint over
HTTP is never told to stop doing so.

**Fix:** Refuse to issue the cookie unless the request arrived over a secure transport, and emit HSTS
on the responses that do. Keep the refusal indistinguishable from the other refusals (same body, same
headers) so the new gate does not become an oracle, and add the declarative constraint to the
descriptor so the container rejects plaintext before the servlet is even reached.

```java
// src/main/java/com/acme/portal/session/SessionHandoffServlet.java - in handle(), before the decision
            if (!serving) {
                respondUnavailable(response, writeBody);
                return;
            }
            // A session identifier is a bearer credential, so it is never put on a cleartext hop.
            // Answered as the same generic refusal as every other "no session for you" outcome, so
            // the transport gate adds no distinguishable response shape.
            if (!request.isSecure()) {
                respondRefused(response, writeBody);
                LOG.log(Level.SEVERE, "session handoff refused: the request did not arrive over a"
                        + " secure transport; configure TLS termination and transport-guarantee");
                return;
            }

            ClientAddress source = ClientAddress.parse(request.getRemoteAddr());
            String assertedId = readAssertion(request);
            SessionHandoffService.Decision decision =
                    service.handle(new SessionHandoffService.Request(assertedId, source));
```

```java
// src/main/java/com/acme/portal/session/SessionHandoffServlet.java - in applyStandardHeaders(...)
        response.setHeader("X-Content-Type-Options", "nosniff");
        // Tell the browser never to come back over cleartext. Safe to send unconditionally: a
        // conforming client ignores HSTS on a plaintext response.
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
```

```xml
<!-- deploy/web.xml - add alongside the servlet-mapping -->
  <security-constraint>
    <web-resource-collection>
      <web-resource-name>Session handoff</web-resource-name>
      <url-pattern>/session/handoff</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
      <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
  </security-constraint>
```

### SEC-02: Unauthenticated test control servlet and header-driven assertion filter are packaged into deployable WARs

- **Severity:** Medium
- **CWE:** CWE-489: Active Debug Code
- **Location:** `build.sh:117-119` and `build.sh:123-131`; `deploy/web.test-only.xml:16-34`; `src/test/java/com/acme/portal/testapp/StubControlServlet.java:41-44`; `src/test/java/com/acme/portal/testapp/StubAuthenticatorFilter.java:57-60`

**Vulnerable code:**
```bash
# build.sh:117-119
  mkdir -p "$stage/WEB-INF/classes/com/acme/portal/testapp"
  cp build/test-classes/com/acme/portal/testapp/Stub*.class \
     "$stage/WEB-INF/classes/com/acme/portal/testapp/" || return 2
```

```xml
<!-- deploy/web.test-only.xml:16-24 -->
<servlet>
  <servlet-name>StubControl</servlet-name>
  <servlet-class>com.acme.portal.testapp.StubControlServlet</servlet-class>
</servlet>

<servlet-mapping>
  <servlet-name>StubControl</servlet-name>
  <url-pattern>/stub/control/*</url-pattern>
</servlet-mapping>
```

```java
// src/test/java/com/acme/portal/testapp/StubAuthenticatorFilter.java:57-60
            String asserted = http.getHeader("X-Stub-Assert");
            if (asserted != null) {
                http.setAttribute(ASSERTION_ATTRIBUTE, asserted);
            }
```

**Why it is a problem:** `build_war` assembles `build/handoff.war`, `build/handoff-limited.war` and
`build/handoff-nofv.war` — all three present in the tree — with the stub classes inside
`WEB-INF/classes` and the test-only descriptor fragment spliced into `web.xml`. Those archives are
indistinguishable from a production artifact except by filename, and the project's own comment
(`deploy/web.test-only.xml:10`) says the control endpoint "is unauthenticated, which is exactly why it
must never ship". If such an archive is deployed, `GET /stub/control/expire-oldest` lets any
unauthenticated caller invalidate the oldest live session (denial of service against a real user) and
`/stub/control/live` discloses the live session count, while `StubAuthenticatorFilter` turns the
`X-Stub-Login`/`X-Stub-Assert` request headers — pure client input — into the "trusted" assertion the
component consumes. `X-Stub-Login` lets any caller mint a brand-new live session in the stand-in store
and immediately receive its cookie, which is a complete authentication bypass for that deployment. The
build verifies that `Harness`, `E2EClient` and `ProbeVerifier` are *absent* from the WAR
(`build.sh:271-282`) but deliberately requires at least four `Stub*` classes to be present, so the
existing guard cannot catch this. The reason this is Medium rather than High is that the intended
production path copies `deploy/web.xml` (which contains only the marker comment) and compiles only
`src/main`; the exposure requires the e2e artifact to be mistaken for the shipping one.

**Fix:** Keep the test scaffolding out of anything that can be deployed by accident. Build the
shippable WAR from `src/main` only and give the e2e archives a name and a guard that make them unusable
as production artifacts — for example a mandatory system property the stubs refuse to start without.

```bash
# build.sh - gate the stub payload behind an explicit, self-identifying test build
build_war() {
  # $1 = output war path, $2 = "with"|"without" services, $3 = "test-scaffolding"|"shippable"
  local war="$1" services="$2" kind="${3:-shippable}"
  local stage="build/stage-$(basename "$war" .war)"
  rm -rf "$stage"
  mkdir -p "$stage/WEB-INF/classes" "$stage/WEB-INF/static"
  cp -r build/classes/. "$stage/WEB-INF/classes/"
  if [ "$kind" = "test-scaffolding" ]; then
    # Only ever reachable for the *-e2e-test.war targets, which are never published, and the
    # stubs additionally refuse to initialise unless -Dportal.e2e.scaffolding=enabled is set.
    mkdir -p "$stage/WEB-INF/classes/com/acme/portal/testapp"
    cp build/test-classes/com/acme/portal/testapp/Stub*.class \
       "$stage/WEB-INF/classes/com/acme/portal/testapp/" || return 2
  fi
  # ... descriptor assembly: inject deploy/web.test-only.xml only when kind = test-scaffolding,
  # and leave the marker comment in place otherwise.
}
```

```java
// src/test/java/com/acme/portal/testapp/StubControlServlet.java - refuse to run outside the e2e harness
    @Override
    public void init() throws jakarta.servlet.ServletException {
        if (!"enabled".equals(System.getProperty("portal.e2e.scaffolding"))) {
            throw new jakarta.servlet.ServletException(
                    "test scaffolding is deployed but portal.e2e.scaffolding is not enabled;"
                            + " refusing to expose an unauthenticated control endpoint");
        }
    }
```

### SEC-03: Deployment-hygiene gate ignores group-writable code locations

- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/acme/portal/session/DeploymentHygiene.java:144-148` (decision), used at `DeploymentHygiene.java:81-87` and `SessionStateVerifierProvider.java:101`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/session/DeploymentHygiene.java:144-148
    private static boolean worldWritable(Path path) {
        try {
            Set<java.nio.file.attribute.PosixFilePermission> permissions =
                    Files.getPosixFilePermissions(path);
            return permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
```

**Why it is a problem:** This method is the whole of the check that
`DeploymentHygiene.java:13-15` describes as guarding "the one class of deployment mistake that turns a
correct component into remote code execution: loading classes from somewhere another local account can
write" — and `SessionStateVerifierProvider.java:95-110` relies on it before instantiating the
`ServiceLoader`-discovered session verifier, i.e. before running code that decides whether a session is
valid. Only `OTHERS_WRITE` is examined. A classpath entry or code-source directory owned by
`root:deployers` with mode `0775`, or `tomcat:ci` with mode `0770`, is writable by every other local
account in that group, yet `worldWritable` returns `false`, `describeProblem` returns `null`, and the
servlet serves. Any member of the group can then drop a `META-INF/services` entry and a class that
answers `isSessionValid` with `true` for every input, which makes the component mint a valid session
cookie for an attacker-chosen identifier — exactly the compromise the check exists to prevent.
Group-writable deployment directories are the normal, not the exotic, arrangement on CI-managed hosts.
`Files.getPosixFilePermissions` also follows symlinks and ignores POSIX ACLs, so the check can be
bypassed on a filesystem where an `A+user:attacker:w` ACL grants write access without setting any mode
bit. The in-process harness only exercises the `rw-rw-rw-` case
(`src/test/java/com/acme/portal/session/Harness.java:1469`), so the gap is untested.

**Fix:** Treat any non-owner write permission as untrusted, resolve symlinks before inspecting, and
reject locations carrying an ACL that cannot be reduced to POSIX mode bits. Keep the existing
fail-closed behaviour for filesystems that cannot answer.

```java
// src/main/java/com/acme/portal/session/DeploymentHygiene.java
    /**
     * True when any account other than the owner can write the path. Group write counts: a
     * deployment directory shared with a CI or operator group is writable by every member of it,
     * and one of them supplying the session verifier is the compromise this check exists to stop.
     */
    private static boolean writableByAnotherAccount(Path path) {
        try {
            Path real = path.toRealPath();
            Set<java.nio.file.attribute.PosixFilePermission> permissions =
                    Files.getPosixFilePermissions(real);
            if (permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE)
                    || permissions.contains(java.nio.file.attribute.PosixFilePermission.GROUP_WRITE)) {
                return true;
            }
            // An ACL can grant write access with no mode bit set, so a path that carries one
            // cannot be cleared by mode bits alone.
            java.nio.file.attribute.AclFileAttributeView acl = Files.getFileAttributeView(
                    real, java.nio.file.attribute.AclFileAttributeView.class);
            return acl != null && !acl.getAcl().isEmpty();
        } catch (UnsupportedOperationException notPosix) {
            return true;
        } catch (IOException unreadable) {
            return true;
        }
    }
```

### SEC-04: Session identifier is logged as an unkeyed truncated SHA-256 digest

- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `src/main/java/com/acme/portal/session/SessionId.java:246-250` (digest construction), emitted at `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:328-330` and `SessionHandoffServlet.java:346-347`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/session/SessionId.java:246-250
    public String fingerprint() {
        // Two parts rather than one concatenation: see the note in CacheSupport about not copying a
        // bearer credential merely to prefix it.
        return CacheSupport.digestHexPrefix(new String[]{FINGERPRINT_PREFIX, value}, FINGERPRINT_HEX);
    }
```

**Why it is a problem:** Every granted handoff writes 48 bits of `SHA-256("acme-sid-v1:" + identifier)`
to the application log. The prefix is a compile-time constant in the source, so the digest is unkeyed
and unsalted: anyone holding the logs can compute the same function offline and test candidate
identifiers against it. The class documents this honestly as a residual risk
(`SessionId.java:236-244`) and it is harmless against the 256-bit values `generate()` mints, but the
component cannot enforce that property on the identifiers the upstream owner actually asserts — and it
deliberately refuses to try (`SessionId.java:34-57`). If the integrator's store issues identifiers from
a smaller space (a counter, a truncated UUID, a timestamp with a fixed prefix — all of which satisfy the
32-character base64url validator), the log line becomes an offline verification oracle that confirms
guesses without touching the server, turning log read access into session takeover. A
deployment-documented requirement is weaker than a control: the fix costs one random value at startup
and removes the dependency on someone else's entropy entirely.

**Fix:** Key the fingerprint with a per-process random value (HMAC-SHA-256 rather than a bare digest).
Correlation across the log lines of one process is preserved, which is all the fingerprint is for, while
the digest stops being reproducible by anyone who only holds the logs — whatever the upstream's entropy.

```java
// src/main/java/com/acme/portal/session/SessionId.java
    /**
     * Per-process fingerprint key, generated at class initialisation and never persisted or logged.
     * It makes the fingerprint a MAC rather than a reproducible digest, so a log reader cannot test
     * candidate identifiers offline even if the session owner issues low-entropy values.
     */
    private static final byte[] FINGERPRINT_KEY = new byte[32];
    static {
        SECURE_RANDOM.nextBytes(FINGERPRINT_KEY);
    }

    public String fingerprint() {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(FINGERPRINT_KEY, "HmacSHA256"));
            mac.update(FINGERPRINT_PREFIX.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] tag = mac.doFinal(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(FINGERPRINT_HEX);
            for (int i = 0; i < FINGERPRINT_HEX; i++) {
                byte b = tag[i / 2];
                hex.append("0123456789abcdef".charAt((i % 2 == 0) ? ((b >> 4) & 0xF) : (b & 0xF)));
            }
            java.util.Arrays.fill(tag, (byte) 0);
            return hex.toString();
        } catch (java.security.GeneralSecurityException unavailable) {
            // No fingerprint is better than a weaker one: the caller logs the outcome without it.
            return "unavailable";
        }
    }
```

### SEC-05: HTML responses lack anti-framing, CSP and `Referrer-Policy` headers

- **Severity:** Low
- **CWE:** CWE-1021: Improper Restriction of Rendered UI Layers or Frames
- **Location:** `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:385-391`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/session/SessionHandoffServlet.java:385-391
    private void applyStandardHeaders(HttpServletResponse response) {
        // Pragma for HTTP/1.0 proxies, max-age=0 for anything that honours Cache-Control strictly.
        response.setHeader("Cache-Control", "no-store, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("text/html;charset=UTF-8");
        response.setHeader("X-Content-Type-Options", "nosniff");
    }
```

**Why it is a problem:** This is the single header block for every response the component emits, and it
sets no framing restriction, no `Content-Security-Policy` and no `Referrer-Policy`. The two documents
are static and carry no credential or form, so the direct impact is limited — but the endpoint is
embeddable in a hostile page, which lets an attacker frame it to detect whether the victim currently has
a session (the grant and refusal documents differ) and to drive the credential-issuing endpoint inside
an attacker-controlled page. `Referrer-Policy` matters here specifically because this is the URL that
issues a session: without it, a navigation away from the handoff page leaks the full handoff URL,
including any query string a future revision adds, to third-party origins. All three are single header
lines in a method that already exists and is already asserted on for shape-equality across outcomes.

**Fix:** Add the three headers to the same block, so every outcome keeps an identical header shape.

```java
    private void applyStandardHeaders(HttpServletResponse response) {
        // Pragma for HTTP/1.0 proxies, max-age=0 for anything that honours Cache-Control strictly.
        response.setHeader("Cache-Control", "no-store, max-age=0");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("text/html;charset=UTF-8");
        response.setHeader("X-Content-Type-Options", "nosniff");
        // The two documents load nothing and are never framed, so the policy can be maximally
        // restrictive; frame-ancestors 'none' keeps the credential-issuing endpoint out of a
        // hostile page, and X-Frame-Options covers clients that predate CSP level 2.
        response.setHeader("Content-Security-Policy",
                "default-src 'none'; style-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Referrer-Policy", "no-referrer");
    }
```

### SEC-06: Per-source throttle collapses to a single shared bucket behind a reverse proxy

- **Severity:** Low
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:256`; bucket derivation at `src/main/java/com/acme/portal/session/ClientAddress.java:189-257`; ceilings at `src/main/java/com/acme/portal/session/AttemptLimiter.java:181-196`

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/session/SessionHandoffServlet.java:256
            ClientAddress source = ClientAddress.parse(request.getRemoteAddr());
```

**Why it is a problem:** Not reading `X-Forwarded-For` is the right default — the code is explicit about
it (`ClientAddress.java:21-22`) and avoids the spoofable-identity trap entirely. But the component is
documented to sit behind an upstream authenticator and, in any realistic deployment, a TLS terminator;
in that topology `getRemoteAddr()` is the proxy's address for *every* request, so all clients land in
one bucket keyed on it. The per-source ceiling (default 30 per 60 s, `SessionHandoffSettings.java:36`)
then applies to the entire user population rather than per client: 30 legitimate sign-ins a minute
exhaust it and every subsequent handoff gets a 429, and an attacker needs only those 30 requests to
deny session issuance to everyone. The component has no way to notice this has happened — the limiter
reports healthy, and the only visible symptom is `unknownSource=false` 429s. The README names the
condition, but nothing in the code detects or warns about it.

**Fix:** Make the trusted-proxy case explicit configuration rather than an undetectable degradation:
accept a forwarded-address header only when the immediate peer is in an operator-configured trusted
proxy list, and log a startup warning when neither a trusted proxy nor a direct-connection topology has
been declared.

```java
// src/main/java/com/acme/portal/session/SessionHandoffServlet.java - in handle()
            // getRemoteAddr() is the only unspoofable source for a direct connection, and the only
            // useless one behind a proxy. Which of the two applies is deployment configuration, not
            // something to guess from a header an attacker can set.
            ClientAddress peer = ClientAddress.parse(request.getRemoteAddr());
            ClientAddress source = trustedProxies.contains(peer)
                    // Rightmost entry the trusted hop appended; everything left of it is client text.
                    ? ClientAddress.parse(lastForwardedFor(request))
                    : peer;
```

```java
// src/main/java/com/acme/portal/session/SessionHandoffSettings.java - new validated setting
    /** Comma-separated addresses whose forwarded-for header may be believed. Empty = direct only. */
    public static final String TRUSTED_PROXIES_ENV = "PORTAL_TRUSTED_PROXIES";
    // ... parsed through ClientAddress.parse() so only canonical literals can enter the set, and
    // an unparseable entry aborts startup like every other malformed setting.
```

## 6. Verified Controls and Checks With No Finding

- **Cookie attribute hardening:** `Secure`, `HttpOnly`, host-only (no `Domain`) and browser-session lifetime (no `Max-Age`/`Expires`) are class invariants that configuration cannot switch off — `SessionCookiePolicy.java:171-188`, applied at `SessionCookieWriter.java:63-75`; `setMaxAge`/`setDomain` are never called (verified by grep).
- **`SameSite` handling:** `Strict` default, `Lax` permitted, `None` refused at startup with no silent coercion; a typo fails loudly — `SessionCookiePolicy.java:135-150`.
- **`__Host-` prefix consistency:** a `__Host-` name paired with a non-`/` path refuses startup instead of emitting a cookie the browser would silently drop — `SessionCookiePolicy.java:77-80`.
- **Cookie/header injection:** the identifier allowlist is base64url only, rejecting CR, LF, NUL, space, quote, `=`, `;`, `,` and all non-ASCII, and the value is re-inspected immediately before emission by an independent gate; emission uses `response.addCookie` rather than a raw `setHeader` — `SessionId.java:181-187`, `SessionCookieWriter.java:56-75`. Cookie name and path carry their own allowlists — `SessionCookiePolicy.java:95-133`.
- **Reject-only validation (no normalisation):** no trimming, case folding or unescaping anywhere on the identifier path, so two byte strings can never fold onto one session — `SessionId.java:112-129`.
- **Fail-closed authorisation:** a missing, ambiguous, unconstructable or null-returning verifier yields `null` and the servlet refuses every request with 503; `DENY_ALL` is the substitute of record; a verifier that throws is treated as "not valid" — `SessionStateVerifierProvider.java:76-122`, `SessionHandoffService.java:100-105`, `SessionHandoffService.java:182-193`, `SessionHandoffServlet.java:102-128`.
- **Foreign-code discovery ordering:** `ServiceLoader.stream()` is used so the hygiene verdict is reached before a candidate's static initialiser or constructor runs; the ordering is proven by `ProbeVerifier`'s marker file — `SessionStateVerifierProvider.java:56-110`, `Harness.java:1484-1530`.
- **Assertion trust boundary:** the assertion is read only from a server-set request attribute, accepted only when it is a `String`, and never from a cookie, header, query parameter or body; a throwing source is treated as "no assertion" — `RequestAttributeAssertionSource.java:29-46`, `SessionHandoffServlet.java:303-311`. The attribute name is validated to a Java-identifier shape with reserved namespaces refused — `SessionHandoffSettings.java:150-181`.
- **No container session is created or read:** no `getSession` call exists in `src/main/java` (verified by grep), so no second session mechanism and no second `Set-Cookie` can appear; `tracking-mode=COOKIE` stops the container appending `;jsessionid=` to a URL — `deploy/web.xml:29-35`.
- **Uniform refusal responses (no oracle):** one compile-time-constant refusal body shared by every refusal path, one header block for all outcomes, and HEAD reporting the same `Content-Length` the GET would — `ResponseBody.java:19-24`, `SessionHandoffServlet.java:385-409`.
- **Error handling and log hygiene:** every exception is caught and answered as 503 with only the exception *class name* logged, never a cause message that could carry a connection string; container error pages are overridden with a static page containing no request data — `SessionHandoffServlet.java:289-296`, `SessionHandoffService.java:185-190`, `deploy/web.xml:63-76`, `deploy/WEB-INF/static/error.html:1-3`.
- **Secret masking:** `SessionId.toString()` returns a fingerprint rather than the value, `value()` is package private, `equals`/`hashCode` are deliberately absent, and the `toString()` of `Decision`, `SessionCookiePolicy`, `AttemptLimiter`, `SessionHandoffSettings` and the servlet carry no identifier, address or secret — `SessionId.java:222-262`, `SessionHandoffService.java:80-84`, `AttemptLimiter.java:296-302`. (The remaining fingerprint-in-log concern is SEC-04.)
- **Cryptography:** one shared non-blocking `SecureRandom` for the 32-byte identifier material, base64url without padding, and a self-test that refuses to hand out a degenerate value — `SessionId.java:210-220`, `SessionId.java:264-269`. SHA-256 is used only as a fingerprint and as constant-cost padding, never as a MAC, KDF or password hash; intermediate byte arrays are zeroed — `CacheSupport.java:45-74`, `WorkEqualizer.java:95-106`. No key material, signing key or hardcoded secret exists anywhere in the tree (verified by grep for password/secret/key/token patterns).
- **Timing side channel:** a fixed 160-compression SHA-256 pad over a constant buffer runs before every gate including the throttle and the availability check, with the sizing measured rather than guessed — `WorkEqualizer.java:35-106`, applied unconditionally at `SessionHandoffServlet.java:243`.
- **Rate-limit correctness and atomicity:** read, roll-over, compare and increment all happen inside one monitor, so no check-then-act window exists; denied attempts consume no allowance; the global lane is checked before any per-source increment so a flood cannot spend a victim's quota; windows roll so no limit is permanent; the clock is monotonic (`System.nanoTime`) so an NTP step cannot create a permanent block — `AttemptLimiter.java:175-213`.
- **Bounded limiter state:** the bucket map is capped and reclamation is a bounded 64-candidate second-chance hand, so monitor hold time is O(1) and independent of how many sources an attacker creates; only rolled buckets are ever dropped, so an active attacker's counter cannot be wiped — `AttemptLimiter.java:102`, `AttemptLimiter.java:242-263`. Saturating the cap sheds new sources rather than growing the heap, which is a deliberate fail-closed trade documented at `AttemptLimiter.java:44-47`.
- **Address parsing / SSRF-and-resolver safety:** a character allowlist plus full IPv4 dotted-quad and IPv6 literal grammars run before `InetAddress.getByName`, so no hostname can reach the OS resolver and no DNS round trip can be induced per request; shorthand forms, scope ids and brackets are refused; canonicalisation prevents one host holding several buckets; unparseable input degrades to a single restricted shared bucket rather than an unlimited one — `ClientAddress.java:41-257`.
- **Method handling:** only GET and HEAD are served; POST/PUT/DELETE/OPTIONS return 405 with `Allow` and no body; TRACE is disabled outright (cross-site tracing defence) — `SessionHandoffServlet.java:189-223`.
- **Caching of credential-bearing responses:** `Cache-Control: no-store, max-age=0` and `Pragma: no-cache` are set on every response and again, first, by the cookie writer before the value is added, so even a partial response is unstorable — `SessionHandoffServlet.java:386-388`, `SessionCookieWriter.java:49-52`.
- **Output encoding / XSS:** the only interpolated value in either body is the validated cookie name, HTML-escaped in text context with the length bound computed on *escaped* output so an entity is never cut in half, and control characters substituted rather than emitted — `ResponseBody.java:52-110`.
- **Configuration validation:** every environment value is range- and charset-checked, non-printable bytes (CR/LF injection) are refused, non-integers abort startup, no security-relevant attribute is defaulted permissively, and `maxPerWindow > globalMax` is refused — `SessionHandoffSettings.java:109-147`, `SessionHandoffSettings.java:102-105`.
- **Concurrency/visibility of wiring:** the four collaborator fields are `volatile` with `serving` written last, so a request thread that observes `serving == true` cannot see a null collaborator; incomplete wiring sets `serving = false` rather than serving with fewer checks — `SessionHandoffServlet.java:63-66`, `SessionHandoffServlet.java:134-157`.
- **Supply-chain integrity in the build:** the servlet API jar is checked against both the publisher's SHA-1 and a locally pinned SHA-512 (with a 40-character length guard so a truncated signature file cannot match), and the Tomcat archive against a pinned SHA-512 *before* extraction; the build also refuses stray control characters in sources and a malformed descriptor — `build.sh:33-48`, `build.sh:151-159`, `build.sh:52-77`.
- **`tools/mutants.py` subprocess usage:** `sh()` sets `shell=isinstance(cmd, str)`, which would invoke a shell for a string argument, but all five call sites pass argument *lists* (`tools/mutants.py:351`, `:360`, `:415`, `:425`), so no shell is ever spawned and no injection path exists. Reviewed against CWE-78; no finding, though the conditional `shell=` is a latent hazard worth removing.
- **Test client transport:** `E2EClient` targets only `http://127.0.0.1` on a loopback port and installs no `TrustManager`, `SSLContext` or hostname-verifier override (verified by grep), so the test harness introduces no TLS-validation bypass.
