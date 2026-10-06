# Security Review: Java Session Handoff Component

## 1. Executive Summary

The component accepts a session identifier asserted by an upstream in-process authenticator, validates its shape, verifies it against an application-supplied server-side session store, rate-limits the request, and returns it in a hardened servlet cookie. The implementation has strong input validation, fail-closed session verification, cookie attributes, uniform error handling, bounded in-process state, and HTML encoding.

Five vulnerabilities were identified. Two are High severity: the deployment hygiene gate accepts group-writable executable code, and the build allows an environment-selected servlet API JAR to bring its own supposedly trusted checksum before `javac` loads it. Two Medium findings affect throttling: all users collapse into one rate-limit bucket behind a reverse proxy, while replicas maintain independent counters that multiply the allowed attempt and load budget. One Low finding logs a deterministic verifier derived from a bearer session token. No Critical findings were found.

## 2. Scope

The canonical authored sources, deployment files, build tooling, tests, and documentation under `/data/results/qwen/set_a/post_research/1/security/` were reviewed statically. `build/mut-pristine` is byte-identical to `src/main`; compiled classes, WAR/JAR archives, logs, and staged copies are derived artifacts; and `build/apache-tomcat-10.1.60` is a vendored third-party Tomcat distribution. Those duplicates and binaries were inventoried but not treated as separate authored implementations. Nothing from the source tree was executed, built, installed, or imported.

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `README.md` | Architecture, threat model, deployment guide, and known limitations | Documents the trusted authenticator boundary, proxy behavior, per-JVM throttling, token logging, and test-only WARs. |
| `build.sh` | Compiles, packages, launches test Tomcat instances, and drives end-to-end checks | Selects toolchain/dependencies, verifies hashes, creates WARs, and launches processes. |
| `tools/mutants.py` | Mutates security controls and invokes the frozen test harness | Copies source trees, invokes compiler/JVM subprocesses, and writes test artifacts. |
| `deploy/web.xml` | Production starting-point servlet descriptor | Maps the handoff endpoint, restricts URL session tracking to cookies, hardens container cookies, and installs static error pages. |
| `deploy/web.test-only.xml` | Injected end-to-end-test descriptor fragment | Exposes test-only authenticator and session-control components; explicitly excluded from the production descriptor. |
| `deploy/WEB-INF/static/error.html` | Static generic error page | Avoids reflecting request or exception data. |
| `src/main/java/com/acme/portal/session/AttemptLimiter.java` | Fixed-window per-source and global limiter | Maintains atomic, bounded, JVM-local counters and computes `Retry-After`. |
| `src/main/java/com/acme/portal/session/CacheSupport.java` | SHA-256 and truncated fingerprint helper | Hashes bearer identifiers and clears temporary arrays. |
| `src/main/java/com/acme/portal/session/ClientAddress.java` | Parses and canonicalizes rate-limit source addresses | Rejects malformed IP text, avoids DNS lookup, folds IPv4-mapped IPv6, and groups IPv6 by `/64`. |
| `src/main/java/com/acme/portal/session/DeploymentHygiene.java` | Checks classpath and code-source permissions | Gates service/provider loading based on existence and POSIX writability and sanitizes paths for logs. |
| `src/main/java/com/acme/portal/session/InvalidSessionIdentifierException.java` | Safe validation exception | Carries only a rejection enum, never token data. |
| `src/main/java/com/acme/portal/session/RequestAttributeAssertionSource.java` | Reads the upstream authenticator assertion | Accepts only a `String` from a configured server-side request attribute. |
| `src/main/java/com/acme/portal/session/ResponseBody.java` | Produces grant/refusal HTML | Uses constant refusal content and context-appropriate HTML text encoding with an output bound. |
| `src/main/java/com/acme/portal/session/SessionCookiePolicy.java` | Validates cookie configuration | Enforces Secure, HttpOnly, host-only, session lifetime, safe name/path, and Strict/Lax SameSite. |
| `src/main/java/com/acme/portal/session/SessionCookieWriter.java` | Emits the session cookie | Revalidates the token, sets no-store headers, and delegates safe cookie serialization to the servlet API. |
| `src/main/java/com/acme/portal/session/SessionHandoffService.java` | Makes the authorization decision | Validates assertions, consumes throttle budget, and requires authoritative server-side verification. |
| `src/main/java/com/acme/portal/session/SessionHandoffServlet.java` | HTTP adapter and response writer | Wires dependencies, handles methods, derives source address, logs results, emits cookies, and normalizes errors. |
| `src/main/java/com/acme/portal/session/SessionHandoffSettings.java` | Loads and validates environment configuration | Applies strict character/range checks and fails startup on unsafe settings. |
| `src/main/java/com/acme/portal/session/SessionId.java` | Validates, generates, and masks opaque session identifiers | Uses a 256-bit CSPRNG, base64url allowlist, length bounds, and deterministic log fingerprinting. |
| `src/main/java/com/acme/portal/session/SessionStateVerifierProvider.java` | Discovers the application session verifier | Uses `ServiceLoader`, rejects ambiguity, and checks code location before provider instantiation. |
| `src/main/java/com/acme/portal/session/TrustedSessionAssertionSource.java` | Defines the trusted assertion-source contract | Explicitly forbids client-controlled cookie/header/query/body fallbacks. |
| `src/main/java/com/acme/portal/session/WorkEqualizer.java` | Adds fixed computational work to all request paths | Reduces timing differences while imposing bounded per-request CPU work. |
| `src/test/java/com/acme/portal/session/Harness.java` | In-process security and concurrency test harness | Tests validation, cookies, authorization, limiting, address parsing, logging, permissions, and timing. |
| `src/test/java/com/acme/portal/testapp/E2EClient.java` | End-to-end HTTP assertion client | Sends normal and raw hostile HTTP requests and checks response/cookie behavior. |
| `src/test/java/com/acme/portal/testapp/ProbeVerifier.java` | Provider-loading test probe | Uses a static file-write side effect to detect premature class initialization. |
| `src/test/java/com/acme/portal/testapp/StubAuthenticatorFilter.java` | Test-only authenticator | Converts special request headers into test sessions/assertions; unsafe by design if deployed outside tests. |
| `src/test/java/com/acme/portal/testapp/StubControlServlet.java` | Test-only session control endpoint | Expires or counts test sessions without authentication; unsafe by design if deployed outside tests. |
| `src/test/java/com/acme/portal/testapp/StubSessionStore.java` | Test-only in-memory session authority | Generates random session IDs and stores ticket/session mappings. |
| `src/test/java/com/acme/portal/testapp/StubSessionVerifier.java` | Test-only verifier provider | Confirms identifiers against the stub live-session map. |
| `src/test/resources/META-INF/services/com.acme.portal.session.SessionHandoffService$SessionStateVerifier` | Registers the test verifier | Causes `ServiceLoader` to instantiate the stub provider in test deployments. |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: used to inventory all authored code, identify security-relevant behavior, route the review to specialized skills, and require CWE/file-line evidence.
- `testing-api-authentication-weaknesses`: applied to the trusted assertion boundary, server-side session validation, token generation/leakage, fail-closed behavior, and session cookie lifecycle.
- `implementing-api-rate-limiting-and-throttling`: applied to per-source/global counter atomicity, source-key trust, distributed deployment behavior, bounded state, HTTP 429, and `Retry-After`.
- `testing-for-xss-vulnerabilities`: applied to all data rendered in HTML and the output-encoding/CSP boundary.
- General OWASP Top 10 / CWE knowledge: applied to POSIX code-source permissions, Java compiler/annotation-processor supply-chain trust, shell/process invocation, test-only deployment artifacts, error handling, cryptography, and unsafe deserialization because no closer specialized skill matched those behaviors.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Group-writable verifier code passes the deployment hygiene gate | High | CWE-732 | `src/main/java/com/acme/portal/session/DeploymentHygiene.java:144-149` |
| SEC-02 | Attacker-selected build dependency supplies its own trust evidence | High | CWE-829 | `build.sh:10-15,44-47,82-83` |
| SEC-03 | Reverse-proxy deployments collapse all clients into one throttle bucket | Medium | CWE-400 | `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:256` |
| SEC-04 | JVM-local counters multiply the authentication budget across replicas | Medium | CWE-307 | `src/main/java/com/acme/portal/session/AttemptLimiter.java:86-87` |
| SEC-05 | Logs contain a deterministic verifier derived from the bearer token | Low | CWE-532 | `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:328-329,346-347` |

## 5. Detailed Findings

### SEC-01: Group-writable verifier code passes the deployment hygiene gate

- **Severity:** High
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `src/main/java/com/acme/portal/session/DeploymentHygiene.java:144-149`

**Vulnerable code:**
```java
private static boolean worldWritable(Path path) {
    try {
        Set<java.nio.file.attribute.PosixFilePermission> permissions =
                Files.getPosixFilePermissions(path);
        return permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
```

**Why it is a problem:** The gate claims to prevent another local account from changing code that is about to become the session-validity authority, but it checks only `OTHERS_WRITE`. A JAR, class directory, or its parent can be writable by `GROUP_WRITE` and still be accepted. Any different account in that group can replace the verifier or application code. Because `SessionStateVerifierProvider` subsequently instantiates that code and trusts its answer, exploitation yields arbitrary code execution in the servlet process and a complete authentication bypass. The test harness covers `0777` and `0700`, but not a group-writable mode such as `0770` or `0660`.

**Fix:** Reject group-writable as well as world-writable code locations and parents, and add regression cases for both group-writable files and directories. If a deployment intentionally shares a group, validate ownership and require a dedicated group with no other principals rather than treating any group write bit as safe.
```java
private static boolean worldWritable(Path path) {
    try {
        Set<java.nio.file.attribute.PosixFilePermission> permissions =
                Files.getPosixFilePermissions(path);
        return permissions.contains(java.nio.file.attribute.PosixFilePermission.GROUP_WRITE)
                || permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
    } catch (UnsupportedOperationException | IOException cannotVerify) {
        return true;
    }
}
```

### SEC-02: Attacker-selected build dependency supplies its own trust evidence

- **Severity:** High
- **CWE:** CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- **Location:** `build.sh:10-15,44-47,82-83`

**Vulnerable code:**
```bash
SERVLET_API="${SERVLET_API_JAR:-tools/jakarta.servlet-api-6.0.0.jar}"
TOMCAT_HOME="build/apache-tomcat-10.1.60"
JAVA_HOME_DIR="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
JAVAC="$JAVA_HOME_DIR/bin/javac"
JAVA="$JAVA_HOME_DIR/bin/java"
JAR="$JAVA_HOME_DIR/bin/jar"
```

```bash
verify_publisher_sha1 "$SERVLET_API" "$SERVLET_API.sha1" \
  || { echo "ERROR $SERVLET_API does not match the SHA-1 published with it" >&2; exit 2; }
( cd "$(dirname "$SERVLET_API")" && sha512sum -c "$(basename "$SERVLET_API").pinned-sha512" >/dev/null ) \
  || { echo "ERROR $SERVLET_API does not match the pinned SHA-512" >&2; exit 2; }
```

```bash
"$JAVAC" -Xlint:all -Werror -encoding US-ASCII -cp "$SERVLET_API" \
    -d build/classes $(find src/main/java -name '*.java') || exit 2
```

**Why it is a problem:** `SERVLET_API_JAR` controls both the dependency path and the locations of the SHA-1 and “pinned” SHA-512 evidence. An attacker who can influence the build environment and provide files can point the build at `evil.jar`, `evil.jar.sha1`, and `evil.jar.pinned-sha512`; all checks then succeed because the attacker selected both the object and its expected digests. `javac` is invoked without `-proc:none` or an isolated processor path, so a malicious classpath JAR can register and execute an annotation processor during compilation. Even without annotation processing, later build/test use trusts the substituted API classes.

**Fix:** Anchor the dependency and expected checksum to repository-controlled, non-overridable paths (or an authenticated dependency lock/provenance system), compare against that independent value, and disable annotation processing when the project does not use it. If an override is operationally required, make its expected digest a separately protected input that cannot travel beside the override.
```bash
SERVLET_API="$ROOT/tools/jakarta.servlet-api-6.0.0.jar"
SERVLET_API_SHA512="$ROOT/tools/jakarta.servlet-api-6.0.0.jar.pinned-sha512"

( cd "$ROOT/tools" && sha512sum -c "$(basename "$SERVLET_API_SHA512")" >/dev/null ) \
  || { echo "ERROR servlet API does not match the repository-pinned SHA-512" >&2; exit 2; }

"$JAVAC" -proc:none -Xlint:all -Werror -encoding US-ASCII -cp "$SERVLET_API" \
    -d build/classes $(find src/main/java -name '*.java') || exit 2
```

### SEC-03: Reverse-proxy deployments collapse all clients into one throttle bucket

- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:256`

**Vulnerable code:**
```java
ClientAddress source = ClientAddress.parse(request.getRemoteAddr());
```

**Why it is a problem:** Behind a reverse proxy or ingress, `getRemoteAddr()` is normally the proxy address, so every external user shares a single per-source bucket. One remote attacker can consume the default 30 grants/attempts and force every other user routed through that proxy to receive 429 responses until the window rolls. The README acknowledges this as an availability limitation, but the code offers no trusted-proxy mode, so the documented HTTPS-terminator deployment can turn an anti-abuse control into a low-cost denial-of-service primitive. Blindly trusting `X-Forwarded-For` would create a bypass; the missing control is a proxy-aware resolver that trusts forwarded identity only when the immediate peer is explicitly trusted and the proxy overwrites the header.

**Fix:** Configure canonical addresses/CIDRs for trusted proxy peers. Use a single proxy-overwritten client-IP header only when the immediate peer matches that allowlist; otherwise retain the socket peer. Reject malformed or multi-valued input into the restricted unknown bucket.
```java
ClientAddress peer = ClientAddress.parse(request.getRemoteAddr());
ClientAddress source = peer;
if (trustedProxyKeys.contains(peer.key())) {
    String forwarded = request.getHeader("X-Real-IP");
    source = ClientAddress.parse(forwarded);
}
```

### SEC-04: JVM-local counters multiply the authentication budget across replicas

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/acme/portal/session/AttemptLimiter.java:86-87`

**Vulnerable code:**
```java
private final java.util.concurrent.ConcurrentHashMap<String, Window> windows =
        new java.util.concurrent.ConcurrentHashMap<String, Window>();
```

**Why it is a problem:** All source and global counters exist only in one `AttemptLimiter` object in one JVM. With `N` replicas, a client that rotates requests across instances receives approximately `N` times the configured per-source allowance, and the purported global store-protection ceiling is also multiplied by `N`. Autoscaling therefore weakens the control exactly when load is high. Sticky routing reduces but does not eliminate the problem because reconnects, failover, and deliberate backend selection can move requests. The README documents this limitation, but no deployment guard enforces a single replica.

**Fix:** Move check-and-increment state to a shared backend and perform rollover, comparison, and increment atomically (for example, a Redis Lua script keyed by endpoint and canonical source). Fail closed or apply a deliberately documented local emergency ceiling when the backend is unavailable. If shared state is intentionally out of scope, enforce and verify a single-replica deployment and describe the “global” limit as process-local in configuration/API names.
```java
public interface HandoffAttemptLimiter {
    AttemptLimiter.Decision tryAcquire(ClientAddress source);
    int retryAfterSeconds(ClientAddress source);
}

// The implementation performs one atomic server-side operation against shared state.
HandoffAttemptLimiter limiter = new RedisHandoffAttemptLimiter(
        redisClient, windowSeconds, perSourceCeiling, globalCeiling);
```

### SEC-05: Logs contain a deterministic verifier derived from the bearer token

- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:328-329,346-347`

**Vulnerable code:**
```java
LOG.log(Level.INFO, "session handoff availability check passed for session {0}",
        decision.sessionIdentifier().fingerprint());
```

```java
LOG.log(Level.INFO, "session handoff granted for session {0}",
        decision.sessionIdentifier().fingerprint());
```

**Why it is a problem:** The 12-hex-character SHA-256 prefix is a deterministic 48-bit verifier of a bearer credential. It is not directly replayable, but anyone who obtains logs can confirm offline guesses for tokens from a weak or structured upstream generator. The validator enforces shape, not entropy, so strings such as repeated characters can pass if the authoritative store accepts them. The comments and README acknowledge this residual risk, but logging the fingerprint creates the oracle and expands credential-derived data into log retention, backup, and analytics systems.

**Fix:** Do not log data derived from a bearer credential. If request correlation is required, generate an independent random request/correlation ID that has no deterministic relationship to the session. A keyed HMAC can reduce offline guessing by readers without the key, but omitting the token-derived value is preferable here.
```java
LOG.log(Level.INFO, "session handoff availability check passed");
```

```java
LOG.log(Level.INFO, "session handoff granted");
```

## 6. Verified Controls and Checks With No Finding

- Session authorization: `SessionHandoffService.handle` validates the assertion, applies the limiter, and requires `SessionStateVerifier.isSessionValid` to return true; null or throwing verifiers fail closed.
- Assertion source: production code reads only a server-side request attribute as a `String`; it does not accept a session identifier from cookies, query parameters, headers, or the body.
- Identifier validation and generation: `SessionId` enforces 32-128 base64url characters and generates 32 random bytes with `SecureRandom`; no weak PRNG, hardcoded secret, signature bypass, or unsafe token normalization was found.
- Cookie security: `SessionCookiePolicy` and `SessionCookieWriter` enforce Secure, HttpOnly, host-only scope, session-only lifetime, safe name/path syntax, SameSite Strict/Lax, and a second validation immediately before emission.
- Header injection: cookie names, paths, SameSite, identifiers, and integer response headers are allowlisted/ranged, and cookie serialization uses `HttpServletResponse.addCookie`; no CRLF injection path was found.
- XSS: the only dynamic HTML value is the validated cookie name, which is additionally encoded for HTML text by `ResponseBody.escapeHtml`; refusal and error pages are constant/static and no client-controlled source reaches an HTML or DOM execution sink.
- Response leakage: authentication refusals share a constant body, exception messages/stacks are not returned, static error mappings cover 500/`Throwable`, and response caching is disabled.
- Method handling: only GET and HEAD reach the handoff logic; state-changing methods are refused and TRACE is disabled. HEAD follows the authorization/limiting path but does not emit a cookie.
- In-process limiter correctness: read/rollover/check/increment operations are synchronized, counter storage and reclamation work are bounded, unknown sources share a stricter bucket, and 429 responses include a positive `Retry-After`.
- Address parsing: `ClientAddress` accepts only literal IPv4/IPv6 grammar, canonicalizes bucket keys, bounds input length, and prevents attacker-triggered DNS lookup. No direct trust of spoofable forwarding headers was found.
- Service loading: provider enumeration rejects zero/multiple providers, checks the candidate code source before initialization, and fails closed on discovery/instantiation errors, apart from the group-write gap in SEC-01.
- Configuration: environment values are length/character/range checked, invalid configuration stops serving, and no passwords, keys, or embedded production credentials were found.
- Cryptographic use: SHA-256 is used for non-password hashing/fingerprinting and `SecureRandom` for token generation; no obsolete cipher, ECB mode, static IV, weak password hash, or home-grown encryption was found.
- Injection and deserialization: production code constructs no SQL/NoSQL queries or OS commands and performs no native Java/object, YAML, or XML deserialization of untrusted data.
- Build process invocation: subprocess executable/argument uses are quoted or passed as argument arrays; no direct shell-command injection from application request data was found. The independent trust failure is reported in SEC-02.
- Test-only artifacts: the unsafe stub authenticator/control endpoint is isolated in `deploy/web.test-only.xml`, the production starting descriptor does not reference it, and the README explicitly warns that generated end-to-end WARs contain test-only elements. These WARs must not be promoted as production artifacts.
