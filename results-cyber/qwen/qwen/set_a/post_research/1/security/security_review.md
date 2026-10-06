# Security Review: Session handoff (`com.acme.portal.session`)

## 1. Executive Summary

This is a static, read-only security review of a Jakarta Servlet 6.0 "session
handoff" component that turns an assertion set by a trusted in-JVM authenticator
into a single hardened `__Host-` session cookie. The reviewed tree is untrusted
generated code; it was read, not executed, built, or imported.

The component is a notably hardened reference implementation. Across the full
HTTP decision path it never reads client-controlled session input (no cookie,
query, body, header, or `*-For` value), re-verifies every asserted identifier
against a server-side authority, fails closed to HTTP 503 wherever a
collaborator is absent/ambiguous/throwing or the deployment hygiene check cannot
be completed, uses a constant-work equaliser plus byte-identical refusal bodies
to suppress timing and response-shape oracles, and encodes every value it emits
into HTML. A mutation battery (`tools/mutants.py`) deliberately weakens each
guard and the harness is written to catch it, which corroborates that the
guards are live rather than decorative.

**No High or Critical findings were identified.** Two LOW findings are reported:
an incomplete code-location coverage in the startup hygiene gate under a WAR
deployment (CWE-426), and a 48-bit truncated digest used as a comparison value
that becomes an offline verification oracle if the *trusted issuer* ever mints
low-entropy identifiers (CWE-326). The latter is a residual the source itself
documents as an integration contract. The remaining reviewed controls — cookie
hardening, header/CRLF-injection resistance, log-secret masking and log forging,
XSS output encoding, rate limiting, and the `InetAddress` parser surface —
held up under the matched skills and are recorded in Section 6.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/main/java/com/acme/portal/session/SessionHandoffServlet.java` | HTTP adapter / lifecycle | Never calls `getSession`; reads only `getRemoteAddr` + one trusted request attribute; fail-closed `serveNothing()`; constant headers/body shape; GET/HEAD parity (HEAD issues no cookie); 429/501/405 handling; logs only fingerprint + exception type |
| `src/main/java/com/acme/portal/session/SessionHandoffService.java` | Pure decision | Validate → budget → verify order; null verifier = `DENY_ALL`; verifier exception ⇒ invalid; `toString` leaks only the outcome |
| `src/main/java/com/acme/portal/session/SessionId.java` | Identifier value type | Reject-only `inspect` (no trim/case-fold/normalise); 32–128 base64url charset; `SecureRandom` `generate()`; truncated-SHA-256 `fingerprint()` is the only loggable material |
| `src/main/java/com/acme/portal/session/SessionCookiePolicy.java` | Cookie description | `secure()`/`httpOnly()` hardcoded true; host-only (`domain()` null); session cookie (`maxAge()` 0); refuses `SameSite=None`; `__Host-` requires `Path=/` |
| `src/main/java/com/acme/portal/session/SessionCookieWriter.java` | Emission path | Re-validates value at the boundary; sets `no-store` before the cookie; `addCookie` not `setHeader`; never `setMaxAge`/`setDomain` |
| `src/main/java/com/acme/portal/session/SessionHandoffSettings.java` | Config from env | 8 vars, type/length/range validated; rejects non-printable env bytes; blocks reserved Jakarta/Java attribute prefixes; enforces `maxPerWindow ≤ globalMax` |
| `src/main/java/com/acme/portal/session/AttemptLimiter.java` | Fixed-window throttle | Whole `tryAcquire` under one monitor; per-source + global + tracking-saturation ceilings; global checked before increment; bounded bucket map with O(1) reclaim; monotonic clock; reduced ceiling for unknown sources |
| `src/main/java/com/acme/portal/session/ClientAddress.java` | Bucket key from socket address | Never reads `*-For`; strict dotted-quad / IPv6-literal grammar enforced **before** `InetAddress.getByName`; folds `::ffff:a.b.c.d`→/32, v6→/64; shared reduced `UNKNOWN` lane |
| `src/main/java/com/acme/portal/session/CacheSupport.java` | SHA-256 helper | ThreadLocal digest; feeds parts in chunks (no credential copy to prefix); zeroes scratch buffers |
| `src/main/java/com/acme/portal/session/DeploymentHygiene.java` | Startup code-location gate | Inspects `java.class.path` + named code-owner code sources; refuses on `OTHERS_WRITE`/missing/unreadable/non-POSIX; `logSafe` strips control chars (anti log-forging) |
| `src/main/java/com/acme/portal/session/ResponseBody.java` | Response bodies | Byte-identical `REFUSAL` for every denial; grants interpolate only the HTML-escaped cookie name; output-width bound on escaping |
| `src/main/java/com/acme/portal/session/WorkEqualizer.java` | Timing equaliser | Constant SHA-256 work on every path; constant cost independent of inputs; clones shared input |
| `src/main/java/com/acme/portal/session/SessionStateVerifierProvider.java` | `ServiceLoader` discovery | `stream()`+`type()` so a candidate's static-init/ctor never runs before the hygiene verdict; refuses ambiguous (count>1) and unloaded providers; fail-closed |
| `src/main/java/com/acme/portal/session/RequestAttributeAssertionSource.java` | Trusted-input reader | Reads only `request.getAttribute(name)`; accepts only `String`; exception ⇒ null |
| `src/main/java/com/acme/portal/session/TrustedSessionAssertionSource.java` | Contract interface | Forbids reading client data / logging the value / throwing |
| `src/main/java/com/acme/portal/session/InvalidSessionIdentifierException.java` | Checked rejection | Message = rejection enum name only; never carries the value; `Locale.ROOT` lowercasing |
| `deploy/web.xml` | Shipped descriptor | COOKIE tracking mode; `http-only`/`secure` as intent; error/`Throwable` → static `error.html`; test-only marker |
| `deploy/web.test-only.xml` | Test-only fragment | Injected into TEST wars only; unauthenticated `StubControl` on `/stub/control/*`; **must never ship** (enforced by `build.sh`) |
| `deploy/WEB-INF/static/error.html` | Static error page | No scriptlet, no request data |
| `build.sh` | Dev-only build/e2e | Verifies servlet-api jar (published SHA-1 + pinned SHA-512) and Tomcat tarball (pinned SHA-512) before use; stray-byte + XML gates; `-Werror`; asserts packaged WAR class set |
| `src/test/**` | Harness, e2e client, stubs, probe verifier | Test scaffolding; only `Stub*.class` ship, harness/client/probe excluded (asserted by `build.sh`) |
| `tools/mutants.py` | Mutation battery | Weakens each guard to prove the harness detects it (attests guards are live) |

Out of scope: `build/apache-tomcat-10.1.60/**`, `*.class`, `*.war`,
`tools/*.tar.gz`, `tools/*.jar` (vendored build inputs), and the generation
meta files at the source root (`prompt.txt`, `prompt_hash.txt`, `result.md`,
`return.txt`, `README.md`).

## 3. Skills Applied

Matched from the skill library by keyword and applied one at a time to the code:

- **`performing-cryptographic-audit-of-application`** — applied to
  `SessionId.generate()` / `SECURE_RANDOM` (`SessionId.java:210`, `:269`),
  `SessionId.fingerprint()` (`SessionId.java:246-249`) and the truncated-digest
  constant (`SessionId.java:61`), and `CacheSupport` (`CacheSupport.java`).
  Surfaced **SEC-02**; confirmed `generate()` uses 256 bits of `SecureRandom`
  and that `CacheSupport` avoids copying the credential to prefix it (§6).
- **`testing-for-xss-vulnerabilities`** — applied to `ResponseBody.granted()` and
  `escapeHtml()` (`ResponseBody.java:57-58`, `:67-110`). No XSS: the only
  interpolated value is the cookie name, whose charset excludes HTML
  metacharacters, and it is escaped regardless (§6).
- **`implementing-api-rate-limiting-and-throttling`** — applied to
  `AttemptLimiter.tryAcquire()` (`AttemptLimiter.java:182-204`). Verified the
  global lane is checked before charging a source, tracking is bounded, and the
  reclaim work inside the monitor is O(1) (§6).
- **`exploiting-server-side-request-forgery`** — applied to
  `ClientAddress` (`ClientAddress.java:205-222`). Confirmed the grammar is
  proven before `InetAddress.getByName`, so attacker text never reaches the OS
  resolver (§6).

No skill in the library is named specifically for cookie
hardening (`__Host-` prefix), HTTP response-header / CRLF injection,
CWE-117 log forging, CWE-426 untrusted search path, or timing side-channels.
Those were reviewed against general OWASP/CWE practice; SEC-01 (CWE-426)
originates from that general review, and the rest are covered in Section 6.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Startup hygiene gate does not cover the webapp classloader's own repositories under a WAR | Low | CWE-426 | `SessionHandoffServlet.java:91`, `:118`; `DeploymentHygiene.java:47-70` |
| SEC-02 | 48-bit truncated fingerprint is an offline verification oracle for low-entropy identifiers | Low | CWE-326 | `SessionId.java:61`, `:246-249` |

Both findings are Low. No High/Critical/Medium findings were identified.

## 5. Detailed Findings

### SEC-01 — Hygiene gate misses WEB-INF repositories in a WAR deployment

- **Severity:** Low
- **CWE:** CWE-426 (Untrusted Search Path) — incomplete enumeration of code
  locations whose write-accessibility is being attested.
- **Location:** `src/main/java/com/acme/portal/session/SessionHandoffServlet.java:91`
  and `:118` (call sites);
  `src/main/java/com/acme/portal/session/DeploymentHygiene.java:47-70`
  (the enumeration).

**Vulnerable code**

`DeploymentHygiene.describeProblem` builds the set of locations to attest from
two sources only — the JVM `java.class.path`, plus the code source of each
explicitly-passed code-owner class:

```java
// DeploymentHygiene.java:45-70
static String describeProblem(Class<?>... codeOwners) {
    Set<Path> locations = new LinkedHashSet<Path>();
    String classpath = System.getProperty("java.class.path", "");
    if (!classpath.isEmpty()) {
        String[] entries = classpath.split(File.pathSeparator);
        if (entries.length > MAX_ENTRIES) {
            return "the JVM classpath has more than " + MAX_ENTRIES + " entries";
        }
        for (String entry : entries) {
            Path path = toPath(entry);
            if (path != null) {
                locations.add(path);
            }
        }
    }
    for (Class<?> codeOwner : codeOwners) {
        // ...
        Path fromCodeSource = codeSourceLocation(codeOwner);
        // ...
        locations.add(fromCodeSource);
    }
    // ...
}
```

and the servlet passes exactly two code owners:

```java
// SessionHandoffServlet.java:91
hygieneProblem = DeploymentHygiene.describeProblem(SessionHandoffServlet.class);
// ...
// SessionHandoffServlet.java:118
hygieneProblem = DeploymentHygiene.describeProblem(SessionHandoffServlet.class, verifier.getClass());
```

**Why it is a problem**

The servlet is deployed as a WAR. In that layout `java.class.path` is the
container bootstrap path (Tomcat's `bootstrap.jar`, `tomcat-juli`, etc.); it
does **not** contain the web application's `WEB-INF/classes` or the jars under
`WEB-INF/lib`, which are loaded by the webapp classloader. Consequently the only
webapp-side bytecode the gate attests is the code source of the two named
classes: `SessionHandoffServlet` itself (→ `WEB-INF/classes`) and
`verifier.getClass()` (the verifier's own jar). The verifier's *transitive*
dependencies — e.g. the session-store driver it delegates to
(`sessstore-driver.jar`, a JDBC/Redis/Kafka client) sitting in `WEB-INF/lib` —
are never inspected for world-writability. An attacker who can write inside the
deployed directory tree but who does not (yet) hold write access to the two
attested locations could plant or replace such a dependency jar and have it
loaded as part of the "is this session valid" authority without the hygiene gate
ever objecting. The impact is bounded (the attacker still needs local write
access to the deployment, and every security decision still fails closed on a
null/throwing verifier), which is why this is Low rather than higher — but it is
a real gap between the gate's intent ("prove the code we are about to run is
read-only") and what it actually enumerates.

**Fix**

Enumerate the webapp classloader's own repositories as well, from the servlet,
using the `ServletContext` real paths for the two webapp locations, and pass them
into an overload of `describeProblem`. Example:

```java
// SessionHandoffServlet.java (init), replacing the two describeProblem calls
java.util.List<java.nio.file.Path> extra = new java.util.ArrayList<>();
String webInf = getServletContext().getRealPath("/WEB-INF");
if (webInf != null) {
    java.nio.file.Path lib = java.nio.file.Paths.get(webInf, "lib");
    if (java.nio.file.Files.isDirectory(lib)) {
        try (java.util.stream.Stream<java.nio.file.Path> jars = java.nio.file.Files.list(lib)) {
            jars.forEach(extra::add);            // every WEB-INF/lib/*.jar
        } catch (java.io.IOException e) {
            extra.add(lib);                      // let the gate fail closed on unreadable
        }
    }
    extra.add(java.nio.file.Paths.get(webInf, "classes"));
}
// Pass the webapp repositories + both code owners to a Path-accepting overload
// that applies the existing worldWritable()/parent/missing-entry checks to each.
hygieneProblem = DeploymentHygiene.describeProblem(
        extra, SessionHandoffServlet.class, verifier.getClass());
```

The `describeProblem` overload then folds the supplied `extra` paths into the
same `locations` set the `for (Path location : locations)` loop already
attests, preserving the current "unknown is not safe" behaviour for each added
entry.

### SEC-02 — 48-bit fingerprint is an offline oracle when the issuer's entropy is low

- **Severity:** Low (conditional on the trusted issuer's identifier entropy)
- **CWE:** CWE-326 (Inadequate Encryption Strength / insufficient comparison
  strength); related to CWE-327 (use of a broken/risky digest as a comparator).
- **Location:** `src/main/java/com/acme/portal/session/SessionId.java:61` and
  `:246-249`.

**Vulnerable code**

```java
// SessionId.java:61
private static final int FINGERPRINT_HEX = 12;   // 48 bits of SHA-256
```

```java
// SessionId.java:246-250
public String fingerprint() {
    // Two parts rather than one concatenation: see the note in CacheSupport about not copying a
    // bearer credential merely to prefix it.
    return CacheSupport.digestHexPrefix(new String[]{FINGERPRINT_PREFIX, value}, FINGERPRINT_HEX);
}
```

**Why it is a problem**

`fingerprint()` is the *only* session material the component ever logs (grant
lines, and `toString()`/exception masking), so its strength is a real security
property, not a cosmetic one. A 48-bit truncated digest is not a one-way mask —
it is a **verifier**: anyone who obtains the logs can, entirely offline, confirm
a guessed identifier against a logged line. For identifiers with genuine
entropy this is safe (2^48 work per line yields no usable value), which is why
this is conditional. The exposure is concrete when the trusted upstream issuer
mints identifiers from a space smaller than the 48 bits the digest publishes —
a short counter, a truncated UUID, a timestamp with a fixed prefix. In that case
a log leak turns into an enumeration oracle over the small identifier space,
without any access to the session store. The component cannot close this in
`inspect()` (deliberately — guessing about entropy caused false rejections
before), so the burden is stated as a deployment requirement, but a reviewer
should still flag the fixed 48-bit comparison width as the residual it is.

**Fix**

Widen the published digest so the offline-confirmation cost is far above the
largest identifier space an integrator might plausibly use, and — if a
deployment secret is acceptable — make it a keyed MAC so the log is not an
offline-verifiable function of the value at all:

```java
// Option A (no new secret): publish 96 bits instead of 48.
private static final int FINGERPRINT_HEX = 24;   // 96 bits

// Option B (stronger, needs a deployment secret): keyed, so the digest is not
// a public function of the identifier and cannot be verified offline at all.
// static { KEY = <read once from a secret manager>; }
private static final javax.crypto.Mac MAC =
        javax.crypto.Mac.getInstance("HmacSHA256");   // per-call, not shared/ThreadLocal-unsafe
```

If neither is adopted, keep the current width but treat "issuer entropy ≥ 128
bits" as a **hard pre-acceptance gate** in the integration contract (assert it
in `SessionStateVerifier` implementations and in deployment review), rather than
leaving it only as narrative in the Javadoc and README.

## 6. Verified Controls and Checks With No Finding

The following were reviewed (mostly via the matched skills in Section 3) and
held; they are recorded so the coverage is explicit.

**Trusted-input boundary (no client-controlled session input).**
`SessionHandoffServlet` never calls `request.getSession`, and the assertion is
read only via `RequestAttributeAssertionSource.readAssertion` →
`request.getAttribute(name)` (`RequestAttributeAssertionSource.java:39-47`),
which accepts a `String` and returns `null` on any exception. Cookies, query,
body, and headers are never consulted for identity. `ClientAddress` never reads
`X-Forwarded-For` or any `*-For` header (`ClientAddress.java:21`). Choosing the
socket peer (`getRemoteAddr`, `SessionHandoffServlet.java:256`) as the rate-limit
bucket — instead of a spoofable `XFF` — is the security-correct choice for an
authorization decision; the source notes the reverse-proxy caveat as an
operational, not security, tradeoff.

**Reject-only validation / canonicalization.** `SessionId.inspect`
(`SessionId.java:112-131`) enforces length 32–128 and the base64url charset with
no trimming, case-folding, or normalisation, so two byte-strings cannot fold to
one session. `LOW_CHAR_DIVERSITY` is applied only to `generate()`'s own output
via `selfTest` (`SessionId.java:146`), not to asserted ids — the mutation battery
documents that applying it to the request path false-rejected ~1.7% of
store-vouched ids, so this scoping is deliberate, not an oversight.

**Cookie hardening.** `SessionCookiePolicy` hardcodes `secure()`/`httpOnly()` to
`true` (`SessionCookiePolicy.java` `secure()`/`httpOnly()`), `domain()` to
`null` (host-only) and `maxAge()` to `0` (session cookie). `canonicalSameSite`
refuses `None` and anything other than `Strict`/`Lax`; `__Host-` requires
`Path=/`; name/path charsets exclude `;`, `"`, `,`, `:`, CR, LF, NUL, and
non-ASCII. `build.sh`'s mutation battery carries `POLICY-*`/`WRITER-*` mutants
that prove these invariants are enforced, not aspirational.

**HTTP response-header / CRLF injection.** The cookie is emitted with
`response.addCookie(...)` (`SessionCookieWriter.java`), so the container owns
header syntax and quoting; the value is base64url-only and the name/path are
charset-validated; `SessionHandoffSettings` rejects any env byte `<0x21` or
`>0x7E`, so CR/LF cannot enter a configured name, path, or SameSite.

**Emission-boundary re-validation.** `SessionCookieWriter.writeSessionCookie`
re-runs `SessionId.inspect(value)` immediately before building the `Cookie` and
sets `Cache-Control: no-store, max-age=0` / `Pragma: no-cache` *first*, so a
rejected value never reaches the response and any partial response is already
uncacheable. It deliberately never calls `setMaxAge`/`setDomain`.

**Fail-closed everywhere.** `serveNothing()` (`SessionHandoffServlet.java:134`)
nulls all collaborators and sets `serving=false`; init runs it on invalid
settings, absent verifier, ambiguous/unloadable provider, or any hygiene problem.
`SessionHandoffService` maps a null verifier to `DENY_ALL`; a verifier that
throws is treated as "invalid". The provider uses `ServiceLoader.stream()` +
`Provider.type()` and calls `describeProblem(candidate)` **before**
`only.get()` (`SessionStateVerifierProvider.java`), so a verifier planted in a
writable location is refused before its static initialiser or constructor runs
(the mutation battery's `SVC-hygiene-order` mutant pins this ordering).
`web.xml` maps `Throwable` to a static `error.html`, so even an `Error` yields no
stack trace to the client.

**Secret leakage / log forging (CWE-117).** The only session material ever logged
is the fingerprint; grant lines log `fingerprint` only, and errors log
`exceptionType` (`SessionHandoffServlet.handle` catch at
`SessionHandoffServlet.java:289`). `InvalidSessionIdentifierException` carries
only the rejection enum name (with `Locale.ROOT`), never the value.
`SessionId`/`SessionHandoffService` `toString()` deliberately expose only the
fingerprint/outcome. `DeploymentHygiene.logSafe`
(`DeploymentHygiene.java:101`) strips CR/LF/NUL/DEL from paths so a filename
cannot forge a second log line.

**Timing / shape oracles.** `WorkEqualizer.apply()` runs constant SHA-256 work
on every path (`SessionHandoffServlet.java:243`), before the serving check and
before the limiter, so response timing cannot rank outcomes; `ResponseBody.REFUSAL`
is byte-identical for every denial (`ResponseBody.java:19`), and GET/HEAD share
decision, headers, and work while HEAD writes no cookie (`writeBody=false`,
`SessionHandoffServlet.java:232`, `:319`). (Fixed CPU before shedding is an
accepted tradeoff: the limiter sheds the store round-trip and cookie write, not
the equaliser's fixed cost; the source reasons about this and ships a timing
harness.)

**XSS.** `ResponseBody.granted` interpolates only `escapeHtml(policy.name())`
(`ResponseBody.java:57-58`, `:67-110`). The cookie-name charset contains no HTML
metacharacters, escaping covers `& < > " '`, control characters become spaces,
and the output-width bound (`MAX_ESCAPED_LENGTH` charged against `WIDEST_ENTITY`)
makes entities whole-or-absent rather than truncated-mid-entity.

**Rate limiting (CWE-799-adjacent resource control).** `AttemptLimiter.tryAcquire`
is fully under one monitor (`AttemptLimiter.java:182`); the global ceiling is
checked *before* charging either counter (`:198-204`) so a shared-lane flood
cannot spend innocent sources' allowance; tracking is bounded
(`maxTrackedSources`) with an O(1) `RECLAIM_CANDIDATES`-sized reclaim hand so one
stalled client's scan stays independent of crowd size; the clock is monotonic;
unknown sources get a reduced ceiling.

**SSRF / resolver reach (CWE-404-adjacent).** `ClientAddress.parse` applies a
character allowlist and full dotted-quad / IPv6-literal grammar
(`ClientAddress.java:41`, `:131`, `:205-212`) **before** calling
`InetAddress.getByName` (`:222`), so inputs like `517996801`, `0x7f.1`, or a
hostname never reach the OS resolver; `::ffff:a.b.c.d` folds to /32 while the
obsoleted `::a.b.c.d` form deliberately does not fold.

**Build/provenance (dev tooling).** `build.sh` verifies the servlet-api jar
against its published SHA-1 **and** a pinned SHA-512, and the Tomcat tarball
against a pinned SHA-512, before either is used/extracted; gates stray non-ASCII
bytes and malformed `web.xml`; compiles `-Werror`; and asserts the packaged WAR
carries the four test `Stub` classes and **not** `Harness`/`E2EClient`/
`ProbeVerifier`. The unauthenticated `StubControlServlet` on `/stub/control/*`
exists only in `web.test-only.xml`, which is injected solely into throwaway test
wars and is not part of the shipped `deploy/web.xml`.
