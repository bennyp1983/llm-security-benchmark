# Security Review: Internal Employee Portal Authentication (`com.portal.auth`)

## 1. Executive Summary

The reviewed code is a self-contained Java 21 authentication service for an internal employee
portal, built only on JDK primitives (no third-party runtime dependencies). It offers an HTTPS
front end (`GET /login`, `POST /login`, `POST /logout`) on the JDK `HttpsServer`, plus an
operator/employee CLI (`login`, `add-user`, `set-password`, `disable-user`, `status`,
`version`). Credentials are checked against a file-backed roster of PBKDF2-HMAC-SHA256
records; failed attempts are limited per account and per source and persisted to a durable
ledger; sessions and CSRF tokens are server-side state keyed by SHA-256 of a `SecureRandom`
token.

The defensive engineering here is unusually thorough, and most of the classic findings a
reviewer looks for are genuinely absent: there is no SQL, no deserialization, no command
execution, no hardcoded secret, no plaintext or reversible password storage, no user-controlled
session identifier, no HTTP fallback, no username enumeration channel (identical responses,
identical KDF work and a latency floor on every denial), and credential arrays are wiped on
every exit path. Cookies carry `HttpOnly; Secure; SameSite=Strict; Path=/`, roster/ledger/audit
files are created `0600` inside a `0700` directory with symlink and ownership refusals, and
every configuration value is strictly validated with unknown keys treated as fatal.

The findings that remain are therefore not credential-exposure bugs but **availability and
cryptographic-strength** issues, all reachable without authentication:

* **SEC-01 (High)** — the global, bounded CSRF pending-token map can be flushed by an
  unauthenticated flood of `GET /login` (which is itself subject to no limit). That makes login
  impossible for everyone while the flood runs, and because a CSRF failure is charged to the
  *victim's* source budget, 30 such failures block a legitimate source address for 8 hours.
* **SEC-02 (Medium)** — the per-source budget is consumed by *successful* logins too and is
  never reset by success, so every user behind one NAT/proxy egress address shares a 30-attempt
  budget whose block ceiling is 8 hours.
* **SEC-03 (Medium)** — PBKDF2-HMAC-SHA256 at a 150,000-iteration default (100,000 floor) is
  well below current OWASP guidance (600,000) for this KDF.
* Four low-severity issues: unvalidated algorithm labels in stored records, ledger write
  amplification and a hard capacity failure in the throttle map, public test hooks that mutate
  security state in the production artifact, and one unsynchronized read of shared mutable
  state.

## 2. Scope

All files under `/data/results/qwen/set_a/post_research/5/security/` were read. Line references
below are to the source tree; compiled `out/**/*.class` artifacts and `__pycache__` were not
disassembled (they are build output of the reviewed sources).

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/portal/auth/Main.java` | Process entry point; dispatches CLI vs. HTTPS listener | Refuse-only startup, exit code 2, error text reduced to a machine token |
| `src/main/java/com/portal/auth/Authenticator.java` | The single authentication decision | One KDF derivation per outcome, decoy derivation on every denial, throttle reservation before verification, locale-free ASCII case fold, password wiped at one exit point |
| `src/main/java/com/portal/auth/PasswordHasher.java` | PBKDF2-HMAC-SHA256 record format, verify, rehash | KDF parameters, per-record iteration count, decoy salt derivation, strict/lenient record parsing |
| `src/main/java/com/portal/auth/Crypto.java` | JDK crypto wrappers | `SecureRandom` tokens, SHA-256, `MessageDigest.isEqual`, strict canonical base64, truncated 64-bit identity references, array wiping |
| `src/main/java/com/portal/auth/SessionManager.java` | Server-side sessions and CSRF pairs | Session id generation (256-bit), SHA-256-keyed lookup, idle/absolute expiry, bounded self-evicting maps, single-use CSRF pair consumption |
| `src/main/java/com/portal/auth/ThrottleManager.java` | Per-account and per-source failed-attempt limiting | Atomic check-and-increment, exponential account back-off, 8-hour source block, latency padding, ledger persistence |
| `src/main/java/com/portal/auth/Ledger.java` | Durable throttle counters | Strict line parsing, generation-based anti-downgrade merge, cross-process `FileLock`, bounded sizes |
| `src/main/java/com/portal/auth/EmployeeStore.java` | Roster of `username -> record` | Refuse-only load, duplicate-name rejection, stat-based reload so revocation takes effect, locked atomic read-modify-write |
| `src/main/java/com/portal/auth/PortalServer.java` | HTTPS routing and responses | Method/content-type allowlist, 8 KiB body cap, strict form parser with key allowlist, CSRF enforcement, one byte-identical denial, cookie attributes, security headers, HTML escaping |
| `src/main/java/com/portal/auth/JdkHttpsListener.java` | TLS listener | PKCS12 keystore + password file, TLS 1.2/1.3 only, bounded thread pool, bounded body read, literal peer address (no reverse DNS), keystore password wiped |
| `src/main/java/com/portal/auth/PortalCli.java` | Operator/employee command line | No secret on argv, `Console.readPassword`, bounded non-trimming line reader, generic denial text, redacted error tokens |
| `src/main/java/com/portal/auth/PortalConfig.java` | Configuration loader | env/file/property precedence, unknown key fatal, strict int/host/path grammar, secret read as a path to a private file |
| `src/main/java/com/portal/auth/PrivateFiles.java` | All filesystem access | `0600`/`0700` enforcement, `NOFOLLOW_LINKS`, ownership probe, world-writable ancestor refusal, atomic replace, bounded reads |
| `src/main/java/com/portal/auth/InputPolicy.java` | The input trust boundary | Username/password character class and length, no trimming, opaque token shape, enrolment strength rules |
| `src/main/java/com/portal/auth/SourceRef.java` | Peer address to throttle key | Hand-written literal IPv4/IPv6 parsing (no DNS), `X-Forwarded-For` honoured only from trusted CIDRs, right-to-left hop walk |
| `src/main/java/com/portal/auth/CookieParser.java` | Single `Cookie` header parse | Exact `name=value` match, bounded value length, no lenient aliasing |
| `src/main/java/com/portal/auth/AuditLog.java` | Security event log | Identity references only (never names/secrets), fixed token alphabet, exception reduced to class name, logging failure never changes a decision |
| `src/main/java/com/portal/auth/AuditClock.java` | Single clock source | Mutable static clock used by expiry and lockout windows |
| `src/main/java/com/portal/auth/HttpExchangeView.java`, `PortalRuntime.java` | HTTP abstraction, dependency wiring | Refuse-only boot ordering; strictness contract for implementations |
| `src/test/java/com/portal/auth/*.java` (6 suites) | Adversarial test harness | Fixture credentials used only against temp data directories; source-shape assertions |
| `build.sh`, `test.sh`, `portal.sh`, `portal.cmd` | Build and launch | ASCII-only compile, fixed classpath, `CLASSPATH` stripped, no `.`/wildcard on the classpath, no secrets on argv |
| `tools/gen-cert.sh` | Throwaway PKCS12 keystore | Password from `/dev/urandom`, `umask 077`, `-storepass:env` (never argv), never echoed, refuses to overwrite |
| `tools/get-jdk.sh` | JDK fetch | Pinned version, HTTPS-only (`--proto '=https' --tlsv1.2`), SHA-256 verified before use |
| `tools/mutate.py` | Mutation-testing harness | `subprocess` with argument lists, no untrusted input, scratch dirs only |
| `config/portal.properties.example`, `.gitignore`, `README.md`, `docs/THREAT_MODEL.md` | Docs and config template | No secrets committed; runtime state and TLS material git-ignored |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router skill — drove the file-by-file behaviour
  inventory in section 2 and the keyword list (password storage, session/CSRF, rate limiting,
  cryptography, secrets, file permissions, TLS, input validation, timing side channels, DoS).
- `performing-cryptographic-audit-of-application`: applied to `Crypto.java`,
  `PasswordHasher.java` and `JdkHttpsListener.java` — weak-hash/cipher-mode/ECB checks (none
  present), RNG source (`SecureRandom` only), hardcoded-secret scan (none), KDF parameter check
  (`scripts/process.py` KDF rule and its OWASP 600,000-iteration reference produced SEC-03),
  and deprecated-protocol check (TLS 1.0/1.1 explicitly excluded).
- `performing-csrf-attack-simulation`: applied to `PortalServer.route`/`csrfAcceptable` and
  `SessionManager.consumeCsrfToken` — ran the skill's token tests statically (missing token,
  empty token, random token, replayed token, foreign token, SameSite enforcement). All are
  refused; the state-store exhaustion path behind those checks is SEC-01.
- `implementing-api-rate-limiting-and-throttling`: applied to `ThrottleManager` and the
  `GET /login` path — per-identity vs. per-IP keying, window semantics, counter reset
  semantics, and unmetered endpoints (produced SEC-01 and SEC-02).
- `performing-security-headers-audit`: applied to `PortalServer.securityHeaders` and the
  cookie builders — CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
  `Cache-Control: no-store`, and `HttpOnly`/`Secure`/`SameSite`/`Path` on both cookies (no
  finding; observations in section 6).
- `testing-for-sensitive-data-exposure`: applied to `AuditLog`, `PortalCli`, `Main`,
  `PortalConfig` and `PrivateFiles` — secrets in logs/argv/errors, file modes, PII in
  responses (no finding).
- `testing-api-authentication-weaknesses`: applied to `Authenticator`, `SessionManager` and
  `InputPolicy` — token entropy, token validation, missing auth on endpoints, weak password
  policy, credential-stuffing resistance (no finding; the JWT-specific parts of the skill do
  not apply, there are no JWTs here).
- Reviewed against general OWASP Top 10 / CWE knowledge because no library skill matched:
  the POSIX file-permission and symlink/TOCTOU model in `PrivateFiles` (CWE-732, CWE-59,
  CWE-367); cross-process `FileLock` and check-then-act atomicity in `EmployeeStore`,
  `Ledger` and `ThrottleManager` (CWE-367, CWE-362, CWE-567); the hand-written
  `x-www-form-urlencoded` and cookie parsers and the `X-Forwarded-For` trust model (CWE-20,
  CWE-348, CWE-444); response-header construction and HTML escaping (CWE-113, CWE-79);
  timing/work equalisation across authentication outcomes (CWE-203, CWE-208); resource bounds
  on maps, files and request bodies (CWE-400, CWE-770); and the shell/Python tooling
  (CWE-78, CWE-494).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unauthenticated `GET /login` flood evicts pending CSRF tokens, denying login and triggering 8-hour blocks of legitimate source addresses | High | CWE-770 | `src/main/java/com/portal/auth/SessionManager.java:73-82`, `src/main/java/com/portal/auth/PortalServer.java:131-137`, `src/main/java/com/portal/auth/PortalServer.java:152-154` |
| SEC-02 | Per-source budget is consumed by successful logins and never cleared by success, so one shared egress address locks out every user behind it | Medium | CWE-645 | `src/main/java/com/portal/auth/ThrottleManager.java:163-185`, `src/main/java/com/portal/auth/ThrottleManager.java:244-256` |
| SEC-03 | PBKDF2-HMAC-SHA256 iteration count (default 150,000, floor 100,000) is below current guidance | Medium | CWE-916 | `src/main/java/com/portal/auth/PasswordHasher.java:39-41` |
| SEC-04 | Stored password records' algorithm labels are never validated, so a record claiming any algorithm is verified as PBKDF2-HMAC-SHA256 | Low | CWE-20 | `src/main/java/com/portal/auth/PasswordHasher.java:268-297` |
| SEC-05 | Every attempt rewrites the whole throttle ledger, and a full subject map turns authentication into a 500 | Low | CWE-400 | `src/main/java/com/portal/auth/ThrottleManager.java:439-461`, `src/main/java/com/portal/auth/ThrottleManager.java:394-406` |
| SEC-06 | Public test hooks in the production artifact can rewind the clock and clear lockout state | Low | CWE-489 | `src/main/java/com/portal/auth/AuditClock.java:31-34`, `src/main/java/com/portal/auth/ThrottleManager.java:387-392` |
| SEC-07 | Unsynchronized read of the CSRF map outside the monitor that guards it | Low | CWE-567 | `src/main/java/com/portal/auth/SessionManager.java:157` |

## 5. Detailed Findings

### SEC-01: Unauthenticated `GET /login` flood evicts pending CSRF tokens, denying login and triggering 8-hour blocks of legitimate source addresses

- **Severity:** High
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/portal/auth/SessionManager.java:73-82` (and `:150-158`, `:174-187`), `src/main/java/com/portal/auth/PortalServer.java:152-154`, `src/main/java/com/portal/auth/PortalServer.java:131-137`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/SessionManager.java:73-83
    private final LinkedHashMap<String, Long> pendingCsrf = new LinkedHashMap<>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
            // Self-evicting for the same reason the session map is, and because one
            // unauthenticated visitor may request the login page (and therefore a CSRF
            // pair) as often as they like: an eviction that only ran when the writer
            // happened to notice the ceiling had been reached could be skipped entirely by
            // a caller that removed entries as it went, letting the map grow past the
            // documented bound. The bound is what keeps that heap cost finite.
            return size() > MAX_PENDING_CSRF;
        }
    };
```

```java
// src/main/java/com/portal/auth/PortalServer.java:152-154
    private void showLoginPage(HttpExchangeView ex) throws IOException {
        String token = Crypto.randomUrlToken(InputPolicy.CSRF_TOKEN_BYTES);
        runtime.sessions().issueCsrfToken(token, token);
```

```java
// src/main/java/com/portal/auth/PortalServer.java:131-137
        if (!csrfAcceptable(ex, fields)) {
            String csrfSource = sourceHexOf(ex);
            runtime.throttle().consumeSourceBudget(csrfSource);
            audit.event("csrf", "-", csrfSource, "denied", "token-mismatch");
            denied(ex);
            return;
        }
```

**Why it is a problem:** `pendingCsrf` is a single process-wide map holding at most
`MAX_PENDING_CSRF = 50_000` entries (`SessionManager.java:38`), evicting the *oldest* entry on
every insert past the bound. Every `GET /login` inserts one entry
(`PortalServer.java:152-154`), and `GET /login` is reached before any throttle check:
`route` (`PortalServer.java:104-111`) dispatches it directly, and nothing on that path calls
`beginAttempt` or `consumeSourceBudget`. An unauthenticated attacker who issues 50,000 cheap
`GET /login` requests therefore evicts every pending token issued to real users. A victim who
loaded the login page and then posts correct credentials fails
`consumeCsrfToken` (`SessionManager.java:184`, the entry is gone), so the request never reaches
authentication and returns the generic 401 — login is impossible for the whole service for as
long as the flood continues.

The consequence is worse than a transient outage, because the refusal is charged to the
*victim's* source, not the attacker's: `PortalServer.java:133` calls
`consumeSourceBudget(csrfSource)`, which at 30 charges sets
`blockedUntil = now + MAX_SOURCE_BLOCK_SECONDS` — 8 hours
(`ThrottleManager.java:259-271`, `:56`). A user (or an office NAT address, see SEC-02) that
retries a form 30 times during the flood is then refused for 8 hours even after the flood
stops. The same flood also makes `issueCsrfToken` O(n) per request, because
`pruneCsrfLocked` (`SessionManager.java:207-213`) walks the whole 50,000-entry map inside the
monitor on every page view, serialising all session and CSRF work behind it.

**Fix:** Do not keep per-visitor CSRF state in a shared global map, and never charge a
CSRF failure (which the server itself can cause by evicting or expiring a token) to the
client's lockout budget. Make the login token self-authenticating: an HMAC over a random nonce
and an expiry, keyed by a process secret, verified in constant time. Nothing then has to be
stored, so there is nothing to evict and no cross-user interference; replay is bounded by the
expiry, and the double-submit cookie plus `SameSite=Strict` still supplies the cross-site
protection. Independently, meter `GET /login` per source so the page itself cannot be used as
an amplifier.

```java
// SessionManager.java -- stateless, per-request CSRF token; no shared store to exhaust.
private static final byte[] CSRF_KEY = Crypto.randomBytes(32); // process-lifetime secret

/** Mint "<expiryEpochSecond>.<nonce>.<hmac>" -- nothing is stored server-side. */
public String mintCsrfToken() {
    long expiry = AuditClock.epochSecond() + CSRF_TIMEOUT.getSeconds();
    String nonce = Crypto.randomUrlToken(InputPolicy.CSRF_TOKEN_BYTES);
    String payload = expiry + "." + nonce;
    return payload + "." + Crypto.base64Url(Crypto.hmacSha256(CSRF_KEY, payload));
}

/** Verify shape, signature and expiry. No server-side entry, so no eviction and no replay window beyond the expiry. */
public boolean verifyCsrfToken(String cookieValue, String hiddenValue) {
    if (cookieValue == null || hiddenValue == null
            || !Crypto.equalConstantTime(cookieValue, hiddenValue)) {
        return false;
    }
    int lastDot = hiddenValue.lastIndexOf('.');
    if (lastDot <= 0 || hiddenValue.length() > 256) {
        return false;
    }
    String payload = hiddenValue.substring(0, lastDot);
    String mac = hiddenValue.substring(lastDot + 1);
    if (!Crypto.equalConstantTime(mac, Crypto.base64Url(Crypto.hmacSha256(CSRF_KEY, payload)))) {
        return false;
    }
    int sep = payload.indexOf('.');
    try {
        return sep > 0 && Long.parseLong(payload.substring(0, sep)) > AuditClock.epochSecond();
    } catch (NumberFormatException malformed) {
        return false;
    }
}
```

```java
// PortalServer.java -- a failure we may have caused ourselves must not spend the client's budget,
// and the login page itself must be metered.
    private void route(HttpExchangeView ex) throws IOException {
        // ... method/path checks unchanged ...
        if (method.equals("GET")) {
            if (path.equals(LOGIN_PATH)) {
                // Meter the page: one source cannot mint unbounded tokens for free.
                if (runtime.throttle().beginAttempt(PAGE_SUBJECT, sourceHexOf(ex))
                        == ThrottleManager.Kind.THROTTLED) {
                    ex.respond(429, HttpExchangeView.EMPTY, securityHeaders());
                    return;
                }
                showLoginPage(ex);
            } else {
                ex.respond(404, HttpExchangeView.EMPTY, securityHeaders());
            }
            return;
        }
        // ...
        if (!csrfAcceptable(ex, fields)) {
            // No consumeSourceBudget here: an expired or server-evicted token is not client abuse,
            // and charging it lets a third party lock this address out.
            audit.event("csrf", "-", sourceHexOf(ex), "denied", "token-mismatch");
            denied(ex);
            return;
        }
```

### SEC-02: Per-source budget is consumed by successful logins and never cleared by success, so one shared egress address locks out every user behind it

- **Severity:** Medium
- **CWE:** CWE-645: Overly Restrictive Account Lockout Mechanism
- **Location:** `src/main/java/com/portal/auth/ThrottleManager.java:163-185` and `:244-256` (ceiling at `:56`)

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/ThrottleManager.java:172-179
            Kind verdict;
            if (blocked) {
                verdict = Kind.THROTTLED;
            } else {
                a.failures++;
                s.failures++;
                verdict = Kind.ALLOWED;
            }
```

```java
// src/main/java/com/portal/auth/ThrottleManager.java:244-252
    public void recordSuccess(String accountRef, String sourceHex) {
        synchronized (monitor) {
            State a = live(accounts, requireRef(accountRef));
            a.failures = 0;
            a.blockedUntil = 0;
            a.strikes = 0;
            a.windowStart = AuditClock.epochSecond();
            a.generation++;
            counters.merge(Kind.ALLOWED, 1L, Long::sum);
```

**Why it is a problem:** `beginAttempt` increments the *source* counter for every reserved
attempt, whether or not it later fails, and `recordSuccess` clears only the account state —
`s.failures` is never decremented or reset on success (no `sources` entry is touched in
`recordSuccess`). The source counter is therefore a budget on **all authentication traffic**
from an address, not on failures: once 30 attempts occur inside one 300-second window
(`WINDOW_SECONDS`, `ThrottleManager.java:41`), `beginAttempt` returns `THROTTLED` for everyone
sharing that address until the window rolls (`live`, `ThrottleManager.java:422-426`).

That address is frequently not one user. The shipped default is
`portal.trusted.proxy.cidrs =` empty (`config/portal.properties.example:57`), so
`SourceRef.resolvePeer` returns the socket peer and every employee behind one corporate NAT or
one reverse proxy shares a single bucket. Thirty normal, *successful* sign-ins in five minutes
then deny the thirty-first. The same shared bucket makes the 8-hour `MAX_SOURCE_BLOCK_SECONDS`
ceiling (`ThrottleManager.java:56`) a weapon rather than a defence: the class comment asserts
"the blocked party here is the attacker's own address, so a long ceiling is not a lockout
weapon", which does not hold under NAT — one misbehaving or malicious client inside the office
(or the SEC-01 flood) can arm an 8-hour block for all of their colleagues. This directly
contradicts the stated requirement that a limit must not be usable to lock legitimate users
out.

**Fix:** Count only *failures* against the source budget, clear a source's counter on a
successful authentication from that source, and keep the long block for failure-only
escalation. Where a proxy is in use, configure `portal.trusted.proxy.cidrs` so the bucket is
the real client; where it is not, treat a shared address as a reason for a larger failure
budget with a shorter ceiling, not an 8-hour block.

```java
// ThrottleManager.java -- reserve the slot without spending the source's *failure* budget.
    public Kind beginAttempt(String accountRef, String sourceHex) {
        synchronized (monitor) {
            String acct = requireRef(accountRef);
            long now = AuditClock.epochSecond();
            State a = live(accounts, acct);
            State s = live(sources, sourceHex);
            boolean blocked = a.blockedUntil > now || s.blockedUntil > now
                    || a.failures >= ACCOUNT_MAX_FAILURES
                    || s.failures >= SOURCE_MAX_FAILURES;
            Kind verdict;
            if (blocked) {
                verdict = Kind.THROTTLED;
            } else {
                // Reserve against the account (check-then-act must stay atomic), but leave the
                // source counter to recordFailure: a successful login is not source abuse, and
                // a shared NAT address must not run out of budget by being used correctly.
                a.failures++;
                a.inFlight++;
                verdict = Kind.ALLOWED;
            }
            counters.merge(verdict, 1L, Long::sum);
            lastDecisionNanos = System.nanoTime();
            persistLocked();
            return verdict;
        }
    }

    public void recordFailure(String accountRef, String sourceHex) {
        synchronized (monitor) {
            String acct = requireRef(accountRef);
            long now = AuditClock.epochSecond();
            State a = live(accounts, acct);
            State s = live(sources, sourceHex);
            s.failures++;   // charged here, where the attempt is known to have failed
            // ... existing account back-off and source back-off logic unchanged ...
            persistLocked();
            lastDecisionNanos = System.nanoTime();
        }
    }

    public void recordSuccess(String accountRef, String sourceHex) {
        synchronized (monitor) {
            State a = live(accounts, requireRef(accountRef));
            a.failures = 0;
            a.blockedUntil = 0;
            a.strikes = 0;
            a.windowStart = AuditClock.epochSecond();
            a.generation++;
            // A proven-good credential from this address clears its failure window too, so
            // honest traffic from a shared egress address can never accumulate into a block.
            State s = live(sources, sourceHex);
            s.failures = 0;
            s.windowStart = a.windowStart;
            s.generation++;
            counters.merge(Kind.ALLOWED, 1L, Long::sum);
            persistLocked();
            lastDecisionNanos = System.nanoTime();
        }
    }
```

### SEC-03: PBKDF2-HMAC-SHA256 iteration count (default 150,000, floor 100,000) is below current guidance

- **Severity:** Medium
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/main/java/com/portal/auth/PasswordHasher.java:39-41` (floor re-asserted at `:212`, `:241-245`, `:282`)

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/PasswordHasher.java:38-41
    /** Records below this are refused outright; they are never honoured. */
    public static final int MIN_ITERATIONS = 100_000;
    public static final int MAX_ITERATIONS = 2_000_000;
    public static final int DEFAULT_ITERATIONS = 150_000;
```

**Why it is a problem:** The construction is otherwise correct — per-record 16-byte
`SecureRandom` salt, 32-byte derived key, constant-time comparison, per-record cost stored so
records can be upgraded. The cost itself is the weak part: current OWASP password-storage
guidance for PBKDF2-HMAC-SHA256 is 600,000 iterations, and the library's own crypto-audit rule
set carries that threshold
(`performing-cryptographic-audit-of-application/scripts/process.py:173`). At 150,000, an
attacker who obtains `employees.dat` — via a backup, a snapshot, a misconfigured restore, or
any file-read bug — can test guesses roughly four times faster than the current baseline, and
the 100,000 floor means a deployment that *lowers* the knob is still accepted. The code's own
justification (the JDK ships no memory-hard KDF) argues for a higher iteration count, not a
lower one, and the design already supports raising it without a format break via
`needsRehash`/`rotateSecret`.

**Fix:** Raise the floor and the default to at least the current guidance, and keep the
existing login-time rehash so deployed records upgrade on next use. The per-login cost is one
derivation, so the latency budget documented in `config/portal.properties.example:23-29`
should be re-measured for the new value; where ~0.9 s per login is unacceptable, the
alternative is a memory-hard KDF (Argon2id/scrypt) rather than a reduced iteration count.

```java
    /** Records below this are refused outright; they are never honoured. */
    // OWASP password-storage guidance for PBKDF2-HMAC-SHA256: 600,000 iterations.
    public static final int MIN_ITERATIONS = 600_000;
    public static final int MAX_ITERATIONS = 10_000_000;
    public static final int DEFAULT_ITERATIONS = 600_000;
```

### SEC-04: Stored password records' algorithm labels are never validated, so a record claiming any algorithm is verified as PBKDF2-HMAC-SHA256

- **Severity:** Low
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `src/main/java/com/portal/auth/PasswordHasher.java:268-297` (consumers at `:101-115`, `:203-222`)

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/PasswordHasher.java:268-297
    private static ParsedRecord parseLenient(String record) {
        if (record == null || record.length() > 256) {
            return null;
        }
        String[] parts = record.split("\\$", -1);
        if (parts.length != 5) {
            return null;
        }
        int iterations;
        try {
            iterations = Integer.parseInt(parts[2]);
        } catch (NumberFormatException notInt) {
            return null;
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            return null;
        }
        byte[] salt;
        byte[] key;
        try {
            salt = Crypto.base64Strict(parts[3]);
            key = Crypto.base64Strict(parts[4]);
        } catch (IllegalArgumentException badEncoding) {
            return null;
        }
        if (salt.length != SALT_BYTES || key.length != KEY_BYTES) {
            return null;
        }
        return new ParsedRecord(parts[0], parts[1], iterations, salt, key);
    }
```

**Why it is a problem:** `parts[0]` (`alg`) and `parts[1]` (`hashAlg`) are carried into
`ParsedRecord` but never compared against `ALG`/`HASH_ALG` in any gate.
`requireValidRecord` (`:203-222`) — the strict loader that `EmployeeStore` and
`refreshIfChanged` rely on and whose documentation promises the roster is "validated field by
field" (`EmployeeStore.java:32`) — checks only iterations and field lengths, and `verify`
(`:101-115`) derives with `PBKDF2WithHmacSHA256` regardless of what the record claims. So a
record such as `scrypt$sha1$150000$<salt>$<key>` loads cleanly and is verified under the wrong
advertised algorithm. Today the impact is limited to a label mismatch (the real primitive is
always PBKDF2-HMAC-SHA256, and the account simply cannot authenticate until
`needsRehash`/`rotateSecret` rewrites it), so this is not currently an authentication bypass.
It is the standard precondition for algorithm confusion: the moment a second algorithm is
supported, the field that selects it is already unvalidated, and the version marker that is
supposed to make such an upgrade safe is the one field nobody checks.

**Fix:** Reject unknown algorithm labels inside the parser, so no caller can inherit an
unchecked record.

```java
        String[] parts = record.split("\\$", -1);
        if (parts.length != 5) {
            return null;
        }
        // The algorithm labels select the primitive; an unrecognised one is a refusal, never a
        // record that is silently verified as something else.
        if (!ALG.equals(parts[0]) || !HASH_ALG.equals(parts[1])) {
            return null;
        }
```

### SEC-05: Every attempt rewrites the whole throttle ledger, and a full subject map turns authentication into a 500

- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/portal/auth/ThrottleManager.java:439-461` and `:394-406`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/ThrottleManager.java:439-455
    private void persistLocked() {
        if (ledger == null) {
            return;
        }
        Map<String, Ledger.Counter> snapshot = new HashMap<>();
        for (Map.Entry<String, State> e : accounts.entrySet()) {
            snapshot.put(Ledger.key('a', e.getKey()),
                    new Ledger.Counter(e.getValue().windowStart, e.getValue().failures,
                            e.getValue().blockedUntil, e.getValue().generation));
        }
        for (Map.Entry<String, State> e : sources.entrySet()) {
            snapshot.put(Ledger.key('s', e.getKey()),
                    new Ledger.Counter(e.getValue().windowStart, e.getValue().failures,
                            e.getValue().blockedUntil, e.getValue().generation));
        }
        try {
            ledger.persist(snapshot);
```

```java
// src/main/java/com/portal/auth/ThrottleManager.java:397-403
        if (s == null) {
            if (map.size() >= MAX_SUBJECTS) {
                sweep(map);
                if (map.size() >= MAX_SUBJECTS) {
                    throw new IllegalStateException("throttle-subject-capacity");
                }
            }
```

**Why it is a problem:** Two compounding issues on one attacker-reachable path.
(a) `persistLocked` is called inside the monitor on *every* `beginAttempt`, `recordFailure`,
`recordSuccess` and `consumeSourceBudget`, and it serialises the **entire** subject map; each
call makes `Ledger.persist` re-read the file, merge it, write a temp file, `fsync` it and
`ATOMIC_MOVE` it (`Ledger.java:123-168`, `PrivateFiles.writePrivateAtomic`). With the map
anywhere near its 50,000-subject bound that is megabytes of synchronous I/O per request, all of
it under one lock — a cheap request amplifies into disproportionate disk work and global
serialisation. (b) When either map is full and `sweep` frees nothing (entries younger than the
24-hour retention, or still blocked), `live` throws. That exception escapes `beginAttempt`
through `Authenticator.decide` (which does not catch it) and surfaces as a generic 500 in
`PortalServer.handle` (`PortalServer.java:84-93`), so authentication stops working for every
*new* subject — presented username or source address — until entries age out. Each distinct
presented username creates an `accounts` entry, so filling the map does not require any valid
account.

**Fix:** Persist incrementally (only the subjects that changed) or on a bounded time/write
interval outside the monitor, and make capacity pressure evict the least-relevant unblocked
subject instead of failing the request. Keep the fail-closed direction for the subject that
actually tripped a block.

```java
    private State live(Map<String, State> map, String subject) {
        State s = map.get(subject);
        long now = AuditClock.epochSecond();
        if (s == null) {
            if (map.size() >= MAX_SUBJECTS) {
                sweep(map);
                // Still full: evict the oldest entry that is neither blocked nor counting
                // failures, rather than failing authentication for every new subject.
                if (map.size() >= MAX_SUBJECTS && !evictOneIdle(map, now)) {
                    // Nothing idle to drop: refuse this *subject* conservatively instead of
                    // throwing an exception that the HTTP layer can only turn into a 500.
                    State blockedFallback = new State();
                    blockedFallback.blockedUntil = now + BASE_BLOCK_SECONDS;
                    return blockedFallback;
                }
            }
            s = new State();
            map.put(subject, s);
        }
        // ... roll-over logic unchanged ...
        return s;
    }

    private boolean evictOneIdle(Map<String, State> map, long now) {
        String victim = null;
        long oldest = Long.MAX_VALUE;
        for (Map.Entry<String, State> e : map.entrySet()) {
            State v = e.getValue();
            if (v.blockedUntil <= now && v.failures == 0 && v.windowStart < oldest) {
                oldest = v.windowStart;
                victim = e.getKey();
            }
        }
        if (victim == null) {
            return false;
        }
        map.remove(victim);
        return true;
    }
```

### SEC-06: Public test hooks in the production artifact can rewind the clock and clear lockout state

- **Severity:** Low
- **CWE:** CWE-489: Active Debug Code
- **Location:** `src/main/java/com/portal/auth/AuditClock.java:31-34`, `src/main/java/com/portal/auth/ThrottleManager.java:387-392`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/AuditClock.java:31-34
    /** Test hook. Passing {@code null} restores the system clock. */
    public static void useForTesting(Clock replacement) {
        clock = replacement == null ? Clock.systemUTC() : replacement;
    }
```

```java
// src/main/java/com/portal/auth/ThrottleManager.java:387-392
    public void clearAccountForTesting(String accountSubjectHex) {
        synchronized (monitor) {
            accounts.remove(accountSubjectHex);
            persistLocked();
        }
    }
```

**Why it is a problem:** `AuditClock` is the single time source for every lockout window,
back-off expiry, session idle/absolute timeout and CSRF expiry. A `public static` setter means
any code that ends up in this JVM can set a fixed or back-dated clock, which simultaneously
expires nothing and makes every `blockedUntil > now` comparison false — i.e. it disables the
lockout and lets sessions live forever. `clearAccountForTesting` is likewise `public` and
deletes an account's lockout state outright, persisting the cleared counters to the ledger.
Neither is reachable from an HTTP request today, so this is not a remote vulnerability; it is
ambient authority that the rest of this codebase deliberately avoids (compare
`ThrottleManager.setTimingControlsForTesting`, which is package-private for exactly this
reason), and it is the kind of hook that becomes reachable the moment the class is embedded in
a larger application, a plugin host, or an admin endpoint.

**Fix:** Reduce both to package-private so only the in-package test suites can reach them, and
gate the clock replacement on an explicit test flag so a production process cannot be
re-clocked at all.

```java
// AuditClock.java
    private static final boolean TEST_HOOKS =
            Boolean.getBoolean("portal.test.hooks"); // absent in production

    /** Test hook. Passing {@code null} restores the system clock. */
    static void useForTesting(Clock replacement) {
        if (!TEST_HOOKS) {
            throw new IllegalStateException("clock-replacement-not-permitted");
        }
        clock = replacement == null ? Clock.systemUTC() : replacement;
    }
```

```java
// ThrottleManager.java -- package-private, like setTimingControlsForTesting above it.
    void clearAccountForTesting(String accountSubjectHex) {
        synchronized (monitor) {
            accounts.remove(accountSubjectHex);
            persistLocked();
        }
    }
```

### SEC-07: Unsynchronized read of the CSRF map outside the monitor that guards it

- **Severity:** Low
- **CWE:** CWE-567: Unsynchronized Access to Shared Data in a Multithreaded Context
- **Location:** `src/main/java/com/portal/auth/SessionManager.java:157`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/SessionManager.java:150-158
    public int issueCsrfToken(String cookieValue, String hiddenValue) {
        long now = AuditClock.epochSecond();
        synchronized (monitor) {
            pruneCsrfLocked(now);
            pendingCsrf.put(Crypto.sha256Hex(cookieValue + "\n" + hiddenValue),
                    now + CSRF_TIMEOUT.getSeconds());
        }
        return pendingCsrf.size();
    }
```

**Why it is a problem:** `pendingCsrf` is a plain `LinkedHashMap` whose every other access is
inside `synchronized (monitor)` (`:183`, `:208`, `:224`); this `size()` read sits outside it
while other listener threads are inserting, pruning and evicting. Every other accessor in this
class is correctly guarded (`pendingCsrfCount()` at `:222-225` is the same read, done right),
so this is an isolated slip rather than a design gap. The value is an operator-facing count and
the current caller (`PortalServer.showLoginPage:154`) discards it, so there is no security
decision behind it today — but it is an unguarded read of concurrently-mutated non-thread-safe
state in the class that holds all session and CSRF state, and the next caller to use the
returned number (for example, to decide whether to shed load) would be acting on a value read
under a data race.

**Fix:** Read the size inside the monitor, like every other accessor in the class.

```java
    public int issueCsrfToken(String cookieValue, String hiddenValue) {
        long now = AuditClock.epochSecond();
        synchronized (monitor) {
            pruneCsrfLocked(now);
            pendingCsrf.put(Crypto.sha256Hex(cookieValue + "\n" + hiddenValue),
                    now + CSRF_TIMEOUT.getSeconds());
            return pendingCsrf.size();
        }
    }
```

## 6. Verified Controls and Checks With No Finding

- **Password storage format**: PBKDF2-HMAC-SHA256 via `SecretKeyFactory`, 16-byte per-record
  `SecureRandom` salt, 32-byte key, cost stored per record, compared with
  `MessageDigest.isEqual` — `PasswordHasher.java:61-74`, `:101-115`, `:237-258`. No MD5/SHA-1,
  no unsalted hash, no reversible transform, no password in the roster. (Cost parameter: see
  SEC-03.)
- **Credential lifetime in memory**: `authenticate` wipes the password array in a `finally` at
  a single exit point (`Authenticator.java:126-134`), `PBEKeySpec.clearPassword()` is always
  called (`PasswordHasher.java:253-257`), the CLI wipes both confirmation arrays
  (`PortalCli.java:217-220`), and the keystore password is wiped after the `SSLContext` is
  built (`JdkHttpsListener.java:236-238`).
- **No hardcoded or recoverable secrets**: no credential, key or password literal exists in
  `src/main`; the keystore password is read from a `0600` file named by the environment
  (`PortalConfig.java:130-141`, `JdkHttpsListener.java:245-276`), never from argv
  (`PortalCli.java:16-20`), and `tools/gen-cert.sh:52-75` generates it from `/dev/urandom` and
  passes it via `-storepass:env`. Test-suite fixture passwords (e.g.
  `ConfigCliSuite.java:888`) are used only against per-test temporary data directories and
  grant nothing in a deployment.
- **Username enumeration and timing**: every outcome performs exactly one KDF derivation —
  decoy for malformed input, throttled and unknown-name paths
  (`Authenticator.java:152-190`), real verification otherwise — the decoy salt is
  domain-separated per identity (`PasswordHasher.java:129-150`), the throttled path
  deliberately does not read the roster, the roster `stat` happens first on every path
  (`Authenticator.java:144`), and all paths including success are padded to a shared latency
  floor (`ThrottleManager.padToFloor`, `Authenticator.java:235-236`, `:248-249`).
- **Identical failure responses**: one `denied()` helper produces byte-identical 401s with the
  same header set for bad credentials, unknown user, malformed input, throttling, CSRF failure
  and oversized body (`PortalServer.java:234-236`, `:253-265`); the internal reason is exposed
  only through `reasonForInternalUseOnly()` and the audit log
  (`Authenticator.java:87-89`). The CLI prints the same `GENERIC_DENIED` for every denial
  (`PortalCli.java:140`), and password-strength text appears only at enrolment
  (`InputPolicy.java:91-99`).
- **Session identifier generation and validation**: 256-bit `SecureRandom` token minted
  server-side only after a verified match (`SessionManager.java:89-96`), never accepted from
  the caller as proof; the cookie value is only a lookup key, validated for exact shape and
  canonical base64url (`InputPolicy.isSessionToken`, `Crypto.base64UrlStrictExpectedLen`) then
  hashed, with absence/expiry/wrong-shape all collapsing to anonymous
  (`SessionManager.java:103-127`). Only SHA-256(id) is stored, so a heap or map dump yields no
  usable id. Idle (20 min) and absolute (8 h) timeouts are enforced on read and by a janitor
  task; `logout` and `revokeAllFor` delete server-side state.
- **Cookie attributes**: both cookies carry `Path=/; HttpOnly; Secure; SameSite=Strict` with a
  bounded `Max-Age`, and both have explicit cleared variants
  (`PortalServer.java:274-294`). (Observations, not findings: the `__Host-` prefix is not used,
  and no `Permissions-Policy` header is sent.)
- **CSRF**: a pair is required on every state-changing request including `POST /logout`; both
  halves must be present, well-formed, equal in constant time, and match an issued pair, and a
  match is consumed so it cannot be replayed (`PortalServer.java:321-330`,
  `SessionManager.java:174-187`). Statically ran the `performing-csrf-attack-simulation` token
  tests: absent token, empty token (rejected by the form parser's zero-length rule
  `PortalServer.java:436`), random token, and replayed token are all refused; `SameSite=Strict`
  plus `HttpOnly` prevents a cross-site attacker from supplying the cookie half. (The
  exhaustion weakness behind these checks is SEC-01.)
- **Request parsing and injection surfaces**: method allowlist, pinned
  `application/x-www-form-urlencoded` media type, 8 KiB body cap read in bounded chunks, form
  key allowlist with duplicate-key rejection, percent-decoding that refuses any byte outside
  `0x21..0x7E` rather than substituting (`PortalServer.java:96-143`, `:397-501`,
  `JdkHttpsListener.java:139-158`). No SQL, no ORM, no shell execution, no deserialization, no
  XML/XXE, no template engine, no file path derived from user input anywhere in `src/main`.
- **Output encoding**: the only dynamic value rendered into HTML is the server-generated CSRF
  token, HTML-escaped (`PortalServer.java:168`, `:365-379`), under a CSP of
  `default-src 'none'; script-src 'none'; form-action 'self'; base-uri 'none';
  frame-ancestors 'none'`. Response header values are code-generated (base64url tokens and
  fixed strings), so no CRLF header-injection vector exists
  (`JdkHttpsListener.java:172-198`).
- **Source attribution / spoofing**: `X-Forwarded-For` is ignored unless the socket peer is
  inside a configured trusted IPv4 CIDR, and then only by a right-to-left walk that stops at
  the first non-proxy hop, with strict literal parsing, a hop cap, OWS-only trimming, and no
  DNS resolution anywhere (`SourceRef.java:354-416`, `JdkHttpsListener.java:161-169`).
  Unparseable addresses collapse into a still-throttled `unknown` bucket rather than escaping
  limiting (`SourceRef.java:47-73`).
- **Lockout atomicity**: the verdict and the counter mutation happen in one monitored
  read-modify-write (`ThrottleManager.beginAttempt`), so a concurrent burst cannot all observe
  the same headroom; the ledger merge is anti-downgrade with a generation field, under an
  exclusive cross-process `FileLock` (`Ledger.java:123-168`, `:230-248`), and a corrupt ledger
  resets counters to the strictest state while logging the anomaly
  (`ThrottleManager.java:105-116`, `PortalRuntime.java:47-53`).
- **Revocation actually takes effect**: `refreshIfChanged` re-reads the roster when its
  inode/size/mtime changes, so `disable-user` and `set-password` from a separate process are
  honoured by the running server, and an unparsable roster empties the map (refusing everyone)
  rather than being treated as empty-and-fine (`EmployeeStore.java:125-162`). `disable-user`
  also revokes live sessions (`PortalCli.java:240-241`).
- **Roster integrity**: refuse-only load — header version, line length, name policy, duplicate
  names, account count, record validity and KDF floor are all fatal
  (`EmployeeStore.java:171-217`, `PortalRuntime.java:43-45`); all mutations go through an
  exclusive lock plus a re-read of the on-disk state and an atomic rewrite, so concurrent
  writers cannot silently discard each other's accounts (`EmployeeStore.java:396-448`).
- **File permissions and symlink handling**: files `0600`, directories `0700`, modes re-read
  from the filesystem after creation, `NOFOLLOW_LINKS` on both the pre-check and the open,
  world-writable non-sticky ancestors refused, ownership proven by a uid-compared probe,
  group/other-readable config or keystore refused, bounded reads
  (`PrivateFiles.java:46-253`, `:329-348`). Runtime state and TLS material are git-ignored
  (`.gitignore:3-26`).
- **Logging hygiene**: the audit log records only 16-hex identity/source references (never
  names, passwords, session ids or tokens), restricts every field to a fixed alphabet, reduces
  exceptions to a class name, and a logging failure never changes an authentication decision
  (`AuditLog.java:44-155`). The in-memory ring is
  bounded. Observation, not a finding: the on-disk `audit.log` has no rotation or size cap, so
  operational log-growth limits should be applied outside the program.
- **Configuration trust boundary**: unknown config keys are fatal, every value has a strict
  grammar (unsigned decimal only, literal bind host only, absolute paths with no `..` segment
  checked on raw segments), no security-weakening default exists, and refusals name the key but
  never the value (`PortalConfig.java:113-303`). `Main`/`PortalCli` reduce every error message
  to a machine token before printing (`PortalCli.java:370-388`).
- **TLS**: HTTPS only with no HTTP fallback (startup refuses without a keystore), TLS 1.2/1.3
  only with TLS 1.0/1.1 excluded, JDK default suites, bounded thread pool, and
  `sun.net.httpserver` header/time limits set (`JdkHttpsListener.java:55-110`). HSTS is sent on
  every response (`PortalServer.java:263`). The self-signed-certificate caveat in
  `tools/gen-cert.sh:2-6` is documented as test-only.
- **Supply chain / platform preference**: no third-party runtime or test dependency; the single
  network fetch pins a JDK version and verifies Adoptium's SHA-256 over HTTPS before use
  (`tools/get-jdk.sh:11-33`); launchers strip `CLASSPATH` and use a fixed classpath with no `.`
  and no wildcard (`portal.sh:36-40`, `portal.cmd:24-25`); `tools/mutate.py` invokes
  `subprocess` with argument lists over paths it constructs itself. (Observation: the
  `${VERSION/%+/%2B}` substitution in `tools/get-jdk.sh:13` does not fire, so the URL is
  malformed — a functional bug in the fetch script, not a security weakness; the digest check
  still gates anything that is downloaded.)
- **CLI input handling**: secrets read as `char[]` via `Console.readPassword` (no echo) or a
  bounded, non-trimming stdin reader that treats CR/LF as framing but never deletes a CR from
  inside a value, returning an over-long array on overflow so the policy boundary produces the
  generic refusal (`PortalCli.java:260-357`). No subcommand accepts a password argument.
- **Checked and found acceptable by design, with the residual risk documented in-code**: the
  64-bit truncated `Crypto.idRef` used as audit and throttle-bucket key
  (`Crypto.java:213-237`); a ledger writer who already has write access being able to zero a
  counter (`Ledger.java:51-55`); a stolen session id remaining usable until expiry
  (`SessionManager.java:24-31` of the class note); `HEAD` responses omitting
  `Content-Length` (`PortalServer.java:45-49`); and an account back-off capped at 15 minutes
  so lockout cannot be weaponised against one user (`ThrottleManager.java:44-51`). One
  inconsistency worth noting without raising a finding: `ThrottleManager.consumeSourceBudget`
  documents itself as the charge for "a forged session id", but `PortalServer.logout`
  (`:215-223`) does not charge it — session-id probing is unmetered, which is not exploitable
  against a 256-bit token but does not match the stated intent.
