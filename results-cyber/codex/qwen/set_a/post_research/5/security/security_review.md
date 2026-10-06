# Security Review: Employee Portal Authentication

## 1. Executive Summary
The component is a Java 21 employee-authentication portal with CLI administration, an HTTPS login/logout front end, PBKDF2 password records, server-side sessions, one-time CSRF tokens, persistent account/source throttling, and private on-disk roster, ledger, and audit files. Supporting shell/Python tools build, test, mutate, download a pinned JDK, and generate a local TLS keystore.

Eight vulnerabilities were found. The most serious are an arbitrary recursive-delete target in the mutation tool and the HTTPS listener's unbounded work queue, which can respectively destroy files under the invoking account and permit remote memory exhaustion. Other findings allow persistent throttle-state exhaustion, unbounded audit-log disk consumption, acceptance of chunked requests despite a fixed-length-only design, plaintext-password retention in immutable strings, permission clobbering by the certificate helper, and fail-open loss of throttling after ledger corruption. Authentication, cryptographic primitives, credential comparisons, session entropy/expiry, CSRF single use, form-key duplication checks, TLS protocol selection, and private-file modes otherwise have substantial defensive controls.

## 2. Scope
| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `.gitignore` | Excludes build and local runtime artifacts | Reduces accidental inclusion of generated/private state. |
| `build.sh` | Compiles production Java sources | Resolves the compiler, clears the output tree, and fixes source encoding. |
| `portal.sh` | Unix launcher | Pins the classpath, clears inherited `CLASSPATH`, and forwards CLI arguments. |
| `portal.cmd` | Windows launcher | Pins the classpath and clears inherited `CLASSPATH`. |
| `test.sh` | Builds and launches test suites | Compiles source/test trees and launches each suite. |
| `tools/gen-cert.sh` | Generates a self-signed PKCS12 keystore | Creates a password and changes destination permissions; affected by SEC-06. |
| `tools/get-jdk.sh` | Downloads a pinned JDK | Enforces HTTPS and verifies a fixed SHA-256 digest before extraction. |
| `tools/mutate.py` | Runs security mutation tests | Deletes and recreates an environment-selected work tree; affected by SEC-01. |
| `config/portal.properties.example` | Documents deployable configuration | Defines KDF, bind, trusted-proxy, and HSTS settings. |
| `src/main/java/com/portal/auth/AuditClock.java` | Central clock abstraction | Supplies times for expiry and throttling; exposes package test hooks. |
| `src/main/java/com/portal/auth/AuditLog.java` | Writes sanitized security events | Redacts identifiers and bounds its memory ring, but not its disk file (SEC-04). |
| `src/main/java/com/portal/auth/Authenticator.java` | Makes login decisions | Validates credentials, equalizes KDF work, updates throttles, and issues sessions. |
| `src/main/java/com/portal/auth/CookieParser.java` | Parses selected cookie values | Applies header/value bounds and exact cookie-name matching. |
| `src/main/java/com/portal/auth/Crypto.java` | Wraps hashing, randomness, encoding, and comparisons | Uses `SecureRandom`, SHA-256, strict Base64, and constant-time comparison. |
| `src/main/java/com/portal/auth/EmployeeStore.java` | Maintains the password roster | Strictly parses records and uses locks plus atomic private-file replacement. |
| `src/main/java/com/portal/auth/HttpExchangeView.java` | Abstracts an HTTP exchange | Exposes request headers/body/peer and response operations to the router. |
| `src/main/java/com/portal/auth/InputPolicy.java` | Validates usernames, passwords, and tokens | Enforces length, character, and token-shape boundaries. |
| `src/main/java/com/portal/auth/JdkHttpsListener.java` | Configures TLS and adapts JDK HTTPS exchanges | Restricts TLS versions and request sizes, but uses an unbounded executor queue (SEC-02). |
| `src/main/java/com/portal/auth/Ledger.java` | Persists throttle counters | Strictly parses and atomically merges bounded counter records. |
| `src/main/java/com/portal/auth/Main.java` | Selects CLI or HTTPS mode | Fails startup closed and sanitizes error messages. |
| `src/main/java/com/portal/auth/PasswordHasher.java` | Creates and verifies password records | Uses PBKDF2-HMAC-SHA256 with bounded iterations and per-record salts. |
| `src/main/java/com/portal/auth/PortalCli.java` | Implements operator/employee commands | Uses bounded stdin, avoids secrets in argv, and wipes secret arrays. |
| `src/main/java/com/portal/auth/PortalConfig.java` | Loads and validates configuration | Restricts keys, numeric values, paths, file modes, hosts, and proxy CIDRs. |
| `src/main/java/com/portal/auth/PortalRuntime.java` | Wires checked runtime components | Opens roster, ledger, throttle, session, and audit services; affected by SEC-07. |
| `src/main/java/com/portal/auth/PortalServer.java` | Routes login/logout HTTP requests | Enforces form/CSRF/cookie policies, but not fixed-length request framing (SEC-05), and copies passwords into immutable strings (SEC-06). |
| `src/main/java/com/portal/auth/PrivateFiles.java` | Centralizes private file I/O | Checks POSIX modes, rejects symlinks, bounds reads, and uses atomic replacement. |
| `src/main/java/com/portal/auth/SessionManager.java` | Stores sessions and pending CSRF tokens | Generates high-entropy tokens, hashes session IDs, expires/revokes state, and caps maps. |
| `src/main/java/com/portal/auth/SourceRef.java` | Parses peer addresses and trusted proxies | Strictly parses/canonicalizes IP literals and derives throttle references. |
| `src/main/java/com/portal/auth/ThrottleManager.java` | Applies account/source rate limits | Persists bounded maps, but allocates account state for blocked sources (SEC-03) and resets on ledger failure (SEC-07). |
| `src/test/java/com/portal/auth/AuthFlowSuite.java` | Tests authentication, throttling, sessions, CSRF, and timing | Exercises concurrent and persistent security decisions. |
| `src/test/java/com/portal/auth/ConfigCliSuite.java` | Tests config and CLI subprocess behavior | Exercises path, mode, redaction, input, and concurrent-writer rules. |
| `src/test/java/com/portal/auth/CoreSecuritySuite.java` | Tests cryptography, storage, and source guards | Covers strict parsing, private files, audit redaction, and source-text invariants. |
| `src/test/java/com/portal/auth/HttpSuite.java` | Tests router responses and cookies | Covers denial uniformity, form parsing, CSRF, session lifecycle, and headers. |
| `src/test/java/com/portal/auth/SourceRefSuite.java` | Tests IP/CIDR/XFF parsing | Covers malformed literals, canonicalization, and trusted-proxy walking. |
| `src/test/java/com/portal/auth/TestKit.java` | Provides test fixtures and cleanup | Creates private temporary directories and recursively removes only recorded fixtures. |
| `out/main/**/*.class`, `out/test/**/*.class` | Compiled production/test artifacts | Derived copies of the reviewed Java sources; no independent source logic. |
| `README.md`, `docs/THREAT_MODEL.md` | Documents architecture and claimed controls | Used to compare stated security properties with implementation behavior. |

## 3. Skills Applied
- `review-code-for-security-vulnerabilities`: Dispatched the behavior-first review, specialized-skill selection, evidence collection, and CWE reporting workflow.
- `testing-api-authentication-weaknesses`: Applied to login decisions, enumeration resistance, session generation/expiry/revocation, cookie handling, and credential throttling.
- `performing-cryptographic-audit-of-application`: Applied to PBKDF2 parameters, salts, random tokens, comparisons, hashing, TLS versions, and secret handling.
- `performing-csrf-attack-simulation`: Applied statically to login/logout state changes, token presence, equality, entropy, expiry, replay, and SameSite cookies.
- `implementing-api-rate-limiting-and-throttling`: Applied to account/source budgets, concurrency, persistence, capacity, proxy attribution, and resource-exhaustion behavior.
- `performing-http-parameter-pollution-attack`: Applied to duplicate form keys, repeated headers, parser precedence, and request framing.
- `performing-ssl-tls-security-assessment`: Applied statically to HTTPS-only startup, TLS protocol selection, keystore handling, cookies, and HSTS.
- General OWASP Top 10 / CWE knowledge: Applied where no close library skill matched, especially destructive filesystem tooling, POSIX permission changes, bounded logging, symlink/path handling, shell argument handling, and exceptional-state behavior.

## 4. Summary of Findings
| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Environment-controlled mutation path is recursively deleted | High | CWE-73 | `tools/mutate.py:38` |
| SEC-02 | Fixed thread pool has an unbounded request queue | High | CWE-400 | `src/main/java/com/portal/auth/JdkHttpsListener.java:95` |
| SEC-03 | Blocked sources can exhaust persistent account throttle capacity | Medium | CWE-400 | `src/main/java/com/portal/auth/ThrottleManager.java:167-182` |
| SEC-04 | Audit log grows without a disk bound or rotation | Medium | CWE-400 | `src/main/java/com/portal/auth/AuditLog.java:66-80` |
| SEC-05 | POST routes accept chunked bodies despite fixed-length-only policy | Medium | CWE-444 | `src/main/java/com/portal/auth/PortalServer.java:116-120` |
| SEC-06 | HTTP form parsing retains the plaintext password in immutable strings | Medium | CWE-316 | `src/main/java/com/portal/auth/PortalServer.java:125` |
| SEC-07 | Certificate helper changes permissions on an arbitrary existing directory | Medium | CWE-732 | `tools/gen-cert.sh:43-47` |
| SEC-08 | Corrupt or unreadable throttle ledger resets enforcement state | Low | CWE-754 | `src/main/java/com/portal/auth/ThrottleManager.java:105-115` |

## 5. Detailed Findings

### SEC-01: Environment-controlled mutation path is recursively deleted
- **Severity:** High
- **CWE:** CWE-73: External Control of File Name or Path
- **Location:** `tools/mutate.py:38,414-415`

**Vulnerable code:**
```python
# tools/mutate.py:38
WORK = Path(os.environ.get("MUT_WORK", "/tmp/qmut"))

# tools/mutate.py:414-415
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
```

**Why it is a problem:** `MUT_WORK` completely controls the target of an unconditional recursive delete. Running the tool with a poisoned or mistaken environment such as `MUT_WORK=/`, `MUT_WORK=/etc`, or `MUT_WORK=.` can delete unrelated files with the privileges of the developer or CI account. The default is safe, but there is no validation that an override is a dedicated mutation directory.

**Fix:** Create a unique work directory beneath a fixed safe base, or canonicalize an override and require it to be a non-root child of that base before deleting it. Never recursively delete the override itself.
```python
from pathlib import Path
import os
import shutil
import tempfile

SAFE_WORK_ROOT = Path(os.environ.get("MUT_WORK_ROOT", "/tmp/qmut-runs")).resolve()
if SAFE_WORK_ROOT == Path(SAFE_WORK_ROOT.anchor):
    raise SystemExit("unsafe mutation work root")
SAFE_WORK_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
WORK = Path(tempfile.mkdtemp(prefix="run-", dir=SAFE_WORK_ROOT))

# Delete only the unique directory created by this process.
def clean_work() -> None:
    resolved = WORK.resolve()
    if resolved.parent != SAFE_WORK_ROOT:
        raise RuntimeError("unsafe mutation work path")
    shutil.rmtree(resolved)
```

### SEC-02: Fixed thread pool has an unbounded request queue
- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/portal/auth/JdkHttpsListener.java:92-96`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/JdkHttpsListener.java:92-96
        // Bounded pool: an unbounded cached pool turns a connection flood into an OOM. The
        // queue is what absorbs a burst; beyond it the server stops accepting, which is the
        // correct direction to fail.
        server.setExecutor(Executors.newFixedThreadPool(
                Math.max(4, Runtime.getRuntime().availableProcessors() * 2)));
```

**Why it is a problem:** `Executors.newFixedThreadPool` bounds the worker count but uses an unbounded `LinkedBlockingQueue`. An unauthenticated client can enqueue requests faster than the expensive PBKDF2-backed handlers complete, causing queued exchanges and their request state to consume memory until the JVM becomes unavailable. The comment claims the opposite behavior.

**Fix:** Use an explicitly bounded queue and a saturation policy that applies backpressure or rejects excess work. Retain the executor and shut it down with the listener.
```java
int workers = Math.max(4, Runtime.getRuntime().availableProcessors() * 2);
java.util.concurrent.ThreadPoolExecutor requests =
        new java.util.concurrent.ThreadPoolExecutor(
                workers,
                workers,
                0L,
                TimeUnit.MILLISECONDS,
                new java.util.concurrent.ArrayBlockingQueue<>(128),
                new java.util.concurrent.ThreadPoolExecutor.CallerRunsPolicy());
server.setExecutor(requests);
```

### SEC-03: Blocked sources can exhaust persistent account throttle capacity
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/portal/auth/ThrottleManager.java:163-183`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/ThrottleManager.java:163-183
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
                a.failures++;
                s.failures++;
                verdict = Kind.ALLOWED;
            }
            counters.merge(verdict, 1L, Long::sum);
            lastDecisionNanos = System.nanoTime();
            persistLocked();
            return verdict;
        }
    }
```

**Why it is a problem:** The account entry is created before checking whether the source is already blocked. A single throttled source can keep submitting different syntactically valid usernames, creating a new zero-failure account entry and rewriting the full ledger for every request. At 50,000 retained subjects, `live()` throws `throttle-subject-capacity`; new account references then receive HTTP 500 responses until entries age out. The repeated whole-map persistence also creates increasing CPU and disk I/O before the cap is reached.

**Fix:** Validate both references, inspect an existing source first, and return immediately when that source is blocked without creating account state. Create the account bucket only when the request can consume an account slot.
```java
public Kind beginAttempt(String accountRef, String sourceHex) {
    synchronized (monitor) {
        String acct = requireRef(accountRef);
        String src = requireRef(sourceHex);
        long now = AuditClock.epochSecond();
        State s = live(sources, src);

        if (s.blockedUntil > now || s.failures >= SOURCE_MAX_FAILURES) {
            counters.merge(Kind.THROTTLED, 1L, Long::sum);
            lastDecisionNanos = System.nanoTime();
            return Kind.THROTTLED; // no account allocation or ledger rewrite
        }

        State a = live(accounts, acct);
        Kind verdict;
        if (a.blockedUntil > now || a.failures >= ACCOUNT_MAX_FAILURES) {
            verdict = Kind.THROTTLED;
        } else {
            a.failures++;
            s.failures++;
            verdict = Kind.ALLOWED;
        }
        counters.merge(verdict, 1L, Long::sum);
        lastDecisionNanos = System.nanoTime();
        persistLocked();
        return verdict;
    }
}
```

### SEC-04: Audit log grows without a disk bound or rotation
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `src/main/java/com/portal/auth/AuditLog.java:66-80`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/AuditLog.java:66-80
    private void append(String line) {
        recent.addLast(line);
        while (recent.size() > MAX_KEPT) {
            recent.removeFirst();
        }
        if (!enabled) {
            return;
        }
        try {
            PrivateFiles.appendPrivateLine(file, line);
            written++;
        } catch (RuntimeException cannotWrite) {
            // Never let logging availability change an authentication decision, and never
            // let the log's own error text (which may name a path) reach the caller.
            failedWrites++;
        }
    }
```

**Why it is a problem:** `MAX_KEPT` limits only the in-memory deque. Every authentication or CSRF denial is appended to `audit.log`, including requests from already-throttled sources, and there is no disk-size limit, rotation, retention, or aggregation. An unauthenticated client can therefore grow the log until the data filesystem fills, disrupting roster/ledger writes and potentially other services on the volume. The threat model incorrectly describes the disk log as having 200,000-line retention.

**Fix:** Implement a cross-process-safe bounded append/rotation operation, place logs on a quota-controlled volume, and aggregate repeated throttled events. The size check and append must be performed under the same lock.
```java
private static final long MAX_AUDIT_BYTES = 100L * 1024 * 1024;

private void append(String line) {
    recent.addLast(line);
    while (recent.size() > MAX_KEPT) {
        recent.removeFirst();
    }
    if (!enabled) {
        return;
    }
    try {
        // This helper must lock, rotate with owner-only permissions, and append atomically.
        PrivateFiles.appendPrivateLineBounded(file, line, MAX_AUDIT_BYTES, 5);
        written++;
    } catch (RuntimeException cannotWrite) {
        failedWrites++;
    }
}
```

### SEC-05: POST routes accept chunked bodies despite fixed-length-only policy
- **Severity:** Medium
- **CWE:** CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')
- **Location:** `src/main/java/com/portal/auth/PortalServer.java:112-120`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/PortalServer.java:112-120
        if (!path.equals(LOGIN_PATH) && !path.equals(LOGOUT_PATH)) {
            ex.respond(404, HttpExchangeView.EMPTY, securityHeaders());
            return;
        }
        if (!hasFormContentType(ex)) {
            ex.respond(415, HttpExchangeView.EMPTY, securityHeaders());
            return;
        }
        byte[] body = readBody(ex);
```

**Why it is a problem:** The class documentation and threat model say `Content-Length` is required and chunked bodies are refused, but the router checks neither `Transfer-Encoding` nor `Content-Length`. The listener simply reads the decoded body stream, so chunked requests reach authentication logic. When the portal is behind a reverse proxy, accepting framing that the application claims to reject increases exposure to front-end/back-end request-framing discrepancies and request smuggling. Even without a proxy, it expands the accepted request surface beyond the reviewed policy.

**Fix:** Before reading any POST body, reject every `Transfer-Encoding` value, require exactly one canonical decimal `Content-Length`, and enforce the body cap against that declared length as well as while reading.
```java
        if (!path.equals(LOGIN_PATH) && !path.equals(LOGOUT_PATH)) {
            ex.respond(404, HttpExchangeView.EMPTY, securityHeaders());
            return;
        }
        if (!hasFixedLengthBody(ex) || !hasFormContentType(ex)) {
            ex.respond(415, HttpExchangeView.EMPTY, securityHeaders());
            return;
        }
        byte[] body = readBody(ex);

private boolean hasFixedLengthBody(HttpExchangeView ex) {
    if (!ex.headers("Transfer-Encoding").isEmpty()) {
        return false;
    }
    List<String> lengths = ex.headers("Content-Length");
    if (lengths.size() != 1 || !lengths.get(0).matches("[1-9][0-9]{0,3}")) {
        return false;
    }
    try {
        return Long.parseLong(lengths.get(0)) <= MAX_BODY_BYTES;
    } catch (NumberFormatException invalid) {
        return false;
    }
}
```

### SEC-06: HTTP form parsing retains the plaintext password in immutable strings
- **Severity:** Medium
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/main/java/com/portal/auth/PortalServer.java:125,418-439`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/PortalServer.java:125
        FormFields fields = FormFields.parse(new String(body, StandardCharsets.UTF_8));

// src/main/java/com/portal/auth/PortalServer.java:418-439
        static FormFields parse(String body) {
            if (body.isEmpty() || body.length() > MAX_BODY_BYTES) {
                return null;
            }
            FormFields out = new FormFields();
            for (String pair : body.split("&")) {
                if (pair.isEmpty()) {
                    return null;
                }
                int eq = pair.indexOf('=');
                if (eq <= 0 || eq == pair.length() - 1) {
                    return null;
                }
                String key = percentDecode(pair.substring(0, eq), true);
                if (key == null || !ALLOWED.contains(key) || out.values.containsKey(key)) {
                    return null;
                }
                byte[] value = percentDecodeBytes(pair.substring(eq + 1));
                if (value == null || value.length == 0 || value.length > MAX_FIELD) {
                    return null;
                }
                out.values.put(key, value);
            }
```

**Why it is a problem:** The complete URL-encoded body is converted to an immutable `String`, and `split`/`substring` create further string objects containing the plaintext password. Wiping the original byte array does not clear those strings, which remain in heap until garbage collection and can appear in heap dumps or post-compromise memory inspection. This contradicts the component's stated invariant that passwords remain in wipeable arrays and are never copied into `String`.

**Fix:** Parse delimiters and percent escapes directly from the mutable request byte array, store each decoded field only in a `byte[]`, and wipe both the input and all password-bearing temporary arrays in `finally` blocks. Keys can be converted to strings only after they are proven to be one of the non-secret ASCII key literals.
```java
byte[] body = readBody(ex);
if (body == null) {
    denied(ex);
    return;
}
FormFields fields;
try {
    fields = FormFields.parse(body); // byte-oriented parser; never constructs a body String
} finally {
    Crypto.wipe(body);
}

static FormFields parse(byte[] body) {
    // Scan '&' and '=' as bytes, percent-decode each slice into a byte[],
    // and convert only validated field names (never values) to String.
    return parseAsciiFormBytes(body);
}
```

### SEC-07: Certificate helper changes permissions on an arbitrary existing directory
- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `tools/gen-cert.sh:21-22,43-47`

**Vulnerable code:**
```bash
# tools/gen-cert.sh:21-22
DIR="${1:-/etc/portal/tls}"
CN="${2:-portal.internal}"

# tools/gen-cert.sh:43-47
# 0700 on the directory and 0600 on both files from the first byte: umask before create,
# because a keystore that exists world-readable for one instant can be copied in that instant.
umask 077
mkdir -p "$DIR"
chmod 700 "$DIR"
```

**Why it is a problem:** The caller can name any directory, and the script unconditionally changes that directory to mode `0700` even when it already exists. A privileged invocation with an accidental target such as `/etc` or a shared application directory can remove access required by the system or other services. The script also does not reject a symlinked destination before `mkdir`/`chmod` follows it.

**Fix:** Refuse root, symlinks, and pre-existing directories unless they already have the required ownership and mode; create only a dedicated absent directory. Do not repair an arbitrary existing directory in place.
```bash
DIR="${1:-/etc/portal/tls}"
if [ "$DIR" = / ] || [ -L "$DIR" ]; then
  echo "REFUSED: unsafe TLS directory" >&2
  exit 1
fi
if [ -e "$DIR" ]; then
  if [ ! -d "$DIR" ] || [ "$(stat -c '%a' "$DIR")" != 700 ]; then
    echo "REFUSED: existing TLS directory must already be a private directory" >&2
    exit 1
  fi
else
  ( umask 077; mkdir -- "$DIR" )
fi
```

### SEC-08: Corrupt or unreadable throttle ledger resets enforcement state
- **Severity:** Low
- **CWE:** CWE-754: Improper Check for Unusual or Exceptional Conditions
- **Location:** `src/main/java/com/portal/auth/ThrottleManager.java:105-115`

**Vulnerable code:**
```java
// src/main/java/com/portal/auth/ThrottleManager.java:105-115
        if (ledger != null) {
            try {
                loadFromLedger();
            } catch (RuntimeException ledgerUntrustworthy) {
                // A corrupt or unreadable ledger is never a reason to allow more
                // attempts: counters are reset to zero, which is the strictest state,
                // and the anomaly is reported by the caller through the audit log.
                accounts.clear();
                sources.clear();
                ledgerLosses++;
            }
        }
```

**Why it is a problem:** Zero counters are the least restrictive state, not the strictest. If the ledger becomes truncated, corrupt, unreadable, or oversized and the service restarts, all active account and source blocks are silently discarded and every subject receives a fresh attempt budget. The runtime logs the condition but continues serving authentication, contradicting its fail-closed startup contract. Exploitation generally requires a separate way to damage state or induce storage failure, so severity is Low.

**Fix:** Treat an untrustworthy persistent security state as a startup failure. If availability requirements prohibit that, enter an explicit globally blocked recovery mode until trusted state is restored; do not represent the loss as empty counters.
```java
        if (ledger != null) {
            try {
                loadFromLedger();
            } catch (RuntimeException ledgerUntrustworthy) {
                accounts.clear();
                sources.clear();
                throw new IllegalStateException("throttle-ledger-untrustworthy",
                        ledgerUntrustworthy);
            }
        }
```

## 6. Verified Controls and Checks With No Finding
- Authentication decision uniformity: unknown users, disabled users, malformed input, wrong passwords, and throttled attempts return the same client-visible denial through `Authenticator` and `PortalServer`; internal reasons are not rendered.
- Password storage: `PasswordHasher` uses PBKDF2-HMAC-SHA256, 16-byte random salts, 32-byte keys, 100,000-2,000,000 bounded iterations, strict canonical record parsing, and constant-time derived-key comparison.
- Password handling: CLI input uses `char[]`, authentication wipes password/scratch arrays on decision exits, and no password is accepted through argv; the HTTP `String` copy exception is reported as SEC-06.
- Token generation and validation: session IDs use 256 bits and CSRF tokens 192 bits from `SecureRandom`; wire encodings are canonical Base64URL with exact decoded lengths.
- Session lifecycle: server-side session records enforce 20-minute idle and 8-hour absolute expiry, support logout and per-user revocation, store only SHA-256 of session IDs, and cap live state.
- Cookie controls: session and CSRF cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/`; logout expires both relevant cookies.
- CSRF: both cookie and form token are required, strictly shaped, compared in constant time, checked against server-side issued state, expired after 15 minutes, and consumed on successful matching use.
- Form parsing: only `username`, `password`, and `csrf` keys are accepted; duplicate/unknown keys, empty values, malformed escapes, control bytes, non-ASCII bytes, and oversized fields are refused.
- Output encoding and browser headers: the only dynamic HTML value is escaped; responses include CSP, frame denial, no-sniff, no-referrer, no-store, HSTS, and `Vary: Cookie`.
- TLS: there is no plaintext listener or fallback; only TLS 1.2/1.3 are enabled, and the keystore/password file must be private regular non-symlink paths.
- Source attribution: raw peers are numeric literals, X-Forwarded-For is ignored unless the socket peer matches configured trusted IPv4 CIDRs, chains are walked right-to-left, and malformed inputs fall into a throttled unknown bucket.
- File confidentiality and integrity: roster, ledger, audit, and lock files are owner-private; the data directory is owner-only; symlinks are refused; bounded reads and atomic temp-file replacement are used.
- Roster mutation: same-process monitors plus cross-process `FileLock` and re-read-under-lock prevent ordinary lost updates; authentication refreshes changed roster state and fails closed if refreshed data is invalid.
- Audit content: field alphabets and hashed references prevent passwords, usernames, session IDs, raw addresses, exception messages, and line breaks from entering events.
- Command and SQL injection: no database is used, no OS command is constructed from HTTP/credential input, Java subprocess tests use argument arrays, and reviewed shell invocations quote caller-controlled values.
- Supply chain: production has no third-party runtime dependency; `tools/get-jdk.sh` uses HTTPS and verifies the pinned archive digest before extracting it.
