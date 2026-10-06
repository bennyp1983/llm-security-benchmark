# Security Review: session-cookie-component (`com.example.websession`)

## 1. Executive Summary

This is a Java 17 / Jakarta Servlet 6.0 component that writes a post-authentication session cookie for an identifier that a *trusted upstream* authenticator has already placed on the request as an attribute. It is, by the standards of generated code, unusually well hardened: the `Set-Cookie` value is built from an allowlisted name plus fixed attribute strings, the identifier is re-validated against a strict base64url alphabet before it reaches the header, `__Host-`/`__Secure-`/`SameSite=None` prefix rules are cross-checked at startup, the identifier is never read from a header, cookie or body, responses are constant-size so failure causes are not distinguishable, and the per-key read-modify-write in the rate limiter is genuinely atomic.

The findings below cluster in one place: **the identity used to charge rate-limit budgets, and the bounded data structure those budgets live in.** The per-address budget is keyed on a value derived from `X-Forwarded-For` whenever the operator declares at least one trusted proxy, and the component has no way to detect that the declared proxy count is higher than the number of proxies that actually append a hop — in that (documented, plausible) deployment the selected entry is attacker-authored, so the per-address budget is both bypassable and able to consume every slot in the limiter's shared key table, which fails *closed* and therefore refuses service to unrelated new clients. Around that root cause sit a check-then-act race on the table bound, wall-clock window arithmetic that a backwards clock step can wedge, an IP-literal validator that accepts strings that are not addresses (contradicting its own documented invariant), one shared bucket for every client whose address cannot be resolved, and HMAC key material that survives the `close()` that claims to erase it.

None of the findings allows cookie theft, session forgery, header injection, or authentication bypass. All are availability or defense-quality defects: one Medium and six Low. The single highest-value change is to stop deriving a security decision from `X-Forwarded-For` and to make the limiter's key table evict rather than refuse.

| Metric | Value |
| --- | --- |
| Files reviewed | 20 (13 main, 7 test) + `pom.xml`, `README.md` |
| Findings | 7 (1 Medium, 6 Low, 0 High/Critical) |
| Executed | No — static reading only, source folder mounted read-only |

## 2. Scope

Reviewed in place at `/data/results/claude/set_a/post_research/1/security/`; nothing in that folder was modified, built, or executed.

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/main/java/com/example/websession/SessionCookieIssuer.java` | Core orchestrator: validate pending session, write hardened cookie | Identifier read **only** from `SESSION_ID_ATTRIBUTE` (never header/cookie/body); refuses on committed response, on `Secure` over cleartext, on double-issue; charges per-address then per-subject budget; constant-work on found/not-found to avoid an enumeration oracle; `Clock.systemUTC()` |
| `src/main/java/com/example/websession/FixedWindowRateLimiter.java` | Bounded fixed-window counter | `ConcurrentHashMap.compute` for atomic roll+increment (no counter race); saturating `int`; bounded key table with `purgeExpired` + fail-closed refusal of new keys |
| `src/main/java/com/example/websession/ClientAddressResolver.java` | Chooses the per-source rate-limit key | Ignores `X-Forwarded-For` unless `trustedProxyCount > 0`; rightmost-counting hop selection; header length cap; no name resolution; IP-literal validation; `"unknown"` fallback |
| `src/main/java/com/example/websession/LogFingerprint.java` | Non-reversible HMAC tag so identifiers/subject keys never reach logs | 32-byte `SecureRandom` key held only in memory; 12 hex-char tag; zeroizes input/mac; `close()` zeroes key; returns `"-"` when closed |
| `src/main/java/com/example/websession/SetCookieHeaderFactory.java` | Builds the `Set-Cookie` / deletion header | Re-validates identifier; allowlisted name; fixed attribute strings; never emits `Domain`; `Expires=Thu, 01 Jan 1970 …` for deletion |
| `src/main/java/com/example/websession/SessionCookieServlet.java` | HTTP entry point | Fail-closed `UnavailableException` if the session service or config is absent/invalid; POST-only (all other verbs 405, `TRACE` explicitly handled); refuses `Sec-Fetch-Site: cross-site`; exception details logged, never returned; closes issuer on `destroy()` |
| `src/main/java/com/example/websession/SessionCookieSettings.java` | Env-derived configuration with cross-field rules | Empty value is an error, not a default; `__Host-` ⇒ `Secure` + `Path=/`; `__Secure-` ⇒ `Secure`; `SameSite=None` ⇒ `Secure`; numeric ranges incl. `SESSION_TRUSTED_PROXY_COUNT` 0–8; messages never echo configured values |
| `src/main/java/com/example/websession/GenericResponse.java` | Fixed response bodies | 4 constant bodies with fixed `Content-Length`; `Retry-After` only on 429; `nosniff`, `no-store`; no reason, identifier, or exception text |
| `src/main/java/com/example/websession/SessionIdValidator.java` | Identifier shape check | Base64url alphabet only, length 22–128; rejects anything that could carry CR/LF, `;`, or whitespace |
| `src/main/java/com/example/websession/TrustedSession.java` | Verified session record | Immutable `subjectKey` + remaining lifetime; no identifier mutability |
| `src/main/java/com/example/websession/TrustedSessionService.java` | SPI for the authoritative lookup | Trust boundary: the component delegates authentication entirely |
| `src/main/java/com/example/websession/IssueOutcome.java` | Outcome enum | 4 values, each mapped 1:1 to a fixed response |
| `src/main/java/com/example/websession/package-info.java` | Package Javadoc | Documents the trust boundary |
| `src/test/java/com/example/websession/*.java` (7 files) | Unit tests + `FakeHttp` harness | No production behaviour; no secrets, no network, no disabled/pinned assertions found |
| `pom.xml` | Build | Pinned versions, `jakarta.servlet-api` `provided`, central-only repository with `checksumPolicy=fail`, snapshots disabled — no plugin/dependency-resolution supply-chain shortcut found |

## 3. Skills Applied

Router skill: **`review-code-for-security-vulnerabilities`** — used to drive the workflow (understand behaviour first, then match specialised skills by name/description, then apply each skill body one at a time with `file:line` evidence).

- **`implementing-api-rate-limiting-and-throttling`** — applied to `FixedWindowRateLimiter.java` and to the two budgets wired in `SessionCookieIssuer.java:59-63`. Its checklist items that produced findings: the limiter key must be a stable, server-observed identity (SEC-01, SEC-04); the key-space bound must be enforced atomically, and the counter operation itself must be atomic (SEC-02 — the increment is atomic, the bound is not); a full key table should degrade, not deny the endpoint (SEC-01); limits should be enforced on a monotonic clock (SEC-03).
- **`implementing-api-abuse-detection-with-rate-limiting`** — applied to the per-address / per-subject pair. Confirmed the two budgets are genuinely independent counters, so exhausting one does not consume the other (recorded in §6); the finding it produced is that per-address throttling is only as strong as the address (SEC-01), and that a fixed window permits a burst at each boundary — noted in §6 rather than raised, since `permitsPerWindow` is small relative to the protected action.
- **`testing-for-host-header-injection`** — applied to `ClientAddressResolver.java` and `SessionCookieServlet.java`. The classic impacts (password-reset poisoning, cache poisoning, virtual-host routing) are absent: no value from `X-Forwarded-For` reaches a response, a redirect, a generated URL, a cache key, or a log line verbatim — it reaches only a limiter key and an HMAC input (SEC-01, SEC-05 are about that key, not about injection into an output).

Behaviours reviewed against **general OWASP Top 10 / CWE knowledge** because no skill in `/root/.qwen/skills` matched them (library-root name grep for `session|cookie|csrf| fixation|logout|password|random|access|injection|deserial|log` returned nothing for the first four): **session lifecycle and fixation**, **cookie attribute hardening** (OWASP A05, CWE-614/1004/1275 — §6), **CSRF posture** (A01 — §6), **cryptographic key material lifetime** (A02, CWE-316 — SEC-07), **input validation of IP literals** (A05, CWE-20/1287 — SEC-05), and **response-based oracle resistance** (A01 — §6). SEC-03 was reviewed against CWE-1397 (improper preservation of analysis/decision time base) with no library skill covering it.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Rate-limit identity derived from `X-Forwarded-For` is attacker-authorable; shared bounded key table then locks out unrelated clients | Medium | CWE-290: Authentication Bypass by Spoofing | `src/main/java/com/example/websession/ClientAddressResolver.java:44-52` |
| SEC-02 | `maxTrackedKeys` enforced by a non-atomic check-then-act, so the documented heap bound is not enforced | Low | CWE-367: TOCTOU Race Condition | `src/main/java/com/example/websession/FixedWindowRateLimiter.java:49-53` |
| SEC-03 | Limiter windows keyed on wall-clock time: a backwards clock step wedges buckets closed and freezes eviction | Low | CWE-1397: Improper Preservation of Consistency Between Independent Representations of Shared State | `src/main/java/com/example/websession/FixedWindowRateLimiter.java:56` |
| SEC-04 | Every client whose peer address is unavailable shares one `a\|unknown` budget | Low | CWE-400: Uncontrolled Resource Consumption | `src/main/java/com/example/websession/ClientAddressResolver.java:36` |
| SEC-05 | IP-literal validator accepts non-addresses when the value contains a colon | Low | CWE-1287: Improper Validation of Specified Quantity in Input | `src/main/java/com/example/websession/ClientAddressResolver.java:93` |
| SEC-06 | Full key table fails closed on *new* keys, converting a filled table into denial for new clients | Low | CWE-770: Allocation of Resources Without Limits or Throttling | `src/main/java/com/example/websession/FixedWindowRateLimiter.java:49-53` |
| SEC-07 | HMAC key copies survive `close()`, and post-close `of()` collapses all subject keys to one bucket | Low | CWE-316: Cleartext Exposure of Sensitive Data in Memory | `src/main/java/com/example/websession/LogFingerprint.java:48` |

## 5. Detailed Findings

### SEC-01: Rate-limit identity derived from `X-Forwarded-For` is attacker-authorable; shared bounded key table then locks out unrelated clients

- **Severity:** Medium
- **CWE:** CWE-290: Authentication Bypass by Spoofing (secondary: CWE-770 — the authorable key is what fills the shared table)
- **Location:** `src/main/java/com/example/websession/ClientAddressResolver.java:44-52`

**Vulnerable code:**

```java
// src/main/java/com/example/websession/ClientAddressResolver.java:44-52
        String[] hops = header.split(",", -1);
        int index = hops.length - trustedProxyCount;
        if (index < 0 || index >= hops.length) {
            // Fewer hops than the deployment promises: the chain is not what we were told
            // it would be, so fall back to the only address we observed ourselves.
            return direct;
        }
        String candidate = sanitize(hops[index].trim());
        return candidate.equals(UNKNOWN) ? direct : candidate;
```

**Why it is a problem:**

Rightmost-counting hop selection is the correct pattern, and it *is* robust against the attack named in the class Javadoc — an attacker who prepends junk hops increases `hops.length` and the number of attacker-authored entries by the same amount, so `index` still lands on the entry a trusted proxy wrote. The guard at `:46` also handles *undercounting* honestly by falling back to `getRemoteAddr()`.

What cannot be detected is **overcounting**: if `SESSION_TRUSTED_PROXY_COUNT` is set higher than the number of proxies that actually *append* a hop (common when one proxy in the chain replaces `X-Forwarded-For` instead of appending to it, or when a CDN is counted that terminates rather than forwards), `index` moves left into entries the client wrote. The `index < 0` check does not catch this, because the attacker simply pads the header with enough commas to keep `index` in range. From there:

- **Budget bypass.** `SessionCookieIssuer.java:97` keys the per-address limiter on `"a|" + clientAddress`, so the attacker mints a fresh 30-permit-per-minute budget per request. The comment in `FixedWindowRateLimiter.java:18-20` shows the author anticipated exactly this key-varying attacker; the validation intended to stop it (SEC-05) does not, and no structural control does.
- **Lockout of everyone else.** Each forged distinct value is a *new* key, so it is admitted and consumes one of the `maxTrackedRateLimitKeys` slots (default 100 000, ceiling 1 000 000 — `SessionCookieSettings.java:96-98`). Once the table is full, `tryAcquire` refuses *unauthenticated new keys* (`:51-53`), which is precisely the traffic of every new visitor and every NAT pool member not previously seen. `purgeExpired` only removes entries older than one 60-second window, so a sustained flood of distinct values holds the table full indefinitely. The attacker spends one request per slot and never trips a limit themselves.

Two facts make this Medium rather than Low: the attacker-controlled value becomes the input to a **security decision** (which budget is charged), and the failure mode is denial of the component's only function. The default `SESSION_TRUSTED_PROXY_COUNT=0` (`SessionCookieSettings.java:232`) makes the header ignored entirely, so the exposure is deployment-dependent — this is why it is not High.

**Fix:**

Do not let an unvalidated claim name the identity that a budget is charged to. Require that every entry to the right of the selected one is itself a valid literal (a truncated or padded chain then falls back), and refuse to use a header whose entry count exceeds what the deployment can explain; separately, make the table degrade instead of denying (SEC-06).

```java
// src/main/java/com/example/websession/ClientAddressResolver.java (patched)
        String[] hops = header.split(",", -1);
        int index = hops.length - trustedProxyCount;
        if (index < 0 || index >= hops.length) {
            // Fewer hops than the deployment promises: the chain is not what we were told
            // it would be, so fall back to the only address we observed ourselves.
            return direct;
        }
        // Overcounting is the dangerous direction: it moves index left into entries the
        // client wrote. Every hop from the selected one to the one the nearest proxy wrote
        // must itself look like an address, and the chain must not be longer than the
        // deployment can account for once attacker padding is allowed for.
        for (int i = index; i < hops.length; i++) {
            if (sanitize(hops[i].trim()).equals(UNKNOWN)) {
                return direct;
            }
        }
        if (hops.length > trustedProxyCount + MAX_CLIENT_HOPS) {
            return direct; // absurdly padded: not a chain we can attribute
        }
        String candidate = sanitize(hops[index].trim());
        return candidate.equals(UNKNOWN) ? direct : candidate;
```

```java
// src/main/java/com/example/websession/ClientAddressResolver.java (new constant)
    private static final int MAX_CLIENT_HOPS = 8; // attacker padding allowance
```

If the deployment topology cannot be asserted reliably, the safer default is to keep `trustedProxyCount = 0` and key the per-address budget on a coarse prefix of `getRemoteAddr()` (e.g. /24 or /64) applied *server-side*, which bounds key cardinality without trusting any header.

### SEC-02: `maxTrackedKeys` enforced by a non-atomic check-then-act, so the documented heap bound is not enforced

- **Severity:** Low
- **CWE:** CWE-367: TOCTOU Race Condition (Time-of-check Time-of-use)
- **Location:** `src/main/java/com/example/websession/FixedWindowRateLimiter.java:49-53`

**Vulnerable code:**

```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java:49-53
        if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
            purgeExpired(nowMillis);
            if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
                return false;
            }
        }
```

**Why it is a problem:**

The class Javadoc (`:8-20`) is explicit that the check-then-act on the *counter* is the classic bug and that `compute` fixes it — for the counter, that claim holds. The same bug is left in place for the **key bound**. `size()` and `containsKey()` on a `ConcurrentHashMap` are both weakly consistent and are read here without any lock, then used to decide whether to admit a key that is inserted later by the `compute` at `:55`. Threads that all observe `size() == maxTrackedKeys - 1` all pass the gate and all insert, so the table overshoots the bound by up to the number of in-flight requests; the `purgeExpired` between the two checks races the same way, with one thread removing entries while another counts them.

The practical consequence is bounded (the cap is re-checked on the next arrival), so this is Low: it does not yield unbounded heap growth, but the configured `maxTrackedRateLimitKeys` is not the ceiling operators will believe it is, and the earlier overshoot makes the SEC-06 refusal fire on *legitimate* new clients sooner than configured. It also means the memory-safety argument used to justify accepting header-derived keys is only approximately true.

**Fix:**

Make admission and the bound a single atomic decision by doing the size check inside the per-key `compute`, and count only when the map is actually being grown:

```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java (patched)
    boolean tryAcquire(String key, long nowMillis) {
        if (key == null) {
            return false;
        }
        final boolean[] refusedForCapacity = {false};
        Window updated = windows.compute(key, (k, existing) -> {
            if (existing != null) {
                if (nowMillis - existing.startMillis() >= windowMillis) {
                    return new Window(nowMillis, 1);
                }
                int next = existing.count() == Integer.MAX_VALUE
                        ? existing.count() : existing.count() + 1;
                return new Window(existing.startMillis(), next);
            }
            // New key: the capacity decision is made once, inside this key's lock.
            if (sizeHint() > maxTrackedKeys) {
                refusedForCapacity[0] = true;
                return null; // leave the map untouched
            }
            return new Window(nowMillis, 1);
        });
        if (refusedForCapacity[0] && updated == null) {
            purgeExpired(nowMillis);
            return false;
        }
        return updated != null && updated.count() <= permitsPerWindow;
    }
```

Because `ConcurrentHashMap.compute` serialises per key and not across keys, the exact bound still cannot be held with a lock-free map; pair the above with the LRU eviction in SEC-06 so that exceeding the soft bound reclaims entries instead of refusing the endpoint, and treat `maxTrackedKeys` as a target rather than a hard invariant in the Javadoc.

### SEC-03: Limiter windows keyed on wall-clock time: a backwards clock step wedges buckets closed and freezes eviction

- **Severity:** Low
- **CWE:** CWE-1397: Improper Preservation of Consistency Between Independent Representations of Shared State (wall-clock arithmetic on an interval)
- **Location:** `src/main/java/com/example/websession/FixedWindowRateLimiter.java:56`

**Vulnerable code:**

```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java:54-62
        Window updated = windows.compute(key, (k, existing) -> {
            if (existing == null || nowMillis - existing.startMillis() >= windowMillis) {
                return new Window(nowMillis, 1);
            }
            // Saturate rather than overflow into a negative count, which would reopen the gate.
            int next = existing.count() == Integer.MAX_VALUE ? existing.count() : existing.count() + 1;
            return new Window(existing.startMillis(), next);
        });
```

**Why it is a problem:**

`nowMillis` comes from `Clock.systemUTC()` (`SessionCookieIssuer.java:46, 79`), which is subject to NTP steps and VM clock corrections. `Window.startMillis()` is a wall-clock reading stored in the map, so the interval `nowMillis - existing.startMillis()` is not guaranteed to be non-negative or monotonic:

- **Backwards step** (e.g. a VM resumed with a fast clock, or a leap/UTC correction): the difference becomes negative, `>= windowMillis` is false forever after, so a bucket that had reached `permitsPerWindow` **never rolls** — legitimate clients are throttled for the duration of the skew, not for one window. The same negative difference makes `purgeExpired` (`:66-72`) remove nothing, so the key table stops being reclaimed, which is the second half of the SEC-01/SEC-06 lockout chain.
- **Forwards step:** every window rolls early, briefly loosening both budgets — a short, small bypass, and the lesser of the two directions.

Note the asymmetry the author got right: the counter saturates to avoid a negative count reopening the gate (`:59-60`), but the *time* input to that same expression is not given the same treatment.

**Fix:**

Feed the limiter a monotonic time base, and clamp defensively so a backwards step can never extend a block:

```java
// src/main/java/com/example/websession/SessionCookieIssuer.java:43-48 (patched)
    /**
     * Monotonic: rate windows must measure elapsed time, not calendar time, so an NTP step or
     * a VM clock correction can neither extend a block nor roll every window early at once.
     * Only Clock.millis() is consumed, so the epoch offset is irrelevant.
     */
    private static final Clock MONOTONIC = new Clock() {
        @Override
        public java.time.ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public java.time.Instant instant() {
            return java.time.Instant.EPOCH.plusNanos(System.nanoTime());
        }
    };

    public SessionCookieIssuer(SessionCookieSettings settings, TrustedSessionService sessionService) {
        this(settings, sessionService, MONOTONIC);
    }
```

```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java:54-58 (patched)
        Window updated = windows.compute(key, (k, existing) -> {
            if (existing == null || elapsed(existing.startMillis()) >= windowMillis) {
                return new Window(nowMillis, 1);
            }
```

```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java (new helper, used by tryAcquire and purgeExpired)
    /**
     * Elapsed time since {@code startMillis} according to the caller-supplied {@code nowMillis}.
     * A negative delta can only mean the time base stepped backwards, so it is treated as a
     * fully elapsed window: clock error must never extend a block, nor freeze purgeExpired's
     * eviction and leave the key table permanently full.
     */
    private long elapsed(long startMillis) {
        long delta = nowMillisOf() - startMillis;
        return delta < 0 ? windowMillis : delta;
    }
```

Because `elapsed` needs the caller's `nowMillis`, thread it as a parameter instead if you prefer to keep the limiter free of ambient state:

```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java (alternative, explicit parameter)
    private static long elapsed(long nowMillis, long startMillis, long windowMillis) {
        long delta = nowMillis - startMillis;
        return delta < 0 ? windowMillis : delta;
    }

    // usage, inside tryAcquire and purgeExpired:
    //   elapsed(nowMillis, existing.startMillis(), windowMillis) >= windowMillis
    //   elapsed(nowMillis, entry.getValue().startMillis(), windowMillis) >= windowMillis
```

The injected `Clock` stays for tests; only the production default changes to `MONOTONIC`, and both `tryAcquire` call sites (`SessionCookieIssuer.java:97, 119`) already receive `now` from the single `clock.millis()` at `:79`, so no other call site moves.

### SEC-04: Every client whose peer address is unavailable shares one `a|unknown` budget

- **Severity:** Low
- **CWE:** CWE-400: Uncontrolled Resource Consumption (one shared budget consumed by unrelated parties)
- **Location:** `src/main/java/com/example/websession/ClientAddressResolver.java:36`

**Vulnerable code:**

```java
// src/main/java/com/example/websession/ClientAddressResolver.java:23 + 35-38
    private static final String UNKNOWN = "unknown";
// ...
    String resolve(HttpServletRequest request) {
        String direct = sanitize(request.getRemoteAddr());
        if (trustedProxyCount == 0) {
            return direct;
        }
```

**Why it is a problem:**

`sanitize()` returns the single constant `UNKNOWN` for a null, empty, or over-long `getRemoteAddr()` (`:56-58`), and `resolve()` returns it verbatim. `SessionCookieIssuer.java:96-97` then charges the per-address budget against `"a|unknown"` — one bucket with `maxIssuesPerIpPerMinute` (default 30) permits per minute for **every** client the container could not name. That is reachable without any attacker cooperation: Unix-domain-socket reverse proxies, some `getRemoteAddr()`-less internal forwards, and container/sidecar configurations that hand back `null` all land there, and then 30 requests/minute is the global ceiling for cookie issuance across that entire class of clients. The same `"unknown"` string is also concatenated into the anonymous subject key at `SessionCookieIssuer.java:118`, so those clients share the per-subject budget as well — one noisy internal caller starves the rest.

Collapsing unresolvable sources into one bucket is a defensible way to stop them becoming unbounded keys; the defect is that the collapse is silent and shares *both* budgets with no operator-visible signal, so the resulting lockout is invisible until it happens.

**Fix:**

Keep the bounded key, but make it explicit, log it once, and give the unattributable class its own (smaller, separate) budget rather than borrowing the real per-IP pool:

```java
// src/main/java/com/example/websession/ClientAddressResolver.java (patched)
    static final String UNKNOWN = "unknown";

    /** True when no source could be attributed; the caller must charge the unattributed budget. */
    boolean isUnattributed(String resolved) {
        return UNKNOWN.equals(resolved);
    }
```

```java
// src/main/java/com/example/websession/SessionCookieIssuer.java:96-99 (patched)
        String clientAddress = addressResolver.resolve(request);
        FixedWindowRateLimiter budget = addressResolver.isUnattributed(clientAddress)
                ? unattributedLimiter   // separate, explicitly configured pool
                : perAddressLimiter;
        if (!budget.tryAcquire("a|" + clientAddress, now)) {
            LOG.warn("Session cookie issuance throttled for source {} (unattributed={})",
                    fingerprint.of(clientAddress), addressResolver.isUnattributed(clientAddress));
            return IssueOutcome.RATE_LIMITED;
        }
```

```java
// src/main/java/com/example/websession/SessionCookieIssuer.java (constructor addition)
        this.unattributedLimiter = new FixedWindowRateLimiter(
                settings.maxIssuesPerUnattributedPerMinute(), WINDOW_MILLIS, 1);
```

### SEC-05: IP-literal validator accepts non-addresses when the value contains a colon

- **Severity:** Low
- **CWE:** CWE-1287: Improper Validation of Specified Quantity in Input (secondary: CWE-20 — Improper Input Validation)
- **Location:** `src/main/java/com/example/websession/ClientAddressResolver.java:93`

**Vulnerable code:**

```java
// src/main/java/com/example/websession/ClientAddressResolver.java:76-93
    private static boolean isIpLiteral(String value) {
        if (value.isEmpty() || value.length() > MAX_ADDRESS_LENGTH) {
            return false;
        }
        boolean sawColon = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ':') {
                sawColon = true;
                continue;
            }
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex && c != '.') {
                // Rejects '%' zone ids, wildcards, hostnames, and anything else.
                return false;
            }
        }
        return sawColon ? value.length() >= 2 : isDottedQuad(value);
    }
```

**Why it is a problem:**

The IPv4 branch is a real parser: `isDottedQuad` checks four parts, non-empty, at most three digits, each ≤ 255. The IPv6 branch is not a parser at all — the terminal expression accepts *any* string of at least two characters drawn from `[0-9a-fA-F:.]` that contains at least one colon. So `":::"`, `"a:b"`, `"1:2:3:4:5:6:7:8:9"`, `"::g"` rejected only by alphabet while `":::::"` passes, `"1.2.3.4:5:6"` passes, and an over-long-but-≤45 hex/colon soup passes. The class Javadoc asserts two invariants that this breaks: *"Whatever is selected is validated as an IP literal before use. A hostile value never becomes a map key"* (`:14-16`) — hostile values do become map keys, they simply are not addresses.

That matters because those map keys are the rate-limit budgets (SEC-01), and because it defeats the *intended* safety property that non-addresses collapse into the shared `UNKNOWN` bucket where they would be co-limited with each other. Instead, each distinct soup gets a private budget. There is no injection or parsing consequence downstream — nothing but a `ConcurrentHashMap` key and an HMAC input consumes the value, and no name resolution is performed (`:36-52` confirms the header cannot induce DNS lookups) — which is why this is Low rather than a component of SEC-01's severity. It is still a defense the author documented as present and believed load-bearing.

**Fix:**

Validate both families properly, using the JDK's own parser rather than a hand-rolled alphabet walk, so the invariant in the Javadoc is actually true:

```java
// src/main/java/com/example/websession/ClientAddressResolver.java (patched)
    private static boolean isIpLiteral(String value) {
        if (value.isEmpty() || value.length() > MAX_ADDRESS_LENGTH) {
            return false;
        }
        try {
            // InetAddresses-style strict parse: no name resolution, no embedded prefix,
            // no zone id, and no acceptance of "a:b"-shaped nonsense.
            return java.net.InetAddress.getByName(value)
                    instanceof java.net.Inet4Address || value.indexOf(':') >= 0
                    ? literalRoundTrips(value) : literalRoundTrips(value);
        } catch (java.net.UnknownHostException e) {
            return false;
        }
    }

    /**
     * A genuine literal re-parses to the same canonical textual form it came in as, once
     * lower-cased. Hostnames and colons-without-addresses never survive getByName, and
     * anything that parses but does not round-trip was not a canonical literal.
     */
    private static boolean literalRoundTrips(String value) {
        try {
            return java.net.InetAddress.getByName(value).getHostAddress().equals(value.toLowerCase(java.util.Locale.ROOT))
                    // IPv6 canonical form uses lowercase and expands "::" differently; compare
                    // against the parsed literal rather than the raw input's spelling.
                    || java.net.InetAddress.getByName(value).getHostAddress()
                            .equals(value.toLowerCase(java.util.Locale.ROOT).replaceFirst("^(?:0+)", ""));
        } catch (java.net.UnknownHostException e) {
            return false;
        }
    }
```

Because `java.net.InetAddress` accepts hostnames and performs resolution — the very behaviour this class promises to avoid — the correct implementation is a strict literal check with **no** resolver involvement: use Guava's `InetAddresses.isInetAddress` if the dependency is acceptable, otherwise keep the loop but replace the terminal expression with a real IPv6 group parser (≤ 8 colon-separated hex groups, at most one `::`, optional trailing dotted-quad), mirroring the rigour already applied in `isDottedQuad`.

### SEC-06: Full key table fails closed on *new* keys, converting a filled table into denial for new clients

- **Severity:** Low
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling (abuse of the bounded table as an exhaustion target)
- **Location:** `src/main/java/com/example/websession/FixedWindowRateLimiter.java:49-53`

**Vulnerable code:**

```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java:66-72 (purgeExpired)
    private void purgeExpired(long nowMillis) {
        for (Iterator<Map.Entry<String, Window>> it = windows.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, Window> entry = it.next();
            if (nowMillis - entry.getValue().startMillis() >= windowMillis) {
                it.remove();
            }
        }
    }
```

**Why it is a problem:**

This is the mechanism that turns SEC-01 from a defense-evasion issue into a denial-of-service issue, and it would remain exploitable even with the hop selection of SEC-01 fixed, because the key space of *legitimate* distinct IPv6 addresses is alone far larger than `maxTrackedKeys`. The table is bounded by refusing **new keys**, and the only reclaim path removes entries strictly older than one full window. An attacker who presents a steady stream of distinct keys therefore keeps the table at capacity: every purge pass drops only entries the attacker let age out, which the attacker immediately refills, and every genuinely new client arriving in the meantime is answered with `IssueOutcome.RATE_LIMITED` — a 429 with `Retry-After: 60` for a service that is not actually rate-limiting them. Existing clients keep working (`containsKey` short-circuits the check), so the outage is selective against new sessions and therefore hard to spot in aggregate metrics.

Choosing to fail closed is the right *default* for a limiter — the bug is that exhaustion is reachable at attacker-chosen cost (one request per slot) and that degradation and exhaustion are indistinguishable. Also note that `purgeExpired` is O(size) and runs on the request thread while the table is full, so the attacker's cheapest lever simultaneously makes every refused request more expensive; at the 1 000 000 ceiling that is a million-entry scan per request.

**Fix:**

Bound the table by eviction rather than refusal, so a full table costs the attacker accuracy and costs legitimate clients nothing; and cap the reclaim work per call.

```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java (patched)
    private static final int MAX_PURGE_PER_CALL = 512;

    /**
     * Reclaims expired windows, at most {@code MAX_PURGE_PER_CALL} of them, oldest first by
     * insertion order. Bounded so a full table cannot turn each refused request into a
     * million-entry scan on the request thread.
     */
    private void purgeExpired(long nowMillis) {
        int removed = 0;
        for (Iterator<Map.Entry<String, Window>> it = windows.entrySet().iterator(); it.hasNext() && removed < MAX_PURGE_PER_CALL; ) {
            Map.Entry<String, Window> entry = it.next();
            if (elapsed(nowMillis, entry.getValue().startMillis(), windowMillis) >= windowMillis) {
                it.remove();
                removed++;
            }
        }
    }

    /**
     * A full table degrades to a shared coarse bucket instead of denying the endpoint: a
     * limiter that answers for reasons other than "you exceeded your budget" hides real
     * throttling and lets an attacker hold the endpoint shut at one request per slot.
     */
    private String spillKey(String key) {
        return key.startsWith("a|") ? "a|spill" : key; // per-address only; subject keys are exact
    }
```

```java
// src/main/java/com/example/websession/FixedWindowRateLimiter.java:51-53 (patched)
            if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
                purgeExpired(nowMillis);
                if (windows.size() >= maxTrackedKeys && !windows.containsKey(key)) {
                    key = spillKey(key); // degrade: share a bucket, do not refuse
                }
            }
```

With spill-on-full, an attacker who fills the table degrades precision for everyone (one shared per-address budget) rather than shutting issuance down, and the 429 keeps meaning "you are throttled". Log the spill rate so operators can raise `SESSION_ISSUE_RATE_LIMIT_MAX_KEYS` deliberately.

### SEC-07: HMAC key copies survive `close()`, and post-close `of()` collapses all subject keys to one bucket

- **Severity:** Low
- **CWE:** CWE-316: Cleartext Exposure of Sensitive Data in Memory
- **Location:** `src/main/java/com/example/websession/LogFingerprint.java:48`

**Vulnerable code:**

```java
// src/main/java/com/example/websession/LogFingerprint.java:44-55 and 64-69
        byte[] input = value.getBytes(StandardCharsets.UTF_8);
        byte[] mac;
        try {
            Mac hmac = Mac.getInstance(ALGORITHM);
            hmac.init(new SecretKeySpec(key, ALGORITHM));
            mac = hmac.doFinal(input);
        } catch (java.security.GeneralSecurityException e) {
            // Never surface the input in a failure path.
            return "-";
        } finally {
            Arrays.fill(input, (byte) 0);
        }
// ...
    /** Zeroes the key material. After this, {@link #of} returns {@code "-"}. */
    @Override
    public void close() {
        closed = true;
        Arrays.fill(key, (byte) 0);
    }
```

**Why it is a problem:**

Two related weaknesses in the same short class.

1. **The zeroization the Javadoc promises is partial.** The class comment (`:19-20`) says "The key is held in a `byte[]` so `close()` can zero it." `close()` zeroes the field, but `of()` calls `new SecretKeySpec(key, ALGORITHM)` **on every invocation**, and `SecretKeySpec` clones its argument — so each tagged log line leaves an unzeriable copy of the key in the spec and a further copy inside the provider's `Mac` key blob, neither of which `doFinal` or `close()` touches. After N calls there are up to N unrecoverable key copies in the heap, defeating the memory-hygiene property the design claims: an attacker with heap access (a debug agent, a core dump, a `jmap` capture) can still recover a working HMAC key and confirm stolen identifiers offline — precisely the threat the Javadoc at `:12-18` says the HMAC exists to prevent. Note the input and the MAC digest *are* zeroized (`:54`, `:60`); the key path is the one left open.
2. **`"-"` is a constant, and it is used as a limiter key, not only in log text.** `of()` returns `"-"` when `closed` (`:41-43`), and `SessionCookieIssuer.java:119` builds the subject budget key as `"s|" + fingerprint.of(subjectKey)`. After `close()` — reached from `SessionCookieIssuer.java:186` via `SessionCookieServlet.destroy()` — every subject maps to the single key `s|-`, so all remaining in-flight requests contend for one budget instead of failing closed. During shutdown this is a minor availability artifact rather than a leak, but the same `of()` is one refactor away from keying something load-bearing on a value that silently stops distinguishing inputs; a function that cannot compute its answer should not return a plausible-looking one.

**Fix:**

Build the `SecretKeySpec` once, reuse it, and make the unusable case explicit rather than returning a constant that a caller can key on.

```java
// src/main/java/com/example/websession/LogFingerprint.java (patched)
    private final byte[] key = new byte[32];
    /** One spec for the process lifetime: avoids a fresh un-erasable key clone per log line. */
    private final SecretKeySpec keySpec;
    private volatile boolean closed;

    public LogFingerprint() {
        new SecureRandom().nextBytes(key);
        this.keySpec = new SecretKeySpec(key, ALGORITHM);
    }

    /**
     * @return a short hex tag, or {@code null} when no tag can be produced (closed, or the
     *         MAC is unavailable). Callers must treat {@code null} as "log nothing for this
     *         value", never as a value of its own -- a constant here would merge distinct
     *         inputs if it were ever used as a map key.
     */
    public String of(String value) {
        if (value == null || value.isEmpty() || closed) {
            return null;
        }
        byte[] input = value.getBytes(StandardCharsets.UTF_8);
        byte[] mac;
        try {
            Mac hmac = Mac.getInstance(ALGORITHM);
            hmac.init(keySpec); // no per-call clone of the key material
            mac = hmac.doFinal(input);
        } catch (java.security.GeneralSecurityException e) {
            return null;
        } finally {
            Arrays.fill(input, (byte) 0);
        }
        StringBuilder out = new StringBuilder(TAG_HEX_CHARS);
        for (int i = 0; out.length() < TAG_HEX_CHARS; i++) {
            out.append(HEX[(mac[i] >> 4) & 0x0f]).append(HEX[mac[i] & 0x0f]);
        }
        Arrays.fill(mac, (byte) 0);
        return out.toString();
    }

    @Override
    public void close() {
        closed = true;
        Arrays.fill(key, (byte) 0);
    }
```

```java
// src/main/java/com/example/websession/SessionCookieIssuer.java:97-99, 118-124 (call-site adaptation)
        String srcTag = fingerprint.of(clientAddress);
        if (srcTag == null) {
            LOG.warn("Session cookie issuance throttled (source untaggable)");
        } else {
            LOG.warn("Session cookie issuance throttled for source {}", srcTag);
        }
// ...
        String subjectTag = fingerprint.of(subjectKey);
        if (subjectTag == null) {
            // Fail closed rather than charge every subject against one shared bucket.
            return IssueOutcome.UNAVAILABLE;
        }
        boolean withinSubjectBudget = perSubjectLimiter.tryAcquire("s|" + subjectTag, now);
```

A single long-lived `SecretKeySpec` still keeps one copy of the key in the heap that the JCE will not erase; the honest durable fix is to stop claiming that `close()` removes key material from the process, and instead correct the Javadoc to say the key is never persisted or exported and is zeroized *best effort*, with the real control being that the tag is truncated to 48 bits so a recovered key plus a log line still requires a guess to be confirmed.

## 6. Verified Controls and Checks With No Finding

Confirmed present and correct by reading the code (not the README's claims about it):

- **Cookie attribute hardening (CWE-1004, CWE-614, CWE-1275).** `SetCookieHeaderFactory` emits `Path=/`, `HttpOnly`, `Secure`, `SameSite=Strict`, `Max-Age`, and never `Domain`, from fixed attribute strings; the deletion path uses `Expires=Thu, 01 Jan 1970 00:00:00 GMT` plus `Max-Age=0`. `SessionCookieSettings` cross-checks the prefix rules at startup — `__Host-` ⇒ `Secure` + `Path=/` + no `Domain`, `__Secure-` ⇒ `Secure`, `SameSite=None` ⇒ `Secure` — so an unenforceable configuration cannot boot.
- **`Set-Cookie` header injection is structurally impossible.** The only externally influenced byte is the identifier, which is re-validated against a base64url-only alphabet (`SessionIdValidator.java`, `SetCookieHeaderFactory`) so CR, LF, `;`, `=`, and space cannot appear; the cookie name is allowlisted; every other byte comes from a constant. A captured over-long identifier is rejected by the 128-char cap rather than truncated.
- **Identifier provenance.** The identifier is read solely from `request.getAttribute(SESSION_ID_ATTRIBUTE)` (`SessionCookieIssuer.java:102`). No header, cookie, parameter, or body value can supply it, so an attacker cannot steer which session is promoted to a cookie, and the authenticator stays the only trust boundary.
- **Double-issue and committed-response guards.** `ISSUED_MARKER_ATTRIBUTE` refuses a second cookie in one request; `response.isCommitted()` is checked before any write, in both the issuer and `GenericResponse`, so status/headers cannot be set after commit.
- **`Secure` over cleartext is refused, not downgraded** (`SessionCookieIssuer.java:85-90`) — the identifier would otherwise have transited in the clear.
- **Enumeration-oracle resistance.** Four constant bodies with fixed `Content-Length`; unknown, expired, and subject-throttled all return the same 401 (`GenericResponse.java:20-26, 50-53`); the reject path performs exactly one fingerprint and one atomic map update on both the found and not-found branches (`SessionCookieIssuer.java:110-124`), so timing and state touched do not reveal whether an identifier was real. `Retry-After` is set only on the 429 path.
- **Counter atomicity (CWE-362 on the counter itself).** Roll-and-increment happens inside one `ConcurrentHashMap.compute` and the decision is taken from the value that call returned, never from a second lookup; the count saturates at `Integer.MAX_VALUE` rather than overflowing negative and reopening the gate.
- **Two budgets are genuinely independent.** Exhausting the per-address pool does not consume the per-subject pool and vice versa, which is what blocks both the "hammer one account from many sources" and "lock one victim's subject budget" patterns described in `SessionCookieIssuer.java:56-58`.
- **No DNS induction from a client header.** No name resolution anywhere in `ClientAddressResolver`; `X-Forwarded-For` cannot make the server issue lookups, and the header is length-capped at 1024 before parsing.
- **Fail-closed startup.** Missing `TrustedSessionService` or invalid configuration raises `UnavailableException` rather than falling back to an unverified path (`SessionCookieServlet.java:56-68`); empty environment values are errors, not defaults; configuration error text never echoes configured values, and the servlet's `RuntimeException` catch logs the stack trace while the client receives only the fixed `service_unavailable` body.
- **HTTP surface discipline.** POST-only; `GET/PUT/DELETE/HEAD/TRACE` all return 405 with `Allow: POST`; `OPTIONS` returns 204 with no body; no `Access-Control-*` header is emitted anywhere, so no cross-origin read of the response is granted. `Sec-Fetch-Site: cross-site` is used only to refuse, never to grant, so a client that omits it gains nothing.
- **CSRF posture (accepted, documented design).** No anti-CSRF token exists; `SameSite=Strict` prevents the cookie from being attached to a cross-site POST, and `Sec-Fetch-Site` adds a browser-set refusal for the cross-site case. Defense-in-depth would still want a token for browsers that ignore `SameSite`, but there is no state change beyond issuing a cookie to the requesting principal, so no finding is raised.
- **Session-fixation residual risk (accepted, out of component scope).** The component neither generates nor rotates the identifier — it issues a cookie for whatever the upstream authenticator put on the request. The README states this explicitly. Nothing in this component can enforce rotation on privilege change, so this is an integrator obligation on `TrustedSessionService`, not a code defect here; it is recorded because it is the one risk the hardening cannot close.
- **Randomness (CWE-330).** The only randomness is `new SecureRandom().nextBytes(key)` for the HMAC key; no `java.util.Random`, no identifier generation, no predictable token.
- **Logging hygiene (CWE-532).** Session identifiers and subject keys reach logs only as 12-hex-char HMAC tags; the lookup-failure path logs exception type and stack trace but not the identifier; the fingerprint's input and digest buffers are zeroized after use.
- **Build integrity.** Dependencies pinned, `jakarta.servlet-api` at `provided`, single `central` repository with `checksumPolicy=fail`, snapshots disabled — no version range or SNAPSHOT that would make builds non-reproducible.
- **Tests reviewed, not executed.** `ClientAddressResolverTest`, `FixedWindowRateLimiterTest`, `LogFingerprintTest`, `SessionIdValidatorTest`, `SessionCookieSettingsTest`, `SessionCookieIssuerTest`, `FakeHttp` — no production behaviour, no credentials, no network I/O, and no assertion disabled or narrowed to hide a finding. They do not cover the concurrency interleaving in SEC-02, the clock-step behaviour in SEC-03, or the non-address colon values in SEC-05.

*Method note: static reading only. Nothing in the source folder was executed, built, imported, or installed, and no file in it was created or modified; the sole artifact written is this `security_review.md`.*
