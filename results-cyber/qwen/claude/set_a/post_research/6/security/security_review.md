# Security Review: com.example.auth authentication component

## 1. Executive Summary

The source folder contains a self-contained, dependency-free Java SE 17 authentication
component (package `com.example.auth`): credential verification with PBKDF2-HMAC-SHA512,
a session registry, a login throttle, allow-list input validation, and a size-bounded,
permission-restricted audit log.

The code is materially better hardened than typical generated code. The cryptographic
core is correct (JDK `PBKDF2WithHmacSHA512`, 16-byte random salt, 512-bit derived key,
`MessageDigest.isEqual` comparison, `SecureRandom` 256-bit session identifiers stored
only as SHA-256 digests), there is no injection, deserialisation, template, command or
SSRF sink anywhere in the component, and the audit file is created `0600` inside a `0700`
directory and opened `NOFOLLOW_LINKS`.

Six findings were identified, none of which exposes a credential or a session
identifier directly. All of them attack the component's two headline promises: that the
throttle bounds the cost of guessing, and that response timing does not disclose which
usernames exist.

The most important is **SEC-01 (High)**: `LoginThrottle.admit()` only *reads* the failure
counters and never reserves an attempt, while the increment happens later in
`recordFailure()`, after a full 210 000-iteration key derivation. A parallel burst of
requests therefore admits arbitrarily many attempts past the budget and past the CPU-cost
bound the throttle exists to enforce. The project's own concurrency self-check tolerates
this by asserting `admitted <= budget + threads`.

**SEC-02** shows the per-source budget is keyed on a caller-supplied address string that
is only format-validated, so the primary brute-force brake is evadable by whoever asserts
the source value. **SEC-03** shows the same table can be filled by an unauthenticated
attacker to switch the throttle into its fail-closed mode and refuse all genuine logins.
**SEC-04** and **SEC-05** leave a username-enumeration timing oracle open, which the
decoy record was specifically added to close.

Findings are individually Medium-or-below in isolation but cluster on the same two
controls; SEC-01 and SEC-02 together reduce the throttle to a cosmetic limit and should be
remediated first.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/main/java/com/example/auth/AuthenticationService.java` | Orchestrates one login attempt: validate → throttle → look up → verify → issue session → audit. | Order of `admit`/`recordFailure` defines the throttle's real enforcement; decoy path for unknown accounts; generic failure result; zeroes the password buffer in `finally`. |
| `src/main/java/com/example/auth/PasswordHasher.java` | PBKDF2-HMAC-SHA512 verify/hash and the unknown-account decoy record. | Iteration counts, salt/key lengths, constant-time compare, decoy cost construction, `char[]`/`PBEKeySpec` clearing. |
| `src/main/java/com/example/auth/CredentialRecord.java` | Stored verifier (salt, hash, iteration count). | Validates salt/key length and iteration range on construction; redacts material in `toString()`. |
| `src/main/java/com/example/auth/LoginThrottle.java` | Per-source and per-account failure budgets with cool-off. | Admission decision, counter mutation, capacity cap of 50 000 keys per dimension, success-clearing. |
| `src/main/java/com/example/auth/InputPolicy.java` | Allow-list canonicalisation and range checks. | Username/length/charset allow-lists, IPv4/IPv6 shape validation of `source`, session-id shape, `requireInRange` that throws instead of clamping. |
| `src/main/java/com/example/auth/SessionRegistry.java` | Issues and validates opaque session identifiers. | 32-byte `SecureRandom` base64url ids, stores only SHA-256 digests, atomic validate/refresh, 100 000-session cap. |
| `src/main/java/com/example/auth/Session.java` | Session state and expiry predicate. | Idle and absolute expiry; `toString()` omits the identifier. |
| `src/main/java/com/example/auth/SessionCookie.java` | Renders the `Set-Cookie` header. | `__Host-session`, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`; refuses non-canonical values and out-of-range `Max-Age`. |
| `src/main/java/com/example/auth/AuthEvent.java` | Immutable audit record. | Carries only masked username, keyed correlation id, masked source, short detail. |
| `src/main/java/com/example/auth/AuthEventLog.java` | Audit interface, `AuditException`, default correlation. | Fail-closed contract: an audit failure must abort a successful login. |
| `src/main/java/com/example/auth/FileAuthEventLog.java` | File-backed audit sink with rotation. | `0600` file / `0700` directory enforcement, `NOFOLLOW_LINKS` append, size ceiling, HMAC-SHA256 correlation id, serialised flush. |
| `src/main/java/com/example/auth/LogSanitizer.java` | Field escaping, truncation, masking. | Neutralises `"`/`\`/control bytes so user input cannot forge records or split lines; masks username and source. |
| `src/main/java/com/example/auth/CredentialStore.java` | Read-only lookup interface. | Only `find` + checked `CredentialStoreException`; no write path. |
| `src/main/java/com/example/auth/InMemoryCredentialStore.java` | Reference store. | Empty by default (no default/backdoor accounts), canonicalises keys. |
| `src/main/java/com/example/auth/AuthenticationResult.java` | Result DTO. | Single generic failure message, static FAILURE singleton, masked username in `toString()`. |
| `src/test/java/com/example/auth/AuthenticationSelfCheck.java` | 44 bare-JDK behavioural checks. | Documents intended guarantees; `checkConcurrentBudget` bounds admissions by `budget + threads`. |
| `pom.xml`, `README.md` | Build and design claims. | No third-party dependencies, compiler plugin only; README lists controls and residual risks. |

`prompt.txt`, `prompt_hash.txt`, `result.md` and `return.txt` are task metadata, not code,
and were read only to confirm they contain no configuration or secrets.

## 3. Skills Applied

- **`performing-cryptographic-audit-of-application`** — applied to `PasswordHasher.java`,
  `CredentialRecord.java`, `SessionRegistry.java` and `FileAuthEventLog.java`: algorithm and
  mode choice, KDF iteration floor, salt and derived-key length, RNG choice and seeding,
  constant-time comparison, key-material lifetime and zeroing, HMAC key handling for the
  correlation digest. This produced SEC-04 and SEC-05 and cleared the crypto core.
- **`exploiting-race-condition-vulnerabilities`** — applied to `LoginThrottle.admit()` /
  `recordFailure()` and to `AuthenticationService.attempt()`, looking for
  check-then-act ("time-of-check to time-of-use") gaps between the admission decision and
  the state mutation, including the single-packet/parallel-request framing. This produced
  SEC-01 and informed SEC-03.
- **`implementing-api-rate-limiting-and-throttling`** — applied as the reference model for
  what a budget must do: an atomic check-and-consume of a token at admission time, keyed on
  an identity the client cannot choose. Contrasting `LoginThrottle` against that model
  produced SEC-01 (no consume) and SEC-02 (spoofable key), and the capacity discussion in
  SEC-03.
- **`testing-api-authentication-weaknesses`** — applied to the whole attempt path in
  `AuthenticationService.java`, `AuthenticationResult.java`, `SessionRegistry.java` and
  `SessionCookie.java`: token entropy and validation, session fixation, token leakage in
  responses/logs/URLs, user-enumeration resistance, and whether failure modes disclose
  account existence. This produced SEC-04 and cleared the session handling.
- **`performing-security-headers-audit`** — read and applied narrowly to
  `SessionCookie.java`: cookie `Name`/`Secure`/`HttpOnly`/`SameSite`/`Path`/`Max-Age`
  correctness and header-injection resistance. No finding (see section 6).
- **`testing-for-host-header-injection`** and **`testing-for-broken-access-control`** — read
  and applied at assessment level: the component consumes no request Host/absolute-URI and
  builds no URL or authorisation decision, so no finding was possible.
- **`implementing-secrets-management-with-vault`** — read and applied to the
  `correlationKey` parameter of `FileAuthEventLog`: no secret is hardcoded, the key is
  injected, a too-short key is rejected, and the ephemeral fallback key is zeroed. No
  finding.

Behaviours reviewed against general OWASP Top 10 / CWE knowledge because no skill in the
library matched the code's actual behaviour (the component has no template engine, no
database, no network client, no deserialisation, no file upload, no command execution and
no JWT):

- Injection classes (SQL/NoSQL/LDAP/OS command, CWE-89/CWE-74/CWE-78) — no sink exists; the
  only string consumers are the log writer and exception messages.
- Log forging / unsanitised log output (CWE-117) — reviewed against `LogSanitizer` and
  `FileAuthEventLog.render`.
- Cross-site scripting and SSRF (CWE-79, CWE-918) — no HTML rendering and no outbound
  request path.
- Insecure direct object reference / missing authorisation (CWE-639, CWE-862) — the
  component authenticates and issues a session; it does not authorise resources.
- Denial of service by uncontrolled resource consumption (CWE-770/CWE-400) — reviewed for
  the throttle tables, the session cap and the log ceiling; produced SEC-03.
- Observable timing discrepancy and user enumeration (CWE-208, CWE-648, CWE-307) — produced
  SEC-04.
- Supply-chain review of `pom.xml` (CWE-1104) — zero runtime dependencies, plugin pinned to
  `3.13.0`, no repository or plugin-execution surprises. No finding.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Throttle checks the budget but never consumes it, so concurrent attempts overrun it | High | CWE-362 | `src/main/java/com/example/auth/LoginThrottle.java:87` |
| SEC-02 | Per-source budget is keyed on a caller-supplied address that is only format-validated | Medium | CWE-307 | `src/main/java/com/example/auth/InputPolicy.java:108` |
| SEC-03 | Unauthenticated attacker can fill the throttle tables and force fail-closed refusal of all logins | Medium | CWE-770 | `src/main/java/com/example/auth/LoginThrottle.java:142` |
| SEC-04 | Decoy record does not match real verification cost, leaving a username-enumeration oracle | Medium | CWE-208 | `src/main/java/com/example/auth/PasswordHasher.java:38` |
| SEC-05 | Credential records are accepted with an iteration count below the documented policy floor | Low | CWE-916 | `src/main/java/com/example/auth/CredentialRecord.java:25` |
| SEC-06 | Successful login discards the account's entire failure history | Low | CWE-307 | `src/main/java/com/example/auth/LoginThrottle.java:119` |

## 5. Detailed Findings

### SEC-01: Throttle checks the budget but never consumes it, so concurrent attempts overrun it

- **Severity:** High
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **Location:** `src/main/java/com/example/auth/LoginThrottle.java:87`

The javadoc claims `admit()` "atomically decides whether an attempt may proceed", and each
individual map operation is atomic. What is *not* atomic is the decision-to-mutation pair
that the budget depends on. `admit()` reads the counter inside a `compute` that returns the
existing value unchanged (`isBlocked`, lines 123-135), and never increments anything. The
only increment lives in `recordFailure()`, which `AuthenticationService` calls at line 132 —
after the credential lookup and after a full PBKDF2 verification.

**Vulnerable code:**

```java
// src/main/java/com/example/auth/LoginThrottle.java:82-101
    /**
     * Atomically decides whether an attempt may proceed.
     *
     * @return empty when the attempt may proceed, otherwise the reason it may not
     */
    public java.util.Optional<Block> admit(String canonicalUsername, String source) {
        Instant now = clock.get();
        if (isBlocked(bySource, source, now)) {
            return java.util.Optional.of(Block.SOURCE);
        }
        if (isBlocked(byAccount, canonicalUsername, now)) {
            return java.util.Optional.of(Block.ACCOUNT);
        }
        if (atCapacity(bySource, source, now) || atCapacity(byAccount, canonicalUsername, now)) {
            return java.util.Optional.of(Block.CAPACITY);
        }
        return java.util.Optional.empty();
    }

    /** Records a failed attempt against both budgets, starting a cool-off if a budget is spent. */
```

and the window it leaves open in the caller — the charge is taken 33 lines and one full key
derivation after the decision:

```java
// src/main/java/com/example/auth/AuthenticationService.java:98-106
    private AuthenticationResult attempt(String user, char[] password, String source) {
        Optional<LoginThrottle.Block> block = throttle.admit(user, source);
        if (block.isPresent()) {
            // No key derivation here: doing the work would turn the throttle into
            // a CPU amplifier. The decision depends on failure counts, not on
            // whether the account exists, so it is not an existence oracle.
            audit(AuthEvent.Outcome.THROTTLED, user, source, "blocked by throttle: " + block.get().name());
            return AuthenticationResult.failure();
        }
```

```java
// src/main/java/com/example/auth/AuthenticationService.java:116-136
        boolean verified;
        try {
            if (record.isEmpty()) {
                // Equivalent work for an unknown account, so response time does
                // not disclose which usernames exist.
                hasher.verifyAgainstDecoy(password);
                verified = false;
            } else {
                verified = hasher.verify(password, record.get());
            }
        } catch (GeneralSecurityException | RuntimeException e) {
            audit(AuthEvent.Outcome.ERROR, user, source, "verification failed: " + e.getClass().getSimpleName());
            return AuthenticationResult.failure();
        }

        if (!verified) {
            throttle.recordFailure(user, source);
            audit(record.isEmpty() ? AuthEvent.Outcome.UNKNOWN_ACCOUNT : AuthEvent.Outcome.BAD_CREDENTIALS,
                    user, source, "credentials did not match");
            return AuthenticationResult.failure();
        }
```

**Why it is a problem:**

Every one of N simultaneous requests observes the *pre-burst* counter, is admitted, and only
later contributes its increment. The check-then-act gap spans the entire credential-store
lookup plus a 210 000-iteration PBKDF2 derivation, which is tens to hundreds of milliseconds
per attempt — a wide, deliberately expensive window. With a source budget of 10 failures, an
attacker that issues 500 parallel requests from one address has all 500 admitted before any
`recordFailure()` lands. The consequences are exactly the two the class documents against:

1. The CPU-cost bound is void. The comment at `AuthenticationService.java:101-103` states the
   throttle exists so that blocked attempts do "no key derivation", to avoid becoming "a CPU
   amplifier". Under a parallel burst it becomes one: admission is unlimited until the first
   increment completes, so the attacker buys maximum CPU per round trip.
2. The failure budget is void as a guessing limit. Effective attempts per unit time scale
   with attacker concurrency rather than with the budget. `burp`-style single-packet attacks
   and async sprays are the normal shape of real credential guessing, so this is the case the
   control most needs to survive.

This is not a theoretical reading — the project's own test encodes the overrun as acceptable
behaviour, so a fix that closes the race would break it and the current assertion hides the
defect:

```java
// src/test/java/com/example/auth/AuthenticationSelfCheck.java:225-226
        check("concurrent attempts stay within the budget (+ in-flight slack)",
                admitted.get() <= budget + threads);
```

With `budget = 3` and `threads = 16` (lines 197-201), the assertion permits 16 admissions
where 3 are allowed. A rate limiter whose reference behaviour is "atomic check-and-consume in
one step" (the single-script decrement the `implementing-api-rate-limiting-and-throttling`
reference implementation uses for exactly this reason) must never admit more than the budget
allows; slack of `+ threads` is not slack, it is the bypass.

The single map operations are genuinely careful — `isBlocked` and `penalise` each use one
`compute`, the `Counter` is immutable, and there is no torn read. The defect is at the level
of the *budget protocol*, which spans two method calls, not inside either one.

**Fix:**

Consume the attempt at admission time, inside the same atomic `compute` that makes the
decision, so the decision is made on post-decrement state. `recordFailure()` then no longer
needs to charge (charging eagerly is correct because a successful login refunds the charge):

```java
// src/main/java/com/example/auth/LoginThrottle.java
    /**
     * Atomically consumes one attempt from each budget and decides whether the
     * attempt may proceed. The decision is made on post-decrement state, so a
     * parallel burst cannot all be admitted against the same remaining budget.
     */
    public java.util.Optional<Block> admit(String canonicalUsername, String source) {
        Instant now = clock.get();
        if (reserve(bySource, source, now, sourceFailureBudget, sourceCoolOff)) {
            return java.util.Optional.of(Block.SOURCE);
        }
        if (reserve(byAccount, canonicalUsername, now, accountFailureBudget, accountCoolOff)) {
            return java.util.Optional.of(Block.ACCOUNT);
        }
        return java.util.Optional.empty();
    }

    /** One atomic compute: spend an attempt, then decide on the spent counter. */
    private boolean reserve(Map<String, Counter> table, String key, Instant now, int budget, Duration coolOff) {
        boolean[] refused = new boolean[1];
        table.compute(key, (k, existing) -> {
            Counter counter = (existing == null || existing.isExpired(now, window)) ? new Counter(now) : existing;
            if (counter.isBlocked(now) || counter.failures() >= budget) {
                refused[0] = true;
                return counter.withFailure(now, budget, coolOff);
            }
            return counter.withFailure(now, budget, coolOff);
        });
        return refused[0];
    }

    /** A charged attempt that turned out to be valid is refunded; see SEC-06. */
    public void recordFailure(String canonicalUsername, String source) {
        // No-op: both dimensions were already charged atomically in admit().
    }
```

`Counter.withFailure` already does the right thing for this protocol — it sets
`blockedUntil = now.plus(coolOff)` exactly when the count reaches the budget
(`LoginThrottle.java:199-203`) — so no change to the counter is needed. Also update
`checkConcurrentBudget` to assert `admitted.get() <= budget`, otherwise the regression remains
untested.

### SEC-02: Per-source budget is keyed on a caller-supplied address that is only format-validated

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/auth/InputPolicy.java:108`

`canonicalSource` validates that the supplied string *looks like* an IP literal and then uses
it verbatim as the throttle key (`LoginThrottle.java:104`, `penalise(bySource, source, ...)`).
Nothing in the component establishes that the value is the peer address of the connection; it
is whatever the embedding caller passes.

**Vulnerable code:**

```java
// src/main/java/com/example/auth/InputPolicy.java:92-109
    public static Optional<String> canonicalSource(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > SOURCE_MAX_LENGTH) {
            return Optional.empty();
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex && c != '.' && c != ':') {
                return Optional.empty();
            }
        }
        boolean v6 = raw.indexOf(':') >= 0;
        boolean v4 = raw.indexOf('.') >= 0;
        if (v6 == v4) {
            return Optional.empty();
        }
        return (v4 ? isIpv4(raw) : isIpv6(raw)) ? Optional.of(raw) : Optional.empty();
    }
```

**Why it is a problem:**

`isIpv4`/`isIpv6` accept any syntactically valid address, so an attacker can present a
different one per attempt. IPv6 alone supplies far more than the throttle can track: each
distinct presented address gets its own fresh 10-failures-per-15-minutes budget, so the
per-source dimension — the dimension the README presents as the primary brake — enforces
nothing once the attacker controls the value. The component's own README acknowledges this as
a residual risk (source-address provenance, `X-Forwarded-For`-style input), which is honest,
but the consequence is that the throttle's headline control silently degrades to the
per-account budget, and it degrades *only* under attack, with no alarm and no signal in the
audit log that the source values are attacker-chosen. The audit sink compounds the loss of
value: `LogSanitizer.maskSource` reduces an address to a `/24` or `/48` prefix, so the
recorded history cannot be used to reconstruct the spray either.

This is a boundary-trust defect rather than a coding mistake, but it is the difference between
the control working and not working, and the code offers the embedding application no way to
get it wrong — `authenticate(username, password, source)` accepts the string with no
indication that it must be transport-derived.

**Fix:**

Make the provenance unrepresentable at the type level and refuse header-derived values. Bind
the limiter to the connection, and keep a client-invisible fallback limit:

```java
// src/main/java/com/example/auth/InputPolicy.java
    /**
     * Canonicalises a peer address that MUST come from the transport boundary
     * (e.g. HttpExchange.getRemoteAddress() / SocketConnection), never from
     * X-Forwarded-For or any other client-controllable header. Values that
     * cannot be attributed to a connection must not reach the throttle: pass
     * Optional.empty() and let the caller supply a non-spoofable key instead.
     */
    public static Optional<String> canonicalPeerAddress(InetSocketAddress peer) {
        if (peer == null || peer.getAddress() == null) {
            return Optional.empty();
        }
        return canonicalSource(peer.getAddress().getHostAddress());
    }
```

and lower the surviving, non-spoofable dimension so that it is a real limit on its own — for
example `new LoginThrottle(10, 10, Duration.ofMinutes(15), Duration.ofMinutes(15),
Duration.ofMinutes(15), Instant::now)` at `LoginThrottle.java:60-63` — since with an
evadable source key the account budget is the only enforced constraint. Where the component
is deployed behind a proxy, the trusted proxy's address must be the limiter key or the proxy
must be trusted to rewrite it; that constraint belongs in the README's control list, not only
in its residual-risk list.

### SEC-03: Unauthenticated attacker can fill the throttle tables and force fail-closed refusal of all logins

- **Severity:** Medium
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/example/auth/LoginThrottle.java:142`

The capacity guard bounds memory, which is correct, but its enforcement mechanism is to deny
authentication attempts. Because table entries are created by *unauthenticated* activity at a
per-key granularity the attacker chooses (see SEC-02), reaching the cap is an unauthenticated,
cheap operation, and the resulting state refuses logins from every address not already
tracked.

**Vulnerable code:**

```java
// src/main/java/com/example/auth/LoginThrottle.java:142-148
    private boolean atCapacity(Map<String, Counter> table, String key, Instant now) {
        if (table.size() < MAX_TRACKED_KEYS || table.containsKey(key)) {
            return false;
        }
        purgeExpired(table, now);
        return table.size() >= MAX_TRACKED_KEYS && !table.containsKey(key);
    }
```

with `MAX_TRACKED_KEYS = 50_000` at `LoginThrottle.java:33` and the `Block.CAPACITY` refusal
returned to the caller at `LoginThrottle.java:95-97`.

**Why it is a problem:**

`purgeExpired` removes only entries whose 15-minute window has elapsed, so an attacker who
sends 50 000 attempts with distinct well-formed IPv6 literals — one request each, no valid
credentials required, no per-destination cost beyond a map insert — pins `bySource` at the cap.
From then until the entries age out, `atCapacity` returns true for every genuine user whose
address is not already in the table, and `attempt()` returns `AuthenticationResult.failure()`
before any credential work (`AuthenticationService.java:100-106`). That is a complete
authentication outage sustained by roughly 50 000 cheap requests, and it is self-inflicted by
the fail-closed design: the throttle converts its own memory-pressure condition into a
denial-of-service against the very users it protects. Failing closed is the right choice for
a *suspected* attack on a keyed budget; it is the wrong choice for exhaustion of the
attacker-populated key space, where the innocent majority is refused and the attacker — whose
keys are already resident — is not.

Two secondary effects make it easier to reach and more expensive to recover from: `purgeExpired`
is a full `O(n)` iteration over 50 000 entries executed on the request path each time the cap
is hit, so the attacker's request rate is amplified into CPU work on every refused attempt, and
the same condition also silently drops bookkeeping in `penalise` (`LoginThrottle.java:160-165`),
so failures that do get processed stop being recorded.

**Fix:**

Do not deny genuine attempts because the table is full — evict to make room, and reserve the
CAPACITY refusal for a condition the attacker cannot induce. Eviction should prefer expired
entries, then the oldest window:

```java
// src/main/java/com/example/auth/LoginThrottle.java
    /**
     * Capacity guard. Being at capacity must never refuse a genuine login, because
     * the key space is populated by unauthenticated traffic. Expired entries are
     * reclaimed first; if the table is still full the oldest window is evicted,
     * which costs the attacker's oldest tracking entry, not a real user's login.
     */
    private boolean atCapacity(Map<String, Counter> table, String key, Instant now) {
        if (table.size() < MAX_TRACKED_KEYS || table.containsKey(key)) {
            return false;
        }
        purgeExpired(table, now);
        if (table.size() < MAX_TRACKED_KEYS) {
            return false;
        }
        String oldest = null;
        Instant oldestStart = null;
        for (Map.Entry<String, Counter> entry : table.entrySet()) {
            Instant start = entry.getValue().windowStart();
            if (oldestStart == null || start.isBefore(oldestStart)) {
                oldestStart = start;
                oldest = entry.getKey();
            }
        }
        // Evict at most a bounded slice per call so a sustained flood cannot turn
        // each request into a full-table scan plus mass removal.
        if (oldest != null) {
            table.remove(oldest);
        }
        return false;
    }
```

The eviction scan is still `O(n)`; if the cap must be enforced under flood, replace it with a
insertion-ordered structure (e.g. a `LinkedHashMap` guarded by one lock, or a bounded Caffeine
style window) so eviction is `O(1)`. If a hard refusal remains required for memory safety,
gate it on a rate limit over *new key creation* (one new source key per N attempts) so the
attacker cannot steer the table toward saturation, and surface saturation as an `ERROR`-class
operational event rather than a silent generic failure.

### SEC-04: Decoy record does not match real verification cost, leaving a username-enumeration oracle

- **Severity:** Medium
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `src/main/java/com/example/auth/PasswordHasher.java:38`

The decoy exists so that "an attempt on an unknown username costs what an attempt on a known
username costs" (`PasswordHasher.java:69-72`). It is built once, at construction, from a
random secret of the *maximum permitted password length*, hashed at *this instance's*
configured iteration count:

**Vulnerable code:**

```java
// src/main/java/com/example/auth/PasswordHasher.java:34-51
    public PasswordHasher(int iterations) {
        this.iterations = InputPolicy.requireInRange("iterations", iterations, MIN_ITERATIONS, MAX_ITERATIONS);
        byte[] decoySalt = new byte[SALT_LENGTH];
        random.nextBytes(decoySalt);
        char[] decoySecret = new char[InputPolicy.PASSWORD_MAX_LENGTH];
        for (int i = 0; i < decoySecret.length; i++) {
            // Random, process-local, never persisted: this is not a credential
            // anybody can use, only a cost-matching target for unknown accounts.
            decoySecret[i] = (char) ('!' + random.nextInt(90));
        }
        try {
            this.decoyRecord = new CredentialRecord(decoySalt, derive(decoySecret, decoySalt, this.iterations), this.iterations);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 is unavailable in this JRE", e);
        } finally {
            Arrays.fill(decoySecret, '\0');
        }
    }
```

Real verification takes neither of those values:

```java
// src/main/java/com/example/auth/PasswordHasher.java:59-66
    public boolean verify(char[] password, CredentialRecord record) throws GeneralSecurityException {
        byte[] derived = derive(password, record.salt(), record.iterations());
        try {
            return MessageDigest.isEqual(derived, record.hash());
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }
```

**Why it is a problem:**

The two paths diverge on both cost inputs.

*Iteration count.* The decoy always uses `this.iterations` (`DEFAULT_ITERATIONS`, 210 000),
while a known account uses `record.iterations()` read from the store — which
`CredentialRecord` accepts as low as `MIN_ITERATIONS` (100 000; see SEC-05). A record at the
floor completes in roughly half the wall-clock time of the decoy. Any store whose records were
written with a lower count, or which is migrated from an older parameter set, reintroduces a
clean unknown-vs-known timing separation, and it separates in the direction that identifies
existing accounts.

*Password length.* PBKDF2's per-iteration work includes the password block derived from the
secret, so cost grows with secret length. The decoy is always 256 characters; the submitted
password may be as short as 12 (`InputPolicy.PASSWORD_MIN_LENGTH`). An attacker who submits a
12-character password therefore sees the unknown-account path cost *more* than the
known-account path, and can classify by response time with a handful of samples per username.

Because the throttle's `Block` decision is taken before any derivation
(`AuthenticationService.java:99-106`) and both negative outcomes already return the same
`AuthenticationResult.failure()` and near-identical audit records
(`AuthenticationService.java:131-136`), response time is the *only* remaining channel that
distinguishes an existing username from a non-existent one — which is precisely the leak the
decoy was added to close. The README lists "Iteration-count timing" as a residual risk; the
length term is a second, separate divergence the code does not currently address.

**Fix:**

Make the decoy's cost a function of the attempt, not of construction time: match the submitted
password's length, and match the iteration count that the known-account path would have used.

```java
// src/main/java/com/example/auth/PasswordHasher.java
    /**
     * Performs the same key derivation against a process-local decoy so an attempt
     * on an unknown account costs what an attempt on a known account costs. The
     * decoy secret is generated at the SAME LENGTH as the submitted password and
     * uses the SAME iteration count, so neither length nor iteration count leaves a
     * known/unknown timing separation.
     */
    public void verifyAgainstDecoy(char[] password, int recordIterationsIfKnown) throws GeneralSecurityException {
        char[] sameLength = new char[password.length];
        for (int i = 0; i < sameLength.length; i++) {
            sameLength[i] = (char) ('!' + random.nextInt(90));
        }
        int count = recordIterationsIfKnown > 0 ? recordIterationsIfKnown : iterations;
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        try {
            boolean ignored = MessageDigest.isEqual(derive(password, salt, count), derive(sameLength, salt, count));
            if (ignored) {
                // Unreachable for any realistic input; kept so the branch is not elided.
                throw new GeneralSecurityException("decoy collision");
            }
        } finally {
            Arrays.fill(sameLength, '\0');
        }
    }
```

The caller must then pass the count a known-account verification *would* have used, which
means the unknown-account branch has to use a single canonical count that equals what the
store actually contains — `AuthenticationService.attempt()` should call
`hasher.verifyAgainstDecoy(password, hasher.currentIterations())` and `CredentialRecord` must
refuse any count other than that value (SEC-05), so the two paths cannot drift apart again. If
records with mixed counts must be supported, the alternative is to re-hash on read and emit a
new record at the canonical count. Generating a fresh random secret per attempt adds
`SecureRandom` work to the unknown-account path; if that measurably over-costs it, cache one
secret per password length rather than reintroducing a fixed 256-character secret.

### SEC-05: Credential records are accepted with an iteration count below the documented policy floor

- **Severity:** Low
- **CWE:** CWE-916: Password Hash with Insufficient Computational Effort
- **Location:** `src/main/java/com/example/auth/CredentialRecord.java:25`

The class javadoc explains that the iteration count is attacker-relevant and that low counts
are rejected. The floor it rejects against, however, is 100 000 — while the component's own
documented standard is `DEFAULT_ITERATIONS = 210_000`, commented as "OWASP's 2023 floor for
PBKDF2-HMAC-SHA512".

**Vulnerable code:**

```java
// src/main/java/com/example/auth/CredentialRecord.java:25-26
        InputPolicy.requireInRange("record iterations", iterations,
                PasswordHasher.MIN_ITERATIONS, PasswordHasher.MAX_ITERATIONS);
```

with `MIN_ITERATIONS = 100_000` and `DEFAULT_ITERATIONS = 210_000` at
`PasswordHasher.java:24-26`.

**Why it is a problem:**

A store that hands this component a 100 000-iteration record is accepted silently, so the
offline work factor protecting every password in that store is 2.1× below the baseline the
component cites as its requirement — and `hash()` never re-upgrades it, because verification
derives with `record.iterations()` rather than the current parameter
(`PasswordHasher.java:60`). The upper bound is not the problem: the check correctly blocks a
tampered record claiming one iteration, which is the attack the comment describes. The problem
is that the accepted band is wide enough to sit under policy, and nothing surfaces the drift,
so a migration or a store-side default change lowers the security of all future verifications
with no error and no log line. This also directly enables the iteration-count half of SEC-04.
Severity is Low rather than Medium because the affected state requires a misconfigured or
migrated store, and because `hash()` — the normal creation path — always writes the compliant
count.

**Fix:**

Set the accepted floor to the baseline the component claims, so a below-baseline record is a
loud construction failure rather than a silent weakening. `CredentialRecord.java:25-26` needs no
edit — it already defers to `PasswordHasher.MIN_ITERATIONS`, so closing the gap is a one-constant
change:

```java
// src/main/java/com/example/auth/PasswordHasher.java
    /** OWASP's 2023 floor for PBKDF2-HMAC-SHA512 is 210 000 iterations. */
    public static final int DEFAULT_ITERATIONS = 210_000;
    /** No record may be verified below the baseline the component itself claims. */
    static final int MIN_ITERATIONS = DEFAULT_ITERATIONS;
    static final int MAX_ITERATIONS = 10_000_000;
```

If the deployment genuinely must verify legacy records while it migrates, do not widen the
floor: verify them and fail the login with an `ERROR`-class audit event only for accounts
below the baseline, driven by an explicit migration window, so the weakening is bounded in
time and visible in the log.

### SEC-06: Successful login discards the account's entire failure history

- **Severity:** Low
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/main/java/com/example/auth/LoginThrottle.java:119`

`recordSuccess` deletes the whole per-account counter rather than retiring the failures the
successful attempt legitimately supersedes, and its `source` parameter is accepted and never
used — the compiler-visible signal that the method's contract is not what its signature
claims.

**Vulnerable code:**

```java
// src/main/java/com/example/auth/LoginThrottle.java:108-121
    /**
     * Clears the account counter after a successful attempt, so a legitimate user
     * who mistyped a few times is back to a full budget.
     *
     * <p>The source counter is deliberately <em>not</em> cleared. An attacker who
     * holds one valid account of their own would otherwise reset the per-source
     * budget at will and guess against other accounts indefinitely from the same
     * address. The cost is that a source which accumulated failures keeps them
     * until the window elapses; that is bounded and self-healing, whereas the
     * bypass would not be.</p>
     */
    public void recordSuccess(String canonicalUsername, String source) {
        byAccount.remove(canonicalUsername);
    }
```

**Why it is a problem:**

The reasoning for not clearing the *source* counter is sound, and the code documents it well.
The gap is that the same argument applies one notch in to the account counter, and once SEC-01
and SEC-02 are fixed the per-account budget becomes the only constraint that an attacker
cannot steer: it is keyed on the username under attack, which the attacker cannot change
without switching targets. `remove()` discards the accumulated *evidence of sustained
pressure* on that name entirely, so the account returns to a full budget with no memory of
how close it came to the cool-off threshold, and there is no graduated response available —
the mechanism is all-or-nothing between "100 % clean" and "cooled off".

The concrete shape this leaves open: an attacker who owns one valid credential (their own
account, or a colleague's) can interleave successful logins for that account with a slow spray
against a target, and although that does not clear the *target's* counter, it does mean the
system has no way to distinguish "50 failures then a good login for that user" from "50
failures then an unrelated good login", because both collapse the state to empty. Combined
with SEC-01's fix — which charges attempts rather than failures — this also refunds nothing
back to the budget that the reservation protocol needs to keep.

Severity is Low because there is no path by which an attacker clears a *victim's* cool-off:
clearing requires authenticating as that victim, at which point the cool-off is the lesser
problem. It is reported as a defect in the control's design rather than an exploitable bypass.

**Fix:**

Retire only the charge that the success explains, keep the window, and make the signature
match the behaviour:

```java
// src/main/java/com/example/auth/LoginThrottle.java
    /**
     * A successful authentication retires the failures that preceded it for THIS
     * account, but keeps the window and any active cool-off, so the account cannot
     * be returned to a pristine budget by a single good login. The source counter
     * is deliberately not cleared (see below), and source is validated so a future
     * change cannot silently ignore it.
     *
     * <p>The source counter is deliberately <em>not</em> cleared. An attacker who
     * holds one valid account of their own would otherwise reset the per-source
     * budget at will and guess against other accounts indefinitely from the same
     * address.</p>
     */
    public void recordSuccess(String canonicalUsername, String source) {
        java.util.Objects.requireNonNull(source, "source");
        Instant now = clock.get();
        byAccount.computeIfPresent(canonicalUsername, (k, existing) -> {
            if (existing.isBlocked(now) || existing.isExpired(now, window)) {
                return existing == null ? null : existing;
            }
            return existing.retireFailures();
        });
    }
```

with a `Counter` method that clears the count but preserves the window start, and keeps
`blockedUntil`:

```java
// src/main/java/com/example/auth/LoginThrottle.java
        Counter retireFailures() {
            return new Counter(windowStart, 0, blockedUntil);
        }
```

If the intent really is to forget the account's history on success, then delete the unused
`source` parameter so the API stops advertising a source dimension it does not consult, and
record a `SUCCESS`-class audit event whenever a cleared counter had crossed, say, half the
budget — that half-budget signal is the piece of state `remove()` currently destroys.

## 6. Verified Controls and Checks With No Finding

The following were examined and hold up. Each was checked by reading the implementation, not
by executing it, and several are corroborated by `AuthenticationSelfCheck.java`.

**Password storage and verification**

- `PBKDF2WithHmacSHA512` via the JDK's `SecretKeyFactory`, not a hand-rolled KDF, and no
  non-standard cipher, mode or padding anywhere (`PasswordHasher.java:22`, `:91-99`).
- 16-byte per-record salt from `SecureRandom`, 512-bit derived key; both lengths are enforced
  on record construction, so a truncated salt or short verifier cannot be loaded
  (`PasswordHasher.java:27-28`, `CredentialRecord.java:19-24`).
- Iteration count is bounded on both sides and an out-of-range value throws rather than
  clamping; a tampered record claiming one iteration is rejected outright
  (`InputPolicy.requireInRange`, `CredentialRecord.java:25-26`).
- `MAX_ITERATIONS = 10_000_000` is itself a DoS guard against a record that would make
  verification pathologically expensive.
- Comparison uses `MessageDigest.isEqual`, which is constant-time in the JDK implementation;
  there is no early-exit byte comparison (`PasswordHasher.java:62`).
- Iteration counts are not secret and are not treated as such — they are stored in the record
  and echoed in `toString()`, which is correct.
- Plaintext exposure is minimised end to end: passwords are `char[]`, `PBEKeySpec` copies are
  cleared in `finally` via `spec.clearPassword()`, the derived key is zeroed after comparison,
  the decoy secret is zeroed, and the caller zeroes the buffer in `finally`
  (`PasswordHasher.java:49`, `:63-65`, `:95-98`; `AuthenticationService.java:91-95`).
- `hash()` refuses out-of-policy lengths before deriving anything, so an oversize secret
  cannot be enrolled (`PasswordHasher.java:83-85`).

**Randomness and session identifiers**

- Session identifiers are 32 bytes (256 bits) from `SecureRandom`, base64url without padding,
  giving the documented 43 characters — comfortably above the 128-bit floor for session tokens
  (`SessionRegistry.java` `TOKEN_BYTES`, `InputPolicy.SESSION_ID_LENGTH`).
- The registry stores only the SHA-256 digest of the identifier, so a store dump or log leak
  does not yield usable session tokens; lookups are digest-to-digest
  (`SessionRegistry.java` `digest(identifier)`).
- `issue()` always mints a new identifier on successful authentication and
  `resumeSession`/`validate` never mint, so there is no session-fixation path
  (`AuthenticationService.java:138-144`, `:164-165`).
- Validate/refresh/expiry happen inside a single `sessions.compute(...)`, so a session cannot
  be concurrently validated past its expiry or double-refreshed; expiry requires either idle
  or absolute timeout to have elapsed (`SessionRegistry.java` `validate`, `Session.isExpired`).
- Shape checking is applied before any map lookup, and `invalidate` is shape-gated, so
  attacker-controlled identifier strings cannot reach the table as unnormalised keys
  (`InputPolicy.isWellFormedSessionId`, `SessionRegistry.java:173-174`).
- Idle and absolute timeouts are both validated positive and ≤ 7 days, with the absolute
  timeout required to be at least the idle timeout, so a misconfiguration cannot create a
  session that never expires (`SessionRegistry.java:53-57`).
- Session cap of 100 000 with purge-before-refuse bounds memory without unbounded growth.

**Cookie handling**

- `__Host-session` prefix with `Secure`, `HttpOnly`, `Path=/`, `SameSite=Strict` — the
  prefix's own requirements (Secure, no `Domain`, `Path=/`) are all satisfied, and `SameSite`
  is a value that Chrome still honours rather than the ignored `None` (`SessionCookie.java:24-38`).
- `setCookieHeader` refuses any value that is not a canonical 43-character session id and any
  `Max-Age` outside `(0, 604800]`, so neither response splitting nor an absurd lifetime is
  reachable through this method; there is no path that concatenates attacker text into the
  header (`SessionCookie.java:26-36`).
- Not a vulnerability but worth flagging to the deployment: `Max-Age` may legitimately be set
  to 7 days while the registry's default absolute timeout is 8 hours
  (`SessionRegistry.java:53`). The mismatch fails closed — the session dies first and the
  cookie becomes inert — so it is a usability/config-drift footgun rather than a security
  defect. `clearCookieHeader()` exists, which is required for logout.

**Input validation and enumeration resistance**

- Usernames are length-checked and allow-listed to ASCII alphanumerics plus `. _ - @ +`, must
  start and end alphanumeric, and are lowercased with `Locale.ROOT` — an allow-list rather than
  a deny-list, and the `Locale.ROOT` choice avoids the Turkish-I identity-collapse that could
  otherwise alias two accounts (`InputPolicy.canonicalUsername`).
- Validation happens before the store lookup, the throttle key space and the log, so rejected
  values cannot become throttle keys or audit fields at all
  (`AuthenticationService.java:78-85`).
- Every failure path returns the same `AuthenticationResult.failure()` — a static singleton
  with one generic message — and `toString()` masks the username and exposes the session id
  only through `sessionId()`, so no response-side or exception-side channel distinguishes
  unknown account from bad password from invalid input (`AuthenticationResult.java`).
- `AuthEvent.Outcome` distinguishes `UNKNOWN_ACCOUNT` from `BAD_CREDENTIALS` only in the
  audit log, which is operator-facing and never rendered to the client
  (`AuthenticationService.java:133-134`).
- The `char[]` overload is the only credential entry point, and the buffer is zeroed even on
  the exception paths.

**Audit log integrity and confidentiality**

- The log file is created `0600` inside a directory created `0700`; if either already exists
  with permissions that are broader than required, construction throws instead of proceeding,
  and both checks use `NOFOLLOW_LINKS` so a symlink cannot satisfy them
  (`FileAuthEventLog.java:43-44`, `prepareDirectory`, `:150-152`).
- The log is opened `WRITE, APPEND, NOFOLLOW_LINKS` and must be a regular file, so a
  pre-planted symlink cannot redirect writes and a truncated replacement cannot silently drop
  history (`FileAuthEventLog.java:155-156`).
- The permission-check-then-open sequence at `:150-156` is technically a TOCTOU window, but it
  is not exploitable here: the parent directory is `0700` and owner-only, so an actor able to
  swap the file is already the file's owner or root, at which point the file's permissions
  confer nothing. Reported as no-finding rather than a defect for that reason.
- `rotate()` moves to `<file>.1` and re-applies `0600` to the rotated generation; `Files.move`
  preserves the source's `0600`, so the post-move `setPermissions` is belt-and-braces and there
  is no world-readable interval (`FileAuthEventLog.java:181-193`). Total footprint is capped at
  `2 × maxBytes` with `maxBytes` bounded to `[64 KiB, 1 GiB]`, so the log cannot fill the volume.
- Writes are serialised under `writeLock` and flushed per record, so concurrent attempts cannot
  interleave within a record or lose a just-granted authentication to a crash window
  (`FileAuthEventLog.java:163-177`).
- Log forging is not possible: `LogSanitizer.escape` escapes `"` and `\` and maps every byte
  below `0x20` and above `0x7e` to `.`, so CR/LF cannot split a record and quotes cannot inject
  a field boundary, whatever the client sent (`LogSanitizer.escape`). The `...` truncation
  marker can push a field a few bytes past `MAX_FIELD_LENGTH = 64`, which is cosmetic.
- No secret material can reach the log by construction: `AuthEvent` has no field able to hold a
  password or a session id; `render()` emits only timestamp, event, outcome, masked username,
  keyed correlation id, masked source and a short detail; `CredentialRecord.toString()`,
  `Session.toString()` and `AuthenticationResult.toString()` all redact their sensitive members,
  so an accidental `+ record` or `%s`-style interpolation does not leak
  (`FileAuthEventLog.render`, `CredentialRecord.java:41-45`).
- Correlation ids are HMAC-SHA256 with an injected key (`≥ 16` bytes enforced), truncated to 12
  base64url characters ≈ 72 bits — enough to group attempts on one account without letting the
  log's short account space be enumerated offline. The `Mac` is guarded by `synchronized`
  around `reset()`/`doFinal()`, so concurrent correlations cannot mix digests
  (`FileAuthEventLog.java:211-222`).
- When no correlation key is supplied the fallback is a 32-byte `SecureRandom` key that is
  zeroed in `finally`; nothing is hardcoded, and `withDefaults()` is honest in its javadoc that
  correlation then does not survive restarts (`FileAuthEventLog.java:78-103`).
- Audit failure is fail-closed at the security boundary: a `SUCCESS` that cannot be recorded
  invalidates the session it just issued and returns failure, rather than granting an
  unrecorded authentication (`AuthenticationService.java:146-153`). The narrower
  `audit(...)` helper swallows `AuditException` on failure paths, which is the right
  asymmetry — a logging outage must not amplify into an authentication outage, while a
  granted authentication must not go unrecorded.

**Throttle mechanics that are sound**

- Each individual table operation is correctly atomic: `isBlocked` and `penalise` each use one
  `compute`, and `Counter` is immutable, so there is no torn or partially-updated counter
  visible to a reader (`LoginThrottle.java:123-135`, `:167-170`, `:173-204`).
- Counters are window-scoped and self-expiring, with `isExpired` deliberately defined so an
  active cool-off is never aged out early (`LoginThrottle.java:195-197`).
- `withFailure` saturates at `Integer.MAX_VALUE` instead of overflowing, and starts the cool-off
  exactly when the count reaches the budget (`LoginThrottle.java:199-203`).
- All budget and duration parameters are range-checked at construction (budgets `1..1000` and
  `1..10000`; every duration positive and ≤ 1 day), so a zero or negative window cannot produce
  a silently-permanent block (`LoginThrottle.java:51-70`).
- The clock is injectable, which is why the timing behaviour above is testable at all.
- The decision to do no key derivation for a blocked attempt is correct and prevents the
  throttle itself from becoming the CPU amplifier (`AuthenticationService.java:100-106`).

**Absence of other risk classes**

- No SQL, NoSQL, LDAP or OS command execution; no `Runtime.exec`, `ProcessBuilder`, shell, or
  database driver anywhere in the component.
- No deserialisation of any kind: no `ObjectInputStream`, no JSON/XML/YAML parsing, no JNDI
  lookup, and no `Class.forName` or reflective instantiation from input.
- No template rendering, no HTML output, no outbound network call, no file upload, and no path
  built from user input — the only filesystem path is the operator-supplied log destination,
  which is `toAbsolutePath().normalize()`d and whose parent is permission-enforced
  (`FileAuthEventLog.java:68`, `prepareDirectory`).
- No JWT, no cookie parsing (only header rendering), no cryptographic protocol implementation,
  and no use of `MD5`/`SHA-1`/`DES`/`ECB`/`NULL` anywhere.
- No hardcoded credentials, keys, tokens or default accounts: `InMemoryCredentialStore` is
  empty by default, the decoy secret is process-local and zeroed, and the correlation key is
  injected.
- Supply chain: `pom.xml` declares zero runtime dependencies and pins
  `maven-compiler-plugin` to `3.13.0`, with no `<repositories>`, no plugin executions and
  nothing downloaded at build time beyond the compiler itself. There is no dependency to
  typosquat or to inherit a CVE from.
- Source-address validation (`isIpv4`/`isIpv6`) is hand-rolled and lenient — the IPv6 branch
  accepts up to 7 groups with compression, and the check requires exactly one of `:` or `.` —
  but its output is confined to a throttle key and a masked log field drawn from a
  `[0-9a-fA-F.:]` allow-list, so leniency here cannot produce injection. Reported as
  no-finding; the *provenance* problem with `source` is SEC-02.
- `AuthenticationSelfCheck.java` was read as a specification of intended behaviour rather than
  executed. Its 44 checks cover the budget, cool-off, session, cookie, log-permission and
  masking behaviours credibly; the one check that misstates a security property is
  `checkConcurrentBudget`, reported under SEC-01.
