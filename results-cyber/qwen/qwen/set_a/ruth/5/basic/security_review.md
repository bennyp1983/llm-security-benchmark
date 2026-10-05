# Security Review: LoginService (password-based authentication, `src/LoginService.java`)

## 1. Executive Summary

This is an unusually careful authentication component. The credential store holds only a
PBKDF2-HMAC-SHA256 digest with a fresh 16-byte `SecureRandom` salt per registration and a 256-bit
key; the returned `LoginOutcome` carries no credential material; no secret is logged; usernames are
validated byte-exactly against an anchored `[A-Za-z0-9._-]{3,32}` pattern rather than folded, which
closes the Unicode/case-collision account-takeover class; candidates that `PBEKeySpec` would map
lossily (trailing NUL, unpaired surrogate) are refused so two different secrets cannot share a
digest; the stored-digest parser validates prefix, field count, base64 alphabet and salt/digest
lengths; and every refusal path deliberately pays one full key derivation so response time does not
disclose which accounts exist. I found no SQL injection, OS command injection, path traversal,
unsafe deserialisation, SSRF, hardcoded secret, or weak primitive anywhere in the source.

Eight findings remain, and they cluster in three places. First, brute-force defence: the only
throttle is a per-username counter held in a single JVM's heap, with no per-source and no
endpoint-level limit, which lets anyone deny service to any known username and lets a distributed or
multi-instance spray sail past it entirely (SEC-01). Second, work-factor policy: the class will
honour a stored digest at as little as 1,000 rounds and will happily construct a hasher at that
floor, orders of magnitude below current guidance, with no re-hash to upgrade legacy records
(SEC-04); the same `MAX_STORED_ITERATIONS` ceiling also lets a stored record demand 20,000,000
rounds of victim CPU (SEC-03). Third, information and lifecycle hygiene: the equal-work protection
silently stops holding for any digest whose stored round count is below the live policy (SEC-02),
`register()` answers `DUPLICATE_USERNAME` (SEC-05), the enrollment policy is a bare 8-character
floor that `hash()` does not even enforce (SEC-06), cleartext credentials are passed as immutable
`String`s (SEC-07), and session tokens have no lifetime or revocation story (SEC-08).

No finding is Critical: there is no pre-auth code execution, no credential disclosure from storage,
and no bypass of the digest check on the main path. The High finding is the throttle design, because
it is the component's sole brute-force control and it fails both ways -- it can be used as a
denial-of-service lever against legitimate users and it does not constrain a realistic guessing
campaign.

Counts: 0 Critical, 1 High, 3 Medium, 4 Low.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/LoginService.java` (652 lines) | Password-based login/registration: `login()`, `register()`, `PasswordHasher`, `LoginAttemptTracker`, session token, `AccountStore` boundary, demo `main` and interactive console | Credential verification and its ordering vs. lockout/validation; PBKDF2 parameters and salt/iteration handling; digest-record parsing; per-name attempt counting and lock expiry; `SecureRandom` token generation; logging of usernames; cleartext password handling in memory; unauthenticated operator `unlock` in the CLI |
| `src/LoginServiceTest.java` (715 lines, 123 checks) | Self-verifying suite (exits non-zero on failure); not shipped code but pins security properties | Asserts digest-record validation, refusal-wording uniformity, lockout/expiry/reset, token uniqueness, and five measured timing ratios; also demonstrates that a 1,000-round hasher is constructible and that low-round digests verify (`:194-201`), and that `12345678` registers (`:328-329`) |
| `README.md` | Design narrative, build/run instructions, documented limits | Claims under review: equal-work anti-enumeration, digest format, "a legacy digest at a lower round count still verifies", known absence of per-IP limits/endpoint throttling/MFA; documents the surviving `Arrays.equals` mutant |
| `out/*.class` (16 files) | Compiled output of the two sources (`javac -d out ...`) | Build artifacts only; not analysed as source, no separate findings |
| `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt` | Task/harness metadata | Not code; excluded from review |

## 3. Skills Applied

Specialised skills from the library that matched behaviours in this code, applied one at a time in
Step 3:

- **`performing-cryptographic-audit-of-application`** -- audit of `PasswordHasher`: KDF algorithm
  and parameters, salt generation and length, key size, iteration floor/ceiling, digest comparison
  method, and the hardcoded-secret sweep. Its "Weak KDF parameters are identified" criterion produced
  SEC-04; its constant-time-comparison criterion verified clean (`MessageDigest.isEqual`).
- **`testing-api-authentication-weaknesses`** -- `login()`/`register()` as an authentication
  surface: password policy, account-enumeration channels, credential-stuffing/brute-force
  susceptibility, and session-token entropy/lifetime. Produced SEC-01, SEC-05, SEC-06 and SEC-08.
- **`implementing-api-rate-limiting-and-throttling`** -- `LoginAttemptTracker` measured against that
  skill's pitfalls list, specifically "authentication endpoints need limits separate from general API
  limits" and "in-memory counters allow the limit to be bypassed by hitting a different instance".
  Produced SEC-01 and SEC-03.
- **`testing-for-sensitive-data-exposure`** -- cleartext credentials in memory, what reaches the
  logs, and what the returned `LoginOutcome` object carries. Produced SEC-07 and the demo-output
  observation in section 6.
- **`implementing-secret-scanning-with-gitleaks`** (knowledge only) -- swept `src/` for hardcoded
  credentials, API keys, tokens and connection strings. Result in section 6: no finding.
- **`testing-jwt-token-security`** -- opened and rejected. Session tokens here are opaque random
  base64url values, not JWTs; there is no signature verification or claim parsing to attack. The
  residual token concern is lifetime, reported as SEC-08 from general knowledge.

Behaviours with no matching skill in the library, reviewed against general OWASP Top 10 / CWE
knowledge instead: timing side channels and the limits of the equal-work countermeasure
(CWE-208, SEC-02); unauthenticated work amplification (CWE-400, SEC-03); the iteration floor and
missing re-hash of weak records (CWE-916, SEC-04); credential-lifetime-in-memory beyond logging
(CWE-316, SEC-07); session expiry and revocation (CWE-613, SEC-08); and the absence of any
injection / deserialization / path / network sink (CWE-89, CWE-78, CWE-22, CWE-502), checked by
reading both sources end to end.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Only brute-force control is per-username, per-process; no per-source or endpoint limit | High | CWE-307 | `src/LoginService.java:437-442` |
| SEC-02 | Equal-work timing equalization breaks for digests stored below the live work factor | Medium | CWE-208 | `src/LoginService.java:276-293` |
| SEC-03 | Every unauthenticated request is charged a full KDF run; stored record may demand 20M rounds | Medium | CWE-400 | `src/LoginService.java:323` |
| SEC-04 | 1,000-round iteration floor accepted at enrollment and verification; no re-hash upgrade | Medium | CWE-916 | `src/LoginService.java:217-224` |
| SEC-05 | `register()` returns `DUPLICATE_USERNAME`, a username-enumeration oracle | Low | CWE-204 | `src/LoginService.java:97-109` |
| SEC-06 | Enrollment policy is a bare 8-character floor, and `hash()` enforces no policy at all | Low | CWE-521 | `src/LoginService.java:333-339` |
| SEC-07 | Cleartext credentials handed across the API as immutable `String`s | Low | CWE-316 | `src/LoginService.java:627-634` |
| SEC-08 | Session tokens are minted with no expiry, server-side record, or revocation path | Low | CWE-613 | `src/LoginService.java:111-115` |

## 5. Detailed Findings

### SEC-01: Authentication throttling is scoped to username and JVM only

**Severity:** High

**CWE:** `CWE-307: Improper Restriction of the Number of Unequal Authentication Attempts`

**Location:** `src/LoginService.java:437-442` (also `:72-74`, `:454-455`, `:481-500`)

**Vulnerable code:**

```java
// src/LoginService.java:437-442
        private static final int MAX_TRACKED_ACCOUNTS = 100_000;

        private final int maxFailures;
        private final long windowMillis;
        private final long lockMillis;
        private final Map<String, Counter> counters = new ConcurrentHashMap<>();
```

**Why it is a problem:**

The map key is the username and nothing else, the map is a plain field of one `LoginService` in one
JVM, and the only gate on the login path is `tracker.isLocked(username, ...)` (`:72-74`). That
single design choice fails in two opposite directions:

1. **Account-lockout denial of service.** `recordFailure()` is reached for *any* well-formed name
   (`:88-89`), so an unauthenticated attacker who merely knows a username -- which `register()`
   hands out for free, see SEC-05 -- can spend five guesses it never intends to get right and lock
   that user out for 15 minutes, repeating indefinitely. Refusing the *correct* password
   (`LoginStatus.LOCKED`) is an availability failure an attacker triggers at will and costs nothing.
   NIST SP 800-63B recommends against exactly this kind of arbitrary reauthentication disablement
   for that reason.
2. **The throttle does not actually throttle guessing.** Because state is process-local, an attacker
   facing an `InMemoryAccountStore`-shaped deployment behind a load balancer simply spreads attempts
   across instances and sees no counter at all; `LoginAttemptTracker` has no distributed mode and no
   injection point for one. And because the counter is keyed per name, a spray of one or two
   common passwords across the whole username space -- the standard credential-stuffing shape --
   never brings any single counter near `maxFailures`. There is no per-source-IP, per-ASN, per-device
   or global endpoint limit anywhere in the file, which the README acknowledges in "Known limits".

The `MAX_TRACKED_ACCOUNTS` guard bounds memory but not the attack: 100,000 tracked names is far above
any real deployment's active-user count, and `purgeExpired()` only runs once that ceiling is already
breached.

**Fix:**

Make the counter composite (source and name) and shared, so a stranger cannot trip a victim's lock
and a spray cannot dodge the budget; keep this class as the local fast path behind a shared store.

```java
// src/LoginService.java:439-442 -- corrected
        private final int maxFailures;
        private final long windowMillis;
        private final long lockMillis;
        // Key on (source identity, username): a spray from one source cannot stay under the
        // per-account threshold, and traffic from elsewhere cannot lock a named user out.
        private final Map<AttemptKey, Counter> counters = new ConcurrentHashMap<>();
        // Shared, cross-instance state (Redis/JDBC); this map becomes a short-TTL local cache.
        private final AttemptStore shared;

        private record AttemptKey(String sourceKey, String username) {}
```

and gate the attempt on the source budget before any derivation is charged:

```java
// src/LoginService.java:72-75 -- corrected
        if (tracker.isLocked(caller.sourceKey(), username, clock.getAsLong())
                || !tracker.sourceBudgetAvailable(caller.sourceKey(), clock.getAsLong())) {
            hasher.chargeOneDerivation(password);
            // Prefer a per-source cool-down with progressive backoff over a hard account lock,
            // so guessing gets expensive without ever denying the real user their account.
            return LoginOutcome.throttled();
        }
```

Additionally: escalate delay per failure rather than flipping a 15-minute kill switch on the name,
require a CAPTCHA/MFA step before further attempts once a source is anomalous, and never return a
distinguishable `LOCKED` answer to an unauthenticated caller without also consuming
`sourceBudget` (see SEC-02 for why the answer shape matters).

### SEC-02: Equal-work anti-enumeration silently lapses for below-policy digests

**Severity:** Medium

**CWE:** `CWE-208: Observable Timing Discrepancy`

**Location:** `src/LoginService.java:276-293` (also `:299-301`, `:323`; `src/LoginServiceTest.java:469-527` measures only the equal-round case)

**Vulnerable code:**

```java
// src/LoginService.java:276-293
        public Verdict verify(String candidate, String storedDigest) {
            if (structuralRejection(candidate) != null) {
                derive(new char[0], this.dummyDigest.salt(), this.dummyDigest.iterations());
                return Verdict.NO_MATCH;
            }
            char[] password = toChars(candidate);
            if (storedDigest == null) {
                derive(password, this.dummyDigest.salt(), this.dummyDigest.iterations());
                return Verdict.NO_MATCH;
            }
            Digest stored = parse(storedDigest);
            if (stored == null) {
                derive(password, this.dummyDigest.salt(), this.dummyDigest.iterations());
                return Verdict.MALFORMED_RECORD;
            }
            byte[] derived = derive(password, stored.salt(), stored.iterations());
            return MessageDigest.isEqual(derived, stored.digest()) ? Verdict.MATCH : Verdict.NO_MATCH;
        }
```

**Why it is a problem:**

Every refusal path is charged `dummyDigest.iterations()` -- the *live policy* work factor, fixed in
the constructor at `:248-249`. The success/failure path against a known account, however, pays
`stored.iterations()`, taken from the record (`:291`). Those are the same number only while every
stored digest was written at the current policy. The README makes divergence an explicit design
feature -- "a legacy digest at a lower round count still verifies" -- and `LoginServiceTest.java:194-201`
proves the mechanism: a 1,000-round digest verifies under a 2,000-round hasher, and the test asserts
the stored count is honoured.

So after the work-factor increase the format was designed for -- the ordinary 210,000 to 600,000
migration, or any legacy row at the 1,000 floor -- the timing property is inverted for exactly the
population that matters: a login against a low-round account returns in a few milliseconds while an
unknown name still pays the full 210,000-round dummy derivation. Two or three requests per candidate
name and a median is enough to sort "account exists with an old digest" from "no such account",
which is precisely the enumeration the whole dummy-digest apparatus exists to prevent. The suite
cannot catch this: `measuredTiming()` (`src/LoginServiceTest.java:469`) builds the store and the
hasher from one shared `iterations = 60_000` (`:470`), so every timed sample has matched work by
construction and the ratio checks stay inside `[0.8, 1.3]` forever.

This is a regression of the component's headline control, introduced by a routine operational
change rather than a code edit, which is what makes it worth fixing at the code level.

**Fix:**

Pay the greater of the record's cost and the policy cost on every path, so the observable work factor
is `max(stored, policy)` and independent of the store's contents; upgrade the record opportunistically.

```java
// src/LoginService.java:291-292 -- corrected
            byte[] derived = derive(password, stored.salt(), stored.iterations());
            // Observable cost must not depend on what the store happens to hold, or a legacy
            // low-round account answers faster than an unknown name and enumeration is back.
            int padding = this.iterations - stored.iterations();
            if (padding > 0) {
                derive(new char[0], dummyDigest.salt(), padding);
            }
            return MessageDigest.isEqual(derived, stored.digest()) ? Verdict.MATCH : Verdict.NO_MATCH;
```

Then, in `login()` on `Verdict.MATCH`, re-hash with the current policy and `store.put(...)` the new
digest (the `AccountStore` boundary needs a `replace` for this), so below-policy records disappear
instead of lingering. Add a timing assertion that mixes stored rounds (`1_000` vs. `60_000`) against
a fixed policy -- that test fails against the current code, which is the point.

### SEC-03: Unauthenticated requests buy a full key derivation, with no endpoint-level cap

**Severity:** Medium

**CWE:** `CWE-400: Uncontrolled Resource Consumption`

**Location:** `src/LoginService.java:323` (also `:68-75`, `:240`, `:299-301`)

**Vulnerable code:**

```java
// src/LoginService.java:305-330
        static Digest parse(String encoded) {
            if (encoded == null) {
                return null;
            }
            String[] parts = encoded.split("\\$", -1);
            if (parts.length != 4 || !PREFIX.equals(parts[0])) {
                return null;
            }
            int rounds;
            byte[] salt;
            byte[] digest;
            try {
                rounds = Integer.parseInt(parts[1]);
                salt = DECODER.decode(parts[2]);
                digest = DECODER.decode(parts[3]);
            } catch (IllegalArgumentException e) {
                return null;
            }
            if (rounds < MIN_ITERATIONS || rounds > MAX_STORED_ITERATIONS) {
                return null;
            }
            if (salt.length < 8 || salt.length > 64 || digest.length < 16 || digest.length > 64) {
                return null;
            }
            return new Digest(rounds, salt, digest);
        }
```

**Why it is a problem:**

Two bounds combine into an unauthenticated CPU multiplier, and neither bound is checked against the
deployment's own policy.

`login()` charges a derivation *before* it learns anything about the caller: a syntactically invalid
name and a locked account each pay a full `this.iterations` run (`:68-75`, via `chargeOneDerivation`
at `:299-301`), and the default policy is 210,000 rounds, roughly 300 ms of one core on the README's
reference hardware. So a 5-byte request costs the server a few hundred milliseconds, permanently,
with no throttle in front of it -- the README lists "No rate limiting of the *whole* endpoint, no
CAPTCHA" as a known limit. That is a textbook amplification factor for cheap CPU exhaustion from a
single socket, and it is *caused* by the anti-enumeration design: the equal-work charge converts
"garbage input" into "full-price work". The equal-work property is still worth keeping; it just
cannot be paid for out of an unthrottled budget.

The second half is the ceiling. `parse()` accepts any stored round count up to
`MAX_STORED_ITERATIONS = 20_000_000` -- about 100x the policy this class defaults to, i.e. tens of
seconds per attempt -- and `login()` will execute whatever count the record declares. The store is
today an in-memory map, but the README instructs implementers to swap in a JDBC store that "keeps the
same digest format", so the round count becomes a database column. Any defect that lets an attacker
write or alter that column (a separate injection or mass-assignment bug, a mis-scoped migration job, a
shared staging/prod table) converts into a single-request CPU wedge per login for that account, and
the value is legal by this class's own validation, so nothing downstream will flag it.

**Fix:**

Tighten the accepted ceiling to a policy-derived multiple, and put a concurrency budget plus a
per-source allowance in front of the charge so the equal-work design cannot be weaponised.

```java
// src/LoginService.java:222,323 -- corrected
        // A record may be modestly ahead of policy (rollout) but never 100x, or one row = one wedge.
        private static final int MAX_STORED_ITERATIONS = 2_000_000;

        ...

                if (rounds < MIN_ITERATIONS || rounds > MAX_STORED_ITERATIONS) {
                    return null;   // caller sees MALFORMED_RECORD and the row is flagged for re-hash
                }
```

```java
// src/LoginService.java:67-75 -- corrected (budget the work, do not skip it)
    public LoginOutcome login(String username, String password) {
        // Bounded derivation pool + per-source token bucket. When the bucket is empty the request
        // is refused without charging work; that signal is about the source, not the account, so it
        // does not hand back the enumeration the dummy derivation exists to suppress.
        if (!derivationAdmission.tryAcquire(caller.sourceKey())) {
            return LoginOutcome.throttled();
        }
        try {
            if (!isWellFormedUsername(username)) {
                hasher.chargeOneDerivation(password);
                return LoginOutcome.invalidCredentials();
            }
            ...
        } finally {
            derivationAdmission.release();
        }
    }
```

Size the pool to the latency target (`pool / latency` is the sustainable attempts per second); alert
on saturation so deliberate exhaustion is visible rather than just slow.

### SEC-04: Iteration floor of 1,000 is honorable and enrollable, with no upgrade path

**Severity:** Medium

**CWE:** `CWE-916: Password Hashing with Insufficient Work Factor`

**Location:** `src/LoginService.java:217-224` (also `:243-247`, `:323`, `:202-203` of `src/LoginServiceTest.java`)

**Vulnerable code:**

```java
// src/LoginService.java:217-224
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private static final String PREFIX = "pbkdf2-sha256";
        private static final int SALT_BYTES = 16;
        private static final int KEY_BITS = 256;
        private static final int MIN_ITERATIONS = 1_000;
        private static final int MAX_STORED_ITERATIONS = 20_000_000;
        private static final int MIN_ENROLLMENT_CHARS = 8;
        private static final int MAX_CANDIDATE_CHARS = 4_096;
```

**Why it is a problem:**

`MIN_ITERATIONS` is the only work-factor guard in the class and it is used for both directions: the
constructor refuses fewer than 1,000 rounds (`:244`) and `parse()` accepts anything at or above 1,000
(`:323`). Both ends of that door are open.

*Enrollment side:* `new PasswordHasher(1_000)` is legal, and `LoginServiceTest.java:194-201` does
exactly that, so the class itself demonstrates how an operator can ship a store where every password is
protected by 1,000 rounds of HMAC-SHA256. Current public guidance for PBKDF2-HMAC-SHA256 is on the
order of 600,000 iterations (OWASP); 1,000 is ~600x below it, and PBKDF2 is the class of KDF whose
weakness is precisely that it is cheap to run on GPUs and ASICs -- the trade-off the README concedes
in "PBKDF2 is a defensible, dependency-free choice... memory-hard KDFs... resist GPU/ASIC attacks
better".

*Verification side:* a stored digest at 1,000 rounds verifies forever. Nothing in `login()` compares
`stored.iterations()` against `this.iterations`, nothing logs or flags the gap, and the
`AccountStore` interface exposes only `find`/`putIfAbsent`/`count` (`:130-138`) -- there is no
`replace`, so
even a caller that noticed cannot upgrade the record. The result is that a store mixing eras
permanently protects its oldest users with its weakest setting, which is where targeted offline
cracking goes first. `LoginServiceTest.java:202-203` confirms the boundary is the floor, not the
policy: only `$1$` is refused.

**Fix:**

Separate the two constants -- a floor low enough never to reject a legitimate legacy record, and a
policy below which records are refused-and-flagged and upgraded on next successful login -- and raise
the enrollable minimum.

```java
// src/LoginService.java:219-224 -- corrected
        private static final int SALT_BYTES = 16;
        private static final int KEY_BITS = 256;
        private static final int MIN_ITERATIONS = 1_000;        // parse floor: never reject a legacy record outright
        private static final int POLICY_ITERATIONS = 600_000;   // OWASP guidance for PBKDF2-HMAC-SHA256
        private static final int MAX_STORED_ITERATIONS = 2_000_000;
        private static final int MIN_ENROLLMENT_CHARS = 12;
```

```java
// src/LoginService.java:243-246 -- corrected: enrollment cannot be configured below policy
        public PasswordHasher(int iterations) {
            if (iterations < POLICY_ITERATIONS || iterations > MAX_STORED_ITERATIONS) {
                throw new IllegalArgumentException("iterations must be in [" + POLICY_ITERATIONS + ", "
                        + MAX_STORED_ITERATIONS + "], was " + iterations);
            }
```

and in `verify()`/`login()`, treat `stored.iterations() < POLICY_ITERATIONS` on `MATCH` as
"authenticate, then force a re-hash and a password-change prompt", with `AccountStore.replace`
added for the upgrade. If a library dependency is acceptable, prefer Argon2id over raising PBKDF2
further -- the README already reaches this conclusion, and SEC-04 is the reason it should not be left
optional.

### SEC-05: Registration discloses whether a username exists

**Severity:** Low

**CWE:** `CWE-204: Observable Response Discrepancy`

**Location:** `src/LoginService.java:97-109`

**Vulnerable code:**

```java
// src/LoginService.java:97-109
    public Registration register(String username, String password) {
        if (!isWellFormedUsername(username)) {
            return Registration.INVALID_USERNAME;
        }
        if (PasswordHasher.enrollmentRejection(password) != null) {
            return Registration.PASSWORD_REJECTED;
        }
        if (store.putIfAbsent(new Account(username, hasher.hash(password)))) {
            LOG.log(System.Logger.Level.INFO, "registered account ''{0}''", username);
            return Registration.STORED;
        }
        return Registration.DUPLICATE_USERNAME;
    }
```

**Why it is a problem:**

`putIfAbsent`'s boolean is returned verbatim to the caller, so `register()` is a clean, unlimited
existence oracle: `STORED` means the name was free, `DUPLICATE_USERNAME` means someone holds it. The
login path goes to real lengths to avoid exactly this disclosure -- a full dummy key derivation per
unknown-account attempt, a single refusal sentence for every credential-failure shape -- and
registration then answers the same question for free, with no derivation, no delay and no counter.
Anyone with a username list can reduce a spray to confirmed accounts before starting, which is the
precondition that makes SEC-01's lockout-DoS and SEC-04's weak-record targeting practical at scale.
`INVALID_USERNAME` also leaks the validator's rule set, which is minor but feeds the same probing.

Note the asymmetry in cost as well: a rejected login costs the attacker one derivation of server work,
whereas a rejected registration costs a map lookup.

**Fix:**

Answer identically and move the truth out-of-band; rate-limit the endpoint separately from login
because it is cheaper per probe.

```java
// src/LoginService.java:104-109 -- corrected
        // Store it if the name is free, but never tell the caller which happened: a registration
        // endpoint that answers DUPLICATE_USERNAME is an unthrottled enumeration oracle.
        if (store.putIfAbsent(new Account(username, hasher.hash(password)))) {
            LOG.log(System.Logger.Level.INFO, "registered account ''{0}''", username);
            notifyOwnershipVerification(username);   // e-mail/ownership challenge reaches the real owner
        } else {
            LOG.log(System.Logger.Level.INFO, "registration attempted for taken name ''{0}''", username);
        }
        return Registration.STORED_PENDING_VERIFICATION;
```

If the product genuinely needs "that name is taken", require proof of a real client first (CAPTCHA or
a per-source budget shared with `login()`), and never let the answer be cacheable or scriptable.

### SEC-06: Enrollment policy is 8 characters, and `hash()` applies no policy at all

**Severity:** Low

**CWE:** `CWE-521: Weak Password Requirements`

**Location:** `src/LoginService.java:333-339` (also `:223`, `:262-268`, `src/LoginServiceTest.java:328-329`)

**Vulnerable code:**

```java
// src/LoginService.java:333-339
        static String enrollmentRejection(String password) {
            String structural = structuralRejection(password);
            if (structural != null) {
                return structural;
            }
            return password.length() < MIN_ENROLLMENT_CHARS ? "too-short" : null;
        }
```

**Why it is a problem:**

`MIN_ENROLLMENT_CHARS` is 8 (`:223`) and that single length test is the entire password policy -- no
composition, no context/deny-list check, no breach-corpus match, which the README confirms is a known
gap. `LoginServiceTest.java:328-329` asserts that `12345678` registers successfully, so the suite
pins a purely numeric, top-of-the-list password as acceptable. Against a PBKDF2 store whose work
factor is the *only* thing standing between a dump and plaintext -- and, per SEC-04, possibly only
1,000 rounds -- an 8-character password from a breach corpus falls to a targeted dictionary on
commodity GPUs in seconds. The hashing strength buys nothing for a secret that is already in an
attacker's list.

Worse for defence-in-depth, the policy is not enforced where it matters. `register()` calls
`enrollmentRejection()`, but the public `hash(String)` at `:262-268` does not: it only checks
`structuralRejection`. A caller -- or a future refactor of the JDBC store path the README describes --
that hashes directly with `hasher.hash("a")` silently mints a storeable digest for a one-character
password. A policy that lives outside the function that produces the credential is advisory.

**Fix:**

Enforce inside `hash()` so no call path can bypass it, and raise the rule to length-plus-breach
checking.

```java
// src/LoginService.java:262-268 + 333-339 -- corrected
        public String hash(String password) {
            String rejection = enrollmentRejection(password);   // hash() is the policy boundary now
            if (rejection != null) {
                throw new IllegalArgumentException("password is not enrollable: " + rejection);
            }
            byte[] salt = randomSalt();
            ...
        }

        static String enrollmentRejection(String password) {
            String structural = structuralRejection(password);   // keep the lossy-encoding guard
            if (structural != null) {
                return structural;
            }
            if (password.length() < MIN_ENROLLMENT_CHARS) {      // MIN_ENROLLMENT_CHARS = 12
                return "too-short";
            }
            if (BREACH_CORPUS.contains(password)) {              // e.g. HIBP k-anonymity range query
                return "known-breached";
            }
            return null;
        }
```

Length beats composition here, so prefer a 12-14 character minimum plus a breach-list check over
character-class rules, and update `LoginServiceTest.java:328-329` -- that assertion currently encodes
the weakness.

### SEC-07: Cleartext credentials are carried as immutable `String`s

**Severity:** Low

**CWE:** `CWE-316: Cleartext Storage of Sensitive Information in Memory`

**Location:** `src/LoginService.java:627-634` (also `:67`, `:97`, `:262`, `:276`)

**Vulnerable code:**

```java
// src/LoginService.java:627-634
                    console.format("%s%n", service.register(username, new String(secret)));
                    break;
                case "login":
                    secret = console.readPassword("password for %s: ", username);
                    if (secret == null) {
                        return;
                    }
                    LoginOutcome outcome = service.login(username, new String(secret));
```

**Why it is a problem:**

The class clearly intends secrets to be short-lived: `derive()` takes a `char[]`, wipes it with
`Arrays.fill(password, '\0')` and clears the `PBEKeySpec` in a `finally` (`:409-412`), and
`interactive()` zeroes its buffer at `:647-649`. But every public entry point takes a `String`
(`:67`, `:97`, `:262`, `:276`), so `interactive()` converts the freshly-read `char[]` *back* into a
`String` one statement before wiping the array (`:627`, `:634`). That `String` is backed by an
internally unreachable, non-wipeable array; its content stays resident until the garbage collector
happens to reclaim it, and it is exactly the shape of object memory scrapers, heap dumps, `jmap`
snapshots, crash cores and JVM `-XX:+HeapDumpOnOutOfMemoryError` artefacts are written to find. The
zeroing at `:647-649` therefore protects a buffer that no longer holds anything interesting while the
actual copy floats away.

The same applies to every caller: once `toChars(candidate)` copies the `String` inside
`chargeOneDerivation`/`verify`, the original remains under the caller's control, out of reach of the
class's wiping logic. This is Low rather than Medium because exploitation requires an adjacent
primitive (heap read, dump disclosure, debugger) -- but the mitigation the author clearly wanted is
being defeated at the API boundary, not in the crypto.

**Fix:**

Keep the credential in a `char[]` from input to derivation and wipe at the boundary.

```java
// src/LoginService.java:634 -- corrected: hand the char[] over, do not re-materialise a String
                    LoginOutcome outcome = service.login(username, secret);   // login() wipes on return

// src/LoginService.java:67 -- corrected signature
    public LoginOutcome login(String username, char[] password) {
        try {
            ...
        } finally {
            Arrays.fill(password, '\0');   // the only credential copy is now zeroed
        }
    }
```

Where a `String` API must be preserved for compatibility, document that callers should pass a
`char[]`-backed secret, and never log or store it; do not call `String.intern()` on credentials.

### SEC-08: Session tokens have no lifetime or revocation story

**Severity:** Low

**CWE:** `CWE-613: Insufficient Session Expiration`

**Location:** `src/LoginService.java:111-115`

**Vulnerable code:**

```java
// src/LoginService.java:111-115
    private String newSessionToken() {
        byte[] token = new byte[32];
        random.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }
```

**Why it is a problem:**

The entropy is right -- 256 bits from `SecureRandom`, correctly base64url-encoded, one fresh value per
`SUCCESS` (`:83`) -- so this is not a predictability finding. What is missing is everything after
issuance. Nothing records the token: there is no session table, no expiry field, no `issuedAt`, no
scope, and no revoke path anywhere in the file. `login()` hands back an opaque string and forgets it,
so within this component a token is valid forever, cannot be rotated, and cannot be withdrawn --
including when the account it was issued to is subsequently locked out by the tracker or when the
user's password is changed or an operator calls `unlock()` (`:513-516`). A stolen token from any
channel (proxy logs, browser history, a leaked `session token:` line at `:637`) therefore never
expires, and the only "revocation" this layer can offer is deleting the `Account` -- which would also
destroy the user.

The README scopes this out -- "this code authenticates the user and hands back a token, it does not
manage sessions, cookies, or HTTP" -- and that is a fair architectural boundary. It is still reported
because the deliverable *is* an authentication component whose contract says "authenticated", and a
caller that trusts the returned value indefinitely gets an unbounded session with no way to end it.
The `AccountStore` injection point shows the pattern the token needs: define the boundary now, so the
deployment plugs in a store instead of bolting one on.

**Fix:**

Issue a bounded, recorded session with an injected clock -- the same style already used for lockout
timers -- and revoke on lockout, password change and unlock.

```java
// src/LoginService.java:111-115 -- corrected
    private Session newSession(String username) {
        byte[] token = new byte[32];
        random.nextBytes(token);
        long now = clock.getAsLong();
        // Server-side record: bounded TTL, revocable, and invalidated when the account is locked,
        // unlocked or its password changes. Opaque value, no claims in it -- still not a JWT.
        Session session = new Session(Base64.getUrlEncoder().withoutPadding().encodeToString(token),
                username, now + sessionTtlMillis);
        sessions.put(session.token(), session);
        return session;
    }

    private record Session(String token, String username, long expiresAtMillis) {
        boolean live(long nowMillis) {
            return nowMillis < expiresAtMillis;
        }
    }
```

Then call `revokeAllFor(username)` from `recordFailure()` when a lock trips, from `unlock()`, and from
any future password-change path, and have the HTTP layer carry the token in a `Secure`/`HttpOnly`/
`SameSite` cookie rather than a URL.

## 6. Verified Controls and Checks With No Finding

Confirmed correct in code, or checked and found absent/inapplicable:

- **KDF construction (`performing-cryptographic-audit-of-application`).** `PBKDF2WithHmacSHA256`
  (`:217`) with a fresh 16-byte `SecureRandom` salt per registration (`:219`, `:266`, `:396-399`) and
  a 256-bit derived key (`:220`); salt is generated, never reused, never attacker-supplied at
  enrollment. No MD5 or SHA-1 used as a password digest, no DES/Blowfish, no AES/ECB, no
  `java.util.Random`, no `currentTimeMillis`-seeded or otherwise predictable RNG -- `SecureRandom`
  appears only at `:45` and `:236`. No hand-rolled cryptography.
- **Digest comparison.** `MessageDigest.isEqual(derived, stored.digest())` (`:292`); the JDK
  specifies this does not short-circuit on the first differing byte. The README's mutation-testing
  section honestly documents that swapping in `Arrays.equals` leaves the suite green because the leak
  is tens of nanoseconds under a ~85 ms derivation; that residual sub-measurable leak is the same
  class of issue as SEC-02 but is four-plus orders of magnitude smaller than the divergence SEC-02
  describes, so it is not filed separately.
- **Credential wiping inside the crypto.** `derive()` clears the `PBEKeySpec` and zeroes the `char[]`
  in a `finally` block (`:409-412`), so it holds even on `GeneralSecurityException`. (The `String`
  boundary that defeats this at the API level is SEC-07.)
- **Username validation and matching.** `USERNAME_PATTERN` is anchored and byte-exact:
  `Pattern.compile("[A-Za-z0-9._-]{3,32}")` (`:35`, `:39`), used at both `register()` (`:98`) and
  `login()` (`:68`), with no case or Unicode folding at the guard *or* at the lookup (`:146`, `:151`)
  -- `"Alice"` and `"alice"` are distinct accounts and a homoglyph name is refused rather than
  resolving onto a real one. The pattern is a single bounded character class, so there is no
  backtracking/ReDoS exposure, and the alphabet cannot carry CR/LF, which keeps the two log calls
  (`:86`, `:105`) free of log-injection.
- **Lossy-encoding guard.** `structuralRejection()` (`:350-376`) refuses null, empty, >4,096 chars,
  trailing NUL and unpaired surrogates before any derivation, applied in `register()` (`:101`),
  `verify()` (`:277`) and `chargeOneDerivation()` (`:300`). This closes a real authentication-bypass
  class: `PBEKeySpec` maps every unpaired surrogate to `'?'`, so without the guard `"q"`+U+D800,
  `"q"`+U+DC00 and `"q?"` would share one digest and any of them would sign in as a user who enrolled
  with another. The rationale is documented at `:341-349` and the test suite derives through the raw
  JCE to prove the collision is real.
- **Stored-record parsing.** `parse()` (`:305-330`) rejects null, wrong field count, wrong prefix,
  non-numeric and out-of-range round counts, invalid base64, salts outside 8-64 bytes and digests
  outside 16-64 bytes; `verify()` maps that to `MALFORMED_RECORD` and still pays a derivation
  (`:286-290`), and `login()` logs a warning naming the account (`:85-87`) without throwing. A
  malformed row cannot crash a login, be mistaken for an empty digest, or verify.
- **Session token entropy and uniqueness.** 32 bytes from `SecureRandom`, base64url without padding
  (`:111-115`); five successive grants for the same account yield five distinct tokens, asserted at
  `src/LoginServiceTest.java:400-411`.
  (Lifetime/revocation is SEC-08.)
- **What reaches the logs and the returned object.** Only usernames are logged (`:86`, `:105`); no
  password, salt, digest or token appears in any log statement. `Account` holds `username` + digest
  only (`:118`); `LoginOutcome` carries status, username and token with no credential field
  (`:175-206`); `granted()` is defined as `status == LoginStatus.SUCCESS` (`:190-192`), so a `LOCKED`
  or malformed-record answer can never be mistaken for success. The `InMemoryAccountStore` keeps no cleartext
  (`:141-158`).
- **Hardcoded-secret sweep (`implementing-secret-scanning-with-gitleaks`).** Grepped both sources for
  API keys, bearer/pat/ghp tokens, private-key blocks, connection strings and password literals: the
  only credential-shaped values are the README's fictitious demo secrets (`correct horse`,
  `Tr0ubador&x9`) used in the demo and tests. Nothing to rotate, nothing to remove.
- **Demo output.** `demo()` prints the stored digest to stdout at `:553` (plus the session token at
  `:637`, interactively). Reviewed under `testing-for-sensitive-data-exposure` and **not filed**: it
  is a `System.out.println` in the scripted demo path, not a log statement, HTTP response, or
  persisted artefact, and the README states accounts live in memory only. It would become a real
  CWE-532 finding the moment that line is copied into a service that logs at INFO -- worth deleting
  before reuse.
- **No injection, deserialization, path or network sink.** Read end to end: no JDBC, `Statement`, or
  string-built query (`AccountStore` is a `ConcurrentHashMap`; the README's JDBC text is guidance, not
  code), no `Runtime.exec`/`ProcessBuilder`, no `ObjectInputStream`/`readObject`/XStream/SnakeYAML, no
  `File`/`Paths.get`/`zip slip` handling, no `URL`/`HttpClient`/`RestTemplate`. SQL injection
  (CWE-89), OS command injection (CWE-78), unsafe deserialization (CWE-502), path traversal (CWE-22)
  and SSRF have no reachable surface in this code.
- **JWT-specific skills not applicable.** No `io.jsonwebtoken`/`Jwts`, no `decode`/`verify` of
  tokens, no `Bearer` header handling: tokens are opaque random strings, so there is no signature or
  claim logic to attack.
- **Lockout state machine is correct on its own terms.** `recordFailure()` re-arms the window on
  expiry, refuses to extend an active lock, and trips at `maxFailures` (`:481-500`); `isLocked()`
  reads `lockedUntil` under the counter's monitor (`:458-466`); `recordSuccess()` removes state on a
  successful authentication and `unlock()` requires an operator call (`:509-516`), so neither reset
  is reachable by an attacker. Locks apply to unknown names too (a failure is recorded at `:88-89`
  regardless of whether the account exists), so the `LOCKED` answer never proves an account exists --
  which is why the differing wording at `:195` is not itself an enumeration finding.
- **Clock injection reviewed, not filed.** `LoginService` takes a `LongSupplier` clock (constructors
  at `:47-57`; production defaults to wall-clock time, tests use a mutable clock). A backward NTP step
  extends an active lock; a forward step can reset the failure window early. Worth using a monotonic
  clock in a real deployment, but it is an operational nit rather than a defect in this code.
- **`out/*.class`.** Build artifacts of the two reviewed sources per the README build commands; not
  decompiled and not reviewed line-by-line. Regenerate them from `src/` before shipping so they cannot
  drift from audited source.
- **Test suite as evidence.** The 123 checks genuinely pin the controls above (digest validation,
  refusal-wording uniformity across all failure shapes, lockout/window/lock expiry, per-registration
  salt uniqueness, token uniqueness, concurrent-attempt behaviour, timing ratios), which is why the
  findings above are concentrated in *policy* and *scope* rather than in the correctness of the crypto
  or the validation logic. The two places where the suite encodes a weakness rather than a control are
  `src/LoginServiceTest.java:194-201` (honours a 1,000-round digest) and `:328-329` (accepts
  `12345678`) -- see SEC-04 and SEC-06.
