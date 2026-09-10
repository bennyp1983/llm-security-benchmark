# Security review — employee portal authentication module

**Scope:** every file in this folder — 12 main sources under `src/main/java/com/portal/auth/`, the
130-check `AuthVerification` suite, `run.sh`, `tools/mutation-check.py`, `README.md`.
**Method:** per the `review-code-for-security-vulnerabilities` workflow — full read of every file,
keyword-driven selection of specialised library skills (applied one at a time), then a per-behaviour
review against OWASP Top 10 / CWE knowledge for anything no skill covered.

The module is unusually well-built: the password-guessing control (pre-hash lock gate, decoy hashing
for timing parity, generic wording, `MessageDigest.isEqual`, `char[]` wiping, iteration-count DoS
cap) is correct, and the mutation check shows the test suite detects its removal. The findings below
are the residual gaps — mostly at the module's *boundaries* (admin operations, demo surface,
deployment shape), which the README already acknowledges as "known limits".

---

## Findings

### 1. `AdminService` performs privileged operations without any caller authentication or authorisation
- **Severity:** Medium
- **CWE:** CWE-862 (Missing Authorization); related CWE-306 (Missing Critical Step in Authentication)
- **Evidence:**
  - `src/main/java/com/portal/auth/AdminService.java:12` — Javadoc: the caller is expected to have
    "authenticated and authorised the operator at the portal's admin boundary; this class does not"
    enforce it.
  - `src/main/java/com/portal/auth/AdminService.java:31` — `unlock(String username, String operator)`:
    the "operator" is a caller-supplied string, not an authenticated principal; any code path holding
    a reference can release any account's lockout.
  - `src/main/java/com/portal/auth/AdminService.java:45` — `setStatus(String, UserStatus, String)`:
    same gap; an unauthorised caller can `DISABLED`/`ACTIVE` arbitrary accounts.
  - `src/main/java/com/portal/auth/AdminService.java:63` — `setPassword(String, char[], String)`:
    an unauthorised caller can reset **any** password and thereby take over any account (including,
    if ever wired, an admin's).
  - `src/main/java/com/portal/auth/AdminService.java:82` — `create(String, String, char[])` not only
    takes no authorisation but **no operator at all**; the `ACCOUNT_CREATED` audit event (line 87)
    therefore cannot attribute account creation to anyone.
- **Why it is a problem:** the class's Javadoc pushes the control out of the module, so the module is
  only safe if *every* future wiring adds an admin boundary. A single careless integration (e.g. an
  HTTP endpoint that constructs `AdminService` directly) yields trivial account takeover via
  `setPassword`. This is the highest-impact gap in the codebase.
- **Fix:** introduce an authenticated principal (e.g. a `Principal`/token-validated interface) that
  `AdminService` requires and verifies (or at minimum enforces a capability), give `create` an
  operator parameter for audit attribution, and make it a compile-time requirement rather than a
  Javadoc expectation.

### 2. No password strength or complexity policy anywhere
- **Severity:** Medium (low if a policy layer is guaranteed upstream — see README)
- **CWE:** CWE-521 (Weak Password Requirements)
- **Evidence:**
  - `src/main/java/com/portal/auth/AdminService.java:83-85` — `create` accepts any non-null, non-empty
    `char[]` (`password.length == 0` is the only check).
  - `src/main/java/com/portal/auth/AdminService.java:64-66` — `setPassword` has the identical
    non-empty-only check.
  - `src/main/java/com/portal/auth/PasswordHasher.java` — strong *storage* (PBKDF2 600k) but no
    policy layer; nothing in the module validates length, composition, or known-bad passwords.
- **Why it is a problem:** `create`/`setPassword` are the only places passwords enter the system, and
  they accept e.g. `"a"`. NIST SP 800-63B (which the README cites for throttling) requires subscriber
  verification/credential policies; a 1-character password defeats the 600k-iteration KDF in one
  guess. The README defers the policy to the caller, but then this module's own admin surface is
  unbounded.
- **Fix:** add a `PasswordPolicy` (minimum length, ideally a blocklist check) that
  `create`/`setPassword` enforce, or make it a constructor-injected dependency so no caller can
  bypass it.

### 3. Hardcoded demo credentials in source (and printed to stdout)
- **Severity:** Low (explicitly demo; becomes Critical if this app is ever run unmodified against a
  real store)
- **CWE:** CWE-798 (Use of Hardcoded Credentials); the stdout print is CWE-532 (Insertion of
  Sensitive Information into Log File / Output)
- **Evidence:**
  - `src/main/java/com/portal/auth/PortalAuthApp.java:24` —
    `private static final String DEMO_PASSWORD = "Correct-Horse-9";`
  - `src/main/java/com/portal/auth/PortalAuthApp.java:47` — `System.out.println("Demo account: demo / "
    + DEMO_PASSWORD + ...)` prints the live password to stdout on every startup.
  - `src/main/java/com/portal/auth/PortalAuthApp.java:60` —
    `hasher.hash(PasswordHasher.toChars("another-secret-passphrase"))` (seeded `jchen`).
  - `src/main/java/com/portal/auth/PortalAuthApp.java:63` —
    `hasher.hash(PasswordHasher.toChars("left-the-company"))` (seeded `terminated.user`).
  - `run.sh:35` — the `demo` target pipes `Correct-Horse-9` to the app via `printf` (visible in the
    script and in process arguments while running).
  - `README.md:14` and `src/test/java/com/portal/auth/AuthVerification.java:81,814-820` — the same
    passwords are documented and embedded in the test fixture.
- **Why it is a problem:** per secret-scanning practice these are exactly the strings gitleaks flags:
  credentials in the repo, one of them also emitted to a log-like stream (stdout). Anyone who runs
  `run.sh app` gets valid portal credentials for free, and the passwords remain valid as long as the
  store is persistent.
- **Fix:** seed demo accounts from environment variables or a local file the user creates, or accept
  them as arguments; never print a password to stdout (`Demo account: demo` is enough); keep the
  README's account table without the password column.

### 4. Piped-input fallback reads passwords with echo enabled
- **Severity:** Low
- **CWE:** CWE-200 (Exposure of Sensitive Information) — the Javadoc frames it as
  CWE-540 (insecure design of the convenience fallback)
- **Evidence:**
  - `src/main/java/com/portal/auth/PortalAuthApp.java:116` —
    `private final Console console = System.console();` (null when stdin is a pipe).
  - `src/main/java/com/portal/auth/PortalAuthApp.java:129-133` — `readPassword` falls back to
    `promptLine(prompt)` (line 133, implementation at line 137) when no console exists, i.e. piped
    or redirected stdin **echoes the password** back into the terminal, shell history, or whatever
    captured the pipe.
- **Why it is a problem:** the README mitigates the blast radius by seeding low-value demo passwords,
  but the fallback exists in a class that will presumably also be pointed at a real store; any
  scripted invocation against real credentials would expose them to anyone watching the session.
- **Fix:** when `console == null`, either refuse to prompt for a password (take it via an environment
  variable or file descriptor with a documented mechanism), or read the line from a pre-opened
  echo-off fd. At minimum, log a conspicuous warning when the fallback is used.

### 5. Lockout state is per-JVM in memory: budget multiplication and reset-on-restart
- **Severity:** Low
- **CWE:** CWE-770 (Uncontrolled Resource Consumption, via N × 5 guesses) and CWE-639
  (User Lockout, state lost/replicated by deployment shape)
- **Evidence:**
  - `src/main/java/com/portal/auth/LoginAttemptTracker.java:46` —
    `private final Map<String, Counter> counters = new ConcurrentHashMap<>();` — process-local state,
    no shared backend.
  - `src/main/java/com/portal/auth/LoginAttemptTracker.java:44` —
    `MAX_TRACKED_ACCOUNTS = 100_000` bounds the *memory* a spray can force, not the *guess budget*.
  - README "Known limits": "N app instances multiply the guess budget by N".
- **Why it is a problem:** behind a load balancer with N replicas the effective per-account threshold
  is 5N; a rolling restart mid-attack clears the attacker's entire history. The 100k LRU bound
  (line 121, line 189) is a sound memory control but is orthogonal to this.
- **Fix:** before multi-instance deployment, back the tracker with the shared store the README
  already points at (SQL/Redis) via the existing seam; until then, run exactly one instance or
  enforce the threshold at the edge (per-IP/session) as well.

### 6. Account lockout is itself a harassment/DoS vector
- **Severity:** Low (explicitly accepted trade-off in README)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Evidence:**
  - `src/main/java/com/portal/auth/LoginPolicy.java:21-22` —
    `DEFAULT = new LoginPolicy(5, 15 min, 15 min, 0)`: any anonymous caller can lock a named account
    for 15 minutes with 5 wrong passwords.
  - `src/main/java/com/portal/auth/AuthenticationService.java` — the correct password is also refused
    while locked (documented as deliberate; verified by `lockoutBlocksCorrectPasswordToo`).
- **Why it is a problem:** five requests per victim per day can make an employee's sign-in
  permanently fail during business hours. The module's own design decisions (no lock extension,
  self-clearing expiry) already minimise this; what remains is the intrinsic cost the README accepts.
- **Fix:** layer a per-source-address or per-session throttle in front (edge WAF/gateway) so 5
  guesses cost more than 5 anonymous requests; keep `permanentLockAfterLocks` as the escalation
  knob. No code change in this module is required for the accepted baseline.

### 7. `AuditEvent` sanitisation is bypassable by direct construction, and `detail` is rendered raw
- **Severity:** Low
- **CWE:** CWE-74 (Improper Neutralization of Special Elements in Output) / CWE-117 (Improper Output
  Encoding)
- **Evidence:**
  - `src/main/java/com/portal/auth/AuditEvent.java:12` — the record's public canonical constructor
    takes `username` and `detail` **unsanitised**; only the factory
    `src/main/java/com/portal/auth/AuditEvent.java:30` (`AuditEvent.of`) applies `safe()` — and only
    to `username`, never to `detail`.
  - `src/main/java/com/portal/auth/AuditEvent.java:66-69` — `toString()` prints `detail` verbatim, so
    an event built with a newline, ANSI escape, or bidirectional-override character in `detail`
    forges extra log lines or reorders the rendered text in the consuming viewer.
  - `src/main/java/com/portal/auth/AuditEvent.java:46` — `safe()` strips only `c < 0x20 || c == 0x7F`;
    Unicode line separators (U+2028/U+2029) and bidi overrides (U+202E) pass through, which some
    log viewers render as newlines or direction flips.
- **Why it is a problem:** every current call site is safe (details are built from internal enums and
  counters; the only external string, `operator`, goes through `safe()` in `AdminService.java:41,55,
  74`), so this is a latent, not active, flaw — but the class's own contract ("one event renders to
  exactly one line", README "Log forging") is guaranteed only for `of()`-built events, and the public
  constructor lets any future caller break it.
- **Fix:** either make the canonical constructor private and force all construction through a
  sanitising factory that applies `safe()` to **both** fields, or have `toString()` run `detail`
  through the same sanitiser; extend `safe()` to also map U+2028/U+2029/U+202A-202E (and
  U+2060-2064) to `'?'`.

### 8. `mutation-check.py` builds shell commands with `shell=True`
- **Severity:** Informational (local developer tool, no external input today)
- **CWE:** CWE-78 (OS Command Injection)
- **Evidence:**
  - `tools/mutation-check.py:88-90` — `subprocess.run("javac -d %s $(find %s/src/main/java ...)" %
    (build, work), shell=True, ...)`.
  - `tools/mutation-check.py:96-97` — `subprocess.run("java -cp %s com.portal.auth.AuthVerification"
    % build, shell=True, ...)`.
- **Why it is a problem:** the substituted values are a `tempfile.mkdtemp` path (random) and `SEC`
  (the script's own directory), so there is no live injection path; the risk is that the pattern
  invites a future edit that interpolates user-controlled text (a branch name, a mutant label) into
  the same command string.
- **Fix:** pass argument lists to `subprocess.run` (no `shell=True`); replace the `find` in the javac
  invocation with `glob`/`os.walk`.

---

## Skills applied (per the router workflow, one at a time)

1. **`performing-cryptographic-audit-of-application`** — audited `PasswordHasher` (KDF choice,
   iteration count, salt, key length, constant-time comparison, RNG), and swept the tree for
   hardcoded secrets, weak crypto, and key material in logs/outputs. Findings fed into #3 and
   confirmed the hashing layer sound (see "Verified clean" below).
2. **`testing-api-authentication-weaknesses`** — audited the authentication/authorization surface:
   unauthenticated privileged operations (#1), weak password policy (#2), account-enumeration
   vectors (checked clean: generic wording, decoy timing, `accountExists` never rendered),
   credential-stuffing exposure (mitigated per-account; deployment-shape limits in #5/#6), and
   session-handling absence (out of scope by design, noted in README).
3. **`implementing-secret-scanning-with-gitleaks`** — applied its "secrets in source" criteria
   (hardcoded credentials, secrets in scripts/docs/CI, secrets printed to output streams) to every
   non-Java file as well; produced #3 (including `run.sh:35` and the README/test occurrences) and the
   remediation note (rotate/treat as burned if this tree is ever deployed).

**Behaviours with no matching library skill** were reviewed against general OWASP Top 10 / CWE
knowledge and are noted as such: log-injection/log-forging design (#7, CWE-74/117), brute-force and
lockout DoS design (#5/#6, CWE-307/400/639/770), timing side channels (decoy hashing and
`MessageDigest.isEqual` — verified clean), concurrency/race safety of the tracker (CWE-362 —
verified clean: all state transitions `synchronized`, 16-thread contention check passes, mutation
tests confirm the invariants are load-bearing), and dev-tooling command construction (#8, CWE-78).

---

## Verified clean (checked, no issue)

| Concern | Where | Why it holds |
|---|---|---|
| Password storage KDF | `PasswordHasher.java` (600k PBKDF2-HMAC-SHA256, 16-byte `SecureRandom` salt, 256-bit key, self-describing digest) | Meets OWASP 2023 guidance; salt is per-password random |
| Digest comparison | `PasswordHasher.java` (`MessageDigest.isEqual`) | Full-length constant-time compare, no early exit |
| Timing parity unknown vs known user | `AuthenticationService.java` (decoy `burnEquivalentWork`) | Both paths do one KDF call; suite measures ratio 1.00; removing the decoy is a detected mutant |
| Username enumeration by wording/countdown | `LoginResult.java`, `PortalAuthApp.render` | One generic message for wrong/unknown; countdown branch never reads `accountExists` (verified by mutants MUT6/MUT7) |
| Password lifetime in memory | `AuthenticationService.java`, `AdminService.java`, `PasswordHasher.java` | `char[]` wiped in `finally` on every path; `PBEKeySpec.clearPassword()` |
| DoS via tampered digest | `PasswordHasher.java` parse (refuses >5M iterations) | A crafted stored record cannot force unbounded CPU |
| Memory pressure via username spray | `LoginAttemptTracker.java:44,121,189` | 100k-entry cap with LRU eviction of unlocked entries |
| Lock held open by sustained guessing | `LoginAttemptTracker.java` (`registerFailure` does not extend an active lock) | Invariant mutation-tested (MUT2) |
| Secret leakage into audit trail | `AuthenticationService.java`, `AuditEvent.java`, `ConsoleAuditLog.java` | Audit fields structurally cannot carry candidate/digest; MUT5 (log the password) is detected; `Credential.toString` redacts the digest |
| Concurrency | `LoginAttemptTracker.java` (all transitions `synchronized`) | 16-thread contention check: one lock, no lost updates, no escape |
| Attack surface of the module itself | all files | Pure JDK in-memory: no SQL, deserialization, file, network, or TLS surface to inject into; `InMemoryCredentialStore` is heap-only by design |

**Overall assessment:** no high-severity defects in the credential-checking core — the anti-guessing
control is correctly implemented and proven load-bearing by mutation testing. The residual risk
concentrates in finding #1 (admin operations with no enforced authorisation) and #2 (no password
policy), both of which are one careless integration away from account takeover; findings #3–#8 are
low-severity boundary/hardening items, several of which the README already documents as accepted
limits.
