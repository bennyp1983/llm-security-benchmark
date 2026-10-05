# Security Review — Employee Portal Authentication (Java 17)

Scope: all Java sources under `src/com/example/portal/auth/` (10 files, ~1000 LOC), plus
`README.md`. Compiled artefacts in `out/` were not reviewed (build output of the same
sources). Review performed with the `review-code-for-security-vulnerabilities` router
skill; specialised skills applied are listed at the end.

---

## 1. What the code does

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `PortalApp.java` | Console front end: arg parsing, `login` / `add-user` commands, masked prompts | Credential input, `char[]` wiping, privileged account-creation command, store path from env/CLI, exit codes |
| `AuthenticationService.java` | Credential verification, in-memory lockout, registration | Authentication decision, brute-force throttling, transparent rehash-on-login, global lock |
| `AuthenticationResult.java` | Outcome + single user-facing message | Uniform failure messages (anti-enumeration) |
| `PasswordHasher.java` | PBKDF2-HMAC-SHA256 hash/verify, dummy-hash timing equalisation | KDF parameters, salt generation (`SecureRandom`), constant-time compare, parsing of stored hash fields |
| `PasswordPolicy.java` | Rules for new passwords | Length bounds, deny-list, username-in-password check; converts `char[]` to `String` |
| `FileCredentialStore.java` | TSV-file credential store, atomic rewrite | File parsing, serialisation of untrusted fields, POSIX permissions, temp-file handling |
| `EmployeeRecord.java` | One employee row | Username normalisation (`Locale.ROOT`), hash omitted from `toString()` |
| `CredentialStore.java` | Store interface | — |
| `AuditLog.java` | One line per sign-in attempt to a `PrintStream` | Log record construction from untrusted username; no persistence |
| `AuthenticationTests.java` | Dependency-free self-test harness | Test-only fixture passwords |

Behaviour keywords derived: *password storage / KDF*, *authentication & brute-force
throttling*, *user enumeration & timing*, *credential file storage and permissions*,
*record/log injection*, *access control on administrative functions*, *sensitive data in
memory*, *error handling*.

There is **no SQL, no deserialization, no network/TLS, no XML/XXE, no template rendering,
no web surface and no hardcoded production secret** in this codebase — those classes of
issue were looked for and are absent (the only literal passwords are fixtures inside
`AuthenticationTests.java:38-88`, which is acceptable for a test harness).

---

## 2. Findings

### F-01 (High) — Account lockout can never trigger from the shipped CLI; brute force is effectively unthrottled
**CWE-307: Improper Restriction of Excessive Authentication Attempts** (also CWE-654)

- Evidence: `AuthenticationService.java:32` (`private final Map<String, FailureState> failures = new HashMap<>();` — process-local state), `AuthenticationService.java:25` (`MAX_FAILED_ATTEMPTS = 5`), `PortalApp.java:25` (`MAX_PROMPTS = 3`), `PortalApp.java:47-48` (a fresh `AuthenticationService` is constructed on every process start).

Every `java ... PortalApp login` invocation builds a brand-new service, so the failure
counters start empty. The CLI then offers at most **3** guesses per process, while lockout
requires **5** consecutive failures. The threshold is therefore unreachable through the
only front end that ships: an attacker scripting `while true; do ... PortalApp login; done`
gets unlimited guesses at the full-speed PBKDF2 rate, and `LOCKED_OUT` is dead code outside
the unit tests. The README's "Online guessing is throttled" security property does not hold
for this deployment, and its "Limits" section frames the in-memory counter as a
*clustering* concern only, which understates it.

Fix: persist the failure counter and lockout deadline with the record (e.g. two extra
columns in the TSV, or a shared store), keyed by username *and* source identity, so it
survives process restart. Make `MAX_PROMPTS` ≥ nothing — the throttle must live below the
front end, not in the prompt loop. Add a per-attempt delay that grows with the failure
count.

---

### F-02 (High) — `add-user` performs no authentication or authorisation
**CWE-306: Missing Authentication for Critical Function** (also CWE-269, CWE-620)

- Evidence: `PortalApp.java:53-55` (`case "add-user": System.exit(addUser(service, rest));`), `PortalApp.java:102-126` (no caller identity is established anywhere), `PortalApp.java:109` (`String role = args.length > 2 ? args[2] : "employee";`), `AuthenticationService.java:94-101` (`register` overwrites any existing record for that username).

Anyone who can execute the program with write access to `employees.tsv` can create an
account, **reset an existing employee's password without knowing the old one**, and assign
themselves an arbitrary `role` string (`admin`, `security`, …) that the downstream
authorization layer is documented to trust (`EmployeeRecord.role()`, README "Design"). This
is a direct vertical-privilege-escalation and account-takeover path — the classic
"administrative function with no function-level check".

Fix: require an authenticated session with an administrative role before `add-user`
(re-authenticate the operator through `AuthenticationService.authenticate` and check the
role), restrict `role` to a validated enum, separate "create user" from "reset password",
and rely on OS-level ownership of the store file as defence in depth rather than as the
only control.

---

### F-03 (Medium) — Record injection into the credential store via unvalidated `displayName` / `role`
**CWE-74: Injection (CWE-93: CRLF Injection / record delimiter injection)**

- Evidence: `PasswordPolicy.java:28-30` validates tabs/newlines **only for the username**; `PortalApp.java:107-109` takes `displayName` and `role` straight from `argv` with no validation; `AuthenticationService.java:97-98` builds the record from them; `FileCredentialStore.java:95-96` writes them with `String.join("\t", …)` and `FileCredentialStore.java:101` writes one list element per line.

A `displayName` (or `role`) containing a newline is written verbatim, so the next load
parses the injected text as an additional record line. Example:

```
add-user jdoe $'Jane Doe\tanalyst\ttrue\nceo\tpbkdf2_sha256$210000$<attacker salt>$<attacker hash>\tCEO\tadmin' analyst
```

produces a second, fully-formed `ceo` row whose password the attacker chose. A tab alone
is enough to shift fields and either corrupt the row (`FileCredentialStore.java:55-58`
throws and the whole store fails to load — a denial of service on every subsequent login)
or silently redefine `active`. Where `add-user` is fed from an HR feed or a wrapper script
that constrains only the username, this bypasses that constraint entirely.

Fix: validate every field that reaches the store — reject tabs, CR, LF and leading `#` in
`username`, `displayName` and `role` inside `PasswordPolicy.validate` / the
`EmployeeRecord` constructor — or switch the store to a format with real escaping (JSON
lines, or a database).

---

### F-04 (Medium) — Plaintext passwords are materialised into immutable `String`s, defeating the `char[]` hygiene
**CWE-316: Cleartext Storage of Sensitive Information in Memory** (also CWE-226)

- Evidence: `PasswordPolicy.java:39` — `String lower = new String(password).toLowerCase(Locale.ROOT);`
- Evidence: `PortalApp.java:180-181` — `String line = readLine(prompt); return line == null ? null : line.toCharArray();`

The codebase goes to real trouble to keep passwords in wipeable `char[]` buffers
(`PortalApp.java:91`, `PortalApp.java:131-136`, `PasswordHasher.java:120`), and the README
advertises this. Both lines above create *two* uncontrollable `String` copies of the
cleartext (`new String(password)` and its lowercase form; the `BufferedReader` line) that
survive on the heap until GC and land in any heap dump or core file. One flaw undoes the
whole control for the registration path and for every non-TTY login.

Fix: perform the length/deny-list/username checks over the `char[]` directly (lowercase in
place into a scratch `char[]`, compare, then `Arrays.fill` it). For the non-console path,
read bytes into a reusable buffer rather than through `BufferedReader.readLine()`, or
document that non-TTY use is unsupported and refuse to run.

Related, lower severity: when `System.console()` is null the password is **echoed to the
terminal** (`PortalApp.java:160`, `PortalApp.java:176-182`) — the warning is printed, but
the program still accepts the credential (CWE-549). Prefer failing closed.

---

### F-05 (Medium) — KDF parameters are read back from the stored hash without bounds checking
**CWE-1188 / CWE-916: Insufficient Computational Effort — and CWE-400 on the upper bound**

- Evidence: `PasswordHasher.java:81` — `iterations = Integer.parseInt(parts[1]);`
- Evidence: `PasswordHasher.java:87` — only `iterations <= 0 || salt.length == 0 || expected.length == 0` is rejected; there is **no minimum** iteration count, **no minimum salt length** and **no maximum**.
- Evidence: `PasswordHasher.java:90` — `derive(password, salt, iterations, expected.length * 8);` — the derived key length is taken from the stored value.

A single tampered or corrupted row makes the verifier follow the attacker's parameters:
`iterations=1` with a 1-byte hash means a *one-in-256* chance that any password verifies,
and `iterations=2147483647` turns one login attempt into an unbounded CPU burn (amplified
by F-11, which holds the service lock throughout). `needsRehash`
(`PasswordHasher.java:96-107`) only repairs the record *after* a successful verification,
so it does not prevent the downgrade.

Fix: enforce floors and ceilings before deriving — e.g. `iterations` in
`[100_000, 4_000_000]`, `salt.length >= 16`, `expected.length == KEY_BITS/8` — and treat
anything outside as a corrupt record (fail closed, alert), not as a verifiable hash.

---

### F-06 (Medium) — PBKDF2 work factor is below current OWASP guidance, and the deny-list is unreachable dead code
**CWE-916: Use of Password Hash With Insufficient Computational Effort; CWE-521: Weak Password Requirements**

- Evidence: `PasswordHasher.java:29` — `DEFAULT_ITERATIONS = 210_000` with `ALGORITHM = "PBKDF2WithHmacSHA256"` (`PasswordHasher.java:23`). OWASP's Password Storage Cheat Sheet puts 210,000 at PBKDF2-**HMAC-SHA512**; for HMAC-**SHA256** the current recommendation is 600,000. The chosen constant is roughly a third of guidance for the algorithm actually in use.
- Evidence: `PasswordPolicy.java:16-18` lists deny-list entries (`"password"`, `"letmein"`, `"qwerty"`, `"123456"`, …) that are all **shorter than 12 characters**, while `PasswordPolicy.java:31-34` rejects anything under `MIN_PASSWORD_LENGTH = 12` first, and `PasswordPolicy.java:40` matches the whole password exactly (`FORBIDDEN.contains(lower)`). The deny-list check can therefore never fire; `passwordpassword` and `123456789012` both pass the policy.

Fix: raise to ≥600,000 iterations (the self-describing format already supports migration via
`needsRehash`), or better, move to Argon2id/scrypt, which PBKDF2 cannot match against GPU
cracking. Make the deny-list a *substring/normalised* check against a real breached-password
corpus (HIBP k-anonymity, as the README itself suggests) rather than an exact-match set of
short strings. Consider a secret pepper held outside the store file.

---

### F-07 (Low) — Audit records are forgeable through the username field
**CWE-117: Improper Output Neutralization for Logs**

- Evidence: `AuditLog.java:26-28` — `out.println(… + " auth " + status + " user=" + (username.isEmpty() ? "<blank>" : username));`

`EmployeeRecord.normalizeUsername` (`EmployeeRecord.java:24-27`) only trims and lowercases;
embedded `\n`, `\r` and formatting characters survive, and `authenticate` is a public API
(`AuthenticationService.java:52`) reachable by any embedder — the CLI's line-based read is
the only thing limiting it today. An attacker who controls the username can inject whole
fabricated audit lines (e.g. a forged `auth GRANTED user=ceo`) and destroy the evidentiary
value of the log.

Fix: strip or escape CR/LF and control characters before logging, and cap the logged
username length; better, emit structured (JSON) log events.

---

### F-08 (Low) — Audit trail is ephemeral and non-integrity-protected
**CWE-778: Insufficient Logging**

- Evidence: `PortalApp.java:48` — `AuditLog.toStream(System.err)`; `README.md` explicitly recommends `2>/dev/null` to keep audit lines out of the transcript.

Sign-in outcomes go to stderr and nowhere else: there is no file, no syslog, no rotation,
no tamper resistance, and the documented usage discards them. Neither brute-force detection
nor post-incident investigation is possible. Note also that no source identity (host, PID,
terminal) is recorded — only the username.

Fix: write to an append-only file or syslog with owner-only permissions, include a source
identifier, and never document discarding it.

---

### F-09 (Low) — Unbounded failure map: memory exhaustion via arbitrary usernames
**CWE-770: Allocation of Resources Without Limits or Throttling**

- Evidence: `AuthenticationService.java:32` and `AuthenticationService.java:118-122` — `failures.computeIfAbsent(key, k -> new FailureState())` inserts an entry for **every** attempted username, including ones that do not exist; entries are only removed on success (`:82`) or after the lockout expires (`:114`), and expired entries below `MAX_FAILED_ATTEMPTS` are never swept.

A long-running embedding of `AuthenticationService` that is fed distinct usernames grows the
map without limit. Fix: bound the map (LRU / size cap) and evict entries whose last failure
is older than the lockout window.

---

### F-10 (Low) — Lockout keyed only by username enables targeted denial of service
**CWE-645: Overly Restrictive Account Lockout Mechanism**

- Evidence: `AuthenticationService.java:56-61`, `AuthenticationService.java:103-116`.

Where F-01 is fixed and lockout becomes real, five deliberate bad guesses lock a named
colleague out for 15 minutes, repeatable indefinitely. The README acknowledges this. Fix:
combine username throttling with per-source throttling and exponential backoff rather than
a hard lock, or require an out-of-band unlock.

---

### F-11 (Low) — Global lock held across PBKDF2 and disk I/O
**CWE-667: Improper Locking (availability); CWE-400**

- Evidence: `AuthenticationService.java:56` — `synchronized (this)` wraps the store lookup, the ~100 ms PBKDF2 derivation (`:66`) *and* the full-file rewrite on rehash (`:85-87`).

All authentication is serialised on one monitor, so a handful of concurrent attempts (or one
attempt against a record with a huge `iterations` value, F-05) stalls every other user.
Fix: hold the lock only around the failure-counter mutations; perform derivation and I/O
outside it.

---

### F-12 (Low) — Unhandled runtime exceptions leak stack traces and absolute paths
**CWE-209: Generation of Error Message Containing Sensitive Information**

- Evidence: `FileCredentialStore.java:78-80` throws `UncheckedIOException("Could not persist credential store " + file, …)` with the absolute path; `PasswordHasher.java:118` throws `IllegalStateException`; `PortalApp.java:61` catches only `IOException`.

A failed rehash-on-login (`AuthenticationService.java:86`) or a read-only store directory
therefore terminates the JVM with a stack trace on stderr, exposing filesystem layout and
internal class structure, and turning a *successful* authentication into a crash. Fix:
catch `RuntimeException` at the top level, print a generic message, log the detail to the
audit sink, and treat a failed opportunistic rehash as non-fatal.

---

### F-13 (Low) — Store location is taken from an environment variable with no validation
**CWE-15: External Control of System or Configuration Setting**

- Evidence: `PortalApp.java:31-32` — `System.getenv().getOrDefault("PORTAL_STORE", DEFAULT_STORE)`; `PortalApp.java:34-41` (`--store`); `FileCredentialStore.java:45-47` silently treats a missing file as an **empty store**.

Anything that can set `PORTAL_STORE` (a wrapper script, a setuid/sudo context, a CI job)
redirects authentication to a store it controls, or to a nonexistent path where every login
fails closed but `add-user` silently creates a shadow store. Fix: resolve the store path
from a root-owned config file for privileged deployments, refuse relative paths, and
distinguish "store missing" from "store empty" (fail loudly on the former for `login`).

---

### F-14 (Low) — Permissions are enforced only on files this program creates
**CWE-732: Incorrect Permission Assignment for Critical Resource**

- Evidence: `FileCredentialStore.java:110-118` (`restrictPermissions`, applied to the temp file at `:100`), `FileCredentialStore.java:44-48` (`load()` reads whatever it finds, unconditionally).

A store file that already exists with `0644`, or one created by a different tool, is read
without complaint, and the "owner-only permissions" property is silently skipped on
non-POSIX filesystems (`:115-117` swallows the exception). Password hashes readable by all
local users is exactly the input to an offline cracking attack. Fix: on load, check owner
and mode and refuse (or warn loudly) if group/other have any access; on Windows, set an
explicit ACL rather than silently doing nothing.

---

### F-15 (Informational) — Residual timing side channels in the enumeration defence
**CWE-208: Observable Timing Discrepancy**

The dummy-hash design (`PasswordHasher.java:37`, `:66-70`) is sound in principle, but:
- `DUMMY_HASH` is always generated at `DEFAULT_ITERATIONS` (`PasswordHasher.java:37`, `:44`), so an *unknown* username is distinguishable by response time from a *known* username whose record still carries a legacy, lower iteration count (the very case `needsRehash` exists to handle).
- A malformed stored hash returns at `PasswordHasher.java:74-76` **before any derivation**, so a corrupt record answers far faster than a valid one.
- The rehash-on-success path performs a whole-file write (`AuthenticationService.java:85-87`), a large and observable timing difference — though only on a successful login.

Fix: derive the dummy at the *minimum* iteration count observed in the store, or normalise
total response time with a fixed floor (sleep to a constant deadline) around the whole
`authenticate` call.

---

### F-16 (Informational) — Records can be silently dropped on reload
**CWE-1284: Improper Validation of Specified Quantity in Input (data integrity)**

- Evidence: `FileCredentialStore.java:51` — `if (line.isBlank() || line.startsWith("#")) continue;` while `PasswordPolicy.java:25-30` permits a username beginning with `#`.

A user named `#ops` round-trips to a line that the loader treats as a comment: the account
vanishes at the next start with no error. Fix: reject `#` at the start of a username, or
quote the field on write.

---

## 3. What was checked and found sound

- **Salt generation and RNG**: `SecureRandom` used for salts and the dummy password, 16-byte salt, fresh per hash (`PasswordHasher.java:31`, `:48-49`, `:124-128`). No `java.util.Random`, no time-based seeding, no predictable IVs.
- **Hash comparison**: `MessageDigest.isEqual` (`PasswordHasher.java:92`) is the length-constant primitive — correct choice.
- **No deprecated primitives**: no MD5, SHA-1, DES/3DES/RC4, no ECB mode, no home-rolled crypto anywhere in the tree.
- **Uniform failure messaging**: unknown user, wrong password and deactivated account all return the identical `GENERIC_FAILURE` string (`AuthenticationResult.java:26`, `:77-82`), with the real reason confined to `status()`. Verified by `AuthenticationTests` lines 137-145.
- **Username normalisation** uses `Locale.ROOT` (`EmployeeRecord.java:26`), avoiding the Turkish-dotless-I collision class.
- **`EmployeeRecord.toString()`** deliberately omits the password hash (`EmployeeRecord.java:54-58`).
- **Atomic store rewrite** via temp file + `ATOMIC_MOVE` with `deleteIfExists` cleanup (`FileCredentialStore.java:98-106`); `Files.createTempFile` is used rather than a predictable name, so there is no symlink/TOCTOU race on the temp path.
- **`Boolean.parseBoolean(fields[4])`** (`FileCredentialStore.java:60`) fails closed — any unparseable value yields `active=false`.
- **`PBEKeySpec.clearPassword()`** is called in a `finally` block (`PasswordHasher.java:119-121`).
- **No hardcoded production credentials or API keys** in `src/`; the only literals are test fixtures (`AuthenticationTests.java:38-88`).
- **Not applicable / absent**: SQL and NoSQL injection, OS command execution, insecure deserialization, path traversal from user input into file *reads*, XXE/XML, SSRF, XSS, CSRF, JWT/session handling, TLS configuration — this is an offline console program with no query construction, no network calls and no serialization framework. Reviewed against general OWASP Top 10 / CWE knowledge and confirmed no instances exist.

---

## 4. Priority order for remediation

1. **F-01** — make throttling persistent (the advertised control does not exist today).
2. **F-02** — put an authorisation check in front of `add-user`.
3. **F-03** — validate every field written to the TSV store.
4. **F-05**, **F-06** — bound KDF parameters read from disk; raise the work factor; fix the dead deny-list.
5. **F-04** — stop copying cleartext passwords into `String`s.
6. Everything else in file order.

---

## 5. Skills applied

Selected by matching the Step-1 behaviour keywords against the skill library and reading each
skill body in priority order:

1. `performing-cryptographic-audit-of-application` — KDF parameters, salt/RNG, algorithm
   choice, constant-time comparison, hardcoded secrets → F-05, F-06, F-15, §3.
2. `testing-api-authentication-weaknesses` — password policy strength, credential-stuffing /
   brute-force resistance, account enumeration, credential leakage into logs → F-01, F-06,
   F-07, F-15.
3. `testing-for-sensitive-data-exposure` — insecure storage of credential material, secrets
   in source, data at rest and in memory → F-04, F-08, F-14, §3.
4. `testing-for-broken-access-control` — missing function-level check, vertical privilege
   escalation → F-02.
5. `testing-for-business-logic-vulnerabilities` — workflow/threshold bypass, role and
   permission logic → F-01, F-02, F-10.
6. `performing-hash-cracking-with-hashcat` — offline-cracking economics used to judge the
   work factor and store-file exposure → F-06, F-14.

Behaviours with no closely matching library skill — log-record construction (CWE-117/778),
TSV record serialisation (CWE-74/93), resource bounding and locking (CWE-770/667/400), error
handling (CWE-209), environment-controlled configuration (CWE-15) and file permissions
(CWE-732) — were reviewed against general OWASP Top 10 and CWE knowledge, as recorded in
F-03, F-07 through F-14 and F-16.
