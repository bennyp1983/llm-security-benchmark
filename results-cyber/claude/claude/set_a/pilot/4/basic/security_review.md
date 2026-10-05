# Security Code Review — Account Registration & Authentication (Java 17)

Scope: `src/accounts/*.java` (`Main.java`, `AccountStore.java`, `UserAccount.java`,
`PasswordHasher.java`, `AccountStoreTest.java`), plus `README.md` for stated intent.
Compiled artefacts in `out/` were not reviewed as source.

Review performed with the `review-code-for-security-vulnerabilities` router skill,
dispatching to the specialised skills listed at the end.

---

## Step 1 — What each file does, and its security-relevant behaviour

| File | Role | Security-relevant behaviour |
| --- | --- | --- |
| `PasswordHasher.java` | PBKDF2-HMAC-SHA256 derivation, salt generation, comparison | Cryptography: KDF choice and parameters, `SecureRandom`, constant-time compare, Base64 encode/decode of untrusted input |
| `UserAccount.java` | One account; hashing on create, verification, `username:iterations:salt:hash` record (de)serialization | Parsing of attacker-influenceable persisted records; work factor sourced from the record |
| `AccountStore.java` | File-backed registry: load, validate, register, authenticate, atomic save | Credential file I/O and permissions, username/password validation, authentication decision, anti-timing dummy hash, error messages |
| `Main.java` | CLI: interactive menu plus `register`/`login` subcommands | Credential file path from `ACCOUNTS_FILE` env var, password input handling/masking, `char[]` wiping, exit codes as an auth signal, error text shown to the user |
| `AccountStoreTest.java` | Self-contained test harness | Uses `Files.createTempDirectory` (safe perms), hard-codes only test passwords |

Keywords derived: *cryptography / KDF work factor*, *password storage*, *authentication*,
*credential file at rest & file permissions*, *untrusted record parsing / input validation*,
*secrets in memory*, *username enumeration / timing side channels*, *brute force*,
*environment-controlled file path*.

No SQL, no OS command execution, no Java serialization (`ObjectInputStream`), no network
calls, no HTML/template rendering, and no hardcoded production secrets exist anywhere in
the codebase — the corresponding vulnerability classes (SQLi, command injection,
CWE-502 deserialization, XSS, SSRF, hardcoded credentials) were searched for and are
**not present**.

---

## Findings

Severity is engineering judgement for a local, single-user CLI tool; it would rise for a
multi-user or service deployment.

### 1. Password is copied into an immutable `String`, defeating the `char[]` wiping design — MEDIUM
- **CWE-316: Cleartext Storage of Sensitive Information in Memory**
- **Evidence:** `src/accounts/AccountStore.java:152` — `String asText = new String(password);`
  (used at `:153` and `:156`), reached from `register()` at `src/accounts/AccountStore.java:103`.
- **Why it matters:** the whole codebase is built around handling passwords as `char[]` and
  zeroing them (`Main.java:95-97`, `Main.java:136-140`, `PasswordHasher.java:44`,
  `PasswordHasher.java:54`). This one line copies the cleartext password into an immutable
  `String` that cannot be wiped and stays on the heap until GC. Any heap dump, core dump,
  swap file, or `LaZagne`/memory-scraping style access after registration can recover the
  plaintext password — precisely the exposure the `char[]` discipline was meant to remove.
  The README's claim that "passwords are handled as `char[]` and zeroed after use rather
  than left in the string pool" is therefore not true for the registration path.
- **Fix:** do both checks on the `char[]` directly — e.g. scan for a non-whitespace char with
  `Character.isWhitespace` for the blank test, and compare case-insensitively against
  `username` character by character (`Character.toLowerCase`) for the equality test. Never
  construct a `String` from a password.

### 2. No rate limiting, throttling, or account lockout on authentication — MEDIUM
- **CWE-307: Improper Restriction of Excessive Authentication Attempts**
- **Evidence:** `src/accounts/AccountStore.java:119-131` (`authenticate` has no attempt
  counter, delay, or lockout state); `src/accounts/Main.java:100-114` and the menu loop at
  `src/accounts/Main.java:59-77` allow unlimited `login` attempts; `Main.java:42-43` exposes
  each attempt as a scriptable exit code.
- **Why it matters:** an attacker with local execution (or any wrapper that exposes this
  binary) can run unbounded online guessing. `java -cp out accounts.Main login alice` with a
  piped password list is a complete credential-stuffing / brute-force harness. The 210,000
  PBKDF2 iterations slow but do not stop this, and combined with finding 5 an attacker
  already knows which usernames are worth attacking.
- **Fix:** persist per-account failure counters and a lockout/backoff window (e.g.
  exponential delay after 5 failures, temporary lock after 10), and record the last failure
  timestamp in the account record so the limit survives process restarts.

### 3. KDF work factor is read from the credential file without any bounds check — MEDIUM
- **CWE-916: Use of Password Hash With Insufficient Computational Effort**
  (also **CWE-1284: Improper Validation of Specified Quantity in Input**, **CWE-400: Uncontrolled Resource Consumption**)
- **Evidence:** `src/accounts/UserAccount.java:54` — `Integer.parseInt(parts[1])` is accepted
  verbatim as `iterations`; used unchecked at `src/accounts/UserAccount.java:33` →
  `src/accounts/PasswordHasher.java:38`. Loading path: `src/accounts/AccountStore.java:48`.
- **Why it matters:** `iterations` is stored per account precisely so it can be changed
  (README), but nothing enforces a floor. Anyone who can write `accounts.db` can rewrite
  `alice:210000:...` to `alice:1:...`, re-deriving the record with the same salt and a
  1-iteration hash, reducing the offline cracking cost of that account by a factor of
  210,000 — a silent KDF downgrade that no code path detects. The same field with no ceiling
  (e.g. `2000000000`) turns a single `login` into a CPU-exhaustion denial of service, and a
  negative or zero value makes `PBEKeySpec` throw `IllegalArgumentException`, which no caller
  catches (`AccountStore.java:107`/`:130` propagate it out of `main`).
- **Fix:** validate on load — reject records whose `iterations` is below a hard minimum
  (e.g. `< 210_000`) or above a sane ceiling (e.g. `> 5_000_000`), and treat a
  below-minimum record as "must re-enrol" rather than authenticating against it. Wrap
  `Integer.parseInt` so a non-numeric field yields a controlled parse error.

### 4. Credential store path is taken from an environment variable without validation — MEDIUM
- **CWE-15: External Control of System or Configuration Setting**
  (also **CWE-73: External Control of File Name or Path**)
- **Evidence:** `src/accounts/Main.java:52-55` — `System.getenv("ACCOUNTS_FILE")` is passed
  straight to `Paths.get(...)`, then to `new AccountStore(...)` at `src/accounts/Main.java:32`.
  The resulting path is written to at `src/accounts/AccountStore.java:63-66`.
- **Why it matters:** two directions of abuse. (a) *Authentication redirect*: whoever controls
  the environment of the process picks which credential file the answer comes from, so
  `ACCOUNTS_FILE=/tmp/mine.db java -cp out accounts.Main login alice` returns exit code 0
  for a password the attacker chose. Any script or service that treats this program's exit
  code as an authorization decision is trivially bypassed. (b) *Arbitrary write*: registration
  causes `Files.createDirectories` plus an atomic move onto the supplied path, so pointing
  `ACCOUNTS_FILE` at, say, a config file or a file in another user's tree overwrites it with
  account records under whatever rights the process holds.
- **Fix:** resolve the configured path against a fixed, trusted base directory, reject paths
  that escape it after `toRealPath()`/normalisation, refuse symlinked targets, and ignore the
  override entirely when the process runs with elevated privileges. If the tool is ever used
  as an authorization oracle, the store location must be compile-time or root-owned config,
  not an environment variable.

### 5. Registration error reveals whether a username exists (account enumeration) — LOW
- **CWE-204: Observable Response Discrepancy** (username enumeration)
- **Evidence:** `src/accounts/AccountStore.java:105` — `"Username '" + username + "' is already taken."`,
  printed verbatim to the user at `src/accounts/Main.java:92`.
- **Why it matters:** the login path is carefully non-committal ("Invalid username or
  password.", `Main.java:109`) and even burns CPU on unknown users to hide their absence
  (`AccountStore.java:125-128`). The registration path undoes that: probing `register <name>`
  distinguishes existing from free usernames with certainty, handing an attacker the exact
  target list for finding 2. Note the check is case-insensitive (`AccountStore.java:104`/`:83-85`),
  so it also leaks case variants.
- **Fix:** for a tool where enumeration matters, return a generic outcome for taken
  usernames, or gate registration behind an authenticated/administrative path. At minimum,
  make the message match the level of detail the login path allows.

### 6. Password input is unmasked and materialised as a `String` when no console is attached — LOW
- **CWE-549: Missing Password Field Masking** (also **CWE-316** for the `String` copy)
- **Evidence:** `src/accounts/Main.java:127-134` — when `System.console()` is `null` the code
  falls back to `prompt(message).toCharArray()`; `prompt` reads via `BufferedReader.readLine()`
  at `src/accounts/Main.java:123`, producing an un-wipeable `String`, and the terminal echo is
  never disabled. `CONSOLE` is captured once at `src/accounts/Main.java:27`.
- **Why it matters:** in an IDE, under `script`, in CI, or whenever stdin/stdout is
  redirected, the password is typed in clear on screen (shoulder-surfing, terminal
  scrollback, session recordings) and additionally left in the heap as an immutable `String`
  the `wipe()` calls at `Main.java:95-97`/`:112` cannot reach. The comment at `Main.java:132`
  acknowledges the masking gap but the memory-residency consequence is unaddressed.
- **Fix:** when no `Console` is available, either refuse to read a password interactively
  (require a console) or read raw bytes into a `char[]`/`byte[]` buffer that can be zeroed,
  and warn the user that input is not masked.

### 7. Persisted records are parsed without validation; one bad line disables the whole store — LOW
- **CWE-20: Improper Input Validation**
- **Evidence:** `src/accounts/AccountStore.java:43-50` (every line is fed to
  `UserAccount.fromRecord` and inserted with no re-validation); `src/accounts/UserAccount.java:45-55`
  (`split(":", 4)`, `PasswordHasher.decode` at `:52-53`, `Integer.parseInt` at `:54`).
  `PasswordHasher.decode` is `src/accounts/PasswordHasher.java:62-64`.
- **Why it matters:** the file is untrusted input (see finding 4 — its location is
  attacker-influenceable). Three concrete effects: (a) a single malformed line makes
  `fromRecord` throw `IllegalArgumentException` (`UserAccount.java:48`), or
  `Base64.getDecoder().decode` / `Integer.parseInt` throw, and because `load()` is called
  from the constructor (`AccountStore.java:36`) the *entire* store becomes unusable — a
  one-byte corruption is a denial of service for every account. (b) usernames from disk
  bypass `validateUsername` entirely (`AccountStore.java:133-145` is only called from
  `register`), so a record may carry a 5,000-character or control-character username that the
  registration rules forbid. (c) two records differing only in case collapse onto the same
  lower-cased key at `AccountStore.java:49`, silently discarding one account with no error.
  There is also no bound on file size before `Files.readAllLines` (`AccountStore.java:43`).
- **Fix:** validate each record on load (username against `validateUsername`, salt length,
  hash length, iterations range), skip-and-log individual bad records instead of aborting the
  load, and reject a duplicate key explicitly rather than overwriting.

### 8. Credential file has no integrity protection — LOW
- **CWE-353: Missing Support for Integrity Check**
- **Evidence:** `src/accounts/AccountStore.java:53-70` writes plain `username:iterations:salt:hash`
  lines (format built at `src/accounts/UserAccount.java:37-43`) with no MAC or signature;
  `load()` at `src/accounts/AccountStore.java:39-51` accepts whatever it reads.
- **Why it matters:** confidentiality of the hashes is addressed (PBKDF2 + per-account salt +
  `0600`), but authenticity is not. Anyone who can write the file can substitute a hash they
  generated, add accounts, or delete them, and authentication will succeed against the
  forged record with no detection. This is the mechanism that makes findings 3 and 4
  exploitable rather than theoretical.
- **Fix:** append an HMAC over the whole file (or per record) keyed from an OS keystore or a
  root-owned key file, and refuse to load when it does not verify.

### 9. No authentication logging or audit trail — LOW
- **CWE-778: Insufficient Logging**
- **Evidence:** the only output is user-facing text — `src/accounts/Main.java:89`, `:92`,
  `:105`, `:109`; `AccountStore.authenticate` (`src/accounts/AccountStore.java:119-131`)
  records nothing. There is no logger anywhere in `src/accounts/`.
- **Why it matters:** successful logins, failed logins, lockouts, registrations, and
  credential-file load errors are all invisible. Brute force (finding 2), enumeration
  (finding 5), and tampering (finding 8) leave no trace to detect or investigate.
- **Fix:** emit structured events (timestamp, username, outcome, source) to a log the
  application user cannot rewrite. Never log the password or the derived hash.

### 10. Temp file left behind on failure; parent directory created with default permissions — LOW
- **CWE-459: Incomplete Cleanup** (also **CWE-276: Incorrect Default Permissions** for the directory)
- **Evidence:** `src/accounts/AccountStore.java:63` creates `accounts*.tmp` in the credential
  directory; if `Files.write` (`:64`), `restrictPermissions` (`:65`), or `Files.move` (`:66`)
  fails, the `catch` at `:67-69` throws without deleting the temp file. `Files.createDirectories`
  at `:61` applies the process umask rather than an explicit owner-only mode.
- **Why it matters:** a failed save leaves an orphaned file containing every account's salt
  and hash; it inherits `createTempFile`'s owner-only permissions on POSIX so exposure is
  limited, but on non-POSIX filesystems `restrictPermissions` is a silent no-op
  (`AccountStore.java:78-80`) and the debris accumulates indefinitely. A world-readable
  parent directory also lets others enumerate account filenames and observe write activity.
- **Fix:** delete the temp file in a `catch`/`finally`, and create the parent directory with
  an explicit `PosixFilePermissions.asFileAttribute` of `rwx------`. On Windows, set an
  explicit owner-only ACL instead of ignoring the failure.

### 11. Weak password policy — LOW
- **CWE-521: Weak Password Requirements**
- **Evidence:** `src/accounts/AccountStore.java:28` (`MIN_PASSWORD_LENGTH = 8`) enforced at
  `src/accounts/AccountStore.java:147-159`; the only other rules are "not all whitespace"
  (`:153`) and "not equal to the username" (`:156`).
- **Why it matters:** an 8-character minimum with no check against breached or common
  passwords means `password`, `12345678`, and `qwertyui` are all accepted. Given no lockout
  (finding 2), these are the first guesses an attacker makes, and the strong KDF does not
  compensate for a password in the top-1000 list.
- **Fix:** follow NIST SP 800-63B — raise the minimum to 12 characters, allow long
  passphrases (no maximum below ~64), and screen candidates against a breached-password list
  (e.g. a local Pwned Passwords hash set) instead of adding composition rules.

### 12. Anti-timing dummy hash does not track the account's stored work factor — INFORMATIONAL
- **CWE-208: Observable Timing Discrepancy**
- **Evidence:** `src/accounts/AccountStore.java:127` always uses
  `PasswordHasher.DEFAULT_ITERATIONS` for the unknown-user path, whereas a real account is
  verified with its own stored value (`src/accounts/UserAccount.java:33`).
- **Why it matters:** the mitigation is correct today because every account is created with
  `DEFAULT_ITERATIONS` (`UserAccount.java:24-25`). The moment the work factor is raised — the
  documented reason the field is per-account — existing accounts hash at the old cost while
  unknown users hash at the new one, and the response-time difference re-opens the
  enumeration channel the code deliberately closed. The dummy path also does an extra
  `newSalt()` (`AccountStore.java:127`) that the real path does not, a small constant skew.
- **Fix:** derive the dummy iteration count from the store (e.g. the minimum or the most
  common stored value), or better, verify against a fixed dummy account record so both paths
  execute identical code.

---

## Checked and found sound

These behaviours were reviewed and no issue was identified:

- **KDF choice and parameters** — PBKDF2-HMAC-SHA256 (`PasswordHasher.java:19`), 210,000
  iterations (`:24`, meets the OWASP 2023 guidance of ≥600,000 for SHA-256 only loosely but
  is well above legacy minimums and is raisable by design), 128-bit salt (`:20`), 256-bit
  output (`:21`). No MD5/SHA-1, no DES/RC4, no ECB, no static IV.
- **Salt generation** — one `SecureRandom` instance, fresh 16-byte salt per account
  (`PasswordHasher.java:26`, `:31-35`, `UserAccount.java:23`); verified by the test at
  `AccountStoreTest.java:49-52`.
- **Hash comparison** — `MessageDigest.isEqual` (`PasswordHasher.java:52`) is the constant-time
  primitive, and the derived hash is zeroed afterwards (`:54`).
- **Password lifetime in `PasswordHasher`** — `spec.clearPassword()` in a `finally`
  (`PasswordHasher.java:43-45`).
- **No hardcoded secrets** — the only literal credentials are test fixtures in
  `AccountStoreTest.java:18`, `:22`, `:37`, and they never reach a production path.
- **Login-failure messaging** — uniformly generic (`Main.java:109`), and unknown users still
  pay the hashing cost (`AccountStore.java:125-128`).
- **Registration input validation** — username length and character allow-list
  (`AccountStore.java:137-144`) prevent record-delimiter (`:`) and newline injection into the
  credential file format defined at `UserAccount.java:37-43`.
- **Atomic write** — `ATOMIC_MOVE` + `REPLACE_EXISTING` (`AccountStore.java:66`) prevents a
  truncated credential file on crash.
- **Defensive copying** — `salt` and `passwordHash` are cloned in and out of `UserAccount`
  (`UserAccount.java:16-17`), so callers cannot mutate stored state.
- **`toString` hygiene** — `UserAccount.toString` (`:58-60`) exposes only the username, never
  salt or hash, so accidental logging cannot leak material.
- **Test harness** — `Files.createTempDirectory` (`AccountStoreTest.java:14`) creates an
  owner-only directory; cleanup at `:78-88` is bounded to that directory.

## Classes searched for and not present

Reviewed against general OWASP Top 10 / CWE knowledge where no specialised library skill
applied: **SQL/NoSQL injection** (no database or query construction anywhere),
**OS command injection** (no `Runtime.exec`/`ProcessBuilder`), **insecure deserialization,
CWE-502** (no `ObjectInputStream`/`readObject`; the record format is a hand-parsed text line),
**XSS/template injection** (no HTML, no web layer), **SSRF and TLS misconfiguration** (no
network I/O, no `HttpClient`, no `TrustManager` overrides), **path traversal from user input**
(usernames never reach a filesystem path; the only external path is the env var covered in
finding 4), **XXE** (no XML parsing), **hardcoded cryptographic keys** (none), and
**authorization/access-control flaws** (the program has no roles, sessions, or protected
resources beyond the single authenticate call — `Main.java:104-106` grants nothing but a
greeting and an exit code).

## Skills applied

1. `performing-cryptographic-audit-of-application` — KDF algorithm/parameters, salt and RNG
   quality, constant-time comparison, hardcoded-secret scan, weak-KDF detection (findings 3, 12;
   confirmed the sound items above).
2. `testing-api-authentication-weaknesses` — password policy strength, credential-stuffing
   susceptibility, credential storage and handling, authentication-response discrepancies
   (findings 2, 5, 11).
3. `testing-for-sensitive-data-exposure` — secrets in source, insecure storage at rest,
   sensitive data resident in memory, credential-file permissions (findings 1, 6, 8, 10).
4. `hunting-credential-stuffing-attacks` — applied inverted, as a defensive gap analysis: the
   authentication path emits none of the log signals (login velocity, failure counts) such
   detection depends on, and imposes no attempt limit (findings 2, 9).
5. `performing-hash-cracking-with-hashcat` — used to evaluate offline cracking resistance of
   the stored `username:iterations:salt:hash` format: the format is directly hashcat-parseable
   (mode 10900, PBKDF2-HMAC-SHA256), which makes the unvalidated work factor of finding 3 and
   the weak password policy of finding 11 the decisive cost factors for an attacker holding a
   stolen `accounts.db`.
