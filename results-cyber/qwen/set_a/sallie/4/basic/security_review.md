# Security Review: `account` — Java command-line registration and login program

## 1. Executive Summary

The component is a self-contained Java 17 command-line program that registers accounts and
authenticates them against a plain text file. Its cryptographic core is sound: PBKDF2-HMAC-SHA256
at 210,000 iterations, a fresh 16-byte `SecureRandom` salt per account, a 256-bit digest compared in
constant time, plus a set of deliberate hardenings (timing equalisation for unknown users, rejection
of passwords that `PBEKeySpec` cannot represent one-to-one, an allowlisted username charset,
fail-closed parsing of the store, and a locked read-modify-write with an atomic replace). The
widely abused classes of vulnerability are simply absent: there is no database, no HTML or template
output, no network I/O, no deserialisation of untrusted bytes, no subprocess, and no authorisation
boundary.

**Six findings: 0 Critical, 0 High, 2 Medium, 4 Low.** Both Mediums concern secret handling and
guess rate rather than broken cryptography — authentication is not throttled at all, and the
`verify` subcommand takes the password as a command-line argument where every local user can read
it. The Lows are a KDF-cost downgrade window that contradicts a documented guarantee, a password
copy that cannot be erased from memory on the piped input path, unvalidated text written to the
terminal and to captured logs, and a length-only password policy.

Two candidate findings were investigated and **disproved** rather than reported (see §6): the
store file does *not* inherit permissive permissions (`Files.createTempFile` creates it `0600` and
`ATOMIC_MOVE` is a rename that preserves those bits), and the prebuilt `out/account/*.class` files
that `run.sh` actually executes were disassembled with `javap` and match the reviewed sources in
every security-relevant constant and message. `README.md` already acknowledges several of the
accepted risks; where a risk is inherent to the design (the store file is not encrypted, usernames
are case-sensitive) it is not re-reported as a finding, but the missing throttling in SEC-01 is
reported despite being acknowledged, because it is the mechanism that turns a stolen store file into
a live guessing oracle.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/account/Main.java` | CLI front end: parses argv, prompts, prints messages, sets exit codes | Accepts the store path and an arbitrary `verify` password from argv; reads secrets via `Console.readPassword` when available, otherwise via a piped line reader that returns a `String`; echoes unvalidated text (unknown command, store path) to stdout/stderr; prints exception messages only, never stack traces |
| `src/account/AccountService.java` | Registration and authentication use case | Allowlists usernames to `[A-Za-z0-9._-]` (3–32); burns equivalent key-derivation work for unknown users; returns distinct `UNKNOWN_USER` / `INVALID_CREDENTIALS` / `USERNAME_TAKEN` results; performs no attempt counting |
| `src/account/PasswordHasher.java` | Password hashing and verification | PBKDF2-HMAC-SHA256, 210 000 iterations, 16-byte `SecureRandom` salt, 256-bit output; constant-time comparison; trusts the iteration count stored in the file down to a 10 000 floor; length-only password policy |
| `src/account/AccountStore.java` | File-backed account registry | POSIX shared/exclusive `FileChannel` locking; re-read and merge under the exclusive lock; temp file + `ATOMIC_MOVE` replace; refuses corrupt or duplicated store files |
| `src/account/User.java` | One account and its one-line serialisation | Splits store lines on `\|`, fails closed on malformed records and bad timestamps; plaintext password never present |
| `src/test/account/AccountSystemTest.java` | 94-check self-test that drives the real program in a second process | Proves the collision guard, timing equalisation, and concurrent-registration behaviour; covers only a 1-iteration weakened record |
| `run.sh` | Builds if needed, then runs the program | Decides whether to rebuild by comparing the newest source against one class file's mtime; aborts on `javac` failure; `exec java -cp out account.Main "$@"` |
| `out/account/*.class`, `out-test/account/*.class` | Shipped bytecode that `run.sh` actually executes | Verified with `javap` to match `src/`; executed without a rebuild when sources are not strictly newer |
| `README.md` | Design and accepted-risk documentation | Not executable; used to distinguish deliberate choices from defects and to check documented guarantees against the code |

Not in scope as code: `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt`
(harness files, no executable content).

## 3. Skills Applied

- **`review-code-for-security-vulnerabilities`** — the dispatcher. Used for the whole engagement:
  established what each file does before judging it, then dispatched to the specialised skills below
  rather than pattern-matching on keywords. Its verification checklist (list the skills applied, give
  a CWE id and `file:line` for every finding) shapes this report.
- **`performing-cryptographic-audit-of-application`** — applied to `src/account/PasswordHasher.java`
  and its call sites: reviewed the primitive choice and parameters (algorithm, iteration count, key
  length), the source and uniqueness of the salt, the comparison function for early-exit leakage, key
  destruction after use, and the self-describing record format as a trust boundary. This skill's
  "Weak KDF / low iteration count" and "timing side-channel" rows drove SEC-03 and the two
  crypto controls recorded in §6.
- **`testing-api-authentication-weaknesses`** — applied to `AccountService.register`/`authenticate`
  and `Main.exitForLogin`/`exitForVerify`/`exitForRegister`: credential storage strength, absence of a
  session mechanism, response and timing discrepancies usable for account enumeration, and
  brute-force/lockout posture. Drove SEC-01 and SEC-06, and the enumeration controls in §6.
- **`testing-for-sensitive-data-exposure`** — applied to the credential store and all output paths:
  what the store file contains, the permissions of the store and its temp file, secrets in process
  arguments and echoed input, source-level scanning for embedded credentials, and whether error
  messages leak internal detail. Drove SEC-02, SEC-04 and SEC-05.
- **`exploiting-insecure-deserialization`** — applied to the store-parsing path (`User.fromLine`,
  `PasswordHasher.matches`, Base64 decoding) to check for unsafe object or type-driven parsing.
  No `ObjectInputStream`, no reflective type resolution, no gadget surface; parsing is length- and
  charset-checked and fails closed. No finding (§6).
- **`exploiting-race-condition-vulnerabilities`** — applied to `AccountStore.load`/`add`/`writeCurrent`
  for time-of-check/time-of-use between the in-memory snapshot, the duplicate-name check, and the file
  write. The critical section re-reads under an exclusive lock and replaces the file atomically, so
  concurrent registration loses no accounts and cannot smuggle a duplicate identity. No finding (§6).
- **`implementing-secret-scanning-with-gitleaks`** — its description matched the
  "secrets in source" question; not applied as a scanner because the repository is nine text files
  reviewed in full, so the equivalent check was done by reading. Only `EQUALIZING_PASSWORD` /
  `EQUALIZING_SALT` (`PasswordHasher.java:42-43`) look credential-like and they are timing pads, not
  secrets — deliberately **not** reported as CWE-798.

Reviewed against general OWASP Top 10 / CWE knowledge, because the library has no skill covering
the behaviour:

- **Authentication throttling and lockout** (`CWE-307`) — no skill in the library addresses
  rate limiting; SEC-01.
- **Secrets in process arguments and in non-zeroizable memory** (`CWE-522`, `CWE-316`) — SEC-02,
  SEC-04.
- **Output neutralisation for logs and terminals** (`CWE-117`) — control characters in the `--store`
  path and unknown-command text; SEC-05.
- **Password policy** (`CWE-521`) — SEC-06.
- **File and temporary-file permissions** (`CWE-732`, `CWE-377`) — checked and disproved (§6).
- **Shell command injection in `run.sh`** (`CWE-78`) — checked, no finding (§6); the library has no
  shell-injection skill.
- **Build-artifact integrity** — checked `out/account/*.class` against `src/` with `javap`, no
  finding (§6).
- **Broken access control** — not applicable: single-user local tool, one trust domain, no privilege
  or tenant boundary to cross. SQL injection, XSS, SSRF, XXE, path traversal and JWT findings are not
  applicable because no such surface exists (§6).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | No limit on authentication attempts: no rate limiting, lockout, or backoff | Medium | CWE-307 | `src/account/AccountService.java:100-115` |
| SEC-02 | `verify` takes the password as a command-line argument, readable by any local user | Medium | CWE-522 | `src/account/Main.java:109-114` |
| SEC-03 | Stored PBKDF2 cost is trusted down to 10 000 iterations (21× below policy) | Low | CWE-916 | `src/account/PasswordHasher.java:27, 120-125` |
| SEC-04 | Password kept in an immutable, un-wipeable `String` on the piped input path | Low | CWE-316 | `src/account/Main.java:205-212` |
| SEC-05 | Unvalidated store path and command text written to the terminal and to logs | Low | CWE-117 | `src/account/Main.java:124-127` |
| SEC-06 | Password policy is length-only: no common-password or username containment screen | Low | CWE-521 | `src/account/PasswordHasher.java:55-64` |

## 5. Detailed Findings

### SEC-01: No limit on authentication attempts: no rate limiting, lockout, or backoff

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `src/account/AccountService.java:100-115`

**Vulnerable code:**

```java
// src/account/AccountService.java:100-115
    Result authenticate(String username, char[] password) {
        String name = normalizeUsername(username);
        try {
            PasswordHasher.validatePassword(password);
        } catch (IllegalArgumentException e) {
            return Result.INVALID_CREDENTIALS;
        }
        Optional<User> user = store.find(name);
        if (user.isEmpty()) {
            PasswordHasher.burnEquivalentWork();
            return Result.UNKNOWN_USER;
        }
        return PasswordHasher.matches(password, user.get().passwordEncoding())
                ? Result.AUTHENTICATED
                : Result.INVALID_CREDENTIALS;
    }
```

**Why it is a problem:** `authenticate` keeps no record that an attempt happened, and neither
`Main.exitForLogin` (`Main.java:91-107`) nor `Main.exitForVerify` (`Main.java:109-122`) adds one, so
every failure is followed immediately by permission to try again. `README.md` lists "rate limiting on
failed attempts, account lockout" under "What this program does not do", but the consequence is
concrete for this design: the whole defence in depth of the store is a per-guess cost of roughly a
third of a second, and there is exactly one such layer. Anyone able to invoke the program — a second
local user, a shared CI runner, a script that takes a username argument — can loop
`verify <user> <password>` over a dictionary indefinitely with no increasing cost, no lockout, and no
audit record of the attempt, so a slow-but-steady online guess against one account is invisible after
the fact. The 210 000 iterations make each guess expensive, not the attempt count bounded, and the
"unknown username" path costs a full derivation (`AccountService.java:107-111`), which means an
attacker spraying a username list pays the same price as an attacker guessing one account's password
and is equally unthrottled.

**Fix:** Record failures per username in a sidecar file and make the next attempt pay for them,
resetting on success. A per-username counter alone lets an attacker spray many names, so also cap
total failures across the store in the same window, and prefer a growing delay over a permanent
lockout so the throttle cannot itself disable an account.

```java
    Result authenticate(String username, char[] password) {
        String name = normalizeUsername(username);
        attempts.enforceDelay();          // sleeps on recent failures; throws if saturated
        try {
            PasswordHasher.validatePassword(password);
        } catch (IllegalArgumentException e) {
            attempts.recordFailure(name);
            return Result.INVALID_CREDENTIALS;
        }
        Optional<User> user = store.find(name);
        if (user.isEmpty()) {
            PasswordHasher.burnEquivalentWork();
            attempts.recordFailure(name);
            return Result.UNKNOWN_USER;
        }
        boolean ok = PasswordHasher.matches(password, user.get().passwordEncoding());
        if (ok) {
            attempts.clear(name);
        } else {
            attempts.recordFailure(name);
        }
        return ok ? Result.AUTHENTICATED : Result.INVALID_CREDENTIALS;
    }
```

`AttemptTracker.enforceDelay()` should read a store-sidecar file written under the same exclusive
lock used by `AccountStore.add`, sleep `min(cap, base * 2^failures)` once the count in the current
window exceeds a small threshold, and count failures globally as well as per username; because the
counter file lives beside the store, a reset requires write access to the store itself.

### SEC-02: `verify` takes the password as a command-line argument, readable by any local user

- **Severity:** Medium
- **CWE:** CWE-522: Insufficiently Protected Credentials
- **Location:** `src/account/Main.java:109-114`

**Vulnerable code:**

```java
// src/account/Main.java:109-114
    private static void exitForVerify(AccountService service, String[] operands) {
        if (operands.length != 2) {
            ERR.println("Error: verify needs a username and a password.");
            System.exit(2);
        }
        char[] password = operands[1].toCharArray();
```

**Why it is a problem:** Command-line arguments are world-readable on Linux through
`/proc/<pid>/cmdline` (mode `0444`), so for the lifetime of the JVM any user on the machine can read
the plaintext password with a plain `ps -ef` or by watching `/proc`; the same string is then retained
in shell history, in `ps`-based monitoring and process-accounting data, and in CI job logs. The
program's own help text acknowledges this at `Main.java:136-137` ("Same check with the password on the
command line (for scripts only - it is visible to other processes)") and `README.md` repeats it, but
documenting an exposure does not narrow it, and the recommendation targets scripts — the exact context
in which the credential ends up committed to a repository or echoed into a build log. This is also the
only path that bypasses the careful secret handling everywhere else: `register` and `login` prompt via
`Console.readPassword` and never put the secret in argv, and `exitForVerify` still zeroes the buffer
(`Main.java:120`), which cannot help once the value was transmitted in the clear. (Also commonly
reported as the "sensitive information in a command-line argument" exposure, CWE-214.)

**Fix:** Take only the username as an operand and read the secret from a channel that is not world
readable — stdin, or an environment variable, whose `/proc/<pid>/environ` is owner-read-only — while
keeping the interactive prompt as the default:

```java
    private static void exitForVerify(AccountService service, String[] operands) {
        if (operands.length != 1) {
            ERR.println("Error: verify needs a username; the password comes from stdin"
                    + " or $ACCOUNT_PASSWORD, never from the command line.");
            System.exit(2);
        }
        String fromEnv = System.getenv("ACCOUNT_PASSWORD");
        char[] password = fromEnv != null ? fromEnv.toCharArray() : readSecret("Password: ", true);
        try {
            AccountService.Result result = service.authenticate(operands[0], password);
            OUT.println(result == AccountService.Result.AUTHENTICATED ? "OK" : "FAIL");
            System.exit(result == AccountService.Result.AUTHENTICATED ? 0 : 1);
        } finally {
            Arrays.fill(password, (char) 0);
        }
    }
```

If a two-operand call must keep working for one release, reject it unless an explicit
`--allow-password-in-argv` flag is present, and print a warning to stderr on that path so the
exposure is never silent.

### SEC-03: Stored PBKDF2 cost is trusted down to 10 000 iterations (21× below policy)

- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `src/account/PasswordHasher.java:27, 120-125`

**Vulnerable code:**

```java
// src/account/PasswordHasher.java:27
    private static final int MIN_ITERATIONS = 10_000;
// ... (lines 28-119 elided)
// src/account/PasswordHasher.java:120-125
        // A stored record is only trusted if its cost is still sane: otherwise a
        // tampered file could ask for one iteration and make cracking cheap.
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS
                || salt.length < SALT_BYTES || expected.length != HASH_BITS / 8) {
            return false;
        }
```

**Why it is a problem:** The iteration count travels inside the stored record, and the only floor
applied to it at verification time is `MIN_ITERATIONS = 10_000` — 21× cheaper than the `ITERATIONS =
210_000` the program itself writes. Rewriting one field of one record from `$210000$` to `$10000$`
leaves the account fully functional while making its hash 21 times cheaper to attack, and it does so
without any other observable change; the same holds for any old, cheap record restored from a backup.
This contradicts a guarantee `README.md` states outright ("A weakened record in the file is not
trusted. If somebody edits a stored record to say 'one round of maths', logging in with the matching
password is still refused") — a record claiming one round *is* refused, but the accepted range reaches
a tenth of the policy cost, and `AccountSystemTest.weakStoredCostIsRejected()`
(`src/test/account/AccountSystemTest.java:303-309`) only exercises the single case
`pbkdf2-sha256$1$...`, so the downgrade in the 10 000–209 999 band is neither blocked nor tested. The
severity is Low rather than higher because exploiting it needs write access to the store file, and an
attacker with that access can already run guesses offline against the original record — the damage is
a silent weakening of the one remaining defence, not a new entry path.

**Fix:** Separate the compatibility floor from the policy floor, and refuse anything below policy
instead of below "not absurd". Raising a legacy record is a re-hash on successful login, not a
refusal:

```java
    static final int ITERATIONS = 210_000;
    // Cost a stored record may claim: anything below the current policy is a downgrade,
    // not a legacy record, because re-stretching happens on a successful login.
    private static final int MIN_ACCEPTED_ITERATIONS = 100_000;

        if (iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ITERATIONS
                || salt.length < SALT_BYTES || expected.length != HASH_BITS / 8) {
            return false;
        }
```

Then have the successful-login path re-write the record with `hash(password)` at `ITERATIONS` so
records at the policy floor are pulled back up to 210 000 rather than being tolerated indefinitely.

### SEC-04: Password kept in an immutable, un-wipeable `String` on the piped input path

- **Severity:** Low
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in Memory
- **Location:** `src/account/Main.java:205-212`

**Vulnerable code:**

```java
// src/account/Main.java:205-212
        if (warnIfEchoed) {
            ERR.println("Note: no console attached, the password will be echoed as you type it.");
        }
        String value = promptLine(prompt);
        if (value.isEmpty()) {
            throw new IllegalArgumentException("a password is required");
        }
        return value.toCharArray();
```

**Why it is a problem:** When no console is attached, the secret is read as a `String`
(`promptLine`, `Main.java:164-189`) and only then copied into a `char[]`. Every later zeroing — the
`Arrays.fill(password, (char) 0)` in `exitForRegister`/`exitForLogin`/`exitForVerify` — wipes the
*copy*, while the original `String` stays intact and un-wipeable in the heap until the garbage
collector moves or frees it, and `String` contents may additionally survive in the `BufferedReader`
line buffer that produced it. That defeats the reason the rest of the program uses `char[]` and
`Console.readPassword` at all: on this path a core dump, a heap dump taken for another purpose, or a
debugger attached to the process yields the password directly. The same fallback has a second,
smaller inconsistency: the echo warning is printed only when `warnIfEchoed` is true, and
`exitForLogin` passes `false` (`Main.java:93`), so under `script(1)` or a pseudo-terminal without a
Java console the login password is displayed with no notice at all — the "said out loud rather than
hidden" promise in the class comment holds for registration but not for login.

**Fix:** Read the line straight into a growable `char[]` so no `String` copy of the secret is ever
created, and warn on every no-console path rather than only on registration:

```java
    private static char[] readSecret(String prompt, boolean warnIfEchoed) {
        Console console = System.console();
        if (console != null) {
            char[] secret = console.readPassword("%s", prompt);
            if (secret == null || secret.length == 0) {
                throw new IllegalArgumentException("a password is required");
            }
            return secret;
        }
        ERR.println("Note: no console attached - the password is not hidden and cannot be"
                + " erased from memory; run from a terminal to avoid this.");
        return readSecretFromPipe(prompt);   // fills a char[], returns an exact-length copy,
    }                                        // zeroing the scratch buffer in a finally block
```

A `readSecretFromPipe` implementation should `Reader.read(char[], int, 1)` characters from
`new InputStreamReader(System.in, UTF_8)` into a scratch `char[]` until `'\n'`, return an exact-length
copy, and zero the scratch buffer in a `finally` block.

### SEC-05: Unvalidated store path and command text written to the terminal and to logs

- **Severity:** Low
- **CWE:** CWE-117: Improper Output Neutralization for Logs
- **Location:** `src/account/Main.java:124-127`

**Vulnerable code:**

```java
// src/account/Main.java:124-127
    private static void exitForList(AccountService service) {
        OUT.println(service.accountCount() + " account(s) stored in " + service.storeFile());
        System.exit(0);
    }
```

**Why it is a problem:** The store path is never validated — `AccountStore` only absolutises and
normalises it (`AccountStore.java:36`), which does not remove control characters — and it is
interpolated verbatim into program output here and at `Main.java:79-80`. The first argv element is
echoed the same way for an unrecognised command (`Main.java:50`). Two consequences follow. CR or LF
inside the path or command forges additional output lines, so when stdout or stderr is collected into
a log — the normal deployment for a scripted credential check — an attacker who influences those
arguments can fabricate entries that appear to come from this program, for example a second
"account(s) stored in" line naming a file that was never touched. ESC and OSC sequences survive to the
terminal and are interpreted there: `OSC 52` sets the clipboard, `OSC 8` inserts a clickable hyperlink
with arbitrary label and target, `OSC 0`/`OSC 2` rewrite the window title, so the output of a command
whose arguments came from elsewhere (a wrapper script, a filename, a CI matrix entry) can plant a
misleading line plus a link whose label is not its destination. This is an inconsistency rather than an
unknown risk class in this codebase: the username is allowlisted to `[A-Za-z0-9._-]` precisely to stop
invisible characters from reaching stored or displayed identities, yet the path and command bypass all
screening. Note also that the success message prints `username.trim()` — the raw argument — rather
than the validated value; it is safe today only because `register` throws first for any character
outside the allowlist, an ordering dependency that will silently break if the message is ever reached
by another path.

**Fix:** Neutralise control characters on every path that echoes data the program did not construct,
and print the validated username rather than the raw argument:

```java
    private static String safeDisplay(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                out.append(String.format("\\u%04x", (int) c));   // CR, LF, ESC, DEL neutralised
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static void exitForList(AccountService service) {
        OUT.println(service.accountCount() + " account(s) stored in "
                + safeDisplay(service.storeFile().toString()));
        System.exit(0);
    }
```

Apply the same helper at `Main.java:50` (`safeDisplay(command)`) and `Main.java:79-80`, and use the
value returned by `AccountService.normalizeUsername` for the registered-username message.

### SEC-06: Password policy is length-only: no common-password or username containment screen

- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/account/PasswordHasher.java:55-64`

**Vulnerable code:**

```java
// src/account/PasswordHasher.java:55-64
    static void validatePassword(char[] password) {
        if (password == null) {
            throw new IllegalArgumentException("password is missing");
        }
        if (password.length < MIN_PASSWORD_CHARS) {
            throw new IllegalArgumentException("password must be at least " + MIN_PASSWORD_CHARS + " characters");
        }
        if (password.length > MAX_PASSWORD_CHARS) {
            throw new IllegalArgumentException("password must be at most " + MAX_PASSWORD_CHARS + " characters");
        }
```

**Why it is a problem:** The remaining checks in this method (`PasswordHasher.java:65-79`) exist only
to reject passwords `PBEKeySpec` cannot represent one-to-one, so the *policy* is exactly "at least 10
characters" — `password1234`, `1234567890` and `qwertyuiop` are all accepted. The store file keeps no
secret of its own, so the work factor protects only against guesses a dictionary will never reach; a
ten-character common word is recovered in a fraction of the guesses the 210 000 iterations are there
to make expensive, which means the KDF budget is spent protecting the passwords least worth
protecting. There is also no relation check between the two inputs the user supplies in the same
command: `./run.sh register alice` followed by the password `alice123456` is accepted, and the
username sits in plaintext on the same line as the record, so it is the first thing a guesser tries.
This is not a case of missing code the project declined to write — `validatePassword` is the designed
enforcement point and is already called from both `register` and `authenticate`
(`AccountService.java:84, 103`) — but it is Low because the exposure requires the store file to be
read, and per-account salts prevent one cracked password from being replayed against the others.

**Fix:** Screen against a built-in list of the most common leaked passwords and against the username,
keeping the representability checks as they are:

```java
    private static final Set<String> FORBIDDEN = CommonPasswords.topTenThousand();

    static void validatePassword(String username, char[] password) {
        // ... existing null, length, NUL and surrogate checks unchanged ...
        char[] lowered = Character.toLowerCase(password[0]) == password[0]
                ? password : java.util.Arrays.copyOf(password, password.length);
        for (int i = 0; i < lowered.length; i++) {
            lowered[i] = Character.toLowerCase(lowered[i]);
        }
        boolean forbidden = FORBIDDEN.contains(new String(lowered))
                || (username != null && containsIgnoreCase(lowered, username));
        java.util.Arrays.fill(lowered, (char) 0);
        if (forbidden) {
            throw new IllegalArgumentException(
                    "password is too easy to guess; do not reuse a common word or the username");
        }
    }
```

Ship the deny list as a resource file so it can be refreshed without a code change, and test the
boundary cases already used for the collision guard so a `char[]`-based comparison never reintroduces
a `String` copy of the secret (see SEC-04).

## 6. Verified Controls and Checks With No Finding

- **Key stretching parameters** — `PBKDF2WithHmacSHA256` at 210 000 iterations producing a 256-bit
  key (`PasswordHasher.java:22-26, 144-152`), roughly a third of a second per guess. This is at or
  above current guidance for PBKDF2-HMAC-SHA256, so newly created records are not a CWE-916 finding;
  only the accepted-range floor is (SEC-03).
- **Salt generation and uniqueness** — `new SecureRandom()` (`PasswordHasher.java:33`) filling a fresh
  16-byte salt per account inside `hash` (`PasswordHasher.java:86-87`), never reused across accounts
  and never derived from the username or a timestamp, so identical passwords yield different records
  and precomputed tables do not apply.
- **Constant-time verification** — `MessageDigest.isEqual(expected, actual)`
  (`PasswordHasher.java:133`) rather than `Arrays.equals` or a `String.equals` loop, so verification
  time does not depend on how many digest bytes match.
- **Existence does not leak through login timing** — the unknown-user branch performs a real key
  derivation against fixed inputs (`AccountService.java:107-111`, `PasswordHasher.java:139-142`), so
  wrong-username and wrong-password attempts cost the same, and `AccountSystemTest` asserts the ratio
  stays within bounds. The login failure message is a single generic string for every failure
  (`Main.java:100-102`), so no CWE-204 response discrepancy exists on the login path.
- **Existence does not leak through registration timing either** — `PasswordHasher.hash(password)` is
  evaluated before the existence check inside `store.add(...)` (`AccountService.java:85`), so a
  duplicate-name attempt costs the same as a new registration; only the message distinguishes them
  (`Main.java:83`), which is inherent to any uniqueness-enforcing registry and is the documented
  trade-off.
- **Password-identity collisions closed** — trailing NULs and unpaired surrogates are refused rather
  than cleaned (`PasswordHasher.java:65-79`), which closes a real cross-account authentication
  collision in `PBEKeySpec`; `AccountSystemTest.rawDeriveBytes` proves the raw JCE really collapses
  those passwords before the program rejects them.
- **Username charset is an allowlist** — `[A-Za-z0-9._-]`, 3–32 characters
  (`AccountService.java:51-74`), with `trimSpacesOnly` (`AccountService.java:119-131`) instead of
  `String.trim()`. This blocks identity folding (`alice\n`, `alice\t`, `alice` + NUL, look-alike code
  points) *and* makes store-line forgery impossible: `|`, CR and LF can never reach
  `User.toLine()` (`User.java:20-24`), so the field separator cannot be injected.
- **Corrupt store fails closed** — a record with the wrong field count, a bad version, an
  unparseable timestamp, or a repeated username aborts the run with `IllegalStateException`
  (`User.java:29-40`, `AccountStore.java:130-139`); the program never half-loads a credential file to
  decide who may log in, and `PasswordHasher.matches` returns `false` for an unparseable record rather
  than throwing, so a caller cannot distinguish "no such account" from "damaged record"
  (`PasswordHasher.java:102-125`).
- **No lost-update or TOCTOU in registration** — `add` takes an exclusive `FileChannel` lock, re-reads
  the file *inside* the critical section, merges anything another process added, and replaces the file
  with `ATOMIC_MOVE` (`AccountStore.java:86-108, 145-171`); `load` takes a shared lock only for the
  snapshot (`AccountStore.java:57-68`). The duplicate check therefore reflects disk state, not the
  possibly stale in-memory map, and six racing processes were confirmed not to lose accounts.
- **Store and temp-file permissions are not permissive (disproved CWE-732 / CWE-377)** — the file is
  written via `Files.createTempFile(storeFile.getParent(), ...)`
  (`AccountStore.java:153`), which on POSIX creates the file with owner read/write only (`0600`)
  regardless of umask, and the replacement is a rename
  (`StandardCopyOption.ATOMIC_MOVE`, `AccountStore.java:156`) that preserves those bits rather than
  inheriting the destination's permissions. The parent directory always exists because line 36
  absolutises the path, so the temp file is created beside the store rather than in a shared `/tmp`,
  and every failure path deletes it in a `finally` block (`AccountStore.java:162-170`). No finding.
- **Secret material destroyed after use** — `PBEKeySpec.clearPassword()` in a `finally` block
  (`PasswordHasher.java:150-152`), derived digests zeroed (`PasswordHasher.java:93, 135`), and caller
  buffers zeroed via `Arrays.fill` on every exit path including `System.exit` (`Main.java:86-87, 105,
  120`). The console path uses `Console.readPassword`, which returns a `char[]` and never creates a
  `String` (`Main.java:198-204`); only the piped fallback does (SEC-04).
- **Error messages do not leak internals** — `main` catches `IllegalArgumentException` and
  `IllegalStateException` and prints only `e.getMessage()` (`Main.java:55-61`), and every such message
  is a fixed, user-facing string written at the throw site; no stack trace, no class name, no file
  offset and no stored hash reaches stderr, and `IOException` causes are summarised without exposing
  parsing state (`AccountStore.java:47-49, 63-64, 103-104`).
- **Plaintext passwords are never persisted or reflected** — `User` holds only the self-describing
  encoding (`User.java:11`), `toLine` writes version, username, encoding and epoch second
  (`User.java:20-24`), and no output statement prints a password or a derived key; `list` reports a
  count and a path, never usernames (`Main.java:124-127`), so it is not an enumeration channel.
- **`run.sh` has no shell injection surface (checked against CWE-78)** — `set -u` is active, `PROJ_DIR`
  and every path expansion are double-quoted, arguments are forwarded as `"$@"`, there is no `eval`,
  and the only unquoted expansions are `find` results naming the project's own fixed `.java` files,
  which contain no spaces or glob characters (`run.sh:9, 24, 30-32, 36`). A compilation failure is
  detected and exits 2 rather than falling through to the stale classes (`run.sh:30-34`).
- **Shipped bytecode matches the reviewed sources** — `javap -p -constants` on `out/account/*.class`
  reports `ITERATIONS = 210000`, `MIN_ITERATIONS = 10000`, `MAX_ITERATIONS = 20000000`,
  `PBKDF2WithHmacSHA256` and the same user-facing strings as `src/`, so `run.sh` executing prebuilt
  classes is not currently a divergence or a backdoor. The residual risk is procedural, not a code
  defect: the rebuild trigger at `run.sh:24` compares source mtimes against `out/account/Main.class`,
  so sources restored with older timestamps (a checkout, a `cp -p`) would run classes that do not
  correspond to them.
- **Absent attack surface confirmed** — no database or query construction (no SQL/NoSQL injection),
  no HTML/template rendering or unescaped response body (no XSS, no SSTI, no Open Redirect), no
  network I/O of any kind (no SSRF, no TLS/certificate handling, no SSRF-to-metadata), no
  `ObjectInputStream`/XML/JSON deserialisation of untrusted bytes, no `Runtime.exec` or subprocess, no
  JWT or cookie handling, no cryptographic key files, and no logging or telemetry that could carry a
  secret. `--store` is a path the operator supplies directly to their own process, so there is no
  lower-privilege caller whose input could be composed into it (no path traversal).
- **No embedded credentials (checked against CWE-798)** — the only credential-shaped constants are
  `EQUALIZING_PASSWORD` and `EQUALIZING_SALT` (`PasswordHasher.java:42-43`), fixed inputs whose sole
  purpose is to make the unknown-user branch cost a real derivation; they guard nothing and are not
  secrets, so they are deliberately not reported.
- **No authorisation boundary to test** — the program has one local operator, no sessions, roles or
  tenants, and no cross-user data; broken-access-control and session-management findings are not
  applicable, and case-sensitive usernames (`Alice` ≠ `alice`) is a documented design choice rather
  than an access-control defect.
