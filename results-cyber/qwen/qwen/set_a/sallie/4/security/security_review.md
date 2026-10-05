# Security Review: Account Registrar and Authenticator (Java)

## 1. Executive Summary

This is a dependency-free Java command-line program that registers a username/password pair,
stores only a PBKDF2-HMAC-SHA256 verifier in a flat file, and authenticates later against that
file. The core password-storage design is genuinely sound: per-account 16-byte `SecureRandom`
salt, a one-way salted derivation, `MessageDigest.isEqual` for comparison, key-derivation work
spent on every refusal so that timing does not leak whether an account exists, `char[]`
passwords that are wiped, and a store that refuses malformed records on load. 127 self-tests and
an 18-mutant mutation battery back those claims.

Ten findings remain, none of which is a broken hash. The two most consequential are outside the
crypto entirely: the program accepts a password as a **command-line argument**, which publishes
the secret to every local process through `ps` / `/proc/<pid>/cmdline` and into shell history
(SEC-01), and `login()` performs **no attempt counting, lockout, or rate limiting** of any kind,
so the ~85 ms derivation is the only thing between an attacker and an unbounded online guessing
rate (SEC-02). A cluster of medium findings covers the KDF work factor sitting roughly half of
the current OWASP recommendation while `tryParse` still accepts records as thin as 1,000 rounds
(SEC-03), a password policy that admits `Password1`-class secrets (SEC-04), file-permission
narrowing that fails **silently** (SEC-05), an unsynchronised whole-file rewrite that loses
updates and admits a registration TOCTOU (SEC-06), and credential material printed to stdout
(SEC-07). Lower-severity items are user enumeration through the non-timing channel that the
timing equalisation leaves open (SEC-08), a never-wiped filler array (SEC-09), and an
unvalidated `--store` / `ACCOUNT_STORE` path (SEC-10).

The README is candid about most of this — it lists rate limiting, lockout and concurrency safety
as "deliberately absent". That reduces surprise, not risk: this is reviewed as code, and each
documented gap is still reported below with a fix.

## 2. Scope

| Path | Lines | Role | Reviewed |
| --- | --- | --- | --- |
| `src/UserAccountApp.java` | 172 | CLI entry point: `register`, `login`, `inspect`, `selftest`, password acquisition, store path | Yes — full |
| `src/UserAccountService.java` | 93 | Registration and authentication rules, refusal statuses | Yes — full |
| `src/PasswordHasher.java` | 167 | PBKDF2 derivation, stored format, `verify`, `burnWork`, record parsing | Yes — full |
| `src/AccountStore.java` | 149 | Flat-file store: load/validate, add, atomic save, POSIX permissions | Yes — full |
| `src/Passwords.java` | 80 | Length bounds, unhashable-character guard, strength rule, wipe | Yes — full |
| `src/Usernames.java` | 54 | Username allowlist, space-only trim, `Locale.ROOT` fold | Yes — full |
| `src/SelfTest.java` | 676 | 127 behavioural checks; also reads `src/PasswordHasher.java` structurally | Yes — full (test code) |
| `README.md` | 175 | Design rationale; documents the argv usage examples and the absent controls | Yes — as evidence |
| `mutation-battery.sh` | 172 | 18 targeted defects, each required to be caught | Yes — informational only |
| `out/*.class` | 12 files | Compiled output of `src/` | No — derived artefacts, not source |
| `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `return.txt`, `result.md` | — | Harness/review metadata, not product code | No — out of scope |
| `security_review.md` | — | This report | — |

No deserialisation sink, no network listener, no session or token issuance, and no privilege
boundary crossing exist in this codebase, which bounds the applicable vulnerability classes.

## 3. Skills Applied

Selected by matching this program's behaviour against each skill's description, then applied one
at a time with `file:line` citations.

1. **`review-code-for-security-vulnerabilities`** — the dispatcher: understand all code first,
   match skills, apply bodies, report with CWE + `file:line` + fix.
2. **`performing-cryptographic-audit-of-application`** — drove SEC-03 and SEC-09, and the audit
   of primitive choice, salt generation/length, KDF work factor, comparison semantics, and
   secret lifetime. Its "weak KDF / low-iteration PBKDF2" row and its pointer to the OWASP
   Password Storage Cheat Sheet are the basis for the iteration-count finding; the recommended
   figure (600,000 for PBKDF2-HMAC-SHA256) was taken from that cheat sheet rather than from
   memory.
3. **`testing-api-authentication-weaknesses`** — OWASP API2:2023. Step 6 supplied the two checks
   that produced SEC-04 (weak-policy acceptance: the skill's own example list includes
   `Password1`, "meets basic complexity but is common") and SEC-08 (account enumeration by
   comparing the response for a valid versus an invalid account). Steps 1–5 (JWT, token
   lifecycle, unauthenticated endpoint discovery) have **no applicable surface** here — this
   program issues no tokens, sessions, or cookies — and are recorded in §6 as checked-with-no-
   finding.
4. **`performing-hash-cracking-with-hashcat`** — quantified the offline cost of a stolen store
   for SEC-03 and SEC-04, and supplied the validation criterion that matters here: a rule-based
   attack that "cracks policy-compliant passwords", which is exactly what a
   `length + two character classes` policy produces. Note that PBKDF2-HMAC-SHA256 is hashcat
   mode 10000; that mode is not listed in the skill's hash-type table, so the mapping comes from
   general knowledge.
5. **`exploiting-race-condition-vulnerabilities`** — TOCTOU / limit-overrun framing for SEC-06.
   The skill's scenario 5, "Account Registration Bypass — create multiple accounts with the same
   email by submitting concurrent registration requests", is the exact shape of
   `AccountStore.add`'s check-then-write.

**Reviewed and recorded as having no applicable sink:** `exploiting-insecure-deserialization`.
That skill's triggers are Java `ObjectInputStream` (`aced0005` / `rO0AB`), PHP `O:`, .NET
ViewState, Python `pickle`, and YAML `!!python/object`. None is present: the store is parsed by
hand with `line.indexOf('\t')` and `split("\\$", -1)`, then validated field by field
(`PasswordHasher.java:112-141`). See §6.

**Behaviours checked against general OWASP/CWE knowledge with no matching skill in the library:**
secrets exposed through process argv (CWE-214, SEC-01); filesystem permission assignment and
silent failure (CWE-276/732, SEC-05); credential material written to stdout and therefore into
logs and scrollback (CWE-532/212, SEC-07); symlink/path handling of the `--store` and
`ACCOUNT_STORE` inputs (CWE-59/377, SEC-10); memory wiping of residual secret material
(CWE-226, SEC-09, cross-checked against the cryptographic-audit skill).

## 4. Summary of Findings

| ID | Severity | CWE | Title | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | High | CWE-214, CWE-522 | Password accepted as a command-line argument | `src/UserAccountApp.java:114-116` |
| SEC-02 | High | CWE-307 | No attempt limit, lockout, or rate limiting on login | `src/UserAccountService.java:60-76` |
| SEC-03 | Medium | CWE-916, CWE-326 | PBKDF2 work factor below current guidance; 1,000-round records still accepted | `src/PasswordHasher.java:21-23, 126` |
| SEC-04 | Medium | CWE-521 | Password policy admits common single-pattern secrets | `src/Passwords.java:4, 52-72` |
| SEC-05 | Medium | CWE-276, CWE-732 | Store permission narrowing fails silently | `src/AccountStore.java:127-135` |
| SEC-06 | Medium | CWE-362, CWE-367 | Unlocked whole-file read-modify-write; registration TOCTOU | `src/AccountStore.java:32-62, 80-89, 93-125` |
| SEC-07 | Medium | CWE-532, CWE-212 | Verifier material printed to stdout | `src/UserAccountApp.java:61-62, 104-110` |
| SEC-08 | Low | CWE-204 | Account enumeration through the non-timing channel | `src/UserAccountService.java:64, 68, 73, 79-81, 89-92`, `src/UserAccountApp.java:72, 100` |
| SEC-09 | Low | CWE-226 | Derivation filler array is never wiped | `src/PasswordHasher.java:35-36, 89-98` |
| SEC-10 | Low | CWE-59, CWE-377 | Unvalidated account-store path from argv or environment | `src/UserAccountApp.java:136-143` |

## 5. Detailed Findings

### SEC-01 — Password accepted as a command-line argument

**Severity:** High
**CWE:** CWE-214 (Sensitive Information in Process Arguments), CWE-522 (Insufficiently Protected Credentials)
**Location:** `src/UserAccountApp.java:114-116`; reached from `:55` (`register`) and `:83` (`login`); examples at `README.md:118, 120`

**Vulnerable code**

```java
    private static char[] takePassword(String[] args, int index, String prompt) {
        if (args.length > index && !"-".equals(args[index])) {
            return args[index].toCharArray();
        }
        Console console = System.console();
```

`README.md:118` and `README.md:120` present this as the primary usage:

```bash
java -cp out UserAccountApp register AdaLovelace 'Correct Horse 9'
java -cp out UserAccountApp login    adalovelace 'Correct Horse 9'
```

**Why it is a problem**

Everything after `java` in that line is stored verbatim in the process's argument vector, which
on Linux is world-readable through `/proc/<pid>/cmdline` and is rendered by `ps aux`, `top`,
`htop`, `ps -ef` in `auditd`/`syslog` process-accounting records, monitoring agents, crash
reporters, and shell history (`.bash_history` keeps the whole line, quotes and all). The secret
therefore outlives the process immediately, is copied into every log and terminal recording of
the invocation, and cannot be revoked from those copies. It also defeats the care taken
everywhere else in this program: the password is carefully carried as `char[]` and wiped
(`UserAccountApp.java:57, 85`, `Passwords.java:75-79`), yet it arrives through a channel that is
more exposed than the verifier file it protects. A `Console` prompt path and a `-` stdin path
already exist (`UserAccountApp.java:118-131`), so the argv form buys nothing except exposure.

**Fix**

Never read a secret from argv. Keep the prompt path, keep `-` for "read from standard input", and
refuse a literal password argument with a message that says why:

```java
    private static char[] takePassword(String[] args, int index, String prompt) {
        if (args.length > index && !"-".equals(args[index])) {
            System.err.println("Refusing a password given as an argument: command lines are visible"
                    + " to every local process (ps, /proc/<pid>/cmdline) and are kept in shell"
                    + " history. Omit the argument to be prompted, or pass '-' to read it from stdin.");
            System.exit(2);
            return new char[0];
        }
        Console console = System.console();
        // ... unchanged prompt / stdin paths ...
    }
```

Update `README.md:110-122` so the documented examples are the safe ones. Note that the
`positional()` helper at `UserAccountApp.java:147` already drops option-looking tokens, so
dropping the argv password does not disturb option parsing. For genuinely non-interactive use,
read from a mode-0600 file descriptor (`--password-file` opened and wiped) rather than argv.


### SEC-02 — No attempt limit, lockout, or rate limiting on login

**Severity:** High
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**Location:** `src/UserAccountService.java:60-76`; absence acknowledged at `README.md:169-172`

**Vulnerable code**

```java
    public Outcome login(String rawUsername, char[] candidate) {
        String username = Usernames.normalize(rawUsername);
        if (username == null || !Passwords.withinLength(candidate)) {
            hasher.burnWork();
            return new Outcome(username == null ? Status.INVALID_USERNAME : Status.INVALID_PASSWORD);
        }
        if (!Passwords.isHashable(candidate)) {
            hasher.burnWork();
            return new Outcome(Status.REJECTED);
        }
        Optional<String> stored = store.verifierFor(username);
        if (stored.isEmpty()) {
            hasher.burnWork();
            return new Outcome(Status.REJECTED);
        }
        boolean matched = hasher.verify(candidate, stored.get());
        return new Outcome(matched ? Status.OK : Status.REJECTED);
    }
```

**Why it is a problem**

`UserAccountService` keeps no state between calls (`:26-27` are the only fields), so nothing in
the authentication path counts attempts, remembers failures, delays repeats, or locks an account.
`README.md:169-170` lists "rate limiting and lockout after repeated failures" as deliberately
absent, which is a statement of scope rather than a mitigation: the class is written as a
reusable service — it takes `char[]` candidates and returns a structured `Outcome` — and any
embedding that puts `login()` behind a socket, form handler, or automation endpoint inherits an
unbounded guessing oracle from it. Two consequences follow. First, online guessing is limited
only by the caller's CPU: nothing here even slows a scripted loop on the *same* account, and
credential stuffing across usernames is not considered at all. Second, the equalising
`burnWork()` at `:63, 67, 72` means an unauthenticated caller can force a full 310,000-round
derivation per request without holding any credential, so the same missing counter is also the
cheapest available CPU-exhaustion vector. The 310,000 rounds protect a *stolen file* (an offline
attacker pays per guess); they do not protect the *live endpoint*, where the defender pays per
guess on the attacker's schedule.

**Fix**

Add a failure counter keyed on the account (and, when exposed over a channel, on the source
identity), returning the same uniform refusal so the counter itself is not an oracle:

```java
    private static final int MAX_FAILURES = 10;
    private static final long COOLDOWN_NANOS = java.util.concurrent.TimeUnit.MINUTES.toNanos(15);

    private final java.util.concurrent.ConcurrentMap<String, long[]> failures =
            new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentMap<String, Long> lockedUntil =
            new java.util.concurrent.ConcurrentHashMap<>();

    public Outcome login(String rawUsername, char[] candidate) {
        String username = Usernames.normalize(rawUsername);
        if (username != null && isLockedOut(username)) {
            hasher.burnWork();                       // keep refusal cost identical
            return new Outcome(Status.REJECTED);
        }
        // ... existing shape checks, unchanged ...
        boolean matched = hasher.verify(candidate, stored.get());
        if (matched) {
            failures.remove(username);
            lockedUntil.remove(username);
        } else {
            noteFailure(username);
        }
        return new Outcome(matched ? Status.OK : Status.REJECTED);
    }

    private boolean isLockedOut(String username) {
        Long until = lockedUntil.get(username);
        return until != null && System.nanoTime() < until;
    }

    private void noteFailure(String username) {
        long[] state = failures.compute(username, (key, previous) -> {
            long now = System.nanoTime();
            if (previous == null || now - previous[1] > COOLDOWN_NANOS) {
                return new long[] {1, now};
            }
            previous[0]++;
            return previous;
        });
        if (state[0] >= MAX_FAILURES) {
            lockedUntil.put(username, System.nanoTime() + COOLDOWN_NANOS);
            failures.remove(username);
        }
    }
```

For anything beyond a single process, the counters must live in shared storage (Redis, a DB
row) with both per-account and per-source keys, plus exponential backoff and an alert on the
threshold being reached — the same remediation the race-condition skill prescribes for
attempt-limiting mechanisms ("implement distributed locks for multi-server environments").


### SEC-03 — PBKDF2 work factor below current guidance, with a 1,000-round acceptance floor

**Severity:** Medium
**CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort), CWE-326 (Inadequate Encryption Strength)
**Location:** `src/PasswordHasher.java:21-23`, enforced at `:126`, used at `:79`; no upgrade path (`README.md:171-172`)

**Vulnerable code**

```java
    public static final int DEFAULT_ITERATIONS = 310_000;
    public static final int MIN_ITERATIONS = 1_000;
    public static final int MAX_ITERATIONS = 5_000_000;
```

```java
        if (rounds < MIN_ITERATIONS || rounds > MAX_ITERATIONS) {
            return null;
        }
```

**Why it is a problem**

Two separate weaknesses share one constant block.

*The default is behind the times.* OWASP's Password Storage Cheat Sheet currently states
"PBKDF2-HMAC-SHA256: 600,000 iterations (recommended)". `DEFAULT_ITERATIONS = 310_000` is about
half that, so a file disclosed today costs an attacker half the work the design intended. The
absence of re-hashing "when the round count is raised" (`README.md:171-172`) makes this strictly
worse over time: verifiers are written once at the creation-time cost and never revisited, so
every stored account is permanently marked with the hardware assumptions of the day it was
created, and raising the constant only helps accounts registered after the change.

*The acceptance floor is a policy hole.* `MIN_ITERATIONS = 1_000` is not a "legacy compatibility"
floor, it is 310 times cheaper than the policy. `tryParse` accepts any record in
[1,000, 5,000,000] and `verify` then derives using `record.iterations()` (`:79`), so the
attacker-relevant work factor is read from the same file an attacker wants to crack. A store
that was ever written by a lower setting — `SelfTest` legitimately builds temp stores at 2,000
rounds (`SelfTest.java:82, 258, 436`), and `PasswordHasher(int)` is public — is accepted silently
and forever by the default configuration; the program never warns that the accounts it is
protecting are up to 310x weaker than it claims in its own documentation. In cracking terms (the applied hash-cracking skill's
methodology), a 1,000-round PBKDF2-HMAC-SHA256 record is a fast-hash target: a dictionary plus
rules run against it at GPU wordlist rates, not at the "tens of thousands of times more expensive
per guess" rate that `README.md:30` promises.

There is a second-order effect on the program's headline control. `burnWork()` always derives at
the *hasher's* cost, while `verify` derives at the *record's* cost, so for a 1,000-round record a
wrong password returns in well under a millisecond while an unknown account returns in ~85 ms.
That is precisely the "instant for unknown users, slow for known ones" signal
`README.md:52-56` says the design exists to remove — reachable without any password at all.

**Fix**

Separate "parseable" from "allowed by policy", and make the cost a property of the deployment
rather than of the file:

```java
    public static final int DEFAULT_ITERATIONS = 600_000;   // OWASP: 600,000 for PBKDF2-HMAC-SHA256
    public static final int MIN_ITERATIONS = 1_000;         // parse floor: what the format can express
    public static final int MAX_ITERATIONS = 5_000_000;
    /** Records below this are refused outright: the file must not set the security level. */
    public static final int POLICY_MIN_ITERATIONS = DEFAULT_ITERATIONS;

    public static boolean meetsPolicy(StoredRecord record) {
        return record != null && record.iterations() >= POLICY_MIN_ITERATIONS;
    }
```

Refuse sub-policy records at load time rather than accepting them quietly
(`AccountStore.load`, around `:55`):

```java
            if (Usernames.normalize(user) == null
                    || PasswordHasher.tryParse(verifier) == null
                    || !PasswordHasher.meetsPolicy(PasswordHasher.tryParse(verifier))) {
                throw new IllegalStateException("Weak or malformed account store " + file
                        + " at line " + (i + 1));
            }
```

and upgrade on successful login so the cost can rise over the store's lifetime:

```java
        boolean matched = hasher.verify(candidate, stored.get());
        if (matched) {
            PasswordHasher.StoredRecord record = PasswordHasher.tryParse(stored.get());
            if (record.iterations() < hasher.iterations()) {
                store.replace(username, hasher.hash(candidate));   // same password, current cost
            }
        }
```

Measure the new default rather than trusting a constant: pick the highest round count that keeps
verification inside the latency budget on the deployed hardware, and document the measured value.
If the format can be changed, `README.md:173-175` is right that Argon2id (`m=19456, t=2, p=1`) or
scrypt (`N=2^17, r=8, p=1`) resist GPU and custom-hardware cracking far better than PBKDF2. Also
consider a pepper — a secret mixed into the derivation and held *apart* from the store file, which
is what makes a file disclosure alone insufficient.


### SEC-04 — Password policy admits common single-pattern secrets

**Severity:** Medium
**CWE:** CWE-521 (Weak Password Requirements)
**Location:** `src/Passwords.java:4`, `src/Passwords.java:52-72`; called from `src/UserAccountService.java:42-43`

**Vulnerable code**

```java
    public static boolean strongEnough(char[] password) {
        if (!withinLength(password)) {
            return false;
        }
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean other = false;
        for (char c : password) {
            if (c >= 'a' && c <= 'z') {
                lower = true;
            } else if (c >= 'A' && c <= 'Z') {
                upper = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            } else {
                other = true;
            }
        }
        int classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (other ? 1 : 0);
        return classes >= 2;
    }
```

**Why it is a problem**

The rule is `length >= 8` plus "at least two character classes", with no denylist and no
comparison against breached or common passwords. Every example the applied authentication skill
uses to demonstrate a weak policy is accepted here: `Password1`, `passw0rd`, `qwerty123`,
`abcABC123`, `letmein1`. Character-class counting is a 2005-era proxy that does not measure
guessability at all — it rewards exactly the capitalise-first-letter, append-a-digit,
substitute-a-zero transformations that hashcat's `best64`-style rule sets exist to generate.
Because this program's entire defence against a disclosed store is "the password was not
guessable" (`README.md:32-33` says as much: "no stored password is *literally* unrecoverable,
because people choose guessable passwords"), the policy is not a UX detail; it is the term that
multiplies the KDF cost from SEC-03. A single cracked common password in the file is a full
account takeover regardless of how many rounds were used. The README's own demo secret,
`'Correct Horse 9'` (`README.md:118`), is a dictionary-phrase pattern of exactly this class.

**Fix**

Set a length floor of 12, relax the composition requirement only for genuinely long passphrases,
and reject known-breached values. The comparison must not materialise the password as a `String`,
which would defeat the `char[]` discipline used elsewhere:

```java
    public static final int MIN_LENGTH = 12;
    private static final String[] DENIED = {
        "password", "password1", "passw0rd", "qwerty123", "12345678", "iloveyou", "letmein1",
    };

    public static boolean strongEnough(char[] password) {
        if (!withinLength(password)) {
            return false;
        }
        if (password.length < 12 && characterClasses(password) < 3) {
            return false;                       // short secrets must be mixed; long ones may not
        }
        char[] folded = new char[password.length];
        try {
            for (int i = 0; i < password.length; i++) {
                folded[i] = Character.toLowerCase(password[i]);
            }
            for (String denied : DENIED) {
                if (matchesIgnoringCase(folded, denied)) {
                    return false;
                }
            }
            return true;
        } finally {
            java.util.Arrays.fill(folded, '\0');
        }
    }

    private static boolean matchesIgnoringCase(char[] folded, String denied) {
        if (folded.length != denied.length()) {
            return false;
        }
        for (int i = 0; i < denied.length(); i++) {
            if (folded[i] != Character.toLowerCase(denied.charAt(i))) {
                return false;
            }
        }
        return true;
    }
```

A static list is the floor, not the answer. For real coverage check the candidate against a
breached-password corpus using a k-anonymised range query, and measure the resulting entropy
against the store's own cracking cost rather than against a class count.


### SEC-05 — Permission narrowing fails silently

**Severity:** Medium
**CWE:** CWE-276 (Incorrect Default Permissions), CWE-732 (Incorrect Permission Assignment for Critical Resource)
**Location:** `src/AccountStore.java:127-135`, called at `:106` and `:113`; no mode check in `load()` at `:32-62`

**Vulnerable code**

```java
    private static void narrowPermissions(Path path) {
        try {
            Set<PosixFilePermission> only = Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, only);
        } catch (UnsupportedOperationException | IOException e) {
            // Filesystem without POSIX permissions, or the file vanished: nothing else to do.
        }
    }
```

**Why it is a problem**

The file being protected is the credential store, and this is the only line of defence applied to
it. The catch is total: `UnsupportedOperationException` means the filesystem has no POSIX
permissions at all — the case where the protection is entirely absent — and the program
continues, prints nothing, and exits `0` as if the store were protected. `IOException` is treated
the same way. So on Windows NTFS, on SMB/CIFS and NFS mounts, inside some container bind mounts,
and on any filesystem where the `chmod` fails, the store's accessibility is decided by directory
ACL inheritance and the mount's permission masks with no signal to the operator, while
`README.md:83` states flatly that "the file is set to `0600` (only the owner may read it)".
Three specific gaps follow. (1) No verification: the code never reads back the attributes it
believes it applied. (2) No operator feedback: a protection that silently did not happen is worse
than one that fails loudly, because it removes the reason to look. (3) No check of an
*already-existing* file: `load()` inspects every byte of the store's *content* for malformed
records (`:44-59`) but never asks who can read the file, so a store created world-readable by
`cp`, `scp`, a shared-directory umask, or a restore from backup keeps working for years while
being open to every local account. Note the one mitigating fact, so this is not overstated:
`Files.createTempFile` creates the temp file owner-only on POSIX, and `ATOMIC_MOVE` preserves that
inode's mode, so the normal Linux save path does yield `0600` even if the `chmod` at `:113`
failed — which is exactly why a silent catch is easy to ship and hard to notice.

**Fix**

Verify what was applied, and make the unprotectable case loud rather than invisible:

```java
    private static void narrowPermissions(Path path) {
        Set<PosixFilePermission> only = Set.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        try {
            Files.setPosixFilePermissions(path, only);
            if (!Files.getPosixFilePermissions(path).equals(only)) {
                throw new IllegalStateException("Unable to restrict permissions on " + path);
            }
        } catch (UnsupportedOperationException e) {
            System.err.println("WARNING: " + path.getFileName() + " is on a filesystem without POSIX"
                    + " permissions; the account store is NOT protected by file mode. Point"
                    + " ACCOUNT_STORE at a path on an access-controlled filesystem.");
        } catch (IOException e) {
            throw new IllegalStateException("Unable to restrict permissions on " + path, e);
        }
    }
```

and report exposure when loading a store somebody else created
(`AccountStore.java:36-39`, just after the existence check at `:34`):

```java
        try {
            Set<PosixFilePermission> mode = Files.getPosixFilePermissions(file);
            if (mode.contains(PosixFilePermission.GROUP_READ)
                    || mode.contains(PosixFilePermission.OTHERS_READ)
                    || mode.contains(PosixFilePermission.GROUP_WRITE)
                    || mode.contains(PosixFilePermission.OTHERS_WRITE)) {
                System.err.println("WARNING: account store " + file + " is readable or writable by"
                        + " others: " + PosixFilePermissions.toString(mode));
            }
        } catch (UnsupportedOperationException | IOException e) {
            System.err.println("WARNING: unable to check permissions on " + file + ": " + e);
        }
```

### SEC-06 — `AccountStore` does an unlocked whole-file read-modify-write; registration is a check-then-act

**Severity:** Medium
**CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization), CWE-367 (Time-of-check Time-of-use Race Condition)
**Location:** `src/AccountStore.java:32-62` (`load()`), `src/AccountStore.java:80-89` (`add()`), `src/AccountStore.java:93-125` (`flush()`)

Vulnerable code (`:80-90`):

```java
    public boolean add(String username, String verifier) {
        if (PasswordHasher.tryParse(verifier) == null) {
            throw new IllegalArgumentException("refusing to store a malformed verifier");
        }
        if (records.containsKey(username)) {
            return false;
        }
        records.put(username, verifier);
        flush();
        return true;
    }
```

and the write half (`:100-113`):

```java
            Path dir = file.getParent();
            if (dir != null) {
                Files.createDirectories(dir);
            }
            temp = Files.createTempFile(dir, file.getFileName().toString(), ".tmp");
            Files.write(temp, text.toString().getBytes(StandardCharsets.UTF_8));
            narrowPermissions(temp);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
            temp = null;
            narrowPermissions(file);
```

**Why this is a problem.** `load()` (`:32-62`) slurps the whole file into an in-memory `LinkedHashMap` and nothing ever re-reads it. `add()` then performs check-then-act against that snapshot — `records.containsKey(username)` at `:84` is evaluated against data read at `:39` — and `flush()` serialises the *entire* map and `REPLACE_EXISTING`-moves it over the target. Two processes against the same store therefore produce two well-known interleavings:

* **Lost update.** P1 loads *n* accounts, P2 loads *n*, P1 registers Alice and writes *n+1*, P2 registers Bob and writes *n+1*. Bob's file replaced Alice's whole map: Alice is gone, silently, and both processes printed `Registered account`.
* **Duplicate registration.** Two concurrent registrations of the same username both pass `:84` and both return `true`. That is precisely the scenario the `exploiting-race-condition-vulnerabilities` skill names as "Account Registration Bypass" — concurrent requests to a state check that is not atomic with the state change.

`ATOMIC_MOVE` at `:108` prevents *torn* files, which is a different property: indivisible replacement is exactly the mechanism by which the losing writer's data vanishes. There is no `FileChannel.lock()`, no lock file, no version or `mtime` check before the move, and `flush()` is public, so callers can compose load → mutate → flush across an arbitrary window. `SelfTest` only ever drives a single writer, so nothing in the 127 checks exercises this.

`README.md:171-172` states the limit — "concurrency safety (the store rewrites the whole file, so run one process at a time against it)" — and that honesty is why this is Medium rather than High. But an admission is a scope statement, not a mitigation: `AccountStore` is a public class with a public `flush()`, the load-mutate-save lifecycle invites multi-process use, and "run one process at a time" is not enforceable from inside the class that would be corrupted by breaking it.

**Fix.** Take an OS advisory lock across the whole load → check → mutate → save sequence, so the check and the act share a critical section:

```java
    public boolean add(String username, String verifier) {
        if (PasswordHasher.tryParse(verifier) == null) {
            throw new IllegalArgumentException("refusing to store a malformed verifier");
        }
        try (FileChannel lockChannel = FileChannel.open(
                Path.of(file.toString() + ".lock"),
                StandardOpenOption.CREATE, StandardOpenOption.WRITE);
             FileLock ignored = lockChannel.lock()) {   // blocks until the other writer is done
            load();                                     // re-read under the lock
            if (records.containsKey(username)) {
                return false;
            }
            records.put(username, verifier);
            flush();
            return true;
        }
    }
```

For multi-host use an advisory lock is not enough, and the skill's own remediation list applies: move the store behind a database with row-level locking, add an optimistic version column, key registrations with an idempotency key, or hold a distributed lock. A single-node alternative that avoids `FileChannel` is optimistic concurrency — record the store's `mtime` and size at load time and have `flush()` refuse to move when either changed, asking the caller to re-merge.

### SEC-07 — The stored verifier is printed to stdout, where the store file's protections do not follow it

**Severity:** Medium
**CWE:** CWE-532 (Insertion of Sensitive Information into Log File), CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer)
**Location:** `src/UserAccountApp.java:61-62`, `src/UserAccountApp.java:104-110`

Vulnerable code — printed after every successful registration (`:59-63`):

```java
            case OK -> {
                System.out.println("Registered account '" + Usernames.normalize(rest[0]) + "'.");
                System.out.println("Stored verifier: "
                        + service.storedVerifier(rest[0]).orElse("(unavailable)"));
                System.out.println("No password was stored; only this salted hash was.");
            }
```

and the `inspect` breakdown (`:104-110`):

```java
        System.out.println("stored string : " + stored.get());
        System.out.println("algorithm     : " + PasswordHasher.FORMAT_TAG);
        System.out.println("iterations    : " + record.iterations());
        System.out.println("salt (base64) : " + java.util.Base64.getEncoder()
                .encodeToString(record.salt()));
        System.out.println("hash (base64) : " + java.util.Base64.getEncoder()
                .encodeToString(record.digest()));
```

**Why this is a problem.** The whole design of `AccountStore` is that the verifier is confidential: it is created `0600` and narrowed after every write (SEC-05 is about enforcing that). stdout has no such control. Whatever the surrounding environment does with it applies — terminal scrollback, a CI job's console log, `tee`, a `script` or `asciinema` recording, a systemd unit's `StandardOutput`, a log aggregator that retains copies off-host for months. The store's `0600` and its directory never travel with that copy, and its lifetime is nobody's responsibility.

`inspect` is the more explicit case: it prints the whole record *and* a decoded breakdown, which is a hashcat mode `10000` input in human form. `README.md:128-130` says so itself — `inspect` "prints the salt and the hash for an account, which is everything an attacker with the file would have". That is the right lesson to teach and the wrong reason to emit it by default: the program is advertising that its own standard output is an offline-cracking input.

This is deliberately kept distinct from SEC-01. The verifier is not the password; printing it does not hand over a credential, it hands over the ability to *test* credentials offline. That is exactly what the store file is for, and exactly why its permissions were tightened — the same material leaving through an uncontrolled channel deserves the same attention.

**Fix.** Do not echo the verifier after `register`; make `inspect` mask by default and require an explicit opt-in:

```java
            case OK -> {
                System.out.println("Registered account '" + Usernames.normalize(rest[0]) + "'.");
                System.out.println("No password was stored; only a salted hash, in the store file.");
            }
```

```java
        boolean showFull = java.util.Arrays.asList(rest).contains("--unsafe-show-verifier");
        String salt = java.util.Base64.getEncoder().encodeToString(record.salt());
        System.out.println("salt (base64) : "
                + (showFull ? salt : salt.substring(0, Math.min(8, salt.length())) + "…(masked)"));
        if (!showFull) {
            System.out.println("Pass --unsafe-show-verifier to print the full record. Note that stdout is"
                    + " typically retained and shipped elsewhere, unlike the 0600 store file.");
        }
```

If a full dump is genuinely wanted for the teaching demo, send it to stderr with a one-line warning so the operator can redirect it deliberately rather than have it captured by whatever wraps the command.

### SEC-08 — Account enumeration survives through the non-timing channel

**Severity:** Low
**CWE:** CWE-204 (Observable Response Discrepancy)
**Location:** `src/UserAccountService.java:64, 68, 73, 79-81, 89-92`, `src/UserAccountApp.java:72, 100`

Vulnerable code (`UserAccountService.java:60-64` and `:79-81`):

```java
    public Outcome login(String rawUsername, char[] candidate) {
        String username = Usernames.normalize(rawUsername);
        if (username == null || !Passwords.withinLength(candidate)) {
            hasher.burnWork();
            return new Outcome(username == null ? Status.INVALID_USERNAME : Status.INVALID_PASSWORD);
        }
```

```java
    public boolean accountExists(String rawUsername) {
        String username = Usernames.normalize(rawUsername);
        return username != null && store.contains(username);
    }
```

and the CLI's zero-cost oracle (`UserAccountApp.java:72`):

```java
            case ACCOUNT_EXISTS -> System.out.println("Rejected: that account already exists.");
```

**Why this is a problem.** The code spends real effort making *time* uniform — `burnWork()` runs a full derivation on every refusal path (`:63, 67, 72`), and `SelfTest` holds the five refusal shapes between 0.6x and 1.8x of a real check. Then the answer comes back through three channels that cost nothing:

* `:64` returns a different `Status` for an unusable username than for an unusable password, and `:68`/`:73` collapse other refusals into `REJECTED` — three distinct shapes out of one function.
* `accountExists()` (`:79-81`) and `storedVerifier()` (`:89-92`) are public existence oracles; one is a boolean, the other an `Optional`.
* The CLI prints `Rejected: that account already exists.` (`UserAccountApp.java:72`) for a username alone, with no password supplied and no derivation performed, and `No such account.` (`:100`) for `inspect`.

`README.md:57-59` defends the duplicate fast path — "a new username is checked against the list before any hashing happens, which is the right way round" — and that is true *as written about timing*. It is still an enumeration primitive: one string compare against a 310,000-round derivation the rest of the design exists to force. This is the check Step 6 of `testing-api-authentication-weaknesses` asks for — compare responses for valid versus invalid accounts, not just their timings. For a local CLI whose caller can already read the file, the marginal exposure is small (hence Low); the `Status` enum is exactly the shape a network embedding would serialise, so the same code behind a socket makes this Medium.

**Fix.** Collapse refusals into one observable outcome, and demote the oracles:

```java
    public Outcome login(String rawUsername, char[] candidate) {
        String username = Usernames.normalize(rawUsername);
        if (username == null || !Passwords.withinLength(candidate) || !Passwords.isHashable(candidate)) {
            hasher.burnWork();
            return new Outcome(Status.REJECTED);      // one shape for every refusal
        }
        // ... unchanged: unknown account and damaged record also return Status.REJECTED
    }
```

Keep the fine-grained reason for diagnostics only — a field that is never serialised, or a log line at a debug level an embedding has to enable deliberately. Make `accountExists()` and `storedVerifier()` package-private or test-scoped (the CLI's `inspect` can go through the same path `SelfTest` uses), so a caller cannot ask the question directly. For `register` the tension is real and unavoidable: telling a user "that username is taken" *is* an enumeration answer. Either accept and document it, or return a generic acknowledgement and confirm the outcome out of band.

### SEC-09 — The derivation filler array is allocated once and never wiped

**Severity:** Low
**CWE:** CWE-226 (Sensitive Information or Data in Unreleased Resource Before Release or Reuse)
**Location:** `src/PasswordHasher.java:35-36`, `src/PasswordHasher.java:89-98`

Vulnerable code:

```java
    private char[] dummyPassword;
    private byte[] dummySalt;
```

```java
    private synchronized void ensureDummyMaterial() {
        if (dummySalt == null) {
            dummySalt = new byte[SALT_BYTES];
            random.nextBytes(dummySalt);
            dummyPassword = new char[32];
            for (int i = 0; i < dummyPassword.length; i++) {
                dummyPassword[i] = (char) ('a' + random.nextInt(26));
            }
        }
    }
```

**Why this is a problem.** `burnWork()` (`:84-87`) exists so a refusal costs a real derivation, and its operands are built once and then retained for the process's whole life: after the first refused login, a core dump or heap inspection contains a 32-character password-shaped `char[]` and a 16-byte salt-shaped array until the JVM exits.

Severity is Low and the reasoning should stay honest. These are random filler from `random.nextInt(26)`; they are not a user secret, they are never equal to anyone's password, and nothing is protected by them. What makes the finding worth recording is consistency with the rest of the class: `derive()` takes care to run `spec.clearPassword()` in a `finally` (`:107`), and — as SEC-01 explains — that call only clears `PBEKeySpec`'s *internal* copy, which is precisely why the caller has to wipe the array it passed in. The dummy pair is the one derivation material this class owns outright and could clear itself. It is also the array most likely to be mistaken for real material by whoever reads a crash dump.

**Fix.** Build the filler per call and clear it, so no derivation operand outlives the call that needed it:

```java
    public void burnWork() {
        char[] filler = new char[32];
        byte[] salt = new byte[SALT_BYTES];
        try {
            random.nextBytes(salt);
            for (int i = 0; i < filler.length; i++) {
                filler[i] = (char) ('a' + random.nextInt(26));
            }
            derive(filler, salt, iterations);
        } finally {
            Passwords.wipe(filler);
            java.util.Arrays.fill(salt, (byte) 0);
        }
    }
```

The fields at `:35-36` and `ensureDummyMaterial()` then go away entirely. If keeping them is preferred to avoid re-allocating on every refusal, blank both in a `finally` inside `burnWork()` and let `ensureDummyMaterial()` rebuild them — the allocation is negligible next to the derivation it feeds.

### SEC-10 — The account-store path comes from argv or the environment with no validation

**Severity:** Low
**CWE:** CWE-59 (Improper Link Resolution Before File Access), CWE-377 (Insecure Temporary File)
**Location:** `src/UserAccountApp.java:136-143`; sinks at `src/AccountStore.java:27-29` and `src/AccountStore.java:100-113`

Vulnerable code (`UserAccountApp.java:136-144`):

```java
    private static String storePathFrom(String[] args) {
        for (int index = 0; index + 1 < args.length; index++) {
            if ("--store".equals(args[index])) {
                if (index + 1 >= args.length) {
                    System.out.println("--store requires a path");
                    System.exit(2);
                }
                return args[index + 1];
            }
        }
        String fromEnvironment = System.getenv("ACCOUNT_STORE");
        return fromEnvironment == null ? DEFAULT_STORE : fromEnvironment;
    }
```

and what the class does with it (`AccountStore.java:27-29`, `:100-108`):

```java
    public AccountStore(Path file) {
        this.file = file.toAbsolutePath();
    }
```

```java
            Path dir = file.getParent();
            if (dir != null) {
                Files.createDirectories(dir);
            }
            temp = Files.createTempFile(dir, file.getFileName().toString(), ".tmp");
            Files.write(temp, text.toString().getBytes(StandardCharsets.UTF_8));
            narrowPermissions(temp);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
```

**Why this is a problem.** `--store` and `$ACCOUNT_STORE` are legitimate features for a teaching tool. What follows them is the concern: the constructor does nothing but `toAbsolutePath()` (`AccountStore.java:27-29`), and `flush()` responds by creating whatever parent directory is named and overwriting whatever file is named, in full. So the program's single write primitive is aimed by unvalidated input, and an attacker-controlled `ACCOUNT_STORE` in a launched environment — a CI job that exports variables into steps, a cron wrapper, a support script that inherits an exported value — redirects a whole-file rewrite at any path the process can write: `~/.ssh/authorized_keys`, `~/.bashrc`, a systemd unit. The damage is the destruction of that file's real contents, replaced by `username<TAB>verifier` lines that the victim's shell or sshd will then be handed; the username allowlist (`[A-Za-z0-9._@-]`, `Usernames.java`) means the injected text is not arbitrary, which limits the second stage but does nothing about the overwrite itself. The environment variable is also silent: the store can move away from `accounts.txt` with no notice at all (contrast the permission warning proposed in SEC-05).

Be precise about the symlink question, because the usual CWE-59 framing overstates it here. `flush()` never opens `file` for writing — it writes a temporary and `ATOMIC_MOVE`s over the target, which normally replaces the link itself rather than following it. So classic symlink-following into a privileged file is *not* the main exposure on the atomic path; it returns on the non-POSIX fallback at `:110`, and it does not need to work at all for an arbitrary-path overwrite of a regular file to matter. CWE-377 is included for the same reason in reverse: the `.tmp` sibling is created with a predictable prefix derived from the store's own name in a directory the caller chose, and relies on the later move plus `narrowPermissions` for its protection.

**Fix.** Validate the path before constructing the store, and make a relocated store loud:

```java
    private static String storePathFrom(String[] args) {
        String value = /* unchanged --store / ACCOUNT_STORE / DEFAULT_STORE resolution */;
        Path resolved = Path.of(value);
        if (Files.exists(resolved, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(resolved) || !Files.isRegularFile(resolved)) {
                System.out.println("Store path must be a regular file, not a link or directory: " + resolved);
                System.exit(2);
            }
            resolved = resolved.toRealPath();
        }
        if (!value.equals(DEFAULT_STORE)) {
            System.out.println("Account store: " + resolved);   // never relocate silently
        }
        return resolved.toString();
    }
```

Inside `AccountStore`, reject a parent directory that is writable by group or others (SEC-05's read check generalises to a write check), and keep the temporary on the same filesystem but with an unpredictable suffix so a co-located attacker cannot pre-create or race the name.

## 6. Verified Controls and Checks With No Finding

The code is unusually well-built for its size, and the review confirmed most of it rather than assuming it. What follows is what was checked and found sound, with the evidence that showed it.

* **One-way storage, correctly done.** PBKDF2-HMAC-SHA256 via `PBKDF2WithHmacSHA256`, random 16-byte per-account salt from `SecureRandom` (`PasswordHasher.java:60`), salt and round count stored in the clear alongside the digest, no reuse across accounts — salt uniqueness is asserted in `SelfTest`. No encryption, no reversible encoding, no home-grown construction anywhere.
* **Constant-time comparison, structurally proven.** `MessageDigest.isEqual` at `PasswordHasher.java:80`, and `SelfTest` checks the *structure* (no `Arrays.equals` early exit) rather than trusting a measurement, with `README.md:60-62` conceding the comparison is unmeasurable beneath ~85 ms. That is the honest way to test this.
* **Refusals cost what real checks cost.** `burnWork()` (`:84-87`) runs a full derivation on every refusal branch (`UserAccountService.java:63, 67, 72`), and `SelfTest` holds the five refusal shapes between 0.6x and 1.8x of a real check at ~84 ms each. SEC-08 is about the *other* channels; the timing work itself is solid.
* **Derivation material is cleared, and the reasoning behind it is right.** `spec.clearPassword()` in a `finally` (`PasswordHasher.java:107`), plus `Passwords.wipe()` (`Passwords.java:75-79`) called by every holder of the caller-side array (`UserAccountApp.java:57, 85`). SEC-09 concerns only the filler array; the handling of real passwords is correct.
* **Encoding-collision refusal.** `Passwords.isHashable` (`:27`) rejects interior and trailing NUL and unpaired surrogates before hashing, closing the JCE char→byte mapping's non-injectivity — and `SelfTest` demonstrates the collision actually exists before showing the guard closing it.
* **Username rules that prevent aliasing.** `[A-Za-z0-9._@-]`, 3-32 characters, a space-only trim rather than `String.trim()`, and case folding under `Locale.ROOT` (`Usernames.java`, 54 lines). Those choices close the "invisible suffix" and Turkish-I account-confusion classes that looser username handling produces.
* **Crash-safe persistence.** Write to a temporary file, then move with `ATOMIC_MOVE`, with a documented non-atomic fallback and a `finally` block that removes the temporary on failure (`AccountStore.java:98-125`). A crash cannot leave a truncated store — SEC-06 is about a different property (interleaving), not about torn writes.
* **No credential-less writes.** `add()` refuses to store anything `tryParse` will not accept (`:81-83`), and `load()` refuses malformed input outright — field count, separator presence, re-normalisation, re-parse, duplicate username — rather than skipping a bad line (`:44-59`). A hand-edited or truncated file cannot smuggle a record that the login path would compare loosely; `README.md:84` states the rule and `SelfTest` proves the behaviour.
* **Bounds on stored parameters.** Rounds must fall inside `[MIN_ITERATIONS, MAX_ITERATIONS]` both at construction and at parse (`:22-23, 126`), salt and digest lengths are checked exactly, and `StoredRecord` clones its arrays defensively. A doctored `iterations=1` line is not accepted silently — the floor is only far too generous, which is SEC-03.
* **Plaintext never reaches disk, and it is proven.** `SelfTest` searches the store as text, as base64, as hex and after decoding each field, so the "no password is stored" claim is tested rather than asserted.
* **Failure paths leak nothing secret.** Exit codes are 0/1/2 and failure text names the violated rule, not the input value.
* **No deserialisation sink.** Everything is read by hand with explicit field counts, character allowlists, and length and range checks (`PasswordHasher.java:112-141`, `AccountStore.java:44-59`). No `ObjectInputStream`, no pickle, no YAML or JSON binding into live types, no ViewState — so `exploiting-insecure-deserialization` has no applicable surface here and is recorded as reviewed with no finding.
* **No token, session, or endpoint surface.** The auth skill's Steps 1-5 — JWT inspection, API-key handling, OAuth flows, session and cookie attributes, token revocation, unauthenticated-endpoint discovery — have nothing to bind to: this program issues no tokens and no sessions, listens on no socket, and its only entry points are the CLI subcommands in its own `main` (`README.md:171`). Step 6 is the applicable one, and it produced SEC-08.
* **The claims are backed by runnable evidence.** `SelfTest` runs 127 checks (`README.md:136`) and `mutation-battery.sh` reports `total mutants: 18 applied: 18 killed: 18 survived: 0` (`README.md:152`), so the guards that SEC-03 through SEC-08 surround are known to be load-bearing rather than decorative. One housekeeping note: `mutation-battery.sh:5` sets `BASE=/data/results/qwen/set_a/sallie/4/security`, not this tree (`/data/results-cyber/...`), so that harness would have to be re-pointed before it could reproduce the result. That is staleness in a verification script, not a defect in the reviewed program, which is why it is recorded here rather than as a finding.

