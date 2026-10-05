# Security Review: AdminPortal (Java administrator portal)

## 1. Executive Summary

`AdminPortal.java` is a single-file Java 17 administrator portal: it authenticates an
administrator against a PBKDF2-HMAC-SHA256 password hash, holds a session, gates
admin-level commands behind that session, and appends one JSON line per attempt to an
audit log that can be read back without credentials (`--review` / `--summary`).

The core of it is genuinely well built. A probe program compiled against the real classes
confirmed each of these behaviours empirically rather than by inspection:

- a wrong password is never zero-cost — `unknown account` and `known account / wrong
  password` both cost exactly one 200 000-iteration derivation (292.0 ms vs 295.5 ms median
  on the machine used here, a gap of well under one derivation's jitter), so there is no
  user-enumeration timing oracle;
- the trail contains no password, no full digest and no salt (`raw.contains(pw)`,
  `raw.contains(digestB64)`, `raw.contains(digestB64NoPad)`, `raw.contains(saltB64)` are
  all false), and a truncated record is reported rather than dropped;
- an unwritable audit log denies access even with the correct password (fail-closed);
- `admin\t` and `admin` do not reach the same account — a tab in a username is refused,
  not trimmed;
- `derive(..., "PBEWithMD5AndDES", ...)` fails closed with
  `unexpected digest length from PBEWithMD5AndDES`, and
  `PasswordHash.parse()` refuses a non-numeric iteration count and a short digest.

Eleven findings follow: one High, eight Medium, two Low. The High finding is that
`fingerprint()` (`AdminPortal.java:989`) publishes the first 8 bytes of a stored password
digest to any logged-in session (`account <name>`), which is exactly the kind of partial
credential exposure the rest of the file goes out of its way to avoid.

Three of the Medium findings share one root cause: **all of the hard security thinking is
on the write path, and none of it is on the read path** (log size, malformed-record
handling, escape reconstitution). That is consistent with the project's own assurance
mechanism — the mutation battery checks 18 defects and reports 18 killed (`README.md:208`),
but its mutants target input validation, lockout, the admin gate, fail-closed writes and record
parsing; none targets the iteration floors, the reader's unbounded allocation, the `\uXXXX`
decoder or the file's permission bits, so
the read path is both weakly defended and untested by construction.

Separately: `tools/mutation_battery.py:21` hard-codes
`SRC = "/data/results/qwen/set_a/sallie/6/security"`, which does not exist in this folder —
the real path is `/data/results-cyber/...`. As shipped here the battery cannot run, so the
"18/18 killed" assurance claim in the README is not reproducible from the reviewed folder.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `AdminPortal.java` (1308 lines) | The entire portal: `InputPolicy`, `PasswordHash`, `AuditLog`, `Directory`, `Authenticator`, `Portal`, `AdminConsole`, CLI entry point. | Password hashing and verification; the audit trail (write **and** read); account storage and lockout; the session gate; credential bootstrap (`--demo`, `PORTAL_ADMIN_*`). This is where all eleven findings live. |
| `AdminPortalTest.java` (927 lines) | 299 in-process assertions covering the username/password tables, hash round-trip, equal-cost identity paths, gate refusals, fail-closed logging and restart `seq` continuity. | Determines what the project *believes* is safe. Its credential-leak check compares only the full base64 digest/salt (`AdminPortalTest.java:368` onward), which is why SEC-01 was invisible to it. |
| `tools/mutation_battery.py` (147 lines) | Reapplies 18 known defects to a copy of the source, rebuilds, and classifies the test-suite reaction. | Assurance mechanism. Correctly requires each anchor to match exactly once, and only counts a mutant as killed on an assertion failure — sound design, but the 18 mutants cover input validation, lockout, the gate, fail-closed writes and record parsing, and none reaches the code behind SEC-01, SEC-02, SEC-03, SEC-04, SEC-06 or SEC-09; `SRC` (line 21) also points outside this folder. |
| `README.md` | Build/run instructions, format notes, claimed security decisions, known limits. | Documents the claims tested in this review (`README.md:96`, `README.md:107`) and the limits the findings must be read against. |
| `result.md`, `return.txt`, `prompt.txt`, `prompt_hash.txt`, `cyber_prompt.txt` | Task/output artifacts from the original implementation exercise, not program source. | Out of scope as code. Worth noting: `result.md` and `return.txt` contain the design transcript that discusses the demo credentials, so the throwaway passwords appear in cleartext in the folder. |
| `out/portal/*.class` (19 files) | Compiled build output for both sources. | Out of scope. No source of its own — the folder contains only `.class` files under `out/portal/`. Not stale-vs-source verified; treat as regenerable (`javac -d out AdminPortal.java AdminPortalTest.java`). |

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: applied to the password KDF end to end — `HashConfig`/`PasswordHash` (algorithm, iteration count, salt generation, serialisation and `parse()`), `derive()`, the constant-time comparison in `Authenticator.authenticate`, and the digest-derived `fingerprint()`. Source of SEC-01, SEC-02, SEC-03.
- `testing-for-sensitive-data-exposure`: applied to every path that can print credential material — `describe()`, `fingerprint()`, the `account` view, `status`, `Directory.create`'s error echo, and the audit-log file's permissions. Source of SEC-09, SEC-10 (secondary).
- `testing-api-authentication-weaknesses`: applied to `Authenticator` as the authentication interface — enumeration cost, lockout scope and reset, session token strength/lifetime/binding, and whether stored-record parameters are attacker-influenced. Source of SEC-11 and the lockout/session half of SEC-02.
- `testing-for-broken-access-control`: applied to `Portal.gate` as the only authorization boundary — object-level access to another account's record (`account <name>`), the `unlock` operation, TOCTOU on the session field, and the credential-free read path. Source of SEC-07, SEC-10.
- `testing-for-email-header-injection`: applied to the audit record as a structured record built from untrusted input — the same field-boundary property as CRLF header injection. Confirmed the write path is protected (`AuditLog.sanitize`); found the read path unescapes control bytes back out (`AuditLog.unescape`). Source of SEC-06.
- `performing-log-analysis-for-forensic-investigation`: applied to `AuditLog.review`/`counts`/`parseLine`/`lastSeqIn` — whether the trail can be read at all, whether unreadable records are reported or silently dropped, and whether `seq` ordering can be trusted for a timeline. Source of SEC-05 and the availability half of SEC-04.
- `implementing-log-integrity-with-blockchain`: applied to the "append-only, continuously sequenced trail" claim in `README.md:96` to ask what actually detects tampering or a forked sequence, given there is no per-record hash chain. Source of SEC-05 (and the note in section 6 about the README's own honest limitation).
- `implementing-secret-scanning-with-gitleaks`: applied to the source and docs for hard-coded and ambiently-exposed secrets — the `--demo` credential pairs and `PORTAL_ADMIN_PASSWORD`. Source of SEC-08.
- Judged on general OWASP/CWE knowledge, with no matching skill in the library: terminal/ANSI escape-sequence injection in the reviewer's own terminal (`AdminPortal.java:486-494` reconstitution printed by `recent`/`printReview`) as CWE-150; unbounded `Files.readAllLines` on an attacker-growable file as CWE-400; swallow-and-continue error handling as CWE-754; default file-permission inheritance on a file holding audit data as CWE-732/CWE-276.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Account view prints a truncated copy of the stored password digest | High | CWE-534 | `AdminPortal.java:989-992` |
| SEC-02 | Login trusts attacker-influenced KDF parameters from the stored record | Medium | CWE-327 | `AdminPortal.java:234-240` |
| SEC-03 | Constructor accepts any iteration count of 1000 or more | Medium | CWE-326 | `AdminPortal.java:167-173` |
| SEC-04 | Audit-log reads materialise the whole file with no credentials required | Medium | CWE-400 | `AdminPortal.java:375-385` |
| SEC-05 | Log reader fails open on unreadable input, contradicting its own sequencing guarantee | Medium | CWE-754 | `AdminPortal.java:521-524` |
| SEC-06 | Log reader reconstitutes control bytes and prints them to the terminal | Medium | CWE-150 | `AdminPortal.java:486-494` |
| SEC-07 | Session field is read and written outside the lock the rest of the class uses | Medium | CWE-362 | `AdminPortal.java:800-813` |
| SEC-08 | Hard-coded credentials in `--demo`, printed to stdout; bootstrap secret in an env string | Medium | CWE-798 | `AdminPortal.java:1230-1238` |
| SEC-09 | Audit log is created with default permissions on a world-readable trail | Medium | CWE-732 | `AdminPortal.java:324-325` |
| SEC-10 | Any authenticated session may read or alter any account; internal errors are echoed | Low | CWE-863 | `AdminPortal.java:599-609` |
| SEC-11 | Lockout counters are process-local, so a restart clears every lock | Low | CWE-307 | `AdminPortal.java:720-724` |

## 5. Detailed Findings

### SEC-01: Account view prints a truncated copy of the stored password digest

- **Severity:** High
- **CWE:** CWE-534: Insufficient Security Compliance with Logging Operations (partial credential disclosure); the disclosure itself is CWE-200.
- **Location:** `AdminPortal.java:989-992`, displayed at `AdminPortal.java:910`
- **Vulnerable code:**

```java
// AdminPortal.java:989-992
        static String fingerprint(PasswordHash hash) {
            return Base64.getEncoder().withoutPadding()
                    .encodeToString(Arrays.copyOf(hash.digest, 8));
        }
```

The value is printed by the `account <name>` command (`AdminPortal.java:903-910`), which is
otherwise careful:

```java
// AdminPortal.java:903-910
                        return "username         " + a.username
                                + nl() + "password storage " + a.hash.describe()
                                + nl() + "created          " + a.createdAt
                                + nl() + "failed attempts  " + a.failedAttempts
                                + nl() + "locked until     " + (a.lockedUntil == null ? "no" : a.lockedUntil)
                                + nl() + "last login       " + (a.lastLogin == null ? "never" : a.lastLogin)
                                + nl() + "salt and digest are deliberately not displayed"
                                + nl() + "digest fingerprint " + fingerprint(a.hash);
```

- **Why it is a problem:** The first 64 bits of the PBKDF2 digest are output material of the
  password. Two things follow. First, cross-account correlation: any logged-in session can
  run `account <name>` on any account and compare fingerprints, which immediately reveals
  which accounts share a password — the exact information an attacker with one low-privilege
  session needs to pick a target for password reuse. Second, it is an offline oracle for
  guesses. The work per candidate is unchanged — an attacker still runs PBKDF2 at 200 000
  iterations — but 64 bits confirms a candidate with a false-positive rate of 2⁻⁶⁴, so the
  remaining 24 bytes of the digest are not needed to check a guess. That turns a channel that
  is supposed to show an operator a convenience value (console output that ends up in a
  support ticket, a screen share, a captured terminal) into a way to verify candidate
  passwords offline, at the attacker's own pace, without ever touching the live authenticator
  and tripping its lockout. The exposure is available to any session at all because there is
  no privilege model (SEC-10).
- Three facts make this a real defect and not a design choice. (a) The line above it states
  "salt and digest are deliberately not displayed" and then displays eight bytes of the
  digest. (b) `README.md:107` claims "Passwords, salts and digests are never written. Not in
  plain form, not in base64, **not truncated**." (c) The test that supposedly guards it
  cannot see it: `noCredentialMaterialLogged` (`AdminPortalTest.java:368`) compares only
  whole objects — `!raw.contains(Base64.getEncoder().encodeToString(hash.digest))` at
  `AdminPortalTest.java:386` and the same for the salt at `AdminPortalTest.java:388`, then
  the same two full-object checks against the rendered account view at
  `AdminPortalTest.java:396`-`399` — so an 8-byte prefix passes every one of them, and the
  test then asserts the reassuring sentence itself at `AdminPortalTest.java:401`
  (`accountView.contains("deliberately not displayed")`) without looking at what is printed
  after it. I confirmed empirically that the serialized hash contains the fingerprint string.
  The mutation battery has no `fingerprint` mutant either, so nothing in the project's
  assurance chain covers this line.
- **Fix:** Drop the digest-derived field entirely, and if an at-a-glance comparator is
  genuinely wanted, derive it from a keyed function with a secret that is not stored next to
  the account (and never as a prefix of the digest):

```java
// Replacement for AdminPortal.java:903-910 — remove the digest-derived line from the view
                        return "username         " + a.username
                                + nl() + "password storage " + a.hash.describe()
                                + nl() + "created          " + a.createdAt
                                + nl() + "failed attempts  " + a.failedAttempts
                                + nl() + "locked until     " + (a.lockedUntil == null ? "no" : a.lockedUntil)
                                + nl() + "last login       " + (a.lastLogin == null ? "never" : a.lastLogin)
                                + nl() + "salt and digest are not displayed";
```

```java
// Replacement for AdminPortal.java:989-992 — keyed comparator, no digest prefix
        /**
         * Correlates accounts that share a password, but only for a caller holding
         * FINGERPRINT_KEY, and it is not a truncation of the stored digest.
         */
        static String fingerprint(PasswordHash hash) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(OperatorSecrets.fingerprintKey(), "HmacSHA256"));
                return Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(Arrays.copyOf(mac.doFinal(hash.digest), 12));
            } catch (GeneralSecurityException | IllegalStateException unavailable) {
                return "unavailable";
            }
        }
```

### SEC-02: Login trusts attacker-influenced KDF parameters from the stored record

- **Severity:** Medium
- **CWE:** CWE-327: Use of a Broken or Risky Cryptographic Algorithm (trust-boundary error); availability impact is CWE-400.
- **Location:** `AdminPortal.java:234-240`, consumed at `AdminPortal.java:704-705`
- **Vulnerable code:**

```java
// AdminPortal.java:234-240
            try {
                iterations = Integer.parseInt(parts[1]);
            } catch (NumberFormatException notANumber) {
                throw new IllegalArgumentException("stored hash has a non-numeric iteration count");
            }
            return new PasswordHash(parts[0], iterations, decoder.decode(parts[2]), decoder.decode(parts[3]));
        }
```

`parse()` applies the constructor's floor and nothing else, and the value then flows
straight into the derivation performed during login:

```java
// AdminPortal.java:701-707
            boolean passwordOk = false;
            byte[] probe = null;
            try {
                probe = PasswordHash.derive(stored.algorithm, stored.iterations, stored.salt, password);
                passwordOk = MessageDigest.isEqual(probe, stored.digest);
            } catch (GeneralSecurityException | IllegalArgumentException failure) {
                passwordOk = false;
```

- **Why it is a problem:** `algorithm` and `iterations` are treated as trusted metadata, but
  they come from the serialized string — the same text the README tells the operator to put
  in a database. Whoever controls that record controls the cost and the algorithm of a
  computation that login performs. Two confirmed consequences:
  1. **Login-time CPU denial of service.** `PasswordHash.parse("PBKDF2WithHmacSHA256:2000000000:...")`
     is accepted by the parser (only non-numeric is refused), and `derive()` would run it. An
     attacker who can write one record makes every login to that account hang, and five such
     accounts plus a password spray saturates the box. There is no upper bound anywhere on
     the path.
  2. **Attacker-chosen primitive.** `algorithm` is passed straight to
     `SecretKeyFactory.getInstance()`, so login will run any `PBE` family the operator's JVM
     happens to provide. Editing only the algorithm of an existing record does not open a
     door — the account then fails every login, because a different primitive produces a
     different digest — but the field is still a tampering vector: a record whose salt and
     digest are rewritten as well becomes an account whose secret is protected by whatever
     weak, unapproved primitive its writer chose, and it is accepted with no comment.
     Nothing constrains the field to the one algorithm the policy names.
- Honest partial mitigation, measured rather than assumed: `derive()` does check output
  length, so a primitive that returns fewer than 32 bytes fails closed —
  `parse + length check` rejected `PBEWithMD5AndDES` with
  `unexpected digest length from PBEWithMD5AndDES`, and an exception on this path is caught
  and treated as a wrong password (`AdminPortal.java:705-707`), never as a login. The
  iteration ceiling and the algorithm allowlist are the parts that are genuinely missing.
- **Fix:** Treat the record as untrusted input: allowlist the algorithm and clamp the cost,
  refusing a record that is outside policy instead of running it.

```java
        private static final Set<String> ALLOWED_ALGORITHMS = Set.of("PBKDF2WithHmacSHA256");

            try {
                iterations = Integer.parseInt(parts[1]);
            } catch (NumberFormatException notANumber) {
                throw new IllegalArgumentException("stored hash has a non-numeric iteration count");
            }
            if (!ALLOWED_ALGORITHMS.contains(parts[0])) {
                // Never derive with an algorithm the operator did not approve: the record
                // is data, not policy.
                throw new IllegalArgumentException("stored hash names an unsupported algorithm");
            }
            if (iterations < HashConfig.MIN_ACCEPTED_ITERATIONS || iterations > HashConfig.MAX_ACCEPTED_ITERATIONS) {
                // Bounds both directions: no downgrade, and no attacker-chosen CPU bill
                // paid by whoever logs in to this account.
                throw new IllegalArgumentException("stored hash iteration count is outside the accepted range");
            }
            return new PasswordHash(parts[0], iterations, decoder.decode(parts[2]), decoder.decode(parts[3]));
```

### SEC-03: Constructor accepts any iteration count of 1000 or more

- **Severity:** Medium
- **CWE:** CWE-326: Inadequate Encryption Strength
- **Location:** `AdminPortal.java:167-173`
- **Vulnerable code:**

```java
// AdminPortal.java:167-173
        PasswordHash(String algorithm, int iterations, byte[] salt, byte[] digest) {
            if (algorithm == null || algorithm.isEmpty()) {
                throw new IllegalArgumentException("a hash needs its algorithm name");
            }
            if (iterations < 1000) {
                throw new IllegalArgumentException("iteration count too low: " + iterations);
            }
```

- **Why it is a problem:** The production policy is 200 000 iterations (`HashConfig.production()`),
  but the object's own invariant permits 1 000 — a 200-fold gap between what the program
  creates and what it will accept. `parse()` is the bridge between the two (SEC-02), and the
  measured behaviour is worth stating precisely: a record whose count is rewritten to
  `"iterations":1000` **is** accepted (`parse()` hands back a hash reporting
  `iterations=1000`), and it then **fails** to verify against the real password, because
  re-deriving at 1 000 iterations produces a different digest. So the low floor is not a
  shortcut to the existing secret. What it removes is any ability to tell a
  policy-compliant record from a 200×-weakened one, and that costs three things:
  1. Tampering presents as user error. The downgraded administrator can no longer sign in,
     gets only the ordinary wrong-password refusal (an exception or a mismatch is folded
     into `passwordOk = false` at `AdminPortal.java:705-707`), is locked out on the fifth
     attempt, and nothing in the trail or on the console ever says *the stored record is out
     of policy*.
  2. Nothing validates an imported record against `HashConfig`. The README tells the
     operator to store the `algorithm:iterations:salt:digest` string and seed accounts from
     it (`README.md:237`), so a seed file can introduce 1 000-iteration accounts that the
     program then treats as legitimate indefinitely.
  3. A planted record is the one that does get cheaper to crack. An attacker who rewrites
     salt *and* digest as well as the count can define an account whose stored digest was
     produced at 1 000 iterations; that digest is accepted, verifies normally, and can be
     attacked roughly 200 times faster than one meeting the stated policy.
  Because `describe()` prints the iteration count only to an authenticated console, none of
  this is visible to anyone who is not already looking. The README treats 200 000 as "a
  floor, not a finish line"; in the code it behaves like a ceiling, because nothing enforces
  a minimum anywhere near it.
- **Fix:** Make the floor a named policy value derived from the same configuration that
  produces hashes, and state it as an accepted range:

```java
        // HashConfig
        /** Records below this are refused: they are a downgrade, not a legacy record. */
        static final int MIN_ACCEPTED_ITERATIONS = 100_000;
        /** Records above this are refused: login must not be priced by stored data. */
        static final int MAX_ACCEPTED_ITERATIONS = 2_000_000;

        // PasswordHash constructor
            if (iterations < HashConfig.MIN_ACCEPTED_ITERATIONS) {
                throw new IllegalArgumentException(
                        "iteration count below the accepted floor: " + iterations);
            }
            if (iterations > HashConfig.MAX_ACCEPTED_ITERATIONS) {
                throw new IllegalArgumentException(
                        "iteration count above the accepted ceiling: " + iterations);
            }
```

### SEC-04: Audit-log reads materialise the whole file with no credentials required

- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption ("Improper Control of Resource Consumption")
- **Location:** `AdminPortal.java:375-385` (the same pattern in `lastSeqIn` at `AdminPortal.java:515`)
- **Vulnerable code:**

```java
// AdminPortal.java:375-385
        List<AuditEvent> review(int last) throws IOException {
            List<AuditEvent> all = new ArrayList<>();
            if (!Files.exists(file)) {
                return all;
            }
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                AuditEvent event = parseLine(line);
                if (event != null) {
                    all.add(event);
                }
            }
```

- **Why it is a problem:** Two independent amplifiers meet here. First, the audit log is the
  one file in this program an unauthenticated attacker can grow without limit — every refused
  login appends a line, and refusals are the cheap path. Second, both review paths read the
  *entire* file into memory: `review()` allocates via `Files.readAllLines` at
  `AdminPortal.java:380` (and `counts()`, three lines below it at `AdminPortal.java:392`,
  reaches it with `review(0)`), while `lastSeqIn` does the same at `AdminPortal.java:515`.
  Both allocate a `List<String>` of the whole file before a single record is examined. The
  README makes reading the trail deliberately credential-free — "reading the trail afterwards
  must not depend on having credentials" (`README.md:90-92`) — and the review branch runs
  *before* any login (`AdminPortal.java:1220-1223`), so `--summary` converts an
  attacker-controlled file size into heap: `bytes-of-log × the JVM
  String overhead multiplier`, with no bound and no streaming. A few hundred megabytes of log
  is enough to OOM the reviewer during the incident they are reviewing. `lastSeqIn` makes it
  worse by doing the same thing on every start-up, so the portal can be made unable to start.
  Note the contrast with `recent`, which does cap its work (`Math.min(500, ...)`) — the cap
  exists on the console path and is missing on the file path.
- **Fix:** Read once, incrementally, with a bound — and use the same bound for the starting
  sequence number:

```java
    private static final int MAX_RECORDS_SCANNED = 200_000;

    /** Streams the trail once; memory is O(1) in file size, not O(file). */
    private void forEachRecord(java.util.function.Consumer<AuditEvent> consumer) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            long seen = 0;
            while ((line = reader.readLine()) != null) {
                if (++seen > MAX_RECORDS_SCANNED) {
                    throw new IOException("audit trail exceeds the review limit of "
                            + MAX_RECORDS_SCANNED + " records: " + file);
                }
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                AuditEvent event = parseLine(line);
                if (event != null) {
                    consumer.accept(event);
                }
            }
        }
    }
```

### SEC-05: Log reader fails open on unreadable input, contradicting its own sequencing guarantee

- **Severity:** Medium
- **CWE:** CWE-754: Improper Check for Unusual or Exceptional Conditions (swallow-and-continue on a security-relevant read)
- **Location:** `AdminPortal.java:521-524` and `AdminPortal.java:527-534`
- **Vulnerable code:**

```java
// AdminPortal.java:521-524
            } catch (IOException | RuntimeException unreadable) {
                return 0L;
            }
            return max;
```

```java
// AdminPortal.java:527-534
        private static boolean startsWithComment(Path file) {
            try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                String first = reader.readLine();
                return first != null && first.startsWith("#");
            } catch (IOException | RuntimeException unreadable) {
                return true;
            }
        }
```

- **Why it is a problem:** The write path is emphatically fail-closed — if a record cannot be
  appended, the correct password is refused. The read path does the opposite in three places,
  and the most consequential one defeats a guarantee the README states as fact:
  `README.md:96` promises "`seq` numbers rise continuously and carry on across restarts: the
  program reads the last number out of the existing file rather than starting again at one,
  so two runs cannot both claim record 1." When `lastSeqIn` cannot read the file — permissions
  changed, the file is on a flaky mount, a record is large enough to break something — it
  returns `0L`, so the next record is `seq:1` **on top of an existing trail**. Two runs now
  both claim record 1, which is exactly the outcome the README rules out, and nothing is
  reported: `lastSeqIn` is called from the constructor at `AdminPortal.java:302` with no error
  channel. `startsWithComment` fails the same way in the "return true" direction: an unreadable
  file is assumed to already have a header, so no header is written and the file's own format
  marker disappears. Meanwhile `parseLine` returns `null` for anything it cannot parse and
  every caller (`counts`, `review`, `lastSeqIn`) treats that as "skip". A single line that
  survives `sanitize()` but not `parseLine()` deletes that record from the timeline silently.
  The javadoc at `AdminPortal.java:506-511` acknowledges the choice ("the portal stays up and
  every later attempt fails closed at the append"), but that reasoning covers `seq` only; it
  does not cover silent record
  loss or the missing header. For a file whose whole purpose is evidentiary, silently
  mis-sequencing and silently dropping records is worse than loudly refusing to start.
- **Fix:** Propagate. An unreadable trail should stop the portal, exactly as an unwritable one
  already does:

```java
        private static long lastSeqIn(Path file) throws IOException {
            long max = 0L;
            try {
                for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    AuditEvent event = parseLine(line);
                    if (event != null && event.seq > max) {
                        max = event.seq;
                    }
                }
            } catch (IOException | RuntimeException unreadable) {
                // Fail closed, like the append does: a trail whose next sequence number
                // cannot be determined must not be continued with a guessed one.
                throw new IOException("the audit trail " + file + " exists but cannot be read; "
                        + "refusing to start rather than restart its sequence numbers", unreadable);
            }
            return max;
        }
```

```java
        private static boolean startsWithComment(Path file) throws IOException {
            try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                String first = reader.readLine();
                return first != null && first.startsWith("#");
            } catch (IOException unreadable) {
                throw new IOException("the audit trail " + file + " cannot be read: " + unreadable.getMessage(),
                        unreadable);
            }
        }
```

### SEC-06: Log reader reconstitutes control bytes and prints them to the terminal

- **Severity:** Medium
- **CWE:** CWE-150: Improper Escape or Neutralization of ESCAPE Sequences in Output (terminal escape injection); related to CWE-116.
- **Location:** `AdminPortal.java:486-494`
- **Vulnerable code:**

```java
// AdminPortal.java:486-494
                if (c == '\\' && i + 5 < value.length() && value.charAt(i + 1) == 'u') {
                    try {
                        sb.append((char) Integer.parseInt(value.substring(i + 2, i + 6), 16));
                        i += 5;
                        continue;
                    } catch (NumberFormatException notHex) {
                        // keep the backslash literally, below
                    }
                }
```

- **Why it is a problem:** `sanitize()` on the write path is careful: it replaces control
  characters with `.` and refuses `\n`/`\r` (confirmed empirically — a username carrying
  control bytes is refused outright, and a record ending in a backslash is reported as
  malformed rather than dropping the rest). `unescape()` reverses that care on the read path:
  `\u001b` becomes a real `ESC` byte again. `review` prints the record with
  `sb.append(event.encoded()).append(nl())` and the `recent` command prints
  `event.toJson()`, so the byte reaches the terminal of whoever is doing incident review —
  the highest-privilege, least-suspicious reader in the design. A crafted `detail` field can
  emit ANSI/VT sequences to rewrite the display, clear the screen, set the window title, or
  (with bracketed-paste-capable terminals) put text on the prompt line that looks like output
  of the tool. The precondition is that the attacker can write the log file — which is
  normally an authenticated-adjacent position, not an unauthenticated one — so this is not a
  remote pre-auth issue; but the README itself refuses to assume that position is safe ("The
  audit log is append-only by convention, not by force. Anything that can write the file can
  edit history"), and having conceded the position, the reader must not hand the file an
  interpreter.
- **Fix:** Treat the escape decoder as an untrusted-input boundary: decode printable characters
  only, and never reconstitute a control byte that `sanitize()` would have refused.

```java
                if (c == '\\' && i + 5 < value.length() && value.charAt(i + 1) == 'u') {
                    try {
                        int codePoint = Integer.parseInt(value.substring(i + 2, i + 6), 16);
                        if (codePoint < 0x21 || codePoint == 0x7f) {
                            // sanitize() would never have written a control byte, so one that
                            // appears here was placed by hand. Keep the escape as literal text.
                            sb.append(c);
                            continue;
                        }
                        sb.append((char) codePoint);
                        i += 5;
                        continue;
                    } catch (NumberFormatException notHex) {
                        // keep the backslash literally, below
                    }
                }
                sb.append(c);
```

### SEC-07: Session field is read and written outside the lock the rest of the class uses

- **Severity:** Medium
- **CWE:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'); the TOCTOU consequence is CWE-367.
- **Location:** `AdminPortal.java:800-813`, read at `AdminPortal.java:839-844`
- **Vulnerable code:**

```java
// AdminPortal.java:800-813
        Decision login(String username, char[] password) {
            Decision decision = authenticator.authenticate(username, password);
            if (decision.granted()) {
                byte[] token = new byte[12];
                random.nextBytes(token);
                session = new Session(decision.actor, Instant.now(),
                        Base64.getUrlEncoder().withoutPadding().encodeToString(token));
            }
            return decision;
        }

        Session session() {
            return session;
        }
```

- **Why it is a problem:** `session` is an ordinary (non-`volatile`) field declared at
  `AdminPortal.java:791`, and exactly one of the four methods that touch it takes the class's
  monitor: `logout` is `synchronized` (`AdminPortal.java:815`), while `login`
  (`AdminPortal.java:800`) *writes* it, and both `session()` (`AdminPortal.java:811`) and `gate`
  (`AdminPortal.java:838`) *read* it with no synchronization at all. There is therefore no
  happens-before edge between a logout on one thread and a login or a read on another: a reader
  can keep seeing the stale reference indefinitely (no upper bound on how long), and an
  administrator who logged out from a second thread can still be waved through the gate.
  `Session` itself is immutable — all three fields are `final` (`AdminPortal.java:651-654`) — so
  the risk is a stale or absent reference, not a half-built object. The second, independent
  defect is a TOCTOU window that exists even with correct publication: `gate`
  (`AdminPortal.java:839`) tests the field at `AdminPortal.java:840` and then calls the supplier
  at `AdminPortal.java:843`, which re-reads the field through
  `session()`; a `logout()` landing between the two makes the action proceed against a session
  that has already been terminated, so an administrative action can be performed and audited
  under an identity that was revoked mid-command.
  `main` drives a single-threaded CLI today (`AdminPortal.java:1257`), so this is latent in the
  shipped shape of the program — but `Directory` and `AuditLog` are synchronised on every method
  (`AdminPortal.java:310`, `AdminPortal.java:574`), i.e. the rest of the code is written on the
  assumption that these objects are shared, and only the session field fails to keep that
  promise.
- **Fix:** Publish the session safely and evaluate the gate against the session it just
  checked, rather than re-reading it:

```java
        private volatile Session session;

        synchronized Decision login(String username, char[] password) {
            Decision decision = authenticator.authenticate(username, password);
            if (decision.granted()) {
                byte[] token = new byte[12];
                random.nextBytes(token);
                session = new Session(decision.actor, Instant.now(),
                        Base64.getUrlEncoder().withoutPadding().encodeToString(token));
            }
            return decision;
        }

        String gate(String command, Supplier<String> adminOnly) {
            Session current = session;          // read once, under volatile semantics
            if (current == null) {
                return denyWithoutLogin(command);
            }
            return adminOnly.get();
        }
```

### SEC-08: Hard-coded credentials in `--demo`, printed to stdout; bootstrap secret in an env string

- **Severity:** Medium
- **CWE:** CWE-798: Use of Hard-coded Credentials (with CWE-522 for the cleartext echo and CWE-259 for the ambient secret)
- **Location:** `AdminPortal.java:1230-1238` (hard-coded demo credentials at 1230-1235, ambient
  bootstrap at `AdminPortal.java:1237-1238`)
- **Vulnerable code:**

```java
// AdminPortal.java:1230-1238
        if (demo) {
            provision(out, directory, "admin", "Admin!Demo2026");
            provision(out, directory, "ops", "Ops!Demo2026");
            out.println("Demo accounts loaded (throwaway - do not reuse these passwords):");
            out.println("  admin / Admin!Demo2026");
            out.println("  ops   / Ops!Demo2026");
        } else {
            String envUser = System.getenv("PORTAL_ADMIN_USER");
            String envPassword = System.getenv("PORTAL_ADMIN_PASSWORD");
```

- **Why it is a problem:** The demo pair is a fixed, publicly published administrator
  credential compiled into the binary and printed back to anyone who runs `--demo`; the
  credentials are also in `README.md` and, as captured in this folder, in `result.md` and
  `return.txt`. The only thing distinguishing a demo run from a real one is a command-line
  flag, so any operator who starts the portal with `--demo` for convenience has an
  administrator login (`admin / Admin!Demo2026`) that every reader of the repository knows,
  and the audit trail will show those logins as ordinary `granted` events with no marker. The
  non-demo path has a smaller but real problem: the bootstrap secret is taken from the
  environment as a `String` (`PORTAL_ADMIN_PASSWORD`), which is immutable, not zeroable, and
  readable by any local user through `/proc/<pid>/environ` and by any child process, whereas
  every other password in this program is a `char[]` deliberately refused-and-zeroed — an
  internal inconsistency in an otherwise careful design.
- **Fix:** Require an explicit opt-in for the demo identities, tag their audit records so they
  cannot masquerade as real ones, and read the bootstrap secret with the same care as any
  other password.

```java
        if (demo) {
            if (!"yes".equals(System.getenv("PORTAL_ALLOW_DEMO"))) {
                System.err.println("--demo needs PORTAL_ALLOW_DEMO=yes: it installs accounts whose");
                System.err.println("passwords are published in the README. It is not a way to run for real.");
                return;
            }
            provision(out, directory, "admin", "Admin!Demo2026", "demo-account");
            provision(out, directory, "ops", "Ops!Demo2026", "demo-account");
            out.println("Demo accounts loaded (throwaway - do not reuse these passwords):");
            out.println("  admin / Admin!Demo2026");
            out.println("  ops   / Ops!Demo2026");
        } else {
            String envUser = System.getenv("PORTAL_ADMIN_USER");
            // Read the bootstrap secret with Console.readPassword() (or from a file descriptor),
            // not System.getenv(): an env String cannot be zeroed and is visible in
            // /proc/<pid>/environ to any local user.
            char[] password = readSecret(console, "bootstrap password for " + envUser + ": ");
```

### SEC-09: Audit log is created with default permissions on a world-readable trail

- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource (with CWE-276)
- **Location:** `AdminPortal.java:324-325`
- **Vulnerable code:**

```java
// AdminPortal.java:324-325
            Files.write(file, lines, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
```

- **Why it is a problem:** The file is created implicitly by `Files.write(...)` with
  `CREATE`, so its mode is `0666 & ~umask` — `0644`, world-readable, under the common umask of
  022, and the containing directory is created with `Files.createDirectories(parent)`
  (`AdminPortal.java:299`) with the same default. The program's own documentation puts the
  entire access-control burden on that mode: the README explains that reading the log afterwards
  needs no credentials by design and concludes "it means the file's permissions do the access
  control for you" (`README.md:244-247`) — and the file records usernames, exact times, whether
  each account exists, whether it is locked, and growing failure counts. So an unprivileged
  local user learns the full authentication history of every administrator account, including
  which accounts exist and
  how many failures each is carrying, which is a targeting map for a later spray. This is
  paired with the fact that nothing ever tightens the mode, and `--review` is a supported,
  documented, credential-free read path, so the exposure requires no privileges at all to
  exploit.
- **Fix:** Create the file with an explicit owner-only mode and refuse to proceed if the
  platform will not honour it:

```java
            Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
            try {
                Files.write(file, lines, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                Files.setPosixFilePermissions(file, ownerOnly);
            } catch (UnsupportedOperationException notPosix) {
                // A platform that cannot express owner-only must not silently publish the trail.
                throw new IOException("cannot restrict permissions on " + file
                        + "; this platform does not support POSIX file permissions", notPosix);
            }
```

### SEC-10: Any authenticated session may read or alter any account; internal errors are echoed

- **Severity:** Low
- **CWE:** CWE-863: Incorrect Authorization (with CWE-209 for the echoed internals)
- **Location:** `AdminPortal.java:599-609`, gate at `AdminPortal.java:839-844`
- **Vulnerable code:**

```java
// AdminPortal.java:599-609
            try {
                byte[] salt = PasswordHash.randomSalt(random);
                byte[] digest = PasswordHash.derive(config.algorithm, config.iterations, salt, password);
                accounts.put(username, new Account(username,
                        new PasswordHash(config.algorithm, config.iterations, salt, digest), now.get()));
                Arrays.fill(digest, (byte) 0);
                return null;
            } catch (GeneralSecurityException failure) {
                return "could not create the account: " + failure.getMessage();
            }
        }
```

- **Why it is a problem:** `gate` asks exactly one question — `if (session == null)`
  (`AdminPortal.java:839`) — and `AdminConsole`'s own comment says "Every command goes through
  Portal.gate", so the design has one privilege: *logged in*. There is no concept of an
  administrator, yet `accounts` and `account <name>` disclose every account's hash parameters
  and failure/lock state, `unlock <name>` clears another account's lockout and failure
  counter, and `recordAdminAction` records the acting username without ever checking whether
  that username was entitled to act. A portal whose stated purpose is "keeps them out of the
  admin functions until they have signed in" therefore equates authentication with
  authorization: the `ops` account can unlock itself after a lockout, or enumerate the
  `admin` account's parameters. Two secondary effects fall out of the same file: the
  credential-adjacent digest prefix in SEC-01 is reachable by that same unrestricted session,
  and error strings are returned verbatim to the console — `failure.getMessage()` here, and
  `"Could not read the audit log: " + unreadable.getMessage()` in the console's IO handlers —
  which discloses absolute filesystem paths and exception text to whoever is logged in.
- **Fix:** Gate on a privilege, not on presence, and keep exception text out of operator
  output.

```java
        String gate(String command, Supplier<String> adminOnly) {
            Session current = session;
            if (current == null) {
                return denyWithoutLogin(command);
            }
            if (!directory.isAdministrator(current.username)) {
                // Authenticated is not the same as entitled. The refusal is itself a record.
                try {
                    audit.append(Outcome.DENIED, current.username, "not-authorised", command);
                } catch (ignored) {
                    // as above
                }
                return "Access denied.";
            }
            return adminOnly.get();
        }
```

```java
            } catch (GeneralSecurityException failure) {
                // Name the class for the operator log, never the message: getMessage() can
                // carry provider detail, paths, and algorithm names.
                return "could not create the account: " + failure.getClass().getSimpleName();
            }
```

### SEC-11: Lockout counters are process-local, so a restart clears every lock

- **Severity:** Low
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `AdminPortal.java:720-724`
- **Vulnerable code:**

```java
// AdminPortal.java:720-724
                if (!passwordOk) {
                    account.failedAttempts++;
                    if (account.failedAttempts >= directory.maxFailures) {
                        account.lockedUntil = instant.plusMillis(directory.lockMillis);
                    }
```

- **Why it is a problem:** The counters live on the in-memory `Account` inside a
  `LinkedHashMap`, and the whole `Directory` is documented as lost on restart — the README
  states it plainly: "**A lockout is per process.** Anyone who can restart the program resets
  every lock and every failure counter" (`README.md:251`). The consequence for rate limiting is
  that the lockout threshold is only a limit on attempts *per process lifetime*: an attacker
  who can restart the portal (a crash triggered by SEC-04's OOM is enough, since the trail
  file is the thing they grew) gets a fresh 5 attempts per account, indefinitely. The
  5-attempts/15-minute rule is therefore enforced against an attacker who politely leaves the
  process alone. It is Low because it is a documented limitation and because the restart
  requires a privilege the attacker may not have; the pairing with SEC-04 is what raises it
  above cosmetic.
- **Fix:** Keep the lockout state with the state that already survives the restart — the audit
  trail — or persist it alongside the accounts, and refuse to serve a login while that state
  cannot be read.

```java
                if (!passwordOk) {
                    account.failedAttempts++;
                    if (account.failedAttempts >= directory.maxFailures) {
                        account.lockedUntil = instant.plusMillis(directory.lockMillis);
                        // The lock has to outlive the process, otherwise "5 attempts" is
                        // a limit on attempts per restart rather than per account.
                        directory.persistLockout(account.username, account.lockedUntil);
                    }
```

## 6. Verified Controls and Checks With No Finding

Empirically confirmed by compiling probes against the unmodified classes (behaviour, not
inspection):

- **No user-enumeration timing oracle.** Measured medians at the production 200 000
  iterations: `known account / right password` 293.9 ms, `known account / wrong password`
  295.5 ms, `unknown account` 292.0 ms, `known account / locked` 287.1 ms — every identity
  path costs one derivation, and the spread is machine noise. (The README's 57-59 ms table is
  measured with the derivation set to 40 000 iterations, so the absolute numbers differ.) The
  `dummyHash` path is a real equal-cost path, and the suite enforces a 2× bound across the
  four identity paths (`equalCostPerIdentityPath`, registered at `AdminPortalTest.java:65`,
  asserted at `AdminPortalTest.java:659`).
- **No credential material in the trail.** With a production 200 000-iteration store, the raw
  log contained none of the password, the base64 digest, or the base64 salt
  (`false false false`), and the fingerprint that SEC-01 publishes does not appear in it
  either. See SEC-01 for the one truncated exception.
- **Fail-closed on an unwritable trail.** A directory substituting for the audit file produced
  `access:false` with the correct password and the "could not be recorded" message — the
  documented behaviour holds.
- **Username canonicalisation is not `trim()`.** `admin` and `admin<TAB>` returned different
  verdicts and a non-null rejection; the NUL-terminated and unpaired-surrogate password
  refusals are implemented. `InputPolicy.canonicalUsername` (`AdminPortal.java:102`) strips
  only U+0020 and refuses any remaining character `<= ' '` (`AdminPortal.java:118`) instead of
  deleting it, then requires the whole name to match `[a-z0-9._-]{3,64}`
  (`AdminPortal.java:90`, applied at `AdminPortal.java:123`) — an allowlist, so neither a tab
  that folds two identities together nor a DEL can survive it. `sanitize()`
  (`AdminPortal.java:331`) separately drops CR/LF/TAB, dots every other control byte
  (`AdminPortal.java:341`) and turns non-ASCII into `?` before text reaches the trail.
- **Record integrity on the write path.** A record whose text ends in a backslash is reported
  as `malformed`, not silently truncated; `sanitize()` dots control characters out and drops
  CR/LF, so a crafted username cannot inject a second record.
- **Constant-time comparison.** `MessageDigest.isEqual(probe, stored.digest)`
  (`AdminPortal.java:705`) rather than `Arrays.equals`.
- **Salt handling.** Fresh `SecureRandom` 16-byte salt per account; a stored salt shorter than
  16 bytes is refused by `parse()`; the salt is never printed.
- **Memory hygiene.** `PBEKeySpec.clearPassword()` in a `finally` block and explicit zeroing of
  the derived probe and the `char[]` password on every path, including refusals — checked for
  each of the four call sites.
- **No shell or command surface.** There is no `Runtime.exec`, no `ProcessBuilder` in the Java
  code, and `mutation_battery.py` uses a timeout-bounded `subprocess.run` with an argument
  list rather than a shell string, so there is no injection surface to report.
- **`recent` bounds its work** (`Math.min(500, Math.max(1, ...))`) — the missing bound is on the
  file-reading paths (SEC-04), not the console one.
- **The README's own limitations are honest and correctly stated** (accounts in memory,
  append-only by convention, no encryption, credential-free reads, lockout per process). The
  findings above are about where behaviour contradicts a claim (SEC-01, SEC-05) or where a
  stated limitation has a sharper consequence than documented (SEC-11) — not about hidden
  design.

Checks I ran that produced nothing, recorded so the absence is not mistaken for an oversight:
`Files.newByteChannel`/temp-file misuse (none — the trail is only ever appended to, so there is
no TOCTOU-on-replace class here); integer overflow in `seq` (`long`, monotonic);
`Locale`-dependent case folding (`toLowerCase(Locale.ROOT)` everywhere in the username path);
base64 decoder strictness for stored salts/digests (the `MIME` decoder's leniency does not
matter because length is checked after decoding, and a wrong-length digest is refused);
session token entropy (12 `SecureRandom` bytes is adequate — the token is in fact never
validated for anything, which is SEC-07's subject, not a strength problem); and the
`AdminPortalTest.java` gate tests, which do verify the refusal path properly —
`adminFunctionsNeedSession` (`AdminPortalTest.java:404`) drives seven admin command strings
through `AdminConsole.execute` with no session and asserts the standard sentence, no leaked
audit records and no leaked log path for each, then records each refusal in the trail.

One assurance gap, reported as such rather than as a CWE: `tools/mutation_battery.py:21` sets
`SRC = "/data/results/qwen/set_a/sallie/6/security"`, a path that does not exist in this
folder (the source under review is `/data/results-cyber/...`). The battery therefore raises
`FileNotFoundError` at `open(os.path.join(SRC, MAIN))` before compiling anything, so the
`README.md:208` claim of `mutants: 18 killed: 18 survived: 0` cannot be reproduced from the
reviewed tree. Even if it were pointed at this folder, only two of the 18 mutants touch the
reader at all — `record-parse-breaks-on-escaped-backslash` and `sequence-never-advances` — and
neither reaches the code behind SEC-04 (the unbounded `Files.readAllLines`), SEC-05's fail-open
`catch` in `lastSeqIn`, or SEC-06's `\uXXXX` reconstitution.
