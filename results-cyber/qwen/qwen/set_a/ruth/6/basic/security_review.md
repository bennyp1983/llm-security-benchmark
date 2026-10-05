# Security Review: UserAuthentication (Java password authentication + audit log)

## 1. Executive Summary

The component is a single-file, self-contained password authentication service (`UserAuthentication.java`, 1069 lines) that registers accounts, verifies credentials with PBKDF2-HMAC-SHA256, enforces per-account lockout, and writes a sanitized pipe-delimited audit log. It is unusually careful for a demo: salts come from `SecureRandom`, the comparison uses `MessageDigest.isEqual`, every authentication path pays exactly one key derivation so an unknown user costs the same as a known one, untrusted log fields are sanitized against CRLF/`|` injection, and `toString()` on the credential-bearing types is redacted. A companion suite (`AuthTest.java`) and a mutation-testing harness (`mutation_test.py`) back that up, and 29 of 31 injected mutants were killed.

The residual risk is concentrated at the trust boundary around **stored, self-describing KDF records** and in the **CLI demo entry point**, not in the crypto core:

- **One High finding.** `PasswordHash.parse()` accepts any iteration count above a 1 000 floor straight out of the stored record, and `deriveKey()` then runs the KDF with *that* count during login. A record with `pbkdf2-sha256$2147483647$...` makes that account's login hang for effectively forever, and because the derivation happens before the lockout check, an attacker who can write to the account store can turn any single account (or every account) into a permanent denial of service and pin CPU across the thread pool. Nothing caps, normalises, or rejects out-of-policy cost at parse time.
- **Six Medium findings.** Credentials are accepted on the command line (`--script user:password`), where they are visible in `ps`/`/proc/<pid>/cmdline` and shell history; neither the caller's password `char[]` nor the derived key `byte[]` is ever zeroized, and the no-console interactive fallback routes the password through an immutable `String`; the audit log is created with default permissions and no `PosixFilePermission`/`umask` handling; `FileEventLogger.log()` rethrows an `UncheckedIOException` from inside `authenticate()` *after* the credential check has already been decided, so a full or unwritable log either wedges authentication or silently loses the record depending on how the caller handles the exception; `register()` returns a boolean and logs `created`/`duplicate`, and a public `accountExists()` exists, giving a live user-enumeration oracle; and there is no per-source rate limit, so the per-account lockout is itself an abuse primitive (targeted lock-out of any known username) and a username spray is unthrottled.
- **Four Low findings.** Hardcoded demo credentials that are also printed to stdout; an unrestricted `--log` path argument that appends to any writable location; a KDF policy floor of 1 000 rounds that formally permits near-unstyled hashing; and no password-strength policy at all — `register()` accepts a single-character password.

None of the findings require redesigning the hashing scheme. The High one is closed by a policy ceiling at parse time plus re-derivation on the configured cost; the Medium ones are closed by moving credentials off `argv`, wiping buffers in a `finally`, applying restrictive file attributes, decoupling audit-write failure from the authentication result, and adding a source-keyed limiter.

## 2. Scope

Reviewed in place: `/data/results-cyber/qwen/set_a/ruth/6/basic/`.

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `UserAuthentication.java` (1069 lines) | Production code: account registry, PBKDF2-HMAC-SHA256 password hashing, per-account lockout, audit logger, CLI demo. | KDF parameters and the self-describing record `pbkdf2-sha256$iterations$base64(salt)$base64(key)` (`665`–`789`); iteration policy floor with no ceiling (`139`–`141`, `675`–`677`); unbounded `iterations` parsed from stored data (`709`–`717`) and used for the login derivation (`750`–`753`); `MessageDigest.isEqual` comparison (`755`–`757`); equal-work derivation on every path (`474`–`478`, `117`); NFKC username normalisation (`594`–`612`); password-form collision guard `isHashablePassword` (`623`–`641`); log-field sanitizer (`645`–`660`); duplicate-username boolean and audit detail (`439`–`454`); public `accountExists` (`559`–`562`); lockout arithmetic (`892`–`901`); audit-file creation, permissions and error handling (`370`–`399`); plaintext credential lifetimes (`759`–`772`, `1013`–`1019`); CLI handling of `--log`, `--iterations`, `--script`, demo passwords (`947`–`1067`). |
| `AuthTest.java` (1110 lines) | Test harness for the above (38 test groups; writes only to `Files.createTempFile`, deletes afterwards; `System.exit` at `88`). | Exercises the sanitizer, timing equal-work, lockout, corrupt-record handling. Contains a hardcoded test password (`42`). No production sink, no persistence outside temp files. |
| `mutation_test.py` | Mutation harness: copies the sources into `tempfile.mkdtemp()`, injects 31 mutants, recompiles with `javac` and runs `AuthTest`. | `subprocess` invoked with list arguments — no `shell=True`, no string interpolation into a shell; mutates only copies; `shutil.rmtree(..., ignore_errors=True)` cleanup. Its two surviving mutants are evidence for §6. |
| `README.md` | Design notes and stated limitations. | Documents the equal-work design, the 120 000-round floor, that `main` is a demo, and that front-end rate limiting is the complementary control. Not executable. |

`prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `result.md`, `return.txt`, `mut.log`, `out-test.log` and `out/` (compiled `.class` output) are task metadata and build artefacts, not source under review.

## 3. Skills Applied

- `performing-cryptographic-audit-of-application`: the crypto core — `PasswordHash` record format, `derive()`/`generate()`/`parse()` (`665`–`789`), `SecureRandom` salt generation (`689`–`692`), `MessageDigest.isEqual` (`756`), and the KDF cost policy. Its "check key derivation function parameters", "validate random number generator usage" and "hardcoded keys/passwords/secrets in source" objectives produced SEC-01, SEC-10 and SEC-08; its "Weak KDF / low iteration PBKDF2" risk row is what the 1 000-round floor is judged against.
- `testing-for-sensitive-data-exposure`: credential exposure outside the intended channel — `argv` (`1028`–`1040`), non-`Console` interactive fallback (`1013`–`1019`), uncleared `char[]`/`byte[]` buffers (`759`–`772`), the printed demo credentials (`964`–`965`), and the audit file's on-disk permissions (`376`–`381`). Its masking/redaction step was used to check `Result.toString()` and `PasswordHash.toString()` (both redacted — see §6).
- `testing-api-authentication-weaknesses`: the authentication surface itself — `authenticate()` (`465`–`531`), `register()` (`439`–`454`), the account-enumeration differential test, weak-password acceptance, and lockout behaviour. Drove SEC-06, SEC-07 and SEC-11.
- `performing-directory-traversal-testing`: the two CLI sinks that accept a caller-supplied path/argument — `pathArgument(args, "--log", ...)` (`950`, `1065`–`1067`) and the `argument()` scanner (`1056`–`1063`). Drove SEC-09.
- No skill in the library covers log-injection hardening, audit-file permission assignment, secure zeroization of credential buffers, denial of service / resource exhaustion, login-attempt restriction by source, or audit-write failure handling. Those behaviours were reviewed against general **OWASP Top 10 (A02 Cryptographic Failures, A05 Security Misconfiguration, A07 Identification and Authentication Failures, A09 Logging Failures)** and **CWE (CWE-400/770, CWE-307, CWE-316/244, CWE-732, CWE-754/248, CWE-117)** knowledge; they account for SEC-01, SEC-02, SEC-03, SEC-04, SEC-05 and SEC-07, and the log-injection control is verified in §6.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Login KDF cost taken from the stored record with no upper bound → account-level denial of service | High | CWE-400 | `UserAuthentication.java:709-717`, `750-753` |
| SEC-02 | Credentials accepted on the command line (`--script user:password`) | Medium | CWE-214 | `UserAuthentication.java:1028-1040` |
| SEC-03 | Password `char[]` and derived key `byte[]` never zeroized; interactive fallback puts the password in a `String` | Medium | CWE-316 | `UserAuthentication.java:759-772`, `1013-1019` |
| SEC-04 | Audit log created with default permissions, no file-mode control | Medium | CWE-732 | `UserAuthentication.java:376-381` |
| SEC-05 | Audit-write failure rethrown from inside `authenticate()` after the credential decision | Medium | CWE-754 | `UserAuthentication.java:388-399` |
| SEC-06 | Account-enumeration oracle via `register()` result, audit detail and public `accountExists()` | Medium | CWE-204 | `UserAuthentication.java:439-454`, `559-562` |
| SEC-07 | No per-source attempt limit; per-account lockout is itself abusable | Medium | CWE-307 | `UserAuthentication.java:465-531`, `892-901` |
| SEC-08 | Hardcoded demo credentials in source, also printed to stdout | Low | CWE-798 | `UserAuthentication.java:958-965` |
| SEC-09 | Unrestricted `--log` path is opened for append at any writable location | Low | CWE-22 | `UserAuthentication.java:950`, `1065-1067` |
| SEC-10 | KDF policy floor of 1 000 rounds permits near-unstyled hashing | Low | CWE-916 | `UserAuthentication.java:139-141`, `675-677` |
| SEC-11 | No password-strength policy at registration | Low | CWE-521 | `UserAuthentication.java:439-448`, `623-641` |

## 5. Detailed Findings

### SEC-01: Login KDF cost is taken from the unbounded stored record, enabling account-level denial of service

- **Severity:** High
- **CWE:** CWE-400: Uncontrolled Resource Consumption ('Improper Resource Limitation or Throttling'); also CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `UserAuthentication.java:709-717` (unbounded parse), `UserAuthentication.java:750-753` (that count drives the login derivation)

**Vulnerable code:**

```java
// UserAuthentication.java:709-717
            int rounds;
            try {
                rounds = Integer.parseInt(parts[1]);
            } catch (NumberFormatException notNumeric) {
                throw new IllegalArgumentException("iterations is not a number", notNumeric);
            }
            byte[] salt = strictBase64(parts[2]);
            byte[] key = strictBase64(parts[3]);
            return new PasswordHash(rounds, salt, key);
```

```java
// UserAuthentication.java:750-753
        /** Runs the KDF; the caller owns the returned array. */
        byte[] deriveKey(char[] password) {
            return derive(password, salt, iterations);
        }
```

**Why it is a problem:** The record is self-describing by design — that is what lets the cost be raised later without a migration. But nothing bounds the value read back out. `PasswordHash`'s constructor only enforces a *floor* (`675`–`677`, `iterations < 1_000`), so `pbkdf2-sha256$2000000000$AAAA...$BBBB...` parses cleanly and becomes a legitimate `Account`. `deriveKey()` then runs PBKDF2-HMAC-SHA256 with the record's own count, and `authenticate()` calls it at `477` — **before** the enabled check (`496`), **before** the lockout check (`502`) and before any per-source throttle exists. Consequences: (a) anyone able to write to the account store — a compromised persistence layer, an unsafe import/repair path, `Account.withCorruptHash`-adjacent tooling at `842` — can make a single account's login never return, or make every account's login consume minutes-to-hours of CPU each, saturating the request pool while the service reports "up"; (b) `new Config(Integer.MAX_VALUE, ...)` is legal, so a single operator mistake at startup is a permanent outage; (c) because the derivation is deliberately equal-work on the unknown-user path too, the cheapest possible unauthenticated probe still triggers a KDF, so an attacker spraying usernames amplifies the cost rather than being cheaply rejected. The `--iterations` CLI value (`951`) is parsed with `Integer.parseInt` and flows straight into `Config`, so the demo path exposes the same lack of a ceiling. The README calls 120 000 rounds "a reasonable 2026 floor", which is exactly the shape of the bug: a floor with no ceiling is not a policy.

**Fix:** Treat the iteration count in a stored record as hostile input and clamp it to an accepted band at parse time, rejecting anything above the current policy maximum (and, separately, migrating records that fall below today's floor rather than honouring them). Then derive with a count the service has chosen, not one the data chose:

```java
// UserAuthentication.java:709-717 (corrected)
            int rounds;
            try {
                // Long.parseLong first so that "99999999999999" is a policy violation
                // rather than a silent NumberFormatException-turned-400.
                long parsed = Long.parseLong(parts[1]);
                if (parsed < MAX_ACCEPTED_ITERATIONS_LONG) {
                    throw new IllegalArgumentException("iterations above policy maximum");
                }
                rounds = (int) parsed;
            } catch (NumberFormatException notNumeric) {
                throw new IllegalArgumentException("iterations is not a number", notNumeric);
            }
            byte[] salt = strictBase64(parts[2]);
            byte[] key = strictBase64(parts[3]);
            // Never exceed the deployment's policy ceiling, whatever the record claims.
            return new PasswordHash(Math.min(rounds, config.maxIterations()), salt, key);
```

```java
// UserAuthentication.java:675-677 (corrected) — bound both ends, in one place
            if (iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS) {
                throw new IllegalArgumentException("iterations must be in ["
                    + MIN_ACCEPTED_ITERATIONS + ", " + MAX_ACCEPTED_ITERATIONS + "], got " + iterations);
            }
```

Additionally: keep a per-attempt wall-clock budget (`deriveKey` on a dedicated, bounded executor with a timeout that fails closed), reject `--iterations` values outside the band at `951` instead of trusting `Integer.parseInt`, and upgrade any record whose count is below the current floor on successful login so cost only ever moves up.

### SEC-02: Credentials passed on the command line are visible to other local principals

- **Severity:** Medium
- **CWE:** CWE-214: Exposure of Sensitive Information in an OS Command's Arguments (also CWE-522)
- **Location:** `UserAuthentication.java:1028-1040` (`scripted`), reached from `UserAuthentication.java:974-976`

**Vulnerable code:**

```java
// UserAuthentication.java:1028-1040
    private static void scripted(UserAuthentication auth, String[] args, PrintStream out) {
        for (String pair : args) {
            // Usernames can never contain ':', so splitting at the last one lets the password do so.
            int at = pair.lastIndexOf(':');
            if (at < 0 || pair.startsWith("--")) {
                continue;
            }
            show(out, pair.substring(0, at),
                auth.authenticate(pair.substring(0, at), pair.substring(at + 1).toCharArray(), "cli"));
        }
    }
```

**Why it is a problem:** Any credential handed to `java UserAuthentication --script alice:winter-Frost-42` is a plaintext secret in the process argument vector for the lifetime of the JVM. On Linux every local user can read `/proc/<pid>/cmdline` (and `ps -ef`, `ps auxww`) for a process they do not own; `argv` is also written into shell history (`~/.bash_history`), into `auditd`/`sysmon` exec telemetry, into CI job logs and container-inspect output, and into crash/hang dumps. A shared build agent or a multi-tenant host running this demo therefore leaks every scripted password to every other account on the box, and the passwords leak again into whatever log shipper collects the CI output. This is also the only path that lets a credential reach the service *without* the `char[]`-erasure affordances the API otherwise provides — the secret is unavoidably an immutable `String` taken straight out of `args`.

**Fix:** Take scripted credentials from stdin or from a descriptor/file with restrictive permissions, never from `argv`, and refuse to start if the argument looks like a credential:

```java
// corrected: read "user:password" pairs from stdin, one per line
    private static void scripted(UserAuthentication auth, String[] args, PrintStream out)
            throws IOException {
        BufferedReader in = new BufferedReader(new java.io.InputStreamReader(
            System.in, StandardCharsets.UTF_8));
        String pair;
        while ((pair = in.readLine()) != null) {
            int at = pair.lastIndexOf(':');
            if (at < 0) {
                continue;
            }
            char[] password = pair.substring(at + 1).toCharArray();
            try {
                show(out, pair.substring(0, at),
                    auth.authenticate(pair.substring(0, at), password, "stdin"));
            } finally {
                java.util.Arrays.fill(password, '\0');   // erase as soon as the call returns
            }
        }
    }
```

`main()` should then reject any `args` element matching `[^-][^:]*:` with a message pointing at stdin, so an operator who types the old form is told rather than silently leaking. (For scripted pairs that must come from a file, open it via a `--script-file` path and check the mode is no wider than `0600` first.)

### SEC-03: Cleartext credential buffers are never erased; the no-console fallback routes the password through a `String`

- **Severity:** Medium
- **CWE:** CWE-316: Cleartext Storage of Sensitive Information in a Memory Region (also CWE-244: Improper Clearing of Memory Before Release)
- **Location:** `UserAuthentication.java:759-772` (`derive`), `UserAuthentication.java:1013-1019` (`interactive` fallback)

**Vulnerable code:**

```java
// UserAuthentication.java:759-772
        private static byte[] derive(char[] password, byte[] salt, int iterations) {
            if (!isHashablePassword(password)) {
                throw new IllegalArgumentException("password form cannot be hashed safely");
            }
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BYTES * 8);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF);
                return factory.generateSecret(spec).getEncoded();
            } catch (GeneralSecurityException unsupported) {
                throw new IllegalStateException(KDF + " is unavailable on this JVM", unsupported);
            } finally {
                spec.clearPassword();
            }
        }
```

```java
// UserAuthentication.java:1013-1019
                out.print("username: ");
                out.flush();
                username = in.readLine();
                out.print("password: ");
                out.flush();
                String line = in.readLine();
                password = line == null ? null : line.toCharArray();
```

**Why it is a problem:** `spec.clearPassword()` erases only the copy that `PBEKeySpec` made internally. Two buffers that the API exists to make erasable are left behind: the caller's `password` `char[]`, which is passed in at `759` and never zeroized by `derive`, `deriveKey`, `authenticate` or any `register` path (a search of the file for zeroization finds none — `Arrays.fill` appears nowhere), and the derived `byte[]` returned at `766`, whose javadoc at `750` explicitly says "the caller owns the returned array" while `authenticate()` (`477`) never writes to it again after `stored.matches(presented)` (`512`). Both therefore stay resident in the heap until the garbage collector happens to move and reuse those pages, and are dumped wholesale by a heap dump, a core dump, `jmap`, a crash reporter, or a memory-scraping attacker on a shared host. The point of the `char[]` API — over `String` — is precisely that it can be erased; not erasing it forfeits the benefit while keeping the cost. The fallback at `1018` is worse: when `System.console()` is null (any non-tty invocation: CI, pipe, IDE run, `systemd` service), the password is read via `BufferedReader.readLine()` into an **immutable `String`** that is neither erasable nor guaranteed to leave the heap, and is additionally echoed to the terminal because `readLine` cannot suppress input without a `Console`. That silently downgrades security based on how the process was launched, with no warning.

**Fix:** Erase on every exit path in a `finally`, including the returned key, and refuse to accept a credential that has already become a `String`:

```java
// UserAuthentication.java:759-772 (corrected)
        private static byte[] derive(char[] password, byte[] salt, int iterations) {
            if (!isHashablePassword(password)) {
                throw new IllegalArgumentException("password form cannot be hashed safely");
            }
            byte[] key = null;
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BYTES * 8);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF);
                key = factory.generateSecret(spec).getEncoded();
                return key;
            } catch (GeneralSecurityException unsupported) {
                throw new IllegalStateException(KDF + " is unavailable on this JVM", unsupported);
            } finally {
                spec.clearPassword();
                java.util.Arrays.fill(password, '\0');   // caller's buffer: erase before returning
            }
        }
```

```java
// UserAuthentication.java:1013-1019 (corrected)
            } else {
                // No Console means no echo-free read and no way to avoid an immutable String.
                // Fail closed rather than downgrade silently.
                throw new IOException("no console available: refusing to read a password "
                    + "from a non-tty stdin; run with --script and feed credentials on stdin");
            }
```

`authenticate()` should likewise zeroize `presented` once the comparison returns (`java.util.Arrays.fill(presented, (byte) 0)` in a `finally` around the `matches` call at `512`), and the contract comment at `750` should state that ownership means an obligation to erase.

### SEC-04: The audit log is created with default permissions and no symlink check

- **Severity:** Medium
- **CWE:** CWE-732: Incorrect Permission Assignment for Critical Resource
- **Location:** `UserAuthentication.java:376-381`

**Vulnerable code:**

```java
// UserAuthentication.java:376-381
            try {
                if (file.getParent() != null) {
                    Files.createDirectories(file.getParent());
                }
                this.writer = Files.newBufferedWriter(file, StandardCharsets.US_ASCII,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
```

**Why it is a problem:** This file is the security audit trail: every line carries a timestamp, the username, the outcome and reason, the caller-supplied remote address and the running failure count. It is opened with no `FileAttribute`, so on a POSIX filesystem the new file gets the process umask's default — `0644` under the usual `umask 022`, i.e. readable by every local account — and `Files.createDirectories(file.getParent())` likewise creates any missing parent directory with the default `0755 & ~umask`. Nothing in the class applies `PosixFilePermissions`, an `aclFileView`, or documents a `umask 077` requirement, so the confidentiality of the log depends entirely on an accident of the launching environment. Any unprivileged local user can therefore read who authenticates, from which address, how often, and how close any account is to tripping its lockout — which is a ready-made targeting list for a spray and tells an attacker exactly which accounts are already locked. Worse, because the file is opened with `APPEND` and the path is caller-supplied (SEC-09) with no `Files.isSymbolicLink` check, a local attacker who can win the create race on a world-writable parent directory — or who pre-creates `auth-demo.log` as a symlink to a target — gets the service appending attacker-shaped lines through that symlink with the service's own privileges.

**Fix:** Request the restrictive mode at creation, re-apply it if the file already existed, refuse symlinked targets, and state the non-POSIX fallback:

```java
// UserAuthentication.java:376-384 (corrected)
            try {
                boolean posix = file.getFileSystem()
                    .supportedFileAttributeViews().contains("posix");
                if (Files.isSymbolicLink(file)) {
                    throw new IOException("refusing to append through a symlink: " + file);
                }
                if (file.getParent() != null) {
                    Files.createDirectories(file.getParent());
                    if (posix) {
                        Files.setPosixFilePermissions(file.getParent(),
                            PosixFilePermissions.fromString("rwx------"));
                    }
                }
                this.writer = posix
                    ? Files.newBufferedWriter(file, StandardCharsets.US_ASCII,
                        new java.nio.file.attribute.FileAttribute<?>[] { PosixFilePermissions
                            .asFileAttribute(PosixFilePermissions.fromString("rw-------")) },
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                        StandardOpenOption.APPEND)
                    : Files.newBufferedWriter(file, StandardCharsets.US_ASCII,
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                        StandardOpenOption.APPEND);
                if (posix) {
                    // CREATE does not change the mode of a file that already existed.
                    Files.setPosixFilePermissions(file,
                        PosixFilePermissions.fromString("rw-------"));
                }
            } catch (IOException cannotOpen) {
                throw new UncheckedIOException("cannot open audit log " + file, cannotOpen);
            }
```

The `asFileAttribute` form alone is not enough (it is ignored for a pre-existing file and throws `UnsupportedOperationException` on non-POSIX stores), which is why both the attribute and the follow-up `setPosixFilePermissions` sit behind the `posix` capability check. On Windows, where the view is absent, apply an explicit DACL instead — `icacls <file> /inheritance:r /grant:r "<service account>:F"` — and document `umask 077` as a deployment requirement for anything that can do neither.

### SEC-05: Audit-write failure is rethrown from inside `authenticate()` after the credential decision

- **Severity:** Medium
- **CWE:** CWE-754: Improper Check for Unusual or Exceptional Conditions
- **Location:** `UserAuthentication.java:388-402` (rethrow at `396`)

**Vulnerable code:**

```java
// UserAuthentication.java:388-402
        public void log(Event event) {
            String line = event.format();
            synchronized (lock) {
                try {
                    writer.write(line);
                    writer.newLine();
                    writer.flush();
                } catch (IOException writeFailed) {
                    throw new UncheckedIOException("cannot write audit log " + file, writeFailed);
                }
            }
            if (echo != null) {
                echo.println(line);
            }
        }
```

**Why it is a problem:** `log()` is called from twelve places on the authentication paths — `451`, `481`, `485`, `489`, `493`, `497`, `502`, `508`, `515`, `529`, `554` and inside `refuse()` at `571` — and it converts a write failure into an unchecked exception that escapes `authenticate()`. The credential decision has already been computed at that point (`512`-`523`), yet the caller never receives a `Result`. Both ways of living with that are wrong. Fail-closed by accident: a full log partition, an immutable attribute, an exceeded quota or a disconnected mount turns *every* login into an `UncheckedIOException`, so a logging fault becomes a total authentication outage that any principal able to grow a file in that directory can cause (SEC-09 lets the operator point the log at any writable path). Fail-open by wrapper: the natural application-level response is `catch (RuntimeException e) { /* log is down, carry on */ }`, which silently discards both the exception and the record — so the exact event an investigator needs ("what happened while the log was broken?") is the one that is guaranteed missing, and there is no `EventType` for it either, so the outage is invisible in-band. The success path has a second ordering problem: `recordSuccess()` at `526` clears the failure counter and `lockedUntil` *before* the `LOGIN_SUCCESS` write at `529`, so a failing write mutates account state while leaving no trace that a successful authentication occurred — an ideal hiding place for one targeted login on a host the attacker already controls enough to make a file unwritable.

**Fix:** Make `log()` total and return a verdict, then make the caller's fail-open/fail-closed choice explicit. The existing enums have no value for either condition (`Outcome` is `58`-`64`, `Reason` is `68`-`77`), so they must be extended first:

```java
// UserAuthentication.java:58-77 (additions)
    public enum Outcome {
        SUCCESS,
        INVALID_CREDENTIALS,
        ACCOUNT_LOCKED,
        ACCOUNT_DISABLED,
        INVALID_INPUT,
        AUDIT_UNAVAILABLE          // renders the same generic message as INVALID_CREDENTIALS
    }

    public enum Reason {
        OK,
        UNKNOWN_USER,
        BAD_PASSWORD,
        ACCOUNT_LOCKED,
        ACCOUNT_DISABLED,
        MALFORMED_USERNAME,
        MALFORMED_PASSWORD,
        CORRUPT_RECORD,
        AUDIT_WRITE_FAILED
    }
```

```java
// UserAuthentication.java:387-402 (corrected)
        /** @return true when the record is durably appended; never throws. */
        @Override
        public boolean log(Event event) {
            String line = event.format();
            synchronized (lock) {
                try {
                    writer.write(line);
                    writer.newLine();
                    writer.flush();
                } catch (IOException writeFailed) {
                    failedWrites++;                       // exposed as failedWrites() for alerting
                    if (echo != null) {
                        echo.println("AUDIT WRITE FAILED: " + writeFailed);
                    }
                    return false;
                }
            }
            if (echo != null) {
                echo.println(line);
            }
            return true;
        }
```

```java
// UserAuthentication.java:526-532 (corrected)
        int cleared = account.recordSuccess(startedAt);
        Result result = new Result(Outcome.SUCCESS, Reason.OK, username, startedAt,
            elapsedMillis(nanos), 0);
        if (!log.log(new Event(EventType.LOGIN_SUCCESS, username, Outcome.SUCCESS, Reason.OK,
                remoteAddress, result.durationMillis(), 0,
                cleared > 0 ? "prior failures cleared" : "ok"))) {
            // A success we cannot record is a success we cannot honour: refuse the session
            // explicitly instead of letting an exception decide it upstream.
            return new Result(Outcome.AUDIT_UNAVAILABLE, Reason.AUDIT_WRITE_FAILED, username,
                startedAt, result.durationMillis(), 0);
        }
        return result;
```

Change the `EventLogger` interface to `boolean log(Event event)` and update its in-memory implementation and `AuthTest.RecordingLog` accordingly; alert on `failedWrites() > 0` out of band (metrics/syslog), and size the log on a filesystem with `Enospc`-free headroom, ideally with a fallback sink that is opened at startup rather than at failure time.

### SEC-06: Account-existence oracle through `register()`, the audit detail and `accountExists()`

- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `UserAuthentication.java:439-454`, `UserAuthentication.java:559-562`

**Vulnerable code:**

```java
// UserAuthentication.java:439-454
    public boolean register(String rawUsername, char[] password) {
        String username = normalizeUsername(rawUsername);
        if (username == null) {
            throw new IllegalArgumentException("username must be " + USERNAME_MIN + "-"
                + USERNAME_MAX + " characters of [A-Za-z0-9._-] after trimming");
        }
        if (!isHashablePassword(password)) {
            throw new IllegalArgumentException("password is empty, too long, ends with NUL or "
                + "contains an unpaired surrogate");
        }
        PasswordHash hash = PasswordHash.generate(password, config.iterations, random);
        boolean created = accounts.register(username, hash);
        log.log(new Event(EventType.ACCOUNT_REGISTERED, username, null, Reason.OK, null, 0, 0,
            created ? "created" : "duplicate"));
        return created;
    }
```

```java
// UserAuthentication.java:559-562
    public boolean accountExists(String username) {
        String name = normalizeUsername(username);
        return name != null && accounts.find(name) != null;
    }
```

**Why it is a problem:** The login path is carefully built to be non-differentiating: `Outcome` deliberately collapses "no such user" into `INVALID_CREDENTIALS` (the javadoc at `56`-`57` says so), the refusal text is identical on both branches, and every path pays one KDF (`474`-`478`) — the mutation harness confirms both controls with `unknown-user-reason-merged` and `user-message-leaks-unknown-user` killed (`mut.log:26`-`27`). `register()` and `accountExists()` then hand back the same secret through a wider door. `register()` returns `true`/`false` for created/duplicate and records `"created"` versus `"duplicate"` in the audit line, so any caller that exposes signup — the normal case — leaks whether a username is taken, which is exactly the enumeration primitive a credential-stuffing or spraying campaign uses to build its target list, and it leaks it with a side channel that survives a rewritten login screen: the timing also differs (a duplicate pays for the derivation at `449` and then throws the result away, and the store write is skipped, so the response profile is measurably different from a fresh creation). `accountExists()` is a public method whose only job is to answer that question; nothing in this file calls it, so it exists for callers to wire straight into a controller or an admin endpoint. Combined with SEC-12 (no password policy) and SEC-07 (no per-source limit), a caller with a signup form can enumerate the whole `[A-Za-z0-9._-]` namespace cheaply and then spray the hits.

**Fix:** Return a status that does not distinguish "created" from "already yours, and we are not telling you", and remove the existence accessor from the public surface:

```java
// UserAuthentication.java:439-454 (corrected)
    /**
     * Registration is deliberately opaque: a caller cannot learn from this return value,
     * from its timing, or from the audit trail whether the name already existed.
     */
    public void register(String rawUsername, char[] password) {
        String username = normalizeUsername(rawUsername);
        if (username == null) {
            throw new IllegalArgumentException("username must be " + USERNAME_MIN + "-"
                + USERNAME_MAX + " characters of [A-Za-z0-9._-] after trimming");
        }
        if (!isHashablePassword(password)) {
            throw new IllegalArgumentException("password is not acceptable");
        }
        PasswordHash hash = PasswordHash.generate(password, config.iterations, random);
        boolean created = accounts.register(username, hash);
        // Same event shape either way: the distinction is internal-only.
        log.log(new Event(EventType.ACCOUNT_REGISTERED, username, null, Reason.OK, null, 0, 0,
            created ? "created" : "created"));
        // Duplicate attempts are additionally throttled per source (SEC-07's limiter).
    }
```

```java
// UserAuthentication.java:559-562 (corrected) — delete the public existence probe.
    // Admin tooling that genuinely needs it goes through a privileged, separately audited
    // interface (e.g. a package-private AccountStore.size() behind an operator role),
    // never through the authentication façade.
```

If the application must tell a user "that name is taken", do it out of band (a confirmation e-mail to the address on file, or a rate-limited check behind a CAPTCHA) rather than from the primitive, and keep the `"created"`/`"duplicate"` distinction out of anything a non-operator can read — including the log line, which `FileEventLogger` echoes to stdout by default.

### SEC-07: No per-source attempt limit — the per-account lockout is itself an abuse primitive

- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
- **Location:** `UserAuthentication.java:465-531`, `UserAuthentication.java:892-901`

**Vulnerable code:**

```java
// UserAuthentication.java:892-901
        synchronized FailureState recordFailure(Instant now, Config config) {
            if (lastFailure != null
                && Duration.between(lastFailure, now).compareTo(config.failureWindow) > 0) {
                failures = 0;
            }
            failures++;
            lastFailure = now;
            boolean tripped = failures >= config.maxFailures;
            if (tripped) {
                lockedUntil = now.plus(config.lockDuration);
```

**Why it is a problem:** All attempt limiting in this class is keyed on the *account*. `recordFailure` bumps a counter that lives inside the target's `Account` (`892`-`904`), and `authenticate()` (`465`-`531`) consults only that account's state (`502`-`506`). `remoteAddress` is threaded through purely for logging — it is sanitised at `568`-`570` and written into the event, never used to make a decision. Two consequences. First, password spraying is unbounded: an attacker can try one password against every username in the directory without ever accumulating `maxFailures` consecutive failures on any single account, so the lockout never engages for the victim and, because each probe costs the *server* a full PBKDF2 run (`477`, on the unknown-user path too), the cheapest remote probe buys the most server work. Second, and worse for availability, the lockout is a free denial-of-service lever against any username the attacker knows: `maxFailures` wrong passwords from anywhere locks the real user out for `lockDuration`, with the source never considered, so `alice` can be kept permanently locked by anyone who can reach the endpoint — no credential of her own required. The code is aware of the second half of this: the comment at `519`-`520` notes the trip is reported as a plain bad credential so the response does not disclose the lock, and `main` demonstrates the lockout at `985`-`990`. But "the response does not reveal the lock" is not the same as "the lock cannot be pulled by a stranger". The README names front-end rate limiting as the complementary control, which makes this a documented gap rather than an oversight — it is still the only missing link in the attempt-limiting design, and nothing in the class makes it hard to add.

**Fix:** Add a source-keyed budget, and check it *before* paying for the KDF, while keeping the equal-work property among admitted attempts so the throttle does not become a new enumeration channel:

```java
// UserAuthentication.java:58-77 (additions)
    public enum Outcome { SUCCESS, INVALID_CREDENTIALS, ACCOUNT_LOCKED, ACCOUNT_DISABLED,
        INVALID_INPUT, ATTEMPT_THROTTLED }   // renders the same generic message as the others

    public enum Reason { OK, UNKNOWN_USER, BAD_PASSWORD, ACCOUNT_LOCKED, ACCOUNT_DISABLED,
        MALFORMED_USERNAME, MALFORMED_PASSWORD, CORRUPT_RECORD, RATE_LIMITED }
```

```java
// UserAuthentication.java:469-478 (corrected: cheap checks and the budget precede the derivation)
        String username = normalizeUsername(rawUsername);

        if (username == null) {
            return refuse(EventType.LOGIN_REFUSED, Outcome.INVALID_INPUT,
                Reason.MALFORMED_USERNAME, rawUsername, remoteAddress, startedAt, nanos, 0,
                "username rejected");
        }
        if (!limits.allowLoginAttempt(remoteAddress)) {   // token bucket, keyed per source
            return refuse(EventType.LOGIN_REFUSED, Outcome.ATTEMPT_THROTTLED,
                Reason.RATE_LIMITED, username, remoteAddress, startedAt, nanos, 0,
                "source budget exhausted");
        }

        // Admitted attempts all pay exactly one derivation, known user or not (see 474-478).
        boolean derivable = stored != null;
        byte[] presented = derivable ? stored.deriveKey(password)
            : equalWorkHash.deriveKey(EQUAL_WORK_SECRET);
```

`limits` is a bounded ` ConcurrentHashMap<String, Bucket>` (evicting on size or age so the table cannot itself become the DoS, fail-closed when the source is unknown), sized to the legitimate traffic of one account's users behind one NAT gateway, and it must be a *budget over time* rather than a counter — otherwise an attacker simply spreads attempts across a proxy pool. Keep `recordFailure` as the per-account backstop, and additionally require a second factor or an operator unlock before a *locked* account can be unlocked by password entry alone, so that locking is not reversible by the same attacker who pulled it. Consider making the lock sticky-per-source (failures from a source that has already tripped one account count against that source's budget) so the "lock everybody" script becomes the most expensive thing an attacker can do.

### SEC-08: `setEnabled()` changes account state with no audit record and returns an existence oracle

- **Severity:** Medium
- **CWE:** CWE-778: Insufficient Logging; also CWE-204: Observable Response Discrepancy
- **Location:** `UserAuthentication.java:536-544`

**Vulnerable code:**

```java
// UserAuthentication.java:535-544
    /** Enables or disables an account; disabled accounts are refused before any credential use. */
    public boolean setEnabled(String username, boolean enabled) {
        String name = normalizeUsername(username);
        Account account = name == null ? null : accounts.find(name);
        if (account == null) {
            return false;
        }
        account.setEnabled(enabled);
        return true;
    }
```

**Why it is a problem:** Disabling an account is a security-relevant state transition — it is indistinguishable, from the user's point of view, from a denial of service, and `authenticate()` refuses a disabled account before touching the credential (`495`-`497`), so `setEnabled(name, false)` is a complete, silent lockout primitive for any username. It writes no `Event` at all. The class is otherwise explicit about auditing exactly this kind of transition: operator unlock logs `ACCOUNT_UNLOCKED` at `554`-`555` (`"unlocked by operator"`), the automatic lock-expiry logs `ACCOUNT_UNLOCKED` at `508`, lockout logs `ACCOUNT_LOCKED_OUT` at `515`, registration logs at `451`, and every refusal goes through `refuse()` which logs at `571`. So the audit trail records every failure a user experiences *except* the one an operator (or anyone holding a reference to this object, or a compromised admin endpoint) caused by disabling them — precisely the transition most in need of attribution, and the one whose absence lets an insider disable an account, let the victim suffer a stream of `LOGIN_REFUSED … ACCOUNT_DISABLED` events that look like user error, and leave nothing pointing at who did it. `EventType` (`80`-`88`) has no `ACCOUNT_DISABLED`/`ACCOUNT_ENABLED` value, so the record could not be written even if the code tried. The `boolean` return compounds it: `true`/`false` distinguishes "that account exists" from "it does not", adding a second existence oracle alongside SEC-06, and `main` uses it at `962` in a way any caller can copy.

**Fix:** Log the transition before returning, with the actor recorded, and stop leaking existence into the return value:

```java
// UserAuthentication.java:80-88 (additions)
    public enum EventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGIN_REFUSED,
        ACCOUNT_REGISTERED,
        ACCOUNT_LOCKED_OUT,
        ACCOUNT_UNLOCKED,
        ACCOUNT_ENABLED,
        ACCOUNT_DISABLED
    }
```

```java
// UserAuthentication.java:535-544 (corrected)
    /** Enables or disables an account; disabled accounts are refused before any credential use. */
    public void setEnabled(String username, boolean enabled, String operator) {
        String name = normalizeUsername(username);
        Account account = name == null ? null : accounts.find(name);
        if (account == null) {
            // Recorded too: "operator tried to disable an unknown account" is itself a signal.
            log.log(new Event(EventType.LOGIN_REFUSED, name, null, Reason.UNKNOWN_USER, null,
                0, 0, (enabled ? "enable" : "disable") + " refused, no such account, by "
                    + operator));
            return;
        }
        account.setEnabled(enabled);
        log.log(new Event(enabled ? EventType.ACCOUNT_ENABLED : EventType.ACCOUNT_DISABLED,
            name, null, Reason.OK, null, 0, 0, "changed by " + operator));
    }
```

The `operator` identity must come from the authenticated caller, not from a self-asserted parameter, and this method belongs behind the same privileged, separately-audited interface proposed for SEC-06's `accountExists()`. If a `boolean` is genuinely needed by an in-process caller, keep it package-private so it cannot become a remote oracle, and prefer `ACCOUNT_ENABLED`/`ACCOUNT_DISABLED` events for the unknown-name case rather than a silent `false`.

### SEC-09: Hardcoded demo credentials in source, also printed to stdout

- **Severity:** Low
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Location:** `UserAuthentication.java:958-965`

**Vulnerable code:**

```java
// UserAuthentication.java:958-965
            auth.register("alice", "winter-Frost-42".toCharArray());
            auth.register("bob", "correct horse battery staple".toCharArray());
            auth.register("dave", "hunter2-hunter2".toCharArray());
            auth.register("erin", "sup3r-Secret!".toCharArray());
            auth.setEnabled("erin", false);
            out.println();
            out.println("Demo accounts: alice / winter-Frost-42, bob / correct horse battery staple");
            out.println("Accounts dave (lockout demo) and erin (disabled) also exist.");
```

**Why it is a problem:** Four passwords are baked into the shipped source and two more are printed on every run (`964`), so the credential pair `alice / winter-Frost-42` is simultaneously in the repository, in the compiled class file, in stdout, and in whatever collects stdout. The damage is not the demo box — it is reuse. This class is written well enough to be lifted into something real, and the moment someone wires a persistent store to `main` for a staging deployment, the first accounts created carry a password that is public and printed, with no prompt to change it; `962` even disables `erin`, which teaches the copy-paster that demo state is expected to persist. The same string lives in `AuthTest.java:42` (`private static final char[] PW = "winter-Frost-42".toCharArray();`), so it is also duplicated across the test suite and grep-able as "the" password of this component. `964` additionally defeats the only defence the interactive path has: `readPassword` exists to keep a password off the screen, and the same program prints other accounts' passwords two lines above the prompt. The `--iterations` default at `951` (`60000`, half the configured `120_000`) is a second thing a copy-pasted `main` carries into production quietly.

**Fix:** Supply demo secrets from the environment or generate them, never print them, and keep the test fixture distinct:

```java
// UserAuthentication.java:958-965 (corrected)
            char[] alicePw = demoPassword("ALICE_DEMO_PASSWORD");
            char[] bobPw = demoPassword("BOB_DEMO_PASSWORD");
            auth.register("alice", alicePw);
            auth.register("bob", bobPw);
            auth.register("dave", demoPassword("DAVE_DEMO_PASSWORD"));   // lockout demo
            auth.register("erin", demoPassword("ERIN_DEMO_PASSWORD"));   // disabled demo
            auth.setEnabled("erin", false, "demo-operator");
            java.util.Arrays.fill(alicePw, (char) 0);                    // see SEC-03
            java.util.Arrays.fill(bobPw, (char) 0);
            out.println();
            out.println("Demo accounts: alice, bob, dave (lockout), erin (disabled).");
            out.println("Passwords come from *_DEMO_PASSWORD or a generated value; this");
            out.println("program never prints them.");
```

```java
    // New helper next to argument()/pathArgument() (~1057-1067).
    private static char[] demoPassword(String envVar) {
        String fromEnv = System.getenv(envVar);
        if (fromEnv != null && !fromEnv.isEmpty()) {
            return fromEnv.toCharArray();
        }
        byte[] raw = new byte[18];
        RANDOM.nextBytes(raw);   // never argv (SEC-02), never stdout
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
            .toCharArray();
    }
```

Do not accept the replacement on the command line — that would reintroduce SEC-02. For `AuthTest.java:42`, a literal is defensible as a test fixture because the tests use an in-memory store and a temp file, but it should be renamed to something obviously non-credential (e.g. `TEST_FIXTURE_ONLY`) and must never be an acceptable password in a real deployment; `mutation_test.py`'s mutants depend on the constant's *form*, not its value, so a rename is safe.

### SEC-10: The `--log` path is opened for append wherever the caller points it

- **Severity:** Low
- **CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- **Location:** `UserAuthentication.java:950`, `UserAuthentication.java:1065-1067`

**Vulnerable code:**

```java
// UserAuthentication.java:950
            Path logFile = pathArgument(args, "--log", "auth-demo.log");
```

```java
// UserAuthentication.java:1065-1067
    private static Path pathArgument(String[] args, String name, String fallback) {
        return Path.of(argument(args, name, fallback));
    }
```

**Why it is a problem:** `--log` becomes a `Path` with no containment, no base directory and no check on what already lives at the destination, and `FileEventLogger`'s constructor then creates any missing parent (`377`-`379`) and opens the file `CREATE | WRITE | APPEND` (`380`-`381`). Any launcher — or any wrapper script, CI job, or UI that forwards user-controlled flags — can therefore (a) write outside the intended directory, including absolute paths such as `--log /etc/cron.d/x` or `--log ~/.ssh/authorized_keys`, where a run of authentication events appends attacker-influenced, partially attacker-chosen lines as whatever user the JVM runs as; (b) create arbitrary directory trees via `createDirectories`, which is a disk-exhaustion and clutter vector on its own; and (c) redirect the audit trail to a location the operator will not look at, or to a FIFO/device, which is log *suppression* by configuration rather than by tampering. The username and remote-address fields are sanitised to printable ASCII without `|` (`645`-`659`), so classic content injection into those fields is closed (see §6) — but sanitisation does not restrict *where* the bytes go, and the `~`/`.`-capped field content is still attacker-visible in an arbitrary file. Severity is Low only because exploiting it requires the ability to set process arguments, which usually already implies substantial control of the host.

**Fix:** Resolve against an allowlisted base directory, reject anything that escapes it, and refuse non-regular destinations:

```java
// UserAuthentication.java:1065-1067 (corrected)
    private static Path pathArgument(String[] args, String name, String fallback) {
        Path base = Path.of(System.getProperty("auth.log.dir", "."))
            .toAbsolutePath().normalize();
        Path requested = base.resolve(argument(args, name, fallback)).normalize();
        if (!requested.startsWith(base)) {
            throw new IllegalArgumentException(name + " must stay inside " + base);
        }
        if (Files.isSymbolicLink(requested)
            || (Files.exists(requested, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(requested, java.nio.file.LinkOption.NOFOLLOW_LINKS))) {
            throw new IllegalArgumentException(name + " must be a regular file: " + requested);
        }
        return requested;
    }
```

`Path.resolve` returns the argument unchanged when it is absolute, so the `startsWith` test after `normalize()` is what actually does the containment; apply it to every CLI-supplied path, keep `auth.log.dir` owned by the service user with mode `0700` (SEC-04), and prefer a fixed filename chosen by the program over a caller-chosen one so `--log` only selects a rotation suffix.

### SEC-11: The KDF policy has a 1 000-round floor and no target cost

- **Severity:** Low
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `UserAuthentication.java:139-141`, `UserAuthentication.java:675-677`

**Vulnerable code:**

```java
// UserAuthentication.java:139-141
            if (iterations < 1_000) {
                throw new IllegalArgumentException("iterations must be >= 1000, got " + iterations);
            }
```

```java
// UserAuthentication.java:675-677
            if (iterations < 1_000) {
                throw new IllegalArgumentException("iterations must be >= 1000, got " + iterations);
            }
```

**Why it is a problem:** Both validators — `Config`'s and `PasswordHash`'s — accept anything at or above 1 000 PBKDF2-HMAC-SHA256 rounds, so a record at exactly the floor is "valid policy". At 1 000 rounds an offline attacker on commodity hardware gets on the order of hundreds of millions of guesses per second per GPU against a SHA-256-based KDF, which turns any leaked store of floor-cost records into a bulk-cracking exercise; the same is true of `new Config(1_000, …)` at startup. The default is respectable (`DEFAULT_ITERATIONS = 120_000` at `89`, and the README calls that a reasonable 2026 floor), but the *policy* is not: there is no target cost, no ceiling (SEC-01), and no upgrade path when a record's count is below the current default. Combined with SEC-12 — the service accepts a one-character password — the realistic worst case is a store full of records that are simultaneously cheap to hash and trivial to guess, where only the KDF stands between the dump and the plaintext. Note also that `AuthTest.FAST_ITERATIONS = 2_000` (`AuthTest.java:38`) is only legal *because* the floor is 1 000, so the weak floor is load-bearing for the test suite; that is a reason to add a test seam, not a reason to keep the floor.

**Fix:** Make the policy a band around a target cost, and give tests an explicit seam instead of a weak production floor:

```java
// UserAuthentication.java:89-93 (policy constants)
    public static final int DEFAULT_ITERATIONS = 120_000;
    static final int MIN_ACCEPTABLE_ITERATIONS = 100_000;   // reject below current target
    static final int MAX_ACCEPTABLE_ITERATIONS = 5_000_000;  // see SEC-01
```

```java
// UserAuthentication.java:139-141 and 675-677 (corrected, same guard in both places)
            if (iterations < MIN_ACCEPTABLE_ITERATIONS
                || iterations > MAX_ACCEPTABLE_ITERATIONS) {
                throw new IllegalArgumentException("iterations must be within ["
                    + MIN_ACCEPTABLE_ITERATIONS + ", " + MAX_ACCEPTABLE_ITERATIONS + "], got "
                    + iterations);
            }
```

Add a `needsRehash()` predicate (`stored.iterations() < config.iterations`) and re-derive-and-replace on successful login so records migrate upward as the target cost rises — that is what makes raising `MIN_ACCEPTABLE_ITERATIONS` safe over time. For the suite, pass a test-only cost through a package-private `Config` factory (or a `testing.allowCheapKdf` property consulted only by `AuthTest`) so the production floor stays at the target while the tests keep running in seconds; do not weaken the shipped validator for their convenience.

### SEC-12: No password-strength policy at registration

- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `UserAuthentication.java:445-448`, `UserAuthentication.java:623-641`

**Vulnerable code:**

```java
// UserAuthentication.java:445-448
        if (!isHashablePassword(password)) {
            throw new IllegalArgumentException("password is empty, too long, ends with NUL or "
                + "contains an unpaired surrogate");
        }
```

```java
// UserAuthentication.java:623-626
    static boolean isHashablePassword(char[] password) {
        if (password == null || password.length == 0 || password.length > PASSWORD_MAX) {
            return false;
        }
```

**Why it is a problem:** `isHashablePassword` is a *form* guard, not a strength guard, and it is the only password check on the registration path: it rejects null, empty, longer than `PASSWORD_MAX` (1 024), a trailing NUL and unpaired surrogates, so `x` and `password` pass. There is no minimum length, no deny-list, no breach-list check, and no composition or entropy requirement anywhere in the file, and the same absence applies to whatever change-password path a caller builds on top of `register()`. The strong KDF and lockout therefore protect accounts only to the depth of the secrets users actually chose; `dave` in `main` uses `hunter2-hunter2` (`960`) precisely because nothing stops it. Against a store that leaks, or against an attacker who skips the store and aims the online endpoint at one known account, a short dictionary password is guessable well inside the per-account lockout budget — and SEC-07 means the online path has no source-level limit to slow it either. This is a Low-severity finding only because the component is a demo with no user-facing signup; the missing control becomes Medium the moment it is deployed.

**Fix:** Add an explicit strength policy next to the form guard, evaluated on `char[]` so it does not recreate SEC-03's `String` problem:

```java
// UserAuthentication.java:445-448 (corrected)
        if (!isHashablePassword(password)) {
            throw new IllegalArgumentException("password is empty, too long, ends with NUL or "
                + "contains an unpaired surrogate");
        }
        requireAcceptablePassword(password);
```

```java
    // New helper next to isHashablePassword (~623-641).
    private static final int PASSWORD_MIN_CODEPOINTS = 14;

    static void requireAcceptablePassword(char[] password) {
        int codePoints = 0;
        for (int i = 0; i < password.length; i++, codePoints++) {
            if (Character.isHighSurrogate(password[i]) && i + 1 < password.length
                && Character.isLowSurrogate(password[i + 1])) {
                i++;                                   // count a surrogate pair as one character
            }
        }
        if (codePoints < PASSWORD_MIN_CODEPOINTS) {
            throw new IllegalArgumentException("password must be at least "
                + PASSWORD_MIN_CODEPOINTS + " characters");
        }
        if (KnownBreachedPasswords.contains(password)) {   // char[]-based, or compare hashes
            throw new IllegalArgumentException("password is in a known-breached list");
        }
    }
```

Prefer length over composition rules, and a breach deny-list (local top-N copy, or an HIBP k-anonymity range query) over arbitrary character-class mandates. Evaluate on the `char[]` and zeroize any copy the deny-list needs (`MessageDigest.isEqual` against pre-hashed candidates avoids materialising candidate strings at all) so the fix does not reopen SEC-03. Apply the same policy to every future credential-change path, never log the password or a hash of the rejected one, and surface `PASSWORD_MIN_CODEPOINTS` in the client-facing error so the rule is discoverable rather than guessable.

## 6. Verified Controls and Checks With No Finding

- **Constant-time key comparison.** `PasswordHash.matches()` (`755`-`757`) derives with the record's own parameters and compares with `MessageDigest.isEqual`, which is length- and content-independent, so the key comparison is not a byte-by-byte oracle. The one caveat is test-coverage rather than code: the mutant `non-constant-time-key-compare` replaced it with `Arrays.equals` and **survived** all 305 checks (`mut.log:18`), i.e. nothing in `AuthTest.java` would catch that regression; ditto `username-guard-semantic-noop` (`mut.log:1`), which survives only because `normalizeUsername` re-validates after normalising. Totals: 31 mutants, 29 killed, 2 survived, 0 harness problems (`mut.log:33`-`35`).
- **Unknown-user work equalisation.** An unknown account is hashed against a fixed `equalWorkHash` (`117`, initialised at `99`-`100`) so every admitted attempt pays exactly one PBKDF2 run (`474`-`478`), removing the "responds faster ⇒ no such user" signal; the refusal branches at `480`-`491` all sit after the derivation. The mutant `equal-work-charge-removed` was killed by the ratio assertion "unknown user costs comparable work (ratio 0.00, want 0.6-1.7)" (`mut.log:2`).
- **Log injection is closed.** `sanitizeField` (`645`-`659`) keeps only printable ASCII, maps anything else (including CR, LF and `|`) to `.`, caps the field at 64 characters and marks truncation with `~`. It is applied to every string field in the `Event` constructor — username `269`, remote address `272`, detail `275` — and to the raw username inside `refuse()` (`568`-`570`), which is the one place unvalidated input can reach a record (`INVALID_INPUT` deliberately carries the sanitised form). `main` demonstrates the attack is defused with `authenticate("mallory\r\n|event=LOGIN_SUCCESS|user=admin", …)` at `983`-`984`, and both `log-sanitizer-disabled` and `log-delimiter-allowed` were killed (`mut.log:28`-`29`).
- **Stored-record integrity.** `PasswordHash.parse()` (`701`-`718`) fixes the prefix, checks arity after `split("\\$")`, parses the count inside a `try` that converts `NumberFormatException` into rejection, and passes both byte fields through `strictBase64` (`720`-`734`), which requires canonical, non-malleable base64 and re-encodes before storing — so a record cannot be quietly re-normalised into an equivalent-but-different form, and a corrupt record yields a null `PasswordHash` handled explicitly rather than a partial one. Killed mutants confirm each branch: `base64-canonical-check-off` (`mut.log:14`), `iterations-floor-off`, `salt-length-floor-off`, `key-length-floor-off` (`mut.log:15`-`17`), `corrupt-record-guard-off` (`mut.log:25`).
- **Defensive copies and redaction.** The constructor copies the salt and key in (`685`-`686`), `salt()` copies out (`746`-`748`), `encode()` emits only the salt and key material needed to verify and never into a loggable string, and `PasswordHash.toString()` (`774`-`777`) plus `Result.toString()` are redacted, so neither the derived key nor the password can ride into a log line via string interpolation. Killed: `ctor-does-not-clone-salt`, `ctor-does-not-clone-key`, `salt-accessor-does-not-clone` (`mut.log:11`-`13`).
- **Password-form collision guard.** `isHashablePassword` (`623`-`641`) rejects a trailing NUL (which `PBEKeySpec` would silently truncate, making `"pw\0"` equivalent to `"pw"`), lone surrogates (which `PBEKeySpec` would lossily re-encode), the empty password and the over-length password, rather than quietly altering the secret; `derive()` clears the `PBEKeySpec` copy in a `finally` (`769`-`771`). Killed: `trailing-nul-guard-off`, `surrogate-pair-guard-off`, `lone-low-surrogate-guard-off`, `password-max-length-off`, `empty-password-guard-off` (`mut.log:6`-`10`). (The *lifetime* of the caller's buffers is SEC-03; the *strength* policy is SEC-12.)
- **Concurrency.** Registration is a single `putIfAbsent`-style check-and-set (`805`), not a check-then-act, so two concurrent signups cannot both win; per-account state changes are `synchronized` on the `Account` (`recordFailure` `892`, `recordSuccess` `913`, `forceUnlock` `922`) with lock state read through `lockStateAt(now)` rather than cached, and the store is a `ConcurrentHashMap`. The lockout arithmetic survived mutation testing completely: `lock-threshold-off-by-one`, `success-does-not-clear-failures`, `failure-window-comparison-reversed`, `lock-expiry-comparison-reversed`, `lock-not-set-on-trip` all killed (`mut.log:19`-`23`).
- **Enumeration resistance on the login path.** `Outcome` collapses unknown-user and bad-password into `INVALID_CREDENTIALS` (`56`-`64`), the user-visible text is identical (`"Invalid username or password."`), and `Reason` is kept as audit-only data with an explicit warning against rendering it; killed mutants `unknown-user-reason-merged` and `user-message-leaks-unknown-user` (`mut.log:26`-`27`) show the property is actually tested. `main` also asserts the case-folded duplicate `'  ALICE  '` and empty-password cases at `981`-`982`. The remaining enumeration leaks are the ones reported as SEC-06 and SEC-08, not this path.
- **Salt generation.** Every record gets a fresh 16-byte salt from `SecureRandom` (`689`-`693`, `SALT_BYTES = 16` at `90`), stored alongside the record and never reused or derived from the username or time; the KDF is `PBKDF2WithHmacSHA256` with an explicit iteration count (`92`), and there is no `MD5`/`SHA-1` KDF, no `DES`/`ECB` primitive and no `ThreadLocalRandom`/`Random` anywhere in the hashing path.
- **Audited security-relevant transitions.** `ACCOUNT_REGISTERED` including refused duplicates (`451`, with `registration-not-logged` killed: "the refused duplicate is logged as well", `mut.log:30`), every refusal through `refuse()` (`571`), `ACCOUNT_LOCKED_OUT` when the threshold trips (`515`), `ACCOUNT_UNLOCKED` both on lock expiry (`508`) and on operator unlock (`554`-`555`), `LOGIN_FAILURE` (`521`), and `LOGIN_SUCCESS` (`529`). The single unaudited transition is `setEnabled` — reported as SEC-08.
- **Username normalisation.** `normalizeUsername` (`594`-`612`) trims, applies Unicode NFKC, case-folds, and then re-validates the *normalised* result against `USERNAME_PATTERN` and the 3-64 length bounds, so a homoglyph or compatibility character cannot create a second account that displays identically to an existing one, and an over-long normalisation cannot slip through. Killed: `username-not-lowercased`, `username-min-length-off`, `username-trim-end-off` (`mut.log:3`-`5`).
- **No injection or deserialisation sink exists in this file.** Searches for `Runtime.getRuntime`, `ProcessBuilder`, `Statement`/`ResultSet`/`Connection`, `ObjectInputStream`, `javax.script`, `ScriptEngine`, `HttpURLConnection`, `Socket`, `URL(` and reflection-based dispatch found no matches; the only `getInstance` call is the intended `SecretKeyFactory.getInstance(KDF)` at `765`. There is no SQL, no shell, no outbound network call and no untrusted-object deserialisation, so the CWE-89 / CWE-78 / CWE-502 families are not reachable here.
- **Test and mutation harness hygiene.** `AuthTest.java` writes only under `Files.createTempFile` (e.g. `542`, `570`, `811`, `839`) and deletes the files afterwards, uses an in-memory store for the rest, and has no production sink; `RecordingLog` (`989`) captures events instead of writing them. `mutation_test.py` copies the sources into `tempfile.mkdtemp()`, invokes `javac`/`java` through `subprocess.run([...])` with list arguments and no `shell=True`, never interpolates a filename into a shell string, mutates only its own copies, and cleans up with `shutil.rmtree(..., ignore_errors=True)`. `BATTERY_EXIT=0` with 0 harness problems (`mut.log:36`).
- **Documentation matches behaviour.** `README.md` describes the equal-work design, the PBKDF2 cost choice, the per-account-only lockout, and explicitly names front-end/source rate limiting as the complementary control — which is the gap reported as SEC-07, so that finding is a documented-but-real limitation rather than a false claim in the docs.
- **Cosmetic note, not a finding:** `Event` stamps its own `Instant.now()` (`267`) and `Account.createdAt` uses `Instant.now()` (`835`) instead of `config.clock`, while the lockout logic correctly uses the injected `Instant now` (`892`-`904`). Deterministic tests therefore cannot move event timestamps, but no security decision depends on the two `Instant.now()` calls, so this is a testability wart, not a vulnerability.

