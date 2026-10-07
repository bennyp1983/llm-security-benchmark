# Security Review: Internal Employee Portal Authentication (com.acme.portal)

## 1. Executive Summary

The component is a dependency-free Java 17 console authentication verifier for an internal employee portal. Employees enter a username and password at an attached terminal; credentials are verified against salted PBKDF2-HMAC-SHA-256 verifiers in a fixed-path, mode-`0600` file store. Failed attempts are limited by a per-source sliding-window block and per-account progressive backoff, and an administrator-only `provision` command creates credentials after length, blocklist, and username-equality checks.

The code is unusually well hardened. The password-storage crypto (PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte `SecureRandom` salts, constant-time comparison), fail-closed input validation, uniform-work failure handling against user enumeration, atomic file writes with symlink/permission checks, and serialized check-then-grant all pass the applicable specialised checklists. **No Critical, High, or Medium vulnerabilities were found.** Two Low findings remain: (SEC-01) authentication outcomes and internal exception details are not recorded anywhere, leaving no audit trail (the rate-limit state is also purely volatile memory); and (SEC-02) the compromised-password blocklist matches only the exact byte sequence of the password, so case variants of a blocked password (e.g. `Correct Horse Battery Staple` when `correct horse battery staple` is listed) pass provisioning. Both are defense-in-depth gaps rather than exploitable authentication bypasses.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `src/main/java/com/acme/portal/Main.java` | CLI entrypoint (`login` / `provision`), console I/O, audit decision printing | Accepts exactly one literal argument; requires a real `System.console()`; fixed absolute store path; zeroizes password/hash buffers in `finally`; generic user-facing errors; PBKDF2 length rules on provision; constant-time password/confirmation and password/username comparison; reloads the store under an exclusive file lock on every login attempt |
| `src/main/java/com/acme/portal/Authenticator.java` | Core verify-and-decide flow | Username canonicalization (lowercase `Locale.ROOT`, regex allowlist, 3–64 chars); password length bounds (1–128); dummy-record PBKDF2 work for unknown/invalid users to equalize timing and deny uniformly; consults/updates `LoginGuard`; `synchronized` to make check-then-grant atomic |
| `src/main/java/com/acme/portal/LoginGuard.java` | In-memory brute-force restriction | Sliding-window per-source failure limit (5/5 min → 15 min block) using the monotonic clock; per-account exponential backoff capped at 2 s (no hard account lockout); account keys stored as salted SHA-256, bounded at 10,000 entries with fail-closed exhaustion handling |
| `src/main/java/com/acme/portal/CredentialStore.java` | Load/write the credential verifier file; inter-process update lock | Strict allowlist parsing (header, 3 fields, username regex, strict Base64, fixed salt/hash lengths, duplicate rejection, size/line bounds); requires regular non-symlink `0600` file and non world/group-writable non-symlink parent; atomic temp-file-plus-rename writes; `FileChannel` update lock with symlink/permission validation |
| `src/main/java/com/acme/portal/PasswordHasher.java` | Password hashing and verification | PBKDF2WithHmacSHA256, 600,000 iterations, 128-bit `SecureRandom` salt, 256-bit output; `MessageDigest.isEqual` constant-time compare; clears `PBEKeySpec` and candidate digest |
| `src/main/java/com/acme/portal/PasswordBlocklist.java` | Loads/queries a file of SHA-256 hashes of blocked weak passwords (provisioning only) | Fixed-path, regular non-symlink `0600` file, 10k–1M unique 64-hex-char lines, size bound; UTF-8 SHA-256 of candidate compared with constant-time `equals`; fails closed on any anomaly |
| `src/test/java/com/acme/portal/SecurityTests.java` | Self-contained security regression tests | Exercises valid/invalid login, unknown user, invalid username, oversized password, source block, file mode enforcement, malformed-store rejection |
| `build.sh` | Build/test script | `umask 077`, `javac -Xlint:all -Werror`, no third-party dependencies, no network access |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: router — read every source file, built the behaviour/keyword list (password storage/KDF, authentication & enumeration, rate limiting/lockout, file path/permission validation, secrets in source, deserialization), and dispatched to the specialised skills below.
- `performing-cryptographic-audit-of-application`: applied to `PasswordHasher.java`, `PasswordBlocklist.java`, and `LoginGuard.java` — deprecated algorithms, KDF parameters, salt/entropy source, constant-time comparison, hardcoded secrets, secret-material clearing.
- `implementing-api-rate-limiting-and-throttling`: applied to `LoginGuard.java` and the `Authenticator.authenticate` decision flow — sliding-window vs fixed-window counting, per-source and per-account separation, backoff vs attacker-triggered hard lockout, bounded state, monotonic timing, fail-closed exhaustion.
- `testing-api-authentication-weaknesses`: applied to `Authenticator.java` and `Main.java` (knowledge applied to a console flow rather than HTTP) — fail-closed verification against server-side state, weak password policy, credential-stuffing resistance, enumeration/timing uniformity, secrets in logs or arguments, absence of caller-supplied identifiers.
- `performing-directory-traversal-testing`: applied to `CredentialStore.java` path handling (knowledge only) — the store path is a fixed absolute constant (never a caller parameter), validated normalized/non-symlink/permission-correct, with `NOFOLLOW_LINKS` opens; no traversal surface exists.
- `implementing-secret-scanning-with-gitleaks`: applied across the whole repository (knowledge only) — search for hardcoded usable credentials; the only embedded string secret is the inert `DUMMY_PASSWORD` placeholder (CWE-798 checked, see section 6).
- `exploiting-insecure-deserialization`: applied to `CredentialStore.java` / `PasswordBlocklist.java` parsing — confirmed no Java native deserialization (`ObjectInputStream`/`readObject`/`XMLDecoder` absent); parsing is strict allowlist string decoding.
- General OWASP Top 10 / CWE knowledge (no matching library skill): audit logging of authentication events (CWE-778, SEC-01), weak-password blocklist coverage (CWE-521, SEC-02), TOCTOU analysis of the lock/temp-file/atomic-rename sequences, and in-memory state-exhaustion review.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | No audit trail: authentication outcomes unlogged and internal exceptions swallowed without details | Low | CWE-778 | `src/main/java/com/acme/portal/Main.java:41-47` |
| SEC-02 | Compromised-password blocklist is exact-match only, so case variants of blocked passwords pass provisioning | Low | CWE-521 | `src/main/java/com/acme/portal/PasswordBlocklist.java:60-72` |

No Critical, High, or Medium findings were identified.

## 5. Detailed Findings

### SEC-01: No audit trail: authentication outcomes unlogged and internal exceptions swallowed without details

- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/com/acme/portal/Main.java:41-47` (related: `src/main/java/com/acme/portal/LoginGuard.java:21-24`)

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/Main.java:41-47
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.log(Level.WARNING, "Authentication operation interrupted");
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            // No paths, usernames, credentials, or exception text are emitted.
            LOG.log(Level.SEVERE, "Authentication operation failed internally");
        }
```

**Why it is a problem:** The user-facing output is correctly generic, but the detail never reaches any log either: the catch-all logs a fixed string and discards the exception object `e` entirely, and successful/failed authentication decisions are never logged at all (they are only printed to the console and then the process state is whatever `LoginGuard` kept in volatile memory — `sourceFailures`, `accountFailures`, and `sourceBlockedUntil` are plain in-memory fields with no persistence). For an authentication component this means a brute-force or spray campaign, a store-corruption fail-closed event, or an unexpected internal error leaves no forensic trace once the console output scrolls away or the supervised process restarts. The project's own Rule 6 ("Report errors to users in generic terms; details go to the log only") intends details to land in the server-side log; here they land nowhere. This is a detection/forensics gap, not an authentication bypass, hence Low.

**Fix:** Keep user-facing messages generic, but pass the exception to the logger (the `java.util.logging` output is an operator channel, never the console prompt) and record an audit event per authentication outcome. Message strings already contain no usernames, paths, or credentials, so nothing sensitive leaks:

```java
// Main.java — login(): record the outcome (server-side log only)
            boolean allowed = /* existing decision */ false;
            LOG.log(allowed ? Level.INFO : Level.WARNING,
                    "Authentication {0} for username ''{1}''",
                    new Object[] {allowed ? "succeeded" : "denied", username});

// Main.java — run(): preserve internal failure details for operators
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.log(Level.WARNING, "Authentication operation interrupted", e);
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            // Details go to the operator log only; the console still gets the generic message.
            LOG.log(Level.SEVERE, "Authentication operation failed internally", e);
        }
```

Additionally, consider persisting (or shipping to a central log) the failed-attempt counters, since the README itself notes a process restart resets all throttling state.

### SEC-02: Compromised-password blocklist is exact-match only, so case variants of blocked passwords pass provisioning

- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `src/main/java/com/acme/portal/PasswordBlocklist.java:60-72` (contract at line 20; call site `src/main/java/com/acme/portal/Main.java:105`)

**Vulnerable code:**
```java
// src/main/java/com/acme/portal/PasswordBlocklist.java:20
/** A server-managed set of lowercase, hex-encoded SHA-256 hashes of blocked passwords. */
```
```java
// src/main/java/com/acme/portal/PasswordBlocklist.java:60-72
    boolean contains(char[] password) throws NoSuchAlgorithmException, CharacterCodingException {
        ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(password));
        byte[] digest = null;
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(encoded.asReadOnlyBuffer());
            digest = sha256.digest();
            return hashes.contains(new HashValue(digest, false));
        } finally {
            if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
            if (digest != null) Arrays.fill(digest, (byte) 0);
        }
    }
```

**Why it is a problem:** The blocklist file is defined (line 20, and the README) as hashes of *lowercase* blocked passwords, but `contains` hashes the password exactly as typed. A user provisioning `Correct Horse Battery Staple`, `CORRECT HORSE BATTERY STAPLE`, or `correct horse battery stapLe` produces a SHA-256 digest that is not in the set, so a known-compromised or dictionary passphrase passes the weak-password check purely by changing capitalization. Case substitution is the first mutation attackers and password-guessing tools try, so the control is materially weaker than intended. Severity is Low because the 15-character minimum and the rest of the design already stop the short weak passwords that dominate blocklists; long dictionary passphrases are exactly the class the blocklist exists for, which keeps this out of "informational".

**Fix:** Query the blocklist for the as-typed digest *and* the lowercase digest (matching the file's documented lowercase semantics), clearing the temporary array:

```java
// PasswordBlocklist.java
    boolean contains(char[] password) throws NoSuchAlgorithmException, CharacterCodingException {
        if (containsExact(password)) {
            return true;
        }
        char[] lowered = new char[password.length];
        for (int i = 0; i < password.length; i++) {
            lowered[i] = Character.toLowerCase(password[i]);
        }
        try {
            return containsExact(lowered);
        } finally {
            java.util.Arrays.fill(lowered, '\0');
        }
    }

    private boolean containsExact(char[] password)
            throws NoSuchAlgorithmException, CharacterCodingException {
        ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(password));
        byte[] digest = null;
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(encoded.asReadOnlyBuffer());
            digest = sha256.digest();
            return hashes.contains(new HashValue(digest, false));
        } finally {
            if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
            if (digest != null) Arrays.fill(digest, (byte) 0);
        }
    }
```

(For full Unicode case-folding robustness the organization could additionally ship fold-normalized entries in the list; the per-`char` lowercasing above already covers the ASCII case-variant class that dominates real bypasses.)

## 6. Verified Controls and Checks With No Finding

- **Password storage crypto (`performing-cryptographic-audit-of-application`)**: `PasswordHasher.java:11-41` — PBKDF2WithHmacSHA256 at 600,000 iterations / 256-bit output matches the OWASP Password Storage Cheat Sheet current parameter; 16-byte salts from `SecureRandom` (`PasswordHasher.java:14,18-22`); no MD5/SHA-1/DES/RC4/ECB anywhere (the only digests used are SHA-256 family, used appropriately); verification uses constant-time `MessageDigest.isEqual` (`PasswordHasher.java:38`).
- **Secret hygiene (`implementing-secret-scanning-with-gitleaks` knowledge)**: no usable credentials, keys, or API tokens in any file (`grep` for `password=`/`secret`/`api_key`/`token` returned only the `SecretKeyFactory` import and the inert `Authenticator.java:9` `DUMMY_PASSWORD = "fixed-work-placeholder"`, which can never grant access: the dummy record is never persisted or looked up, and `Authenticator.java:42-43` requires `actual != null && passwordValid` before `allowed`; `PasswordHasher.java:30` (`spec.clearPassword()`), `PasswordHasher.java:40`, `Main.java` `finally` blocks, and `PasswordBlocklist.java:69-70` zeroize password-derived buffers). Passwords are read only via `Console.readPassword` — never argv, environment, or piped stdin (a real console is required, `Main.java:27-28`).
- **Hardcoded / untrusted paths (`performing-directory-traversal-testing` knowledge)**: store and blocklist paths are compile-time constants (`Main.java:14`, `PasswordBlocklist.java:22`); no caller- or environment-supplied path exists; `CredentialStore.validateParent` (`CredentialStore.java:207-220`) requires an absolute, normalized path with a non-symlink directory that is not group/world-writable; symlink and mode checks use `NOFOLLOW_LINKS` consistently; the update lock and store are opened with `LinkOption.NOFOLLOW_LINKS` (`CredentialStore.java:78-79`), so a post-check symlink swap fails the open (TOCTOU closed by the directory-permission precondition); writes go to a private temp file created mode `0600` and are applied with `ATOMIC_MOVE` (`CredentialStore.java:172-198`).
- **Untrusted file parsing (general knowledge; malformed-input review)**: store parsing is allowlist-based and fully bounded — fixed header, ≤2 MB/10,000 users, ≤256-char lines, exactly three fields, strict Base64, exact salt/hash lengths, regex-validated usernames, duplicate rejection, empty-store rejection (`CredentialStore.java:112-155`); blocklist parsing likewise bounds size, entry count, exact 64-hex-char lines, and uniqueness (`PasswordBlocklist.java:35-57`). Any anomaly throws and the whole file is rejected (fail closed).
- **No insecure deserialization (`exploiting-insecure-deserialization`)**: `grep` for `ObjectInputStream`/`readObject`/`XMLDecoder`/`Serializable` across `src/` returned nothing; all external data is parsed as strict ASCII strings, never deserialized.
- **Authentication flow / enumeration resistance (`testing-api-authentication-weaknesses`)**: every failure path (invalid username format, unknown account, wrong password, oversized password, source block) returns the identical `Access denied.` and performs the same PBKDF2 work via the salted dummy record (`Authenticator.java:38-41`, `Main.java:76-77`); delay is keyed to the attempted name's own counter, which is tracked for real and nonexistent accounts alike (`LoginGuard.java:41-55`), so timing does not reveal account existence; no tokens, cookies, or session identifiers are issued or accepted; no username or password appears in any log or error message (`Main.java:44-46,74`).
- **Rate limiting / lockout design (`implementing-api-rate-limiting-and-throttling`)**: source failures use a true sliding window over the JVM monotonic clock (immune to wall-clock changes; subtraction-based comparisons are also nanoTime-wraparound safe) — `LoginGuard.java:31-38,63-67`; per-account backoff is progressive (125 ms→2 s cap) rather than an attacker-triggerable permanent lockout (`LoginGuard.java:35-38`); account state is bounded (10,000 keys) with fail-closed exhaustion handling (`LoginGuard.java:50-54`); success clears the account counter (`LoginGuard.java:58-60`). The in-memory, process-local design is explicitly scoped by the README to one supervised instance per console (documented residual risk, matching the skill's "in-memory counters only for single-instance deployments" guidance — deployment constraint, not a code defect).
- **Check-then-act atomicity (general knowledge / concurrency review)**: guard check → hash → decision → counter update are serialized under `Authenticator.authenticate`'s monitor (`Authenticator.java:24`); every login decision reloads the store while holding the exclusive OS `FileLock` shared with provisioning (`Main.java:67-71`, `CredentialStore.java:63-109`), so a grant cannot race a concurrent password change; provisioning holds the same lock across load-modify-atomic-write (`Main.java:110-117`); the lock is validated (`requireHeld`) before use and released in `close()`; `CredentialStore` is immutable and `Record` deep-copies its byte arrays.
- **DoS bounding (general knowledge)**: password length capped at 128 before any hashing (`Authenticator.java:29-31`); store, blocklist, line, record-count, and in-memory-key bounds as above; the oversized-password path is covered by `SecurityTests.java`.
- **Provisioning policy**: 15–128 character minimum (`Main.java:98-102`), constant-time confirmation comparison (`Main.java:132-142`), username-equality rejection (`Main.java:144-154`), blocklist enforcement fails closed on a missing/undersized/unsafe list (`PasswordBlocklist.java:35-58`).
- **Residual design risks (documented in README, out of code scope)**: throttle counters reset on process restart (README requires a supervised single instance with start/stop restricted); a sustained stream of ≥5 failures per 5-minute window can keep the source block extended indefinitely (inherent to source blocking; the "source" here is the physical local console, and the README forbids network exposure and recommends an IdP for anything remote).
