# Security Review: EmployeePortalAuth (Java employee portal console)

## 1. Executive Summary

This folder contains a single-file Java credential portal (`EmployeePortalAuth.java`, 1,384 lines) plus a 1,016-line self-checking test harness (`EmployeePortalAuthTest.java`, 295 assertions) and a `README.md` that documents the design and its limits. The program is a terminal application: it stores employee accounts in a flat text file (`portal-records.txt`, `username|salt|hash|iterations|status`), hashes passwords with PBKDF2-HMAC-SHA256, freezes an account for 15 minutes after 5 wrong passwords, issues `SecureRandom` session tokens with a 30-minute TTL, and offers a handful of operator commands at the prompt.

The cryptography itself is careful — per-account 16-byte salts, a constant-time digest comparison, strict canonical base64, and an deliberate "burn one derivation" so that an unknown username costs the same as a known one. The weaknesses are around it, not inside it:

- **The password hash can be made 200–600× cheaper by anyone who can start the process.** `PasswordHash.MIN_ITERATIONS` is `1_000` (line 486) and both `--iterations` (line 198) and `-Dportal.pbkdf2.iterations` (line 181) accept anything down to that floor, while the 210,000 default is itself below current OWASP guidance for PBKDF2-HMAC-SHA256 (SEC-01).
- **The operator commands are unauthenticated.** `add`, `status`, `disable`, `enable` and `unlock` (lines 1195-1211) run straight from the prompt with no identity check, so anyone at the keyboard can mint an account, switch staff off, or clear a brute-force lockout — and the audit line blames a "by operator" that is never identified (SEC-02).
- **Three paths leak whether a username exists** — the LOCKED and UNAVAILABLE sign-in replies and `status` — undoing the identical-wording work the code otherwise does well (SEC-03).

The remaining findings are the in-memory-only lockout (restart clears every freeze; lockout is also a denial-of-service against a known username), an unbounded session map, permission handling that silently gives up on non-POSIX filesystems, audit output that goes only to stdout and leaks password shape plus a token prefix, a residual timing oracle for cheap legacy records, a thin creation policy, exception text echoed to the terminal, and an unlocked whole-file store rewrite.

Nothing here is remotely exploitable as written — this is a single-user console tool, and `README.md` honestly admits several of these limits. They are reported because the code is written as a reusable reference implementation, and each one becomes a real vulnerability the moment it is lifted behind a network boundary.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `EmployeePortalAuth.java` | The portal: flat-file credential store, PBKDF2 password hashing, per-account lockout, session-token registry, audit logger, and terminal UI with operator commands. | Hashes and verifies every password; mints and validates session tokens; decides grant/deny/lock answers to sign-in attempts; writes credentials to disk and sets their file mode; performs administrative actions (create, disable, enable, unlock, inspect) at the prompt; emits audit lines. |
| `EmployeePortalAuthTest.java` | 295-check self-test harness run via `main`; builds throwaway stores in temp directories and drives the service and console directly. | Runs the KDF at `ITERS = 1_000` (the cheap floor the production CLI also accepts); asserts store permissions are `rw-------`, refusal wordings are identical, no password is echoed or written to disk, and the login timing spread stays within 2×. Test-only, no production attack surface. |
| `README.md` | Design notes: file format, CLI flags, what each component guarantees. | Not executed, but it is the security contract readers trust — it claims refusals are worded identically, that restart clears freezes, that the store has no locking, and that nothing is audited to a durable place. Findings SEC-03, SEC-04, SEC-07 and SEC-11 are checked against these claims. |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: the router — drove the workflow (establish what the code does first, then select specialised skills, then audit) and the per-file understanding recorded in section 2 for both `.java` files.
- `performing-cryptographic-audit-of-application`: applied to `PasswordHash` (`EmployeePortalAuth.java:481-560`) — salt generation and length, PBKDF2 iteration bounds, digest comparison, canonical-base64 decoding, `SecureRandom` use, and the `PBEKeySpec` character-fidelity problem that `PasswordRules.structuralProblem` guards.
- `testing-api-authentication-weaknesses`: applied to `PortalAuthService.login` (`:944-1000`), `LoginAttemptTracker` (`:694-752`) and `SessionRegistry` (`:776-826`) — token entropy and TTL, lockout enforcement and persistence, password policy, and enumeration resistance.
- `testing-for-broken-access-control`: applied to `PortalConsole.handleLine` (`:1160-1213`) — which verbs need an identity, and the fact that holding a valid session grants no privilege over an anonymous keyboard.
- `testing-for-sensitive-data-exposure`: applied to `FileRecordStore.flush`/`restrictToOwner` (`:442-472`), `AuditLog.record` (`:1112-1114`) and the console's printing paths — what lands on disk and on stdout, file modes, and whether secrets are wiped from `char[]`.
- `implementing-aes-encryption-for-data-at-rest`: applied to the credential store as a whole — the salt/digest/iterations/status record is written in cleartext with no key material or at-rest protection.
- `implementing-secret-scanning-with-gitleaks`: applied as a hardcoded-credential sweep across both files; the only secret-shaped literal is `PROBE_PASSWORD = "portal-timing-probe-passphrase"` (`:907`), a fixed timing probe that authenticates nothing.
- `exploiting-race-condition-vulnerabilities`: applied to `FileRecordStore.put`/`flush` (`:378-386`, `:442-464`) and the `inspect` → `registerFailure` split across two calls in `login` (`:975`, `:987`) — read-whole-file → rewrite-whole-file with no lock.

Behaviours reviewed against general OWASP Top 10 / CWE knowledge because no skill matched: username-enumeration resistance including the deliberate equalising derivation and its residual cost mismatch (CWE-204/CWE-208); terminal escape-sequence injection through usernames that are printed back (CWE-150) — blocked by the `[a-z0-9._-]` whitelist in `UsernameRules`; the durability of in-memory authentication state across restarts (CWE-307); the console command model's absent trust boundary (CWE-306); and audit-log integrity/sink choice (CWE-532).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Password hashing can be weakened to 1,000 iterations by any launcher | High | CWE-916 | `EmployeePortalAuth.java:486` |
| SEC-02 | Administrative commands run without any operator identity | High | CWE-306 | `EmployeePortalAuth.java:1195-1211` |
| SEC-03 | Lock, disable and status replies confirm that a username exists | Medium | CWE-204 | `EmployeePortalAuth.java:1231-1243` |
| SEC-04 | Brute-force lockout lives only in memory and is per-account only | Medium | CWE-307 | `EmployeePortalAuth.java:727-738` |
| SEC-05 | Session registry grows without bound and is never swept | Medium | CWE-400 | `EmployeePortalAuth.java:792-813` |
| SEC-06 | Credential store permissions are applied best-effort and never verified | Medium | CWE-276 | `EmployeePortalAuth.java:466-471` |
| SEC-07 | Audit log goes only to stdout and records password shape and a token prefix | Low | CWE-532 | `EmployeePortalAuth.java:1112-1114` |
| SEC-08 | Legacy cheap records answer faster than unknown usernames | Low | CWE-208 | `EmployeePortalAuth.java:1003-1004` |
| SEC-09 | Password creation policy is a 10-character minimum plus letter-and-digit | Low | CWE-521 | `EmployeePortalAuth.java:655-673` |
| SEC-10 | Absolute store path and raw I/O exception text printed to the terminal | Low | CWE-209 | `EmployeePortalAuth.java:80-87` |
| SEC-11 | Whole store rewritten from an in-memory copy with no lock | Low | CWE-367 | `EmployeePortalAuth.java:378-386` |

## 5. Detailed Findings

### SEC-01: Password hashing can be weakened to 1,000 iterations by any launcher
- **Severity:** High
- **CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
- **Location:** `EmployeePortalAuth.java:486` (also `:126`, `:181-184`, `:198-202`)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:484-489
    static final int SALT_BYTES = 16;
    static final int HASH_BYTES = 32;
    static final int MIN_ITERATIONS = 1_000;
    static final int MAX_ITERATIONS = 5_000_000;

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
```

**Why it is a problem:** `MIN_ITERATIONS` is the only thing standing between the default cost and an effectively unsalted fast hash, and it is set to 1,000. Both cost knobs are validated against that floor rather than against the policy: `-Dportal.pbkdf2.iterations` at `:181-184` (`iterations = parseInt(costOverride, "portal.pbkdf2.iterations", PasswordHash.MIN_ITERATIONS, PasswordHash.MAX_ITERATIONS);`) and `case "--iterations":` at `:198-202` do exactly the same. A single mistyped or hostile launch flag — `--iterations 1000`, which `README.md` itself suggests for demos — makes every account created under it 210× cheaper to crack than one created under `DEFAULT_ITERATIONS = 210_000` (`:126`), and the store happily records the cheap cost. Nothing later repairs it: `raiseCost` (`:1010`) only ever lifts a record that is below *current* policy, so once policy is read back as 1,000 the cheap records look compliant. The default is also stale — OWASP's current guidance for PBKDF2-HMAC-SHA256 is around 600,000 iterations or more, and PBKDF2 on a stolen store is the realistic threat here because the store is plain text (SEC-06). The cost difference is silent: sign-in succeeds either way, so a downgrade is invisible until the file is cracked.

**Fix:** Make the accepted floor equal today's policy minimum so no launch flag can undercut it, raise the default with it, and require an explicit acknowledgement for anything below the default so a downgrade is a deliberate, visible act.

```java
// PasswordHash: the floor is a policy floor, not a sanity floor.
    static final int SALT_BYTES = 16;
    static final int HASH_BYTES = 32;
    static final int MIN_ITERATIONS = 600_000;
    static final int MAX_ITERATIONS = 5_000_000;

// Config: DEFAULT_ITERATIONS moves with the floor (line 126).
    static final int DEFAULT_ITERATIONS = 600_000;

// Config.parse: a below-default cost must be acknowledged, and one flag cannot both
// acknowledge it and set it silently.
                case "--iterations":
                    int requested = parseInt(nextValue(args, i, option), option,
                            PasswordHash.MIN_ITERATIONS, PasswordHash.MAX_ITERATIONS);
                    if (requested < DEFAULT_ITERATIONS && !allowWeakKdf) {
                        throw new IllegalArgumentException(option + " below " + DEFAULT_ITERATIONS
                                + " requires --allow-weak-kdf");
                    }
                    iterations = requested;
                    i++;
                    break;
```

The test harness needs a cheap KDF; give it a package-private constructor or a dedicated `MIN_ITERATIONS_FOR_TESTS = 1_000` constant that only `EmployeePortalAuthTest` may pass, instead of lowering the production floor for everyone.

### SEC-02: Administrative commands run without any operator identity
- **Severity:** High
- **CWE:** CWE-306: Missing Authentication for Critical Function
- **Location:** `EmployeePortalAuth.java:1195-1211` (also `:1068-1069`, `:1083`)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:1192-1211
            case "logout":
                logout();
                return;
            case "add":
                addAccount(argument);
                return;
            case "status":
                status(argument);
                return;
            case "disable":
                changeStatus(argument, AccountStatus.DISABLED);
                return;
            case "enable":
                changeStatus(argument, AccountStatus.ACTIVE);
                return;
            case "unlock":
                reportOperatorResult(unlockAccount(argument));
                return;
            default:
                signIn(line);
```

**Why it is a problem:** Every verb that changes the authentication system's state is dispatched with no check of who is typing. `add` calls `createAccount`, which hashes a caller-supplied password and writes the record (`:1024-1048`) — that is an authentication-bypass back door for anyone who can reach the prompt, because they now hold a valid credential for a brand-new account. `disable` shuts an employee off, `unlock` clears the brute-force freeze that SEC-04 depends on, and `status` dumps an account's state and failure count. `currentSession` is never consulted on these paths, and nothing else in the program consults it either, so signing in buys no additional authority — the trust boundary that the rest of the code carefully builds around sign-in simply does not exist around administration. The audit trail compounds it: `setStatus` and `unlockAccount` log the detail as `"by operator"` (`:1068-1069`, `:1083`) and `createAccount` logs `"cost ..."` (`:1046`), so a malicious or mistaken change is recorded as if it came from an identified principal and cannot be attributed. `README.md` states the assumption plainly ("Anyone at the keyboard is an operator"), which is a legitimate choice for a demo but makes this the highest-impact gap when the file format or service is reused.

**Fix:** Gate the operator verbs behind an authenticated operator session, and bind the audit line to the identity that produced it.

```java
// PortalConsole: operator verbs require an operator, not a keyboard.
            case "add":
            case "status":
            case "disable":
            case "enable":
            case "unlock":
                requireOperatorThen(command, argument);
                return;
            default:
                signIn(line);

    private void requireOperatorThen(String command, String argument) {
        if (operatorSession == null || sessions.validate(operatorSession.token(), service.now()).isEmpty()) {
            audit.record("operator-refused", "<anonymous>", "unauthenticated " + command);
            out.println("that command needs an operator session.");
            return;
        }
        dispatchOperatorCommand(command, argument);
    }

// PortalAuthService.setStatus: record who did it.
        audit.record("account-" + status.name().toLowerCase(java.util.Locale.ROOT),
                canonicalName.get(), "by " + actor.userName());
```

If a separate operator credential is genuinely out of scope, remove the write verbs from this program and drive the store from a tool that has its own authentication — do not leave the audit trail implying an identified operator.

### SEC-03: Lock, disable and status replies confirm that a username exists
- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `EmployeePortalAuth.java:1231-1243` (also `:1311`, `:1058`, `:1080`)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:1231-1243
                case LOCKED:
                    out.println("Access denied: this account is locked for about "
                            + outcome.lockRemainingMinutes() + " more minute(s).");
                    break;
                case UNAVAILABLE:
                    out.println("Access denied: that account cannot be used right now."
                            + " Ask the portal administrator.");
                    break;
                case DENIED:
                default:
                    // One wording for a wrong name and a wrong password, so typing a name here
                    // cannot be used to find out whether the portal knows it.
                    out.println("Access denied: invalid username or password.");
```

**Why it is a problem:** The `DENIED` branch is deliberately worded so a wrong name and a wrong password are indistinguishable, and `login` backs that up with a real derivation for unknown names (`:959`, `:969`). Two other branches break the property it is protecting. `LOCKED` prints a minute count that only a name present in `LoginAttemptTracker.states` can produce, and `UNAVAILABLE` prints "that account cannot be used right now" only after `login` matched a stored record whose status is `DISABLED` (`:976-978`). So `alice` answering "invalid username or password" while `bob` answers "locked for about 15 more minute(s)" is a positive confirmation that `bob` exists and `alice` does not, obtainable without ever supplying a correct password. That hands an attacker a username list, which is the precondition for both the password spray SEC-04 struggles against and for targeted phishing. The same name-confirms-exists signal is available in one keystroke through the unauthenticated `status` command — `out.println("no account named " + canonicalName.get());` at `:1311`, with the matching strings at `:1058` and `:1080` for `enable`/`disable`/`unlock` — which makes the sign-in-side subtlety academic while SEC-02 stands.

**Fix:** Collapse every non-granted outcome onto the one wording already written for `DENIED`, and reserve the diagnostic detail for the audit line where it belongs. Keep `status` behind the operator credential from SEC-02 rather than trying to word its way out of the leak.

```java
                case LOCKED:
                case UNAVAILABLE:
                case DENIED:
                default:
                    // One wording for every refusal: wrong name, wrong password, locked,
                    // disabled. Nothing a signer-in can see tells them the name exists.
                    out.println("Access denied: invalid username or password.");
                    break;

// login already keeps the detail on the audit side; keep it there.
            audit.record("login-refused", userName,
                    "locked for " + remaining.getSeconds() + " more second(s)");
            return LoginOutcome.denied("locked");
```

### SEC-04: Brute-force lockout lives only in memory and is per-account only
- **Severity:** Medium
- **CWE:** CWE-307: Improper Restriction of the Number of Attempts
- **Location:** `EmployeePortalAuth.java:727-738` (also `:699`)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:727-738
    synchronized boolean registerFailure(String userName, Instant now) {
        if (inspect(userName, now).phase() == Phase.LOCKED) {
            return false;
        }
        State state = states.computeIfAbsent(userName, key -> new State());
        state.failures++;
        if (state.failures >= maxFailures) {
            state.lockedUntil = now.plus(lockDuration);
            return true;
        }
        return false;
    }
```

**Why it is a problem:** The failure counter and the freeze exist only in `states`, a `LinkedHashMap` field on the tracker (`:699`), and the store's record format has no column for them. Restarting the process therefore discards every active freeze and every partial count, so the 5-failures-then-lock control is enforced only for the lifetime of one run: an attacker who can restart the portal — or simply waits for the next planned restart or deploy — gets a fresh budget of five guesses per account, indefinitely. The counter is also keyed purely by username, with no source dimension, which inverts the control in two ways: anyone may lock a known account out by spending its five failures (denial of service against a legitimate employee, with no way to tell that from real attacker activity), and an attacker who sprays one or two passwords across a thousand usernames never trips any single counter at all. `inspect` and `registerFailure` are also two separate synchronised calls from `login` (`:975`, `:987`), so the "was it locked before this attempt" decision and the increment are not one atomic step, though that gap is minor next to the durability problem. `README.md` records the restart behaviour as known ("Restarting the program clears every freeze"), but the counter's persistence and source-scoping are real requirements, not limitations.

**Fix:** Persist failure counts and lock expiry with the record so a restart cannot reset them, and add a per-source counter alongside the per-account one.

```java
// Persist the counters: add failures|lockedUntil to the record and to flush()'s line format.
record EmployeeRecord(String userName, String salt, String hash, int iterations,
                      AccountStatus status, int failures, Instant lockedUntil) {
}

// LoginAttemptTracker: one atomic decide-and-increment, loaded from the store at startup,
// written back through put() so a restart keeps the freeze.
    synchronized FailureDecision recordAttempt(String userName, String source, Instant now) {
        State state = loadOrFresh(userName);
        if (state.isLockedAt(now)) {
            return FailureDecision.locked(state.remainingLock(now));
        }
        state.failures++;
        sourceStates.merge(source, 1, Integer::sum);          // spray-resistant dimension
        if (state.failures >= maxFailures || sourceStates.get(source) >= sourceMaxFailures) {
            state.lockedUntil = now.plus(lockDuration);
            persist(userName, state);
            return FailureDecision.locked(lockDuration);
        }
        persist(userName, state);
        return FailureDecision.open(state.failures);
    }
```

### SEC-05: Session registry grows without bound and is never swept
- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption
- **Location:** `EmployeePortalAuth.java:792-813`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:792-813
    synchronized AccessSession issue(String userName) {
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        Instant now = time.now();
        AccessSession session =
                new AccessSession(TOKEN_ENCODER.encodeToString(raw), userName, now, now.plus(timeToLive));
        live.put(session.token(), session);
        return session;
    }

    /** Returns the session only while its token is valid and unexpired. */
    synchronized Optional<AccessSession> validate(String token, Instant now) {
        AccessSession session = live.get(token);
        if (session == null) {
            return Optional.empty();
        }
        if (!session.isCurrentAt(now)) {
            live.remove(token);
            return Optional.empty();
        }
        return Optional.of(session);
    }
```

**Why it is a problem:** `issue` appends to the `live` map (`:784`) and nothing ever removes an entry except `validate` — and `validate` removes only the one token it happens to be handed, and only once that token has expired. A session that is issued and then never presented again is retained forever: log out, close the terminal, or simply never call `whoami`, and the `AccessSession` object plus its 43-character token stay in the map. Every successful login therefore leaks one entry, and because SEC-02 lets anyone at the prompt `add` an account, the entry count is attacker-controlled and unbounded — a memory-exhaustion path that ends the process and, per SEC-04, also clears every lockout. The map is also not the only concern in these twelve lines: `live.get(token)` at `:804` resolves the token through `HashMap` hashing and `equals`, so the lookup is not constant-time the way the password comparison at `:531-532` carefully is. With 32 random bytes of token that is not a practical attack, but the file otherwise goes out of its way to close exactly this class of side channel, so it reads as an oversight rather than a decision.

**Fix:** Sweep expired sessions on every registry touch and cap concurrent sessions per account, so the map's size tracks live activity rather than lifetime login count.

```java
    synchronized AccessSession issue(String userName) {
        purgeExpired(time.now());
        long heldForUser = live.values().stream()
                .filter(s -> s.userName().equals(userName))
                .count();
        if (heldForUser >= maxSessionsPerAccount) {
            live.values().removeIf(s -> s.userName().equals(userName));   // oldest grants win
        }
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        Instant now = time.now();
        AccessSession session =
                new AccessSession(TOKEN_ENCODER.encodeToString(raw), userName, now, now.plus(timeToLive));
        live.put(session.token(), session);
        return session;
    }

    private void purgeExpired(Instant now) {
        live.values().removeIf(session -> !session.isCurrentAt(now));
    }
```

### SEC-06: Credential store permissions are applied best-effort and never verified
- **Severity:** Medium
- **CWE:** CWE-276: Incorrect Default Permissions
- **Location:** `EmployeePortalAuth.java:466-471` (also `:442-464`, `:347-352`; related CWE-312)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:442-472
    private void flush() throws IOException {
        List<String> lines = new ArrayList<>(records.size() + 1);
        lines.add(HEADER);
        for (EmployeeRecord record : records.values()) {
            lines.add(String.join("|", record.userName(), record.salt(), record.hash(),
                    Integer.toString(record.iterations()), record.status().name()));
        }
        Path parent = path.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        Path temp = Files.createTempFile(parent, path.getFileName().toString(), ".tmp");
        try {
            Files.write(temp, lines, StandardCharsets.US_ASCII);
            restrictToOwner(temp);
            try {
                Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException platformWithoutAtomicMove) {
                Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private void restrictToOwner(Path file) {
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException notPosix) {
            // Best effort: a file system without POSIX permissions keeps its defaults.
        }
    }
```

**Why it is a problem:** The file being written is the entire authentication database — every username with its salt, digest, and iteration count — in cleartext, and the only protection applied to it is swallowed by a `catch` that treats failure as a platform quirk. On a filesystem without POSIX ACLs (Windows without the right permission AclFileAttributeView, most FAT/exFAT/USB media, many container and network mounts) `setPosixFilePermissions` throws `UnsupportedOperationException`, the comment waves it through, and the store lands with `Files.createTempFile`'s mode or the directory's inherited defaults. Three gaps compound it: `Files.createDirectories(parent)` at `:450` creates the parent with the default umask, so a `portal-records.txt` inside a world-readable directory may be unreachable but listable and often still readable; the window between `Files.write` at `:453` and `restrictToOwner` at `:454` leaves the temp file readable to others for a moment; and the constructor at `:347-352` calls `reload()` on any file it finds without ever checking the mode it arrives with, so a store that was created world-readable by an older run, a manual copy, or a restore is accepted silently and the portal keeps happily writing credentials there. The test suite asserts `rw-------` on Linux, which is precisely the platform where the control is already easy to pass.

**Fix:** Treat "I could not restrict this file" as fatal rather than advisory, restrict the directory as well, and refuse to start against a store that is already group- or world-accessible.

```java
    private void restrictToOwner(Path file) throws IOException {
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException noPosixAcl) {
            throw new IOException("refusing to write credentials on a file system that cannot "
                    + "restrict them to the owner: " + file, noPosixAcl);
        }
    }

// flush(): create the directory owner-only up front, and propagate a failed chmod.
        Path parent = path.toAbsolutePath().getParent();
        Files.createDirectories(parent, PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")));

// FileRecordStore constructor: verify the mode of whatever we are about to trust.
    FileRecordStore(Path path) throws IOException {
        this.path = path;
        if (Files.exists(path)) {
            rejectAccessibleToOthers(path);
            reload();
        }
    }
```

Since the content is the credential corpus, also consider `implementing-aes-encryption-for-data-at-rest`: even `0600` does not help once the file is copied by a backup agent or read through a stolen process.

### SEC-07: Audit log goes only to stdout and records password shape and a token prefix
- **Severity:** Low
- **CWE:** CWE-532: Insertion of Sensitive Information into Log File
- **Location:** `EmployeePortalAuth.java:1112-1114` (also `:75`, `:769-772`, `:950-951`, `:998`, `:1228`)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:1112-1114
    synchronized void record(String event, String subject, String detail) {
        out.println("[audit] " + time.now() + " " + event + " user=" + subject + " detail=" + detail);
    }
```

**Why it is a problem:** The sink is a `PrintStream` bound to `System.out` at `:75` (`new AuditLog(System.out, TimeSource.system())`), so every security event — `login-denied`, `login-refused`, `account-created`, `account-unlocked` — exists only as far as the terminal buffer keeps it. The person whose activity is being logged is the person holding that terminal: they can redirect it, scroll past it, or kill the process, and nothing survives. That makes the trail useless for the one thing an audit log is for, and it is why `README.md` concedes "Nothing is audited to a durable place." The content is leaky as well as transient. The rejected-attempt path at `:950-951` writes the password's structural reason verbatim — `passwordProblem.orElse("unusable username")` yields strings like "password contains a control character" or "password longer than 1024 characters", so the log accumulates facts about what people typed as passwords. And the granted path at `:998` logs `session " + session.fingerprint()`, an eight-character raw prefix of the bearer token (also echoed to the operator at `:1228`) — `fingerprint()` at `:770-771` is `token.substring(0, 8)`, so eight of 43 base64url characters, roughly 48 bits, are in the log and on screen; nowhere near enough to replay a 256-bit token, but it is live key material in a log line for no benefit beyond eyeballing correlation.

**Fix:** Append to an owner-only, append-only sink that the console user cannot rewrite, drop password-shape detail to an opaque reason code, and derive a non-reversible handle.

```java
// AuditLog: durable sink chosen by the operator, not inherited from the console.
    static AuditLog toFile(Path logFile, TimeSource time) throws IOException {
        Files.createDirectories(logFile.toAbsolutePath().getParent(),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        return new AuditLog(new PrintStream(Files.newOutputStream(logFile,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND), true, StandardCharsets.UTF_8), time);
    }

// AccessSession: correlate without publishing any part of the bearer token.
    String fingerprint(byte[] logKey) {
        return HexFormat.of().withUpperCase().formatHex(
                new javax.crypto.Mac... // HmacSHA256(logKey, token) truncated to 6 bytes
        ).substring(0, 12);
    }

// login: opaque code instead of the password's shape.
            audit.record("login-rejected", canonicalName.orElse("<unusable-name>"),
                    passwordProblem.isPresent() ? "PW_REJECTED_SHAPE" : "NAME_UNUSABLE");
```

### SEC-08: Legacy cheap records answer faster than unknown usernames
- **Severity:** Low
- **CWE:** CWE-208: Observable Timing Discrepancy
- **Location:** `EmployeePortalAuth.java:1003-1004` (also `:974`)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:1002-1004
    /** Accounts are switched off by an operator, so count nothing and say the account is off. */
    private void burnOneDerivation(char[] candidate, byte[] salt, byte[] digest) {
        PasswordHash.matches(candidate, salt, digest, policyIterations);
```

**Why it is a problem:** `burnOneDerivation` always derives at `policyIterations`, which is correct for the two paths where an unknown name is being equalised against a fixed probe (`:959`, `:969`). But a real account whose record was created under an older, cheaper setting verifies at its own cost — `PasswordHash.matches(password, salt, digest, record.iterations())` at `:974`. So for a record stored at 1,000 iterations and a portal policy of 210,000, an attempt against that existing name returns roughly two hundred times faster than an attempt against a name the portal has never heard of. Wall-clock measurement then becomes a username oracle that works even where SEC-03's wording is fixed, and it reaches further than the wording leak because it needs no operator command: an attacker simply times responses and keeps the fast ones. The window in which this bites is real rather than theoretical, because SEC-01 lets records be created at the cheap floor, and `raiseCost` (`:994-996`) repairs a record only after someone signs in successfully with the plaintext in hand — exactly what an attacker measuring timings will never do. The existing test that keeps the timing spread inside 2× is measured with all records at the same cost, so it cannot see this.

**Fix:** Compare at a cost that does not identify the record — at least the policy cost, and burn the record's own cost when the name is unknown.

```java
// login: the comparison cost must be the same for every name that reaches this line.
        int compareAt = Math.max(record.iterations(), policyIterations);
        boolean credentialsMatch = PasswordHash.matches(password, salt, digest, compareAt);

// Or, if the intent is that every attempt costs what the target account costs, make the
// probe carry the same weight as a real record instead of the policy default:
    private void burnOneDerivation(char[] candidate, byte[] salt, byte[] digest, int cost) {
        PasswordHash.matches(candidate, salt, digest, cost);
    }
```

Whichever direction is chosen, assert it in the harness with mixed-cost records — build one account at the floor and one at policy and require their refusal times to fall inside the same 2× budget.

### SEC-09: Password creation policy is a 10-character minimum plus letter-and-digit
- **Severity:** Low
- **CWE:** CWE-521: Weak Password Requirements
- **Location:** `EmployeePortalAuth.java:655-673`

**Vulnerable code:**
```java
// EmployeePortalAuth.java:655-673
    static Optional<String> creationProblem(char[] password) {
        Optional<String> problem = structuralProblem(password);
        if (problem.isPresent()) {
            return problem;
        }
        if (password.length < CREATION_MIN_LENGTH) {
            return Optional.of("a new password needs at least " + CREATION_MIN_LENGTH + " characters");
        }
        boolean hasLetter = false;
        boolean hasDigit = false;
        for (char c : password) {
            hasLetter |= Character.isLetter(c);
            hasDigit |= Character.isDigit(c);
        }
        if (!hasLetter || !hasDigit) {
            return Optional.of("a new password needs at least one letter and one digit");
        }
        return Optional.empty();
    }
```

**Why it is a problem:** `CREATION_MIN_LENGTH` is 10 (`:624`) and the composition rule is one letter and one digit, so `aaaaaaaaa1` passes and is the canonical shape this policy actually selects for. Against PBKDF2 at policy cost, ten lowercase characters plus a digit is inside the reach of a determined offline attack once the store is obtained — and SEC-01 and SEC-06 are what make obtaining it plausible. There is no deny-list and no check against breached or common passwords, no rejection of the username inside the password, and no length bonus, while `structuralProblem` actively caps useful input at 1,024 characters rather than encouraging long passphrases. Because `add` is unauthenticated (SEC-02), this is also the policy that governs the back-door accounts an attacker creates, so a weak minimum directly weakens the credentials that protect the portal from them.

**Fix:** Raise the minimum, prefer length over composition, and screen against a compromised-password list at creation time.

```java
    static final int CREATION_MIN_LENGTH = 14;

    static Optional<String> creationProblem(char[] password, Set<String> deniedSecrets) {
        Optional<String> problem = structuralProblem(password);
        if (problem.isPresent()) {
            return problem;
        }
        if (password.length < CREATION_MIN_LENGTH) {
            return Optional.of("a new password needs at least " + CREATION_MIN_LENGTH + " characters");
        }
        String lowered = new String(password).toLowerCase(java.util.Locale.ROOT);
        for (String denied : deniedSecrets) {              // breached/common list, or HIBP range query
            if (lowered.contains(denied)) {
                return Optional.of("that password is too common to use");
            }
        }
        return Optional.empty();                            // length is the strength; no composition rule
    }
```

### SEC-10: Absolute store path and raw I/O exception text printed to the terminal
- **Severity:** Low
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `EmployeePortalAuth.java:80-87` (also `:1044`, `:1063`, `:1297`)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:80-87
        } catch (IOException unreadableStore) {
            out.println("cannot open the records store " + config.storePath.toAbsolutePath()
                    + ": " + unreadableStore.getMessage());
            System.exit(2);
            return;
        }

        out.println("employee portal - records store: " + store.path().toAbsolutePath());
```

**Why it is a problem:** Startup announces the absolute filesystem location of the credential store to whoever is watching the terminal, on both the success path (`:87`) and the failure path (`:81`), which hands an attacker with any local read or a shoulder-surfing observer the exact target for SEC-06 and the path layout around it. The failure path then appends `unreadableStore.getMessage()` — raw JDK/NIO text that routinely embeds paths, permission wording, and on some platforms file sizes and inode-level detail — into an operator-facing line. The same pattern recurs in `createAccount` and `setStatus`, where `"could not write the records store: " + couldNotWrite.getMessage()` (`:1044`, `:1063`) is returned as a user-visible problem string, and `reportOperatorResult` prints it verbatim: `out.println("could not do that: " + problem.get());` (`:1297`). Exception text is written for developers, carries whatever the platform puts in it, and is not a stable or safe user-facing contract.

**Fix:** Show a generic message to whoever is at the terminal, keep the detail in the audit record where the operator's own diagnostic sink is the intended reader, and default the banner to the configured path rather than the resolved absolute one.

```java
        } catch (IOException unreadableStore) {
            audit.record("store-unreadable", "<system>",
                    unreadableStore.getClass().getName() + ": " + unreadableStore.getMessage());
            out.println("cannot open the records store; see the audit log for details.");
            System.exit(2);
            return;
        }

// createAccount / setStatus: distinguish the failure without reciting it.
        } catch (IOException couldNotWrite) {
            audit.record("store-write-failed", canonicalName.get(),
                    couldNotWrite.getClass().getName() + ": " + couldNotWrite.getMessage());
            return Optional.of("could not write the records store; nothing was changed");
        }
```

### SEC-11: Whole store rewritten from an in-memory copy with no lock
- **Severity:** Low
- **CWE:** CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Location:** `EmployeePortalAuth.java:378-386` (also `:442-464`)

**Vulnerable code:**
```java
// EmployeePortalAuth.java:378-386
    /** Inserts or replaces a record and flushes the whole store to disk. */
    synchronized void put(EmployeeRecord record) throws IOException {
        if (!record.isWellFormed()) {
            throw new IllegalArgumentException("refusing to store a malformed record for "
                    + record.userName());
        }
        records.put(record.userName(), record);
        flush();
    }
```

**Why it is a problem:** Every mutation flushes the entire store from this process's in-memory `records` map, and nothing coordinates that with any other writer. The `synchronized` keyword guarantees only single-process ordering; a second portal instance pointed at the same path — two terminals, a cron job and an interactive session, or a container restarted while the old one is still shutting down — will overwrite the file with its own stale view, silently deleting accounts the other instance created and resurrecting accounts it disabled. There is no read-back before the move and no check that the file on disk is the one that was loaded, so the loser of the race learns nothing: `reload()` runs once in the constructor (`:347-352`) and never again. For an authentication store, quiet loss of a `disable` is a security event — an account an administrator turned off comes back on next write. The rename is at least atomic (`ATOMIC_MOVE` at `:456-457`), so the file never appears half-written; the defect is lost updates and stale-authoritative state, not corruption. `README.md` flags "One machine, one file … The store has no locking", so this is a documented boundary, but the failure mode is silent and security-relevant enough that the code should enforce the assumption it rests on.

**Fix:** Take an exclusive OS-level lock for the process's lifetime so a second instance refuses to start rather than racing, and re-check that the file on disk still matches what was loaded before overwriting it.

```java
    private FileLock mutationLock;      // held for the process lifetime, released on close()

    FileRecordStore(Path path) throws IOException {
        this.path = path;
        this.lockFile = path.resolveSibling(path.getFileName() + ".lock");
        this.lockChannel = FileChannel.open(lockFile,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        this.mutationLock = lockChannel.tryLock();
        if (mutationLock == null) {
            throw new IOException("another portal process already holds " + lockFile);
        }
        if (Files.exists(path)) {
            loadedDigest = sha256(path);
            reload();
        }
    }

    private void flush() throws IOException {
        if (!Arrays.equals(loadedDigest, sha256(path))) {       // someone else wrote: refuse
            throw new IOException("records store changed under us; refusing to overwrite it");
        }
        // ... existing temp-file write, chmod and atomic move ...
        loadedDigest = sha256(path);
    }
```

## 6. Verified Controls and Checks With No Finding

- **Constant-time digest comparison:** `PasswordHash.matches` compares with `MessageDigest.isEqual` (`:532`) rather than `Arrays.equals` or `String.equals`, so a stored digest is not revealed byte-by-byte through comparison timing.
- **Per-account random salt:** `PasswordHash.newSalt` (`:496-500`) draws 16 fresh bytes from a `SecureRandom` per account; no salt is reused across records, so precomputed/parallel cracking of the whole store is not possible.
- **Password material wiped:** `PBEKeySpec` is cleared in a `finally` inside `derive`, `signIn` wipes its password buffer in a `finally` (`:1245-1247`), and `addAccount` wipes both confirmation buffers the same way (`:1273-1276`), so plaintext does not linger in the console's buffers longer than the derivation.
- **Token strength and contents:** `SessionRegistry` issues 32 bytes from `SecureRandom`, base64url without padding (`:778-779`, `:793-797`); the token contains no username, no timestamp, and no forgeable structure, so it cannot be predicted or decoded into a subject.
- **Session expiry is strict:** `AccessSession.isCurrentAt` uses `now.isBefore(expiresAt)` (`:765-766`), so the expiry instant itself is invalid, and `validate` removes an expired record on sight; `whoami` revalidates rather than trusting the cached `currentSession`.
- **Canonical base64 is genuinely strict:** `decodeCanonical` re-encodes and requires an exact round-trip, so unpadded, over-long, or trailing-junk salt/hash text in the store is rejected rather than silently accepted as a shorter byte string.
- **Username normalisation closes two classic holes:** `UsernameRules` (`:566-567` and its character whitelist) trims spaces and admits only `[a-z0-9._-]` with a letter or digit at each end, which means trailing-NUL usernames such as `alice\0` cannot alias `alice`, and no ESC/CSI byte can reach the terminal through a printed username (checked against every `out.println` that echoes a name, e.g. `:1227`, `:1314`).
- **`PBEKeySpec` fidelity guarded up front:** `PasswordRules.structuralProblem` (`:630-652`) refuses control characters, lone surrogates, and over-long input before hashing, so two different inputs cannot hash to one value — the reason `matches` is trustworthy.
- **Malformed store input is not trusted:** `reload` (`:397-437`) skips lines that are malformed or duplicate an existing username and reports the counts (`:88-94`) instead of guessing; the surviving line must still satisfy `isWellFormed`, and `put` (`:380-383`) refuses to persist a malformed record.
- **Store writes are atomic:** `flush` writes a temp file and renames with `ATOMIC_MOVE`, falling back explicitly where the platform lacks it (`:451-460`), so a crash mid-write cannot leave a truncated credential file.
- **Lockout bookkeeping is correct in its own scope:** `registerSuccess` (`:740-742`) clears the counter, an expired lock clears its state and reopens the account on inspection (`:711-718`), and failures during a freeze are not counted (`:728-730`) — so a legitimate user locked out by an attacker is not pushed deeper, and the freeze self-heals.
- **Cost upgrade on sign-in preserves the salt:** `raiseCost` runs only after credentials have actually matched and only upward (`:994-996`), so a stored hash is never silently weakened by a login.
- **CLI bounds and unknown options:** `--max-failures` is clamped to 1..1000 and `--lock-minutes`/`--session-minutes` to 1..1440, and unrecognised options are rejected (`:203-220`) rather than ignored, so a typo cannot silently disable the lockout.
- **Audit lines carry no secret:** `AuditLog.record` output contains no password and no digest on any path; SEC-07 is limited to password *shape* and the 8-character token prefix, and the harness asserts that no password is ever echoed.
- **The timing probe is not a credential:** the only secret-shaped literal in either file, `PROBE_PASSWORD = "portal-timing-probe-passphrase"` (`:907`), is fed to `burnOneDerivation` against a throwaway salt/digest pair and is never compared against a stored record, so it authenticates nothing. A full sweep of both files for hardcoded credentials found nothing else.
- **Test harness coverage:** `EmployeePortalAuthTest.java` runs 295 checks over store permissions, refusal-wording equality, lockout thresholds and expiry, session TTL and revocation, cost upgrade, and the absence of password echoes — it is a real safety net for the controls above, though its `ITERS = 1_000` hides SEC-01 and its uniform-cost records hide SEC-08.
