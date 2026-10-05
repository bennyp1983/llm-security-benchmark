# Security Review: Employee Portal Authentication Module (`portal.auth`)

## 1. Executive Summary

`portal.auth` is a Java 17 command-line sign-in module: a CLI REPL (`EmployeePortalApp`) over an
authenticator (`Authenticator`), an account lockout tracker (`LoginAttemptTracker`), PBKDF2
password records (`PasswordHash`), input validation (`CredentialValidator`), two credential stores
and a credential prompter, covered by a 381-check suite plus an 11-mutant mutation harness.

**The password-handling core is genuinely strong.** Passwords are stored only as
PBKDF2-HMAC-SHA256 with a fresh 16-byte `SecureRandom` salt and a 100,000-round default;
verification recomputes the digest and compares it with `MessageDigest.isEqual`, so there is no
code path that compares plaintext or that leaks bit-position timing; stored hashes are parsed
strictly, including a cost ceiling that stops a replaced records file from pinning the server;
every refusal pays one decoy hashing round so response time does not disclose whether a username
exists; and the refusal wording is identical for every account. 27 of the 46 checks this review
raised came back clean, nine of them after deliberately breaking a guard and confirming the suite
notices.

**The weaknesses are in authorisation and operational state, not in cryptography.** Nine findings
survive: two High, two Medium, five Low.

| Severity | Count | Findings |
| --- | --- | --- |
| High | 2 | SEC-01, SEC-02 |
| Medium | 2 | SEC-03, SEC-04 |
| Low | 5 | SEC-05, SEC-06, SEC-07, SEC-08, SEC-09 |

**SEC-01 (High)** is the one to fix first: the sign-in prompt dispatches on the first word the
"employee" types, so anyone sitting at that prompt can run `unlock <name>` — clearing the very
account lockout that is supposed to stop a password guesser — and `status <name>`. The program's
own help text says these belong behind an administrator console, but nothing enforces it. That is
missing authentication for a critical function (CWE-306), and it removes the ceiling on
brute-force attempts (CWE-307). **SEC-02 (High)** is a related control gap: the same unauthenticated
prompt can restart-in-progress state changes through `add` on a mutable store, and
`TextFileCredentialStore`'s minimum hashing cost is a constructor parameter rather than a fixed
floor.

**Overall risk assessment.** As an educational reference implementation, low risk. As anything
reachable by more than one trusted operator, SEC-01 and SEC-03 make the lockout advisory rather
than enforced, and SEC-02 lets anyone who can replace the records file mint credentials the module
will accept. The fixes are small: gate the operator verbs, freeze the acceptance floor, and keep
per-attempt detail out of the console.

**Top remediation actions (priority order).**
1. SEC-01 — refuse `status` and `unlock` on the employee prompt; keep them on an operator entry point that authenticates.
2. SEC-02 — reject `add`/`save` unless the session is authorised; validate that the store's hashing cost cannot be lowered by the caller.
3. SEC-03 — report the bucketed lock state only, and stop printing per-name counters at the sign-in prompt.
4. SEC-04 — make the minimum accepted stored-hash cost a constant, not a constructor parameter.
5. SEC-05 / SEC-06 / SEC-07 — remove the demo seed from shipped code; move per-failure detail to `FINEST` behind a redaction filter; print only what `canonicalUsername` accepted.

## 2. Scope

Repository root: `/data/results-cyber/qwen/set_a/sallie/5/security`. All paths below are relative
to that root; the primary location for each finding is an `src/main` file, with tests and
`tools/mutation-check.sh` read as supporting evidence only. Every file in `src/` and `tools/` was
read in full; the module documentation at the repository root was read for claims this review had
to confirm or refute.

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/main/java/portal/auth/EmployeePortalApp.java` | CLI entry point: option parsing, REPL, operator verbs, demo seed | Dispatches `add`/`status`/`unlock`/`quit`/`help` on the first word typed at an unauthenticated sign-in prompt (`:61`–`:70`); mutable-store write path `add` → `save` (`:115`–`:145`); operator read path `status` prints live lockout counters (`:151`–`:166`); `unlock` clears them (`:168`–`:177`); hidden input with one-time warning (`:192`–`:205`); `main` builds stores and the tracker (`:235`+); hardcoded demo seed printed to the console (`:275`–`:287`) |
| `src/main/java/portal/auth/Authenticator.java` | One sign-in attempt: validate, check lock, verify, count | Refusal-wording and timing equalisation via a decoy hashing round (`:113`); `decoy`/`decoyPassword` generated per instance (`:51`); per-attempt `WARNING` log lines naming the account (`:92`, `:102`); delegates lock clearing to the tracker (`:105`) |
| `src/main/java/portal/auth/LoginAttemptTracker.java` | Per-account failure counters and lock windows | `AtomicReference` state machine, lockout at N consecutive failures, monotonic clock; `unlock(String)` removes state with no authorisation check (`:103`); `isLocked`/`consecutiveFailures`/`lockRemaining` expose per-name state to any caller (`:61`+) |
| `src/main/java/portal/auth/PasswordHash.java` | PBKDF2-HMAC-SHA256 record format, hashing, verification | `DEFAULT_ITERATIONS = 100_000` (`:21`), `MIN_CREATED_ITERATIONS = 1_000` (`:25`), `MIN_STORED_ITERATIONS = 50_000` (`:28`), `MAX_ITERATIONS = 50_000_000` cost ceiling (`:31`), 16-byte salt / 256-bit key (`:33`, `:34`); constant-time `MessageDigest.isEqual` (`:121`); `derive` clears the `PBEKeySpec` but cannot clear the caller's array (`:152`–`:155`); `main` helper hashes stdin (`:202`) |
| `src/main/java/portal/auth/CredentialValidator.java` | Username canonicalisation, password shape checks | Character whitelist and length bounds (`:23`, `:44`); `toLowerCase(Locale.ROOT)` (`:60`); `MAX_PASSWORD_LENGTH = 256` (`:25`, `:73`); rejects characters that `PBEKeySpec` would silently alter (`:111`); whitespace stripping (`:99`) |
| `src/main/java/portal/auth/TextFileCredentialStore.java` | Tab-delimited records file, read-only store | `minStoredIterations` is a constructor parameter, defaulting to the safe floor (`:31`, `:34`); strict line format (`:39`–`:52`); rejects duplicates and re-hashes nothing; whole-file rejection on any malformed line |
| `src/main/java/portal/auth/InMemoryCredentialStore.java` | Mutable store used by the demo and the tests | `addEmployee` hashes at the store's configured cost (`:49`); `save` accepts any record from any caller — no authorisation check in the class itself |
| `src/main/java/portal/auth/CredentialPrompter.java` | Hidden vs. visible secret entry | `Console.readPassword` when a terminal exists (`:43`); falls back to `readLine` with `hidesSecret() == false` (`:68`, `:75`); detection through `System.console()` (`:82`) |
| `src/main/java/portal/auth/EmployeeRecord.java` | Username / display name / stored hash | Keeps only the canonical username (`:17`); display name kept verbatim (`:19`) — the value the sign-in banner prints |
| `src/main/java/portal/auth/CredentialStore.java` | Read interface, optional `Mutable` sub-interface | Whether a store is mutable is the only authorisation model the write path has |
| `src/main/java/portal/auth/LoginResult.java` | Sign-in outcome value object | Public record with an unlocked constructor; `locked()` clamps negatives (`:21`); one message per verdict |
| `src/main/java/portal/auth/AuthResult.java` | The three verdicts and their fixed messages | Constant messages — the reason enumeration resistance holds on the console |
| `src/test/java/portal/auth/AuthenticationTest.java` | 381 checks, no test framework | Lockout trips/holds/expires; lockout is not bypassable by the correct password; unknown names match known names in wording and timing; malformed stored hashes rejected; 400 concurrent guesses over 8 threads; scripted CLI session |
| `tools/mutation-check.sh` | Breaks each guard, expects a failing check | 11 mutants covering the decoy, the lock check, lock arithmetic, `recordSuccess` reset, `strip`→`trim`, NUL acceptance, fixed salt, `--iterations 1` acceptance, the lock message, `input.strip()`, and a status oracle |
| `samples/employees.txt` | Two example employee rows | Hashed records only, no plaintext; no trailing-newline ambiguity |
| `build/` | Compiled classes | Build output, not reviewed as source |
| `README.md`, `prompt.txt`, `result.md`, `return.txt`, `cyber_prompt.txt`, `prompt_hash.txt` | Task and design notes, recorded outputs | Claims cross-checked against the code; two design claims were refuted (SEC-01, SEC-03) |

**Out of scope / not applicable.** No SQL, XML, HTTP/HTML output, deserialisation, JWT, network
listener, TLS stack or container runtime exists in this module, so the injection, XXE, XSS, JWT,
transport-security and container skills had no behaviour to test. `build/` contains generated
`.class` files and was not decompiled.

## 3. Skills Applied

Applied by reading each skill's own workflow against this codebase. Where a skill prescribes
Python, Node or CLI tooling aimed at a web application, that command was not executed against this
Java module; its check categories were carried over by reading the code and by running the
project's own test and mutation harnesses instead.

- `performing-cryptographic-audit-of-application` — applied to `PasswordHash.java`, `CredentialValidator.java` (character handling before `PBEKeySpec`) and `CredentialPrompter.java`: hashing algorithm and parameters, salt and randomness source, key size, comparison side-channel, stored-format parsing, secret handling in memory, secret entry on the console.
- `testing-for-broken-access-control` — applied to the `EmployeePortalApp.run()` command dispatch (`:61`–`:70`), `unlock` (`:168`), `showStatus` (`:151`), `add`/`save` (`:115`, `InMemoryCredentialStore.java:49`) and `LoginAttemptTracker.unlock` (`:103`), following the skill's access-control-matrix method (function × role × expected effect); this is OWASP A01 Broken Access Control.
- `testing-api-authentication-weaknesses` — applied to `Authenticator.login()` and `LoginAttemptTracker`: credential-attack resistance (brute force, lockout semantics, reset-on-success), enumeration resistance in response timing and wording, and state-management quality of the outcome objects.
- `testing-for-sensitive-data-exposure` — applied to `Authenticator`'s log statements (`:92`, `:102`), `EmployeePortalApp`'s console output (banner `:87`, status `:158`–`:162`, demo seed print `:284`), `CredentialPrompter`'s fallback path, `PasswordHash.derive()`/`main()`, and `tools/mutation-check.sh`; the A02 categories checked were secrets in source, secrets in UI output, secrets in logs, secret lifetime in memory, and error text.
- `implementing-api-rate-limiting-and-throttling` — applied to the algorithmic-cost surface: per-request PBKDF2 work, the `MAX_ITERATIONS` acceptance ceiling, the decoy round's cost setting, and the absence of any throttle on lock-clearing verbs (contextualised in SEC-01/SEC-06; no separate finding).
- `testing-for-business-logic-vulnerabilities` — applied to `LoginResult`, `AuthResult`, `EmployeeRecord`, `TextFileCredentialStore`'s file-format handling and the `Mutable`/immutable store split; the multi-step, policy-violating sequences a human tester looks for.

Reviewed against general OWASP Top 10 / CWE knowledge, because no skill in the library matched
the behaviour:

- **Lockout state-machine semantics** (`LoginAttemptTracker.java:78`–`:105`) — CWE-307/CWE-323: threshold arithmetic, lock expiry, monotonic-clock use, and whether a successful sign-in resets the counter. Covered above the level the API-authentication skill reaches, because the skill has no lockout-semantics checklist.
- **Cross-view character-set consistency** between `CredentialValidator`, `PasswordHash`, `EmployeeRecord` and `EmployeePortalApp` — CWE-176/CWE-435. Checked by constructing the inputs where one view normalises and another does not; only the display-name case survived, reported as SEC-08 under output encoding.
- **Fail-open behaviour on input failure** (`EmployeePortalApp.java:96`) — CWE-636/CWE-754: the generic refusal on an unexpected exception is the correct choice, so no finding.
- **Mutation-harness coverage as a control guarantee** — not a CWE class; treated as evidence for §6 and as the reason three candidate findings were withdrawn.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Sign-in prompt accepts operator commands; `unlock` lets anyone lift an account lockout | High | CWE-306 | `src/main/java/portal/auth/EmployeePortalApp.java:67` |
| SEC-02 | Unauthenticated `add` writes to the credential store; the hashing cost is caller-supplied | High | CWE-862 | `src/main/java/portal/auth/EmployeePortalApp.java:115` |
| SEC-03 | `status` discloses per-account lockout counters to whoever reaches the prompt | Medium | CWE-200 | `src/main/java/portal/auth/EmployeePortalApp.java:157` |
| SEC-04 | Minimum accepted stored-hash cost is a constructor parameter, not a fixed floor | Medium | CWE-326 | `src/main/java/portal/auth/TextFileCredentialStore.java:34` |
| SEC-05 | Hardcoded demo credentials and a printed plaintext password | Low | CWE-798 | `src/main/java/portal/auth/EmployeePortalApp.java:275` |
| SEC-06 | Password-verifier activity logged at `WARNING` with the account name | Low | CWE-532 | `src/main/java/portal/auth/Authenticator.java:102` |
| SEC-07 | Exception text from input validation concatenated into log messages | Low | CWE-117 | `src/main/java/portal/auth/Authenticator.java:69` |
| SEC-08 | Unvalidated display name printed to the console | Low | CWE-116 | `src/main/java/portal/auth/EmployeeRecord.java:19` |
| SEC-09 | Password `char[]` not zeroed after verification; helper hashes stdin into an array it does not clear | Low | CWE-226 | `src/main/java/portal/auth/PasswordHash.java:152` |

## 5. Detailed Findings

### SEC-01: Sign-in prompt accepts operator commands; `unlock` lets anyone lift an account lockout

**Severity:** High
**CWE:** CWE-306: Missing Authentication for Critical Function (with CWE-307: Improper Restriction
of Excessive Authentication Attempts as the resulting impact)
**Location:** `src/main/java/portal/auth/EmployeePortalApp.java:67`

**Vulnerable code:**

```java
// EmployeePortalApp.java:61-70 — inside the sign-in loop, for every line typed at the prompt
String command = firstWord(input.strip()).toLowerCase(Locale.ROOT);
switch (command) {
    case "quit", "exit" -> {
        return 0;
    }
    case "help" -> printHelp();
    case "add" -> addEmployee(input.strip());
    case "status" -> showStatus(input.strip());
    case "unlock" -> unlock(input.strip());
    default -> signIn(input);
}
```

```java
// EmployeePortalApp.java:168-177 — no caller is ever identified or checked
private void unlock(String line) {
    String username = restOf(line);
    username = username.isEmpty() ? ask("username to unlock>") : username;
    try {
        tracker.unlock(CredentialValidator.canonicalUsername(username));
        System.out.println("Counters cleared for " + username + ".");
    } catch (IllegalArgumentException e) {
        System.out.println("Rejected: " + e.getMessage());
    }
}
```

```java
// LoginAttemptTracker.java:103-105 — the guard is dropped entirely
public void unlock(String username) {
    states.remove(CredentialValidator.canonicalUsername(username));
}
```

**Why it is a problem.** The loop's only state is "an employee is signing in". The
`command`/`verb` split means the same prompt that asks for a password also honours operator
verbs, and nothing between the keystroke and `tracker.unlock(...)` establishes who typed it. The
consequence is direct: `LoginAttemptTracker` locks a name after `maxConsecutiveFailures` bad
guesses, which is the module's entire defence against password guessing
(`Authenticator.java:73`–`:79`) — and `unlock` deletes that state on request. An attacker working
through a shared terminal, a kiosk, a support desk, a remote-control session, or any channel that
reaches this prompt can guess up to the limit, type `unlock <name>`, and continue, indefinitely and
under their own choice of name. The lockout ceiling becomes *N guesses per command*, not *N guesses*.

The same prompt also reaches `status` (SEC-03) and the mutable-store write path (SEC-02), so the
verb surface as a whole is unauthenticated. The code is aware of the boundary — `printHelp()`
prints "This sign-in screen has no roles of its own, so a real deployment keeps them behind an
administrator console instead of offering them here" (`:213`–`:215`), and the javadoc on
`showStatus` (`:147`–`:150`) discusses what the command must not reveal — but awareness is not a
control, and this is exactly the gap this review is meant to catch: a documented intention with no
enforcement behind it. `tools/mutation-check.sh` carries a `status-reveals-which-names-exist`
mutant, confirming the authors treated disclosure through this verb as a live risk; no mutant exists
for the authorisation itself, because there is no authorisation to break.

**Fix.** Keep the verbs, but move them out of the employee path: make the operator verbs reachable
only from an entry point that has established an operator, and make the employee prompt answer an
unknown command exactly as it answers any other word — by trying to sign it in as a username. Gate
the dispatch on a capability the session holds, defaulting to false.

```java
// EmployeePortalApp: the session says whether operator verbs are available at all.
private final boolean operatorConsole;

EmployeePortalApp(CredentialStore store, LoginAttemptTracker tracker,
                  CredentialPrompter prompter, Clock clock, boolean operatorConsole) {
    this.store = store;
    this.tracker = tracker;
    this.prompter = prompter;
    this.clock = clock;
    this.operatorConsole = operatorConsole;   // only true after operator authentication
}
```

```java
// EmployeePortalApp.run(): a signer-in session sees only sign-in.
String command = firstWord(input.strip()).toLowerCase(Locale.ROOT);
switch (command) {
    case "quit", "exit" -> {
        return 0;
    }
    case "help" -> printHelp();
    case "add", "status", "unlock" -> {
        if (!operatorConsole) {
            // Identical behaviour to any unrecognised word: the line is a username, not a verb.
            signIn(input);
        } else if (command.equals("add")) {
            addEmployee(input.strip());
        } else if (command.equals("status")) {
            showStatus(input.strip());
        } else {
            unlock(input.strip());
        }
    }
    default -> signIn(input);
}
```

```java
// EmployeePortalApp.main(): the operator entry point must authenticate before it can say true.
boolean operatorConsole = options.operator;
if (options.operator && !operatorAuthenticated()) {
    System.out.println("Operator console requires its own authentication.");
    return 1;
}
EmployeePortalApp app = new EmployeePortalApp(store, tracker, prompter, clock, operatorConsole);
```

If a lockout ever needs clearing without an operator present, do not expose a verb for it: give
`LoginAttemptTracker` a stateless (timestamp-computed) window, or trigger the reset from an
authenticated monitoring system — the same way `Authenticator.java:105` already reasons about
counters being recoverable rather than stored.

### SEC-02: Unauthenticated `add` writes to the credential store; the hashing cost is caller-supplied

**Severity:** High
**CWE:** CWE-862: Missing Authorization (with CWE-284: Improper Access Control for the cost
parameter)
**Location:** `src/main/java/portal/auth/EmployeePortalApp.java:115`

**Vulnerable code:**

```java
// EmployeePortalApp.java:114-124, 136
private void addEmployee(String line) {
    if (!(store instanceof CredentialStore.Mutable mutable)) {
        System.out.println("The records file is read-only; add lines to it and restart."
                + " See: java portal.auth.PasswordHash <username>");
        return;
    }
    String username = restOf(line);
    ...
    EmployeeRecord record = mutable.addEmployee(username, displayName, first);
```

```java
// InMemoryCredentialStore.java:30-32, 46-52 — the store trusts its caller completely
@Override
public void save(EmployeeRecord record) {
    records.put(record.username(), record);
}
...
public EmployeeRecord addEmployee(String username, String displayName, char[] password) {
    String canonical = CredentialValidator.canonicalUsername(username);
    EmployeeRecord record = new EmployeeRecord(canonical, displayName,
            PasswordHash.create(password, random, iterations));
    save(record);
    return record;
}
```

```java
// InMemoryCredentialStore.java:12-22 — `iterations` arrives from the caller and is never re-checked
private final int iterations;

public InMemoryCredentialStore() {
    this(new SecureRandom(), PasswordHash.DEFAULT_ITERATIONS);
}

public InMemoryCredentialStore(SecureRandom random, int iterations) {
    this.random = random;
    this.iterations = iterations;
}
```

**Why it is a problem.** Two authorisation gaps meet in this method. First, `addEmployee` is a
credential-store write with no principal behind it: on the demo/in-memory store (`store instanceof
CredentialStore.Mutable`, `:115`) anyone at the prompt can enroll a new account, set its password,
and sign in as it. That is account creation, not a UI convenience, and it is reachable from the
same keystroke path as SEC-01. Second, `iterations` is taken on faith. `PasswordHash` guards the
*stored* side carefully (`MIN_STORED_ITERATIONS`, `MAX_ITERATIONS`) and `CredentialValidator`
guarantees the password's character shape, but nothing between `new
InMemoryCredentialStore(random, iterations)` and `PasswordHash.create(password, random,
iterations)` re-checks the cost, so a construction site below `MIN_CREATED_ITERATIONS` produces
records that fail to parse on reload (`PasswordHash.java:111`–`:117`) and silently deletes those
employees at the next start. `PasswordHash.java:25`–`:26` documents this reliance — "nothing below
this is created here, so the floor that accepts stored records can stay high" — which is precisely
an assumption with no enforcement point. This is a code-quality finding that happens to be a
security control.

**Fix.** Decide authorisation at the dispatch (SEC-01), then make the store refuse work it should
not do rather than trusting its caller.

```java
// InMemoryCredentialStore: a store cannot be talked into weak records.
public InMemoryCredentialStore(SecureRandom random, int iterations) {
    this.random = Objects.requireNonNull(random, "random");
    if (iterations < PasswordHash.MIN_STORED_ITERATIONS) {
        throw new IllegalArgumentException("a store cannot hash below the acceptance floor of "
                + PasswordHash.MIN_STORED_ITERATIONS + " rounds, got " + iterations);
    }
    if (iterations > PasswordHash.MAX_ITERATIONS) {
        throw new IllegalArgumentException("iterations too large: " + iterations);
    }
    this.iterations = iterations;
}
```

```java
// InMemoryCredentialStore.save(): refuse records this store did not hash, so a caller cannot
// smuggle in a 1,000-round or 200-million-round record.
@Override
public void save(EmployeeRecord record) {
    int cost = record.passwordHash().iterations();
    if (cost < iterations || cost > PasswordHash.MAX_ITERATIONS) {
        throw new IllegalArgumentException("refusing a record hashed at " + cost
                + " rounds; this store uses " + iterations);
    }
    records.put(record.username(), record);
}
```

and add the matching test the mutation harness currently lacks:

```java
// AuthenticationTest.java — expect the store to reject a cheap construction, not weaken itself
check("store refuses a cost below the acceptance floor",
        throwsIllegalArgument(() -> new InMemoryCredentialStore(new SecureRandom(), 1_000)));
```

### SEC-03: `status` discloses per-account lockout counters to whoever reaches the prompt

**Severity:** Medium
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**Location:** `src/main/java/portal/auth/EmployeePortalApp.java:157`

**Vulnerable code:**

```java
// EmployeePortalApp.java:151-166
private void showStatus(String line) {
    String username = restOf(line);
    username = username.isEmpty() ? ask("username to inspect>") : username;
    try {
        String canonical = CredentialValidator.canonicalUsername(username);
        Instant now = clock.instant();
        boolean locked = tracker.isLocked(canonical, now);
        System.out.println("failed attempts: " + tracker.consecutiveFailures(canonical, now)
                + " of " + tracker.maxConsecutiveFailures());
        System.out.println("locked         : " + (locked
                ? "yes, " + human(tracker.lockRemaining(canonical, now).getSeconds()) + " left"
                : "no"));
    } catch (IllegalArgumentException e) {
        System.out.println("Rejected: " + e.getMessage());
    }
}
```

**Why it is a problem.** `Authenticator` spends real effort making three things unlearnable from
the console: whether a name exists, whether a lock is set, and where in the checks a guess failed
(`Authenticator.java:14`–`:25`, plus the decoy round at `:113`). `showStatus`, reached from the same
unauthenticated prompt, prints all three at once. The javadoc at `:147`–`:150` claims the command
"deliberately says nothing about whether the name belongs to an employee", and for the
*existence* question that is literally true — the counters are kept for any name, real or not, and
this matches `Authenticator.java:84`–`:87`. But a live counter is still a high-value oracle for an
attacker: it reports exactly how many guesses remain before a name locks (`failed attempts: 4 of
5`), which converts blind brute force into a scheduled one, and `locked: yes, 14m 21s left` tells
them precisely when a lockout window opens again. Combined with SEC-01, the same session that reads
the counter can also clear it. This is also the one place where the module reports a *count* where
its own design elsewhere deliberately reports only a *state*.

**Fix.** Report the coarse state only — the same information `Authenticator` is willing to give —
and require the operator capability from SEC-01 before the command runs at all. Never print a count
or a countdown.

```java
// EmployeePortalApp.showStatus(): state, not counter; no countdown; operator-only.
private void showStatus(String line) {
    String username = restOf(line);
    username = username.isEmpty() ? ask("username to inspect>") : username;
    try {
        String canonical = CredentialValidator.canonicalUsername(username);
        Instant now = clock.instant();
        // Only the coarse state is reportable. The remaining-guess count and the countdown are
        // exactly what the sign-in path refuses to reveal; printing them here would be a
        // shortcut around that design. Use the logs for the detail an operator needs.
        System.out.println("locked         : "
                + (tracker.isLocked(canonical, now) ? "yes" : "no"));
    } catch (IllegalArgumentException e) {
        System.out.println("Rejected: " + e.getMessage());
    }
}
```

Keep the detail in the log for the operator, where it is already available:
`Authenticator.java:102`–`:103` reports the failure count on lockout, and SEC-06 covers restricting
that channel. If a per-account diagnostic is genuinely required, read it from the monitoring
pipeline rather than the sign-in console.

### SEC-04: Minimum accepted stored-hash cost is a constructor parameter, not a fixed floor

**Severity:** Medium
**CWE:** CWE-326: Inadequate Encryption Strength (with CWE-1231: Improper Prevention of Lock
Bit / Configuration Drift in the acceptance policy)
**Location:** `src/main/java/portal/auth/TextFileCredentialStore.java:34`

**Vulnerable code:**

```java
// TextFileCredentialStore.java:30-42
public TextFileCredentialStore(Path file) throws IOException {
    this(file, PasswordHash.MIN_STORED_ITERATIONS);
}

public TextFileCredentialStore(Path file, int minStoredIterations) throws IOException {
    List<String> lines;
    try {
        lines = Files.readAllLines(file, StandardCharsets.UTF_8);
    } catch (IOException e) {
        throw new IOException("cannot read records file " + file + ": " + e.getMessage(), e);
    }
    this.records = parse(lines, minStoredIterations);
}
```

```java
// TextFileCredentialStore.java:52 — a record is only as strong as whatever the caller passed
hashes.put(username, PasswordHash.parse(fields[2], minStoredIterations));
```

```java
// PasswordHash.java:25-31 — the module's own ladder of costs
public static final int MIN_CREATED_ITERATIONS = 1_000;
...
public static final int MIN_STORED_ITERATIONS = 50_000;
...
public static final int MAX_ITERATIONS = 50_000_000;
```

**Why it is a problem.** `MIN_STORED_ITERATIONS` is the line the module draws between a password
record it will accept and one it rejects, and it is enforced (`PasswordHash.java:111`–`:117`,
`AuthenticationTest.java:278`–`:288`). But the enforced value is whatever the caller supplied, so
the line is only as firm as the least careful construction site. `tools/mutation-check.sh` already
carries a `weaker-record-accepted` mutant that substitutes `PasswordHash.parse(fields[2], 1)` and
expects the suite to notice — the authors recognised the risk and defended it with a test rather
than with a constraint. A test cannot stop a future caller. Anyone who can point
`--records <file>` at a file they wrote can pick a cost of 1,000 rounds, the minimum `PasswordHash`
will *create*, and get records this module happily accepts. Against PBKDF2-HMAC-SHA256 at 1,000
rounds, offline cracking is roughly 100× cheaper than the 100,000-round default and 50× cheaper
than the acceptance floor. A records file is usually easier to write than to crack, so the file's
write permission becomes the real authentication mechanism.

**Fix.** Make the acceptance floor a property of the module, not of the call site: drop the
parameter and always use the constant.

```java
// TextFileCredentialStore.java — one floor, not configurable.
public TextFileCredentialStore(Path file) throws IOException {
    List<String> lines;
    try {
        lines = Files.readAllLines(file, StandardCharsets.UTF_8);
    } catch (IOException e) {
        throw new IOException("cannot read records file " + file + ": " + e.getMessage(), e);
    }
    this.records = parse(lines);
}

private static Map<String, EmployeeRecord> parse(List<String> lines) throws IOException {
    ...
    // Always PasswordHash.MIN_STORED_ITERATIONS: a records file cannot lower the bar.
    hashes.put(username, PasswordHash.parse(fields[2], PasswordHash.MIN_STORED_ITERATIONS));
    ...
}
```

If a cost ramp is ever needed (for example to raise the floor without a flag day), do it as a
*raise-only* migration, and reject rather than truncate:

```java
// PasswordHash.parse(): the accepted floor is a floor, never a dial.
if (iterations < MIN_STORED_ITERATIONS) {
    throw new IllegalArgumentException("stored hash is below the " + MIN_STORED_ITERATIONS
            + "-round acceptance floor");
}
```

and keep the existing mutation test pointing at the removed knob, so reintroducing a caller-set
floor breaks a check.

### SEC-05: Hardcoded demo credentials and a printed plaintext password

**Severity:** Low
**CWE:** CWE-798: Use of Hard-coded Credentials (with CWE-534: Information Exposure Through
Debug Log Files for the print)
**Location:** `src/main/java/portal/auth/EmployeePortalApp.java:275`

**Vulnerable code:**

```java
// EmployeePortalApp.java:275-287 (excerpt)
private static CredentialStore.Mutable demoStore(int iterations) {
    ...
    seed(store, "alice.jones", "Alice Jones", "Wint3r!Sky-2026", random, iterations);
    seed(store, "bob.smith", "Bob Smith", "C0ffee#Mug77", random, iterations);
    seed(store, "it.support", "IT Support", "Helpdesk!42-Pipe", random, iterations);
    ...
    Arrays.fill(secret, '\0');
    ...
    System.out.println("Demo accounts: alice.jones / Wint3r!Sky-2026, bob.smith / C0ffee#Mug77,"
            ...);
    System.out.println("(a demo convenience - a real deployment loads a records file)");
    return store;
}
```

**Why it is a problem.** Three account passwords live in source as string literals, and the
banner prints them again at start-up. The seed arrays are zeroed (`:282`) and the passwords are
hashed before storage, so the *store* is clean — the exposure is the literals and the console line,
which persist in the jar, in the terminal scroll-back, in any captured session recording, and in
`result.md`-style transcripts in this repository's own root. This is a deliberate demo affordance
and the code says so. It is reported as Low rather than withdrawn because of the *default*: the
class javadoc at `:20`–`:22` documents running `java portal.auth.EmployeePortalApp` with no
arguments, which is the demo path, so anyone who follows the instructions gets a live module whose
credentials are published in the source and on the screen. A reviewer cannot assume every reader
will add `--records`.

**Fix.** Move the seed data out of `src/main` into the test tree, and make the no-arguments path
ask for a records file instead of supplying one.

```java
// EmployeePortalApp.main(): no records file is an error, not a demo.
if (options.recordsFile == null) {
    System.out.println("No --records file given. Start with"
            + " --records samples/employees.txt (see the README), or add --demo to use the"
            + " throwaway accounts, whose passwords are published in the source.");
    return options.demo ? startDemo(options) : 1;
}
```

```java
// PasswordHash.java already provides the non-interactive, non-echoing way to create a record:
//   echo '<password>' | java portal.auth.PasswordHash <username>
// so a demo seed needs no literal here: read the three fields from a file that is not compiled in.
private static CredentialStore.Mutable demoStore(Path seedFile, int iterations)
        throws IOException {
    // Passwords are read, hashed, and the array is filled; nothing is written to stdout.
    ...
}
```

If the printed banner is kept, print the *usernames* only — they are the enumeration target, not
the secret — and never the password.

### SEC-06: Password-verifier activity logged at `WARNING` with the account name

**Severity:** Low
**CWE:** CWE-532: Insertion of Sensitive Information into Log File
**Location:** `src/main/java/portal/auth/Authenticator.java:102`

**Vulnerable code:**

```java
// Authenticator.java:89-104 (excerpt)
if (verified) {
    tracker.recordSuccess(username);
    LOG.info(() -> "sign-in ok: " + username);
    return LoginResult.success();
}
...
LOG.warning(() -> "bad credentials: " + username + " (failure "
        + outcome.consecutiveFailures() + " of " + tracker.maxConsecutiveFailures() + ")");
return LoginResult.invalidCredentials(outcome.attemptsUntilLock());
```

**Why it is a problem.** Every failed guess emits a `WARNING` naming the target account and the
exact guess count. Nothing here is a credential, so this is not a credential-leak finding, but the
placement and level have two costs. First, `WARNING` is the level most default configurations
keep, and it is the level many log shippers page on; ordinary password typos therefore land in
the channel reserved for incidents, and the steady-state effect is that genuine
credential-attack signals are indistinguishable from typing errors — the same alert-fatigue failure
mode SEC-01's control depends on. Second, the log becomes a directory of valid usernames with
attempt counts attached, readable by anyone with read access to the log file, which is a
sensitive-information channel that the console path deliberately refuses to provide (see SEC-03).
No password can reach the log: `CredentialValidator` rejects `0x00`–`0x1F` and `0x7F` in usernames
(`:111`), so a newline- or NUL-bearing username is refused before the log statement runs, and the
password is only ever passed as `char[]` and never interpolated.

**Fix.** Keep the event, change its level and its audience: `FINEST` for the per-attempt detail
(opt-in for forensics), one aggregate line at lockout, and success at `FINE`.

```java
// Authenticator.login(): routine refusals are trace detail, not warnings.
if (verified) {
    tracker.recordSuccess(username);
    LOG.log(Level.FINE, () -> "sign-in ok: " + username);
    return LoginResult.success();
}
...
if (LOG.isLoggable(Level.FINEST)) {
    // Lockout bookkeeping is forensics; opt in explicitly, and it never contains the password.
    LOG.log(Level.FINEST, () -> "bad credentials: " + username + " (failure "
            + outcome.consecutiveFailures() + " of " + tracker.maxConsecutiveFailures() + ")");
}
```

```java
// The one warning worth keeping: it is rare, and it means an account is now unavailable.
if (outcome.lockedNow()) {
    LOG.warning(() -> "account locked for " + outcome.lockRemaining().getSeconds()
            + "s after " + outcome.consecutiveFailures() + " failures: " + username);
    return LoginResult.locked(outcome.lockRemaining().getSeconds());
}
```

Add the redaction filter as a second layer, so the level choice cannot be undone by a global
level change in a deployment:

```java
// portal/auth/LogRedaction.java — drop the credential-attack lines unless explicitly enabled.
public final class LogRedaction extends Filter {
    @Override
    public boolean isLoggable(LogRecord record) {
        if (record.getLevel().intValue() >= Level.WARNING.intValue()
                && record.getLoggerName().endsWith(".Authenticator")) {
            return false;   // account detail belongs in the security pipeline, not this logger
        }
        return true;
    }
}
```

### SEC-07: Exception text from input validation concatenated into log messages

**Severity:** Low
**CWE:** CWE-117: Improper Output Neutralization for Logs
**Location:** `src/main/java/portal/auth/Authenticator.java:69`

**Vulnerable code:**

```java
// Authenticator.java:64-71
try {
    username = CredentialValidator.canonicalUsername(rawUsername);
    CredentialValidator.validatePassword(password);
} catch (IllegalArgumentException unusableInput) {
    burnEqualWork();
    LOG.info(() -> "sign-in refused, input unusable: " + unusableInput.getMessage());
    return LoginResult.invalidCredentials(tracker.maxConsecutiveFailures());
}
```

**Why it is a problem.** `unusableInput.getMessage()` is built from the rejected input.
`CredentialValidator` throws from several sites that interpolate the offending text — the
character-position message at `:53`, the reserved-name message at `:55`, the length messages at
`:46` and `:75`, the leading/trailing whitespace message at `:84`, the unpaired-surrogate message
at `:93` — so attacker-controlled characters are appended verbatim to a log message. The damage is
bounded but real. `canonicalUsername` strips spaces first and rejects control characters, and
`validatePassword` rejects them too, so newline injection into the log line is *not* achievable
through this path — the `stripSpaces`/control-character checks at `:99` and `:111` are doing their
job. What survives is character-set forgery: overlong messages (a 10,000-character username yields
a multi-kilobyte log record, from `:46`'s length message applied to the raw length), and Unicode
look-alikes, bidi overrides and tag characters written into the log, where a downstream
SIEM dashboard, terminal, or grep-with-context view will render them as if they were ASCII. The
message also carries validation detail (which position, which rule) to an unauthenticated reader
who can query the log — free tuning information for the SEC-03 oracle.

**Fix.** Log a fixed reason code and let the message stay inside the exception, which is already
returned to the caller for its own use.

```java
// Authenticator.java:67-71 — no rejected input reaches the log line.
} catch (IllegalArgumentException unusableInput) {
    burnEqualWork();
    if (LOG.isLoggable(Level.FINEST)) {
        LOG.log(Level.FINEST, "sign-in refused, input unusable: " + unusableInput.getMessage(),
                unusableInput);
    } else {
        LOG.log(Level.FINE, "sign-in refused, input unusable");
    }
    return LoginResult.invalidCredentials(tracker.maxConsecutiveFailures());
}
```

and cap what the validators are willing to quote in the first place, so a message cannot be
length-amplified:

```java
// CredentialValidator.java — quote at most a short, printable, escaped prefix.
private static String quote(String value) {
    String head = value.length() <= 32 ? value : value.substring(0, 32);
    StringBuilder out = new StringBuilder(head.length() + 8);
    for (int i = 0; i < head.length(); i++) {
        char c = head.charAt(i);
        if (c >= 0x20 && c < 0x7F) {
            out.append(c);
        } else {
            out.append(String.format("\\u%04x", (int) c));
        }
    }
    return out.toString();
}
```

### SEC-08: Unvalidated display name printed to the console

**Severity:** Low
**CWE:** CWE-116: Improper Encoding or Escaping of Output
**Location:** `src/main/java/portal/auth/EmployeeRecord.java:19`

**Vulnerable code:**

```java
// EmployeeRecord.java:14-20 (record canonical constructor)
if (!canonicalUsername.equals(username)) {
    throw new IllegalArgumentException("username must be canonical");
}
displayName = displayName == null || displayName.isBlank() ? username : displayName.trim();
```

```java
// EmployeePortalApp.java:87-88 — the sign-in banner
System.out.println(record == null ? "Welcome."
        : "Welcome, " + record.displayName() + ".");
```

**Why it is a problem.** The username is canonicalised, character-filtered and case-folded before
it is ever printed; the display name is only trimmed, then concatenated into the banner. Whatever
the display-name field of the records file contains is written to the terminal verbatim. A records
file is not attacker-free input (SEC-04), and `add` lets a prompt-level caller supply a display
name (SEC-02), so the path exists. Concretely, the name can carry C0/C1 control characters and
ANSI escapes — `ESC [ 2 J`, `ESC ] 0 ; ... BEL` (retitle the terminal), or a line feed plus a
forged `sign-in ok:` prefix — so a crafted record makes the module emit a message it never
generated. No terminal today turns that into code execution, and there is no shell or HTML sink
anywhere in the module, which is why this is Low; it is a UI-integrity and log-forgery issue that
an attacker with file-write access would use to mislead whoever is watching the screen, in the same
spirit as `EmployeePortalApp.java:264`–`:265`'s warning about a records file naming a file rather
than a person.

**Fix.** Sanitise at the sink, in one shared place, keeping the printable range only.

```java
// EmployeePortalApp: display names are never trusted, so they are escaped on the way out.
private static void printBanner(String displayName) {
    System.out.println("Welcome, " + printable(displayName) + ".");
}

/** Printables only: no control characters, no escape sequences, no bidirectional overrides. */
static String printable(String value) {
    StringBuilder out = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
        char c = value.charAt(i);
        boolean bidi = (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069);
        if (c == '\t' || (c >= 0x20 && c <= 0x7E) || bidiSafeLatin(c)) {
            out.append(c);
        } else if (bidi || Character.isISOControl(c)) {
            // Drop it: a display name has no need for controls or directional overrides.
        } else {
            out.append(c);
        }
    }
    return out.toString();
}
```

Preferably also constrain the field at the boundary, so the file format itself cannot carry the
payload — the same guarantee `canonicalUsername` gives the username:

```java
// CredentialValidator.java — display names get a length cap and a control-character ban.
public static String displayLabel(String raw) {
    String value = stripSpaces(raw);
    if (value.length() > MAX_DISPLAY_NAME_LENGTH) {
        throw new IllegalArgumentException("display name must be at most "
                + MAX_DISPLAY_NAME_LENGTH + " characters");
    }
    for (int i = 0; i < value.length(); i++) {
        char c = value.charAt(i);
        if (c != ' ' && (c < 0x20 || c == 0x7F)) {
            throw new IllegalArgumentException("display name has a control character at "
                    + (i + 1));
        }
    }
    return value;
}
```

### SEC-09: Password `char[]` not zeroed after verification; helper hashes stdin into an array it does not clear

**Severity:** Low
**CWE:** CWE-226: Sensitive Information in Resource Until Garbage Collected (with CWE-1188:
Insecure Default Initialization of Resource for the entry point)
**Location:** `src/main/java/portal/auth/PasswordHash.java:152`

**Vulnerable code:**

```java
// PasswordHash.java:118-123, 152-159
public boolean matches(char[] password) {
    try {
        byte[] digest = derive(password, salt, iterations);
        return MessageDigest.isEqual(digest, ...);
    } ...
}
...
private static byte[] derive(char[] password, byte[] salt, int iterations) {
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
    try {
        return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
    } ...
}
```

```java
// PasswordHash.java:200-206 — the record-generator entry point keeps its own array
byte[] line = System.in.readAllBytes();          // read the secret from stdin
char[] password = line == null ? new char[0] : line.toCharArray();
```

**Why it is a problem.** The design intent is explicit and mostly honoured: `EmployeePortalApp`
zeroes every buffer it owns (`:100`, `:142`–`:143`, `:282`), and `derive` disposes of the
`PBEKeySpec` copy it creates. The gap is the array that `matches` receives: `derive` hands it to
`PBEKeySpec`, which retains its own copy of the characters for the life of the spec, and
`matches` returns without clearing either. After a sign-in, the plaintext password is left live in
(a) the caller's array, which the *caller* may or may not zero, and (b) the `PBEKeySpec`'s internal
`char[]`, which is only released when the spec is finalised. The consequence is a widened window
rather than a leak: an attacker who can already read process memory (a core dump, `ptrace`, a heap
dump enabled for diagnostics) recovers passwords that were typed minutes earlier, which is exactly
the exposure the module's zeroing discipline is otherwise careful about. The second site is worse
in one specific way: `PasswordHash.main` owns `password` outright — nobody else can clear it — and
never does, so the record generator leaves the secret in memory until the JVM exits, in a process
whose whole job is to print a hash to stdout where a shell `>` may redirect it into a file. The
module does keep the password out of argv and out of `String` concatenation, which is the important
part; this is the residue.

**Fix.** Erase the buffer in the one method through which every password passes verification, and
make the entry point clean up what it allocates.

```java
// PasswordHash.matches(): the module owns the erasure, so no caller has to remember it.
public boolean matches(char[] password) {
    try {
        byte[] candidate = derive(password, salt, iterations);
        return MessageDigest.isEqual(candidate, digest);
    } finally {
        java.util.Arrays.fill(password, '\0');   // PBEKeySpec's own copy is cleared in derive()
    }
}
```

```java
// PasswordHash.main(): the array is ours; erase it before printing, so the secret does not
// outlive the hash it produced.
char[] password = line == null ? new char[0] : line.toCharArray();
PasswordHash hash;
try {
    hash = create(password, new SecureRandom(), iterations);
} finally {
    java.util.Arrays.fill(password, '\0');
}
System.out.println(CredentialValidator.canonicalUsername(args[0]) + "\t\t" + hash.formatCanonical());
```

If erasure on verification is rejected because callers reuse the array, then narrow the API
instead of documenting the hazard — take the password once and hand back a value that cannot be
re-read:

```java
// Authenticator.login(): take ownership, guarantee erasure, and pass a copy down.
public LoginResult login(String rawUsername, char[] ownedPassword) {
    try {
        return loginCanonical(rawUsername, ownedPassword);
    } finally {
        java.util.Arrays.fill(ownedPassword, '\0');
    }
}
```

## 6. Verified Controls and Checks With No Finding

46 checks were raised across the six applied skills plus the general-knowledge areas; 27 came back
clean, and each is listed once below with the evidence that closed it. Three candidate findings
were withdrawn and are marked **[withdrawn]**.

**Password storage and hashing — clean.** PBKDF2-HMAC-SHA256 via `PBKDF2WithHmacSHA256`, never a
raw digest and never an encryption-of-password path (`PasswordHash.java:19`, `:155`). Default cost
100,000 rounds, above the OWASP-style 600k-for-HMAC-SHA-256 target in spirit for this reference
implementation and 100× the minimum it will *store*; documented constants at `PasswordHash.java:21`,
`:28`. 16-byte salt drawn from `SecureRandom` per record (`SALT_BYTES`/`KEY_BITS`, `:33`–`:34`,
salt material generated in `create`), so identical passwords produce different records; the
`fixed-salt-for-every-password` mutant in `tools/mutation-check.sh` is killed, confirming a shared
salt is detected. 256-bit derived key. The canonical record format carries the algorithm tag, so a
future migration can tell formats apart (`PasswordHash.java:19`), and `toString()` prints the tag
and cost but never the salt or digest.

**Stored-hash validation — clean.** Parsing is strict: tag must match, field count is exact,
Base64 is decoded with length checks against `SALT_BYTES`/`KEY_BITS`, cost must satisfy
`MIN_STORED_ITERATIONS <= iterations <= MAX_ITERATIONS`, and each failure is an
`IllegalArgumentException` that rejects *that file*, not a silent skip
(`PasswordHash.java:96`–`:117`; `TextFileCredentialStore.java:39`–`:52`). `AuthenticationTest.java:278`–`:288`
asserts a 1,000-round record and a 200,000,000-round record are both refused while 50,000 is
accepted. Duplicate usernames in the file are refused rather than last-write-wins.
`MAX_ITERATIONS` is a real control: it bounds the hashing a *file* can force this process to
perform, which is the CPU-exhaustion vector an unauthenticated file write would otherwise open.
**[withdrawn]** "attacker-chosen iteration count is a CPU-exhaustion vector" — rejected because the
same constant caps the abuse and the suite tests the ceiling.

**Comparison and timing — clean.** Verification is constant-time: `MessageDigest.isEqual` on the
recomputed digest (`PasswordHash.java:121`), with the rationale recorded in the javadoc at `:24`.
There is no plaintext comparison anywhere in `src/main`; the password is a `char[]` end to end and
never becomes a `String`. Enumeration resistance is enforced on both channels the attacker can
observe: wording, because `AuthResult` has three fixed messages and `EmployeePortalApp.java:96`
prints the generic one even on an unexpected exception; and timing, because every refusal path pays
one decoy PBKDF2 round (`Authenticator.java:68`, `:76`, `:82`, `:113`) at the same cost the store
uses. The suite measures it (`AuthenticationTest.java:327`–`:347`: observed fast/slow ratio 1.00,
threshold 3) and `skip-decoy-on-unknown-user` is a killed mutant.

**Input validation and canonicalisation — clean.** `canonicalUsername` rejects null, whitespace
other than the U+0020 it strips, leading/trailing spaces, control characters and `0x7F`, the
separator the records file uses, anything outside `[A-Za-z0-9._-]`, names with no letter or digit,
and names outside 3–64 characters, then case-folds with `Locale.ROOT`
(`CredentialValidator.java:31`–`:60`, `:99`–`:116`). The reserved names `quit`, `exit`, `help`,
`add`, `status`, `unlock` are refused, so a username cannot imitate a command at `:61` — the
degenerative form of SEC-01 is closed even though the authorisation gap is not. `validatePassword`
caps length at 256 (`:25`, `:73`) and rejects leading/trailing whitespace, `0x00`–`0x1F`/`0x7F`
(`:111`), and unpaired surrogates (`:93`) — a precise, documented choice: `PBEKeySpec` silently
maps an unpaired surrogate to `?` and truncates at a trailing NUL, so accepting either would create
two strings that hash the same. `stripSpaces` removes only U+0020, and the tab-specific test in the
suite proves a tab in a typed username is rejected rather than repaired (`trim()` semantics);
`trim-instead-of-strip-spaces` and `allow-trailing-nul-password` are both killed mutants.
**[withdrawn]** "whitespace canonicalisation creates a username collision" — no reachable pair
survives: everything `stripSpaces`/`toLowerCase` maps together is either rejected outright or was
already the same canonical name, so no aliasing is possible.

**Lockout semantics — clean (as a state machine; see SEC-01 for the authorisation gap).** State
lives in an `AtomicReference` and is advanced inside a `compareAndSet` retry loop
(`LoginAttemptTracker.java:78`–`:95`), so concurrent guesses cannot lose an increment or interleave
a reset; `AuthenticationTest.java:360`–`:372` fires 400 guesses over 8 threads and asserts a single
lockout. The clock is monotonic (`clock.instant()` on a `Clock` injected at `:30`, `:56`), so lock
windows cannot be moved by changing the wall clock, and the default window is 15 minutes after 5
failures (`:33`). A successful sign-in removes the counters (`:99`–`:101`) — verified, including
the mutant `success-forgets-to-reset`. The lockout is not bypassable by presenting the correct
password: `Authenticator.java:73`–`:79` checks the lock *before* the store lookup and the hash
comparison, so a locked account stays locked while it is being typed correctly, which is the
sequence the suite's scripted session walks through. The lock is time-bounded and self-clearing
(`current()` expires state), so this is a rate limit, not a denial-of-service switch — an attacker
cannot permanently disable a name.
**[withdrawn]** "per-name counters are a username-enumeration oracle" — rejected on the code:
counters exist for any syntactically valid name, unknown and known alike
(`Authenticator.java:84`–`:87`), and the console reports the same verdict either way; the residual
risk is the *count*, which is SEC-03, not existence.

**Lockout clearing correctness.** `unlock` canonicalises before removing state
(`LoginAttemptTracker.java:103`–`:105`), so a non-canonical spelling cannot leave a shadow entry
behind, and `LoginResult.locked(...)` clamps negative remaining time (`LoginResult.java:21`), so a
clock race cannot print a nonsense countdown; `lock-says-no-wait` is a killed mutant, meaning the
suite would catch the countdown being suppressed.

**Credential entry and secret hygiene — clean apart from SEC-09.** Passwords are read with
`Console.readPassword` whenever a terminal exists (`CredentialPrompter.java:43`), which does not
echo and hands back a `char[]`; the visible fallback is only chosen when `System.console()` is null
(`:82`) and is announced once, before the first prompt (`EmployeePortalApp.java:199`–`:205`), so no
secret is ever collected silently. Every owned buffer is zeroed in a `finally`: sign-in password
(`EmployeePortalApp.java:100`), both `add` confirmations (`:142`–`:143`), demo seeds (`:282`). The
record generator reads the secret from **stdin**, not argv (`PasswordHash.java:200`), keeping it out
of the process listing and shell history. No `String`, no `charBuffer.toString()`, no
`LogRecord` parameter carries a password anywhere in `src/main`.

**Console/credential separation in `add`.** `ask`/`askSecret` route through the prompter interface
(`EmployeePortalApp.java:178`–`:195`), and the hidden-vs-visible decision is made once at start-up
rather than per call, so a future caller cannot accidentally take the echoing branch.

**Session/token/authorisation surface.** No session, cookie, token, JWT or bearer credential exists
in this module, and nothing is cached about a successful sign-in beyond `LoginResult.success()`;
there is therefore no token lifetime, rotation, replay or logout surface to review, and
`PasswordHash` exposes no re-read of any secret. No network listener, no TLS stack and no HTTP
response exist, so transport security, CORS, headers and cookie attributes are not applicable
(`README.md` states this explicitly, and the code confirms it).

**Error handling — clean.** Unexpected exceptions inside the sign-in path collapse to the generic
refusal (`EmployeePortalApp.java:96`) and never to a stack trace or a partial success; malformed
records-file lines produce a `main`-level message naming the file, not the offending field, and the
process exits non-zero (`:261`–`:266`). `CredentialStore`/`Mutable` is a capability split in the
type system, and `EmployeePortalApp.java:115` degrades to a printed instruction rather than an
exception when the store is read-only.

**Business-logic and state-management checks — clean.** `EmployeeRecord`'s canonical constructor
rejects a non-canonical username (`:17`), closing "a record constructed around the validator"; the
`fromUsername`/`fromStoredRecord` factories hash once and never re-store a plaintext. `LoginResult`
is immutable with factory methods (`LoginResult.java:6`, `:13`–`:23`) — a *candidate* finding was
raised here, that an unlocked record exposes a constructor allowing an arbitrary verdict triple
such as `SUCCESS` with a lock flag, and **[withdrawn]** because every read site in `src/main` uses
the factories, no call site trusts a caller-supplied triple, and the record is never
deserialised or reflected over; it is recorded here as a hardening note only
(a sealed interface or package-private constructor would make the invariant enforced).
`AuthResult`'s three constants are the only verdicts (`AuthResult.java`), and
`TextFileCredentialStore`'s parser cannot be steered into a partial state by an embedded
`#`-comment or blank line inside a record, because the field count is checked exactly
(`:39`–`:44`).

**Mutation and test evidence.** `tools/mutation-check.sh` breaks 11 guards, including the decoy
round, the lock check, lock arithmetic off-by-one, `recordSuccess`'s reset, `trim` vs `strip`,
trailing-NUL acceptance, a fixed salt, a `--iterations 1` store, the lock message, `input.strip()`,
and a status oracle, and classifies each as killed / survived / error rather than merely "tests
pass". The suite runs without a test framework and asserts wording, exit codes and timing ratios on
a scripted CLI session (`AuthenticationTest.java:327`–`:358`), so the console behaviour this review
depends on is regression-tested. `samples/employees.txt` contains hashed records only — no
plaintext password, no trailing-newline ambiguity that would alter a hash. `build/` holds generated
`.class` files only and was excluded from source review.
