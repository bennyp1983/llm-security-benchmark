# Security Review: AuthenticationService (email/password login component)

## 1. Executive Summary

This folder contains a self-contained Java 17 email/password authentication component.
`AuthenticationService.java` is the product: it looks an e-mail address up in a SQL table, compares a
salted PBKDF2-HMAC-SHA256 digest against the stored value in constant time, and exposes a small CLI
(`login` and `add-user`) over JDBC. `AuthDoublesTest.java` exercises the same logic against proxy
`Connection`/`PreparedStatement` doubles, `AuthH2Test.java` exercises it against a real H2 server,
`schema.sql` defines the one table, `run-mutation-battery.py` breaks the program 30 ways to check the
suites notice, and `README.md` documents the design and its deliberate exclusions.

The core credential path is unusually well built for its size. Every SQL statement is a compile-time
constant with the address bound via `setString`, the digest comparison uses `MessageDigest.isEqual`,
equal-work padding hides "no such account" from response timing, denial text is identical for unknown
account and wrong password, database failures refuse login rather than falling open, and the DB
password comes only from an environment variable. The SQL-injection, credential-comparison and
fail-open classes of defect that this review exists to find are genuinely absent, and §6 records the
evidence.

Nine real issues remain, none of which is a remote unauthenticated compromise of the credential store:

1. **`PASSWORD_MIN = 1`** (`AuthenticationService.java:41`) — the component accepts a one-character
   password. Every downstream control (100 000 rounds, constant-time compare) protects a secret the
   user was allowed to make trivially guessable. This is the finding that matters most.
2. **No throttling or lockout anywhere in `authenticate()`** (`:68`–`:101`) — online guessing is
   unbounded. `README.md:200` states this is out of scope, but out of scope is not the same as safe,
   and the component ships as the whole authentication answer.
3. **`MIN_ITERATIONS = 1_000`** (`:340`) — a stored record hashed at one-tenth the policy cost of the
   `100_000` used at `:337` still logs in, so a single lazily-written record makes offline cracking of
   the whole table's worth of work ~100x cheaper per record.
4. **The test suite's H2 server is started with `-tcpAllowOthers -ifNotExists` and no password**
   (`AuthH2Test.java:578`–`:582`), with user `sa`/empty password everywhere, so any host that can
   reach the CI runner's ephemeral port can read and write the fixture table.

The remaining five are low-severity hygiene defects in secret cleanup (`register()` leaks the password
array on its two early-throw paths, contradicting its own javadoc), output neutralization (the raw
address is printed in a prompt before it is validated), cleartext residue (immutable `String` when
standard input is redirected, plaintext `--stdin-file`), and an account-existence oracle on `add-user`.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `AuthenticationService.java` (586 lines) | The component: login + `add-user` over JDBC, plus CLI entry point. | SQL statement construction and parameter binding (`:34`, `:37`, `:109`–`:112`, `:142`–`:146`); password policy (`:41`–`:42`, `:231`–`:249`); PBKDF2 parameters and acceptance range (`:336`–`:341`, `:362`–`:392`); constant-time compare (`:388`); secret wiping (`:76`, `:84`, `:94`, `:99`, `:139`); timing padding (`:53`, `:114`, `:117`, `:400`–`:404`); error and prompt output (`:451`, `:454`, `:461`, `:487`–`:497`); DB credential source (`:444`, `:564`–`:566`); `--stdin-file` (`:521`, `:574`–`:578`). |
| `AuthH2Test.java` (661 lines) | End-to-end suite against a real H2 TCP server on an ephemeral port. | Starts the server process (`:577`–`:595`); empty-password `sa` connections (`:55`, `:187`, `:261`, `:507`, `:537`, `:547`, `:559`); a deliberately injectable lookup used as a positive control (`:184`–`:194`); hardcoded fixture passwords (`:41`, `:43`, `:214`); writes a fixture password to a plaintext file (`:357`). |
| `AuthDoublesTest.java` | Unit-style suite using proxy `Connection`/`PreparedStatement` doubles that record statement text and bound values. | Asserts statement text never contains the address; documents that only the round-count floor guards a low-cost record (`:209`). No production attack surface. |
| `schema.sql` | One table, `users`. | `password_hash VARCHAR(1024)` prevents silent truncation of a valid digest; `CONSTRAINT users_email_unique UNIQUE (email)` is the mechanism behind the `add-user` existence oracle. |
| `run-mutation-battery.py` | Mutation testing: applies one defect at a time, recompiles, reruns both suites. | Documents intended security invariants as mutant names (`sql-raw-concat`, `register-email-concat`, `iterations-set-to-one`, `round-count-floor-lowered-to-100`, `digest-arrays-equals`, `stored-digest-logged-on-refusal`, `query-text-logged-with-value`) and argues four survivors are equivalent. Useful as the authors' own threat model. |
| `README.md` | Design rationale and limits. | States the component does not rate-limit or lock accounts (`:200`), creates no sessions (`:202`), does not migrate credentials (`:204`), leaves TLS to the JDBC URL (`:210`), and warns not to run the test database server "in anger" (`:351`). |
| `prompt.txt`, `cyber_prompt.txt`, `prompt_hash.txt`, `return.txt`, `result.md` | Harness artifacts that produced and recorded this code (`return.txt` is a 1.2 MB build transcript). | Not application code. Reviewed for secret leakage only: no credentials, tokens, or keys found. |
| `build/` | `javac` output (`.class` files). | Derived artifacts; regenerated by the build, nothing to review in place. |

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: entry point for the whole review — established what
  `AuthenticationService.java` actually does (lookup → PBKDF2 verify → `AuthResult`), then selected the
  specialised skills below from the library rather than reviewing on generalities alone.
- `exploiting-sql-injection-vulnerabilities`: applied to `SELECT_BY_EMAIL` (`:34`) and `INSERT_USER`
  (`:37`) and their only two call sites (`:109`–`:112`, `:142`–`:146`); searched the folder for
  `Statement`/`createStatement`/`+` concatenation into SQL; checked stacked-query and error-based
  leakage paths; identified the one concatenated query in `AuthH2Test.java:186` as an intentional
  in-test positive control, and the driver-text suppression comment at `:460` as a deliberate
  error-based-injection mitigation.
- `performing-cryptographic-audit-of-application`: applied to the `Passwords` class (`:334`–`:430`) —
  algorithm choice, salt length and entropy source, digest length, iteration policy versus the
  acceptance range at `:379`, `PBEKeySpec` NUL/surrogate non-injectivity handling at `:236`–`:248`,
  constant-time comparison at `:388`, and the `DUMMY_SALT`/`System.nanoTime()` padding material at
  `:408` and `:256`.
- `testing-api-authentication-weaknesses`: applied to the authentication surface of `authenticate()`
  (`:68`–`:101`) — Step 6 weak-password probe (a one-character password is accepted), missing
  brute-force throttling, denial-message uniformity, account-enumeration channels (timing via
  `DUMMY_HASH`, existence via `add-user`), and token/secret handling across the CLI boundary.
- `performing-hash-cracking-with-hashcat`: applied to the stored record format
  `pbkdf2-sha256$<iterations>$<base64 salt>$<base64 digest>` (`:342`, `schema.sql` header) to price an
  offline attack: after a trivial field reorder the record is consumable by hashcat `-m 10900`
  (PBKDF2-HMAC-SHA256) or John the Ripper's `pbkdf2-hmac-sha256`, which is what makes the 1 000-round
  floor in SEC-03 a ~100x discount rather than a theoretical one.
- `implementing-secret-scanning-with-gitleaks`: applied as the secret-detection checklist (its rules
  for what constitutes a findable secret and what belongs on an allowlist) rather than by running the
  binary, since no VCS history was requested. Outcome: the only literal secrets in the folder are
  documented test fixtures (`AuthH2Test.java:41`, `:43`, `:214`), and `DB_PASSWORD` is read from the
  environment only (`:564`–`:566`) with `--password` refused as an unknown argument.
- `exploiting-server-side-request-forgery`: searched for URL/URI fetching driven by input — the
  program makes no HTTP or URL requests; the only URL-shaped value is an operator-supplied `--jdbc`
  URL used at `:444`. No matching behaviour, so no finding (see §6).

No skill in the library matched the following behaviours, so they were judged against general OWASP
Top 10 / CWE knowledge: output neutralization for a terminal and log consumer (CWE-117, SEC-06);
incomplete cleanup and cleartext residue of a credential in memory (CWE-459, CWE-316, SEC-05, SEC-07);
cleartext storage of a password in a file created for non-interactive login (CWE-313, SEC-09);
observable response discrepancy disclosing account existence (CWE-204, SEC-08); unclosed stream on a
cached reader (CWE-772, noted in SEC-09); and network exposure of an unauthenticated development
database (CWE-284 with CWE-200 impact, SEC-04).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Password policy accepts a single character | High | CWE-521 | `AuthenticationService.java:41` |
| SEC-02 | No rate limiting or lockout on authentication attempts | High | CWE-307 | `AuthenticationService.java:68` |
| SEC-03 | KDF accepts records at one-hundredth of the policy cost | Medium | CWE-916 | `AuthenticationService.java:340` |
| SEC-04 | Test H2 server exposed to other hosts with no password | Medium | CWE-284 | `AuthH2Test.java:578` |
| SEC-05 | `register()` leaves the password unwiped on its early-throw paths | Low | CWE-459 | `AuthenticationService.java:130` |
| SEC-06 | Unvalidated e-mail address printed to the terminal before validation | Low | CWE-117 | `AuthenticationService.java:451` |
| SEC-07 | Redirected stdin materialises the password in an immutable `String` | Low | CWE-316 | `AuthenticationService.java:495` |
| SEC-08 | `add-user` discloses whether an account exists | Low | CWE-204 | `AuthenticationService.java:454` |
| SEC-09 | Non-interactive login requires the password in a plaintext file | Low | CWE-313 | `AuthenticationService.java:575` |

## 5. Detailed Findings

### SEC-01: Password policy accepts a single character

**Severity:** High
**CWE:** CWE-521: Weak Password Requirements
**Location:** `AuthenticationService.java:41` (enforced at `:233`–`:235`)

**Vulnerable code:**

```java
// AuthenticationService.java:39-43
    static final int EMAIL_MAX = 254;
    static final int EMAIL_LOCAL_MAX = 64;
    static final int PASSWORD_MIN = 1;
    static final int PASSWORD_MAX = 1024;
    private static final int QUERY_TIMEOUT_SECONDS = 5;
```

```java
// AuthenticationService.java:231-235
    static void requireUsablePassword(char[] password) throws InvalidInputException {
        String invalid = "Please enter a password that can be used as typed.";
        if (password == null || password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
            throw new InvalidInputException(invalid);
        }
```

**Why it is a problem:** `PASSWORD_MIN = 1` means the only length requirement is "not empty", so
`register()` will happily store a digest of `a`. Everything else in the design — 100 000 PBKDF2
rounds, a 16-byte `SecureRandom` salt, a constant-time comparison — exists to make guessing hard, and
is defeated at the door for any account whose owner typed one character. `requireUsablePassword()`
goes on at length (and correctly) about NUL bytes and unpaired surrogates, which are exotic, while
allowing the single most exploited weakness in authentication. `README.md:69` shows the same care
elsewhere, so this reads as a permissive-by-default value that was never raised rather than a policy
decision. NIST SP 800-63B §5.1.1.2 sets a minimum of 8 characters for user-chosen secrets; OWASP ASVS
V2.1-1 recommends 12 for user passwords. An unbounded maximum is right (1024 is kept), and no
composition rules are needed — but a real minimum is.

**Fix:** Raise the floor to the policy minimum and keep the ceiling, and reject a length-only pass in
`register()` so a caller cannot store a known-breached secret.

```java
// AuthenticationService.java (replacement for :41 and :231-235)
    static final int PASSWORD_MIN = 12;
    static final int PASSWORD_MAX = 1024;

    static void requireUsablePassword(char[] password) throws InvalidInputException {
        String invalid = "Please enter a password that can be used as typed.";
        if (password == null || password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
            throw new InvalidInputException(invalid);
        }
        // ... unchanged: NUL/0x7F rejection and surrogate-pair validation ...
    }
```

`authenticate()` should keep accepting any length it is handed (a legacy record may have been created
under the old floor) so tightening registration does not lock existing accounts out.

### SEC-02: No rate limiting or lockout on authentication attempts

**Severity:** High
**CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts
**Location:** `AuthenticationService.java:68`–`:101`

**Vulnerable code:**

```java
// AuthenticationService.java:80-101
        String storedHash;
        try {
            storedHash = lookupPasswordHash(normalizedEmail);
        } catch (SQLException dbFailed) {
            wipe(password);
            System.err.println("login: database unavailable ("
                    + dbFailed.getClass().getSimpleName() + "), refusing login");
            return AuthResult.unavailable();
        }

        boolean ok;
        try {
            ok = Passwords.matches(password, storedHash);
        } catch (RuntimeException unverifiable) {
            wipe(password);
            System.err.println("login: stored credential could not be verified ("
                    + unverifiable.getClass().getSimpleName() + "), refusing login");
            return AuthResult.unavailable();
        }
        wipe(password);
        return ok ? AuthResult.success() : AuthResult.denied();
    }
```

**Why it is a problem:** `authenticate()` is stateless: every call performs exactly one lookup and one
digest and then forgets everything. There is no counter, no back-off, no lockout, and no per-source
throttle anywhere in the file, so an attacker who can reach the login path may guess as often as the
database and CPU allow, and the 100 000 rounds become the *only* cost of a guess. Combined with
SEC-01, a one-character or short password is found in seconds. `README.md:200` acknowledges this —
"It does not rate-limit, lock accounts, or refuse repeated guesses. Add that at the layer above" — but
the folder ships a CLI whose `main()` is the entire consumer, so in the delivered configuration there
is no layer above to add it to. Deferring a control to a hypothetical caller is a scope statement, not
a mitigation, and the `buildDummyHash()` work at `:48`–`:53` shows the authors cared about the
guessing budget enough to equalise timing while leaving the number of guesses unlimited.

**Fix:** Add persistent attempt accounting keyed on both account and source, and keep the digest cost
on the refusal path so the throttle is not itself a timing oracle for account enumeration.

```java
// AuthenticationService.java (guard inserted at the top of authenticate(), before :69)
    private final AttemptTracker attempts;   // injected, backed by the same database

    public AuthResult authenticate(String email, char[] password) {
        String normalizedEmail;
        try {
            normalizedEmail = normalizeEmail(email);
            requireUsablePassword(password);
        } catch (InvalidInputException bad) {
            wipe(password);
            return AuthResult.invalidInput(bad.getMessage());
        }
        if (attempts.isBlocked(normalizedEmail)) {
            // Same work as a real verification: a blocked answer must not be cheaper.
            Passwords.matches(password, DUMMY_HASH);
            wipe(password);
            return AuthResult.denied();
        }
        // ... existing lookup and verify ...
        if (!ok) {
            attempts.recordFailure(normalizedEmail);   // e.g. 5 failures -> 15 min back-off
        } else {
            attempts.clear(normalizedEmail);
        }
        wipe(password);
        return ok ? AuthResult.success() : AuthResult.denied();
    }
```

### SEC-03: KDF accepts records at one-hundredth of the policy cost

**Severity:** Medium
**CWE:** CWE-916: Use of Password Hash With Insufficient Computational Effort
**Location:** `AuthenticationService.java:340` (gate at `:379`–`:384`)

**Vulnerable code:**

```java
// AuthenticationService.java:336-341
        static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        static final int ITERATIONS = 100_000;
        static final int SALT_BYTES = 16;
        static final int DIGEST_BYTES = 32;
        private static final int MIN_ITERATIONS = 1_000;
        private static final int MAX_ITERATIONS = 5_000_000;
```

```java
// AuthenticationService.java:379-384
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS
                    || salt.length < 8 || salt.length > 64
                    || expected.length != DIGEST_BYTES) {
                digestQuietly(password);
                return false;
            }
```

**Why it is a problem:** `hash()` always writes `ITERATIONS = 100_000`, but `matches()` accepts any
stored record whose round count is at least 1 000, and the login succeeds on it. A record written at
the accepted floor costs an offline attacker 100 times less to attack than one written by this code,
so one legacy or hand-inserted row is a 100x discount on that row's secret — and, because candidate
passwords are tested across a whole table, an incentive to attack the cheap rows first. The suite
itself records the risk: `AuthDoublesTest.java:209` comments that for such a record "only the
round-count guard stands between it and a working login" — accurate, and the guard is set 100x below
the cost the authors considered adequate. `MIN_ITERATIONS` presumably exists to keep old rows
verifiable (see `README.md:204`, "It does not migrate stored credentials"), which is the right
instinct expressed with the wrong number: the floor should be the policy cost, not a number below
which the record is indefensible.

**Fix:** Raise the floor to the cost actually in force and re-upgrade the record on a successful
login, so legitimate users are never refused and stale records disappear.

```java
// AuthenticationService.java:340 (floor = policy cost)
        private static final int MIN_ITERATIONS = 100_000;
```

```java
// AuthenticationService.java (signal that a stored record needs re-upgrading, added to Passwords)
        static boolean matches(char[] password, String stored) {
            // ... parsing and the range check above, now with MIN_ITERATIONS = 100_000 ...
            boolean equal = MessageDigest.isEqual(expected, actual);
            if (equal && iterations < ITERATIONS) {
                throw new NeedsRehashException(stored);   // caller re-hashes and UPDATEs
            }
            return equal;
        }
```

### SEC-04: Test H2 server exposed to other hosts with no password

**Severity:** Medium (test scope; would be High in any deployed configuration)
**CWE:** CWE-284: Improper Access Control (with CWE-200: Exposure of Sensitive Information)
**Location:** `AuthH2Test.java:578`–`:582` (connections at `:55`, `:187`, `:261`, `:507`, `:537`, `:547`, `:559`)

**Vulnerable code:**

```java
// AuthH2Test.java:578-582
        // -ifNotExists lets this throwaway server create the in-memory database on first
        // connection; it listens on a random port for the length of one test run.
        ProcessBuilder builder = new ProcessBuilder("java", "-cp",
                Paths.get(jar).toAbsolutePath().toString(), "org.h2.tools.Server", "-tcp",
                "-tcpPort", String.valueOf(port), "-tcpAllowOthers", "-ifNotExists");
```

```java
// AuthH2Test.java:55
        try (Connection c = DriverManager.getConnection(jdbcUrl, "sa", "")) {
```

**Why it is a problem:** `-tcpAllowOthers` makes the H2 TCP server bind to a routable interface
instead of loopback only, `-ifNotExists` lets a connecting client create a database by name, and
there is no `-tcpPassword` and no `-localOnly`/`-tcpListen` anywhere in the folder — a search for
`tcpPassword|localOnly|tcpListen` across all `.java` files returns nothing. The single database
account is `sa` with an empty password. So for the lifetime of a test run, any process or host that
can reach the runner's ephemeral port gets unauthenticated read-write SQL over the fixture table,
which contains the fixture digests plus the plaintext `--stdin-file` artifact written at `:357`, and on
a shared CI host also allows arbitrary database creation on the runner. `README.md:351` warns "do not
run a database server that way in anger", which is correct as far as it goes, but the code is what
people copy; the exposure should be impossible to reproduce by accident rather than commented against.

**Fix:** Bind to loopback and set a server password, pre-creating the database so `-ifNotExists` can
be dropped.

```java
// AuthH2Test.java:580-582 (replacement)
        ProcessBuilder builder = new ProcessBuilder("java", "-cp",
                Paths.get(jar).toAbsolutePath().toString(), "org.h2.tools.Server", "-tcp",
                "-tcpPort", String.valueOf(port), "-tcpListen", "127.0.0.1",
                "-tcpPassword", SERVER_PASSWORD);
```

```java
// AuthH2Test.java (matching client side: the TCP password is separate from the schema password)
    private static final String SERVER_PASSWORD =
            System.getProperty("h2.tcp.password", "test-only-not-a-secret");
    // JDBC URL carries the server password too:
    //   jdbc:h2:tcp://127.0.0.1:<port>/mem:authsuite;DB_CLOSE_DELAY=-1;TCP_PASSWORD=<SERVER_PASSWORD>
```

### SEC-05: `register()` leaves the password unwiped on its early-throw paths

**Severity:** Low
**CWE:** CWE-459: Completion Mediation Not Performed ("Incomplete Cleanup"), with CWE-316: Cleartext
Persistence of Sensitive Information in Memory
**Location:** `AuthenticationService.java:130`–`:140`

**Vulnerable code:**

```java
// AuthenticationService.java:129-140
    /** Inserts a new account. {@code password} is wiped by this method. */
    public void register(String email, char[] password) throws SQLException, InvalidInputException {
        String normalizedEmail = normalizeEmail(email);
        requireUsablePassword(password);
        String stored;
        try {
            stored = Passwords.hash(password);
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("cannot create credentials", unavailable);
        } finally {
            wipe(password);
        }
```

**Why it is a problem:** The javadoc promises the array is always wiped, and `authenticate()` honours
exactly that promise on all four of its exits (`:76`, `:84`, `:94`, `:99`). `register()` does not:
`normalizeEmail(email)` at `:131` and `requireUsablePassword(password)` at `:132` can both throw
`InvalidInputException` before the `try`/`finally` that performs the wipe at `:138`–`:139` is ever
entered, so on those paths the caller's cleartext password survives in the array. The only in-tree
caller, `main()`, never wipes the array itself — it takes the reference at `:451` and hands it once to
`register()` — so a rejected `add-user` (bad e-mail, or a password containing a control character)
leaves the typed secret resident in the JVM heap until garbage collection, with nothing zeroing it.
`PASSWORD_MIN = 1` (SEC-01) means the length check rarely fires, but the address check fires often,
and it is the address that arrives first at `:131` — so the common mistyped-address case is precisely
the case that leaks. This is a real defect against the class's own documented contract, not a style
preference.

**Fix:** Widen the `finally` so it covers validation, which makes the javadoc true.

```java
// AuthenticationService.java:130-140 (replacement)
    /** Inserts a new account. {@code password} is wiped by this method. */
    public void register(String email, char[] password) throws SQLException, InvalidInputException {
        try {
            String normalizedEmail = normalizeEmail(email);
            requireUsablePassword(password);
            String stored;
            try {
                stored = Passwords.hash(password);
            } catch (GeneralSecurityException unavailable) {
                throw new IllegalStateException("cannot create credentials", unavailable);
            }
            try (Connection connection = connectionFactory.open();
                 PreparedStatement statement = connection.prepareStatement(INSERT_USER)) {
                statement.setQueryTimeout(QUERY_TIMEOUT_SECONDS);
                statement.setString(1, normalizedEmail);
                statement.setString(2, stored);
                statement.executeUpdate();
            }
        } finally {
            wipe(password);
        }
    }
```

### SEC-06: Unvalidated e-mail address printed to the terminal before validation

**Severity:** Low
**CWE:** CWE-117: Improper Output Neutralization for Logs (terminal/console injection)
**Location:** `AuthenticationService.java:451` (printed at `:493`; also `:454`)

**Vulnerable code:**

```java
// AuthenticationService.java:449-454
                String address = options.email != null
                        ? options.email : readLine(options, "Email address: ");
                char[] password = readPassword(options, "New password for " + address + ": ");
                try {
                    service.register(address, password);
                    System.out.println("Registered " + address + ".");
```

**Why it is a problem:** The prompt at `:451` interpolates the raw, still-unvalidated address, and
`readPassword()` writes it out with `System.out.print(prompt)` at `:493` (the non-`Console` branch)
before any validation happens. `normalizeEmail()`'s control-character rejection at `:177` runs later,
inside `register()`, so the bytes have already reached the display. An address supplied via `--email`
— from a script, a ticket, a copy-pasted note, or an import file — carrying `0x1B` (ESC) or a
CSI sequence can move the cursor, clear the screen, set the window title, or overwrite the line the
user is about to type into, which is a direct prompt-manipulation path in an interactive credential
prompt. If standard output is captured (a CI log, a session recorder, `script(1)`), the escape bytes
are persisted and replayed to whoever reads the log later, which is the classic CWE-117 terminal/log
scenario. The success echo at `:454` is the milder case: it prints the raw string rather than the
normalised one, so it differs from the value actually stored (leading/trailing spaces), but by then
`register()` has rejected control characters, so it cannot inject. The component already treats output
discipline as a security control — see the deliberate suppression of driver text at `:460` — so the
asymmetry with the prompt is an oversight.

**Fix:** Neutralise control characters in the display copy, and prefer echoing the normalised address.

```java
// AuthenticationService.java:451 and :454 (replacement)
                char[] password = readPassword(options, "New password: ");   // no caller data in the prompt
                try {
                    service.register(address, password);
                    System.out.println("Registered " + displaySafe(address) + ".");
```

```java
// AuthenticationService.java (new helper next to wipe())
    /** Strips control characters from anything echoed back to an operator's terminal or log. */
    static String displaySafe(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            out.append(c < 0x20 || c == 0x7F ? ' ' : c);
        }
        return out.toString();
    }
```

### SEC-07: Redirected stdin materialises the password in an immutable `String`

**Severity:** Low
**CWE:** CWE-316: Cleartext Persistence of Sensitive Information in Memory
**Location:** `AuthenticationService.java:495`–`:496`

**Vulnerable code:**

```java
// AuthenticationService.java:487-497
    private static char[] readPassword(CliOptions options, String prompt) throws IOException {
        Console console = System.console();
        if (console != null) {
            char[] secret = console.readPassword(prompt);
            return secret == null ? new char[0] : secret;
        }
        System.out.print(prompt);
        System.out.flush();
        String line = options.input().readLine();
        return line == null ? new char[0] : line.toCharArray();
    }
```

**Why it is a problem:** The interactive branch is careful — `Console.readPassword` returns a
`char[]` that `authenticate()`/`register()` overwrite. The redirected branch is not: `readLine()`
returns an immutable `String`, which cannot be zeroed by any caller, and it is produced through a
`BufferedReader` (`:578`) that also holds the line in its internal `char[]` buffer. The `char[]`
handed to `register()` is a *copy* (`line.toCharArray()`), so wiping it — which `register()` does, per
SEC-05's fix — leaves the original characters intact in the `String` and in the reader's buffer,
where they stay reachable until collection and may land in a swap file or a heap dump. The javadoc
above `readPassword` reasons correctly about not trimming a trailing space and concludes "there is
nothing to hide it from" when input is redirected; that is true of *shoulder surfing* but not of
*memory residue*, which is the residue the rest of the file works to remove.

**Fix:** Read the redirected line as bytes and build the `char[]` directly, clearing the scratch
buffer, and read line-at-a-time rather than through a buffering reader for the secret.

```java
// AuthenticationService.java:495-496 (replacement)
        System.out.print(prompt);
        System.out.flush();
        return readRawLine(options.inputStream());   // byte-wise; no String, no BufferedReader
    }

    /** Reads one line into a char[] with no intermediate String or read-ahead buffer. */
    static char[] readRawLine(InputStream in) throws IOException {
        char[] buf = new char[1025];
        int n = 0;
        int c;
        while ((c = in.read()) != -1 && c != '\n') {
            if (n < buf.length - 1) {
                buf[n++] = (char) (c & 0xFF);
            }
        }
        char[] out = Arrays.copyOf(buf, n);
        Arrays.fill(buf, (char) 0);
        return out;
    }
```

### SEC-08: `add-user` discloses whether an account exists

**Severity:** Low
**CWE:** CWE-204: Observable Response Discrepancy
**Location:** `AuthenticationService.java:454` (contrasting branch at `:459`–`:462`)

**Vulnerable code:**

```java
// AuthenticationService.java:452-462
                try {
                    service.register(address, password);
                    System.out.println("Registered " + address + ".");
                } catch (InvalidInputException bad) {
                    System.out.println(bad.getMessage());
                    System.exit(2);
                    return;
                } catch (SQLException taken) {
                    // Driver text can echo the statement, so only the class is reported.
                    System.out.println("Could not register that email address ("
                            + taken.getClass().getSimpleName() + ").");
```

**Why it is a problem:** A successful insert prints `Registered <addr>.` while a violation of
`CONSTRAINT users_email_unique` (schema.sql) prints `Could not register that email address
(SQLIntegrityConstraintViolationException).`, and the process exit code differs (0 versus 1). Any
caller of `add-user` can therefore enumerate which addresses already have accounts, one line of output
per probe. The design elsewhere goes out of its way to close exactly this channel on the login path —
`DUMMY_HASH` at `:53` burns a full digest so "no such account" is not measurably faster, and denial
text is identical for unknown account and wrong password — so the registration path is the one place
the oracle reopens. Severity is Low rather than Medium because reaching this path requires the
database write credentials that `--jdbc`/`--user`/`DB_PASSWORD` supply (`:444`, `:564`), and anyone
holding those can query the table directly; the realistic exposure is a wrapper that exposes
`add-user` more widely than it exposes the database.

**Fix:** Print one indistinguishable line for both outcomes and reserve the distinction for an
operator-only diagnostic switch.

```java
// AuthenticationService.java:452-463 (replacement)
                try {
                    service.register(address, password);
                    System.exit(0);
                } catch (InvalidInputException bad) {
                    System.out.println(bad.getMessage());
                    System.exit(2);
                    return;
                } catch (SQLException taken) {
                    // Same text and same exit code as success: this path must not confirm
                    // that the address already has an account.
                    System.out.println("Registration request processed for " + displaySafe(address) + ".");
                    System.exit(0);
                }
                System.out.println("Registration request processed for " + displaySafe(address) + ".");
```

(If scripts genuinely need to know whether the insert happened, gate that behind an explicit
`--report-duplicates` flag that is off by default and documented as an enumeration channel.)

### SEC-09: Non-interactive login requires the password in a plaintext file

**Severity:** Low
**CWE:** CWE-313: Cleartext Storage in a File or on Disk (with CWE-772: Missing Release of Resource)
**Location:** `AuthenticationService.java:575`–`:577` (option declared at `:521`, parsed at `:539`)

**Vulnerable code:**

```java
// AuthenticationService.java:574-578
    BufferedReader input() throws IOException {
        InputStream source = stdinFile != null
                ? new FileInputStream(stdinFile)
                : System.in;
        input = new BufferedReader(new InputStreamReader(source, StandardCharsets.UTF_8));
```

```java
// AuthH2Test.java:357
        Files.write(stdinFile, (ALICE + "\n" + ALICE_PW + "\n").getBytes(StandardCharsets.UTF_8));
```

**Why it is a problem:** `--stdin-file` is the documented way to log in without a terminal, so using
it at all means putting the account password into an ordinary file — created with the process umask's
default permissions (typically world-readable, `0644`) and left on disk afterwards, as the suite
itself demonstrates at `AuthH2Test.java:357`. Any local user, any backup job, and any container image
layer that captures that path now holds a credential, which is exactly the exposure `Console`-based
prompting and `DB_PASSWORD`-only handling exist to avoid — the design is careful about not putting the
*database* password on the command line (`README.md:69`) while offering a flag that puts the *account*
password on disk. The file is also chosen by path with no restriction, so a wrapper that forwards a
caller-controlled value here turns the CLI into an arbitrary-file reader (its contents are not echoed,
but the login result becomes an oracle on file contents). Separately, the `BufferedReader` cached at
`:583` is never closed, so the descriptor stays open for the process lifetime — harmless for a
short-lived CLI, a leak for anything that embeds this class.

**Fix:** Prefer a descriptor or environment source for non-interactive use; if a file must be kept,
require tight permissions, refuse to proceed without them, and close the reader.

```java
// AuthenticationService.java:574-579 (replacement)
    BufferedReader input() throws IOException {
        InputStream source;
        if (stdinFile != null) {
            Path p = Path.of(stdinFile);
            if (!Files.getPosixFilePermissions(p).equals(
                    Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))) {
                throw new IOException(stdinFile + " must be mode 600 to be used as an input file");
            }
            source = new FileInputStream(p.toFile());
        } else {
            source = System.in;
        }
        input = new BufferedReader(new InputStreamReader(source, StandardCharsets.UTF_8));
        return input;
    }

    void closeInput() throws IOException {
        if (input != null) {
            input.close();
            input = null;
        }
    }
```

## 6. Verified Controls and Checks With No Finding

- **SQL injection (`AuthenticationService.java`)** — reviewed with
  `exploiting-sql-injection-vulnerabilities`. Both statements are `static final` compile-time
  constants (`:34`, `:37`); the predicate is a single equality with no `LIKE`, `IN`, `ORDER BY` or
  identifier position that could need concatenation; both values are bound with `setString`
  (`:111`, `:144`–`:145`); there is no `createStatement` anywhere in the service, so there is no path
  that accepts raw text; `setQueryTimeout(5)` (`:110`, `:143`) bounds slow injected work; only the
  first row is consumed. `AuthDoublesTest` records statement text to prove the address never appears
  in it, and the CLI test at `AuthH2Test.java:389` runs `--email "x' OR '1'='1"` against the real
  database and expects refusal. The service's own `README.md:122` correctly notes there is no
  `Statement.execute` path that would accept two semicolon-separated statements. **No finding.**
- **Deliberate concatenation in the test suite** (`AuthH2Test.java:184`–`:194`) — `vulnerableLookup`
  does build SQL by `+` and calls `createStatement`, but it exists only to prove the injection test
  would fail if the service ever regressed (a positive control); it is never reachable from
  `AuthenticationService`. **No finding**, and it should not be removed.
- **Error-based information leakage** — `SQLException` text and stack traces are never printed:
  `:85`–`:86` and `:461`–`:462` print `getClass().getSimpleName()` only, with the comment at `:460`
  recording why. Login denial text is uniform, and `AuthH2Test.java:318`–`:319` asserts the password
  is never echoed back. **No finding.**
- **Password hashing and comparison** — reviewed with `performing-cryptographic-audit-of-application`.
  `PBKDF2WithHmacSHA256` (`:336`), 16-byte salt from `SecureRandom` (`:338`, `:349`), 32-byte digest
  (`:339`), 100 000 rounds for new records (`:337`), format is self-describing so parameters travel
  with the record, `salt.length` and `expected.length` and a maximum round count are all validated
  before use (`:379`–`:381`), and comparison uses `MessageDigest.isEqual` (`:388`) rather than
  `Arrays.equals`/`String.equals`. `PBEKeySpec` cannot encode NUL or unpaired surrogates, and
  `requireUsablePassword` rejects exactly those characters (`:236`–`:248`) so two different inputs
  cannot digest identically. **No finding** (the accepted-round floor is SEC-03).
- **Timing-based account enumeration** — a missing row returns `DUMMY_HASH` (`:114`, `:117`) built at
  class load from a random salt and the real round count (`:252`–`:262`), and a malformed stored
  record triggers `digestQuietly` (`:365`, `:376`, `:382`, `:400`–`:404`) so a rejected answer costs
  the same as a verified one. `DUMMY_SALT` (`:408`) and the `System.nanoTime()` filler (`:256`) are
  padding material, not secrets — the security property is that the *salt is random and the work is
  real*, both of which hold. **No finding.**
- **Fail-open on infrastructure error** — a `SQLException` (`:83`–`:88`) or an unverifiable stored
  record (`:93`–`:98`) returns `AuthResult.unavailable()` and never `success()`; `buildDummyHash()`
  turns a missing PBKDF2 implementation into `ExceptionInInitializerError` (`:263`–`:266`) so the
  class refuses to load rather than accept logins. **No finding.**
- **Credential storage and CLI secret handling** — reviewed with
  `implementing-secret-scanning-with-gitleaks`'s checklist. Only the digest is stored
  (`schema.sql`, `INSERT_USER`); `DB_PASSWORD` is read from the environment (`:564`–`:566`) with no
  default leaked; a `--password` flag is refused as `Unknown argument:` (`:545`), which `README.md:69`
  documents as intentional. Literal secrets are limited to documented test fixtures
  (`AuthH2Test.java:41`, `:43`, `:214`) chosen to share no substring so an echo test cannot pass by
  accident (`README.md:345`). No key, token, or production credential anywhere in the folder,
  including `return.txt`. **No finding.**
- **SSRF** — checked with `exploiting-server-side-request-forgery`; the program performs no URL or HTTP
  fetch and resolves no caller-supplied host. The only URL-shaped input is the operator-supplied
  `--jdbc` value used at `:444`, which is an operator-trusted connection string, not attacker data, and
  `README.md:210` correctly makes TLS that connection's responsibility. **No matching behaviour, so no
  finding.**
- **Session management** — out of scope by design and correctly so: `authenticate()` returns a
  yes/no answer and mints no token or cookie (`README.md:202`). There is no session artifact to
  mis-issue. **No finding.**
- **Mutation battery as evidence** — `run-mutation-battery.py` includes `sql-raw-concat`,
  `register-email-concat`, `iterations-set-to-one`, `round-count-floor-lowered-to-100`,
  `digest-arrays-equals`, `stored-digest-logged-on-refusal` and `query-text-logged-with-value` among
  its 30 mutants, confirming the authors already treat those as security invariants the suites must
  catch. Its four `EQUIVALENT` survivors are argued, not silently accepted. This is a positive signal;
  note that `round-count-floor-lowered-to-100` being a *surviving-or-argued* case is consistent with
  SEC-03 — the floor's exact value is not pinned by any test.
