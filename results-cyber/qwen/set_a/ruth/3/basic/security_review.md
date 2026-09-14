# Security Review: UserAccountLookup (JDBC user-account lookup)

## 1. Executive Summary

The folder contains a small JDK-only Java 17 utility, `UserAccountLookup`, that resolves a username
supplied by a user to a row of the `users` table through an already-open JDBC `Connection`, plus two
verification harnesses (`UserAccountLookupTest`, a driver-free `Proxy`-based double, and
`UserAccountLookupH2Test`, an end-to-end run against in-memory H2) and a `README.md` that documents
the behaviour, the expected schema and the build/run commands.

The headline question — *can the user-controlled username reach the SQL text?* — answers **no**, and
that is genuinely well built: the SQL is a compile-time constant with a single `?` placeholder
(`UserAccountLookup.java:34-36`), the value travels only through `setString` (`:66`), there is no
string concatenation anywhere near the statement, the column list is explicit and deliberately
excludes authentication material, and both harnesses assert the property (including a loop that runs
classic injection payloads against a real database engine). No SQL injection finding is raised.

The real weaknesses are all on the **trust boundaries around** the query, and none of them is
Critical or High:

* **SEC-01 (Medium)** — `DB_URL` is handed to `DriverManager.getConnection` verbatim
  (`UserAccountLookup.java:126-134`). A JDBC URL is not just a host and a database name: every
  mainstream driver parses connection properties out of it, and several of those properties
  (`INIT=`/`RUNSCRIPT`, H2 `AUTO_DESERIALIZE`, MySQL `autoDeserialize`/`allowLoadLocalInfile`/
  `queryInterceptors`, PostgreSQL `socketFactory`/`sslfactory`/`loggerFile`) mean "construct classes
  for me" or "read this file for me". If an attacker can influence that value, the parameterized
  query is irrelevant.
* **SEC-02 (Medium)** — `normalizeUsername` trims with `String.trim()` at read time only
  (`:86`, `:137`). The database decides what counts as "the same username" by its own
  collation/`VARCHAR` rules, and `README.md:178-179` explicitly hands that decision to the schema.
  The app's idea of equality and the index's idea of equality therefore disagree: an untrimmed
  sibling row (`'alice '`) is invisible to the unique index yet reachable from a lookup for `'alice'`.
* **SEC-03 (Low)** — the database password is delivered through an exported environment variable
  (`:134`, documented as the standard invocation at `README.md:89`).
* **SEC-04 (Low)** — unsanitised caller-supplied text and driver exception text are written to the
  console (`:137`, `:140`, `:142`, `:145`), which is a CRLF / ANSI-escape injection and
  information-disclosure surface; an uncaught `IllegalStateException` also dumps a stack trace
  outside the documented exit-code contract (`:72-75` vs `:141-147`).
* **SEC-05 (Low)** — `README.md:118` tells the reader to `curl` a third-party jar over HTTPS with no
  checksum, signature or provenance check, and `README.md:119-120` then executes it on the JVM class
  path.
* **SEC-06 (Low)** — identity-relevant input is neither Unicode-normalised nor case-normalised
  before it is treated as a primary identifier (`:86`), which lets visually distinct usernames resolve
  to one identity.

The shipped code is a *library + convenience CLI*, not a service: it has no authentication or
authorisation layer of its own (there is no caller authentication to test), no crypto, no HTML, no
outbound network calls, and the retrieved values never reach a second sink. Section 6 lists every
control that was exercised and passed.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| `UserAccountLookup.java` | Production code: one parameterized lookup `findByUsername(Connection, String)` plus a `main` CLI wrapper | SQL text and placeholder binding (`:34-36`, `:65-66`); username normalisation and length cap (`:82-94`); duplicate-row fail-closed check (`:72-75`); trust of the `DB_URL`/`DB_USER`/`DB_PASSWORD` environment (`:126-134`); console output of caller input, PII and driver error text (`:137-145`); stdin reading (`:150-156`); `UserAccount` record that intentionally carries no authentication material (`:173-179`) |
| `UserAccountLookupTest.java` | Driver-free verification harness (47 checks) built on `java.lang.reflect.Proxy` doubles | Proves the SQL never contains the username, the payload is delivered as a bound value, column labels (not positions) drive mapping, statement/result-set close order, caller connection left open; opens no real connection and is never shipped as a library |
| `UserAccountLookupH2Test.java` | End-to-end verification against real H2 2.2.224 in-memory (30 checks) | Real SQL parser + injection payload loop with a post-run table integrity check (`:119-135`); in-memory DB with `sa`/empty password (`:21`, `:30`); schema deliberately created **without** the unique index so the duplicate check can be exercised (`:158-166`); bcrypt-shaped non-secret fixture in the unread `password_hash` column (`:187`) |
| `README.md` | Behaviour contract, expected schema, build/run/verify instructions, claimed results | Documents the connection-URL/env-var credential invocation (`:88-89`); instructs an unverified third-party jar download that is then executed (`:118-120`); delegates collation, trailing-blank and case-sensitivity semantics to the schema (`:178-179`) |
| `prompt.txt` | The original generation task for this code (plain-text requirement) | Not code; no executable behaviour |
| `cyber_prompt.txt` | Copy of this security-review request | Not code; no executable behaviour |
| `result.md` | Report emitted by the prior code-generation run | Documentation; claims test/mutation results that were not re-run here |
| `return.txt` | Raw JSONL transcript of that prior run (~1 MB) | Not code; contains no credential material (the only literal resembling one is the H2 fixture in the test source) |
| `prompt_hash.txt` | Single SHA-256 digest of the prompt | Integrity metadata for the task harness, not a secret and not a code path |

Review of code and instruction files only; no file other than this report was created or modified,
and none of the harnesses or build commands were executed as part of the review.

## 3. Skills Applied

- `review-code-for-security-vulnerabilities`: the router followed for this review — enumerate the
  security-relevant behaviours, match them to sibling skill *names* first, skim only the matched
  `description` frontmatter, then open and apply one skill body at a time against the real code with
  `file:line` evidence. Its own "Report only" constraint is why nothing except this report was
  written; its library scripts were deliberately not executed because the target is Java.
- `exploiting-sql-injection-vulnerabilities`: applied to the statement construction
  (`UserAccountLookup.java:34-36`, `:65-66`) — checked for string concatenation/`String.format` into
  SQL, dynamic `ORDER BY`/`LIKE`/table/column identifiers, second placeholder misuse and
  allowlist-vs-escaping decisions. Only one static statement with one bound `?` exists.
- `performing-second-order-sql-injection`: applied to the result-handling path (`:96-104`,
  `:173-179`) — traced the retrieved `username`/`email`/`full_name`/`status` values for any later
  re-use in a statement, command, or file; they are only mapped into an immutable record.
- `exploiting-insecure-deserialization`: applied twice — (a) to the JDBC trust surface in SEC-01,
  because driver-side object construction (`AUTO_DESERIALIZE`, `autoDeserialize`,
  `queryInterceptors`) is a deserialization gadget reached through the URL rather than through
  `ObjectInputStream`; (b) as a sweep for Java-native sinks (`ObjectInputStream`,
  `readObject`, JNDI `InitialContext.lookup`, `readUnshared`) — none present.
- `implementing-secret-scanning-with-gitleaks`: applied to the whole folder for committed secret
  material — the bcrypt-shaped literal `UserAccountLookupH2Test.java:187`, the `sa`/empty-password
  H2 URL (`:21`, `:30`) and `DB_USER=sa DB_PASSWORD=secret` in `README.md:89`. Also supplied the
  allowlist/placeholder guidance used in Section 6.
- `implementing-secrets-management-with-vault`: applied to how database credentials reach the process
  (`UserAccountLookup.java:134`, `README.md:88-89`) — env-var exposure, rotation, and non-interactive
  secret retrieval.
- `performing-supply-chain-attack-simulation`: applied to the build/run instructions
  (`README.md:118-120`) — runtime fetch of a third-party artifact onto the class path, dependency
  pinning, and mirror/repo-swap substitution of that artifact.
- `verifying-build-provenance-with-slsa-sigstore`: applied as the integrity standard for that same
  download — no digest, detached signature or attestation is fetched or verified.
- `performing-cryptographic-audit-of-application`: applied to check for crypto misuse in scope
  (password hashing/verification, randomness, token/session/cookie handling, TLS configuration).
  There is none: the password hash is a column the query never selects (`:34-36`), so all of that
  skill's findings are not-applicable rather than passing.
- `testing-api-authentication-weaknesses`: no HTTP API exists, but its username-handling checks
  (case folding, whitespace and Unicode canonicalisation for an identity key, enumeration
  behaviour) were applied to SEC-02 and SEC-06.

Behaviours reviewed against general OWASP Top 10 / CWE knowledge because **no library skill matched
them**: trust of an externally-controlled JDBC connection string and its driver parameters
(CWE-20 / CWE-441 / CWE-502 surface); neutralisation of control, format and escape characters in
informational output (CWE-93 / CWE-117, ANSI/OSC terminal escape injection); information disclosure
through error output and stack traces (CWE-209 / CWE-778); and identity confusion arising from a
client-side vs database-side normalisation mismatch (CWE-436 / OWASP A07).

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Unvalidated `DB_URL` handed to `DriverManager.getConnection` (JDBC connection-argument trust) | Medium | CWE-20 | `UserAccountLookup.java:126-134` |
| SEC-02 | Read-time-only `trim()` disagrees with the database's username equality rules | Medium | CWE-436 | `UserAccountLookup.java:86` (`:137`, `README.md:178-179`) |
| SEC-03 | Database password transported through an exported environment variable | Low | CWE-526 | `UserAccountLookup.java:134` (`README.md:89`) |
| SEC-04 | Caller input, PII and driver error text written to the console unsanitised; uncaught `IllegalStateException` prints a stack trace | Low | CWE-117 | `UserAccountLookup.java:137` (`:140`, `:142`, `:145`, `:72-75`) |
| SEC-05 | Third-party jar downloaded and executed with no integrity or provenance verification | Low | CWE-494 | `README.md:118` (`README.md:119-120`) |
| SEC-06 | No Unicode/case canonicalisation of a primary identity key | Low | CWE-174 | `UserAccountLookup.java:82-94` |

## 5. Detailed Findings

### SEC-01: Unvalidated `DB_URL` handed to `DriverManager.getConnection`
- **Severity:** Medium
- **CWE:** CWE-20: Improper Input Validation (externally-controlled JDBC connection string whose
  embedded properties are interpreted by the driver)
- **Location:** `UserAccountLookup.java:126-134`

**Vulnerable code:**
```java
// UserAccountLookup.java:126-134
        String url = System.getenv("DB_URL");
        if (url == null || url.isBlank()) {
            System.err.println("DB_URL is not set, for example jdbc:h2:mem:app");
            System.exit(2);
            return;
        }

        try (Connection connection =
                     DriverManager.getConnection(url, System.getenv("DB_USER"), System.getenv("DB_PASSWORD"))) {
```

**Why it is a problem:** the guard only rejects *empty* values; the content is never examined before
`DriverManager` parses it and hands it to the first classpath driver that claims the scheme. A JDBC
URL is a property bag, not just an endpoint, and the properties that drivers accept inline are
execution primitives:

* H2: `INIT=<sql>` runs arbitrary SQL on connect and `RUNSCRIPT FROM '<url or file>'` loads and
  executes scripts — this is the classic H2/JDBC client-side RCE chain, and the H2 documentation
  itself warns that the URL must never come from an untrusted source. `AUTO_SERVER`,
  `TRACE_LEVEL_*` and `INIT=... SHUTDOWN` also change behaviour.
* MySQL/MariaDB: `autoDeserialize=true` plus
  `queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor` gives
  driver-side deserialization of the server's replies (so a malicious DB endpoint becomes the
  attacker), and `allowLoadLocalInfile` / `allowUrlInLocalInfile` let the *server* ask the client to
  send any local file — the URL sets the very flag that is meant to be opt-in.
* PostgreSQL: `socketFactory` / `sslfactory` instantiate an attacker-named class from the class path,
  `loggerFile` writes to an arbitrary path, and a URL may point the connection at a different host
  entirely.

Because `main` is a CLI, the natural assumption is "the operator owns the environment". That holds
only if `DB_URL` is never attacker-influenced — it is not in the common deployments where a job
runner, a CI variable, a container/env file, a config-management template, a `.env` file or a
wrapper service populates the environment from user-supplied values. The consequence is asymmetric:
the read query is safely parameterized, but the *connection* is a fully attacker-shapeable
driver-parameter surface. Note also that `System.out.println("DB_URL is not set, for example
jdbc:h2:mem:app")` (`:128`) advertises the URL format to anyone who can run the binary.

**Fix:** validate the URL against an explicit allowlist of targets *and* reject driver properties
before touching `DriverManager`; the strongest form pins the driver class so a rogue classpath
driver cannot claim the URL.

```java
    private static final List<String> ALLOWED_URL_PREFIXES =
            List.of("jdbc:postgresql://", "jdbc:mysql://", "jdbc:h2:mem:");

    /** Driver properties that turn a connection URL into code execution or local file read. */
    private static final List<String> FORBIDDEN_URL_PARAMETERS =
            List.of("init", "runscript", "autodeserialize", "allowloadlocalinfile", "allowurlinfile",
                    "allowurllinfile", "allowmultiqueries", "queryinterceptors", "statementinterceptors",
                    "socketfactory", "sslfactory", "loggerfile", "loggerlevel");

    static String validatedJdbcUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("DB_URL is not set");
        }
        String lower = url.toLowerCase(Locale.ROOT);
        if (ALLOWED_URL_PREFIXES.stream().noneMatch(lower::startsWith)) {
            throw new IllegalArgumentException("DB_URL uses an unsupported JDBC scheme");
        }
        if (FORBIDDEN_URL_PARAMETERS.stream().anyMatch(lower::contains)) {
            throw new IllegalArgumentException("DB_URL sets a JDBC driver property that is not permitted");
        }
        // Inline driver properties: ';' for H2, '?' for MySQL/PostgreSQL.
        if (lower.indexOf(';') >= 0 || lower.indexOf('?') >= 0) {
            throw new IllegalArgumentException("DB_URL must not carry inline JDBC properties");
        }
        return url;
    }
```
```java
        String url;
        try {
            url = validatedJdbcUrl(System.getenv("DB_URL"));
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            System.exit(2);
            return;
        }

        // Strongest form: talk to the pinned driver directly instead of DriverManager, so a driver
        // added to the class path cannot claim the URL and reinterpret its properties.
        try (Connection connection = new org.postgresql.Driver().connect(url, driverProperties())) {
            ...
        }
```
Keep the URL in a read-only, operator-owned config source (not a value derived from request data),
and document that `DB_URL` is a trusted-administrator input.

### SEC-02: Read-time-only `trim()` disagrees with the database's username equality rules
- **Severity:** Medium
- **CWE:** CWE-436: Interpretation Conflict (client-side vs database-side canonical form of an
  identity key); related to CWE-178 / OWASP A07
- **Location:** `UserAccountLookup.java:86` (also `:137`; contract statement at `README.md:178-179`)

**Vulnerable code:**
```java
// UserAccountLookup.java:82-86
    private static String normalizeUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username must not be null");
        }
        String trimmed = username.trim();
```

**Why it is a problem:** the value that the lookup actually searches for is `username.trim()` —
computed only here, at read time, and never written back. The database then applies *its* equality
rule (`users.username = ?` under the column's collation and `VARCHAR` semantics) to decide which row
matches, while `README.md:178-179` explicitly disclaims that decision:

```text
Trailing blank handling depends on the database's `CHAR`/`VARCHAR` semantics (H2's `VARCHAR`
does not pad). Case sensitivity depends on the column collation. Match the schema you deploy
against.
```

Three concrete consequences:

1. **Untrimmed siblings are reachable across identities.** The unique index is the control the
   duplicate check (`:72-75`) relies on, but `UNIQUE` does *not* consider `'alice '` and `'alice'` to
   be the same value under the default H2/PostgreSQL collations, so a registration path that stores
   the untrimmed value creates a row the index happily accepts. A lookup for `'alice'` — after the
   trim — matches the *victim's* row, and `findByUsername` hands back another identity's
   `id`/`email`/`fullName`/`status` while the caller believes it asked for its own string. A caller
   that uses "a row came back" as an existence or ownership decision (the obvious integration
   pattern for this API) now acts on a username it never validated.
2. **The trim is asymmetric with the write path.** Whatever created the row applied its own rule; a
   read-side-only transformation is the classic way an identity key gets two definitions. The
   README's own schema (`:79`, `:82-83`) contains no check that the *stored* form is already
   trimmed.
3. **Fail-closed protection depends on data this code does not create.** The `IllegalStateException`
   fires only when the query returns two rows — i.e. only for usernames that are *not* trimmed
   variants, exactly the mismatch above resolves silently.

Severity is Medium rather than High because exploitation needs a write path (outside this folder)
that stores untrimmed values, and because the leak is profile data, not credentials.

**Fix:** define the canonical username form in **one** place, use it on the write path as well as
here, and make the database's equality rule agree with it (deterministic collation + a constraint
that stored values are already canonical).

```java
    /** The single canonical form for usernames; the registration path must call this too. */
    public static String canonicalUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username must not be null");
        }
        // strip() is Unicode-aware; trim() only removes code points <= U+0020, so it leaves
        // NBSP (U+00A0) and ideographic space (U+3000) glued to the identity.
        String canonical = username.strip().toLowerCase(Locale.ROOT);
        if (canonical.isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        if (canonical.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException(
                    "username must not be longer than " + MAX_USERNAME_LENGTH + " characters");
        }
        return canonical;
    }
```
```sql
-- The index and the application must implement the same equality rule.
ALTER TABLE users ADD CONSTRAINT username_is_stored_trimmed_and_lower
    CHECK (username = LOWER(BTRIM(username)));
CREATE UNIQUE INDEX users_username_key ON users (username COLLATE "C");
```
Then look up the canonical value with no further transformation
(`statement.setString(1, canonicalUsername(username))`), and never echo the caller's raw string back
as if it were the identity (see SEC-04). SEC-06 extends this same function with Unicode
normalisation — there must be exactly one such function, called by both the write path and the read
path.

### SEC-03: Database password transported through an exported environment variable
- **Severity:** Low
- **CWE:** CWE-526: Exposure of Sensitive Information in Environmental Variables
- **Location:** `UserAccountLookup.java:134` (documented pattern at `README.md:89`)

**Vulnerable code:**
```java
// UserAccountLookup.java:133-134
        try (Connection connection =
                     DriverManager.getConnection(url, System.getenv("DB_USER"), System.getenv("DB_PASSWORD"))) {
```

**Why it is a problem:** the README's documented invocation is
`export DB_URL='jdbc:h2:mem:app' DB_USER=sa DB_PASSWORD=secret` (`README.md:89`), so the credential
becomes part of the process environment for the whole session. Environment variables are readable by
any user with `CAP_SYS_PTRACE` or root through `/proc/<pid>/environ` (and, on some systems, world
readable in `ps e` output), are inherited by every child process the JVM spawns, are routinely
captured by crash/core dumps, are echoed by CI runners and container debug tooling
(`docker inspect`, `kubectl describe pod`), and — being an immortal `String` — cannot be erased from
the heap after use. Any debugging flag or heap dump taken later exposes the credential. There is no
rotation story either: a changed password requires restarting the process, which is what pushes
operators to commit a fallback value.

**Fix:** keep the credential out of the environment — read it from the terminal with
`Console.readPassword`, from a file with restrictive permissions, or from a secrets manager, and
prefer the JDBC 4.3 `char[]` APIs so the secret is not an immortal `String`.

```java
        Properties driverProperties = new Properties();
        driverProperties.setProperty("user", System.getenv("DB_USER"));
        char[] secret = readSecretFromTerminal("database password: ");
        try {
            driverProperties.put("password", secret);   // JDBC 4.3 drivers accept char[]
            try (Connection connection = DriverManager.getConnection(url, driverProperties)) {
                Optional<UserAccount> account = findByUsername(connection, username);
                ...
            }
        } finally {
            java.util.Arrays.fill(secret, '\0');        // erase as soon as the driver copied it
        }
```
```java
    private static char[] readSecretFromTerminal(String prompt) throws IOException {
        Console console = System.console();
        if (console == null) {
            throw new IOException("no controlling terminal: obtain the password from a secrets"
                    + " manager or a 0600 file, not an environment variable");
        }
        char[] secret = console.readPassword(prompt);
        if (secret == null || secret.length == 0) {
            throw new IOException("a database password is required");
        }
        return secret;
    }
```
`DataSource.getConnection(String user, char[] password)` (H2 `JdbcDataSource`, `PGSimpleDataSource`)
is the erase-friendly variant. Update `README.md:89` so the documented pattern is not "export the
password", and never ship a default/fallback password for the case where the variable is unset.

### SEC-04: Caller input, PII and driver error text written to the console unsanitised
- **Severity:** Low
- **CWE:** CWE-117: Improper Output Neutralization for Logs (CWE-93 CRLF injection and ANSI/OSC
  terminal escape injection are the same defect class); CWE-209 for the error text; CWE-778 for the
  uncaught exception
- **Location:** `UserAccountLookup.java:137` (also `:140`, `:142`, `:145`, and `:72-75`)

**Vulnerable code:**
```java
// UserAccountLookup.java:136-145
            if (account.isEmpty()) {
                System.out.println("No account found for username: " + username.trim());
                return;
            }
            System.out.println(account.get());
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            System.exit(2);
        } catch (SQLException e) {
            System.err.println("database lookup failed: " + e.getMessage());
```

**Why it is a problem:** four distinct issues on the output side of the same block.

1. `:137` echoes the caller's string after `trim()`, which removes only leading/trailing code points
   `<= U+0020` — **interior** control characters survive (`\r`, `\n`, `\b`, `ESC 0x1B`, NUL) as does
   the whole upper-C1/zero-width range. When this CLI runs under a supervisor, CI runner or syslog
   forwarder, one injected `\n` becomes a *forged log line* attributed to this program
   (`java[123]: No account found for username: alice` / `java[123]: SEVERE: ...`), corrupting audits
   and misleading anyone reading the log. `ESC ]8;;http://evil` additionally injects a spoofed
   clickable OSC-8 hyperlink, and other escape sequences can redraw the terminal, change the window
   title or clear the screen — this code is explicitly designed for interactive shell use.
2. `:140` prints the whole record (`record.toString()`, i.e. `id`, `email`, `fullName`, `status`)
   into whatever sink stdout is wired to (log collector, CI transcript, terminal scrollback), with no
   minimisation or redaction of personal data. It is intentional for a lookup CLI, but it means the
   output must be treated as PII-bearing, which is worth stating in the README.
3. `:145` forwards `SQLException.getMessage()` verbatim. Driver messages routinely contain the DBMS
   product and version, host and port, the failing SQL fragment (PostgreSQL and H2 both do this),
   and sometimes the connection string — useful reconnaissance for an attacker and unnecessary for
   the operator, who only needs the exit status.
4. `IllegalStateException` (`:72-75`, thrown when the unique index is missing) is **not** caught
   here — `main` catches only `IllegalArgumentException` and `SQLException`, so the JVM prints a full
   stack trace and exits with status `1`, outside the documented `0`/`2`/`3` contract. The trace
   leaks class names, the driver's internals and JDBC call sites.

**Fix:** neutralise control/format characters in any caller-supplied text before it reaches a
terminal or a log, keep driver detail out of user-facing output, and close the uncaught-exception
path.

```java
            if (account.isEmpty()) {
                // Do not echo caller-supplied text as if it were an identity; print a fixed message.
                System.out.println("No account found for the supplied username.");
                return;
            }
            System.out.println(account.get());
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            System.exit(2);
        } catch (IllegalStateException e) {
            System.err.println("lookup refused: the users table has no usable unique index");
            System.exit(4);                                   // documented status
        } catch (SQLException e) {
            System.err.println("database lookup failed");     // detail goes to the server-side log
            System.exit(3);
        }
```
```java
    /** If the username must be echoed, strip every character that can forge a line or a sequence. */
    static String neutralizeForDisplay(String value) {
        StringBuilder out = new StringBuilder(value.length());
        value.codePoints().forEach(cp -> out.appendCodePoint(
                Character.isISOControl(cp)
                        || Character.getType(cp) == Character.FORMAT      // U+200B..U+200D, U+FEFF
                        || Character.isSpaceChar(cp)
                        ? '?' : cp));
        return out.toString();
    }
```
If this is ever wired into a service, replace `System.out`/`System.err` with a logging framework that
escapes structured fields, and log the full `SQLException` (with cause chain) at `DEBUG` there rather
than in the terminal.

### SEC-05: Third-party jar downloaded and executed with no integrity or provenance verification
- **Severity:** Low
- **CWE:** CWE-494: Download of Code Without Integrity Check (supply-chain surface, CWE-829)
- **Location:** `README.md:118` (executed at `README.md:119-120`)

**Vulnerable code:**
```bash
# README.md:118
curl -sSLo h2.jar https://repo1.maven.org/maven2/com/h2database/h2/2.2.224/h2-2.2.224.jar
```

**Why it is a problem:** this is the only instruction in the project that reaches outside the
machine, and it is the step everyone runs to reproduce the documented verification results. Nothing
checks what came back: no SHA-256 digest, no detached PGP signature, no attestation, and the
downloaded bytes are then placed on the JVM class path and executed with the full privileges of the
developer's account (`:119-120`). A tampered artifact — compromised or country-positioned mirror,
intercepting proxy, poisoned cache, or a takeover of the coordinate — runs arbitrary code inside the
build and inside any CI job that follows these lines. The version *is* pinned (`2.2.224`), which is
good, but pinning without a digest only guarantees you run the *same* bytes if the bytes are
untouched; `-o` also means a captive portal or error page saved as `h2.jar` is accepted silently
(`-sSL` without `-f` does not fail on HTTP errors). Two supporting issues: `curl -s` hides failures,
and this artifact is a *test* dependency pulled straight from a public repository, so it never passes
through dependency resolution, lockfiles, internal mirrors or SCA scanning, and it is the exact
artifact whose presence on the class path is what makes the SEC-01 JDBC-URL parameters live.

**Fix:** verify integrity against a digest pinned *in the repository* (not fetched from the same
origin as the artifact — that only detects transport corruption), and prefer a dependency manager
that verifies checksums and signatures and records the resolved set.

```bash
# README.md (fixed): fetch, verify against the pinned digest, only then run.
BASE=https://repo1.maven.org/maven2/com/h2database/h2/2.2.224
curl -fsSLo h2.jar          "$BASE/h2-2.2.224.jar"
curl -fsSLo h2.jar.asc      "$BASE/h2-2.2.224.jar.asc"
gpg --homedir "$(mktemp -d)" --keyserver-keys-from-pinned-keyring \
    --verify h2.jar.asc h2.jar \
  || { echo 'signature is not trusted - aborting'; exit 1; }
# h2.jar.sha256.lock is committed to this repository; the fetched copy is never the authority.
echo "$(cat h2.jar.sha256.lock)  h2.jar" | sha256sum -c - \
  || { echo 'digest mismatch - aborting'; exit 1; }
javac -cp h2.jar UserAccountLookupH2Test.java
java  -cp .:h2.jar UserAccountLookupH2Test
```
Better still, let Maven/Gradle resolve the test dependency (checksum + signature verification,
lockfile, SBOM and SCA coverage, internal mirror) or verify a Sigstore/SLSA attestation
(`cosign verify-blob --certificate ... --signature ...`). Do not treat a plain HTTPS URL as an
integrity guarantee — TLS authenticates the channel, not the artifact.

### SEC-06: No Unicode or case canonicalisation of a primary identity key
- **Severity:** Low
- **CWE:** CWE-174: Double Escaping/Improper Handling of Ambiguous Input Interpretation (identity
  key not canonicalised; CWE-436/CWE-178 adjacent)
- **Location:** `UserAccountLookup.java:82-94`

**Vulnerable code:**
```java
// UserAccountLookup.java:82-94
    private static String normalizeUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username must not be null");
        }
        String trimmed = username.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        if (trimmed.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException(
                    "username must not be longer than " + MAX_USERNAME_LENGTH + " characters");
        }
        return trimmed;
    }
```

**Why it is a problem:** `username` is the primary key this whole class resolves, and the only
transformations applied are whitespace trim and a length cap. Three gaps follow:

* **No case folding, and case behaviour is delegated.** `README.md:179` says case sensitivity "depends
  on the column collation", and the H2 harness asserts `Alice` and `alice` are different accounts
  (`UserAccountLookupH2Test.java:137-140`). So whether `ADMIN` reaches the `admin` account is decided
  by DDL this code does not see, and a deploy to a case-insensitive collation silently changes the
  set of usernames that resolve — turning a lookup into a fuzzy match for a security-relevant
  identifier.
* **No Unicode normalisation.** `trim()` leaves NBSP (U+00A0), ideographic space (U+3000), zero-width
  space (U+200B) and BOM (U+FEFF) attached to the string, and NFC/NFD variants of an accented name
  compare unequal byte-wise while looking identical on screen. Combined with SEC-02, either direction
  is possible: two visually identical usernames occupying one identity, or one username failing to
  resolve to its own row while a look-alike resolves.
* **The length cap counts UTF-16 code units**, not grapheme clusters or the database's own width
  unit, so a composed and a decomposed form of the same visible name have different lengths against
  `MAX_USERNAME_LENGTH`.

**Fix:** canonicalise once (shared with the write path, per SEC-02) and make the stored form and the
equality rule match the application's rule, so the answer does not depend on which collation the
deployment happens to use.

```java
    private static String normalizeUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username must not be null");
        }
        String nfkc = java.text.Normalizer.normalize(username, java.text.Normalizer.Form.NFKC);
        nfkc.codePoints().forEach(cp -> {
            if (Character.isSpaceChar(cp)                       // U+00A0, U+3000, U+202F, ...
                    || Character.getType(cp) == Character.FORMAT // U+200B..U+200D, U+FEFF
                    || cp == '\uFEFF') {
                throw new IllegalArgumentException("username contains an invisible character");
            }
        });
        String canonical = nfkc.strip().toLowerCase(Locale.ROOT);   // Locale.ROOT: no Turkish-I drift
        if (canonical.isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        if (canonical.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException(
                    "username must not be longer than " + MAX_USERNAME_LENGTH + " characters");
        }
        return canonical;
    }
```
Pair it with the schema-side `CHECK`/`CREATE UNIQUE INDEX ... COLLATE "C"` from SEC-02 so the
database cannot accept a row whose stored form is not canonical, and keep this method as the single
entry point for every username that enters the system.

## 6. Verified Controls and Checks With No Finding

- **No SQL injection in the lookup path**: the statement is a compile-time constant with a single
  `?` placeholder and an explicit column list (`UserAccountLookup.java:34-36`); the value is delivered
  only via `setString` (`:66`); `grep` over the whole file found no string concatenation,
  `String.format`, `Statement`, or dynamic `ORDER BY`/`LIKE`/identifier construction. Cross-checked
  with `exploiting-sql-injection-vulnerabilities`.
- **Injection behaviour is proven, not assumed**: the driver-free harness asserts the SQL text equals
  the constant, that the SQL contains no quote metacharacters or the username, and that the bound
  value list is exactly `[[1, admin' OR '1'='1 --]]` (`UserAccountLookupTest.java:153-161`); the real
  engine harness loops five payloads (`admin' OR '1'='1`, `admin' --`,
  `admin'; DROP TABLE users; --`, a `UNION SELECT` and wildcards `%`/`_`) asserting no row is returned
  and re-counting the table afterwards to confirm nothing was modified or dropped
  (`UserAccountLookupH2Test.java:119-135`).
- **Second-order/stored injection path closed**: retrieved `username`, `email`, `full_name` and
  `status` are only mapped into an immutable record (`:96-104`, `:173-179`); they are never
  re-interpolated into SQL, a shell command, a file path or a URL, so the
  `performing-second-order-sql-injection` pattern has no sink (`UserAccountLookup.java:173-179`).
- **Least-data column selection**: the query names only `id, username, email, full_name, status,
  created_at` and cannot select `password_hash` or any token/salt column; `UserAccount` therefore
  cannot carry authentication material into a log line or a response (`:34-36`, `:165-179`). The
  harness additionally scans the SQL text for `select *`, `password`, `token` and `salt`
  (`UserAccountLookupTest.java:162-166`).
- **Fail-closed on ambiguous identity**: a second matching row raises `IllegalStateException` instead
  of returning an arbitrary account (`:71-75`), and the real-engine harness confirms both duplicate
  paths (`UserAccountLookupH2Test.java:142-146`). (The *output* consequence of the uncaught exception
  is reported separately as SEC-04; the control itself works.)
- **Resource handling and close order**: `PreparedStatement` and `ResultSet` are closed by
  try-with-resources in the correct order (`:65-79`), and the caller's `Connection` is explicitly left
  open (`UserAccountLookupTest.java:202-215`), so a caller-managed transaction is not cut short.
- **Input validation happens before the driver is touched**: null, blank and over-length values are
  rejected by `normalizeUsername` (`:63` → `:82-94`) before `prepareStatement` is called, so a
  10 MB or empty-string input cannot reach the wire; the upper bound of 254 is aligned with the
  documented `VARCHAR(254)` column (`:38`, `README.md:79`).
- **Mapping is label-based, not positional**: `toUserAccount` reads by column label (`:98-104`), so a
  reordered or extended table cannot silently mis-map `status` into `email`
  (`UserAccountLookupTest.java:282-291`), and a `NULL` `created_at` yields a `null` `Instant` rather
  than an NPE (`:98`, `:103`; `UserAccountLookupH2Test.java:89-93`).
- **No Java-native deserialization sink**: sweep for `ObjectInputStream`/`readObject`/
  `readUnshared`/JNDI `InitialContext.lookup`/script-engine evaluation found none
  (`exploiting-insecure-deserialization`); the only deserialization-adjacent risk is the driver-side
  one already reported as SEC-01.
- **Credentials are not passed as command-line arguments**: the password is read from the environment
  rather than `args`, so it does not appear in `ps`/shell history for the invocation itself
  (`:117-118`, `:134`) — the environment channel itself is still reported as SEC-03.
- **Validation errors do not echo user input**: the only `IllegalArgumentException` messages are
  fixed texts (`username must not be null`, `must not be blank`, `must not be longer than 254
  characters`) (`:84`, `:88`, `:91-92`), so `System.err.println(e.getMessage())` at `:142` discloses
  neither the caller's string nor any JDBC detail (contrast `:145`, reported as SEC-04).
- **Explicit character set for user input**: stdin is decoded as UTF-8 explicitly (`:150-156`) rather
  than relying on the platform default, avoiding silent mojibake in an identity key, and stdin is
  closed by try-with-resources.
- **Test-harness secrets triaged as non-secrets**: the bcrypt-shaped literal `insert.setString(6,
  "$2a$10$notarealhashvalue")` (`UserAccountLookupH2Test.java:187`) is a non-functional fixture for a
  `NOT NULL` column that no query in this project ever reads (`password_hash` is excluded from the
  column list), and the `sa`/empty-password in-memory URL (`:21`, `:30`) is a throwaway database that
  exists only inside the JVM. Applying the `implementing-secret-scanning-with-gitleaks`
  allowlist/placeholder guidance, these are not live credentials and are not reported as findings —
  but they *will* fire secret scanners, so the recommended hygiene is a `.gitleaks.toml` allowlist
  entry scoped to `UserAccountLookupH2Test.java` and a rename of the literal to something obviously
  fake (e.g. `"NOT-A-REAL-HASH-fixture"`), which removes both the noise and the chance of it being
  copy-pasted as a real hash.
- **Test-only schema gap is deliberate and bounded**: `createSchema` intentionally omits the
  `users.username` unique index so the duplicate-row check can be exercised
  (`UserAccountLookupH2Test.java:157-166`, `README.md:180`); the harness touches an in-memory
  database only and never a shared instance, so the missing constraint is not a production control
  gap — but note the coupling with SEC-02, since the unique index *is* the control that bounds the
  trim mismatch.
- **No crypto in scope**: verified there is no password hashing or verification, no randomness, no
  token/session/cookie/JWT handling, and no TLS configuration anywhere in the folder, so the checks
  from `performing-cryptographic-audit-of-application` are not-applicable rather than satisfied
  (the password hash is stored by others and never selected here).
- **No output-encoding or request-forgery surface**: no HTML/template/JSON rendering, no outbound URL
  construction and no user-controlled network target exist in this code, so XSS, SSRF, path
  traversal, command injection and header-injection behaviours are absent by construction.
- **Harness files are not attack surface**: neither test is packaged as a library entry point, both
  are read-only with respect to the source files, and the `Proxy` doubles open no socket
  (`UserAccountLookupTest.java:347-396`).
- **`result.md` / `return.txt` / `prompt*.txt` contain no secrets**: the prior-run transcript and
  reports were scanned for credential material and hashes; the only match is the H2 fixture literal
  triaged above. `prompt_hash.txt` is a task-harness digest of the prompt, not a secret.
- **Verification status**: this review was static. The harnesses were not executed here, so the
  "47 checks / 30 checks / mutation battery" results in `README.md:124-168` are recorded as the
  project's own claim and were assessed by reading the assertions behind each claim, not by re-running
  them.
