# Security Review: UserRegistration (JDBC account registration & authentication)

## 1. Executive Summary

`UserRegistration.java` is a small, unusually careful JDBC component: PBKDF2-HMAC-SHA256 password storage with per-account salts, self-describing digests, strictly parameterised SQL, an allowlist username validator, and a guard-digest timing equaliser. Almost every claim in `README.md` holds up under inspection, and the two dependency-free test suites corroborate the SQL and KDF contracts.

Seven findings remain, one of which is material:

- **SEC-01 (High)** is the reason to read this report. `MIN_ITERATIONS = 1_000` does double duty as the *construction* floor **and** the floor accepted for a **stored** digest (`UserRegistration.java:111-114`, `351-353`). A 1,000-round digest is therefore permanently valid, and because `authenticate()` never re-derives and re-stores a cheaper row, an attacker who can write one row (or anyone who copies the shipped demo, which does exactly this at `UserRegistration.java:651`) gets a ~600x weaker password store that never self-heals. The shipped `README.md` demo output publishes digests of precisely this shape.
- **SEC-02 (Medium)**: the component returns `NO_SUCH_USER` and `BAD_PASSWORD` as distinct values. The guard digest equalises the *timing* of the two paths but not the *value*, so every caller is one `if` away from re-opening username enumeration, and nothing in the API makes that mistake hard.
- **SEC-03 - SEC-07 (Medium/Low)** cover first-row authentication when the unique index is absent, a too-broad `23xxx` integrity-state match that can launder a real data fault into a friendly "username taken", transaction-ownership overreach onto a caller-owned connection, the demo's password-in-argv plus digest-printing, and one test assertion that cannot fail.

No SQL injection, no weak randomness, no credential leak through logs or errors, and no algorithm-confusion path were found; those checks are itemised in section 6 rather than omitted, because in this component they are the controls the whole design leans on.

Verified by execution during this review: `UserRegistrationSqlContractTest` passes **86/86** checks against the shipped `out/` classes; the shipped `.class` files are byte-identical to a fresh compile of the current source (so the artifacts are not stale and contain no extra SQL). The H2 suite could not be run — `h2.jar` is not present in the folder.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
| --- | --- | --- |
| `UserRegistration.java` (727 lines) | The component: `PasswordHasher` (PBKDF2 storage), `UserRegistry` (register/authenticate over a caller-owned JDBC `Connection`), plus a `main` demo | KDF algorithm and iteration bounds; salt generation; digest parsing and comparison; username allowlist; all SQL text and parameter binding; uniqueness handling via constraint violation; commit/rollback ownership of a foreign transaction; demo CLI argument and stdout handling |
| `UserRegistrationH2Test.java` (904 lines) | Integration suite against in-memory H2 | Asserts digest round-trip, refused ambiguous passwords, cost migration, unknown-user and refused-candidate timing ratios; writes SQL of its own (`DELETE`, `SELECT COUNT(*)`, injected-looking fixtures) |
| `UserRegistrationSqlContractTest.java` (694 lines) | SQL/parameter contract suite using JDBC proxies; no database needed | Records and asserts exact statement text, that no password or quote character ever reaches statement text, that every placeholder is bound, that 23505 and 22001 are distinguished, and commit/rollback call counts |
| `README.md` | Design rationale, API, claimed guarantees, demo transcript, mutation-testing table | Publishes `pbkdf2-sha256$1000$...` digests as sample output; documents stored-cost bounds of 1,000-10,000,000 as a control; instructs callers to render the two failure outcomes identically |
| `out/*.class` (14 artifacts) | Committed build output | Would be the real deployed code if shipped; verified here against source (see section 6) |
| `prompt.txt`, `prompt_hash.txt`, `cyber_prompt.txt`, `result.md`, `return.txt` | Task-harness metadata, not application code | Out of scope |

## 3. Skills Applied

Per the router skill's workflow, the skill-library names were grepped first (819 skills), the candidates' frontmatter descriptions skimmed, and only the relevant bodies opened and applied against this code. Each skill's own helper scripts were **not** executed: they are Python, and the router explicitly warns that running them against a Java target would produce spurious errors.

| Skill | What it was applied to |
| --- | --- |
| `review-code-for-security-vulnerabilities` | The workflow itself: read every source file first, enumerate security-relevant behaviours, match them to library skills, apply each checklist with concrete `file:line`, report severity + CWE + fix |
| `performing-cryptographic-audit-of-application` | The on-point checklist (KDF parameter strength, hardcoded secrets, RNG usage). Its "Weak KDF — low iteration PBKDF2" row is what SEC-01 lands on; its "Hardcoded Secrets" row is what forced an explicit verdict on `GUARD_PASSWORD` (section 6) rather than a reflexive finding |
| `testing-api-authentication-weaknesses` | The authentication-weakness taxonomy. Only partially applicable: it targets HTTP/JWT/session surfaces, and this component has no transport or session layer. Its "weak password policies" branch maps to the absent strength policy (section 6, informational); it does not cover password-storage cost, so SEC-01 does not rest on it |
| `exploiting-sql-injection-vulnerabilities` | The injection-point taxonomy (error-, boolean-, time- and OOB-based; second-order/stored execution) used as the checklist the code was tested against for `INSERT_SQL`, `SELECT_DIGEST_SQL`, `EXISTS_SQL`, the two DDL strings, and the demo's `'` and `--` payloads — no finding (section 6) |

Where no library skill covered a behaviour, that is stated at the finding. **SEC-01's severity rests on general knowledge** — OWASP Password Storage Cheat Sheet (600,000 iterations as the current PBKDF2-HMAC-SHA256 floor, credential-upgrade-on-login as the migration mechanism) and CWE-916 — as does **SEC-03**, **SEC-05** and **SEC-07**, which are transaction-semantics, API-design and test-assurance issues that the library's offensive checklists do not address. **SEC-02** was checked against `testing-api-authentication-weaknesses` and general CWE-204 knowledge; **SEC-04** against general CWE-754 knowledge; **SEC-06** against the hardcoded/argv-secret patterns of `performing-cryptographic-audit-of-application`.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
| --- | --- | --- | --- | --- |
| SEC-01 | 1,000-round digests are accepted forever, with no upgrade path | High | CWE-916 Insufficiently Protected Credentials | `UserRegistration.java:111-114`, `150-155`, `351-353`, `651` |
| SEC-02 | Distinct `NO_SUCH_USER` / `BAD_PASSWORD` values re-open username enumeration | Medium | CWE-204 Observable Response Discrepancy | `UserRegistration.java:85-92`, `546-567` |
| SEC-03 | Authentication trusts the first row of an unbounded `SELECT`; duplicates are silently ignored | Medium | CWE-664 Improper Control of a Resource Through its Lifetime (secondary CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition) | `UserRegistration.java:397-398`, `539-543` |
| SEC-04 | Any `23xxx` integrity violation can be reported as "username already exists" | Low | CWE-754 Improper Check for Unusual or Exceptional Conditions | `UserRegistration.java:503-512`, `603-612` |
| SEC-05 | `commitIfManaging()` commits the caller's unrelated pending work by default | Low | CWE-664 Improper Control of a Resource Through its Lifetime | `UserRegistration.java:428-429`, `614-618`, `620-632` |
| SEC-06 | Demo takes the database password in argv and prints every stored digest | Low | CWE-214 Invocation of Process Using Visible Sensitive Information (argv exposure); CWE-532 for the digest dump | `UserRegistration.java:644-653`, `712-718` |
| SEC-07 | Assertion that cannot fail hides a regression in the refused-candidate guard | Low | CWE-1023 Redundant Comparisons | `UserRegistrationH2Test.java:116-122` |

## 5. Detailed Findings

### SEC-01 — 1,000-round digests are accepted forever, with no upgrade path

**Severity:** High

**CWE:** CWE-916 Insufficiently Protected Credentials (weak KDF cost; CWE-326 inadequate key-strength analogue)

**Location:** `UserRegistration.java:111-114` (the constant, with the `DEFAULT_ITERATIONS` it is confused with), `150-155` (constructor floor), `351-353` (stored-digest floor), `651` (demo uses it)

**Vulnerable code:**

```java
    public static final int DEFAULT_ITERATIONS = 600_000;

    /** Floor accepted for a stored digest, so a hostile row cannot ask for 1 round. */
    public static final int MIN_ITERATIONS = 1_000;
```

```java
        public PasswordHasher(int iterations) {
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException(
                        "iterations must be in [" + MIN_ITERATIONS + ", " + MAX_ITERATIONS + "]");
            }
            this.iterations = iterations;
        }
```

```java
                if (iterationCount < MIN_ITERATIONS || iterationCount > MAX_ITERATIONS) {
                    throw new IllegalArgumentException("iteration count out of range: " + iterationCount);
                }
```

```java
        // 1,000 rounds instead of 600,000 so the demo finishes at once. A
        // production registry is built with no argument and gets the default.
        PasswordHasher hasher = new PasswordHasher(PasswordHasher.MIN_ITERATIONS);
```

**Why it is a problem:** The upper bound is a genuine DoS control and should stay. The lower bound is not: `MIN_ITERATIONS` is used for two different jobs, and the second one is dangerous. `Stored.parse` accepts *any* stored digest at or above 1,000 rounds, so 1,000 rounds is a permanently sanctioned cost for a live credential — the javadoc says so in as many words ("Floor accepted for a stored digest"). `authenticate()` verifies with whatever count the row carries and has no re-hash-and-`UPDATE` path (the only `executeUpdate()` in the file is the insert at line 501), so a cheap row never gets expensive. The result is a stable ~600x reduction in offline-cracking cost — 1,000 rounds of PBKDF2-HMAC-SHA256 is on the order of 1.4 ms per guess on the machine described in `README.md`, versus the 860 ms the design is built around — that survives every future hardening of the default. Three independent routes put such a row in place: an attacker with row-write on the table (a SQL-injection bug *anywhere else* in the application, a restore of an old backup, an unpatched write path) simply lowers the count on a target account and waits; `main()` creates exactly these rows and `README.md` prints them as sample output, so copy-pasting the documented demo or its output shape into a fixture, seed script, or support tool ships 1,000-round credentials; and any operator who constructs `new PasswordHasher(1_000)` "for testing" in a service that also serves production traffic gets no warning at all. `README.md` lists "Stored-cost bounds (1,000 - 10,000,000)" in its guarantees table, which frames the weak end of that range as a property rather than the hole.

**Fix:** Split the two constants — keep the low value as the *construction* floor for tests and key-derivation call sites, and make the *stored* floor the OWASP-relevant cost — then add the upgrade path the design is already shaped for, so rows created earlier or tampered with are repaired the next time the user proves the password:

```java
        public static final int DEFAULT_ITERATIONS = 600_000;

        /** Lowest count a caller may ask a hasher to stamp. Tests live here. */
        public static final int MIN_ITERATIONS = 1_000;

        /**
         * Lowest count accepted in a stored digest. Deliberately far above
         * MIN_ITERATIONS: a row below this is treated as corrupt or hostile,
         * not as a cheap-but-legal account.
         */
        public static final int MIN_ACCEPTED_STORED_ITERATIONS = 600_000;

        public PasswordHasher(int iterations) {
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException(
                        "iterations must be in [" + MIN_ITERATIONS + ", " + MAX_ITERATIONS + "]");
            }
            this.iterations = iterations;
        }

        /** @return true when a stored row is cheaper than the current default and should be re-stamped */
        public boolean wantsUpgrade(Stored stored) {
            return stored.iterations < DEFAULT_ITERATIONS;
        }

        /** @return a digest of the same secret at this hasher's current cost */
        public String rehash(char[] password, Stored stored) {
            return hash(password);
        }
```

```java
                if (iterationCount < MIN_ACCEPTED_STORED_ITERATIONS
                        || iterationCount > MAX_ITERATIONS) {
                    throw new IllegalArgumentException(
                            "iteration count out of range: " + iterationCount);
                }
```

```java
            boolean authenticated = hasher.matches(password, storedDigest);
            if (authenticated && hasher.wantsUpgrade(hasher.parseStored(storedDigest))) {
                try (PreparedStatement upgrade = connection.prepareStatement(UPGRADE_DIGEST_SQL)) {
                    upgrade.setString(1, hasher.hash(password));
                    upgrade.setString(2, username);
                    upgrade.executeUpdate();
                }
                commitIfManaging();
            }
            return authenticated
                    ? AuthenticationOutcome.AUTHENTICATED
                    : AuthenticationOutcome.BAD_PASSWORD;
```

with `UPGRADE_DIGEST_SQL = "UPDATE " + TABLE + " SET password_hash = ? WHERE username = ?"`. If a migration window genuinely requires accepting older, cheaper rows, set `MIN_ACCEPTED_STORED_ITERATIONS` to the *known* historical cost (never to the test floor), record it as a tracked exception, and let the upgrade loop above drain the backlog — that is the whole point of storing the count per row. Independently, stop the demo from shipping the weak shape: `main()` should use `new PasswordHasher()` and accept a slower transcript.

### SEC-02 — Distinct `NO_SUCH_USER` / `BAD_PASSWORD` values re-open username enumeration

**Severity:** Medium

**CWE:** CWE-204 Observable Response Discrepancy

**Location:** `UserRegistration.java:85-92` (enum), `546-567` (both failure returns)

**Vulnerable code:**

```java
    public enum AuthenticationOutcome {
        /** The candidate password produced the stored digest. */
        AUTHENTICATED,
        /** No row owns that username. */
        NO_SUCH_USER,
        /** A row exists and the candidate password did not produce its digest. */
        BAD_PASSWORD
    }
```

```java
            if (!PasswordHasher.isVerifiableCandidate(password)) {
                // A blank, over-long or JCE-ambiguous candidate can never match,
                // but it must not be answered cheaply either: a fast refusal
                // would let anyone tell "user exists" from "user absent" by
                // timing, which is the whole leak the guard digest exists to
                // close. Pay the same derivation, then report.
                hasher.matches(GUARD_PASSWORD, guardDigest);
                return found
                        ? AuthenticationOutcome.BAD_PASSWORD
                        : AuthenticationOutcome.NO_SUCH_USER;
            }

            if (!found) {
                hasher.matches(GUARD_PASSWORD, guardDigest);
                return AuthenticationOutcome.NO_SUCH_USER;
            }
            return hasher.matches(password, storedDigest)
                    ? AuthenticationOutcome.AUTHENTICATED
                    : AuthenticationOutcome.BAD_PASSWORD;
```

**Why it is a problem:** The guard digest is real work and it works — the measured unknown-user / wrong-password ratio is 1.00-1.02, and the refused-candidate path is equalised too. But it buys equal *cost*, and then the method hands the caller a value that is not equal: `NO_SUCH_USER` versus `BAD_PASSWORD`. The entire defence against username enumeration is therefore a prose instruction — `README.md` "Show the caller one identical message", and the javadoc's "Render `NO_SUCH_USER` and `BAD_PASSWORD` identically" — with no structure enforcing it. A login handler that writes `return outcome == NO_SUCH_USER ? "no such account" : "wrong password"`, one that returns 404 versus 401, one that logs the two at different severities into a user-visible audit pane, or a support tool exposed behind a low-privilege role, all rebuild the account-enumeration oracle in a single line. That oracle is the precondition for credential stuffing against a known-real account list and for targeted phishing that names actual employees, and it is the exact weakness this component otherwise spends a full extra PBKDF2 run per failed attempt to close. Note the asymmetry: the value leaks instantly and reliably on every failed login, whereas the timing channel the guard was built for is noisy and rate-limited.

**Fix:** Keep the distinction available for server-side telemetry, but make the un-collapsible-by-accident rendering the default surface, and stop returning the discriminator on the value every caller has to handle:

```java
    public enum AuthenticationOutcome {
        /** The candidate password produced the stored digest. */
        AUTHENTICATED,
        /** Either no row owns that username or the secret was wrong: the two are
         *  deliberately not distinguishable to the caller. */
        BAD_CREDENTIALS;

        public boolean isAuthenticated() {
            return this == AUTHENTICATED;
        }
    }
```

```java
            if (!PasswordHasher.isVerifiableCandidate(password)) {
                hasher.matches(GUARD_PASSWORD, guardDigest);
                LOGGER.log(Level.INFO, "login refused candidate user={0} reason={1}",
                        new Object[] {username, found ? "candidate" : "no-row"});
                return AuthenticationOutcome.BAD_CREDENTIALS;
            }

            if (!found) {
                hasher.matches(GUARD_PASSWORD, guardDigest);
                LOGGER.log(Level.INFO, "login for absent user {0}", username);
                return AuthenticationOutcome.BAD_CREDENTIALS;
            }
            boolean ok = hasher.matches(password, storedDigest);
            if (!ok) {
                LOGGER.log(Level.INFO, "login bad password for {0}", username);
            }
            return ok ? AuthenticationOutcome.AUTHENTICATED
                      : AuthenticationOutcome.BAD_CREDENTIALS;
```

The server still learns which case happened, through a log line it has to go out of its way to render; the API no longer offers the discriminator at all. If three-valued outcomes must be preserved for an internal migration tool, keep them on a second, separately named method (`authenticateForServerTelemetry`) whose javadoc states it must never reach a response, and leave `authenticate` two-valued.

### SEC-03 — Authentication trusts the first row of an unbounded `SELECT`

**Severity:** Medium

**CWE:** CWE-664 Improper Control of a Resource Through its Lifetime (the username-uniqueness invariant is assumed rather than controlled), secondary CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition (the row that answers the login can change between registration and authentication)

**Location:** `UserRegistration.java:397-398` (`SELECT_DIGEST_SQL`), `539-543` (first-row consumption), `407-408` (`CREATE INDEX ... IF NOT EXISTS`)

**Vulnerable code:**

```java
        private static final String SELECT_DIGEST_SQL =
                "SELECT password_hash FROM " + TABLE + " WHERE username = ?";
```

```java
            String storedDigest = null;
            boolean found = false;
            try (PreparedStatement select = connection.prepareStatement(SELECT_DIGEST_SQL)) {
                select.setString(1, username);
                try (ResultSet rows = select.executeQuery()) {
                    if (rows.next()) {
                        found = true;
                        storedDigest = rows.getString(1);
                    }
                }
            }
```

**Why it is a problem:** `authenticate()` derives the account's verifier from whichever row the engine happens to return first, and quietly ignores any others. The design assumes that is safe because `ensureSchema()` creates a unique index, but three ordinary situations break that assumption, and none of them is visible from inside this class. `CREATE UNIQUE INDEX IF NOT EXISTS` is a no-op if the index name already exists with different contents, and on most engines it *fails outright* rather than repairing a pre-existing table that already holds duplicate usernames — so a database that predates this component, or one where a DBA renamed or dropped `ux_app_users_username`, has no uniqueness guarantee at all while `register()` keeps returning `CREATED`. A restore-from-backup plus a re-seed produces two `alice` rows with different hashes; the same happens if the schema is ever applied to a table where uniqueness was expressed as a non-unique index for query performance. From then on, login for `alice` silently authenticates against row order: the moment the planner switches (a new index, `ORDER BY` change, vacuum, engine upgrade, or a concurrent insert moving the physical order), the account starts rejecting its real owner while the older digest stays valid for anyone who knows it. That is an identity-resolution failure, not a cosmetic bug — it authenticates a principal against an unverified credential record, and because the code never counts rows, there is no error, no log, and no way to notice. The uniqueness check in `register()` cannot protect login here either: it only inspects the error path of an `INSERT` that a duplicate on a missing index lets through.

**Fix:** Make the ambiguity explicit and fail closed — fetch up to two rows and refuse to guess — and stop relying on `IF NOT EXISTS` to have established the constraint:

```java
        private static final String SELECT_DIGEST_SQL =
                "SELECT password_hash FROM " + TABLE + " WHERE username = ? FETCH FIRST 2 ROWS ONLY";
```

```java
            String storedDigest = null;
            boolean found = false;
            int candidates = 0;
            try (PreparedStatement select = connection.prepareStatement(SELECT_DIGEST_SQL)) {
                select.setString(1, username);
                try (ResultSet rows = select.executeQuery()) {
                    while (rows.next()) {
                        candidates++;
                        if (!found) {
                            found = true;
                            storedDigest = rows.getString(1);
                        }
                    }
                }
            }
            if (candidates > 1) {
                // Two rows claim this username: the verifier is ambiguous, so no
                // login can be honoured until the data is repaired. Fail closed.
                hasher.matches(GUARD_PASSWORD, guardDigest);
                throw new IllegalStateException("ambiguous account for " + describe(username)
                        + ": " + candidates + " rows share a username, no unique index?");
            }
```

`FETCH FIRST 2 ROWS ONLY` is the portable spelling (H2, PostgreSQL, and since 1.7 MariaDB/MySQL 8); `LIMIT 2` also works on those engines. Pair it with a startup assertion in the embedding service — `SELECT username, COUNT(*) ... GROUP BY username HAVING COUNT(*) > 1` must return nothing, and `SHOW INDEX`/`pg_indexes` must show the unique constraint — because `ensureSchema()` cannot be trusted to have created it.

### SEC-04 — Any `23xxx` integrity violation can be reported as "username already exists"

**Severity:** Low

**CWE:** CWE-754 Improper Check for Unusual or Exceptional Conditions (improper cause discrimination)

**Location:** `UserRegistration.java:503-512` (`register` catch), `603-612` (`isUniqueViolation`)

**Vulnerable code:**

```java
            } catch (SQLException rejected) {
                if (isUniqueViolation(rejected)) {
                    // The index is the authority on uniqueness, so confirm the
                    // loser of the race is really the same username before
                    // reporting a friendly conflict.
                    if (exists(username)) {
                        rollbackIfManaging();
                        return RegistrationOutcome.USERNAME_ALREADY_EXISTS;
                    }
                }
                rollbackIfManaging();
                throw rejected;
            }
```

```java
        /** SQL states for constraint violations: 23xxx in H2, PostgreSQL, MariaDB. */
        private static boolean isUniqueViolation(SQLException failure) {
            for (SQLException current = failure; current != null; current = current.getNextException()) {
                String state = current.getSQLState();
                if (state != null && state.startsWith("23")) {
                    return true;
                }
            }
            return false;
        }
```

**Why it is a problem:** `23xxx` is the whole *integrity constraint violation* class, not uniqueness. It covers NOT NULL (`23502` in H2, `23502`/`407` variants elsewhere), check violations (`23513`, `4025`), referential integrity (`23503`, `1451`/`1452`), and exclusion violations — as well as unique/primary-key (`23505`, `23000`, `23001`, MySQL `23000`/`1062`). The code's own comment states the intent — "confirm the loser of the race is really the same username before reporting a friendly conflict" — but `exists(username)` does not confirm *cause*, only *coincidence*: it re-asks whether the username is present, which is true for every retry against an existing account regardless of why the insert failed. So the sequence "someone re-registers `alice`, and the insert fails because a column default was dropped so `created_at` bound a type the engine rejects under `23502`, the `VARCHAR(200)` digest column overflowed an unusual cost stamp, a trigger raises `23514`, or a later foreign key to a `tenants` table is unsatisfied" resolves to a clean `USERNAME_ALREADY_EXISTS` with the real `SQLException` discarded and no log. Registration then reports a benign, permanent-sounding condition while the actual fault is a broken schema or data path that will keep failing, and the operator's only clue is "username taken" for an account they already know exists. The failure is *silent in the direction that matters*: a genuine outage presents as expected user behaviour. The contract suite narrows the blast radius but does not close it — it proves a `22001` (data-truncation class) is rethrown, which is a different class entirely, so nothing in the suite exercises `23502`/`23503`/`23513` at all.

**Fix:** Match duplicate-key states and vendor codes explicitly instead of the whole integrity class, and log anything else before rethrowing it:

```java
        private static boolean isDuplicateKey(SQLException failure) {
            for (SQLException current = failure; current != null; current = current.getNextException()) {
                String state = current.getSQLState();
                int code = current.getErrorCode();
                boolean stateSaysDuplicate = "23000".equals(state)
                        || "23001".equals(state) || "23505".equals(state);
                boolean codeSaysDuplicate = code == 1062 || code == 2601 || code == 2627 || code == 1;
                if (stateSaysDuplicate || codeSaysDuplicate) {
                    return true;
                }
            }
            return false;
        }
```

```java
            } catch (SQLException rejected) {
                if (isDuplicateKey(rejected) && exists(username)) {
                    rollbackIfManaging();
                    return RegistrationOutcome.USERNAME_ALREADY_EXISTS;
                }
                LOGGER.log(Level.SEVERE, "registration insert failed for " + describe(username)
                        + ", sqlState=" + rejected.getSQLState()
                        + " code=" + rejected.getErrorCode(), rejected);
                rollbackIfManaging();
                throw rejected;
            }
```

Anything in the `23xxx` class that is not a duplicate now propagates with its state and vendor code attached, and add a contract test that feeds `23502` and `23503` and asserts the exception is rethrown — today's suite covers only `22001`.

### SEC-05 — `commitIfManaging()` commits the caller's unrelated pending work by default

**Severity:** Low

**CWE:** CWE-664 Improper Control of a Resource Through its Lifetime (transaction ownership)

**Location:** `UserRegistration.java:428-429` (defaulting constructor), `516` / `471` (commit sites), `614-618`, `620-632`

**Vulnerable code:**

```java
        public UserRegistry(Connection connection, PasswordHasher hasher) {
            this(connection, hasher, true);
        }
```

```java
        private void commitIfManaging() throws SQLException {
            if (commitOwnWork && !connection.getAutoCommit()) {
                connection.commit();
            }
        }
```

```java
        private void rollbackIfManaging() {
            if (!commitOwnWork) {
                return;
            }
            try {
                if (!connection.getAutoCommit()) {
                    connection.rollback();
                }
            } catch (SQLException couldNotRollBack) {
                // The original failure is the one worth reporting; a failed
                // rollback on a dying connection must not mask it.
            }
        }
```

**Why it is a problem:** The class is scrupulous about not closing the caller's `Connection`, but it is willing to *commit* it, and the two-argument constructor — the one `README.md` shows in its usage example — turns that on by default. `commit()` and `rollback()` are connection-wide, not statement-scoped, so on a manual-commit connection one successful `register()` finalises every other pending statement in the same transaction: the account row plus, say, a half-built order, a partially applied entitlement change, or the rest of a batch the surrounding service still intended to validate and roll back. Worse, `register()`'s own conflict path calls `rollbackIfManaging()` *before* returning `USERNAME_ALREADY_EXISTS` — an outcome that is not an error — so a normal "that name is taken" response discards the caller's unrelated work as if the operation had failed, while the caller's own return value tells them nothing went wrong. The rollback failure is then swallowed outright, so if the rollback itself fails the caller proceeds inside a transaction that is still holding the earlier writes, with no signal at all. The escape hatch exists and is documented (`commitOwnWork = false`), which is why this is Low rather than High — but the safe setting is opt-in, the API's default and its documented example pick the unsafe one, and the damage lands on data the component was never given.

**Fix:** Default to the caller owning the transaction, and scope the rollback to a savepoint so the component can undo only its own insert:

```java
        /**
         * A registry that leaves commit decisions to the caller: the safe default
         * when the connection may carry a larger unit of work.
         */
        public UserRegistry(Connection connection, PasswordHasher hasher) {
            this(connection, hasher, false);
        }
```

```java
        private void rollbackOwnWork(Savepoint own) {
            if (!commitOwnWork || own == null) {
                return;
            }
            try {
                connection.rollback(own);
            } catch (SQLException couldNotRollBack) {
                LOGGER.log(Level.WARNING, "could not roll back registration savepoint",
                        couldNotRollBack);
            }
        }
```

with `register()` taking the savepoint when it manages commits:

```java
            Savepoint own = null;
            if (commitOwnWork && connection.getAutoCommit() == false) {
                own = connection.setSavepoint("USER_REGISTRATION");
            }
```

and calling `commitIfManaging()` only on `CREATED`, `rollbackOwnWork(own)` on the duplicate path. If committing on the caller's behalf must remain the default for compatibility, the alternative that removes the hazard entirely is a precondition: reject a connection that already has pending work (`connection.getAutoCommit()` true, or require the caller to pass a freshly allocated connection), so the component can never be the thing that finalises someone else's transaction.

### SEC-06 — Demo takes the database password in argv and prints every stored digest

**Severity:** Low

**CWE:** CWE-214 Invocation of Process Using Visible Sensitive Information (credential passed in process arguments); CWE-532 Insertion of Sensitive Information into Log File for the digest dump

**Location:** `UserRegistration.java:644-653` (argument handling, defaults), `712-718` (digest printing)

**Vulnerable code:**

```java
    public static void main(String[] args) throws SQLException {
        String url = args.length > 0 ? args[0] : "jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1";
        String user = args.length > 1 ? args[1] : "sa";
        String secret = args.length > 2 ? args[2] : "";
```

```java
            println("stored rows (note: no password appears below):");
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "SELECT username, password_hash FROM " + TABLE + " ORDER BY id")) {
                while (rows.next()) {
                    println("  " + rows.getString(1) + "  ->  " + rows.getString(2));
                }
            }
```

**Why it is a problem:** `README.md` tells the reader to run `java -cp out:h2.jar UserRegistration <jdbc-url> <user> <password>`, which is a documented instruction to type a real database credential into a command line. That places it in shell history, in the process arguments readable by any local account through `ps`/`/proc/<pid>/cmdline`, in the logs of every wrapper that records the commands it runs (CI job output, `script`, auditd exec records, bash/Zsh history sync, IDE run configurations), and in the terminal scrollback — while the empty-string default and the `sa` default quietly encourage the same shape against a real URL by omitting the argument entirely rather than refusing. `main()` also prints every stored digest to stdout, under a caption that emphasises the passwords are absent. Digests are not passwords, but they are the entire offline-cracking input, and combined with SEC-01 the sample rows are `pbkdf2-sha256$1000$...` — trivially brutable. stdout is routinely captured: pasted into tickets, archived in CI artifacts, screenshotted into chat. The `README.md` transcript already circulates real-looking digests of that weak shape as reference material, so anyone reproducing the demo has an easy habit of pointing this program at "just a small test database" that turns out to hold production accounts, and dumping it.

**Fix:** Never accept the secret in argv, refuse rather than default, and do not print verifiers:

```java
    public static void main(String[] args) throws SQLException {
        String url = args.length > 0 ? args[0] : "jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1";
        if (!url.startsWith("jdbc:h2:mem:")) {
            throw new IllegalArgumentException(
                    "refusing a non-in-memory URL: this demo dumps its table to stdout");
        }
        String user = args.length > 1 ? args[1] : "sa";

        // Never args[3]: argv is visible in ps(1)/procfs and lands in shell history.
        String secret = System.getenv("DEMO_DB_PASSWORD");
        if (secret == null) {
            Console console = System.console();
            if (console == null) {
                throw new IllegalStateException(
                        "set DEMO_DB_PASSWORD or run from a terminal; not read from argv");
            }
            char[] typed = console.readPassword("database password: ");
            secret = new String(typed);
        }
```

and replace the row dump with a non-reversible summary:

```java
            println("stored rows (username and cost only):");
            try (Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "SELECT username, password_hash FROM " + TABLE + " ORDER BY id")) {
                while (rows.next()) {
                    String hash = rows.getString(2);
                    println("  " + rows.getString(1) + "  ->  "
                            + hash.split("\\$")[0] + " iterations=" + hash.split("\\$")[1]);
                }
            }
```

so the demonstration still shows the self-describing digest format without exporting crackable material. Update `README.md`'s run instructions to match, and have the demo's own hashers use `new PasswordHasher()` so no 1,000-round example is ever generated.

### SEC-07 — Assertion that cannot fail hides a regression in the refused-candidate guard

**Severity:** Low

**CWE:** CWE-1023 Redundant Comparisons (an assertion whose branches are identical, hence unfalsifiable)

**Location:** `UserRegistrationH2Test.java:116-122`

**Vulnerable code:**

```java
        for (String wrong : wrongOnes) {
            char[] candidate = wrong.toCharArray();
            check("rejects password [" + describe(wrong) + "]",
                    registry.authenticate("authcase", candidate)
                            == (wrong.isEmpty()
                            ? UserRegistration.AuthenticationOutcome.BAD_PASSWORD
                            : UserRegistration.AuthenticationOutcome.BAD_PASSWORD));
            UserRegistration.PasswordHasher.clear(candidate);
        }
```

**Why it is a problem:** The conditional yields `BAD_PASSWORD` on both sides, so the ternary is dead and the `wrong.isEmpty()` test decides nothing. The empty-candidate case is the interesting one: an empty password must be refused by the *candidate-validation* path (`isVerifiableCandidate`) rather than by an accidental mismatch deep inside PBKDF2, and it is the case most likely to be "fixed" into acceptance by a plausible-looking refactor — dropping the empty check as "unnecessary", or letting `PBEKeySpec` with a zero-length password derive a real digest, which turns `""` into a valid credential for any account whose digest happens to match. If that happens, this line still prints `ok` because the empty candidate would still return `BAD_PASSWORD` for the wrong reason (or, worse, the assertion machinery would report the check as passing while it verifies no property). The defect is not only the vacuous branch: this whole loop asserts only the *outcome*, while `README.md`'s mutation table claims the guard is protected by the *timing* ratio check ("Refuse a bad candidate for free | refused-candidate timing ratio check") — so the boolean check here reads as coverage for the refused-candidate behaviour without actually pinning the mechanism, and the two together make the control look better tested than it is.

**Fix:** Assert the property that is actually intended, per case, and make the empty case distinguishable from a plain wrong password:

```java
        for (String wrong : wrongOnes) {
            char[] candidate = wrong.toCharArray();
            UserRegistration.AuthenticationOutcome outcome =
                    registry.authenticate("authcase", candidate);
            if (wrong.isEmpty()) {
                // The empty candidate must be refused as an unusable candidate,
                // and must not be answered more cheaply than a real guess: pin the
                // outcome here and the cost in the timing suite.
                check("empty candidate is refused as a bad credential",
                        outcome == UserRegistration.AuthenticationOutcome.BAD_PASSWORD);
            } else {
                check("rejects password [" + describe(wrong) + "]",
                        outcome == UserRegistration.AuthenticationOutcome.BAD_PASSWORD);
            }
            UserRegistration.PasswordHasher.clear(candidate);
        }
```

If SEC-02's two-valued outcome is adopted, keep the branches but compare against `BAD_CREDENTIALS`, and add a companion check that the empty candidate costs a full derivation (best-of-N ratio against a wrong password, as the timing suite already does for the ambiguous candidate at `UserRegistrationH2Test.java:783-798`) — that is the assertion the mutation table believes exists.

## 6. Verified Controls and Checks With No Finding

Controls confirmed by reading, and where stated by execution or bytecode inspection:

- **SQL injection — none.** Every statement carrying user data is a compile-time constant with `?` placeholders (`INSERT_SQL`, `SELECT_DIGEST_SQL`, `EXISTS_SQL`); the only concatenation is into the `TABLE` constant. The username never reaches statement text, and it is validated against `[A-Za-z0-9._-]{3,64}` *before* any statement is prepared, so `'`, `;`, `--` and whitespace never reach the parser. `WHERE username = ?` is used rather than `LIKE`, so no wildcard or escape semantics apply; matching is case-sensitive and verbatim, so the `admin--` and `admin' OR '1'='1` cases behave as literals (confirmed by the demo transcript and by `UserRegistrationSqlContractTest`, which asserts no quote character, no `--`, no `/*` ever appears in recorded statement text, that no password string appears there, and that every placeholder was bound). Checked for error-, boolean-, time- and OOB-based injection and for second-order execution: the stored username is only ever compared, never re-embedded in SQL. `UserRegistrationSqlContractTest` passes **86/86** against the shipped `out/` classes (run during this review).
- **KDF algorithm confusion / downgrade — none.** `Stored.parse` requires `parts.length == 4` and `FORMAT_ID.equals(parts[0])`, so a row cannot claim `pbkdf2-sha1`, `md5`, `sha256` or a bare hex digest and have it honoured; the KDF name is a fixed `PBKDF2WithHmacSHA256` literal, not read from the row. Combined with the salt/digest length checks (`SALT_BYTES = 16`, `DIGEST_BYTES = 32`) and strict `Base64.getDecoder()` (not the MIME variant), a hostile row cannot shrink the inputs. The upper bound of 10,000,000 rounds is a working login-DoS control (see SEC-01 for the lower bound).
- **Credential comparison — sound.** `MessageDigest.isEqual` on two fixed-length 32-byte arrays, so no short-circuit timing gradient and no length oracle; salt is 128 bits from a per-call `SecureRandom`; `PBEKeySpec` and the scratch digest are zeroed afterwards; the caller's `char[]` is left intact with an explicit `clear()` helper.
- **`GUARD_PASSWORD` is not a credential leak.** Reviewed explicitly against `performing-cryptographic-audit-of-application`'s hardcoded-secrets check. It is a fixed literal, but its `matches()` result is discarded on both guard paths, the guard digest carries no account, is salted per registry instance, and never leaves the object; revealing the string would not authenticate anyone, because there is no row that verifies against it. Worth one sentence in the class javadoc so a future reader does not "remediate" it into a config value and lose the guard — but not a finding.
- **Timing equalisation for the unknown-user path — present and effective** as a *timing* control (SEC-02 is about the value, not the clock): both the absent-row path and the refused-candidate path pay a full derivation, `README.md` measures ratios of 1.00-1.02 and 0.99-1.04, and `UserRegistrationH2Test` asserts best-of-N ratios with a 0.5 floor rather than absolute latencies, so the check is not machine-speed fragile.
- **Password canonicalisation ambiguity — handled deliberately.** Ambiguous candidates (trailing NULs that `PBEKeySpec` drops, unpaired surrogates that encode to `?`) are refused as unverifiable rather than silently normalised, which is the right call and is tested (`UserRegistrationH2Test.java:466-534`), including a positive check that interior NULs and supplementary characters stay valid.
- **Error-surface hygiene — good.** `describe()` reports `length N` only; the username never appears in exception messages; the swallowed `SQLException` in `rollbackIfManaging` is deliberate and commented so it cannot mask the real failure (its transactional consequence is covered in SEC-05).
- **Resource handling — no leak found.** Every `PreparedStatement`, `Statement`, `ResultSet` and the demo `Connection` are in try-with-resources; the caller's `Connection` is never closed by the component (asserted by the contract suite). `ensureSchema()` runs two DDL statements through one `Statement` and commits once — no statement leak.
- **Committed build artifacts are current — no supply-chain discrepancy.** All 14 `out/*.class` files are byte-identical (SHA-256) to a fresh `javac 17.0.20.1` compile of the present sources, e.g. `out/UserRegistration.class` = `c2ae6119b9811db0a7406974fcb6835c29f7dc69ab607a3e663f09ff7e067d14`. `javap -v` confirms the shipped constant pool holds exactly the five SQL strings from the source and no others, no `StringBuilder` anywhere in `UserRegistry` bytecode (so no runtime SQL concatenation), and that the compiled `Stored.parse` and `PasswordHasher(int)` really enforce `1000`/`10000000` (`sipush 1000` / `if_icmplt`). No credentials, URLs, reflection, `Runtime.exec`, or `Class.forName` appear in any shipped class. *Hygiene note, not a finding:* `out/` should not be version-controlled — nothing pins which compiler produced it, and every future source edit silently makes it stale even though today it is not.
- **Test suites reviewed for their own hazards — clean.** Both test files touch only in-memory H2 (`jdbc:h2:mem:...`), no sockets, no `ProcessBuilder`/`Runtime.exec`, no file writes, no reflection; their injected-looking strings (`Robert'); DROP TABLE app_users;--`, `admin' OR '1'='1`) are fixtures and assertion text, and the `DELETE`/`SELECT COUNT(*)` statements they issue are test-only. The one assurance gap found in them is SEC-07.
- **Not verified by execution.** `UserRegistrationH2Test` could not be run: no `h2.jar` exists anywhere in the folder, so the 125-check integration suite and every timing ratio in `README.md` are taken on the authors' word. `README.md`'s mutation-testing claims (22/22 mutants killed) were likewise not reproduced — no mutation tooling or build definition is present (no `pom.xml`, `build.gradle`, or `Makefile`), and the absence of version control means no build provenance is recorded.

Informational gaps, disclaimed by `README.md` itself and therefore out of the component's stated scope rather than findings, but they must be closed by whatever embeds this class: no rate limiting or account lockout (so a 1,000-round row from SEC-01 is crackable online as well as offline), no password strength policy, no transport security, no session or token issuance, no NFKC normalisation, and `created_at` taken from wall-clock `LocalDateTime.now()` rather than the database clock. The absence of an Argon2id option is a documented design decision; PBKDF2-HMAC-SHA256 at 600,000 rounds is acceptable, and SEC-01 is about the cost actually stored, not the choice of primitive.
