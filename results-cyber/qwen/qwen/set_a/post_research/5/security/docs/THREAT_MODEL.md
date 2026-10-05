# Threat model — employee portal authentication

Scope: the sign-in feature (CLI + HTTPS portal) in `com.portal.auth`.
Reviewer stance assumed: a network-resident attacker, an authenticated but malicious
employee, a malicious/compromised operator, and a stolen credential dump.

Every number and identifier below was re-read from the source, not carried over from an
earlier draft. An earlier revision of this file quoted back-off ceilings that were
swapped, a session-id length that was off by one character, an
`includeSubDomains` attribute the code never emitted, and two class names that do not
exist. A threat model that has drifted from the code is worse than none, because it is
read as a claim that someone checked.

## 1. Inputs crossing the trust boundary

Every row below is treated as attacker-controlled. "Gate" = the code that must vouch
for the value before it is used.

| # | Input | Arrives via | Gate |
|---|-------|-------------|------|
| 1 | username | CLI stdin, `POST /login` form field | `InputPolicy.isUsername` — 3–32 chars, `[a-z0-9._-]`, alphanumeric first and last, no `..`; no trimming, ever |
| 2 | password | `Console.readPassword`, private pipe, form field | `InputPolicy.secret` + `strengthFailure` — 12–128 chars, printable ASCII `0x21..0x7E` only, no leading/trailing space, no control chars, no unpaired surrogates; never trimmed |
| 3 | one typed line (CLI) | stdin, possibly a pipe | `PortalCli` — 1024-char cap, CR terminates a line rather than being deleted, over-long line aborts the field |
| 4 | roster file (`employees.dat`) | disk, operator/backup/other process | `EmployeeStore.load`/`parse` — 8 MiB file cap, 256-byte line cap, strict `u=<name> r=<record>`, name re-validated, KDF-iteration floor, canonical base64, duplicate name ⇒ refuse the whole load, 50 000-account cap, file mode + `NOFOLLOW` |
| 5 | throttle ledger (`throttle.log`) | disk | `Ledger` — 4 MiB / 50 000-line cap, `v2\|kind:subject\|windowStart\|count\|blockedUntil\|generation` grammar, key must be `a:`/`s:` + 16 hex, values range-checked, unparsable line ⇒ refuse |
| 6 | audit log (`audit.log`) | disk | write-only from this process; never parsed for a decision; 200 000-line retention |
| 7 | config file (`portal.properties`) | disk, `PORTAL_CONFIG` | `PortalConfig.readConfigFile` — 16 KiB cap, mode must have no group/other bits, symlink refused, **unknown key ⇒ refuse to start**; every value type/range/charset checked |
| 8 | env vars (`PORTAL_DATA_DIR`, `PORTAL_CONFIG`, `PORTAL_KEYSTORE`, `PORTAL_KEYSTORE_PASSWORD_FILE`, `PORTAL_TRUSTED_PROXY_CIDRS`) | process env | `PortalConfig.fromEnvironment` — same gates; paths must be absolute, may not contain a `..` segment, must not descend through a world-writable ancestor |
| 9 | JVM system properties | command line | same loader; cannot lower a security floor |
| 10 | session cookie (`PORTAL_SESSION`) | HTTP request | `InputPolicy.isOpaqueToken` (43 base64url chars = 32 bytes) then `SessionManager.find` — **hash → server-side lookup**; absent/unknown/expired ⇒ anonymous |
| 11 | CSRF cookie + form field | HTTP request | `InputPolicy.isOpaqueToken` (32 chars = 24 bytes) + constant-time compare; both present and equal, single-use (consumed on use), 15-min TTL, 50 000-entry cap |
| 12 | request body | HTTP | 8 KiB hard cap before parse, `Content-Length` required (no chunked), `application/x-www-form-urlencoded` pinned, known keys only, duplicate keys refused |
| 13 | `X-Forwarded-For` | HTTP | **ignored unless** the peer is inside `portal.trusted.proxy.cidrs`; then strict manual CIDR parse — no DNS, no `InetAddress.getByName`, all-digit prefix, no leading zero, no `+` |
| 14 | TLS keystore + its password file | disk, env | must be supplied together, mode ≤ 0600, symlink refused, type pinned to PKCS12, password file ≤ 512 bytes and printable-ASCII-only, no default password |
| 15 | CLI argv (subcommand, flags) | operator shell | allowlist of subcommands; `PortalCli.safeToken` gates any token taken from argv to `[A-Za-z0-9-_.:]`, ≤ 80 chars, else `unspecified`; **no secret may be passed on argv** |
| 16 | clock (`Instant.now`) | OS | expiry windows only; skew never extends a lockout |

Non-inputs, for contrast: session ids, CSRF tokens, salts and derived keys are
**generated** here (`SecureRandom`, `Crypto.randomUrlToken`), never accepted from a caller.

## 2. Attacks the reviewer will try, and the defence

1. **Username enumeration** (timing / message / status-code differences between
   "unknown user" and "wrong password"). → One body (`Access denied.`), one status, one
   header block, and a `Content-Length` identical for every refusal; the KDF runs
   against a decoy salt for unknown names so the CPU work matches; every refusal path is
   padded to a single absolute latency floor. The header block has **no per-branch
   variant** — see defect 7 below.
2. **Prefix/suffix folding** — `alice\t`, `alice `, `alice␀`, `ALICE`, `ａｌｉｃｅ`,
   `ali\u006ce`, `alice\r127.0.0.1`. → No trimming anywhere. The username must match the
   full-string rules, so an invisible or full-width variant is rejected rather than
   folded onto a real account. `String.trim`/`strip` is banned in this package: it
   deletes control characters (≤ U+0020, including NUL and tab). CR terminates an input
   line instead of being swallowed — see defect 2.
3. **Lockout as a denial-of-service tool** (attacker spends their own 5 guesses to
   freeze a colleague's account). → Account back-off starts at 30 s and doubles per
   repeat trip, capped at **900 s (15 min)** precisely because a long account lock is a
   weapon an attacker can afford. A correct password clears the account's count, block
   and strike history. The per-source budget (30 failures / 300 s) is spent *before* the
   account can be locked by a single address, and the source ceiling is long (8 h)
   because the blocked party is the attacker's own address, so there is no weapon there.
4. **Counter reset by restart / log rotation** → the ledger is on disk and survives
   restart (24 h retention window). Keys are SHA-256 refs, so a stolen roster does not
   reveal who is locked. Pruning is window-based, never "delete everything".
5. **Check-then-act races** → within a process, the decision and the counter mutation
   happen in one `synchronized` transition that returns the verdict. Across processes,
   `Ledger` and (since defect 6) `EmployeeStore` each take an exclusive `FileLock` on a
   sibling lock file and re-read the file while holding it, so a short-lived CLI process
   cannot write over a sibling's change. Serialising the *writer* is not sufficient for the
   roster, because the authenticating process is a long-lived *reader* (see defect 8): it
   re-checks the file's identity before every decision and re-adopts it when it changed.
6. **Brute force with the server's CPU budget** → PBKDF2-HMAC-SHA256, 150 000 iterations
   (≈ 215 ms/derivation, measured on an idle instance of this box; the cost is linear, so
   100 000 ≈ 165 ms and 2 000 000 ≈ 2.85 s), floor 100 000, ceiling 2 000 000; a record
   outside that range is refused at the load boundary, never honoured; the per-source budget
   bounds aggregate cost.
7. **Session fixation / prediction / reuse** → ids are 256-bit `SecureRandom`, only the
   SHA-256 of the id is stored, a session is minted only *after* successful
   authentication, cookies are `HttpOnly; Secure; SameSite=Strict; Path=/`, idle 20 min +
   absolute 8 h, 10 000-session cap, logout removes state and expires the cookie.
8. **CSRF-driven login** (attacker logs the victim into the attacker's account) → login
   requires a cookie+field token pair the server issued, single-use, 15-min TTL.
9. **Leak through logs/errors** → the audit line grammar is
   `ts=… event=… subject=<16hex> src=<16hex> outcome=… detail=…`; `ref()` accepts only a
   16-hex ref or `-`/`invalid`, and `token()` character-gates, so an attacker-supplied
   string cannot forge a field. No path can put a password, session id or keystore
   password into a line (tests assert on captured output). Stack traces go to the log,
   never the response.
10. **Leak through files** → roster, ledger, audit log, lock files and keystore are
    created `0600` inside a `0700` directory; a pre-existing file with group/other bits
    is refused rather than used; writes go temp→fsync→`ATOMIC_MOVE`.
11. **Credential in memory** → passwords are `char[]` end to end, wiped in a `finally`;
    no `String` copy of a password is constructed.
12. **Supply chain** → zero third-party runtime code (JDK 21 built-ins only). The one
    network fetch in the build is the JDK tarball, SHA-256-checked against Adoptium's
    published digest (`tools/get-jdk.sh`).
13. **Planted code or data** → data dir must be owned by us, not world-writable, with no
    world-writable ancestor; the launcher fixes the classpath to its own `out/main`,
    clears `CLASSPATH`, and uses no `.`-discovery (verified: running from a directory
    containing a planted `com/portal/auth/Main.class` does not load it).
14. **Oversized input as memory DoS** → every reader is bounded (§1). Unknown or
    unparsable ⇒ refuse, never "best effort".
15. **Downgrade / cleartext** → HTTPS only; with no keystore configured the portal
    refuses to start rather than fall back to HTTP.
16. **Permissive defaults** → every unsatisfiable startup or consistency check ends the
    process with a generic message. There is no default for an unrecognised value,
    unknown config key, unknown subcommand or unparsable record.

## 3. Defects found by attacking this build

Each was found while trying to report something, not while writing the code, and each has
a test that fails if it returns. Listed in the order found, with what made it reportable.

| # | Defect | How it was found | How it is now tested |
|---|--------|------------------|----------------------|
| 1 | The `..` guard on `PORTAL_DATA_DIR` ran on the **normalised** path — normalising deletes `..`, so the guard could never fire. Startup then created a fresh 0700 directory under `/etc`. | Read the guard, then traced what `Path.normalize()` returns. | `ConfigCliSuite`: exit code 2 + machine token + a before/after diff of the target directory's contents. Mutant M13 restores the old guard and is killed. |
| 2 | A carriage return was **deleted** from input instead of terminating the line, so `alice\r127.0.0.1` folded onto the account `alice` and the trailing text became the next field. | Fed raw CR bytes through the real binary. | `PortalCli` CR-terminates (with 1-slot pushback for CRLF); `ConfigCliSuite` drives real CR/CRLF/LF transcripts. Mutant M18 reverts it and is killed. |
| 3 | `set-password` on a **disabled** account silently re-enabled it. | Asked what a reviewer would say about an operation that un-disable's an account while looking like a password change. | The audit detail distinguishes `updated` from `updated-re-enabled`, the CLI warns, and `isDisabled` exposes the state. Mutant M17 forces the flag false and is killed. |
| 4 | Integer-valued config/CIDR fields leaned on `parseInt`, which accepts a leading `+`, so `portal.listen.port=+8443` or `10.0.0.0/+8` parsed. | Tried the character each validator *forgot*. | Explicit all-digit grammar checks; `+8`/`+0` fixtures in `SourceRefSuite` and `ConfigCliSuite`. Mutants M14/M15. |
| 5 | The durable failure counter was **merge-monotonic** (`max(count)`), so a success's `count=0` was immediately restored from the stale on-disk value: the **6th consecutive correct login was denied** while every individual login succeeded. | Reproduced the suite's payload order against one ledger and read the audit `detail=` token. | A per-subject `generation` field in the `v2` ledger format; `AuthFlowSuite` asserts 8 consecutive correct logins all succeed *and* that a hostile burst still locks. Mutant M12 goes monotonic again and is killed. |
| 6 | `EmployeeStore` serialised roster writes with an **in-process monitor only**, so concurrent CLI processes lost updates: **8 concurrent `add-user` runs all exited 0 and 6 of the 8 accounts were silently discarded.** | Ran 8 real `add-user` processes against one data directory, three times. | Every mutator now takes an exclusive `FileLock` and re-reads the file under it; `ConfigCliSuite` launches 8 writers and asserts all 8 records survive, each writer's own exit code, and that a contested name is won exactly once. Mutants M24/M25. |
| 7 | `Strict-Transport-Security` was omitted on the 404/405/415/500 replies and sent on the authentication replies, so the **header block itself distinguished the branches** — while its own javadoc claimed every reply carried the same headers. | Booted the portal with a generated keystore and compared a real 404 against a real 401. | `securityHeaders()` takes no flag; `HttpSuite` asserts every response cell has an **identical** header set and each sends HSTS; `CoreSecuritySuite` refuses the return of a `withHsts` parameter. |
| 8 | The long-lived `portal` process authenticated against the roster copy it read at start-up, while `disable-user` and `set-password` are **separate short-lived processes**. After `disable-user` had written `r=disabled$v1` the running portal still answered `303`; after `set-password`, the **superseded** password still answered `303`. The operator believed a revocation had landed that had not. | Ran the real portal on a real port, drove the CLI against the same data directory, and read the status code back. | `EmployeeStore.refreshIfChanged()` compares the roster's file key + size + mtime and reloads under the monitor; it is the first statement of `Authenticator.decide`, so its one `stat` costs the same on every branch and is a function of the file, never of the presented name. A roster that stops parsing fails **closed** to an empty map (logged once, never rewritten) and recovers without latching. `AuthFlowSuite.rosterPropagation` covers disable→deny, rotate→old password dead / new password live, enrolment without restart, and the fail-closed/no-latch pair. Mutants M26/M27/M28. |

Two observations that were *not* defects but changed the tests:

- `java.util.Properties` strips leading value whitespace and keeps trailing, so
  `portal.listen.host = 127.0.0.1 ` yields an invalid literal that is (correctly) refused.
  Pinned as documented behaviour in `ConfigCliSuite` rather than worked around.
- A test must own only what its own process does. "The directory must not exist" was
  replaced by "this run neither created it nor wrote into it" after a mutation-battery
  run left a root-owned `/etc/portal-x` behind and made every honest run afterwards fail
  a check unrelated to the code under test.
- A **surviving mutant is a test gap, not a code bug**, and the two must be told apart by
  reading the code rather than by deleting the mutant. M23 (drop `recordFailure` from the
  unknown-username branch) survived the whole suite. The production behaviour is correct,
  but nothing in the suite could notice its removal, because every existing source-block
  assertion sprayed *known* accounts — and a known account's own block was arming the
  ledger row that made the source look blocked. `beginAttempt` only *counts*; the timed
  window is armed exclusively by `recordFailure`, so an unknown-name spray would have kept
  a throttled attacker on a 300 s rolling window instead of the 8 h ceiling. The suite now
  sprays only names that do not exist and asserts the *source* is blocked and its armed
  window reaches the ceiling.
- Two helpers turned a **lossy charset into a security decision**, on inputs that were
  already validated, so nothing was broken: `idRef(String)` hashed
  `getBytes(US_ASCII)`, which replaces any non-ASCII character with `'?'` — two different
  names would have shared one throttle bucket — and `equalConstantTime` did the same to the
  two CSRF operands before comparing them. Both call sites validate first
  (`InputPolicy.isUsername` / `isCsrfToken`), so the fold was unreachable; it is still what
  a reviewer would report, because the transform is one edit away from the decision. Both
  now refuse non-ASCII instead of encoding it, and `CoreSecuritySuite` pins the refusal in
  both directions ("`café` vs `café`" must not compare equal, and `'?'` is not a character
  any account name may contain). Mutants M29/M30 restore each fold and are killed. The same
  pass corrected `idRef`'s javadoc, which described the 16-hex-character truncation as
  "128 bits" when it is 64 — the README had the number right and the comment did not.

## 4. Deliberate deviations (documented residual risk)

- **Externally supplied identifier**: a session id is *accepted* from the cookie, but
  only as a lookup key into server-side state; it grants nothing by itself. Residual
  risk: a stolen cookie on a TLS-terminated connection is usable until expiry — bounded
  by 20 min idle / 8 h absolute, `SameSite=Strict`, HTTPS-only.
- **`X-Forwarded-For`** is ignored by default. Enabling it via
  `portal.trusted.proxy.cidrs` trusts those peers to have set it; wrong config =
  per-source throttling becomes spoofable. Per-*account* throttling is unaffected.
- **Per-source limit and a shared NAT**: a large office behind one address shares the
  per-source budget. The CLI's own source label is the constant `local`, so all CLI
  logins on one host share one budget by construction.
- **Password strength rules are enforced at enrolment only.** Applying them at login
  would create a second, distinguishable failure reason.
- **HSTS is emitted without `includeSubDomains` or `preload`**: this host is not
  necessarily a domain root, and widening the policy to subdomains the operator does not
  control is a worse failure than a narrower one.
- **The roster lock file is advisory.** `FileLock` is process-local: it serialises the
  CLI and the portal on one host, not two hosts sharing a network filesystem. Two
  writers over NFS can still lose an update. Residual risk accepted because the roster
  is documented as host-local state (rule 5's owner-private directory), and a writer who
  can reach the file can delete it anyway.
- **The ledger merge is generation-based, not record-based.** Concurrent writers on the
  same subject keep the higher generation's count and the larger `blockedUntil`; two
  processes that each recorded one failure in the same window may collapse to one count.
  That direction under-reports a *source* by at most one increment per writer and never
  clears a block, so it cannot widen the budget. Same residual-risk boundary as above.
- **PBKDF2 over Argon2id**: the JDK ships no memory-hard KDF, and rule 8 says prefer the
  platform over a hand-rolled or third-party primitive. 150 000 PBKDF2-SHA256 rounds is
  the platform's best provable option; the record format already carries a version field
  so a memory-hard implementation can be dropped in behind it.
- **`com.sun.net.httpserver`** is a JDK-bundled HTTP engine, not a hardened server.
  Mitigated by the request-shape limits in §1 and by refusing anything unexpected;
  it registers a single context (`/`) whose dispatcher serves exactly two routes,
  `/login` and `/logout` — every other path is a 404 with the same header block and body
  as every other refusal.
