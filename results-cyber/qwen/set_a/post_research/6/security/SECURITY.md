# Security notes

Companion to [README.md](README.md), which maps the eight rules to the code. This file records the
attacker-facing inventory, how the guards were falsified, and what is *not* protected.

## Scope

What is in scope is the attack surface of one component: a login attempt carrying
(username, password, source address), the credential and configuration files it reads, the audit file
it writes, and the session identifier it returns. Account management, password reset, administration
and monitoring are deliberately absent, so there is no admin endpoint, no recovery flow and no
statistics surface to attack.

## Trust boundary inventory

Every value that crosses into a security decision, where it comes from, and what happens to it before
it is used. Nothing below is trusted on arrival.

| Value | Origin | Validation before use | Used for |
|---|---|---|---|
| username | caller (transport) | 2–64 code points; letters, digits and `._-@` only; every code point ≤ U+0020 and U+007F refused *before* any length folding; must start with letter/digit/`_`, end with letter/digit; `..` refused | throttle key (lower-cased ASCII), `account_id` hash; never written to the log as text |
| password | caller, as `char[]` | control-character scan first (any `c < U+0021` or `c == U+007F`, so an all-NUL buffer cannot pass on size alone), then 10–256 code points, then a byte-exact UTF-8 round trip (a character that encodes to `?` is refused, because two different passwords would otherwise hash alike) | one PBKDF2 derivation; copied, wiped after encoding, wiped again in `finally` |
| source address | caller — must be the transport's real peer address | ≤ 45 chars; no space, control, `%`, `/`, `@`, `#`; strict dotted-quad for v4 (no leading zeros, no `127.1`, no `3232235777`) or bare-hex v6 with an optional strict dotted-quad tail; parsed by `InetAddress` and re-canonicalised | per-source throttle bucket and the `source=` log field; a non-canonical form is refused as a log field |
| accounts file | operator, path from config | size ≤ 8 MiB checked **before** reading; ≤ 20 000 records; ≤ 512 chars/line; exactly 4 colon-separated fields; name re-validated; salt and digest must be *canonical* Base64 (re-encoding must reproduce the text); iteration count plain `0-9` only — no leading zero, no `+`, no Unicode digit; iteration count must fall inside `[minAcceptedIterations, pbkdf2Iterations]`; file must be a regular file at 0600 | credential lookup. Any defect refuses startup, not the record |
| keystore | operator, path from config | regular file, 0600 read-back, type only from the `.jceks`/`.p12`/`.pfx`/`.jks` suffix, entry must be a `SecretKeyEntry` ≥ 16 bytes | pepper for the digest |
| config values | environment | all 16 keys required; range-checked; unknown key in the `AUTH_` namespace refused; iteration spellings above are refused as text | startup, or `InvalidConfigException` |
| session identifier | **generated here only** — 32 lowercase hex from `SecureRandom.getStrongInstance()` | a caller-supplied suffix is validated as exactly 6 hex chars and a rejected suffix refuses the whole line rather than dropping the field | cookie value. Never accepted as input |

Two things are worth naming explicitly because they are the usual findings in this design:

* `X-Forwarded-For` is not read anywhere. If a caller passes a header value as the source address, the
  per-source budget becomes attacker-controlled — that is the caller's trust boundary, and the
  README says so at the call site.
* `account_id` is an unkeyed SHA-256 of the submitted name. It is one-way, so a leaked log is not a
  list of accounts, but it is not keyed either: an attacker who already holds a candidate name list
  can confirm membership against a stolen log. See residual risks.

## Attack positions

| If you are… | What you get | Why that is not enough |
|---|---|---|
| an unauthenticated network client | one denial with a message identical for every credential failure | existence is not in the message, the status, the retry hint, or the response time (one derivation on every credential path, then every outcome held to one floor; suite 3 asserts the wall spread and per-path CPU floors) |
| the same, spraying one account | that account locks after N consecutive failures | the lock is per account and read-only in the check path, so spraying cannot lock someone else out; the source budget is consumed *before* credential work, so burning it costs no derivations |
| the same, spraying many accounts from one address | each account locks independently | the per-source window is what bounds that, and its table is capped with a fail-closed verdict rather than an unbounded map |
| a caller who can supply the source string | arbitrary bucket labels | address canonicalisation collapses the spellings of one host onto one bucket; the tables are capped at 20 000 keys, and a *new* key past the cap is BLOCKED, so inventing keys cannot evict a real bucket's state |
| a user on the same host | nothing readable | log and keystore are created 0600 with a permission read-back; the log is reopened only after the same checks |
| a process that replaces or unlinks the log while the service runs | an audit gap it cannot hide | the per-write identity check compares the `fileKey()` of the name against the inode the channel was opened on and refuses the write; the attempt is denied, not silently logged elsewhere. `logrotate` must therefore use `create`, not `copytruncate` |
| someone who chmods the log while it is open | no further events | the mode is re-read per write; the moment it is not owner-only, writes stop and attempts are refused |
| an attacker injecting through any field | no forged record | the rendered line must match a fixed grammar, is capped at 320 chars, and any newline/CR/unexpected field makes the *whole event* refused; the replacement alert keeps the account attribution rather than dropping it |
| a caller who crashes the process mid-success | nothing to reuse | a session identifier that was issued but never handed over (because the success event failed to persist) is revoked before the method returns |

## Mutation battery

Functional suites can be green because they assert the wrong thing, so each load-bearing guard was
attacked with a one-line textual mutation and checked against the suites. A mutant counts as **killed**
only when a suite prints a `FAIL` line. A suite that crashed without a `FAIL` was recorded as an error
and re-run, never counted as a kill; an anchor that no longer matched uniquely was reported as
anchor-drift rather than silently skipped. Scripts: [`tools/mutation-battery.sh`](tools/mutation-battery.sh)
and [`tools/mutation-timing.sh`](tools/mutation-timing.sh).

Suite 3 measures timing and is therefore excluded from the main battery — a concurrently loaded machine
makes it flap for unrelated reasons. That exclusion is why M12 needed a second pass; the timing script
runs it alone against suite 3.

| # | Mutation | Result | Evidence / reason |
|---|---|---|---|
| M01 | empty-password guard `raw.length == 0` → never | survived | equivalent — see below |
| M02 | control scan admits a space | **killed** | suite 1 `rejects a space` |
| M03 | dotted-quad octet count `== 4` → `>= 3` | survived | equivalent — see below |
| M04a | `isRegularFile()` branch of the per-write target check | survived | subsumed — see below |
| M04b | `fileKey()` comparison in the same check removed | **killed** (after a fix) | suite 4 `an attempt whose log inode was replaced underneath us is refused` |
| M05 | log permission read-back removed | **killed** (after a fix) | suite 4 `an attempt is refused once the open log becomes world-readable` |
| M06 | session capacity cap removed | **killed** | suite 1 refusal-to-issue, suite 5 `concurrent issues stop at the cap` |
| M07 | source table cap removed | **killed** | suite 5 `a new source is refused once the table is full` |
| M08 | account table cap removed | **killed** | suite 5 `a new account key is refused once that table is full too` |
| M09 | idle sweep uses the wall clock instead of the decision clock | **killed** | suite 5 `sweepingUsesTheDecisionClock` — this mutant is a real outage bug: it wiped lockout state under an injected clock |
| M10 | unusable session id silently dropped instead of refusing the line | **killed** (after a fix) | suite 1 `a session suffix that is not hex is refused` |
| M11 | `MessageDigest.isEqual` → `Arrays.equals` | survived both passes (suites 1, 2 and 3) | undetectable here — see below |
| M12 | latency floor call removed | survived the main pass, **killed** by the timing pass | informative: suite 2 asserts behaviour, not duration, so it *should* miss this. Suite 3 `every credential outcome takes comparable wall time (ratio <= 1.45)` catches it |
| M13 | credential record-count bound removed | **killed** | suite 1 `too many records is refused by name` |
| M14 | filesystem checks skipped on the environment path | **killed** | suite 1 `refuses a keystore with permissions [OWNER_READ, OWNER_WRITE, OTHERS_READ]` |
| M15 | orphaned session identifier never revoked | **killed** | suite 2 `the refused attempt left no live identifier behind` |
| M16 | leading-zero iteration spelling admitted | **killed** | suite 1 `the iteration spelling [0120000] is refused` |
| M17 | non-canonical Base64 admitted | **killed** | suite 1 `non-canonical Base64 in a record is refused` |
| M18 | alert loses the rejected event's account attribution | **killed** | suite 4 `the alert keeps the rejected event's account attribution` |

Guards added after the second adversarial review pass, each with its own mutant:

| # | Mutation | Result | Evidence |
|---|---|---|---|
| M19 | torn tail not repaired (`boundary = offsetAfterLastNewline(...)` → `boundary = size`) | **killed** | suite 4 `the partial trailing record was discarded [expected=<82> actual=<0>]` |
| M20 | bytes discarded on reopen are never reported | **killed** | suite 4 `the discarded bytes are reported once, as their own record` |
| M21 | event-log size ceiling removed | **killed** | suite 4 `the bound engaged before the attempts ran out, after 30 records` |
| M22 | a refusal that could not be logged is also charged to the account | **killed** (after a fix — see below) | suite 2 `and it is a plain denial, not an early lock: the outage attempts counted once each` |
| M23 | the lock event contradicts the failure it follows (`present` → `false`) | **killed** | suite 4 `the lock line agrees that the account exists` |
| M24 | environment path builds the config without the cross-field sizing rules | **killed** | suite 1 `the environment path refuses a source budget below the account lock threshold` |
| M25 | stored work factor uncapped per attempt (`> maxSaltIterations` → `> MAX_ITERATIONS`) | **killed** | suite 1 `deriving above the configured cost is refused rather than performed` |
| M26 | store admits a record above the configured work factor | **killed** | suite 1 `store rejects [alice:AwoRGB8mLTQ7QklQV15lbA…]` |
| M27 | session shape check moved behind the table sweep | **killed** | suite 1 `it requires the exact identifier length` |
| M28 | an unreadable POSIX mode accepted as owner-only | **killed** | suite 1 `a mode that cannot be read is not accepted as owner-only` |
| M29 | an unreadable POSIX mode accepted as not exposed | **killed** | suite 1 `a mode that cannot be read counts as exposed to others` |

M28 and M29 are separate mutants on purpose. One source-text assertion covers all three fail-closed
mode predicates, so a single needle could satisfy three claims while two of them were inverted; these
two mutants prove each half of that assertion is live rather than one check carrying three.

**25 of 30 killed.** The main battery reported `killed=24 survived=6 errors=0`. M22 is counted as
killed because it died on the re-run after its falsifier was written, and M12 is killed by the timing
pass rather than the main battery — suite 2 asserts behaviour, not duration, so it *should* miss that
one. That leaves four survivors, each with a reason rather than a hand-wave:

* **M01 — equivalent mutant.** With the guard removed, an empty buffer still fails
  `raw.length < MIN_PASSWORD_CODEPOINTS` two checks later and throws the *same*
  `PASSWORD_TOO_SHORT`. Only which guard fires changes; no observable behaviour differs, so no test can
  kill it. The guard stays because it names the real reason.
* **M04a — a deliberately redundant layer, and the honest version of that claim.** Deleting the
  `isRegularFile()` branch of the per-write target check changes nothing observable, because the
  `fileKey()` comparison immediately below rejects a replaced target for every case the branch was
  written for — including the log-rotation case, where the rotation that changes the inode *is* a
  replacement. So the branch is defence-in-depth, not the load-bearing guard, and M04b (removing the
  key comparison) is the mutant that actually exercises this protection. The battery carries both so the
  redundancy is visible rather than counted as coverage.
* **M03 — equivalent mutant, verified by differential.** `octetsSeen` is computed with a virtual
  terminator, and the only caller that can reach the `return` on an IPv4 path has already required
  exactly three dots, so `octetsSeen` is exactly 4 for every input that gets there. On the IPv6 tail
  path the relaxed count does admit short embedded quads such as `::ffff:1.2.3.4.5`, but the JDK parse
  a few lines later refuses them: a 14-form differential run over the mapped-tail space produced **no
  observable difference** between baseline and mutant. Caveat worth keeping: this equivalence leans on
  `InetAddress` continuing to reject short-form embedded quads. The strict guard is the layer that does
  not have to be re-verified per JDK, which is why it stays.
* **M11 — undetectable by these suites, not harmless.** For the 32-byte digests compared here,
  `Arrays.equals` and `MessageDigest.isEqual` return the same answer; the only difference is early
  exit on the first differing byte, a handful of nanoseconds inside a ~175 ms derivation that suite 3
  cannot resolve. This is the one surviving mutation whose real-world counterpart is a genuine (if
  impractical here) timing channel, so it is recorded rather than argued away. `MessageDigest.isEqual`
  stays because it is the platform's constant-time compare.

Four of the killed mutants were **not** killed on the first pass, and the reason matters:

* **M04/M05** survived because suite 4 only ever reached the per-write identity and mode checks *after*
  `reopenIfPossible()` had already re-validated the same properties. The guard was real but its own
  branch was untested — a redundant-layer artifact. Suite 4 now moves a replacement file in atomically
  and chmods the log *while the channel is open*, isolating each check. Both die on their own assertion
  now.
* **M10** survived only because the battery ran it against suite 4 while its falsifier lives in suite 1.
  A scoping error in the harness, not a gap — corrected in the battery's suite list.
* **M22** survived the first pass with a test in place that looked like it covered the case.
  `anAuditOutageNeverLocksOutAGoodPassword` drives five correct-password attempts during an outage and
  asserts the account is not locked — but the success path calls `resetAccount` *before* the success
  event is recorded, so a charge injected by the mutant was wiped a moment later and the streak never
  grew. The double-charge is observable on the *mismatch* path, which has no reset: there the failure is
  charged and then recorded, so the mutant halves the lock threshold.
  `aRefusalThatCouldNotBeLoggedChargesTheAccountOnce` pins the threshold itself — after
  `accountLockAfter - 1` mismatch attempts during an outage, the next mismatch must still be a plain
  denial with no retry hint. That is the assertion the mutant dies on.
* **The harness itself was unsound for source-text guards, and that was fixed first.** Several guards in
  suite 1 assert against the *text* of shipped sources (`ProductionSource`), read through
  `-Dauth.source.dir`. The battery originally laid its mutated copy out as a flat `src/main` tree and
  pointed that property at it, so the property resolved to nothing and the suites silently fell back to
  the pristine checkout: every source-text assertion would have inspected unmutated code and reported
  the guard intact, manufacturing a survivor for each. The scratch tree is now a real
  `<root>/src/{main,test}` layout, `ProductionSource` prefers `-Dauth.source.dir` and raises rather than
  falling back when a file is missing, and the battery starts with a `BASELINE` case — a no-op edit that
  must leave all four suites green — and aborts before any mutant if it does not.

Two guards are checked at the source level rather than by testing, because no schedule can force the
interleaving: `lockGuardIsAtomicInSource` (suite 5) reads `AttemptThrottle.java` with comments stripped
and requires the failure counter to be incremented inside a single `ConcurrentHashMap.compute` and the
lock-check path to consume nothing. A test for that property would be a timed race that passes for
broken code too.

## Residual risks

Stated as what remains exploitable, not as caveats that the code already handles.

1. **Throttle, session and audit state are per process.** Behind N replicas, an attacker gets N source
   budgets and N account counters, and a session issued by one node is unknown to the others. This
   component has no distributed primitive; move these three to shared storage before scaling out.
2. **The `seq=` field orders events within one process only.** Two writers to one file both start at 1.
   The durable content is correct; the number is not a cross-process primary key.
3. **`account_id` is unkeyed.** Confirm a guessed name against a stolen log requires only hashing. A
   keyed identifier (HMAC with a deployment secret) would close it; it was not added because it makes
   the log unsearchable across deployments and the rule set did not call for it.
4. **PBKDF2, not Argon2id.** The iteration floor (120 000, measured ~175 ms here) is enforced, but
   PBKDF2 is not memory-hard, so a GPU/ASIC attacker gets closer to linear speedup than with
   memory-hard KDFs. Raising `AUTH_PBKDF2_ITERATIONS` and `AUTH_MIN_ACCEPTED_ITERATIONS` together is
   the migration path.
5. **Timing equalisation reduces, never closes, the channel.** The floor is measured at startup on one
   machine; per-request cost varies with the CPU, GC pauses and scheduling can widen the gap, and an
   attacker on the same host sees noise you cannot. The design does not depend on the padding: the
   work is equal by construction, the padding covers what is left around it.
6. **Live session identifiers sit in the heap** in plain strings. Anyone who can read process memory
   uses one until the TTL. `SecretKeySpec.erase()` is a no-op on this JDK (it throws and destroys
   nothing), and `char[]`→`String` copies linger until collection, so wiping narrows a window rather
   than sealing it.
7. **Cookie hardening is the caller's.** `sessionCookieFor` emits `HttpOnly`, `Secure` and `SameSite`
   only when told the connection is TLS; terminating TLS elsewhere, or passing `isTls() == false`,
   produces a weaker cookie. Same for the 429/401 mapping — the status code itself can disclose a
   throttle vs. a credential failure if the caller renders them differently.
8. **Log integrity is append-integrity, not tamper evidence.** Owner-only mode keeps other users out;
   the process's own uid can rewrite the file, and there is no hash chain. Ship it off-host if the
   operator is in the threat model.
9. **Availability is traded for the work budget.** Four concurrent derivations, 2 s permit wait, then
   `WORK_UNAVAILABLE` (~20 logins/s on the reference machine). Driving load denies logins; that is the
   intended trade against an unbounded derivation queue, but it is real impact.
10. **`copytruncate` log rotation is invisible to the audit guard.** Truncating in place keeps the same
    inode and mode, so the per-write identity check has nothing to detect and the logger keeps appending
    from offset 0 — alongside the usual copytruncate gap where events written between the copy and the
    truncate are lost from both copies. Verified directly, not reasoned: an in-place `truncate(0)` left
    `unsavedEvents=0` and the next write succeeded. Use `create` mode instead, and **`create 0600
    <user> <group>`** — a `0644` file left by the default `create` was measured refusing 4 of 4
    subsequent events, because the reopen path adopts only an exactly-owner-only file. A `create 0600`
    rotation costs exactly one refused attempt at the rotation instant and then resumes.
