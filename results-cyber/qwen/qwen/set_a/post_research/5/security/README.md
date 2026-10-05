# Employee portal authentication

A self-contained Java 21 authentication feature: an employee enters a username and
password, the program checks them against stored records, and grants or denies access.
Repeated failures are restricted per account **and** per source, so the restriction cannot
be used to lock a legitimate user out of their own account.

Two front ends share one decision function:

* `portal login` and the enrolment/admin commands — a batch/terminal client
* `portal portal` — an HTTPS listener with a sign-in form and session cookies

Everything is the JDK's own platform: PBKDF2-HMAC-SHA256 for password storage, `SecureRandom`
for tokens, `MessageDigest.isEqual` for comparisons, `java.nio.file` POSIX modes and atomic
moves for state, `FileLock` for cross-process counters, and `com.sun.net.httpserver` for
TLS. **There is no third-party runtime dependency, so there is nothing to download, pin, or
verify at build time.** The one network fetch in the whole project is `tools/get-jdk.sh`,
which retrieves the compiler itself and refuses the tarball unless its SHA-256 matches.

## Build and run

```sh
tools/get-jdk.sh                                  # optional: fetch + verify JDK 21
JAVA_HOME=/path/to/jdk-21 ./build.sh              # javac -encoding US-ASCII -Xlint:all -Werror
JAVA_HOME=/path/to/jdk-21 ./test.sh               # every suite
JAVA_HOME=/path/to/jdk-21 ./test.sh AuthFlow      # one suite by name
```

```sh
export PORTAL_DATA_DIR=/var/lib/portal            # required, created 0700 if absent
export PORTAL_CONFIG=/etc/portal/portal.properties
tools/gen-cert.sh /etc/portal/tls                 # throwaway keystore; see the note below
export PORTAL_KEYSTORE=/etc/portal/tls/portal.p12          # required for `portal portal`
export PORTAL_KEYSTORE_PASSWORD_FILE=/etc/portal/tls/keystore.password
./portal.sh login                                 # or add-user, set-password, portal, …
```

`portal.sh` (and `portal.cmd` for Windows) is the supported launcher, mainly because of how
it builds the classpath: the JVM is pointed at the launcher's own `out/main` and nothing
else, `CLASSPATH` is removed from the environment rather than trusted, and there is no `.`
entry or wildcard — so the process cannot be made to load a class that another account
dropped in the working directory. `java -cp out/main com.portal.auth.Main …` is the same
thing, typed by hand, and is what the test suites do; the launcher exists so the operator
does not have to remember which invariants matter. Verified: with a planted
`com/portal/auth/Main.class` in the current directory and a hostile `CLASSPATH=/tmp`, the
launcher still runs this build.

`tools/gen-cert.sh` generates a keystore password from `/dev/urandom`, writes it to a 0600
file, and passes it to `keytool` through the environment (`-storepass:env`) so it never
appears in argv; it is never printed. It refuses to overwrite an existing keystore, and
re-opens the result with the password file it just wrote, so a keystore the portal cannot
load is caught at generation time. The certificate is self-signed — it proves nothing about
who owns the key, so replace it with one from the internal CA before employees point at it.

Subcommands: `login`, `add-user`, `set-password`, `disable-user`, `status`, `version`,
`portal`. Exit codes: `0` granted/ok, `1` denied, `2` refused (bad input, bad config,
unknown subcommand). Credentials are **never** command-line arguments — the CLI uses
`Console.readPassword()` (no echo, no shell history) when attached to a terminal and reads
raw lines from stdin in batch mode, so nothing sensitive appears in `ps`, in a shell
history file, or in `/proc/*/cmdline`.

Configuration is environment plus an optional `.properties` file (`PORTAL_CONFIG`). See
`config/portal.properties.example`. Every key is checked for type, length, range and
character class; **an unrecognised key aborts startup** rather than being ignored, so a
typo cannot quietly deploy a weaker setting. There is no default for the data directory or
the keystore. Config numbers accept unsigned ASCII decimals only — `+150000` is refused,
not parsed.

## Threat model in one paragraph

The attacker is anyone who can reach the login path (network or a shared keyboard), and
separately anyone who can write the config or the environment of a process they can start.
The roster and the throttle ledger are the program's only durable state, both owner-private
(`0600` in a `0700` directory). The attacker's realistic goals are: authenticate without the
password; learn whether a name is an employee (then target it); lock a colleague out;
escalate by making the program treat one identity as another; read a password or a session
id from a log, a file, or a timing signal; or bypass a limit by re-labelling themselves.
Each of those is addressed below by name.

## Rule-by-rule

### Rule 1 — Trust boundaries

Every value that crosses into a decision is named, and none is trusted because of where it
came from.

| Input | Where it enters | Validation |
|---|---|---|
| Username | CLI line, `POST /login` form field | `[a-z0-9._-]{3,32}`, first and last character alphanumeric, no `..`; ASCII-case-folded **before** validation |
| Password | `Console.readPassword`, raw stdin line, form field | 12–128 printable ASCII, no NUL/control characters, no space at either end, no unpaired surrogates |
| Line framing | the batch reader | CR terminates a line; a line over `LINE_MAX` (1024) becomes a synthetic over-length value, which the validator then refuses — it is never truncated into a usable credential |
| Session cookie | `CookieParser` → `SessionManager.find` | must match the opaque-token shape (43 base64url chars for 32 bytes) **before** any map lookup |
| CSRF cookie + hidden field | `consumeCsrfToken` | both must independently match the 24-byte token shape, then compare constant-time, then be consumed exactly once |
| Peer address | the socket, never the caller | literal IPv4/IPv6 only, parsed by hand — `InetAddress` is never called on a client value, so no DNS lookup and no hostname accepted |
| `X-Forwarded-For` | `SourceRef.resolvePeer` | honoured only when the socket peer is inside the configured trusted-proxy CIDRs; walked right-to-left, stopping at the first untrusted hop; each hop must be a strict literal after OWS trimming (SP/HTAB only — not `trim()`, which would eat CR/LF/NUL) |
| Config values | env, `.properties`, system properties | type, length, range, character class; unknown key = abort; paths must be absolute with no `..` segment, regular, not a symlink, not group/other-readable |
| Subcommand | `argv[0]` | exact match against a fixed list; anything else exits 2. Values that cannot be rendered as a safe token in argv are refused rather than passed through |
| Stored record | roster file | re-parsed and re-checked on every read: algorithm, iteration floor, salt length, key length. A record that will not parse never authenticates |

Two decisions were taken specifically because a *normalising* validator is where identity
bugs live:

* Usernames are lower-case only. `ALICE` is folded with a 26-letter ASCII table — not
  `toLowerCase()` (locale hazard) and not Unicode case folding (identity hazard). Because
  the accepted alphabet is already lower-case, the fold is injective over real identities.
* Nothing trims a credential. `String.trim()` deletes every character `<= U+0020`,
  including NUL, tab, CR and LF; a `strip`ped address would let an attacker steer their own
  throttle bucket, and a stripped password would silently merge two different secrets.

### Rule 2 — Secrets

* No secret is embedded in the program. Not a password, not a keystore password, not a salt.
* The keystore password is read from a **file path** given in an environment variable
  (`PORTAL_KEYSTORE_PASSWORD_FILE`), never from a variable value and never from argv, so it
  is absent from `ps` and `/proc/*/cmdline`. Both the keystore and that file are refused at
  startup if they are group- or other-readable, a symlink, or not a regular file.
* The data directory and the two TLS paths have **no defaults**; the program will not start
  with a guess.
* Nothing secret is ever printed. Startup refusals are machine tokens (`config-value-out-of-range`,
  `keystore-and-password-file-must-be-supplied-together`) passed through `PortalCli.safeToken`,
  which cuts at the first space, caps at 80 characters and rejects anything outside
  `[A-Za-z0-9-_.:]` with `unspecified` — so a message that accidentally carried a value
  cannot print it. `Main` delegates to the same function rather than copying the rule.
* Log lines cannot carry a secret by construction: `AuditLog` writes only a fixed grammar
  (`ts event subject src outcome detail`), where `subject`/`src` must be a 16-hex reference
  or one of two fixed literals, and `detail` must match a conservative character class or it
  is replaced by `rejected`. A free-form string physically cannot be interpolated.
* Credential buffers are cleared on every path — `Authenticator.authenticate` wipes the
  password in a single `finally`, so no branch can forget, and it also wipes the folded
  username copy and each derived key after use. The CLI's batch reader wipes its line buffer
  on the overflow path.
* Enrolment asks for the new password twice because a terminal read cannot be undone; the
  confirmation comparison is length-safe and exception-free.

### Rule 3 — Authentication and access control

* Access is granted only after verifying the presented secret against the record stored
  **server-side** in the roster file — and against the record that is on disk *now*, not the
  one this process happened to load at start-up (see rule 7). The response never carries a
  decision the client made.
* Fail-closed everywhere: an unparseable stored record cannot authenticate; a corrupt or
  unreadable throttle ledger resets counters to zero (the strictest state, and reported)
  rather than disabling the throttle; a ledger that cannot be written still enforces in
  memory and records the loss; a KDF that throws yields a denial, never a fall-through.
* **Missing check → refuse.** A session id that is absent, malformed, expired, or simply
  unknown all take the same path: no session, no identity, `401`.
* Limits, per `ThrottleManager`: `ACCOUNT_MAX_FAILURES = 5` per `WINDOW_SECONDS = 300`,
  then an exponential back-off (`BASE_BLOCK_SECONDS = 30`, ceiling `900`);
  `SOURCE_MAX_FAILURES = 30` per window, then a long ceiling on the *source* only. The
  check-and-act is atomic and the budget is **reserved before** the password is examined
  (`beginAttempt` returns `ALLOWED`/`THROTTLED` and increments under one monitor), so a
  concurrent burst cannot all observe the same headroom.
* Why this cannot be turned into a lockout weapon: the ceiling on an *account* is short
  (900 s) and self-clearing, and a source that wants to burn one account's budget must spend
  five of its own thirty requests per account — so one source can lock at most
  `SOURCE/ACCOUNT = 6` accounts per window before its own address is blocked for
  `MAX_SOURCE_BLOCK_SECONDS`. A correct login clears the account's counters, so partial
  harassment does not accumulate. The per-source limit exists precisely so the *account*
  limit never has to absorb the attacker's traffic.
* The web layer additionally requires a CSRF token (double-submit, both halves validated and
  consumed once, bounded pending map) for the state-changing `POST /login` and logout.
* The account limit is enforced even when the account does not exist (see rule 6), so the
  throttle cannot be probed around by trying absent names.

### Rule 4 — Identifiers and tokens

* Session ids and CSRF tokens come from `Crypto.randomUrlToken`, i.e. `SecureRandom`, 32 and
  24 bytes respectively (256- and 192-bit), base64url encoded. They are generated only at
  issue time on the server; the program has no code path that accepts a caller-chosen
  session id.
* Nothing about a token is derived from the caller or from time — no username, no counter,
  no timestamp — so possession is the only capability, and one session reveals nothing about
  another.
* A presented token is validated *strictly by shape before lookup* (`isOpaqueToken`: exact
  length for the expected byte count, base64url alphabet only), which keeps malformed values
  out of the map and makes the lookup cost independent of content.
* Session lifetimes: `IDLE_TIMEOUT = 20 min` (sliding on use) and `ABSOLUTE_TIMEOUT = 8 h`,
  both enforced at every lookup and again at sweep time. A session that fails any check is
  removed, not merely reported as expired. Logout is idempotent and never creates a session.
* Cookies: `PORTAL_SESSION` and `portal_csrf` are both emitted as
  `Path=/; HttpOnly; Secure; SameSite=Strict`. `Secure` is unconditional — there is no
  plaintext listener to serve them over. Logout clears both with matching `Path`/attributes
  so the expiry actually matches the stored cookie.
* Session ids are never placed in a URL, a form field, a log line, or a response body.
* **Residual risk, documented:** the CSRF check is double-submit, so it relies on the
  unguessability of the token rather than on server-only knowledge; the pending-token map is
  bounded (`MAX_PENDING_CSRF = 50_000`) and an over-cap purge means an outstanding token may
  stop working early. A peer address that arrives behind a proxy configured with an
  over-wide trusted CIDR lets that proxy name the throttle bucket — which is why the trusted
  list must be explicit CIDRs, is validated at startup, and defaults to empty (header
  ignored). The audit ledger keys are `SHA-256` references truncated to 16 hex chars
  (64 bits): collisions are possible in principle and harmless here, because a collision
  only merges two throttle budgets — it never grants access. The one way that width could
  stop being the only consideration is a lossy encoding, so `Crypto.idRef` refuses a
  non-ASCII name instead of hashing it through a charset that would silently replace the
  character with `'?'` and put two different names in one bucket — and `'?'` is not a
  character any account name may contain, so a folded value could not name an account
  either.

### Rule 5 — Sensitive data

* Files: data directory `0700`; roster, audit log and throttle ledger `0600`, created with
  those modes rather than tightened afterwards (no window where a file is world-readable
  with content in it). Existing files are opened `NOFOLLOW`, so a planted symlink out of the
  data directory is refused instead of followed. Writes go through an atomic temp-file-plus-move
  inside the data directory, with a bounded read size on everything the program reads back.
* The data directory itself is validated: not a symlink, must be a directory, must be owned
  by us, must not be group- or other-writable. A config or keystore path that is
  group/other-readable aborts startup.
* Log masking: subject and source are SHA-256 references, never a username or an address
  (`alice` is written as `2bd806c97f0e00af`). Even the ledger — a file an operator might copy
  — stores only `kind:16-hex` keys, so a leaked backup does not say which account is being
  hammered. There is no code path that writes a password, a derived key, a salt, or a session
  id to the audit log; the `detail` field's character-class gate makes such a value render as
  `rejected` rather than appear.
* Stored sizes are bounded end to end: roster records have a fixed shape and length;
  the audit line is generated from fixed-width tokens; the ledger refuses to parse beyond
  `MAX_LINES`/`MAX_BYTES`; config, header and address values all have length caps checked
  before parsing.
* Credentials are cleared from memory as described under rule 2. `char[]` is not a
  guarantee (the JVM may have copied it) but it removes the ordinary heap-search exposure,
  and the API boundary is `char[]` so the CLI never has to build a `String` of the password.

### Rule 6 — Failure behaviour

Every denial is the same object a client can observe. In `Authenticator.decide` the seven
refusal paths (malformed username, malformed password, budget spent, unknown account, wrong
password, KDF unavailable, and the web layer's missing-field case) all produce:

* the same exit code / status, the same body, and the same headers —
  `Access denied.` on the CLI, `401` with one generic page over HTTPS;
* **the same CPU work.** The invariant is *exactly one* PBKDF2 derivation at the configured
  cost per call, on every path including the refusals: an unknown account verifies against a
  decoy digest derived from a domain-separated salt, a malformed input burns one decoy
  derivation, a throttled attempt runs a decoy verification without ever reading the roster.
  A refusal therefore costs the same as a success, so "does this account exist?" cannot be
  answered by timing or by spending different amounts of the attacker's budget.
* the same wall-clock floor. Every outcome — success included — is padded to one shared
  latency floor that ratchets up to the slowest observed decision.

`reasonForInternalUseOnly()` exists so the log and the tests can tell branches apart; it is
never rendered into a body, status, header, cookie, or byte count. Because `HEAD` and
`Content-Length` can leak a decision that the body hides, the header block is built by one
function that takes **no arguments** — there is no "headers for a denial" variant to get
wrong — and the equality of the resulting set is asserted across every response cell (page,
401, 404, 405, 415, 303) rather than assumed.

That last paragraph describes a fix. The function previously took a `withHsts` flag and the
authentication replies passed `true` while 404/405/415/500 passed `false`, so the header set
itself told a caller which branch had answered — a classifier available to anyone who could
not see the body, in the one place whose stated purpose was to prevent exactly that. It was
found by booting the portal and diffing a real 404 against a real 401; the previous
assertion only asked whether the 401 carried HSTS.

Unknown or invalid input is never given a permissive default: an oversized or unparseable
address joins the `unknown` throttle bucket, which is *still rate-limited*, rather than
skipping the limit; a malformed credential is a refusal, not an empty string; a missing
config value is an abort, not a fallback. The two "defaults" that do exist are floors
(iteration minimum, HSTS maximum) whose absence would be unsafe.

### Rule 7 — Concurrency

* Throttle decision and mutation are one operation under one monitor (`beginAttempt` returns
  the verdict *and* reserves the slot; `recordFailure` only records the caller's observation
  and never re-decides). A separate `isAllowed()` followed by a later `countFailure()` is
  exactly the check-then-act hole this exists to close.
* Cross-process, the ledger is read-modify-written under an exclusive `FileLock` on a
  dedicated lock file (never replaced), and merged so a sibling can only *raise* the danger:
  `blockedUntil` is always the maximum, and within one window the maximum count. The count
  itself is scoped by a per-subject **generation**, bumped wherever the window is
  deliberately replaced — without that field, "take the max" makes the count monotonic and a
  correct password can never clear it. (This was a real defect: the sixth consecutive
  *correct* login of one account was denied, because the merge restored the `5` the previous
  process had left behind.)
* The roster is read-modify-written the same way: one monitor for threads **and** an
  exclusive `FileLock` on `employees.dat.lock` for processes, with the file re-read *while
  the lock is held* so the change is applied to what is actually on disk. The monitor alone
  was not enough and the claim above used to say it was. The `portal` CLI is a short-lived
  process, so an operator enrolling a batch of accounts runs N writers over one file:
  measured before the fix, **eight concurrent `add-user` runs all exited 0 and only two of
  the eight records survived** — the tool reported success while silently discarding six
  accounts. Now all eight survive, and a contested name is won by exactly one process while
  the other seven report that it already exists.
* Writing under a lock is only half of cross-process correctness: the **reader** has to
  notice. `portal` is a long-lived process while `disable-user` and `set-password` are
  short-lived ones, so verifying against the copy loaded at start-up meant a revocation the
  operator had just performed did not take effect until a restart — measured: after
  `disable-user` wrote `r=disabled$v1`, the running portal still answered `303` for that
  account, and after `set-password` the **superseded** password still answered `303`.
  `EmployeeStore.refreshIfChanged()` is therefore the first statement of the decision: one
  `stat` comparing the roster's file key, size and mtime (every sanctioned write is an
  `ATOMIC_MOVE`, hence a new inode), reloading under the monitor only when they differ. It
  is a function of the *file*, never of the presented name, so it cannot answer "does this
  account exist?" and it costs the same on every branch. A roster that stops parsing
  becomes an empty map — every account refused as an unknown name, logged once, and the
  operator's file is never rewritten from a partial view — and it recovers without latching
  as soon as a valid roster is in place again.
* Session issue, use, expiry and removal all take one monitor, and the map insertion that
  must be atomic with the expiry sweep is inside it.
* Latency padding takes `startedAt` as a parameter rather than reading shared state, because
  a shared "last decision" timestamp under concurrency belongs to whichever request wrote it
  last and would make the padding arbitrary. Padding is always done outside the monitor.
* Token generation uses the JVM's thread-safe `SecureRandom`.

### Rule 8 — Platform built-ins

* JDK 21 (Temurin 21.0.12.1+1), compiled with `-encoding US-ASCII -Xlint:all -Werror
  -parameters`. `US-ASCII` is a guarantee, not cosmetics: an invisible non-ASCII byte in a
  source file is exactly the class of input this program refuses from a user.
* Used, not reimplemented: `SecretKeyFactory("PBKDF2WithHmacSHA256")`, `SecureRandom`,
  `MessageDigest.isEqual`, `MessageDigest("SHA-256")`, `Base64.getUrlEncoder`,
  `java.nio.file` POSIX permissions + `Files.move` with `ATOMIC_MOVE`, `FileChannel.lock`,
  `java.time`, `com.sun.net.httpserver.HttpsServer` with a `SSLContext` from the configured
  keystore.
* Hand-written only where the platform's API would have been *looser* than the security
  requirement: IP literal parsing (`InetAddress.getByName` performs DNS and accepts
  hostnames), CIDR parsing (`InetAddress` has no CIDR), and the test harness.
* Nothing is fetched at build or run time. `tools/get-jdk.sh` is the single download; it
  pins an exact version and URL, fetches over HTTPS with `--tlsv1.2`, and refuses the file
  unless `sha256sum --check --strict` passes against the digest shipped next to the release.
* The program never loads code dynamically: no reflection over user input, no service
  loading, no `URLClassLoader`, no classpath entry it did not ask for. It writes nothing into
  its own classpath, and the test harness is deliberately not part of the shipped classes.

## Deliberate behaviours worth knowing

Recorded because each looks like a bug from the outside and each was chosen over a worse
alternative.

* **CR terminates a line; it never merges one.** A CR can split a credential into two fields,
  which is exactly what a CRLF-authored batch file means, so `alice\rFresh-Quiver-71!` is a
  correct login. What it can no longer do is *delete* a character: `ali\rce` is checked as
  `ali` and denied. (The previous behaviour — deleting CRs anywhere — let `ali\rce`
  authenticate as `alice`.)
* **`set-password` on a disabled account also lifts the disable**, and now says so on the
  console and in the audit log (`updated-re-enabled`). It does not refuse, because there is
  no `enable-user` command and refusal would strand the account.
* **A directory legitimately named `..odd` is refused.** The parent-reference rule runs on
  raw path segments; normalising first would make the guard vacuous (`normalize()` is what
  deletes `..`). Refusing a name the program never generates is cheap compared with writing
  private state to a directory the operator did not name.
* **A correct password is refused while an account back-off is running.** The window is the
  restriction; clearing it on sight would let a knowing attacker defeat the lockout.
* **Reserving a slot spends budget; only a recorded failure arms the timed window.** Five
  reservations with no verification roll clean at the window boundary instead of blocking,
  because a reservation alone cannot distinguish five wrong passwords from five requests that
  were never verified.
* **`status` counters are per-process.** `login-ok`/`login-denied` are tallies of the current
  process and read `0` in a fresh CLI by design; the durable state is the roster and the
  throttle ledger.
* **`normalizeForLedger` is not idempotent** (`ref(ref(x))` is a different bucket). Each
  request reduces its label exactly once; the caller that resolves the peer hands a label to
  `Authenticator`, which performs that one reduction.
* **`java.util.Properties` strips leading whitespace in a value and keeps trailing
  whitespace**, so `portal.listen.host= 127.0.0.1` is accepted while `127.0.0.1 ` is refused.
  Removing the asymmetry would mean trimming config values ourselves, which is the same
  folding hazard the credential rules refuse. The validator runs after the strip, so the
  outcome is always a strict literal or a refusal.
* **The JDK's `HttpServer` omits `Content-Length` on a `HEAD` response.** That is platform
  behaviour, not a leak in this program; the denial pages are asserted to agree across methods
  in the dimension the program controls.

## How this was tested

Five suites, one `main()` each, no test framework (`src/test/java/com/portal/auth`):

| Suite | Covers |
|---|---|
| `CoreSecuritySuite` | input matrices, case folding, crypto, hash records, roster, file modes, audit-line shape, source-text guards |
| `AuthFlowSuite` | the decision itself, throttle under bursts, roster changes made by another process, cross-process durability, concurrency, and timing measured two ways |
| `ConfigCliSuite` | the shipped binary as an operator gets it: every case launches the real CLI as a subprocess with a scrubbed environment — no in-process fakes |
| `HttpSuite` | the HTTPS surface: cookies, headers, CSRF, session lifecycle, status/body uniformity |
| `SourceRefSuite` | IP literal, CIDR and `X-Forwarded-For` parsing |

`./test.sh` runs them all. Current state of the run, taken from the suites' own `SUMMARY`
lines: **2077 checks, 0 failures** — auth-flow 439, config-cli 544, core-security 541,
http 354, source-ref 199. Each suite counts its own assertions, so the number moves when a
test is added; it is quoted here rather than as a standing claim.

Timing is measured twice on purpose: once with the padding **suppressed**, to see the paths'
true cost spread, and once with the floor **raised** far above the KDF cost, to prove the
padding holds every path up. A spread-only assertion cannot catch a mutant that deletes work
from *all* branches — that keeps the spread perfect while destroying the guarantee — so the
floor assertion and an absolute minimum are both required.

The guards were then mutation-tested: 30 mutants, each a single semantic weakening of one
guard (drop a decoy derivation, make the comparison length-only, delete CR instead of
terminating on it, restore the vacuous `..` guard, reopen the config grammar, make the ledger
count-merge monotonic, lose a concurrent roster write, stop adopting another process's roster
change, put a lossy charset back in front of a comparison, widen a file mode, skip the
padding, replay a CSRF token, …). Every mutant is run
against **frozen copies of both trees** — the test tree so a mutant can never be killed by its
own edited tests, the main tree so a source edit made mid-run cannot be tested against stale
source-text guards — and both are verified byte-identical to the frozen copies afterwards. A
compile failure, an ambiguous anchor, or a suite that dies without printing its summary is
reported as a harness error rather than counted as a kill. Before any mutant runs, the
pristine tree must itself be green on the fast tier; a battery whose baseline is red reports
every mutant as killed by the pre-existing failure, which is exactly the false result this gate
exists to prevent (the gate was negative-tested by injecting a failure and confirming it
refuses the run).

    tools/mutate.py --preflight          # anchors unique?
    tools/mutate.py --dry-run            # applies + compiles, runs nothing
    tools/mutate.py                      # the battery
    tools/mutate.py M08 M09              # named mutants

Result: **30 of 30 killed**, no survivors, no harness errors, with both trees verified
identical to their frozen copies afterwards. Three mutants initially
survived, and each was a gap in the *tests*, not in the program:

* a length bound probed only far past its limit cannot tell `>` from `>=`;
* a character-class bound probed only at the string edges leaves `0x20` in the middle untested;
* dropping the failure record from the unknown-username branch went unnoticed, because every
  source-block assertion sprayed *known* accounts — and a known account's own back-off was
  arming the ledger row that made the address look blocked. `beginAttempt` only counts; the
  timed window is armed exclusively by `recordFailure`, so an unknown-name spray would have
  stayed on a 300 s rolling window instead of the 8 h ceiling. The suite now sprays only names
  that do not exist and asserts the *source* is blocked and its armed window reaches the
  ceiling.

All three assertions now exist, and the corresponding mutants die on them. A surviving mutant
is treated as information about the tests: the fix is a new assertion, never deleting the
mutant.

## Known limitations

* PBKDF2-HMAC-SHA256 at 150 000 iterations is the platform's best option; the JDK ships no
  memory-hard KDF, so a well-funded offline attacker against a stolen roster has an easier
  time than against Argon2id. Raising `portal.kdf.iterations` is a supported response and
  old records are upgraded on next successful login; the floor is 100 000 and a record below
  it never parses.
* No TLS configuration is exposed: certificate generation, chain and cipher policy are the
  operator's `keytool`/`SSLContext` defaults. `tools/gen-cert.sh` produces a throwaway
  self-signed certificate for testing only.
* A `char[]` cannot be reliably erased in a JVM; clearing removes the ordinary heap-search
  exposure and nothing more.
* Single-node only. Sessions, CSRF state and the roster are process-local; the throttle
  ledger is shared by file and `FileLock`, which is correct for several processes on one host
  and not across a cluster.
* Trusted-proxy support is IPv4 CIDRs only, and the source throttle is per-address: an
  attacker with a large address range can exceed a per-source budget that a single address
  cannot, which is why the account dimension is the primary control.

See `docs/THREAT_MODEL.md` for the attack-by-attack walkthrough and the list of defects found
and fixed during development.
