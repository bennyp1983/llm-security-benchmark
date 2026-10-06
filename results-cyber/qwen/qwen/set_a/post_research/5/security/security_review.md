# Security Review: portal-auth (com.portal.auth)

## 1. Executive Summary

portal-auth is a self-contained Java 21 authentication portal (zero third-party runtime
dependencies) exposing a CLI and an HTTPS login endpoint backed by a single
`Authenticator.decide` path. The cryptographic core is sound: PBKDF2-HMAC-SHA256 with a
100,000-iteration floor, `SecureRandom` salts, constant-time comparison via
`MessageDigest.isEqual`, uniform-denial design (a decoy key derivation and latency-floor
padding on every refusal path), POSIX 0700/0600 file policy with symlink refusal, and
atomic temp+fsync+rename writes for the roster and throttle ledger. The scripts
(`get-jdk.sh` pins a SHA-256 over TLS-pinned curl; `gen-cert.sh` uses a 48-hex random
keystore password with `-storepass:env`; `portal.sh`/`portal.cmd` scrub `CLASSPATH`) are
clean.

Five findings were confirmed, all in the operational/availability and hygiene layers rather
than in the cryptography:

- **SEC-01 (High):** the throttle manager's 50,000-subject cap throws
  `IllegalStateException("throttle-subject-capacity")` on the authentication decision path.
  An unauthenticated attacker can fill the per-account map with distinct syntactically valid
  usernames; once full, the sweep cannot evict in-window entries, so every login for a
  subject not already present fails as an HTTP 500 — a login outage that also bypasses the
  decoy derivation and latency padding, breaking the uniformity invariant the design is
  built on.
- **SEC-02 (Medium):** every single authentication attempt performs a full-ledger snapshot,
  file-lock acquisition (up to ~5 s), whole-file merge read, and write+fsync+rename — while
  holding the one global monitor that also serializes the thread pool — an unauthenticated
  disk-I/O amplification surface.
- **SEC-03 (Medium):** the audit-log append path contains a dead `instanceof FileOutputStream`
  branch, so audit lines are never fsynced; a crash loses recent audit evidence despite the
  code's durability claims.
- **SEC-04 (Low):** a two-byte roster line (`u=`) triggers `StringIndexOutOfBoundsException`
  in `charAt(2)`, which the refresh handler interprets as a wholly corrupt roster and drops
  the account map to empty — a whole-service authentication outage from a single
  unvalidated index access.
- **SEC-05 (Low):** decoded password bytes are retained in an uncleared `HashMap` inside
  `FormFields`; the login handler wipes only defensive copies, leaving the originals in
  cleartext heap until GC — inconsistent with the codebase's own `Crypto.wipe` discipline.

README claims (2077 checks green, 30/30 mutants killed) were treated as claims to verify,
not as evidence; the analysis above is from static reading of every source file.

## 2. Scope

| File | Purpose | Security-relevant behaviour |
|---|---|---|
| src/main/java/com/portal/auth/Main.java | Process entry point | Wires config, runtime, CLI vs server mode; no direct secrets handling |
| src/main/java/com/portal/auth/PortalConfig.java | Configuration loader | Rejects `..` paths, unknown keys, non-literal listen hosts, group/world-readable or symlinked config; literal-only values |
| src/main/java/com/portal/auth/PortalRuntime.java | Component composition root | Owns store, hasher, throttle, sessions lifetimes |
| src/main/java/com/portal/auth/PortalServer.java | HTTP routing, handlers, `FormFields` parser | Bounded body/field sizes, uniform 401, security headers on every response, session/CSRF cookies, generic 500 catch-all; retains decoded credential bytes in a map (SEC-05) |
| src/main/java/com/portal/auth/JdkHttpsListener.java | HTTPS listener on `com.sun.net.httpserver.HttpsServer` | TLSv1.2/1.3 only, keystore password read from 0600 file and wiped, bounded fixed thread pool, idle-session janitor |
| src/main/java/com/portal/auth/HttpExchangeView.java | Thin exchange abstraction | Bounded request-body read (`readBodyBounded`), header sanitization for the view |
| src/main/java/com/portal/auth/Authenticator.java | Core login decision | One PBKDF2 derivation on every outcome incl. refusals (decoy), source-budget charge for malformed input, latency padding, wipes the `char[]` password on every path |
| src/main/java/com/portal/auth/EmployeeStore.java | Roster load/refresh (inode+size+mtime fingerprint) | Fail-closed refresh; unvalidated `charAt(2)` can drop the whole roster (SEC-04) |
| src/main/java/com/portal/auth/PasswordHasher.java | PBKDF2WithHmacSHA256 verify/derive | Iteration floor 100k (default 150k), `MessageDigest.isEqual` comparison, decoy derivation helper |
| src/main/java/com/portal/auth/Crypto.java | Primitives | `SecureRandom`, SHA-256 `idRef` → 16 lowercase hex, `Crypto.wipe` zeroization helpers |
| src/main/java/com/portal/auth/ThrottleManager.java | Per-account (5/300 s, back-off 30→900 s) and per-source (30/300 s, 8 h cap) throttling | Capacity throw on decision path (SEC-01); full-ledger persist inside global monitor per attempt (SEC-02); busy-wait latency floor |
| src/main/java/com/portal/auth/Ledger.java | Crash-durable throttle counters on disk | FileLock + read-merge + atomic write; validates key/count/window fields but not `generation` (documented residual risk); 50k-line/4 MiB caps |
| src/main/java/com/portal/auth/SessionManager.java | Opaque session store | `SecureRandom` session ids, expiry on read, revocation set |
| src/main/java/com/portal/auth/CookieParser.java | Cookie header parsing | Lenient parse, no injection surface into response headers |
| src/main/java/com/portal/auth/SourceRef.java | Source attribution for buckets | Literal-only address parsing (no DNS), XFF honored only when socket peer is in a trusted IPv4 CIDR, right-to-left walk, reduces to 16-hex |
| src/main/java/com/portal/auth/InputPolicy.java | Input validation | Username and secret well-formedness gates (called before any record lookup) |
| src/main/java/com/portal/auth/AuditLog.java | Structured audit events | Refuses to log raw secrets (`safeToken` alphabet-restricted redaction); appends via `PrivateFiles.appendPrivateLine` (SEC-03) |
| src/main/java/com/portal/auth/AuditClock.java | Injected clock for tests | Second-resolution epoch used by throttle windows |
| src/main/java/com/portal/auth/PrivateFiles.java | Private-file discipline | 0700/0600 + NOFOLLOW checks, atomic temp+fsync+ATOMIC_MOVE writer; audit append never fsyncs (SEC-03) |
| src/main/java/com/portal/auth/PortalCli.java | CLI (passwd/status/serve) | Hash generation, status lines; redacts sensitive tokens |
| src/test/java/com/portal/auth/CoreSecuritySuite.java | Boundary/credential-storage/file-policy tests | One-invalid-way fixtures; each asserts the named guard fired |
| src/test/java/com/portal/auth/AuthFlowSuite.java | Login-flow, throttle, concurrency tests | Includes timing-spread assertions under `setTimingControlsForTesting` |
| src/test/java/com/portal/auth/HttpSuite.java | Network-visible behaviour tests | Headers, cookies, status codes, body bounds |
| src/test/java/com/portal/auth/SourceRefSuite.java | Attribution tests | Literal-only parser, trusted-proxy bucketing, crash-resistance of label parsing |
| src/test/java/com/portal/auth/ConfigCliSuite.java | Config/CLI adversarial tests | Rejects symlinked/world-readable config, unknown keys, `..` |
| src/test/java/com/portal/auth/TestKit.java | Minimal harness (no third-party deps) | Temp-dir fixtures, fixed clock |
| tools/gen-cert.sh | Self-signed keystore generation | umask 077, dir 0700, 48-hex `/dev/urandom` password in 0600 file, `-storepass:env`, refuses existing keystore |
| tools/get-jdk.sh | Pinned JDK download | SHA-256-pinned artifact, `curl --proto '=https' --tlsv1.2`, refuses on mismatch |
| tools/mutate.py | Mutation battery for the guards | One semantic weakening per run; frozen test tree; SURVIVED is reported as a missing assertion |
| portal.sh / portal.cmd | Launchers | `env -u CLASSPATH`, `-cp` pinned to build output (no `.` or wildcards) |
| build.sh / test.sh | Build/test drivers | `javac -encoding US-ASCII -Xlint:all -Werror`; each `*Suite` main run separately |
| config/portal.properties.example | Config template | Documents trusted-proxy CIDRs and file paths; no secrets |
| README.md | Documentation | Claims 2077 checks / 30-30 mutants and lists limitations (PBKDF2 not memory-hard, single node, IPv4-only trusted proxies) — treated as claims, not evidence |
| docs/THREAT_MODEL.md | Threat model | Design intent incl. audit/ledger durability claims; SEC-03 contradicts one of them |

## 3. Skills Applied

- **review-code-for-security-vulnerabilities** — driver: understand each file first, then match specialised skills, report-only mode with CWE ids and file:line evidence.
- **performing-cryptographic-audit-of-application** — PBKDF2WithHmacSHA256 parameters (≥100k iterations), `SecureRandom` salt/id generation, `MessageDigest.isEqual` constant-time compare, SHA-256 `idRef`, TLS keystore handling.
- **implementing-api-rate-limiting-and-throttling** — per-account/per-source bucket design, back-off ceilings, and the capacity behavior of the store; the resource-limit design behind SEC-01 and the per-attempt cost behind SEC-02 come from this lens.
- **exploiting-race-condition-vulnerabilities** — reservation-before-verify ordering in `beginAttempt`, the `Ledger` FileLock + merge protocol, and the global-monitor serialization that turns per-attempt disk I/O into an amplification vector (SEC-02).
- **testing-for-sensitive-data-exposure** — password byte lifetimes in `FormFields`/`PortalServer.login` (SEC-05), keystore-password wipe in `JdkHttpsListener.buildSslContext`, CLI redaction.
- **performing-log-analysis-for-forensic-investigation** — audit-log completeness/durability requirements; the dead fsync branch (SEC-03) defeats crash-durable audit.
- **testing-for-business-logic-vulnerabilities** — the uniform-denial invariant (one derivation + padding per outcome) and how SEC-01's exception path breaks it.
- **testing-for-host-header-injection** — Host/XFF handling: labels reduce through `SourceRef` (literal-only, trusted-proxy-gated) and `Location` is a static string; verified, no finding.
- **performing-directory-traversal-testing** — `PrivateFiles` symlink/NOFOLLOW/mode discipline and `PortalConfig` `..` rejection; verified, no finding.
- **configuring-tls-1-3-for-secure-communications** — `JdkHttpsListener` SSLContext build, TLSv1.2/1.3 protocol pinning, `gen-cert.sh` key strength and password handling; verified, no finding.
- **testing-for-broken-access-control** — session cookie flags, single-use CSRF double-submit, denied-path uniformity; verified, no finding.
- **implementing-jwt-signing-and-verification** — not applicable: sessions are opaque `SecureRandom` ids, no JWTs exist in the codebase.
- **performing-privilege-escalation-on-linux** — largely not applicable: the program runs unprivileged and performs no setuid/root operations; file-mode discipline was still checked (clean).
- Unmatched behaviours (resource exhaustion, unchecked index, cleartext-in-memory credentials) were assessed against the OWASP Top 10 and CWE catalogue directly, per the driver skill's fallback rule.

## 4. Summary of Findings

| ID | Title | Severity | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Throttle subject-cap throws on the decision path: unauthenticated login outage and uniform-denial bypass | High | CWE-770 | ThrottleManager.java:394-402 |
| SEC-02 | Full-ledger snapshot + locked file write + fsync on every attempt, inside the global monitor | Medium | CWE-400 | ThrottleManager.java:439-461 |
| SEC-03 | Audit append never fsyncs — `instanceof FileOutputStream` branch is dead code | Medium | CWE-778 | PrivateFiles.java:206-214 |
| SEC-04 | `charAt(2)` on a 2-byte roster line crashes the refresh and empties the whole roster | Low | CWE-129 | EmployeeStore.java:193-195 |
| SEC-05 | Password bytes retained in an uncleared `FormFields` map; only copies are wiped | Low | CWE-522 | PortalServer.java:404,435-439 |

## 5. Detailed Findings

### SEC-01: Throttle subject-cap throws on the decision path: unauthenticated login outage and uniform-denial bypass

- **Severity:** High
- **CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
- **Location:** `src/main/java/com/portal/auth/ThrottleManager.java:394-402`
- **Vulnerable code:**

  ```java
  // src/main/java/com/portal/auth/ThrottleManager.java:394-403
      private State live(Map<String, State> map, String subject) {
          State s = map.get(subject);
          long now = AuditClock.epochSecond();
          if (s == null) {
              if (map.size() >= MAX_SUBJECTS) {
                  sweep(map);
                  if (map.size() >= MAX_SUBJECTS) {
                      throw new IllegalStateException("throttle-subject-capacity");
                  }
              }

  // src/main/java/com/portal/auth/ThrottleManager.java:59
      private static final int MAX_SUBJECTS = 50_000;

  // src/main/java/com/portal/auth/ThrottleManager.java:433-437
      private void sweep(Map<String, State> map) {
          long now = AuditClock.epochSecond();
          map.entrySet().removeIf(e -> now - e.getValue().windowStart > RETENTION_SECONDS
                  && e.getValue().blockedUntil <= now);
      }

  // src/main/java/com/portal/auth/ThrottleManager.java:163-168
      public Kind beginAttempt(String accountRef, String sourceHex) {
          synchronized (monitor) {
              String acct = requireRef(accountRef);
              long now = AuditClock.epochSecond();
              State a = live(accounts, acct);
              State s = live(sources, sourceHex);

  // src/main/java/com/portal/auth/Authenticator.java:173
          ThrottleManager.Kind reserved = throttle.beginAttempt(accountRef, sourceHex);

  // src/main/java/com/portal/auth/PortalServer.java:84-89
          } catch (RuntimeException unexpected) {
              // Generic response, details in the log. Never echo the exception: its message
              // can name a file, a class or a value.
              audit.systemFailure("http", "-", "-", unexpected);
              try {
                  ex.respond(500, HttpExchangeView.EMPTY, securityHeaders());
  ```

- **Why it is a problem:** The per-account map is keyed by `Crypto.idRef(foldedUsername)` and a
  fresh entry is created for every distinct syntactically valid username — which an
  unauthenticated attacker controls completely. `sweep` only evicts entries older than
  `RETENTION_SECONDS` with no live block, so entries created within the retention window can
  never be freed. Once an attacker has posted enough distinct valid usernames to reach
  `MAX_SUBJECTS` (50,000 — reachable in well under the retention window at modest request
  rates), `live()` throws `IllegalStateException` for **every** subject not already present.
  The exception propagates out of `beginAttempt` → `Authenticator.decide` → `login` → `handle`,
  where it is caught as a generic `RuntimeException` and answered with HTTP 500. Two security
  properties break at once: (1) availability — logins for all users whose account entry was
  swept or never created are refused wholesale, an unauthenticated denial of the entire
  authentication service; (2) the uniform-denial invariant — the 500 path skips
  `verifyAgainstDecoy`, `padToFloor`, and the source-budget charge entirely, producing a fast,
  structurally different response the design explicitly promises an observer can never see,
  and trivially distinguishing "fresh username" traffic from normal traffic. The
  per-source map has the same throw, though filling it additionally requires many source
  addresses.
- **Fix:** Never throw from the decision path; make room deterministically instead, and
  degrade to an in-memory-only verdict if eviction cannot free a slot:

  ```java
      private State live(Map<String, State> map, String subject) {
          State s = map.get(subject);
          long now = AuditClock.epochSecond();
          if (s == null) {
              if (map.size() >= MAX_SUBJECTS) {
                  sweep(map);
              }
              if (map.size() >= MAX_SUBJECTS) {
                  evictOldest(map);   // make room instead of throwing
              }
              s = new State();
              map.put(subject, s);
          }
          // ... rollover logic unchanged ...
          return s;
      }

      /** Evict the least-recently-active unblocked subject; last resort, any subject. */
      private void evictOldest(Map<String, State> map) {
          String victim = null;
          long oldest = Long.MAX_VALUE;
          long now = AuditClock.epochSecond();
          for (Map.Entry<String, State> e : map.entrySet()) {
              State v = e.getValue();
              if (v.blockedUntil <= now && v.windowStart < oldest) {
                  oldest = v.windowStart;
                  victim = e.getKey();
              }
          }
          if (victim != null) {
              map.remove(victim);
          } else if (!map.isEmpty()) {
              map.remove(map.keySet().iterator().next());
          }
      }
  ```

  Eviction of an unblocked subject costs only the loss of its (already decayed) failure
  counter, which is exactly what an attacker-driven fill would have evicted anyway; blocked
  subjects are preserved. If a capacity event ever forces last-resort eviction, record it via
  `AuditLog.systemFailure` so the operator sees the pressure instead of an HTTP 500 storm.

### SEC-02: Full-ledger snapshot + locked file write + fsync on every attempt, inside the global monitor

- **Severity:** Medium
- **CWE:** CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')
- **Location:** `src/main/java/com/portal/auth/ThrottleManager.java:439-461` (called from `:182`, `:226`, `:253`, `:269`; disk work in `src/main/java/com/portal/auth/Ledger.java:123-167`)
- **Vulnerable code:**

  ```java
  // src/main/java/com/portal/auth/ThrottleManager.java:180-183
              counters.merge(verdict, 1L, Long::sum);
              lastDecisionNanos = System.nanoTime();
              persistLocked();
              return verdict;

  // src/main/java/com/portal/auth/ThrottleManager.java:439-461
      private void persistLocked() {
          if (ledger == null) {
              return;
          }
          Map<String, Ledger.Counter> snapshot = new HashMap<>();
          for (Map.Entry<String, State> e : accounts.entrySet()) {
              snapshot.put(Ledger.key('a', e.getKey()),
                      new Ledger.Counter(e.getValue().windowStart, e.getValue().failures,
                              e.getValue().blockedUntil, e.getValue().generation));
          }
          for (Map.Entry<String, State> e : sources.entrySet()) {
              snapshot.put(Ledger.key('s', e.getKey()),
                      new Ledger.Counter(e.getValue().windowStart, e.getValue().failures,
                              e.getValue().blockedUntil, e.getValue().generation));
          }
          try {
              ledger.persist(snapshot);
          } catch (RuntimeException ledgerDown) {
              // In-memory enforcement still holds; the decision must not change because
              // the durability layer is unavailable. Recorded for the operator.
              ledgerLosses++;
          }
      }

  // src/main/java/com/portal/auth/Ledger.java:134-149
          FileChannel lockChannel = null;
          try {
              lockChannel = FileChannel.open(lockFile,
                      java.util.EnumSet.of(StandardOpenOption.CREATE, StandardOpenOption.READ,
                              StandardOpenOption.WRITE),
                      PosixFilePermissions.asFileAttribute(PrivateFiles.FILE_MODE));
              FileLock lock = acquire(lockChannel);
              try {
                  Map<String, Counter> merged = new HashMap<>();
                  for (Map.Entry<String, Counter> e : state.entrySet()) {
                      merged.put(e.getKey(), e.getValue().copy());
                  }
                  for (Map.Entry<String, Counter> e : readForMerge().entrySet()) {
                      merged.merge(e.getKey(), e.getValue(), Ledger::max);
                  }
                  PrivateFiles.writePrivateAtomic(file, render(merged));
  ```

- **Why it is a problem:** `beginAttempt` (every login attempt, `:182`), `recordFailure`
  (`:226`), `recordSuccess` (`:253`), and `consumeSourceBudget` (`:269`) each call
  `persistLocked()` **while holding the single `monitor` lock that serializes all throttle
  activity**. `persistLocked` is O(state size): it snapshots every account and source entry,
  then `Ledger.persist` acquires an exclusive `FileLock` (retrying up to ~5 s via `acquire`),
  re-reads and re-parses the whole ledger file, rewrites it through `writePrivateAtomic`
  (temp file + `force(true)` fsync + `ATOMIC_MOVE`), under a cap of 50,000 lines / 4 MiB. An
  unauthenticated attacker who simply keeps the login endpoint busy (a few concurrent
  connections are enough) forces a serialized full-file read+fsync per attempt: request
  latency across the whole bounded pool (`JdkHttpsListener.java:95-96`) collapses onto the
  slowest disk round-trip, and slow-storage or fsync-heavy filesystems turn modest login
  volume into effective denial of service. The attacker pays one HTTP POST; the server pays a
  synchronous full-ledger rewrite behind a global lock — a textbook amplification and
  serialization asymmetry. (A crash between attempts loses at most the inter-persist delta,
  and the merge takes maxima, so batching persistence does not weaken enforcement across
  restarts in any way the design does not already tolerate.)
- **Fix:** Keep the decision cheap: set a dirty flag under the monitor and persist from a
  single background writer outside it, flushing immediately only on state transitions that
  must survive a crash (a block being armed, a clear):

  ```java
      private volatile boolean ledgerDirty = false;

      public Kind beginAttempt(String accountRef, String sourceHex) {
          Kind verdict;
          synchronized (monitor) {
              // ... decision logic unchanged ...
              counters.merge(verdict, 1L, Long::sum);
              lastDecisionNanos = System.nanoTime();
              ledgerDirty = true;               // no I/O on the decision path
          }
          return verdict;
      }

      /** Started by the constructor as a daemon; coalesces bursts into one rewrite. */
      private void persistLoop() {
          while (running) {
              sleep(PERSIST_INTERVAL_MS);        // e.g. 1000 ms
              flushIfDirty();
          }
      }

      private void flushIfDirty() {
          Map<String, Ledger.Counter> snapshot;
          synchronized (monitor) {
              if (!ledgerDirty) {
                  return;
              }
              snapshot = snapshotLocked();        // the two loops from persistLocked
              ledgerDirty = false;
          }
          try {
              ledger.persist(snapshot);           // FileLock + rewrite OUTSIDE the monitor
          } catch (RuntimeException ledgerDown) {
              synchronized (monitor) {
                  ledgerLosses++;
                  ledgerDirty = true;             // retry on the next tick
              }
          }
      }
  ```

  Call `flushIfDirty()` synchronously wherever `blockedUntil` moves forward so an armed block
  is durable before the response is sent; everything else rides the batcher.

### SEC-03: Audit append never fsyncs — `instanceof FileOutputStream` branch is dead code

- **Severity:** Medium
- **CWE:** CWE-778: Insufficient Logging
- **Location:** `src/main/java/com/portal/auth/PrivateFiles.java:206-214`
- **Vulnerable code:**

  ```java
  // src/main/java/com/portal/auth/PrivateFiles.java:196-218
      public static void appendPrivateLine(Path file, String line) {
          refuseSymlink(file);
          requirePrivateParent(file);
          boolean fresh = !Files.exists(file, LinkOption.NOFOLLOW_LINKS);
          try {
              if (fresh) {
                  writeExactly(file, (line + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8),
                          java.nio.file.StandardOpenOption.CREATE_NEW);
              } else {
                  requireMode(file, FILE_MODE);
                  try (OutputStream out = Files.newOutputStream(file,
                          java.nio.file.StandardOpenOption.APPEND,
                          LinkOption.NOFOLLOW_LINKS)) {
                      out.write(line.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                      out.write('\n');
                      out.flush();
                      if (out instanceof java.io.FileOutputStream fos) {
                          fos.getFD().sync();
                      }
                  }
              }
          } catch (IOException failure) {
              throw new IllegalStateException("cannot-append", failure);
          }
  ```

- **Why it is a problem:** `Files.newOutputStream` returns a `FileChannel`-backed stream
  (`ChannelOutputStream`), never a `java.io.FileOutputStream`, so the pattern-match branch at
  `:212-213` can never execute and the audit log is never fsynced on the append path.
  `out.flush()` only pushes bytes into the OS page cache. The threat model and this class's
  own comments present the audit trail as durable evidence (the roster and ledger paths
  *are* fsynced — `writePrivateAtomic` calls `force(true)`, and a correct
  `private static void sync(Path file)` helper with `ch.force(true)` already exists at
  `PrivateFiles.java:354-357`), so the gap is invisible to review and to the mutation
  battery, which cannot observe crash behavior. After a power loss or kernel panic, the most
  recent audit lines — exactly the ones from an incident in progress — are silently lost,
  undermining the forensic timeline the audit log exists to provide.
- **Fix:** Append through a `FileChannel` and force it, mirroring the existing `sync` helper:

  ```java
                  requireMode(file, FILE_MODE);
                  try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(
                          file,
                          java.util.EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.APPEND),
                          LinkOption.NOFOLLOW_LINKS)) {
                      ch.write(java.nio.ByteBuffer.wrap(
                              (line + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                      ch.force(true);
                  }
  ```

### SEC-04: `charAt(2)` on a 2-byte roster line crashes the refresh and empties the whole roster

- **Severity:** Low
- **CWE:** CWE-129: Improper Validation of Array Index
- **Location:** `src/main/java/com/portal/auth/EmployeeStore.java:193-195`
- **Vulnerable code:**

  ```java
  // src/main/java/com/portal/auth/EmployeeStore.java:190-195
              if (++dataLines > MAX_ACCOUNTS) {
                  throw new IllegalStateException("roster-too-many-accounts");
              }
              if (!raw.startsWith("u=") || raw.charAt(2) == '=') {
                  throw new IllegalStateException("roster-line-malformed");
              }

  // src/main/java/com/portal/auth/EmployeeStore.java:135-146
              try {
                  Map<String, String> reloaded = currentRosterOnDisk();
                  for (Map.Entry<String, String> e : reloaded.entrySet()) {
                      hasher.requireValidRecord(e.getValue());
                  }
                  records = Collections.unmodifiableMap(reloaded);
              } catch (RuntimeException unusable) {
                  // Fail closed, and remember the identity we just rejected so a broken file is
                  // parsed once rather than on every login.
                  records = Map.of();
                  audit.systemFailure("roster-refresh", "-", "-", unusable);
              }
  ```

- **Why it is a problem:** For a roster line that is exactly `"u="` (length 2), the condition
  at `:193` passes `startsWith("u=")` and then evaluates `raw.charAt(2)`, which is out of
  bounds — a `StringIndexOutOfBoundsException` rather than the intended, expected
  `roster-line-malformed` state. `refreshIfChanged` catches every `RuntimeException`
  indiscriminately (`:141`) and responds by setting `records = Map.of()` — the *entire*
  roster. Since `store.refreshIfChanged()` runs at the top of every `Authenticator.decide`
  call, one accidentally truncated line (e.g., an editor glitch that drops the rest of a
  record) turns into a whole-service outage: every login for every employee is denied until
  an operator notices the `roster-refresh` system-failure audit event and repairs the file.
  Failing closed is the right direction for authentication, but the crash converts a single
  malformed line into maximum blast radius instead of a rejected line, and the uncaught-then
  -caught `StringIndexOutOfBoundsException` path is exactly the kind of unintended index
  access a bounds check eliminates. (Anyone who can write the roster can also blank it
  deliberately, so this is availability fragility under an already-trusted writer, not a
  privilege escalation — hence Low.)
- **Fix:** Bounds-check the line length before indexing, so a 2-byte line takes the normal
  malformed-line path:

  ```java
              if (raw.length() < 3 || !raw.startsWith("u=") || raw.charAt(2) == '=') {
                  throw new IllegalStateException("roster-line-malformed");
              }
  ```

### SEC-05: Password bytes retained in an uncleared `FormFields` map; only copies are wiped

- **Severity:** Low
- **CWE:** CWE-522: Insufficiently Protected Credentials
- **Location:** `src/main/java/com/portal/auth/PortalServer.java:404, 435-439, 447-450`
- **Vulnerable code:**

  ```java
  // src/main/java/com/portal/auth/PortalServer.java:404
          private final java.util.Map<String, byte[]> values = new java.util.HashMap<>();

  // src/main/java/com/portal/auth/PortalServer.java:435-439
                  byte[] value = percentDecodeBytes(pair.substring(eq + 1));
                  if (value == null || value.length == 0 || value.length > MAX_FIELD) {
                      return null;
                  }
                  out.values.put(key, value);

  // src/main/java/com/portal/auth/PortalServer.java:447-450
          byte[] asciiBytes(String key) {
              byte[] raw = values.get(key);
              return raw == null ? null : Arrays.copyOf(raw, raw.length);
          }

  // src/main/java/com/portal/auth/PortalServer.java:196-199
          String username = new String(userBytes, StandardCharsets.US_ASCII);
          Crypto.wipe(userBytes);
          char[] password = charsFromBytes(passBytes);
          Crypto.wipe(passBytes);
  ```

- **Why it is a problem:** This codebase goes to deliberate lengths to shorten the lifetime of
  secrets in memory: the raw request body is wiped after parsing, `asciiBytes` hands out
  copies so the caller can wipe them (`:197`, `:199`), and `Authenticator.authenticate`
  clears the `char[]` on every path. But `FormFields.parse` stores the decoded password bytes
  themselves into the `values` map (`:439`), and nothing ever clears that map — the copies
  wiped at `:197`/`:199` are copies; the original cleartext password array survives at least
  until the request ends and the map becomes garbage, and indefinitely if the exchange is
  retained by an error path. The stated invariant ("the raw bytes of the form are wiped as
  soon as they are decoded") is only true for the body string, not for the decoded values it
  produces. On a heap-scraping or core-dump exposure, this is precisely the window the rest
  of the discipline tries to close, which is why it is reported rather than waived as a GC
  nit.
- **Fix:** Give `FormFields` an explicit clear and call it from the dispatcher that owns the
  parsed form (the site at `PortalServer.java:125` that parses the body and routes), in a
  `finally` covering every route:

  ```java
          /** Zero every retained decoded value; called by the dispatcher in a finally. */
          void clear() {
              for (byte[] v : values.values()) {
                  Crypto.wipe(v);
              }
              values.clear();
          }
  ```

  ```java
          // dispatcher (PortalServer.route), after:
          //   FormFields fields = FormFields.parse(new String(body, UTF_8));
          //   Crypto.wipe(body);
          try {
              // existing routing to login/logout/page handlers
          } finally {
              if (fields != null) {
                  fields.clear();
              }
          }
  ```

## 6. Verified Controls and Checks With No Finding

- **Credential storage:** PBKDF2WithHmacSHA256 with an enforced 100,000-iteration floor
  (default 150,000), `SecureRandom` salts, and `MessageDigest.isEqual` constant-time
  comparison; record format validated on load (`PasswordHasher`, `Crypto`).
- **Uniform-denial design:** every refusal path in `Authenticator.decide` performs exactly
  one key derivation (`verifyAgainstDecoy`/`burnOneDigest`), charges the source bucket where
  applicable, and passes through `padToFloor` before responding (`Authenticator.java:150-173`
  and the deny helper); the busy-wait padding loop and the upward-only latency-floor ratchet
  (`ThrottleManager.java:286-316`) are deliberate CPU costs documented in the threat model —
  loud but intentional, and not a finding beyond SEC-01/SEC-02.
- **Throttle arithmetic:** the account back-off ceiling is correctly enforced at 900 s
  (`strikes` capped at 7 with `Math.min(MAX_ACCOUNT_BLOCK_SECONDS, ...)` after the documented
  30<<shift fix); count-window and strike-decay roll-overs both fail toward *more*
  restriction, never less.
- **Ledger integrity:** `load()` rejects any malformed line wholesale (`ledger-corrupt`);
  `persist` validates key shape and count/window bounds; merge takes maxima, and the
  `generation` field defeats the clock-rollback failure mode. `persist` does not validate
  `generation`, but the class's own note documents that an attacker who can write the ledger
  file can forge any counter — an accepted residual risk under the trusted-file-writer
  threat model; no additional finding.
- **Source attribution / header injection:** `SourceRef` parses addresses literally (never
  `InetAddress.getByName`, so no attacker-driven DNS), honors `X-Forwarded-For` only when the
  socket peer is inside a configured trusted IPv4 CIDR, walks right-to-left, and reduces to
  16 lowercase hex before use as a ledger key — `Ledger.key` cannot be made to throw;
  `Location:` headers are static strings, so no request data reaches a response header.
- **Path and file discipline:** `PrivateFiles` refuses symlinks, enforces 0700 parent /
  0600 file modes on every path, writes via CREATE_NEW temp + `force(true)` + ATOMIC_MOVE;
  `PortalConfig` rejects `..`, unknown keys, non-literal listen hosts, world/group-readable
  and symlinked config files; roster mode re-verified before use.
- **TLS and keystore handling:** HTTPS-only listener, protocols pinned to TLSv1.2/1.3,
  keystore password read from a 0600 file into a `char[]` and wiped in a `finally`
  (`JdkHttpsListener.java:218-237`); `tools/gen-cert.sh` generates a 48-hex random password,
  passes it via `-storepass:env`, sets umask 077, and refuses to overwrite an existing
  keystore.
- **Sessions and CSRF:** opaque `SecureRandom` session ids; both cookies carry
  `HttpOnly; Secure; SameSite=Strict` on every branch; the CSRF token is double-submit and
  consumed once, with failures charged to the source bucket; `logout` cannot distinguish
  expired from never-existed sessions (uniform denial).
- **Input bounds:** request body capped before parsing; every form field capped at 512
  decoded bytes with a pre-decode cap on the encoded length; percent-decoding enforces
  printable ASCII; duplicate and unknown keys reject the whole form.
- **CLI and launch hygiene:** `PortalCli` redacts secrets through an alphabet-restricted
  `safeToken`; `portal.sh`/`portal.cmd` run with `CLASSPATH` unset and `-cp` fixed to the
  build output (no `.` or wildcard entries); `build.sh` compiles with `-Werror -Xlint:all
  -encoding US-ASCII`.
- **Supply chain:** `tools/get-jdk.sh` pins the JDK by SHA-256 over `curl --proto '=https'
  --tlsv1.2` and refuses on mismatch; the program has zero third-party runtime dependencies.
- **Test/mutation coverage:** five adversarial suites plus a mutation battery
  (`tools/mutate.py`) that freezes the test tree before mutating guards and counts a
  surviving mutant as a missing assertion. The suites' headers show targeted coverage of
  boundaries, attribution, and network-visible behaviour; the README's "2077 checks,
  30/30 mutants killed" figures were not re-executed (static-review constraint) and were not
  relied upon for any conclusion above. No test was found that asserts insecure behaviour —
  including header regressions written *because of* past bugs (the removed `withHsts` flag
  and the CR-line-folding auth bypass are pinned by `sourceTextGuards()` and the
  identical-header-set assertions). Two tool observations, not product findings:
  `mutate.py:414` unconditionally `shutil.rmtree(WORK, ignore_errors=True)`-deletes the
  `MUT_WORK`-overridable scratch path (`/tmp/qmut` by default) at startup — a dangerous
  footgun if the variable is ever set carelessly, though it only fires when a developer runs
  the battery; and mutant M13's cleanup `os.rmdir`s the empty root-owned `/etc/portal-x` the
  test creates (`mutate.py:294-303`, empty-dir removal only, documented in code). All
  subprocess calls pass argument lists; the `shell=isinstance(cmd, str)` helper at
  `mutate.py:206` never evaluates true.
- **Test seams in production classes:** five `*ForTesting` methods ship inside `src/main` —
  `AuditClock.useForTesting` (public static global clock override, `AuditClock.java:32`),
  `ThrottleManager.setTimingControlsForTesting` (can disable the timing-padding mitigation,
  `ThrottleManager.java:332`), `ThrottleManager.clearAccountForTesting` (public lockout/state
  reset, `ThrottleManager.java:387`), and two public `AuditLog` read accessors
  (`AuditLog.java:84,88`). Verified by search that none is called from any production code
  path — only the test suites invoke them — and reaching them out-of-band would require
  arbitrary in-process code execution, at which point the throttle is already moot. Noted as
  residual hardening surface (they could be package-private or compiled out), not a finding.
- **OWASP/CWE fallback sweep** for behaviours no specialised skill matched (HTTP verb
  handling, cache headers via `securityHeaders()` incl. HSTS on all responses, generic 500
  bodies that never echo exception messages, bounded thread pool at
  `JdkHttpsListener.java:95-96`): no additional findings.
