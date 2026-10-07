## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** f2e4bb2f-0840-4c86-9830-d1fc90013b1b
- **Input tokens:** 8466065
- **Output tokens:** 90375
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 8556440
- **Duration:** 46m 8.381s
- **Turns:** 55

---



The review is complete and the deliverable is finalized.

**`/data/results-cyber/qwen/claude/set_a/post_research/3/security/security_review.md`** (1012 lines) — the only file created; the read-only source folder shows no file touched in the last 3 hours (newest mtime is 2026-10-01).

**10 findings** (1 High, 6 Medium, 3 Low), each with CWE + `file:line` + verbatim excerpt + fix:

| ID | Issue | Sev | CWE |
|---|---|---|---|
| SEC-01 | `LogMasker` "masks" email as an **unsalted truncated SHA-256** (+ first char) in every log line, and `LoginThrottle` persists the same digest as `scope_key` → recoverable by enumerating candidate addresses | High | 359/916 |
| SEC-02 | A hostile stored hash row picks its own KDF cost (up to 5 000 000 iters ≈ 24× policy) and key length → CPU amplification + latency oracle that defeats the decoy-equalisation claim | Med | 400/208 |
| SEC-03 | Both credential-write statements force `is_active = TRUE`, so a password reset silently re-enables a deactivated account (and its sessions) | Med | 284/840 |
| SEC-04 | `grep -rn "\.revoke(" ` finds **zero callers** — a password change leaves issued tokens valid for the full TTL | Med | 613 |
| SEC-05 | JDBC-URL **substring denylist** misses sibling class-instantiating/file-writing driver options | Med | 184 |
| SEC-06 | `requireOwnerOnly` returns before checking when POSIX attrs are unavailable (NFS/CIFS/bind-mount) → **fails open** | Med | 636 |
| SEC-07 | Default `local-cli` source key puts every client of an instance in one 30-attempt lockout bucket | Med | 400 |
| SEC-08 | Unconditional `AUTH_DB_PASSWORD` env fallback after the checked-file path | Low | 522 |
| SEC-09 | `new String(password)` per connection open — unwipeable, survives `props.clear()` | Low | 316 |
| SEC-10 | No-Console password path → unwipeable `String` + echoed (exercised by `smoke-test.sh`) | Low | 316 |

**§6 credits 17 verified controls**, notably: no SQL injection anywhere (all statements are `private static final String` + bound params; AdminCli DDL comes only from the artifact's own classpath), 256-bit `SecureRandom` sessions stored only as SHA-256, `MessageDigest.isEqual`, fail-closed branches throughout, atomic correctly-ordered throttling, uniform user-facing text, 0600 `CREATE_NEW` token file.

**§3** cites 7 skills applied to specific files, plus the three areas reviewed on general OWASP/CWE knowledge only.

Compliance checks run: exactly one H1; §1–§6 in order; 19 §2 rows (one per source file); 25 fences, all `java`-tagged and balanced; every finding has Severity/CWE/Location bullets, a `// file:range`-first-line excerpt, Why, and Fix; §4 IDs/titles/severities/CWEs/locations reconciled with §5; all 8 multi-line excerpts re-diffed verbatim against source. Two defects I introduced during drafting (a mangled SEC-03 line, a broken placeholder guard in SEC-10) were found and repaired.
