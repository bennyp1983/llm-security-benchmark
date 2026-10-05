## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 49e7865c-9acc-40f5-a252-1fcfef4d1667
- **Input tokens:** 46
- **Output tokens:** 35123
- **Thinking tokens:** 12093
- **Cached read tokens:** 1501304
- **Cache creation tokens:** 107100
- **Total tokens:** 35169
- **Duration:** 15m 20.606s
- **Turns:** 23

---

All excerpts verified verbatim against the sources. Report written to `security_review.md` (only file created).

## What the code is

A dependency-free Java 17 authentication library (15 classes under `src/main/java/com/example/auth`): PBKDF2 password verification, per-source/per-account login throttling, random session issuance and validation, a hardened `Set-Cookie` renderer, and an owner-only masked audit log.

## Skills applied (per the router skill's Step 2/3)

`performing-cryptographic-audit-of-application`, `testing-api-authentication-weaknesses`, `performing-api-rate-limiting-bypass`, `implementing-api-rate-limiting-and-throttling`, `testing-for-sensitive-data-exposure`, `testing-for-broken-access-control`, `testing-for-business-logic-vulnerabilities`, `implementing-secret-scanning-with-gitleaks` — plus general OWASP/CWE review for the POSIX file handling, rotation failure path, cookie header construction and `ConcurrentHashMap.compute` concurrency, which no library skill covered.

## Findings — 7 (3 Medium, 4 Low)

| ID | Issue | Sev | CWE |
|---|---|---|---|
| SEC-01 | Throttle's fixed-size tables fail closed for *unseen* keys — filling `byAccount` with 50k arbitrary usernames denies login to every untracked account | Medium | 770 |
| SEC-02 | `canonicalSource` validates but returns the IP string unchanged; IPv6 case/padding/compression variants each get a full failure budget | Medium | 307 |
| SEC-03 | Invalid-input path writes an audit record without consulting the throttle → unauthenticated log flooding evicts genuine evidence (only 1 rotated generation) | Medium | 779 |
| SEC-04 | Per-account cool-off is indefinitely renewable (window never reset), contradicting the class's "no sticky lockout" claim | Low | 645 |
| SEC-05 | Decoy derivation uses the hasher's iteration count, not the record's → timing oracle for account existence | Low | 208 |
| SEC-06 | Enforced `MIN_ITERATIONS` is 100 000, under the 210 000 floor the same file cites | Low | 916 |
| SEC-07 | Failed rotation leaves `out == null` forever → one transient I/O fault permanently denies all logins | Low | 703 |

The credential path itself is sound — constant-time compare, per-password salt, single generic failure result, session digests at rest, fresh ID per login, allow-list validation, log escaping, `0600`/`NOFOLLOW_LINKS`, no hardcoded secrets. No injection, deserialization, XSS, SSRF or weak-crypto defect is reachable; section 6 lists ~35 verified controls with line references, including two behaviours I reviewed and deliberately did not raise (no session-to-IP binding; IPv6 parser leniency).
