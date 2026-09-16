## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** f7339d64-09c0-42bf-8914-e188dfc2397f
- **Input tokens:** 10892386
- **Output tokens:** 215910
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 11108296
- **Duration:** 1h 18m 6.993s
- **Turns:** 69

---

SEC-12 has been corrected. This completes the citation audit — every §5 Location, excerpt header, and §6 line reference I was holding has been verified against the authoritative source:

- SEC-01: CredentialStore.java:143-147 ✓ (temp :143, write :144, restrict :146, move :147)
- SEC-02: 108-126 ✓ (parts :108 → rows.put :126)
- SEC-03: 101-126, 386-415 ✓ (bootstrapSupervisor :386, invocation site :122)
- SEC-04: AuditLog 46-48 + AdminPortal:58 ✓ (verified in previous session)
- SEC-05: 63-64, 98-101, 215-223 ✓ (HashMaps :63-64, clearLock :100, put :219)
- SEC-06: LoginService 48-52, 183-194 + AdminPortal 290-317 ✓ (record :48, authorized :191 after javadoc :190, remove :290 → unlock :319)
- SEC-07: 55, 126-131, 140-146, 151-155 ✓ (GENERIC_FAILURE :55, LOCKED :126-130, unusable :144, 2nd branch :151-154)
- SEC-08: Pbkdf2.java:17 ✓ (verified in previous session)
- SEC-09/10/11: Verified in previous session
- SEC-12: LoginService:162 ✓ + currently body lines 120–122 ✓
- SEC-13: PortalChecks 37-38, 150-151 ✓; README disclosure claim ✓ (README:223-228 names the store literals and points at PortalChecks.java)
- §2 line counts: CredentialStore 166 ✓, PasswordPolicy 90 ✓, others verified in previous session
- §6: remove guard 299–302 ✓, ProcessBuilder 636–652 ✓, 111 checks ✓

All anchored. Deliverable is complete. Final confirmation that no other files have been modified — I never wrote to anything other than security_review.md.

Now I'll present the final completion summary: concise, with the result up front. Include the findings table concisely, note the verification method (run-checks.sh executed, structure validated, citations audited). Concise but complete — this is the wrap-up of a large task, and a compact, structured summary is appropriate.
</think>

All citations are now anchored. The task is complete.

**Deliverable:** `/data/results-cyber/qwen/set_a/sallie/6/basic/security_review.md` (552 lines) — the only file created; nothing else was modified.

The review followed the `review-code-for-security-vulnerabilities` skill workflow end to end: understood each file's actual behaviour, consulted the skill's own router index and applied every matching specialised skill (credential-storage, authentication/session, logging-integrity, cryptography, secure-coding hygiene, sensitive-data-exposure), ran `./run-checks.sh` to observe real behaviour (all 111 checks pass), and wrote the report in the exact required format (single H1, sections 1–6, language-tagged fences, SEC-NN ids consistent between the summary table and detailed findings). Every `file:line` citation was then re-audited line-by-line against the source.

**13 findings — 1 High / 7 Medium / 5 Low:**

| ID | Sev | Issue | Location |
|---|---|---|---|
| SEC-01 | High | `save()` writes the credential store to a **world-readable, PID-predictable temp file** before `restrict()` runs — any local user can grab the full salted-hash set during every `create`/`reset`/`remove` (CWE-732/377) | `CredentialStore.java:143-147` |
| SEC-02 | Med | Store file has **no integrity protection** — a tampered row (valid syntax) is trusted on load; no MAC/chain (CWE-345/353) | `CredentialStore.java:108-126` |
| SEC-03 | Med | `bootstrapSupervisor` runs **unauthenticated on an empty store** — first-writer-takes-all from any shell (CWE-287/1188) | `AdminPortal.java:101-126,386-415` |
| SEC-04 | Med | Audit log created **world-readable** at default perms (CWE-276/200) | `AuditLog.java:46-48`, `AdminPortal.java:58` |
| SEC-05 | Med | Lockout maps are `HashMap`s mutated across paths without a common guard — lost-update race can clear a lockout (CWE-362) | `LoginService.java:63-64,98-101,215-223` |
| SEC-06 | Med | Sessions are **self-validating bearer records** — no registry, so `remove`/`reset` cannot revoke a live session (CWE-613) | `LoginService.java:48-52,183-194`, `AdminPortal.java:290-317` |
| SEC-07 | Med | LOCKED/unusable refusals **leak account state** before authentication, defeating the equalized-timing design (CWE-204) | `LoginService.java:55,126-131,140-146,151-155` |
| SEC-08 | Med | PBKDF2 at **100,000 iterations** — 6× below OWASP's 600,000 for SHA-256 (CWE-916) | `Pbkdf2.java:17` |
| SEC-09 | Low | 10-char minimum, no breached-password blocklist (CWE-521) | `PasswordPolicy.java:6,43-48` |
| SEC-10 | Low | Password `char[]` flows into immutable `String` via console/confirm paths (CWE-316) | `AdminPortal.java:493-498` |
| SEC-11 | Low | Audit lines are unchained — truncation/rewrite undetectable (CWE-353) | `AuditLog.java:83-105` |
| SEC-12 | Low | Unknown stored role silently **falls back to granted `operator`** instead of refusing (CWE-1188/639) | `LoginService.java:162` |
| SEC-13 | Low | Fixed hardcoded check passwords (CWE-798, test-scoped) | `PortalChecks.java:37-38,150-151` |

Section 6 also documents what genuinely holds up: constant-time comparison, per-branch equal-cost shadow work, fail-closed audit gating of grants, atomic temp-file+rename persistence, zeroization, input validation with no injection surface, and the self-test suite's ten deliberate-defect assertions.
