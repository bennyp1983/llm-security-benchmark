## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 4a8f9404-c053-4f1f-829d-2479bffc4a5b
- **Input tokens:** 5520746
- **Output tokens:** 65229
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 5585975
- **Duration:** 22m 42.702s
- **Turns:** 36

---



Review complete and validated. `security_review.md` is written to the working folder; the source folder was read-only respected (nothing modified, executed, or built).

## Findings — 9 total (1 High, 4 Medium, 4 Low)

| ID | Title | Sev | CWE | Location |
|---|---|---|---|---|
| SEC-01 | Rate-limiter key space is attacker-controlled; filling it locks out **all** authentication | High | 770 | `AttemptCounters.java:64-74` |
| SEC-02 | File ownership proven via spoofable `user.name` property, not effective UID | Med | 287 | `PrivateFiles.java:78-82` |
| SEC-03 | `enroll` appends to the credential file without the privacy check login performs | Med | 276 | `PortalCli.java:212-231` |
| SEC-04 | Rate-limit state rewritten non-atomically; a crash wipes every active restriction | Med | 693 | `FileAttemptLimiter.java:242-249` |
| SEC-05 | Audit sink swallows write failures; append-only log unbounded | Med | 778 | `AuditLog.java:59-62, 80-84` |
| SEC-06 | Bearer token retained in an immutable `String` | Low | 922 | `SessionManager.java:211` |
| SEC-07 | Prebuilt `.class` files shipped with no provenance binding | Low | 494 | `build.sh:15` |
| SEC-08 | Cookie javadoc contradicts emitted `Path` on a `__Host-` invariant | Low | 1110 | `SessionCookie.java:21, 34` |
| SEC-09 | Stdin decoded byte-wise as Latin-1; committed secret ≠ typed secret | Low | 172 | `PortalCli.java:301-315` |

**The one that matters (SEC-01):** both limiter maps cap at `maxTrackedKeys = 100_000` and return `CAPACITY_EXHAUSTED` for *any* new key once full, which `Authenticator` converts to a denial. Source keys need only match a 64-char whitelist grammar (`InputPolicy.java:127-132` doesn't require a numeric address), and account keys are created even for non-existent users. An unauthenticated caller minting fresh buckets can therefore switch off login org-wide, while each probe still costs a 600k-iteration decoy derivation. Fail-closed is correct; making attacker key cardinality a global kill switch is not.

**No auth bypass, credential leak, injection, or token forgery exists.** This is unusually careful code — I verified rather than trusted each `README.md` hardening claim: iteration-range validation blocks hash downgrade, `MessageDigest.isEqual` plus decoy KDF on unknown-account/restricted paths, slot reserved *before* verify under lock, digest-keyed session table with dual expiry, complete `__Host-`/`HttpOnly`/`Secure`/`SameSite=Strict` rendering, whitelist rejection of traversal/CRLF/NUL before any budget is spent, owner-only modes applied at create time with per-use re-verification, and masking of every logged identifier. §6 records these, plus that `SelfTest` covers **none** of SEC-01/04/05's territory.

Two notes on rigor worth flagging:
- I re-derived every citation with `grep -n` rather than from memory. That caught four slips in my own draft (a `PrivateFiles` comment I had paraphrased inside quotation marks, and off-by-a-few ranges in SEC-05/06/09) — all corrected. It also strengthened SEC-08: `SessionCookie.java:43` states the *correct* `Path=/` invariant 22 lines below `:21`'s wrong one, so the defect is a self-contradiction inside one file.
- SEC-04's fix is not the obvious one: `truncate(0)`+write does preserve the `FileLock`'s inode, so a naive atomic-move would silently split inter-process mutual exclusion. The report prescribes moving the lock to a companion file first.

**Coverage caveat:** static only, as instructed — `build.sh test` was not run, so the 20 self-tests are confirmed to exist and target the right properties, not observed to pass; `out/**/*.class` was not decompiled, so SEC-07 offers the verification mechanism without alleging divergence (`out/` and `src/` mtimes both match 2026-10-01).
