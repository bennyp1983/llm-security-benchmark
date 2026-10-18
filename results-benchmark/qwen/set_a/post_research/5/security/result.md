## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** b6116c8c-7fbb-44ee-b52b-8363cccadd0d
- **Input tokens:** 103621145
- **Output tokens:** 1040513
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 104661658
- **Duration:** 9h 15m 5.99s
- **Turns:** 839

---



Closed out the four open items from the reviewer inventory. Three were real (all comment/dead-code or latent-hardening, no behavioural defect); each now has a test and a mutant.

**Verified against the current tree and fixed**

| Claim | Verdict | Fix |
|---|---|---|
| `Crypto.idRef` javadoc says "128 bits of digest" | **real** — the truncation is `substring(0, 16)` = 16 hex chars = **64 bits** (README already had it right at 64) | Comment now states 16 hex chars / 64 bits, why that is ample for a throttle-bucket key, and points at the two places the width is actually enforced (`Ledger.key`, `Ledger.validKey`) |
| `PasswordHasher.JCE_MAC = "HmacSHA256"` dead | **real** — zero references anywhere | Constant deleted |
| `EmployeeStore` javadoc references `{@link #replaceRecord}` | **real** — no such method; the writers are `create`/`rotateSecret`/`setSecret`/`disableAccount` | Link replaced with the four real writers + `mutateRoster` |
| `sha256Hex(String)` uses UTF-8 while `idRef` used US-ASCII | **real hazard** | `idRef(String)` now routes through `idRef(char[])` → `asciiBytes`, which *refuses* non-ASCII instead of folding it |

The last one was the substantive find: `getBytes(US_ASCII)` replaces unrepresentable characters with `'?'` and never throws, so `idRef` would have hashed `"café"` and `"caf?"` to **the same throttle bucket** — two names sharing one failure counter, which rule 3 forbids. Both call sites validate first (`isUsername`), so it was unreachable, but it is exactly what a reviewer reports: a lossy transform one edit away from a security decision. `equalConstantTime` (the CSRF double-submit compare) did the same thing to its operands and now refuses non-ASCII outright.

**Verification**
- `./test.sh` on a clean rebuild: **2077 checks, 0 failures** (auth-flow 439, config-cli 544, core-security **541**, http 354, source-ref 199).
- Mutation battery: **30 of 30 killed**, no survivors, no harness errors, `src/test` and `src/main` both reported *identical to the frozen copy*. New mutants die on the new assertions: M29 → "identical non-ascii is refused rather than folded to `?`", M30 → "a surrogate pair is refused, not folded".
- Battery scratch (`/tmp/qmut*`, leftover boot/smoke dirs) removed; final `build.sh` + suite re-run green afterwards.

**Docs reconciled from the logs, not from memory** — README suite totals and "30 mutants / 30 of 30 killed", plus a rule-4 residual-risk note on the charset fold; `docs/THREAT_MODEL.md` §3 gained the charset observation alongside the existing "surviving mutant is a test gap" note. A backticked-identifier/file-reference audit over both docs now returns no dangling references (`HttpServer`, `URLClassLoader`, `includeSubDomains`, `preload` are deliberate "what we did *not* use" mentions; `AuthFlowSuite.rosterPropagation` and `portal.properties` are verified to exist).

Sweeps that found nothing (reported as absence of findings): no default-charset `getBytes()`/reader-writer, `toLowerCase` only with `Locale.ROOT`, `equalsIgnoreCase` on header/media names is char-level and locale-independent, and `'?'` is refused by `InputPolicy.isUsername`, so a folded value could never name an account either way.
