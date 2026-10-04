## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 11da1621-3333-4db6-b2ba-76bd0cc2e1cf
- **Input tokens:** 90613980
- **Output tokens:** 840866
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 91454846
- **Duration:** 6h 18m 32.741s
- **Turns:** 459

---



Docs edits since the last suite run touched only `README.md`, `SECURITY.md`, and `tools/mutation-timing.sh` — none affect compilation or the suites, which were verified green on the current code. Everything is done.

## Result

The authentication component is complete and fully verified. Final state:

**Verification (regenerated this run):** both trees compile clean under `-Xlint:all -Werror`; all five suites pass — **800 checks, zero failures** (Suite1 380 / Suite2 181 / Suite3 16 / Suite4 168 / Suite5 55). Suite 3's timing note now reports microseconds straight from the log: whole-path wall spread **1.09×**, deriving-path CPU spread **1.01×**, floor ~250 ms, one derivation ~174 ms.

**Mutation battery:** **25 of 30 killed** (`killed=24 survived=6 errors=0`, harness `BASELINE` self-check clean), plus M12 independently killed by the timing pass (re-run under the repaired harness — M12 KILLED, M11 survived as documented). The last gap I closed this session:

- **M22** ("audit outage charged to the account") had survived a test that *looked* on point. The old test drove five correct passwords through an outage and asserted no lock — but the success path calls `resetAccount` before recording the success event, so a charge injected in the shared catch was wiped. The double-charge is only observable on the **mismatch** path (no reset → lock halves at threshold). New Suite-2 test `aRefusalThatCouldNotBeLoggedChargesTheAccountOnce` pins `accountLockAfter` itself; that's the assertion M22 now dies on.

**Docs re-synced from logs/code** (every number re-derived, not carried over): the check-count table, suite-3 timing paragraph, mutation tallies, plus several code mismatches I found while auditing — SECURITY.md said "all 15 keys" (it's 16), the credential-file cell still described the old "per-record iteration floor" (now the `[min, max]` window), the README's "over eighty times" work-factor example, the mislabelled 7th uniform-denial shape, and a wrong pepper-construction note in the provisioning step (pepper is the HMAC *key*, not a password suffix — and `derive` is package-private, so the README now spells out how to actually provision).

Two durable lessons saved to memory: the reset-masks-a-charge survivor class, and the `-Dauth.source.dir` scratch-tree soundness trap that had been silently manufacturing survivors.
