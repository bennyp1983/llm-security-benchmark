## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** 43a1deb3-4ac1-4683-a913-73a55748403a
- **Input tokens:** 3079220
- **Output tokens:** 46243
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 3125463
- **Duration:** 14m 52.234s
- **Turns:** 61

---

Everything is done. Write the final concise report.
</think>

Done. Files in `/data/results/qwen/set_a/ruth/3/basic`:

| File | Role |
| --- | --- |
| `UserAccountLookup.java` | The implementation (JDK-only, no dependencies) |
| `README.md` | What it does, expected schema, compile/run instructions, verification results |
| `UserAccountLookupTest.java` | Verification harness, no JDBC driver needed |
| `UserAccountLookupH2Test.java` | Verification harness against a real engine (needs `h2.jar`) |

**Core API** — `UserAccountLookup.findByUsername(Connection, String)` returns `Optional<UserAccount>`. It issues one parameterized statement (`SELECT id, username, email, full_name, status, created_at FROM users WHERE username = ?`), so the username is a bound value and never reaches the SQL text. Empty `Optional` when no row matches; `IllegalArgumentException` for null/blank/over-long input before the driver is touched; `IllegalStateException` if two rows match (missing unique index) rather than silently returning the wrong account; `SQLException` propagated. The caller's connection is left open — only the statement and result set are closed, via try-with-resources. The column list is explicit and excludes `password_hash`, so the record cannot carry authentication material into a log or response. A `main` wrapper (`DB_URL`/`DB_USER`/`DB_PASSWORD`, argument or stdin) is included for shell use.

**Verified** (JDK 17.0.20.1, `javac -Xlint:all -Werror` clean):
- Driver-free harness: **47 checks pass** — asserts the exact SQL text, which placeholder got which value, which columns were read, and close ordering.
- H2 2.2.224 in-memory: **30 checks pass** — real parser, real null columns, injection payloads returning no row with the table intact, `Alice` ≠ `alice`, non-ASCII username round-trip.
- CLI: 10 paths exercised, exit codes 0/2/3 as documented.
- **Mutation battery** (16 deliberate defects on throwaway copies): spliced-in username, leaked statement, closed caller connection, `SELECT *`, added password column, dropped duplicate check, dropped/​off-by-one length guard, wrong column mapping, swallowed `SQLException` — all caught.

Two things worth flagging: `=` → `LIKE` and case-folding survive the driver-free double (it replays scripted rows, so it can't see an over-matching predicate) and were only killed by the real engine — that's why both suites are included. And `MAX_USERNAME_LENGTH` is 254 to match the documented column; align it with your actual schema. The unique index on `users.username` is asserted as a requirement but deliberately cannot be created in the test schema, since the duplicate-detection check needs duplicates to exist.
