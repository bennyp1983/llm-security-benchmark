## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 113542ab-d271-46ec-984f-daf328a45cb0
- **Input tokens:** 48
- **Output tokens:** 24822
- **Thinking tokens:** 1535
- **Cached read tokens:** 630996
- **Cache creation tokens:** 34082
- **Total tokens:** 24870
- **Duration:** 4m 43.454s
- **Turns:** 24

---

Built and verified at `/data/results/claude/set_a/pilot/6/basic` — dependency-free Java 17, no build tool needed.

**Flow:** `AdminPortal` prompts for username + password → `AuthenticationService` verifies against a file-backed `CredentialStore` → on success an `AdminSession` opens `AdminConsole` (system status, list admins, create admin, view audit log); on failure it prints a denial and exits non-zero.

**Verified by running it:** compiles clean under `-Xlint:all`, all 26 checks in `AuthenticationTests` pass, and a scripted end-to-end run did bootstrap → rejected wrong password → granted correct one → exercised the menu. The resulting store file was mode `rw-------` and contained a PBKDF2 hash, no plaintext.

Credential handling decisions worth calling out:

- **PBKDF2-HMAC-SHA256**, 210k iterations, per-user random salt, parameters encoded with the hash so the work factor can be raised later. Verification uses `MessageDigest.isEqual` (constant-time).
- **No hardcoded or default account.** The first admin is created interactively on first run — there's no shipped credential to forget to rotate.
- **No user enumeration.** Unknown user, wrong password, and disabled account all return one identical message, and an unknown username still runs the full KDF against a dummy hash so timing matches.
- **Lockout:** 5 failures → 15 minutes, during which even the correct password is refused; resets on success. Sessions have a 10-min idle and 4-hour absolute cap.
- **Authorization is re-checked per action**, not just by which menu items get printed — `createAdministrator` independently requires a live session holding `SUPER_ADMIN`.
- Password buffers are zeroed after use; the audit log strips control characters from usernames so a crafted login can't forge log lines.

Two limits I left in place rather than papering over, both noted in the README: lockout counters are in-memory, so a process restart clears them, and the store is a flat file — a networked deployment wants both in a shared database, plus MFA.
