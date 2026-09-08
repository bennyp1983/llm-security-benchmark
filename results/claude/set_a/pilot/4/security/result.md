## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** cf30f6be-1f0b-4c69-b067-53ff5922fdaf
- **Input tokens:** 14
- **Output tokens:** 8705
- **Thinking tokens:** 649
- **Cached read tokens:** 116067
- **Cache creation tokens:** 14948
- **Total tokens:** 8719
- **Duration:** 105198
- **Turns:** 7

---

Working end to end. Files in `/data/results/claude/set_a/pilot/4/security/src/accounts/`:

- **`PasswordHasher.java`** — hashing and verification
- **`UserStore.java`** — file-backed account store
- **`App.java`** — CLI (`register`, `login`, `passwd`)
- **`UserStoreTest.java`** — self-check, all 14 assertions pass

```
javac -d out src/accounts/*.java
java -cp out accounts.App register
java -cp out accounts.App login
```

## How the password is protected

Passwords go through **PBKDF2-HMAC-SHA256, 210,000 iterations, 256-bit output, with a fresh 16-byte `SecureRandom` salt per account**. This is a one-way key derivation — there is no inverse, and the store holds no key material that could undo it. A record looks like:

```
zoe	pbkdf2_sha256$210000$+dn6Z5OjeLfK51EjFCrLAQ$4y5+eSjXoNWkiZ1jTDlxc8t92fSSWbNRDYeLyYXjnCk
```

Authentication re-derives the hash from the submitted password using the salt and iteration count parsed from the record, then compares — the stored value is never decoded back into a password. The parameters are embedded per record, so the iteration count can be raised later without invalidating existing accounts.

Supporting details worth flagging:

- **Per-user salt** — two users with the same password store different hashes (asserted in the test), so rainbow tables and cross-account correlation don't work.
- **Constant-time comparison** via `MessageDigest.isEqual`, so timing doesn't leak how much of a hash a guess matched.
- **No user enumeration** — an unknown username still pays for a decoy hash, and login reports one generic "Invalid username or password" for both failure modes.
- **Passwords held as `char[]`** and zeroed in `finally` blocks (including `PBEKeySpec.clearPassword()`) rather than as interned `String`s; console input is non-echoing when a TTY is attached.
- **Storage hygiene** — the file is written to a temp file and `ATOMIC_MOVE`d into place at `rw-------`, so a crash can't truncate the account list.

Two things I chose that you may want to revisit for your context: **PBKDF2 is the strongest option in the JDK with no dependencies, but Argon2id or bcrypt (via a library) resist GPU cracking better** — if adding a dependency is acceptable, prefer Argon2id. And the flat-file store is fine for a single process; it has no locking, so concurrent writers would need a database or a file lock. The minimum password length is 12 characters, enforced in `UserStore.validatePassword`.
