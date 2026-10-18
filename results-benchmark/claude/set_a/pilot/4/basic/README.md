# Account Registration & Authentication

A dependency-free Java 17 program that registers user accounts and authenticates
against the stored credentials.

## Build & run

```bash
javac -d out src/accounts/*.java

java -cp out accounts.Main                 # interactive menu
java -cp out accounts.Main register alice  # register (prompts for password)
java -cp out accounts.Main login alice     # authenticate; exit code 0 = success
java -cp out accounts.AccountStoreTest     # test suite
```

Credentials live in `./accounts.db`, overridable with `ACCOUNTS_FILE=/path/to/file`.

## Files

| File | Role |
| --- | --- |
| `PasswordHasher.java` | PBKDF2-HMAC-SHA256 derivation, salt generation, constant-time compare |
| `UserAccount.java` | One account; hashing on create, verification, record (de)serialization |
| `AccountStore.java` | File-backed registry: load, validate, register, authenticate, atomic save |
| `Main.java` | CLI: menu plus `register` / `login` subcommands |
| `AccountStoreTest.java` | Self-contained test harness |

## How credentials are stored

One line per account: `username:iterations:base64(salt):base64(hash)`.

Passwords are never stored, logged, or echoed. Each account gets a fresh 16-byte
random salt, and the password is stretched with PBKDF2-HMAC-SHA256 at 210,000
iterations into a 256-bit hash. Only that hash is written, so the file cannot be
reversed into passwords, and two users who pick the same password produce
different hashes.

## Other security notes

- Verification compares hashes with `MessageDigest.isEqual` (constant time), and
  unknown usernames still pay the hashing cost so timing does not leak which
  accounts exist. Failed logins report only "Invalid username or password."
- Passwords are handled as `char[]` and zeroed after use rather than left in the
  string pool.
- The credential file is written to a temp file and moved into place atomically,
  with owner-only permissions (`0600`) on POSIX systems.
- Rules enforced at registration: usernames are 3–32 chars of `[A-Za-z0-9._-]`
  and unique (case-insensitive); passwords are at least 8 characters and may not
  equal the username.

The `iterations` field is stored per account so the work factor can be raised
later without invalidating existing accounts.
