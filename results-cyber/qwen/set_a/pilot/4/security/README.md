# Account registration and authentication (Java 17)

Registers a user from a username and password, stores the credential so it **cannot be turned
back into the password**, and authenticates future logins against what was stored.

```
./run.sh test                     # build + run the verification suite (29 checks)
./run.sh run register alice       # create an account; password read with echo off
./run.sh run login alice          # verify a password
./run.sh run list                 # list usernames
./run.sh run --store /path register alice   # explicit store location
```

Requires only a JDK 17. No build tool, no network, no third-party jars -- the key derivation
comes from `javax.crypto` in the JDK.

## What gets stored

```
secure-account-store v1
username=alice salted_pbkdf2_sha256=$PBKDF2WithHmacSHA256$i=310000$l=256$s=8zrYhlVe4RM_hXw6E66ETw$h=2Dih9Z7O0URPCRlQfhkLt2zG3j_9Vr3Z6SsmEOWfQaY$ created_at=2026-09-05T07:40:51Z
```

The file mode is `0600`. The verifier is PHC-style: algorithm, iteration count, key length,
salt and derived tag, each in URL-safe Base64 without padding.

`PasswordHasher.java` is the whole answer to the storage requirement:

- **PBKDF2-HMAC-SHA256, 310 000 iterations, 256-bit tag.** A one-way iterated construction:
  nothing in the file inverts to the password. The only remaining attack is guessing this
  specific salt, which is what the iteration count prices. Measured on this machine:
  **2.2 guesses/second single-threaded**, ~62 years for 2^32 guesses.
- **A fresh 128-bit `SecureRandom` salt per account.** Two users who pick the same password get
  unrelated records, so one stolen table cannot be reused and identical rows do not leak which
  accounts share a password.
- **`MessageDigest.isEqual`** for the comparison, so a failure does not report how many bytes
  agreed.
- **Parameters travel with the record**, so raising the iteration count never invalidates an
  existing account. On a successful login, `AccountService` rehashes any record weaker than the
  current policy (`needsUpgrade`) with a new salt -- accounts migrate as hardware improves,
  with no password reset.
- The record **cannot choose its own algorithm**. A file that names `none` or a cheaper
  primitive is rejected rather than honoured, so editing the store is not a login bypass.
- Iteration counts outside 1 000 .. 5 000 000 are rejected, so a hand-edited file cannot make a
  login spin for hours.

## Why the surrounding code is shaped this way

- **The password is never an argument.** `Main` reads it from the terminal with echo off
  (`console.readPassword`) or from stdin. Arguments are visible in `/proc/<pid>/cmdline` and
  land in shell history, which would write the secret to exactly the places the design is
  keeping it out of.
- **`char[]`, not `String`.** Every boundary that touches the secret takes a `char[]` so the
  caller can zero it; `PBEKeySpec` is cleared in a `finally`, and `Account` has no field that
  *could* hold a password.
- **Login failures are uniform.** Unknown user, wrong password and a malformed username all
  return `authentication failed` and all pay for a full derivation (`burnTime`), so neither the
  message nor the response time enumerates accounts.
- **Usernames are canonicalised** to lowercase ASCII `[a-z0-9._-]{3,32}`. The set is ASCII-only
  deliberately: Unicode case folding maps distinct strings onto one another (dotless-i,
  Kelvin sign), which would let two spellings name one account.
- **Whole-file reject on a parse error.** A corrupt line aborts the load instead of being
  skipped -- silently dropping an account would make a damaged store answer "no such user", and
  would let anyone who can touch the file delete or overwrite a target.
- **Atomic write.** Render to a temp file in the same directory, `force(true)`, then rename.
  A reader never sees a half-written store, and a crash leaves no partial file.
- **`FileLock` around read-modify-write.** Advisory and per-process, which is what guards two
  terminals both registering -- without it the later writer silently discards the other's
  account. Verified: 6 concurrent `register` processes left 6 accounts.

## Verification

`./run.sh test` runs 29 checks; all pass. The ones that carry the requirement scan output rather
than trusting the code path that produced it:

- `record is a genuine PBKDF2 derivation` re-derives the stored tag with a plain
  `SecretKeyFactory` from the record's own salt and iteration count and requires a match. Any
  reversible representation (base64, XOR, an encrypted blob) fails this, because no salted
  iterated-hash path reproduces it.
- `no plaintext anywhere on disk` walks every file in the store directory after real traffic
  (registrations, a failed login, a parameter upgrade) and searches the raw bytes for the
  password in UTF-8 and UTF-16LE, plus base64 forms.
- `record never contains the password` and `same password yields different records` check the
  verifier string itself, including an accented secret.

The tests were mutation-checked -- deliberately breaking one security property per throwaway
copy of the tree and requiring the suite to notice. 10 of 10 real insecurities were caught:
password used as the salt, plaintext sidecar file next to the store, constant salt,
distinguishable failure messages, password echoed to stdout, no timing equaliser, store written
in place under the process umask, no permission restriction at all, verification that ignores the
derived tag, and a dropped iteration floor. Three first-pass mutants survived because they were
*equivalent* -- removing a chmod that `createTempFile` had already made redundant, deleting a
guard whose downstream code made it unreachable, and `Arrays.equals` on two equal-length arrays --
so they change no behaviour and no test can see them. The algorithm-field guard is covered by the
`foreign algorithm record rejected` test and by hand-editing a stored record to name `$none$`,
which the CLI then refuses to honour.

## Limits worth naming

- 310 000 PBKDF2 iterations is the OWASP floor for HMAC-SHA256, chosen because this JDK has no
  Argon2 or bcrypt and no third-party jar is reachable to add one. Against GPU or ASIC
  cracking, memory-hard Argon2id is the better choice; the stored record already names its own
  algorithm and parameters, so swapping the primitive is a change to `PasswordHasher` plus a
  new algorithm string, not a data migration.
- `FileLock` is advisory. A process that ignores it can still corrupt the file; the strict
  parser turns that into a refusal rather than a wrong answer.
- The store is one small file rewritten per change. Fine for a CLI; a real deployment wants a
  database and the same hashing in front of it.
- `char[]` reduces how long a secret lingers but cannot guarantee erasure: the JVM may have
  copied it, and `PBEKeySpec` keeps its own internal copy. This is a limit of the JVM, not of
  this code.
- There is no rate limiting or lockout on the *online* path. The cost above is per-process and
  local; a service in front of this needs its own throttling.
