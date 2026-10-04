# secure-data-crypto

Authenticated symmetric encryption for application data: **AES-256-GCM**, a fresh random nonce per
record, the record's header fields bound in as additional authenticated data, and the key handling
needed to load, version, rotate and erase the keys. Nothing else — no CLI, no UI, no admin features.

JDK 17, no runtime dependencies. The only dependency in the build is JUnit, test-scoped.

```
SymmetricCrypto crypto = new SymmetricCrypto();
KeyMaterial key = crypto.generateKey(1);

EncryptedBlob blob = crypto.encrypt(key, cardNumber, "tenant:42");   // context is authenticated
String back = crypto.decryptToString(key, blob, "tenant:42");        // wrong context -> fails
```

In a real deployment the key does not stay in memory forever — you register where it lives and let the
vault load it per operation:

```
KeyVault vault = new KeyVault(v -> new KeyFileKeySource(Path.of("/etc/app/keys/v" + v + ".key")), 1);
EncryptedBlob blob = vault.encryptString(cardNumber, "tenant:42");
String back = vault.decryptStringEncoded(storedValue, "tenant:42");
```

## Build

```
mvn -o test      # 72 tests
mvn -o package
```

Requires a JVM with the unlimited-strength crypto policy: the library refuses to load at all if
AES-256 is unavailable, rather than failing on the first call.

## What is in a record

```
byte 0      format version (1)
byte 1      context flag   (0 or 1)
byte 2      key version    (1..255)
bytes 3..14 nonce          (96 bits, SecureRandom, fresh per record)
bytes 15..  ciphertext + 128-bit GCM tag
```

Text form: `v1.<base64url-nopadding>[.<context>]`. The string form is the only one that carries the
context, so `EncryptedBlob.fromBytes` deliberately refuses a context-bound record — a caller must not
be able to satisfy a context-bound record on the strength of an unauthenticated flag.

The AAD is `format || record's claimed context flag || record's claimed key version ||
caller-has-context || key's real version || encoded context`. Both readings of each header field are
authenticated, so a tampered header cannot be settled by a branch: there is **no early return** for a
version mismatch, and editing the version byte costs exactly as much as editing the ciphertext. An
implementation that returned "unknown key version" before doing the AES-GCM work would leak, by timing
alone, which records name a version this server knows.

## Which of the eight rules apply, and how

Rules 1, 2, 5, 6, 7 and 8 apply directly. Rules 3 and 4 mostly do not — see their sections; pretending
otherwise would be padding.

### 1. Trust boundaries — every input is enumerated and validated before it can affect an outcome

| Input | Where from | Validation before use |
|---|---|---|
| plaintext | caller / database / request body | non-null, ≤ 1 MiB (`Limits.MAX_PLAINTEXT_BYTES`), checked *before* any cipher or array work |
| context string | caller, often derived from a request (`"tenant:42"`) | printable ASCII `0x21..0x7E` only, ≤ 200 chars — no NUL, no newline (log injection), no control chars, no bidi overrides; `null` means "no context" and is recorded as such rather than folded into `""` |
| encoded record | database, HTTP body, file, queue | length cap before scanning, no leading/trailing whitespace or control chars, prefix, field shape, strict base64url alphabet, **canonical re-encode equality**, then length/format/flag/version-range, then flag↔field agreement |
| raw record bytes | same | size bounds, format-version whitelist (`UNSUPPORTED_FORMAT` for anything else), flag must be 0 or 1, key version ≥ 1 |
| key text (`KeyEncoding.decodeKeyBytes`) | config file, env var, secret manager | exactly 32 raw bytes, or their canonical unpadded base64url text. Anything with whitespace, control characters, padding, a newline, or a non-canonical spelling is **refused, not repaired** |
| environment variable name | config | `[A-Za-z_][A-Za-z0-9_]{0,63}`, checked **before** `System.getenv` is called |
| file / directory path | config | non-null, ≤ 4096 chars, no NUL byte; then ownership, symlink, regular-file, mode and ancestor checks (rule 5) |
| key version number | record header (`peekKeyVersion`), config, `addReadableKey` | `1..255` at the API, `1..64` tracked versions; a version never authorises anything (see below) |
| PBKDF2 iteration count | the key file, i.e. an attacker-writable place | whitelist `310 000 .. 2 000 000`, checked **before** `SecretKeyFactory` is invoked |
| passphrase | operator | 32..4096 chars; trailing NULs and unpaired surrogates refused, because `PBEKeySpec` is not injective over `char[]` and would silently map two passphrases to one |
| keystore alias | config | `[A-Za-z0-9_.:\-]{1,64}` |
| `SecureRandom` | caller-supplied (optional constructor) | non-null; `getInstance` failures propagate as `PROVIDER_FAILURE`, never a silent fallback to `Random` |

Nothing in the API has a permissive default. There is no way to ask for AES-128, a shorter tag, a
caller-chosen nonce, or "just decrypt it without the context".

`EncryptedBlob.peekKeyVersion(String)` is the one function that deliberately returns
**attacker-chosen** bytes, so that a caller can load one candidate key instead of all of them. It is
documented at the declaration as untrusted and advisory: it may only narrow which key is *attempted*.
The version byte is inside the AAD, so a record re-stamped to another version fails authentication no
matter what this returned, and `KeyVault` fails closed when it has no key for that version rather than
trying others. Residual risk to note where it is used: it is a cheap routing hint, so it is also a way
for an attacker to make a server attempt — and fail — a decryption. That is why the failure is
constant-cost (rule 6) and why there is no key-confirmation oracle.

### 2. Secrets — no key or password is ever hardcoded, printed, logged, or passed in argv

- No key material, salt, IV, passphrase or default password appears anywhere in the sources. A test
  (`nothingThatLooksLikeAKeyIsEverDerivedFromAConstantOrADefault`) generates 64 keys and asserts they
  are unique, non-zero and byte-varied — i.e. that the generator is really generating.
- Keys come from `KeySource` implementations at runtime: a file, an environment variable, a PBKDF2
  wrapped container, or a PKCS#12 keystore. Passwords are never stored in code or in the container —
  `PasswordKeySource` holds the passphrase as a `char[]` and erases it.
- `CryptoException.getMessage()` is one of exactly four fixed strings. The reason for a failure lives in
  `getTechnicalDetail()`, which is a separate method a caller decides to log; no logger is invoked here,
  and no detail contains key bytes, plaintext, a passphrase, or a file's contents.
- `KeyMaterial.toString()` is `"KeyMaterial[destroyed=…]"`. `KeyVault.toString()` lists versions and
  source descriptions (paths, env names) — locations, never secrets. `EncryptedBlob.toString()` prints
  the record's own metadata, which is not secret.
- `describe()` returns `env:NAME`, `file:/path`, `pbkdf2:/path@v3`, `pkcs12:/path#alias@v1`.
- Nothing is passed through argv. The main sources declare no `main`, no `ProcessBuilder` and no
  `Runtime.exec` at all — verified by grep, not by convention — so a secret can never appear in a
  command line that another user can read from `ps`. (The test suite shells out once, to create a
  world-readable file as a competing writer, and its helper child JVM takes only a variable *name* and
  prints a hash of the key, never the key.)
- A sweeping test (`everyFailurePathRendersNothingAnAttackerWants`) walks 20 failure routes and renders
  `getMessage`, `getLocalizedMessage`, `getTechnicalDetail`, `toString`, `code`, `getCause`,
  `getSuppressed` and `printStackTrace` for each, then asserts that no key hex, no key base64, no
  plaintext and no passphrase appears anywhere in the result.

### 3. Authentication and access control — largely inapplicable, and what replaces it

There is no authentication, session, account or privilege model in a crypto library: it has no users to
authenticate and no access-control decision to make. Two things *are* in scope, and both fail closed:

- **A key version is never an authorisation decision.** `decrypt` attempts exactly the one key a record
  names and never tries others, so there is no "did some key open this?" oracle to probe. If the source
  for a version hands back a key that mislabels itself, that is refused as `INVALID_KEY` — a
  configuration fault, reported as one, on both the encrypt and the decrypt side.
- **Fail closed, always.** No key source returns a default, a zeroed key or a cached last-good key. A
  missing env var, an unreadable file, a wrong password, a disabled version, a closed vault, a source
  that returns `null`, a filesystem without POSIX permissions — every one is an exception. `close()` is
  sticky: a closed vault refuses forever rather than silently re-running the factory and re-deriving the
  key it just erased (a real bug found by the tests, since fixed and now pinned by
  `closingTheVaultMakesItFailClosedRatherThanRecreateAKey`).

**Rate limiting is explicitly not implemented and cannot be** — the component has no request context to
limit per. Whoever calls this must rate-limit per source *and* per account before calling, especially
for `PasswordKeySource.load()`, where each attempt is one offline-guess trial. Measured on this
machine, the KDF floor of 310 000 iterations costs ~462 ms of CPU per attempt and the 2 000 000 ceiling
~2.92 s — which is why the ceiling is enforced *before* the KDF runs. That is the cost of one trial, not a
substitute for limiting trials.

### 4. Identifiers and tokens — mostly inapplicable; the parts that apply are generated here

There are no session cookies, CSRF tokens or public identifiers, so cookie flags (`HttpOnly`,
`SameSite`, `Secure`) have nothing to attach to. What applies:

- **Every cryptographic value this component produces comes from its own `SecureRandom`**: 256-bit data
  keys, 96-bit per-record nonces, 128-bit wrapping nonces, 128-bit PBKDF2 salts, wrapped-key containers,
  and `RandomPasswords` output (48 chars by default from the 94 printable ASCII characters excluding
  space, ≤ 1024, via the unbiased `nextInt(bound)`). Nothing is derived from a timestamp, a counter,
  `UUID`, `Random`, or a caller-supplied seed.
- **No caller can supply a nonce, an IV, a salt or a key-version generator.** The API takes none of them.
- Key versions are assigned by `KeyVault.rotate()` as strictly increasing integers and are never reused,
  even after a version is dropped.
- External identifiers that *are* accepted are validated strictly (rule 1's table): key version numbers,
  env var names, aliases, paths. Residual risk for `peekKeyVersion` is documented above.
- `RandomPasswords` exists so that deployers stop inventing passwords; it is the only place in the code
  that mints a human-usable secret.

### 5. Sensitive data — masked in logs, written only to owner-private files, size-bounded, erased from memory

- **Bound before allocating.** Size caps are checked before any allocation, base64 scan, KDF or cipher
  call, so a 4 GB blob string cannot turn into a 4 GB array, and `iterations = 2000000000` in a hostile
  key file is refused in microseconds (the test asserts the refusal costs under 60 ms).
- **Files.** `PrivateFiles.writeOwnerOnlyFile` creates with `FileChannel.open(CREATE_NEW, …)` *and*
  `unix:mode 0600` as a creation attribute, so the file is never born readable and there is no
  create-then-chmod window. It never overwrites. `newOwnerOnlyOutputStream` exists for the one caller
  that must write the bytes itself (`KeyStore.store`) — `Files.newOutputStream` has no `FileAttribute`
  overload, so a keystore written that way is born `0644`; that is a real window, so the wrapper is used
  instead and the mode is asserted afterwards.
- **Reads** re-verify on *every* load, not once: not a symlink, a regular file, mode ⊆ `0600` (group,
  other and every execute bit refused), no set-id bits, owned by this user, and **every ancestor
  directory** checked — refusing anything writable by others without the sticky bit (`/tmp` is `1777`, so
  the sticky convention is honoured while a genuinely unsafe `0775` is refused). After a read through a
  shared parent, the file is re-identified rather than re-trusted: the parent's mode, the file's
  `st_dev`/`st_ino` identity, its mode and its owner are all compared with what was snapshotted before the
  read, and any disagreement discards the bytes. Checking only the parent's mode — which is what this used
  to do — cannot detect the attack it documented: an attacker who can move entries in a shared parent can
  swap the file for another inode while the mode and the parent's mode both stay put.
- **Memory.** `KeyMaterial` owns its `byte[]` and zeroes it in a `finally` after every use, plus
  `destroy()`/`close()`. The working copies, nonces and plaintext buffers inside the engine are zeroed
  too. `SecretKeySpec.destroy()` is *not* relied on — on this JDK it throws `DestroyFailedException`,
  leaves `isDestroyed()` false and zeroes neither its password nor its key; the only erasure that works is
  the one this code performs on the array it owns. `SecretKeySpec` **clones** its input, so erasing the
  caller's array does not touch the spec's copy and vice versa — `KeyMaterial.use()`'s `finally` therefore
  erases only this class's own copy, which is what its javadoc claims and nothing more.
  `PasswordKeySource` and `KeystoreKeySource` are `AutoCloseable` so a try-with-resources erases the
  passphrase. A caller's arrays are never mutated: `KeyMaterial.fromBytes` clones, and the record's
  `toBytes()` returns a copy (`ciphertext()` is package-private precisely so the non-copying view cannot
  escape).
- **What actually erases a derived passphrase.** `PBEKeySpec.clearPassword()` does erase: measured on this
  JDK (JDK 17.0.20.1) it nulls the spec's internal `char[]`, and it leaves the *caller's* array untouched,
  which is why the caller's array is wiped separately. `derive()` keeps the spec in a local and calls
  `clearPassword()` in a `finally`, so the derived-key window does not depend on the caller closing
  anything. The remaining hole is inside the provider: `PBKDF2KeyImpl` keeps its own `passwd` and `key`
  arrays, and its `destroy()` throws rather than clearing them, so a derived key's copy in JDK internals
  is beyond reach. Probed, measured, documented here rather than promised in a javadoc.
- **Logs.** Nothing is logged. The only channel is `getTechnicalDetail()`, which names the failed
  *requirement* (e.g. `key file permissions grant more than owner read/write: rw-rw-r--`) — a mode and a
  path, which is what an operator needs, never contents.

### 6. Failure behaviour — identical messages, comparable work, no existence oracle

Four user-visible strings, no more:

| code(s) | `getMessage()` |
|---|---|
| `MISSING_INPUT` | `No data was supplied` |
| `INVALID_INPUT`, `UNSUPPORTED_FORMAT`, `TOO_LARGE` | `The supplied data is not in a supported format` |
| `KEY_UNAVAILABLE`, `KEY_NOT_ACTIVE`, `AUTHENTICATION_FAILED`, `INVALID_KEY`, `KEY_SOURCE_UNAVAILABLE`, `INSECURE_KEY_STORAGE` | `The data could not be decrypted` |
| `PROVIDER_FAILURE` | `The data could not be processed` |

- A forged record, a record for a version this vault does not track, a record whose key is disabled, a
  record decrypted with the wrong key, and a record whose context does not match all produce the **same
  sentence** — so nothing confirms that a record, an account, or a tenant exists. A test asserts the
  refusal text names none of: key, password, secret, tenant, context, version, permission, file,
  environment, keystore, tamper.
- **The version table is never a leak, and an unknown version is answered with the tag.** A record naming
  a version above every version this vault ever issued used to be refused by name — *"no key source for
  version 200"* — which is a distinct, cheaper message on a path where the attacker controls the input, and
  it also wrote the size of the key estate into the log. `sourceFor` now refuses nothing for such a record:
  it hands back a stand-in source whose 32 bytes come from a fresh `SecureRandom` draw per call, so the
  caller pays one full AES-GCM attempt and sees an ordinary `AUTHENTICATION_FAILED`, and the factory is
  never invoked (a test asserts both the identical detail and that no factory ran). The stand-in must not
  be a deterministic value — a fixed stand-in for a version the vault will never provision would be a
  forgery channel, since anyone could encrypt under it — and it claims the *record's* version, so the
  `key.version()` cross-check stays behind the tag rather than becoming the oracle that was removed. The
  same ceiling is enforced on both insertion paths, so neither `addReadableKey` nor `rotate` can grow the
  version table past `MAX_VERSIONS` and make the bound a lie.
- **An early return in a guard is itself the oracle.** The lesson above generalised: a check that refuses
  before the cipher runs differs from a tag failure in cost even when the text is copied, so every guard on
  the decrypt path either runs before any attacker-controlled record is parsed (size caps, which refuse
  cheaply and *must* refuse cheaply) or is folded into the AAD and paid for. The two are distinguished in
  tests on purpose: caps assert the refusal is under a time bound, tamper asserts the refusal is *not*
  cheap.
- **Comparable work** is the harder half and it is enforced, not assumed: the version/context mismatch is
  not returned early but folded into the AAD, so every refusal pays for one full AES-GCM attempt.
  `editingTheHeaderCostsTheSameAsEditingTheCiphertext` times seven routes (edited version byte, context
  flag, nonce byte, first body byte, last tag byte, wrong context, wrong key) and asserts the slowest/fastest
  ratio stays under 4 and the fastest is above 40 µs. A cheaper guard was tried and removed for exactly
  this reason: two layers refusing the same invariant make the inner one invisible to a boolean test, so
  the *cost* is what proves it ran.
- Stack traces and suppression are disabled (`super(message, cause, false, false)`), `printStackTrace`
  emits only the class name and the generic message, and `getCause()` is sanitised to a
  class-name-only wrapper, so `javax.crypto.*` internals and file paths cannot ride out on a cause chain.
- **Serialization keeps the safe half.** `technicalDetail` is `transient` and the `code` is not, so an
  exception that crosses a JVM — a queue, a session replica, a cache — keeps its generic message and its
  machine-readable kind and loses the operator-facing detail. That asymmetry is deliberate and pinned by a
  test that round-trips a real failure: message and code survive, `getTechnicalDetail()` comes back `null`.
  (`code` was `transient` until a reviewer pointed out that a deserialised exception then reported *no* kind
  at all, which pushes callers to log the message — the one thing that must stay generic — or invent a
  classification from the text.)
- Details go to the log channel only, and there they *do* differ — deliberately, or the operator's log is
  useless. The test asserts the three authentication routes share one detail (they are one tag check)
  while auth vs format vs missing differ from each other.
- Unknown input is refused, never defaulted: unknown format version → `UNSUPPORTED_FORMAT`; non-canonical
  base64 → refused; padded base64 → refused; a 33-byte key file (a raw key with a newline) → refused
  rather than trimmed; a context bound record with a missing context field → refused.

### 7. Concurrency — check-then-act made atomic

- `KeyVault` keeps `ConcurrentHashMap` of *sources* (never keys) and guards every version transition
  (`rotate`, `addReadableKey`, `disable`, `enable`, `sourceFor`'s cache fill) under one `rotationLock`, so
  "is this version still active?" and "use it" cannot interleave with a rotation. `disable` cannot take
  out the active version; `addReadableKey` cannot claim the active or a future version; `disable` refuses a
  number outside `1..255` instead of recording it as a disabled version that can never exist, and neither
  insertion path can push the table past `MAX_VERSIONS`.
- Replacing a slot releases the object it displaced **only if no other version still points at it**. The
  obvious code released the displaced source unconditionally, which erased a key that another version was
  still serving — a `KeyVault.of(...)` that installs one source under two versions, or a caller that hands
  the same `KeySource` to two `addReadableKey` calls, would lose live key material with no error. The test
  wires a shared PKCS#12 source under two versions, rotates, replaces, and asserts the source is neither
  destroyed nor unreadable afterwards.
- A cache-miss fill uses `putIfAbsent`, and the loser of that race is released by the caller's `finally`
  (tracked by `isCached`) — so a losing `KeyMaterial` is erased rather than leaked, and no source is
  double-released.
- **File creation is the atomic step.** The original code asked `Files.exists(file)` and then created the
  file — two decisions about one fact, with a window in between for a local attacker to create that name
  and have a key written into their file. The pre-check is now gone: `CREATE_NEW` is the decision, made
  inside the one operation that also sets the `0600` mode.
- **How that claim is tested, and why it is not tested with a race.** An earlier version of this test
  raced a second process against the writer and asserted the race had actually been won. It was
  unfalsifiable: because `CREATE_NEW` legitimately decides the contest whichever way the timing falls, the
  racer never once observed a difference across 120 attempts, and the test could not have failed for any
  implementation. Two tests replace it, and both can fail.
  `aKeyFileClaimedBySomebodyElseIsNeverWrittenInto` fixes the two orders instead of gambling on one: the
  attacker holds the name (`sh -c 'umask 000; set -C; : > file'`, so his `0666` file exists first) and our
  key must not reach it — the write is refused, his file keeps its size and mode, and a byte search proves
  the key is absent; then we hold the name and the key must never exist in a file whose mode somebody else
  set (`0600`, our bytes). `theWritePathAsksTheFilesystemRatherThanCheckingFirst` checks the property where
  it actually lives — in the source. It reads the two write methods with comments stripped (the code
  deliberately *prose*s about not checking for existence, so a naive scan finds the banned token in the
  explanation and reports the defect it is looking for) and requires `CREATE_NEW` plus `FileChannel.open`
  while forbidding any existence query **about the target**. The probes are qualified with the target's
  variable name because asking whether the parent *directory* exists is a different question, with no
  competing writer, and refusing it would be an outage rather than a defence. A redundant `Files.exists`
  in front of `CREATE_NEW` is invisible in behaviour — the filesystem still refuses — so a source guard is
  the only thing that can see it, and the mutation harness proves the guard sees it: the
  `target-existence-pre-check` mutant re-adds exactly that pre-check, changes no observable behaviour, and
  is killed only by reading the code. For that to be honest the guard has to read the *mutant*, so the
  lookup honours `-Dsecure.data.crypto.src.main=<dir>`; without the override it resolves from the compiled
  classes, not from the working directory, which is why it survives the harness running elsewhere.
- `KeyMaterial.use` is `synchronized` and single-purpose; `destroy()` is idempotent; `SymmetricCrypto`
  is immutable apart from the thread-safe `SecureRandom`. Concurrency tests round-trip 8×25 (vault) and
  8×40 (engine) operations, and the vault's test additionally asserts one source per version and that a
  record superseded by a rotation fails as `KEY_UNAVAILABLE` — never as `AUTHENTICATION_FAILED`, which
  would mean it was opened with the wrong key.

### 8. Prefer the platform

Everything cryptographic is the JDK's own, pinned in `pom.xml` as `<release>17</release>`:

| need | what is used | why not a library |
|---|---|---|
| cipher | `javax.crypto.Cipher` / `AES/GCM/NoPadding` | a hand-written AEAD is the thing to avoid, not the deliverable |
| randomness | `java.security.SecureRandom` | covers the OS entropy source; no JNR/`/dev/urandom` shim |
| password-based key derivation | `SecretKeyFactory` / `PBKDF2WithHmacSHA256` | standard, auditable, no Bouncy Castle needed |
| key storage | `java.security.KeyStore` (PKCS#12) | the platform's own container format |
| encodings | `java.util.Base64` URL encoder/decoder, `HexFormat` | — |
| file permissions | `Files.getAttribute("unix:mode")`, `PosixFilePermissions`, `FileChannel.open` with creation attributes | no JNI, no `chmod` shell-out in production code |
| charset | `StandardCharsets.UTF_8` with `CodingErrorAction.REPORT` | malformed UTF-8 is refused, not silently replaced with `?` |

**Third-party dependencies: none at runtime.** The shipped jar imports nothing outside `java.*` and
`javax.crypto.*`. The single declared dependency is `org.junit.jupiter:junit-jupiter:5.10.2`,
`<scope>test</scope>`, from Maven Central; this build runs with `mvn -o` against jars already in the
local repository, and the version is pinned in the POM rather than resolved by a range. Because no
third-party code is fetched or executed, "verify the download" and "never run code from a
world-writable location" reduce to: nothing here is loaded from a path the component controls, classes
load from the deployed artifact only, and the *data* paths it does touch are subjected to the rule-5
checks (owner, mode, symlink, ancestor) that make a world-writable location a refusal rather than a
silent risk.

## Residual risks — what this does *not* protect you from

1. **It runs as root on this machine, and root reads everything.** A `0000` key file is refused because
   the *mode* is wrong, but if the mode were merely odd root could still read it. These guards protect
   against unprivileged users, other service accounts and configuration mistakes. They cannot protect a
   key from a process that already owns the machine. (The suite prints this as a `NOTE` rather than
   asserting it, and the ownership check cannot be exercised negatively while `user.name` is root.)
2. **POSIX permissions are required.** On a filesystem without them (NTFS, FAT, some NFS/SMB mounts,
   containers with odd mounts) `unix:mode` is unsupported and the component refuses to proceed — that is
   a refusal, not a downgrade. There is no ACL or SELinux support; deploy a KMS if the key must never be
   readable by the app's own user.
3. **Random 96-bit nonces are unique with probability, not by construction.** After roughly 2³² records
   under one key a nonce collision becomes likely, which for GCM is catastrophic. The component cannot
   see how many records a key has produced across processes, so `KeyVault.rotate()` is the control and
   must be used routinely. If you will write more than ~10⁸ records under one key, rotate before you
   get there.
4. **`peekKeyVersion` reads attacker-chosen bytes.** Documented at the declaration; usable only as a
   routing hint; the tag is the authority. A caller that treats it as authorisation reintroduces the
   retargeting attack this format was designed to defeat. Because it is the one API that accepts a
   record-shaped string *without* authenticating anything, it is also the natural place to aim a
   resource-exhaustion or scan-cost attack, so its own work is bounded and measured: the length caps are
   applied to the string before any decode, the decode touches only the first 4 characters (3 header
   bytes) whatever the input size, a record too short to hold a header is refused on encoded length alone,
   and every failure returns the same `-1` with no exception. The test feeds it 8 MiB and 64 MiB-shaped
   junk and asserts the refusal costs nothing (`peek-oversized 0us` in the build log) as well as asserting
   the correct version for real records, so the bound is not achieved by always answering `-1`.
5. **PKCS#12's internal KDF is cheap.** A keystore protected by a human-chosen passphrase is a target.
   `MIN_PASSPHRASE_CHARS = 32` is a floor, not a recommendation: use `RandomPasswords`, or a random
   store password from a secret manager. The container is a *container*, not a lock.
6. **`PasswordKeySource` protects an offline guess with 310 000 PBKDF2 iterations** (~462 ms of CPU per
   attempt here). That is one guess's cost, not a rate limit. Attempt limiting and lockout belong to the
   caller — and a leaked container file is a *file*, so an attacker can run the guesses in parallel on
   their own hardware at whatever cost they can afford.
7. **No key use limits, no revocation, no crypto-shredding.** Rotation stops *new* reads through an old
   version by default, but old ciphertexts remain decryptable if you `enable` the old version — the
   caller decides, explicitly. There is no per-key record counter and no audit log. `close()` is likewise
   not a barrier: a `decrypt` already past its key load when `close()` runs is not waited for. It cannot
   succeed with erased material — the derivation/unwrap or the tag then fails, so it errors out — but do
   not treat `close()` as "no operation is in flight". Quiesce traffic first if you need that guarantee.
8. **Erasing memory is best-effort.** Zeroing the arrays this code owns is real; the JVM may still have
   copied key bytes into a `SecretKeySpec` it owns, into a page file, or into a heap dump it was asked
   to write. Swap, hibernation and core dumps are outside this component. Do not run this where an
   attacker can read the process's memory and call the result safe.
9. **Timing parity is a measured ratio, not a constant.** Seven tamper routes (edited version byte,
   context flag, nonce byte, first body byte, last tag byte, wrong context, wrong key) were measured at
   **148–205 µs** each over five consecutive runs, with a per-run spread of **1.05×–1.33×**, against the
   < 4× bound the test enforces and its 40 µs floor (it prints the table on every run, so the number is
   evidence in the build log, not a claim here). Note what the spread means: the tightest run was 1.05× and
   the loosest 1.33×, which is ordinary noise, but it is also a reminder that the bound constrains a
   *remote* timing signal and does not eliminate one — under load, GC or NUMA it will widen.
   A caller that logs one failure path and not another, or that returns "404" for "no such record" but
   "403" for "cannot decrypt", will leak far more than this code does.
10. **Plaintext is yours.** `decrypt` returns a `byte[]`/`String` this component cannot erase after you
    have used it, and `String` is not erasable in Java. If the plaintext outlives the call in a field, a
    cache, a log line or an exception message, that is where the leak will be.
11. **The IV/nonce is stored in the clear by design** (offset 3). Anyone who can read a record can see
    which key version wrote it and its nonce. That is metadata GCM needs; it is why the version is
    authenticated rather than trusted.
12. **The context is authenticated, not confidential.** It travels in the text form as plaintext and it is
    part of the AAD, which is exactly what makes it a routing key ("tenant:42"). Do not put anything in it
    that must stay secret — a name, an ID you consider private, a PII fragment. If you need the *reason* for
    a record to be private, encrypt it as plaintext and keep the context coarse.
13. **`KeyVault` loads a key per operation, so a cheap call can become an expensive one.** Every cache miss
    runs the source: a PBKDF2 miss costs ~462 ms of CPU, a keystore miss runs its own KDF, a file miss
    touches the disk. That is the design (a cache full of live keys is the thing to avoid), but it means an
    attacker who can make you miss can multiply your CPU by the miss rate. Put authentication and rate
    limiting in front of `decryptStringEncoded`, and do not hand it unauthenticated input. `MAX_VERSIONS`
    bounds how many distinct sources exist; it does not bound how often they are re-loaded.
14. **The environment-variable key source is the weakest one.** Environment variables leak through
    `/proc/<pid>/environ` (readable by the same uid, and by root), through crash handlers, through
    `System.getenv()` dumps in diagnostics, and through anything that shells out with an inherited
    environment. It exists because deployments already use it; a file with mode `0600`, a keystore, or a KMS
    is strictly better. Nothing here can erase an env var.
15. **`decrypt` attempts exactly one key version and does not fall back — that is a caller obligation, not
    just a library behaviour.** If your storage legitimately holds records under a version you have dropped,
    the record fails `KEY_UNAVAILABLE` and your code must not respond by "trying the others", because that
    loop is the oracle this design removes. Plan retention into rotation: keep old versions readable until
    the data under them is gone, then drop them deliberately.
16. **The build pins versions but verifies no checksums.** `pom.xml` pins `junit-jupiter:5.10.2` and the
    plugins used here, and the build runs offline against the local repository. There is no
    dependency-management BOM, no `maven-dependency-plugin` hash check and no signature verification, so
    "pinned" means "whatever the local repository holds under that version". Import the component into a
    build that enforces artifact hashes or vendor the JDK-only sources; the component itself pulls nothing
    at runtime, which is the only reason this is a low-severity gap.
17. **The JVM keeps key copies this component cannot reach, and this is measured, not assumed.** Probes on
    this JDK found that `PBKDF2KeyImpl` retains its own password and key arrays after `derive()` returns and
    that its `destroy()` throws instead of clearing them; `SecretKeySpec` holds a clone of the bytes handed
    to it. So "we erased the key" means "we erased every copy we own", and residual risk 8's caveats
    (heap dumps, swap, core dumps) apply to the copies we cannot name.

## Tests

`mvn -o test` — 72 tests, ~7 s. They are written as attacks, not as smoke tests.

| class | # | what it tries to do |
|---|---|---|
| `CipherBehaviourTest` | 27 | round-trips; nonce uniqueness across 500 records; every truncation length; bit flips in every byte; header relabelling and re-versioning through the public API; tag width (`theAuthenticationTagIsTheFullWidthTheFormatPromises`); one-record-one-spelling (`aRecordHasExactlyOneTextualSpelling`); timing parity across seven tamper routes; context validation; UTF-8 strictness; concurrency; `peekKeyVersion` correct on real records and `-1` on every junk shape **while staying free on an 8 MiB input**; an oversized raw record refused *before* it is copied (measured in µs, so the bound cannot be paid by the clone) |
| `KeyVaultTest` | 15 | a record opens only under the version it names; rotation is strictly increasing and stops old reads; the version cap bites exactly at `MAX_VERSIONS`; a mislabelled source is refused on both sides; the active version cannot be disabled; close is sticky; concurrent routing across 8 versions; `toString` names no secret **and takes the rotation lock around all three numbers it reports** (a structural guard — see the table below); **a record naming a version that was never issued is answered exactly like a tampered record** — same code, same detail, no factory ran, no cache entry appeared — and the stand-in key behind that answer is not a value anybody can guess (records encrypted under all-zero, all-one, sequential and ASCII keys are all refused); neither insertion path can push the version table past the ceiling; a source still cached under another version is not erased when its slot is replaced; an impossible version number is refused instead of remembered as disabled |
| `KeySourceTest` | 13 | the key parser accepts nothing it has to guess about (padded, wrong-alphabet, whitespace, control chars, oversize, non-canonical duplicates — with an assertion that the duplicate fixture is non-empty); **a key file with a trailing newline is refused in both spellings rather than trimmed**, and the refusal does not quote the key; env-var name refused *before* `getenv` is called; an unset variable vs a bad one, verified by a child JVM; key-file and keystore round-trips; wrong passphrase/store-password → `AUTHENTICATION_FAILED`; a container that lowers the KDF cost is refused **and refused cheaply**; the random-password alphabet is the size its documentation counts it as; the generic message and code survive Java serialization while `technicalDetail` does not |
| `KeyFilePermissionTest` | 13 | 11 different loose modes refused while `0400` is accepted; set-id bits; symlink on read and in every ancestor; non-regular files; shared parents (`0777`, `0775`) refused while sticky `1777` is accepted; the culprit directory named in the detail; write refuses to overwrite, to mkdir -p, and to write into a shared directory; **a file somebody else claimed first never receives our key** (his size, his mode, no key bytes found in it); **the write path contains no pre-check at all**, read out of the source with comments stripped; inode/owner/mode re-check after a read through a shared parent; mode drift after creation; oversized key file refused before reading; and `thePrivacyCheckIsRealAndNotAnAlwaysTrueHelper` |
| `NoSecretLeakTest` | 4 | every failure path rendered through eight surfaces and searched for key/plaintext/passphrase; refusals never confirm existence (and the log details *do* distinguish failure kinds); the three authentication routes are one tag check in code, message *and* cost; no internals ride out on a stack trace or cause chain; no key ever derives from a constant |

## What the final adversarial pass found, and what changed

The closing pass was run as a reviewer who has to report findings rather than approve. It reported eleven
defects in the code; all eleven are fixed, and each fix is pinned by a test *and* by a mutation that the
test kills, so the claim is checkable rather than assertive. Where a fix cannot be pinned
*behaviourally* — because the failure it prevents needs a window nobody can hit on command — the pin is a
structural guard on the source, and that row says so rather than implying a behavioural test exists.

| found | why a reviewer could report it | fix | pinned by |
|---|---|---|---|
| A record naming a version above every version issued was refused *by name* | A distinct, cheaper answer on an attacker-chosen path, and the size of the key estate written to the log — a rule-6 violation by a guard meant to enforce rule 1 | `sourceFor` answers with a per-call random stand-in key; the factory never runs | `aRecordNamingAVersionThatWasNeverIssuedIsAnsweredLikeATamperedRecord`, `theStandInForKeyItWillNotProvisionIsNotAPredictableOne` · mutants `vault-provisions-any-version`, `vault-size-clause-dropped`, `addreadable-ceiling-dropped`, `decoy-key-not-random` |
| `peekKeyVersion` decoded the whole attacker string to read 3 bytes | Unbounded work on the one unauthenticated string API — a scan-cost and memory attack surface | Caps applied to the string first; only the first 4 characters are decoded; short records refused on encoded length | `peekingTheKeyVersionIsCorrectOnRealRecordsAndBoundedOnJunk` · `peek-upper-bound-off`, `peek-lower-bound-off` |
| `structural()` cloned the record before checking its length | The hostile length decided the allocation, which inverts "bound before allocating" | Length bound moved ahead of the clone | `anOversizedRecordIsRefusedWithoutBeingCopiedFirst` (measured, not boolean) · `structural-clones-before-bounding` |
| The PBKDF2 spec was never cleared, while the javadoc claimed the passphrase was erased | A documented control that did not exist is worse than an absent one | `clearPassword()` in a `finally`, with the JDK's measured behaviour written down | `kdf-spec-clearpassword-dropped` is a *survivor by construction* — see the gaps section; the javadoc claim is now the probe's, not the author's |
| The shared-parent re-check compared only the parent's mode | It could not detect the swap its own comment described | `st_dev`/`st_ino` identity plus mode and owner re-checked against a pre-read snapshot | `inode-recheck-dropped` is a stated survivor (no deterministic way to race the read here) |
| `KeyVault.toString()` read rotation state outside the lock | A torn view of `sources` vs `highestIssued` — an operator-facing inconsistency in the one place that describes the estate, during the incident where somebody is working out which key wrote a record | All three numbers snapshotted under `rotationLock` | `theEstateDescriptionSnapshotsEveryNumberUnderTheRotationLock` · `tostring-drops-the-rotation-lock`. **Structural, not behavioural**: a torn render needs a read to land inside a rotation's window, so a test that bet on that timing would either flake or pass the broken code — the guard reads the method instead, and the mutant is what proves it can fail |
| Replacing a version's slot released the displaced source unconditionally | With one `KeySource` installed under two versions, a rotation **erased a live key** with no error | Release only when no other slot still references it | `aSourceStillCachedUnderAnotherVersionIsNotErasedWhenItsSlotIsReplaced` · `shared-source-released-anyway` |
| Two javadocs described input handling the code does not implement (key text whitespace/newline tolerance; the random-alphabet's size and quoting safety) | A deployer who trusts either comment corrupts a key file or logs an unquoted secret | Comments rewritten to the code; `ALPHABET_SIZE` derived instead of restated | `aKeyFileWithATrailingNewlineIsRefusedRatherThanTrimmed`, `theRandomSecretAlphabetIsWhatItsDocumentationCountsItAs` |
| `disable(0)` / `disable(999)` were recorded as disabled versions | State describing something that can never exist, and an inconsistency a future reader must guess about | Range refused at the API | `aVersionThatCannotExistIsRefusedRatherThanRememberedAsDisabled` · `disable-remembers-impossible-versions` |
| `CryptoException.code` was `transient` | Across a JVM boundary the exception had a message and *no kind*, pushing callers to classify from text — and the message is the part that must stay generic | `code` serialises; `technicalDetail` stays transient | `theGenericMessageSurvivesSerialization` · `exception-code-transient-again` |
| A test claimed to force the create race but asserted an outcome `CREATE_NEW` decides either way | An unfalsifiable test is a finding against the suite, which is the thing the other claims rest on | Replaced by two fixed-order tests plus a comment-stripped source guard, and made mutation-testable so the guard itself is proven to fire | `aKeyFileClaimedBySomebodyElseIsNeverWrittenInto`, `theWritePathAsksTheFilesystemRatherThanCheckingFirst` · `target-existence-pre-check` |

The pass also raised twelve design weaknesses that are *not* defects — per-key nonce budget, per-operation
key-load CPU amplification, the env-var source's leak surface, context confidentiality, the no-fallback
caller obligation, PKCS#12's cheap KDF and so on. Those are the numbered residual risks above rather than
silent acceptances: they are properties of the design a caller has to plan around, and a reviewer's job is
to make sure they are written where a caller will read them.

Survivors, stated rather than hidden:

- `no-erase-of-working-copy` is a surviving mutation *by construction*. Deleting the `Arrays.fill` that
  zeroes the working key copy changes nothing an in-process test can observe — `SecretKeySpec` keeps its
  own copy regardless, and reading another object's heap is not something a unit test can do. The
  assertion that would kill it is a heap inspection, not a test. See residual risks 8 and 17.
- `kdf-spec-clearpassword-dropped` and `inode-recheck-dropped` are survivors for the same reason: one
  removes an erasure whose only observable effect is the absence of bytes from a heap the test cannot
  inspect, the other closes a swap window that needs a second privileged process racing a read, which
  cannot be arranged deterministically here. Both are stated rather than worked around, because inventing
  a passing assertion for an unobservable property is how a green suite comes to mean nothing.
- Mutation testing here was a hand-rolled harness (`/tmp/mut/run_mutations.py`): 40 source mutations,
  each anchored to an exact unique site, run against a frozen copy of the tests, with a pre-flight that
  aborts unless the unmutated tree compiles and the baseline suite is green. Result: **37 killed, 3
  survived — the three named just above, all of them by construction — and 0 problems.** Compile failures,
  timeouts, crashes and harness errors are recorded as *problems*, never as kills, and the runner's own
  discovery floor (`found < 70` → harness failure) stops a mutant that silently stops tests from running
  from being scored as a kill. Two of the mutants exist to attack the *tests*: they change no observable
  behaviour and are only caught by reading the source (the two `(source guard)` rows in the run log), which
  is why both guards read the source through `-Dsecure.data.crypto.src.main` — pointed at the mutant's tree
  rather than the pristine one, so the guard's verdict is evidence rather than decoration.
