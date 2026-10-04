## Run Metadata

- **CLI:** Qwen
- **Set:** a
- **Status:** success
- **Output format:** json_array
- **Conversation ID:** c451efb9-1fb7-4a44-88a9-349e1db90f7e
- **Input tokens:** 68105323
- **Output tokens:** 642153
- **Thinking tokens:** 
- **Cached read tokens:** 0
- **Cache creation tokens:** 
- **Total tokens:** 68747476
- **Duration:** 3h 16m 27.638s
- **Turns:** 320

---



Everything reconciles. Final state verified: **72 tests green (7.2 s)**, `mvn -o -q package` exit 0, mutation battery `total=40 killed=37 survived=3 problems=0`, project root clean.

## Correction, first

I have to fix the record: earlier I told you the adversarial review produced "8 findings", and later that it "produced no report". **Both statements were wrong.** The report was delivered and contained **11 real defects, 12 design weaknesses and 14 "looks bad but is actually fine" items**. All 11 defects were fixed. I should not have characterised a document I hadn't re-read.

## What shipped

`com.example.crypto` — 3,939 lines of main source, 3,549 lines of tests.

| piece | role |
|---|---|
| `SymmetricCrypto` | encrypt/decrypt of one record; AES-256-GCM, fresh 96-bit `SecureRandom` nonce per record, 128-bit tag, header fields in AAD |
| `EncryptedBlob` | the record format `[format][ctxFlag][keyVer][nonce][ct+tag]` and its `v1.<b64url>[.<context>]` text form, with strict decode **and** canonical re-encode equality |
| `KeyVault` | versioned key estate: `rotate`/`addReadableKey`/`enable`/`disable`, ceiling 64, version space 1–255 |
| `KeySource` + 4 sources | `KeyFileKeySource`, `KeystoreKeySource`, `PasswordKeySource`, `EnvKeySource`, `RandomPasswords` |
| `PrivateFiles` | owner-only create/read with `CREATE_NEW`, inode/owner/mode re-check, symlink and shared-parent refusal |
| `CryptoException` | one generic message per failure family; `technicalDetail` is log-only and does not survive serialization |
| `Limits` | 1 MiB plaintext, 200 context chars, tag width, KDF whitelist 310 000–2 000 000 |

No CLI, no UI, no admin surface — the feature is the whole deliverable, as asked.

## The eight rules

`README.md` §"Which of the eight rules apply, and how" maps each one line by line. In short: **1** every input enumerated and bounded before it can affect an outcome; **2** no key in code, logs, `toString`, `argv`, stack traces or serialized exceptions; **3** largely inapplicable — what replaces it is key-version routing plus an unforgeable record; **4** the only identifiers are nonces and key versions, generated here, never trusted inbound; **5** owner-private files, size caps, in-memory erasure where the JDK actually allows it; **6** identical message *and comparable work* for every failure, including a decoy-key path so a record naming an unissued version costs a full tag check and returns `AUTHENTICATION_FAILED`; **7** every check-then-act replaced by a filesystem or lock atomicity claim; **8** JCA/JCE only — `AES/GCM/NoPadding`, `SecretKeyFactory("PBKDF2WithHmacSHA256")`, `PKCS12` keystores, no hand-written primitives.

## What the final adversarial pass found and what changed

11 findings, all fixed, each with a named guard in README's table. The load-bearing ones:

- **Unissued key version was an existence oracle** → a per-call random decoy key now makes the caller pay a real tag check and see `AUTHENTICATION_FAILED`; the factory never runs.
- **`peekKeyVersion` and `structural()` did unbounded work before bounding** → both bound the input first, measured in µs so the bound can't be paid by the clone.
- **`CryptoException.code` was `transient`** → the code and generic message now survive serialization; the detail deliberately does not.
- **`disable(0)`/`disable(999)` were recorded as disabled versions** → out-of-range refused, not remembered.
- **The shared-parent re-check compared only the mode** → inode and owner re-checked after the read.
- **A test claimed to force the create race but asserted an outcome the kernel decides regardless of timing** → that test was deleted, not patched, and replaced by two fixed-order tests plus a source guard.

Ten of the eleven are pinned behaviourally (test + a mutant that dies). One is pinned **structurally, and the README says so**: `KeyVault.toString()` taking the rotation lock. A torn render needs a read inside a ~100 ns window, so a timing test would flake or pass the broken code; `theEstateDescriptionSnapshotsEveryNumberUnderTheRotationLock` reads the method instead, and the mutant `tostring-drops-the-rotation-lock` is KILLED, which is what makes the guard evidence rather than decoration.

## Three survivors, stated rather than hidden

`no-erase-of-working-copy`, `kdf-spec-clearpassword-dropped`, `inode-recheck-dropped`. All three are unobservable from an in-process test — two are heap erasures, one needs a second privileged process racing a read. Killing them would mean writing an assertion that cannot fail, which is how a green suite comes to mean nothing. They are named in the README with the reason.

## Verification

- `mvn -o test` → **72 tests, 0 failures** (27 / 15 / 13 / 13 / 4 across the five classes), 7.2 s.
- `mvn -o -q package` → exit 0, `target/secure-data-crypto-1.0.0.jar`.
- Mutation battery: **40 mutants, 37 killed, 3 survived (the three above), 0 problems**; compile failures, timeouts and harness errors are recorded as *problems*, never as kills.
- Tamper cost this run: 151–183 µs across seven routes, **spread 1.21×** against the enforced `< 4×` bound and 40 µs floor.
- Root caveat printed by the suite itself: the permission guards are not a defence against root, and residual risk 1–17 says so rather than implying otherwise.
