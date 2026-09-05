# vault — symmetric encryption for application data

Encrypts and decrypts sensitive application data with **AES-256-GCM** using only the Java
standard cryptography APIs (`javax.crypto`, `java.security.KeyStore`). No third-party
dependencies.

Java 17+ (`javac`/`java` on `PATH`).

## Build and run

```sh
mkdir -p build
javac -Xlint:all -Werror -d build src/vault/*.java
javac -Xlint:all -Werror -cp build -d build src/ReadmeSnippets.java

java -cp build vault.Demo demo-work         # narrated end-to-end walkthrough
java -cp build vault.SelfTest selftest-work # 79 executable checks, exits non-zero on failure
java -cp build ReadmeSnippets readme-work   # compiles/runs the examples below against the real API
java -cp build vault.VaultCli help          # command-line tool
```

`SelfTest` is a plain `main` because this project has no test framework wired in. It covers
round-trips, tamper/wrong-key rejection, key custody, KDF cost enforcement, file streaming,
rotation, and secret hygiene.

## Library use

```java
char[] storePassword = ...;                      // from env, secret file, or prompt

try (KeyVault keys = KeyVault.open(Path.of("app.p12"), storePassword);
     DataVault vault = new DataVault(keys, "app-data")) {

    vault.ensureDefaultKey();                    // create the key on first run

    Envelope sealed = vault.seal(secret.getBytes(UTF_8));
    Files.write(Path.of("secret.bin"), sealed.toBytes());

    try (DataVault.Opened opened = vault.open(Envelope.fromBytes(Files.readAllBytes(Path.of("secret.bin"))))) {
        String clear = new String(opened.data(), UTF_8);
    }                                        // Opened.close() zeroes the plaintext buffer
}
```

Files are handled without buffering the whole payload:

```java
vault.sealFileTo(Path.of("config.yaml"), Path.of("config.yaml.sealed"));
vault.openFile(Path.of("config.yaml.sealed"), Path.of("config.yaml.clear"));
```

Passphrase-derived keys, when no keystore is available:

```java
try (DataVault vault = new DataVault(keys, () -> readPassphraseFromSomewhere())) {
    Envelope sealed = vault.sealWithPassphrase(payload);   // salt + iterations go in the header
    vault.open(sealed);                                    // key rebuilt, never stored
}
```

## Where the key lives

Key custody is the part worth reviewing, so it is isolated in `KeyVault`.

**Keys are held in a PKCS#12 keystore file.** The keystore password is the single secret an
operator or secret manager supplies. Details that matter in practice:

- **File permissions are tightened before the first key is written.** The store is created and
  rewritten `0600`. A key any local user can read is not a secret.
- **The store is rewritten atomically** through a `.part` staging file, so a crash mid-write
  leaves the previous working keystore intact rather than a truncated one.
- **Integrity is verified on load.** PKCS#12 checks its MAC, so an edited or swapped keystore is
  rejected instead of being used quietly. A wrong password surfaces as a load failure.
- **Overwriting an existing alias is refused.** Replacing a key in place strands every payload
  sealed under it; rotation is an explicit, separate operation.
- **Aliases are validated** against `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, so a key name cannot
  become a path.
- **No key material is ever logged.** `describe()` and `Envelope.toString()` expose aliases and
  lengths only; `SelfTest` asserts that a key's bytes never appear in the serialized keystore
  or in any exception message.

**Secrets never come from a command-line argument.** `Passwords` reads, in order: an environment
variable (`VAULT_KEYSTORE_PASSWORD`), a mounted secret file (`VAULT_KEYSTORE_PASSWORD_FILE`),
then a masked console prompt. Arguments are world-readable through `/proc`, land in shell
history, and end up in CI logs. The tradeoff is documented in that class: environment variables
are readable via `/proc/PID/environ` to the same user, so nothing here is perfectly clean.

**Keys are scoped to one operation.** `DataVault` resolves a key, uses it, and drops it rather
than caching it for the process lifetime. This is the honest mitigation for Java's inability to
wipe key material: `KeyVault.zero()` clears the array it is handed, but `SecretKeySpec` keeps a
private copy and returns a fresh clone from `getEncoded()`, so the key object survives — and no
Java API can scrub copies the JVM already duplicated or pinned. `SelfTest` asserts this
behaviour rather than pretending otherwise. Short-lived sessions plus avoiding heap dumps and
`-XX:+HeapDumpOnOutOfMemoryError` on key-holding processes is the practical control.

**For production**, put the keystore itself (or the wrapped key) in a dedicated store rather
than on the app's disk: an HSM or KMS via PKCS#11/JCA provider, a cloud KMS envelope-encryption
scheme, or at minimum a secret manager that mounts `VAULT_KEYSTORE_PASSWORD_FILE`. The
`KeySource` seam and `KeyVault` are the places to add a provider; `AesGcmCipher` does not
change.

## Passphrase-derived keys

Where only a passphrase exists, `PBKDF2WithHmacSHA256` stretches it at **310,000 iterations**
over a random 128-bit salt. The salt and iteration count are stored in the envelope header —
which is authenticated — so the key can be rebuilt without ever being stored, and neither cost
parameter can be quietly lowered to make an old payload readable. Derivation below 100,000
iterations is refused outright. If hardware-backed key storage is available, prefer it:
passphrase stretching is the fallback, not the ideal.

## Envelope format

`Envelope` serialises the metadata needed to reopen a payload, and GCM authenticates all of it
as additional authenticated data. Nothing in the header can be edited without opening failing.

```
magic   4 B  "AVL1"
version 1 B
source  1 B  KEYSTORE or PASSPHRASE
alias   1+N  key name (length-prefixed, max 64 B)
salt   1+N   PBKDF2 salt (16 B for passphrase keys, absent otherwise)
iter    4 B  PBKDF2 iterations (0 for keystore keys)
iv     12 B  GCM nonce
body    ...  ciphertext + 16 B GCM tag
```

Overhead is 32 B of header plus the 16 B tag for a keystore key.

Design points:

- **AES-GCM, not CBC.** GCM is authenticated. CBC without a MAC is malleable and invites padding
  oracles; `AES/CBC/PKCS5Padding` was not an option worth taking.
- **A fresh 12-byte nonce per seal**, from `SecureRandom`. Reusing a GCM nonce under the same key
  is catastrophic — it breaks both confidentiality and the tag — so the nonce is generated at
  seal time and never accepted from a caller.
- **The key comes from the authenticated header**, not from the arguments at open time. A payload
  cannot be re-interpreted under a different key after the fact. `SelfTest` covers the
  specific attack of rewriting the header's alias to point at another *valid, existing* key: the
  tag rejects it.
- **Version and provenance are in the authenticated prefix**, so a future format change cannot be
  smuggled in as a downgrade.

## File handling

- `sealFileTo` streams in 64 KiB chunks; the payload is never fully in memory.
- `openToFile` decrypts into a staging file that is promoted to the destination **only after the
  tag verifies**, so a tampered payload never leaves unauthenticated plaintext at the path the
  caller asked for. The staging file is deleted on failure.
- Sealed files and recovered plaintext are created owner-only. Recovered plaintext in particular
  is not left group/world-readable the way a default-umask create would leave it.
- `rekeyFile` re-seals under a new alias and **leaves the source untouched**, so an interrupted
  rotation loses nothing. Rotate by re-sealing first and deleting the old key last; the demo's
  section 5 shows what happens if you get that order wrong.

## CLI

```sh
export VAULT_KEYSTORE_PASSWORD='...'      # or VAULT_KEYSTORE_PASSWORD_FILE=/run/secrets/ks

java -cp build vault.VaultCli init    --keystore app.p12 --alias app-data
echo 'db.password=...' | java -cp build vault.VaultCli seal --keystore app.p12 --out s.bin
java -cp build vault.VaultCli info    --in s.bin            # provenance, no decryption
java -cp build vault.VaultCli open    --keystore app.p12 --in s.bin --out clear.bin
java -cp build vault.VaultCli keygen  --keystore app.p12 --alias app-data-2026
java -cp build vault.VaultCli rekey   --keystore app.p12 --in s.bin --out s2.bin --alias app-data-2026
java -cp build vault.VaultCli keys    --keystore app.p12
```

`seal` without `--out` prints base64 to stdout; `open` without `--in` reads base64 from stdin,
which is the shape you want for storing a sealed credential in a config file or env var.

`seal`/`open`/`keys` use `KeyVault.openExisting` and **refuse to invent a keystore**: a mistyped
`--keystore` produces "no keystore at …" instead of silently generating an empty store and
reporting a confusing missing-key error. Only `init`/`keygen` create.

## Known limits

- **Secrets are `char[]`, not truly erasable.** See the key-scoping note above; this is a JVM
  limitation, not something this code works around.
- **The PKCS#12 password protects the keystore, and its strength is the weakest link.** A weak
  store password makes the file permission work beside the point.
- **No key versioning policy or rotation schedule** — `rekey`/`rekeyFile` are the mechanisms, and
  deciding when to rotate stays an operational call. Payloads sealed under a deleted alias are
  unrecoverable by design.
- **GCM's nonce ceiling** is per-key: at ~4 billion seals under one key, rotate. The nonce is
  random, not a counter, so this is a birthday-bound limit rather than a hard counter.
- **No padding or format-preserving encryption**; ciphertext is ~48 B larger than the plaintext.
- **Permissions are POSIX.** On Windows/ACL filesystems the chmod calls are skipped silently and
  access control must come from the platform.
- `info` reads only the header, so it reports lengths without holding the whole file — but it
  does not verify the tag, so its output describes what a file *claims* to be.
