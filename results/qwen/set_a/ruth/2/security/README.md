# SecureDataVault

Authenticated symmetric encryption for sensitive application data, written
against the Java standard cryptography APIs only (`javax.crypto`,
`java.security`, `java.nio.file`). No third-party dependencies, no build tool.

The library encrypts a value under an AES key and returns a small text
*envelope* you can store in a database column, a file, or a message queue.
Decrypting returns the original bytes, and any tampering with the envelope -
or an attempt to read it with the wrong key or in the wrong place - is refused
rather than answered with garbage.

The focus of the implementation is the part that usually goes wrong: where the
key comes from, where it lives, and how it goes away.

## Contents

| File | What it is |
| --- | --- |
| `SecureDataVault.java` | The library and its command-line front end. ~1500 lines, one public class, default package. |
| `SelfTest.java` | Executable verification: 246 assertions, run as `java SelfTest`. Not a unit-test framework - plain `main`, because there is no build tool assumed here. |

## Requirements

* JDK 17 or newer (verified on OpenJDK 17.0.20.1). Uses `KeyStore`, `Cipher`,
  `SecretKeyFactory`, `PBKDF2WithHmacSHA256`, AES/GCM - all in the JDK.
* Unlimited-strength policy is *not* required: the code checks
  `Cipher.getMaxAllowedKeyLength("AES")` and refuses to ask for a key size the
  JVM will not allow. 256-bit keys work on any modern JDK; on a restricted one,
  128-bit still does.

## Compile and run

```sh
javac SecureDataVault.java
java SecureDataVault              # prints usage, exits 1
java SecureDataVault --help       # same, exits 0
```

Compile both files together to get the test harness:

```sh
javac -Xlint:all -Werror SecureDataVault.java SelfTest.java
java SelfTest                     # "passed 246, failed 0", exit 0
```

Class-output directory is up to you; if you compile with `-d /tmp/cls`, run with
`java -cp /tmp/cls SecureDataVault`.

## Five-minute walkthrough

Passwords and keys are never command-line arguments (see
[Key handling](#key-handling)), so the examples pass them through the
environment. In production that value is injected by the platform - not written
in a shell script.

```sh
export VAULT_PW='the-keystore-password'

# 1. Create a key. Writes a PKCS12 keystore, mode 0600.
java SecureDataVault keygen --keystore vault.p12 --alias appkey --storepass-env VAULT_PW
```
```
generated a 256-bit AES key
  keystore   vault.p12 (type PKCS12, alias appkey)
  key id     a46b32b8bfbe1ec5   (non-secret fingerprint, safe to log)
```

```sh
# 2. Encrypt. --context binds the ciphertext to the record it belongs to.
java SecureDataVault encrypt --keystore vault.p12 --storepass-env VAULT_PW \
  --text 'ssn=123-45-6789' --context customer-42 --out ssn.enc
cat ssn.enc
```
```
v1:a46b32b8bfbe1ec5:zb8Ubnk8v8UIN4WH48P0ZrysChBKbM8QuIKvzKG+bcFauu6J76IwaARgkg==
```

```sh
# 3. Decrypt. The same context is required.
java SecureDataVault decrypt --keystore vault.p12 --storepass-env VAULT_PW \
  --in ssn.enc --context customer-42 --out -
```
```
ssn=123-45-6789
```

```sh
# 4. Read the same envelope as a different record. Refused.
java SecureDataVault decrypt --keystore vault.p12 --storepass-env VAULT_PW \
  --in ssn.enc --context customer-43 --out -
```
```
error: authentication tag check failed: the envelope was tampered with, or the
supplied context 'customer-43' is not the one it was encrypted with, or the key
is wrong. Nothing was decrypted.
```

`--in` defaults to stdin and `--out` to stdout (`-` means the same explicitly),
so the tool composes with pipes:

```sh
printf 'secret-from-stdin' | java SecureDataVault encrypt --keystore vault.p12 \
  --storepass-env VAULT_PW 2>/dev/null > s.enc
java SecureDataVault decrypt --keystore vault.p12 --storepass-env VAULT_PW \
  --in s.enc --out -
```

Progress notes ("encrypted 15 bytes with key id ...") go to **stderr**; the
**stdout stream carries only data**, so piping never mixes the two.

## Commands

| Command | Does |
| --- | --- |
| `keygen` | Generate an AES key, store it in a keystore, print its fingerprint. Refuses to overwrite an existing alias without `--replace-alias`. |
| `saltgen` | Write a PBKDF2 salt/cost record for passphrase-derived keys. |
| `encrypt` | Read plaintext, write one envelope. |
| `decrypt` | Read an envelope, write the original bytes. |
| `rotate` | Re-encrypt a file of envelopes under a new key. |
| `keyinfo` | Print a key's source and fingerprint. Never the key. |

Exit codes: `0` success, `1` invoked with no command, `2` a handled error
(bad option, wrong key, broken integrity), `3` unexpected failure.

## Key sources

Pick exactly one; giving two is an error rather than a silent precedence rule.

### 1. Keystore (the default choice)

The key is a `SecretKeyEntry` in a password-protected `PKCS12` (or `JCEKS`)
keystore. The password protects the key material at rest - PKCS12 also carries
an integrity check, so a tampered keystore or a wrong password fails loudly on
open.

```
--keystore PATH            keystore file
--keystore-type TYPE       PKCS12 (default) or JCEKS; inferred from .p12/.jceks
--alias NAME               key alias, default "appkey"
--storepass-env VAR        password from an environment variable
--storepass-file PATH      password from a file
--storepass-prompt         typed at the terminal (echo off)
```

`KeyStore` rejects `JKS` for symmetric keys; the code rejects it too, with a
better message than the stack trace.

### 2. Passphrase + PBKDF2 (no keystore to distribute)

A key is *derived*, not stored: `PBKDF2WithHmacSHA256` with 600 000 iterations
(100 000 floor, enforced - a record cannot quietly downgrade the work factor)
over a 32-byte random salt.

```
--kdf PATH                 the salt/cost record
--pass-env VAR / --pass-file PATH / --pass-prompt
```

```sh
java SecureDataVault saltgen --kdf salt.txt --iterations 600000
java SecureDataVault encrypt --kdf salt.txt --pass-prompt --text 'api-key=sk-1' --out k.enc
```

The record is not a secret - it is a salt plus a cost parameter:

```
kdf:v1:pbkdf2-hmac-sha256:600000:Nc+XU5STVWDqVDGaQAgVgxenplb...
```

This is convenient and weaker than option 1 in one specific way: the security
of the derived key is exactly the entropy of the passphrase. PBKDF2 makes
guessing expensive, it does not make a guessable passphrase strong. Fine for a
human opening their own vault; a service should use a keystore.

### 3. Environment variable (dev and CI only)

A Base64 AES key in a variable. Visible to anything running as the same user
through the process table, so it is a bootstrap mechanism, not a production
keystore.

```
--key-env VAR
```

```sh
export APP_KEY_B64=$(java SecureDataVault keygen --print-base64)
```

The decoder is strict (`Base64.getDecoder()`, not the MIME one, which silently
drops invalid characters and would hand you a short key), and the result is
checked to be exactly 16, 24, or 32 bytes before it reaches `SecretKeySpec` -
which, on its own, accepts any length without complaint.

## Key handling

This is what "pay attention to how the key is obtained, stored, and managed"
means in practice here:

* **Never in argv.** `--storepass` and `--key` do not exist, and asking for
  them is refused with an explanation - argv is world-readable through the
  process table and stays in shell history.
* **Generated where it is used.** `KeyGenerator.getInstance("AES")` seeded from
  a shared `SecureRandom`. No passphrase-derived defaults, no hardcoded keys.
  The only output that ever contains a key is `keygen --print-base64`, whose
  entire purpose is to seed a dev/CI environment variable; every other command
  reports the non-secret fingerprint.
* **Owned by a handle.** `KeyHandle` copies the key bytes in, never exposes an
  array, hands a `SecretKeySpec` to callers only through `use(KeyAction)`, and
  zeroes its own copy on `close()`. `toString()` prints the fingerprint only.
* **Single use where it matters.** `KeyStoreKeySource` and
  `PassphraseKeySource` wipe their in-memory secret after the first `load()`, so
  a second load fails loudly instead of silently deriving from zeros.
* **Non-secret identity.** Each envelope carries the key's id: the first 8
  bytes of `SHA-256(key)`, lowercase hex. It is a fingerprint, not a digest of
  the whole key, and it is compared with the constant-time
  `MessageDigest.isEqual`. A mismatch produces an actionable error naming both
  ids instead of a corrupt-looking plaintext.
* **Written carefully.** A keystore is written to a temporary file and moved
  with `ATOMIC_MOVE`, at mode `0600`. A key file that is group- or
  other-readable produces a warning; `--force-insecure-fileperms` silences it.
* **Rotation is a first-class command**, not a manual dump-and-reload.

The honest limit: a JVM cannot guarantee that every copy of a key is erased.
`SecretKeySpec` keeps an internal copy and its `destroy()` is a no-op that
throws. Zeroing here removes the copies this class made, which is the ceiling
for pure Java. A long-lived service should hold the key in an HSM or KMS and
never export it at all.

## Cryptographic design

**AES/GCM/NoPadding** - an AEAD, so confidentiality and integrity come from one
primitive and a modified ciphertext is *rejected*, not answered with garbage.
No padding means no padding-oracle surface.

* **IV**: 12 fresh bytes from `SecureRandom` per call, never supplied or reused
  by callers. GCM catastrophically loses security on IV reuse under one key, so
  the API does not allow it.
* **Tag**: 128 bits.
* **Key size**: 256-bit default, 128/192/256 accepted, capped by what the JVM
  reports as allowed.
* **Context (`--context`)**: an optional string authenticated with the
  ciphertext. Encrypt a customer's SSN with `--context customer-42` and the
  resulting envelope cannot be decrypted as if it belonged to `customer-43`.
  This closes a real attack on per-field encryption: copying a privileged
  user's ciphertext over someone else's row. Must be printable ASCII, no
  spaces, no `|`.

### Envelope format

```
v1 : <16 lowercase hex key id> : base64( IV(12) || ciphertext || tag(16) )
```

and the bytes authenticated alongside the ciphertext (AAD) are

```
aesgcm-v1 | <key id>            (no context)
aesgcm-v1 | <key id> | <context>
```

The version prefix and key id have fixed shapes, so the `|`-delimited AAD
fields cannot be reinterpreted - no AAD-shifting ambiguity. Because the version
tag and key id are *inside* the AAD, an attacker who rewrites the envelope
prefix to downgrade the format, or swaps the key id to redirect the
decryption, breaks the tag instead of being quietly parsed.

`Envelope.parse` validates the prefix, the key-id charset and length, the Base64
charset, and a minimum body of 28 bytes (IV + tag) before any crypto runs.

## Key rotation

```sh
java SecureDataVault keygen --keystore next.p12 --alias appkey --storepass-env NEXT_PW

java SecureDataVault rotate --in batch.txt --out rotated.txt \
  --keystore vault.p12  --storepass-env VAULT_PW \
  --new-keystore next.p12 --new-storepass-env NEXT_PW
```
```
rotating from key id a46b32b8bfbe1ec5 to key id 8dac598c4ebca652
re-encrypted 1 envelope(s) into rotated.txt
```

Destination-key options are the same names with a `new-` prefix
(`--new-alias`, `--new-kdf`, `--new-pass-env`, `--new-key-env`, ...).

`batch.txt` is one envelope per line, or `<context><TAB><envelope>` when values
were each encrypted under their own context - the usual case for per-row
encryption. The output preserves whichever form the input used, so a file can be
rotated again later.

Two properties worth knowing:

* **All or nothing.** Every line is decrypted before anything is written. One
  unreadable line fails the whole run with `line N of <path> could not be read
  with key id ...` and leaves *no output file*, rather than producing a
  half-rotated batch.
* **The old key keeps working until you retire it.** `rotate` moves the data; it
  cannot retract the old key. Until you delete or revoke that keystore, both
  keys decrypt their own envelopes - which is what you want during a cutover,
  and what you must remember to clean up afterwards. Envelopes do not change
  which key id they name, so an old envelope keeps naming the old key even after
  the batch was rotated onto the new one.

## Using it as a library

`SecureDataVault` is in the default package so that `javac` / `java` work with
no classpath gymnastics. The cost: you cannot `import` from the unnamed package,
so a caller names the nested types as `SecureDataVault.X`.

```java
SecureDataVault.KeySource source = new SecureDataVault.KeyStoreKeySource(
        Path.of("vault.p12"), "PKCS12", "appkey", keystorePassword);

try (SecureDataVault.KeyHandle key = source.load()) {
    String envelope = SecureDataVault.encrypt(ssn, key, "customer-42");
    String plain = SecureDataVault.decrypt(envelope, key, "customer-42");

    // Binary payloads, no character-set interpretation:
    byte[] sealed = SecureDataVault.decryptBytes(
            SecureDataVault.encryptBytes(raw, key, null), key, null);
}

// Rotation, keeping the plaintext inside the call that does the swap:
String moved = SecureDataVault.reencrypt(envelope, currentKey, nextKey, "customer-42");
```

This compiles as written under `javac -Xlint:all -Werror`. `load()` throws
`VaultException` (and `IOException` for the keystore source), so declare or
handle them; both are `GeneralSecurityException`s.

Public surface: `encrypt`, `encryptBytes`, `decrypt`, `decryptBytes`,
`reencrypt`, `generateKey`, `generateRawKey`, `storeGeneratedKey`,
`newKdfParams`, `maxAllowedKeyBits`, and the types `KeyHandle`, `KeyAction`,
`KeySource`, `KeyStoreKeySource`, `PassphraseKeySource`, `EnvironmentKeySource`,
`KdfParams`, `Envelope`, `KeyGeneration`, `VaultException`.

## Threat model

**Defends against**

* An attacker with the ciphertext only: cannot read it, cannot forge a
  valid one, cannot change a byte without detection, cannot move a value
  between records when contexts are used, cannot redirect it by rewriting the
  key id.
* Someone with the keystore file but not the password.
* Someone who edits an envelope, or its version prefix, in the store.
* An operator who would otherwise paste a password into `ps` output.
* A truncated or junked key that a lenient API would have accepted.

**Does not defend against**

* Anyone with the key *and* the ciphertext. There is no forward secrecy and no
  hidden-to-hiddencrypto; a compromised process can decrypt everything.
* A stolen keystore plus its password. Store the password separately from the
  file (env var from a secret manager, not next to it).
* A weak passphrase in mode 2 - PBKDF2 slows guessing, it does not add entropy.
* Anything after decryption: your logs, your heap dumps, your database dumps
  once values are in the clear.
* Availability. Wipe the keystore or lose the password and the data is gone.
  There is no back door, by design.

**Known limitations**

* Whole inputs are held in memory; there is no streaming or chunked mode, so
  this is for field- and record-sized values, not multi-gigabyte files.
* One key per envelope, one key per command. Envelopes from several generations
  coexist fine, but you must tell the tool which key to use - there is no key
  registry that resolves an id to the right keystore for you.
* The salt record is fixed once written; rotating it means re-deriving and
  re-encrypting by hand (`saltgen` + `rotate`).
* GCM authentication is only as strong as key secrecy - reusing the same key
  across environments (dev/prod) means a ciphertext from one reads in the other.
  Use distinct keys per environment; `keyinfo` prints the id so you can verify
  which one is loaded.

## Verification

`SelfTest` runs 246 assertions in 5 groups and exits non-zero on any failure:

* **Correctness** - round trips for ASCII, Unicode (UTF-8 bytes preserved
  exactly), empty input, and a 1 MiB binary blob; 128-, 192- and 256-bit keys;
  200 encryptions of the same value all distinct and all decrypting, which is
  the IV-freshness property; the envelope body is exactly IV + plaintext + tag.
* **Integrity/authentication** - a single flipped bit rejected in every region
  of the payload (first and last IV byte, first and later ciphertext byte, final
  tag byte), truncated envelopes, tampered key id, version downgrade,
  non-canonical key id, non-Base64 body, multi-line input, wrong key, wrong
  context, context-character rules, AAD composition.
* **Key material handling** - `KeyHandle.toString()` never contains the key,
  wiping the caller's array cannot corrupt a live handle, a closed handle is
  useless, illegal key lengths refused at the boundary (0, 1, 8, 15, 20, 31, 33,
  64 bytes; 16/24/32 accepted), strict-Base64 rejection, KDF record rules and
  salt copying, passphrase derivation properties, single-use sources, keystore
  round trip, wrong keystore password refused, unknown alias, key-pair alias
  refused, the keystore file holds no raw key bytes, file mode is 0600, JCEKS
  works too.
* **Rotation** - data moves to the new key and the old key can no longer read
  it, `reencrypt` preserves bytes exactly, a bad line aborts the batch with no
  output file.
* **Command line** - real subprocesses: keygen/encrypt/decrypt round trip,
  `--keysize 192` honoured and an odd size refused without writing a keystore,
  stdin/stdout piping, binary fidelity, refusal of `--storepass`-style argv
  secrets, wrong-context writing nothing, tampered envelope, alias-overwrite
  refusal, rotation across keystores, the environment-key source (junk refused
  *without echoing it*), password files, a missing password, passphrase mode,
  `keyinfo` leaking nothing, unknown command, no-args usage, `--help`.

```sh
javac -Xlint:all -Werror SecureDataVault.java SelfTest.java && java SelfTest
```

The build is lint-clean under `-Xlint:all -Werror`, and sources are ASCII-only so
they compile under the platform default charset on machines configured for one
(the JVM here defaults to `US-ASCII`).

What is *not* covered: `--storepass-prompt` needs a terminal, so no test
exercises it; the atomic-write step (`ATOMIC_MOVE`) is not observable from a
black-box test. Both are small, but they are unverified rather than verified.

## All options

| Option | Applies to | Meaning |
| --- | --- | --- |
| `--keystore PATH` | all but `saltgen` | keystore holding the key |
| `--keystore-type TYPE` | same | `PKCS12` (default) or `JCEKS`; inferred from `.p12`/`.pfx`/`.jceks` |
| `--alias NAME` | same | key alias, default `appkey` |
| `--storepass-env VAR` | same | keystore password from environment |
| `--storepass-file PATH` | same | keystore password from file |
| `--storepass-prompt` | same | prompt for it (echo off) |
| `--kdf PATH` | same | PBKDF2 salt/cost record |
| `--pass-env VAR` / `--pass-file PATH` / `--pass-prompt` | same | passphrase for `--kdf` |
| `--key-env VAR` | same | Base64 AES key in the environment |
| `--in PATH` | encrypt, decrypt | input, default stdin |
| `--out PATH` | encrypt, decrypt | output, default stdout |
| `--in PATH` and `--out PATH` | rotate | both required: a half-rotated batch is not a useful default |
| `--text STR` | encrypt | input as an argument (see below) |
| `--context STR` | encrypt, decrypt, rotate | authenticated context, printable ASCII, no `|`. For `rotate` it is the shared context used by lines that carry no `context<TAB>` prefix of their own |
| `--keysize BITS` | keygen | 128, 192 or 256, default 256 |
| `--iterations N` | saltgen | PBKDF2 rounds, default 600000, floor 100000 |
| `--replace-alias` | keygen | allow overwriting an existing alias |
| `--print-base64` | keygen | print a fresh key Base64-encoded (to seed `--key-env`) and exit without writing a keystore |
| `--force-insecure-fileperms` | any command | skip the warning about a keystore, KDF record or password file that is readable beyond the owner |
| `new-` prefix | rotate | destination key: `--new-keystore`, `--new-alias`, `--new-storepass-env`, `--new-kdf`, `--new-pass-env`, `--new-key-env`, ... |

`--text` puts the plaintext in the process table for the lifetime of the
command. It is there for convenience and examples; for real values, pipe on
stdin or use `--in`.

