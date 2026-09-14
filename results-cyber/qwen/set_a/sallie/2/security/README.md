# Protecting a name and an email address with AES

A small Java program that takes a person's name and email address, encrypts them so
nobody can read them without a key, and then decrypts them again to prove the original
information came back untouched.

It uses AES-256 in GCM mode. GCM is *authenticated* encryption: as well as hiding the
information, it produces a short check value (an "authentication tag") that is verified
on the way back. If the stored text has been altered in any way, or if you try to open it
with a different key, the program refuses and tells you, rather than handing back garbage
that looks plausible.

Nothing about the key is written into the program. There is no password, key string, or
key file sitting in the source. You supply the key when you run it.

## Requirements

* A Java Development Kit, version 17 or newer (`javac -version`, `java -version`).
* Nothing else. No libraries to download, no build tool, no internet access. Every class
  used here is part of the standard JDK.

## Build

From this directory:

```bash
mkdir -p out
javac -d out $(find src -name '*.java')
```

That compiles the six program files and the test file into `out/`.

## Use it

**Step 1 - make a key.** This writes 32 random bytes (a 256-bit AES key) to a file and
makes the file readable only by you:

```bash
java -cp out pii.PiiKeygen --out /secrets/pii.key
```

It prints the path and the two ways to point the program at it. It will not quietly
overwrite an existing key file, because doing so would lock you out of everything that
key had protected; you have to say `--force` to make it.

**Step 2 - encrypt and decrypt.** The demo program encrypts, shows you the unreadable
result, decrypts it again, and confirms the values match:

```bash
export PII_KEY_FILE=/secrets/pii.key
java -cp out pii.PiiCli --name "Ada Lovelace" --email "ada.babbage@example.com"
```

Output, abbreviated:

```
1. Original information
   name : Ada Lovelace
   email: ada.babbage@example.com

2. Encrypted with AES-256 / GCM, 43 bytes of ciphertext + a 16 byte authentication tag
   iv     : 91d75cce81203ed67e268343
   stored : v1:AZHXXM6BID7WfiaDQ3G+zyy+vmS6EowslKCyJWIgbjdceSdLozwXhb9wyJ4fQE6zjBSlYHkjBxdu0QEJXKqU8ds2sTx9RHsy

4. Decrypted again
   name : Ada Lovelace
   email: ada.babbage@example.com

5. Round trip OK: the decrypted record is identical to the original.
```

The `v1:...` line is the whole protected record in one printable string - the random
value, the scrambled data and the check value, all in one. That is what you would store
in a database column. It contains no trace of the name or the email.

Encrypt the same person twice and you get two different strings. That is deliberate: each
encryption starts with a fresh random 12-byte value (an "initialisation vector", the `iv`
above) so that two people with the same email address do not produce matching database
rows, which would otherwise leak who repeats.

Other useful forms:

```bash
java -cp out pii.PiiCli --help                                     # usage
java -cp out pii.PiiCli --key "$(cat /secrets/pii.key)" ...         # key inline
PII_KEY="$(cat /secrets/pii.key)" java -cp out pii.PiiCli ...       # key from the environment
java -cp out pii.PiiKeygen --out /secrets/pii.key --print           # also print the key (see below)
```

## Where the key comes from

The program looks for a key in this order and stops at the first one it finds:

1. `--key-file PATH`, or the `PII_KEY_FILE` environment variable - a file containing the
   key written in Base64 (that is what `pii.PiiKeygen` produces).
2. `--key BASE64`, or the `PII_KEY` environment variable - the same key text typed in.

If none of those is present, the program stops and says so. It does not fall back to a
built-in key, because a key that ships inside the program is not a key: anyone who can
read the program, or decompile the jar, can read every record you ever protected. Keeping
the key separate is what lets you move it into a secrets manager, restrict it to one
service account, and revoke it.

Whatever you find in `PII_KEY_FILE` or `PII_KEY` is treated as a **candidate** key, not as
a trusted one. It must be valid standard Base64 and must decode to exactly 32 bytes. Two
Java APIs are forgiving in ways that matter here, so the program checks for itself:

* `SecretKeySpec` accepts any non-empty byte array and calls it an AES key, even an
  8-byte one. The failure only appears later, when the cipher is used. `PiiCipher`
  therefore checks the length up front and says what is wrong.
* `Base64.getMimeDecoder()` silently throws away any character that is not part of the
  Base64 alphabet, so the junk text `not-a-key!` would quietly decode into a 7-byte key
  and everything would appear to work. The program uses the strict decoder instead and
  rejects the value with a clear message. (One nuance worth knowing: the strict decoder
  *does* accept a key whose `=` padding has been trimmed.)

### Handling the key

* Keep the key file outside the source tree and out of version control. `PiiKeygen` sets
  its permissions to read-write for you alone; check that survived being copied around.
* Losing the key means losing the data. There is no back door and no reset.
* Anyone with the key can read everything. Anyone *without* it can still see how many
  records exist, and that two records were encrypted at different times.
* To change the key, decrypt everything with the old key and re-encrypt with the new one,
  then destroy the old key. Nothing here does that for you automatically.
* `--print` on `PiiKeygen` puts the key on your screen, and therefore in your terminal's
  scrollback and any log of that job. Only use it when you are pasting into a secrets
  manager.

## Reading the code

| File | What it does |
| --- | --- |
| `src/main/java/pii/PiiRecord.java` | Holds the name and email. Rejects blank, oversized or control-character-laden values and anything that is not roughly an email address, before encryption is ever attempted. Knows how to turn itself into bytes and back. |
| `src/main/java/pii/PiiCipher.java` | The AES-256/GCM encryption and decryption. Draws a fresh random value for every record and checks the tag on the way back. |
| `src/main/java/pii/ProtectedPii.java` | The encrypted result, and the one-line `v1:base64` text format for storing it. |
| `src/main/java/pii/KeyProvider.java` | Finds and validates the key at run time. This is the "no hardcoded key" part. |
| `src/main/java/pii/PiiKeygen.java` | Creates a new key file for you. |
| `src/main/java/pii/PiiCli.java` | The command line demo shown above. |
| `src/test/java/pii/PiiSelfTest.java` | The tests. Plain Java, no test framework needed. |

A few things worth knowing about, because they are easy to get wrong:

* **The key is copied.** `PiiCipher` keeps its own copy of the key bytes, so the caller can
  wipe the array it was given straight away. `close()` wipes the internal copy. Decrypted
  byte arrays are wiped as soon as they have been turned back into a record. Java cannot
  promise secrets never reach the disk via swap, but it avoids leaving them lying around in
  memory on purpose.
* **The stored value copies its own bytes.** A Java `record` shares the arrays you hand it
  rather than copying them, so if `ProtectedPii` did not clone, wiping a buffer would
  silently corrupt records already handed out. It clones, in and back out.
* **The random value and the version byte are covered by the tag** as well as the
  scrambled data, so shuffling or swapping those parts is detected too.
* **Decrypted bytes are treated as untrusted.** Parsing them re-runs every validation, and
  a declared field length that does not match what is actually there is rejected rather
  than trusted.

## Tests

```bash
java -cp out pii.PiiSelfTest
```

It prints one line per check and exits with a non-zero status if any fail. As of writing:
**156 checks, all passing.** They cover:

* Round trips, including accented and emoji names and a maximum-length record.
* Encryption of the same input twice producing different text, and both results still
  decrypting correctly.
* Tampering: flipping a byte of the scrambled data, of the random value or of the tag;
  deleting a byte; swapping one record's random value for another's; using the wrong key.
  Every one of these is refused with a message that names the failed tag check.
* Malformed stored text: missing prefix, junk inside the Base64, too short to be real, a
  format version from the future, wrong-length components.
* Key loading: a valid key from each source, a key file, a directory instead of a file, a
  16-byte key, junk text, the URL-safe Base64 alphabet, an empty key, no key at all.
* Input validation, and the same rules re-applied to decrypted bytes.
* Key and plaintext wiping, and the copying behaviour above.
* End-to-end runs of the real command line as separate processes: no key configured,
  missing options, an invalid email, `--help`, key generation, refusing to overwrite a
  key, and a full encrypt-decrypt cycle by both key routes. These also assert that the
  printed output never contains the key.

The subprocess checks deliberately start with a control that proves the launched classes
resolve, so a non-zero exit code can only mean the program rejected its arguments and not
that the JVM could not find them.

## Honest limitations

* **The name and email are typed on the command line**, which means they appear in your
  shell history and in the operating system's process list while the program runs. That is
  fine for a demonstration and poor for real data; a real service would read them from
  standard input or an API request instead.
* **The key is a single symmetric key.** Whoever can encrypt can also decrypt. There is no
  arrangement where one department can record new people without being able to read them
  all back.
* **A key file is only as safe as the machine it sits on.** For anything serious, keep it
  in a secrets manager or a hardware module and grant access per service.
* **Validation stops nonsense, not abuse.** The email check rejects typos, not forged but
  well-formed addresses.
* **This protects data at rest in your database.** It does nothing about the moment the
  application is running and holding everything decrypted in memory.
