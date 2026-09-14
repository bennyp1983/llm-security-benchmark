# Encrypting a name and an email address with AES

A small Java program that takes a person's name and email address, encrypts them so
that nobody without the passphrase can read them, and then decrypts them back to the
original text.

It is written with the plain Java development kit only. There is no Maven or Gradle
build and no third-party library to download.

## The files

| File | What it is |
| --- | --- |
| `src/PiiCrypto.java` | The encryption and decryption. This is the interesting one. |
| `src/PiiRecord.java` | A name and an email address that print themselves redacted. |
| `src/PiiApp.java` | The command line. Asks for the values, encrypts, decrypts, prints. |
| `test/PiiCryptoTest.java` | 194 checks. Run it with `java PiiCryptoTest`. |
| `.mutation/` | A harness that deliberately breaks the code, to check the tests notice. |
| `build.sh` | Compiles everything, runs the tests, then runs the demo. |

## How to run it

```
javac -d out src/*.java
java -cp out PiiApp "Ada Lovelace" "ada@example.com"
```

That asks for a passphrase on the terminal, without echoing what you type. On a
machine with no terminal (a script, a container, a cron job) put the passphrase in an
environment variable instead:

```
PII_PASSPHRASE='a long phrase you will remember' java -cp out PiiApp "Ada Lovelace" "ada@example.com"
```

Or build and try everything in one go:

```
./build.sh
```

Here is what the program prints. Every run is a little different, because the
encryption is deliberately not repeatable (see below).

```
Plain text (what you typed, this is the sensitive part)
  name : Ada Lovelace
  email: ada@example.com

Encrypted with AES-256-GCM (store this, it is safe to store)
  AaHIfNklXbPi5fC0eqqbKaG0K3ao3gHFklTOcrLw/kRX26/RKScrscLf4jGN/Kpc10OHXBmarqMgIoDd1awkFaaLy2xECp+KkNX9R7E

Same input encrypted a second time (a different token, same record)
  AaMbm26J1+TkAETgAALrO29lK8DkESQb6szpHR4QKC87pbXMLcq7WSwBaH7+XjetKBOMZnobfmOqli40b5M54oOHT5GFEjBnlwWoiYc
  tokens identical: false

Decrypted again with the same passphrase
  name : Ada Lovelace
  email: ada@example.com

Round trip identical to the input: true

Same token with a wrong passphrase, refused as expected
  cannot open this record: the passphrase is wrong, or the encrypted text was altered
```

Exit codes: `0` fine, `1` you need to fix something (bad email, short passphrase),
`2` something genuinely unexpected.

## Using it from your own code

```java
char[] passphrase = "a long phrase you will remember".toCharArray();

String token = PiiCrypto.encrypt("Ada Lovelace", "ada@example.com", passphrase);
// store `token`: one line of text, safe to put in a database column

PiiRecord person = PiiCrypto.decrypt(token, passphrase);
System.out.println(person.name());   // Ada Lovelace
System.out.println(person.email());  // ada@example.com

Arrays.fill(passphrase, '\0');       // wipe it from memory when done
```

Anything wrong throws `PiiCrypto.PiiCryptoException` with a message you can show a
person. It never returns a partly-correct answer.

## What actually happens, in plain English

1. **A key is made from your passphrase.** AES needs a key of an exact size, and a
   passphrase is whatever length you happen to type. So the passphrase is first run
   through PBKDF2 with HMAC-SHA256 for 210,000 rounds, which turns it into a proper
   256-bit AES key and, more importantly, makes guessing it slow.
2. **Two random values are drawn, freshly, every time.** A 16-byte *salt*, which is
   fed into step 1 so that two records protected with the same passphrase still get
   different keys, and a 12-byte *initial value* (IV), which AES-GCM needs and which
   must never be reused with the same key.
3. **AES encrypts the pair, in GCM mode.** GCM is the part that matters most: besides
   hiding the text it also produces a short check value (a 128-bit tag) that depends
   on the whole record *and* on the key. That is what makes tampering visible.
4. **Everything is packed into one line.** The layout is:

   ```
   version(1 byte) | salt(16) | iv(12) | encrypted text + tag
   ```

   and the whole thing is Base64 encoded so it can live in a text column, a config
   file or an email without escaping problems. The salt and IV are not secret; they
   are the recipe, not the ingredients. Inside the encrypted text the two fields are
   stored with a length in front of each, which is why a name containing an `@` or a
   `|` cannot be mistaken for the email.
5. **Decrypting runs this backwards** and checks the tag. If the passphrase is wrong,
   or one bit of the stored text has changed, the check fails and you get a clear
   refusal instead of a corrupted name.

### Why these particular choices

- **GCM rather than plain AES-CBC.** With CBC you must also get a message
  authentication code right, and getting it wrong is a classic and serious mistake.
  GCM does encryption and integrity in one step and refuses loudly on mismatch.
- **A key derived from a passphrase rather than a random key in a file.** One less
  secret to lose, move around and back up. The price is that the passphrase has to be
  strong, because the 210,000 rounds only slow down a guesser, they do not stop one.
- **Fresh salt and IV per encryption.** Encrypting the same person twice gives two
  different tokens. That is on purpose: if identical inputs produced identical
  tokens, anyone holding the stored data could count how many times each person
  appears without ever decrypting anything.
- **210,000 rounds.** This follows the current OWASP recommendation for
  PBKDF2-HMAC-SHA256. It costs about a tenth of a second per call, which nobody
  notices and an attacker does.
- **Name and email encrypted together.** They are almost always needed together, and
  encrypting them as one blob means one tag covers both, so nobody can swap Alice's
  email onto Bob's name.

### Things it checks before encrypting

These are not fussiness; each one prevents a specific silent failure:

- **No control characters** in a name or email. A newline or a NUL in PII is nearly
  always a mistake or an attack, and it wrecks log and file formats.
- **No half of a two-part character.** Unicode emoji and some scripts are stored as
  character pairs; if one half goes missing, Java quietly replaces it with a `?` and
  the name comes back wrong. Better to refuse.
- **A passphrase must not be empty, only spaces, contain a NUL, or hold half a
  character.** Verified against the JDK rather than assumed: `PBEKeySpec` really does
  stop at a NUL and really does turn a stray half-character into `?`, which would
  otherwise mean two different passphrases open the same record. The test suite
  proves both, so if a future JDK changes we find out.
- **Email shape.** A single `@`, something on both sides, no spaces, no `..`, no
  hyphen at the start or end of a name part, and at least one dot in the host. This
  is a typo filter, not an RFC 5322 validator; it accepts unusual-but-legal addresses
  like `first.last+tag@sub.example.co.uk` and international ones, because nothing in
  the encryption depends on the address being real.
- **Length limits** (200 characters for a name, 254 for an email) keep records a
  sane size and stop a runaway input.

## Testing

```
javac -d out src/*.java test/*.java
java -cp out PiiCryptoTest
```

It prints `OK  194 checks passed` and exits `0`, or lists what failed and exits `1`.
The suite takes about 35 seconds, almost all of it spent doing the real key
stretching the whole point of the design.

It covers, among other things:

- Names and emails come back **exactly** as they went in, including accents, Chinese
  characters and emoji, at ordinary sizes and right at the size limits.
- **A wrong passphrase is refused**, including one that differs by a single last
  character, and the refusal does not repeat the passphrase back.
- **Tampering is refused**: a flipped bit in the cipher text, in the tag, in the salt
  or in the IV; a token cut short; a token with an extra byte glued on; a token
  claiming a format version this code does not know.
- **Malformed input is refused**: not Base64, Base64 in the wrong alphabet, spread
  over two lines, too short to be real, or empty.
- **Nothing leaks.** The token, and the bytes behind it, do not contain the email,
  the name, or any recognisable piece of either.
- **The checks on the decrypt side work**, by hand-building a token around a broken
  payload. Those exist for tokens written by something other than this program.
- **The security numbers are the ones this file claims**: 256-bit key, 128-bit tag,
  16-byte salt, 12-byte IV, at least 200,000 rounds, and a measured lower bound on
  how long one derivation actually takes. That last one matters: if somebody "optimises"
  the rounds away, the tests fail rather than quietly making stored tokens crackable.

Because a test suite that passes on everything proves nothing, `.mutation/` breaks the
code in 24 specific ways (delete the random bytes, weaken the key, use the lax Base64
decoder, remove the control-character check, print the email in `toString`, and so
on) and confirms the suite fails each time:

```
python3 .mutation/run_mutants.py
```

It works on copies, never touches your sources, and takes a few minutes on four
cores.

## What this program is not

Being straight about the edges:

- **It protects data at rest, that is all.** It does not cover the name and email
  while they sit in a database in plain text, appear in a log line, or travel over a
  network.
- **Lose the passphrase and the data is gone.** There is no back door, no reset and
  no second key. That is the correct behaviour for real encryption, and the correct
  worry for you to have.
- **Changing a passphrase means re-encrypting.** Decrypt with the old one, encrypt
  with the new, one record at a time. Nothing here automates that.
- **One shared passphrase for everything is weak.** Anyone who can encrypt can also
  decrypt, so it gives you no proof about who wrote a record. Per-person or
  per-tenant passphrases, or an envelope scheme where a random AES key is itself
  wrapped with RSA, are the usual next step.
- **The passphrase is not wiped as thoroughly as it could be.** `PiiApp` zeroes the
  copies it holds. It cannot reach the copy the Java crypto classes keep internally,
  which the JDK does not let anyone clear.
- **A wrong passphrase and a damaged token produce the same message.** Deliberate:
  telling them apart can hand an attacker free information.
- **The email check is a typo filter.** Do not use it to decide an address exists.
- **A demo, not a audited library.** No formal review, no side-channel hardening. For
  regulated PII, use a vetted encryption library and a key management service.

## Requirements

Java 17 or newer (`java -version` to check). Uses only `javax.crypto` and
`java.security`, which ship with the JDK. It was written and verified on OpenJDK
17.0.20.1.
