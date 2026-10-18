# PII Encryptor

A small Java program that protects personal information. You type in a
person's name and email address, the program scrambles (encrypts) them so
nobody can read them, and then unscrambles (decrypts) them again to show that
the original information comes back exactly as it was.

## What it uses

- **AES-256**, the widely trusted encryption standard, with the longest key size.
- **GCM mode**, which also detects tampering. If anyone changes even one
  character of the encrypted data, or uses the wrong key, decryption fails
  instead of returning garbage.
- A **fresh random value (IV)** every time something is encrypted, so the same
  name encrypted twice gives two different results. This stops people from
  spotting repeated values.

## Where the key lives

The key is **not** written anywhere in the source code. The program reads it
when it starts, from one of these places:

1. A file. Put the file's location in the environment variable
   `PII_ENCRYPTION_KEY_FILE`. The program checks this first.
2. The environment variable `PII_ENCRYPTION_KEY` itself.

If neither is set, the program stops with an error. It never falls back to a
built-in key.

The key must be 32 random bytes written in Base64 (44 characters). The program
can create one for you (see below).

## What you need

- Java 17 or newer (check with `java -version`).

## How to use it

### 1. Compile

```
javac PiiEncryptor.java
```

### 2. Create a key (once)

```
java PiiEncryptor --generate-key
```

This prints a new random key. Treat it like a password. Anyone who has it can
read the encrypted data, and if you lose it, the encrypted data cannot be
recovered.

### 3. Give the program the key

**Option A: key file (recommended).** On Linux or macOS:

```
umask 077
java PiiEncryptor --generate-key > pii.key
export PII_ENCRYPTION_KEY_FILE="$PWD/pii.key"
```

`umask 077` makes sure only you can read the file. Keep the key file out of
version control, for example by adding `pii.key` to `.gitignore`.

**Option B: environment variable.**

Linux / macOS:
```
export PII_ENCRYPTION_KEY="paste-your-key-here"
```

Windows PowerShell:
```
$env:PII_ENCRYPTION_KEY = "paste-your-key-here"
```

In production, a secrets manager (such as AWS Secrets Manager, Azure Key Vault,
Google Secret Manager or HashiCorp Vault) is the best place to keep the key. It
can hand the key to the program through either of the options above.

### 4. Run

```
java PiiEncryptor
```

The program asks for the name and the email address, then prints something like:

```
Name: Ada Lovelace
Email address: ada@example.org
Encrypted data
  Name : 46JGVBNpMm9cFbiURCNecEJiZ+5rEQ1LvMlUHmcfkiqqynuz+ccMwA==
  Email: D96GNFgjg+HrTo7A8Ql/efBoS4gFflPSER8qB1syZIjyJl1ub525UthWmQ==
Decrypted data
  Name : Ada Lovelace
  Email: ada@example.org
Round trip succeeded: the original data was recovered.
```

Your encrypted text will look different every run. That is expected.

## Good to know

- **The name and email are typed in, not passed on the command line.** Command
  line arguments can show up in shell history and in process lists that other
  users on the machine can see. You can still pipe input in if you need to,
  e.g. `printf 'Ada Lovelace\nada@example.org\n' | java PiiEncryptor`.
- **Encrypted values are tied to their field.** An encrypted email cannot be
  passed off as an encrypted name. The program will refuse to decrypt it.
- **Error messages are kept vague on purpose.** If decryption fails, the program
  says only that the key was wrong or the data was altered.
- **Accented or non-Latin characters** are encrypted and recovered correctly.
  If they show up as `?` on screen, your terminal is not set to UTF-8. That
  affects only the display, not the data.
- **This is a demo.** The program shows the decrypted information on screen
  so you can see that it worked. A real application would store the encrypted
  values and decrypt them only when needed. It would not print personal data.

## Format of the encrypted text

Each encrypted value is Base64 text containing, in order:

| Part                | Size     |
|---------------------|----------|
| IV (random value)   | 12 bytes |
| Encrypted data      | same length as the original text (in UTF-8) |
| Authentication tag  | 16 bytes |

## Files

- `PiiEncryptor.java`: the program.
- `README.md`: this file.
