# PII Encryptor

## What this program does

This is a small Java program that protects personal information. You give it a
person's **name** and **email address**. It scrambles (encrypts) both so that
nobody can read them without the secret key. It then unscrambles (decrypts)
them again and checks that you got back exactly what you typed in.

"PII" means *personally identifiable information*: any detail that can be used
to identify a real person, such as a name or email address.

## What you need

- Java 11 or newer (the program was tested with Java 17).
- Nothing else. The program uses only the tools that come built into Java.

To check whether Java is installed, open a terminal and type:

```
java -version
```

## How to run it

1. Open a terminal in the folder that contains `PiiEncryptor.java`.
2. Compile the program:

   ```
   javac PiiEncryptor.java
   ```

3. Run it. You can do this in one of two ways.

   **Option A: let the program ask you questions**

   ```
   java PiiEncryptor
   ```

   It will ask for a name and then an email address.

   **Option B: type the details on the command line**

   ```
   java PiiEncryptor "Jane Doe" jane.doe@example.com
   ```

   Put quotation marks around the name if it contains a space.

## What you will see

```
=== Encrypted (AES-256-GCM, Base64) ===
Name:  q3L0x9...w==
Email: 8Hc1Vb...A==

=== Decrypted ===
Name:  Jane Doe
Email: jane.doe@example.com

Round trip successful: true
```

The encrypted lines look like random letters and numbers. They will be
different every time you run the program, even for the same name. That is
normal and intended: it stops anyone from spotting that two records belong to
the same person just by comparing the scrambled text.

## How it works, in plain terms

1. **A secret key is created.** Each time the program starts, it makes a new,
   random 256-bit key. Think of this as a very long password that only the
   program knows.
2. **Each piece of information is locked.** The name and the email are each
   encrypted with AES, the encryption standard used by governments and banks.
   The program uses a mode called GCM, which does two jobs at once: it hides
   the information, and it adds a seal that shows whether anyone has tampered
   with it.
3. **A fresh random starting value is used every time.** Before encrypting,
   the program picks a random value (called an IV). This is why the output
   changes on every run. The IV is not secret, so it is stored at the front of
   the encrypted text.
4. **Each value is tagged with what it is.** The name is sealed with the label
   "name" and the email with the label "email". If someone swaps the two
   encrypted values around, decryption fails instead of quietly giving wrong
   results.
5. **The information is unlocked again.** The program decrypts both values with
   the same key, checks the tamper seal, and compares the result with what you
   typed in.

## If something goes wrong

- **"name must not be empty"**: you pressed Enter without typing a name.
- **"is not a valid email address"**: the email needs to look like
  `someone@example.com`.
- **"Usage: ..."**: you gave the wrong number of details on the command line.
  Give either none (to be asked) or exactly two: a name and an email.

## Important notes before using this for real data

This program is a demonstration. It shows how to encrypt and decrypt
information correctly, but a real system needs a few more things:

- **Keep the key somewhere safe.** This program throws the key away when it
  finishes, so anything it encrypted can never be decrypted again afterward.
  A real application should store the key in a proper key store or key
  management service (for example AWS KMS, Azure Key Vault, Google Cloud KMS,
  or HashiCorp Vault). Never put the key in your source code or save it next
  to the encrypted data.
- **Do not print the key.** The program deliberately never shows the key on
  screen.
- **The decrypted details are shown on screen** so you can see the program
  works. In a real system you would not print personal information to a
  terminal or a log file.
- **Using the program on the command line (Option B)** may save the name and
  email in your terminal's history. Use Option A if that matters to you.

## Files

| File                | What it is                              |
|---------------------|-----------------------------------------|
| `PiiEncryptor.java` | The Java source code for the program.   |
| `README.md`         | This guide.                             |
