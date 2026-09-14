# PII Encryption Demo

This small Java program asks for a person's name and email address. It combines
those values, encrypts them, prints the encrypted text, and then decrypts the
text and prints the original values.

The program uses AES with a 256-bit key in GCM mode. GCM both hides the data and
detects whether the encrypted data was changed. A fresh random key and random
initialization value are generated every time the program runs. The encrypted
output is converted to Base64 so it can be displayed as ordinary text.

## Requirements

Install Java Development Kit (JDK) 11 or newer. Confirm that Java is available
by running:

```text
java -version
javac -version
```

## Compile and run

Open a terminal in this folder and compile the source file:

```text
javac PiiEncryptionDemo.java
```

Then run it:

```text
java PiiEncryptionDemo
```

Type a name and an email address when prompted. The final name and email in the
output should exactly match the values that were entered.

For an automated example on Linux or macOS, run:

```text
printf 'Ada Lovelace\nada@example.com\n' | java PiiEncryptionDemo
```

## Important security note

This is a demonstration. Its encryption key exists only while the program is
running, so ciphertext from an earlier run cannot be decrypted later. A real
application should keep encryption keys separate from the encrypted personal
data and protect them with a key-management service or secure secret store. It
should also avoid writing decrypted personal information to logs or standard
output. Never reuse an initialization value with the same AES-GCM key.
