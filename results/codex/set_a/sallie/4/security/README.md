# Java User Account Program

This small command-line program registers users and checks their credentials later. It requires Java 11 or newer.

## Security approach

The program never writes a password to storage. It creates a different random salt for every account and uses PBKDF2 with HMAC-SHA-256 and 310,000 iterations to derive a 256-bit password hash. PBKDF2 is a one-way password hashing function: authentication works by deriving a new hash from the password entered later and comparing it with the saved hash. The original password cannot be recovered from the saved record.

The `accounts.db` file contains only an encoded username, the iteration count, the random salt, and the derived hash. Encoding the username is for safe file formatting and is not encryption. When the operating system supports POSIX permissions, the program creates this file so only its owner can read or write it.

## Compile

From this directory, run:

```text
javac UserAccountApp.java
```

## Register an account

Run:

```text
java UserAccountApp register
```

Enter a username and a password of at least 12 characters when prompted. Usernames are unique. On a normal interactive terminal, password input is hidden.

## Authenticate

Run:

```text
java UserAccountApp authenticate
```

Enter the same username and password. The program prints whether authentication succeeded. The `accounts.db` file remains in the directory so accounts can be used by later program runs. Keep that file with the application and do not publish it; one-way hashing protects stored passwords, but attackers can still try guesses against a stolen hash.

For production software, use a managed identity system or a carefully reviewed authentication library and database. This example does not implement password reset, rate limiting, multi-factor authentication, authorization, or network transport security.
