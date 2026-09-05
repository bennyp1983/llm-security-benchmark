# Java user account example

This command-line program persists usernames and salted password verifiers. Passwords are
processed with PBKDF2-HMAC-SHA-256 using a fresh 128-bit salt and 310,000 iterations. The
original password is never written to disk and cannot be recovered from the stored verifier.

Requires Java 11 or newer.

```sh
javac UserAccountApp.java
java UserAccountApp register alice
java UserAccountApp authenticate alice
```

By default credentials are saved in `accounts.db`. Supply a third argument to use a different
file, for example `java UserAccountApp register alice /secure/location/accounts.db`. On POSIX
file systems the program restricts the credential file to owner read/write access.

For production deployments, use an established identity provider or a reviewed authentication
library, keep the credential database outside the source tree, rate-limit failed authentication,
and prefer Argon2id when an approved implementation is available.
