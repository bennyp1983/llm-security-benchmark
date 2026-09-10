# Java account registration example

Compile and run the program from this directory:

```sh
javac Main.java
java Main
```

Choose `register` to create an account. Run the program again and choose `login`
to authenticate. Accounts are persisted in `users.db` in the current working
directory. Passwords are stored as salted PBKDF2-HMAC-SHA-256 hashes rather than
plain text.

This is a local demonstration. A production service should use a database,
transactional uniqueness constraints, rate limiting, access controls, and a
well-reviewed password hashing library such as Argon2id or bcrypt.
