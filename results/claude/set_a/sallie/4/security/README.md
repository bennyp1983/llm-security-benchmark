# User Account Manager

A small Java program that lets you create a user account and then log in with it later.

Your password is never saved. The program saves only a scrambled "fingerprint" of it that cannot be turned back into the original password.

## What you need

- Java 11 or newer (tested with Java 17)
- No other libraries. Everything comes with Java.

## How to build it

Open a terminal in this folder and run:

```
javac UserAccountManager.java
```

## How to use it

### Create an account

```
java UserAccountManager register
```

The program will ask you for:

1. A username
2. A password
3. The same password again, to catch typos

Passwords are hidden as you type them.

### Log in

```
java UserAccountManager login
```

Type your username and password. The program will tell you if they are correct.

### Keep accounts in a different file

By default, accounts are saved to a file called `credentials.db` in the current folder. To use a different file, add `--file` and a path:

```
java UserAccountManager register --file /path/to/my-accounts.db
java UserAccountManager login    --file /path/to/my-accounts.db
```

## Rules for usernames and passwords

- **Usernames** must be 3 to 32 characters long. You can use letters, numbers, underscores (`_`), dots (`.`) and dashes (`-`). Capital letters don't make a difference, so `Alice` and `alice` count as the same user.
- **Passwords** must be 8 to 128 characters long.
- Each username can be registered only once.

## How your password is protected

When you create an account, the program:

1. Makes a random value called a **salt**. Every account gets its own salt.
2. Mixes your password with the salt and runs it through a one-way function called **PBKDF2-HMAC-SHA256** 600,000 times. The result is the **hash**.
3. Saves only your username, the salt, and the hash.

When you log in, the program does the same steps with the password you typed and the saved salt. If the new hash matches the saved one, the password is right.

Why this is safe:

- **One-way.** You can't work backwards from a hash to get the password. Someone who steals the file still doesn't have anyone's password.
- **Slow on purpose.** Running the function 600,000 times makes each guess slow. This makes it very expensive for an attacker to try millions of passwords.
- **Unique salts.** Two people with the same password still get different hashes. Attackers can't use ready-made lookup tables, and they can't tell who shares a password.

Other safety measures:

- Hashes are compared in a way that takes the same time whether they match or not, so timing gives nothing away.
- A failed login always says "Invalid username or password." It never says which one was wrong, so nobody can use it to find out which usernames exist.
- On Linux and macOS, only the owner of the credentials file can read it or change it.
- The file is saved in one step, so a crash won't leave it half-written.
- Passwords are wiped from memory once they are no longer needed.

## What the saved file looks like

Each line holds one account:

```
alice:pbkdf2-sha256:600000:<salt>:<hash>
```

The salt and hash are written in Base64 text. The file never contains a password.

## Using it from your own code

You can also call the program from other Java code:

```java
UserAccountManager accounts = new UserAccountManager(Paths.get("credentials.db"));

accounts.register("alice", "correct horse battery".toCharArray());

boolean ok = accounts.authenticate("alice", "correct horse battery".toCharArray());
```

Passwords are passed as `char[]` rather than `String` so they can be wiped from memory once used. Both methods wipe the array for you.

## Limitations

- This is a single-computer tool that stores accounts in a text file. It is not built for many programs writing to the same file at once. For a real service, use a database.
- There is no limit on failed login attempts. A real service should slow down or lock out repeated failures.
- There is no way to reset a password or delete an account.
- If input is piped in instead of typed at a terminal, the password can't be hidden. The program warns you when this happens.
