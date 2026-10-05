# Employee Portal Login

This is a small Java program that checks whether an employee is allowed into the internal employee portal.

An employee types in their username and password. The program looks up that username in a records file and checks the password. If both are right, it says **Access granted**. If not, it says **Access denied**.

---

## What you need

- Java 11 or newer (Java 17 is recommended).
- Nothing else. The program uses only what comes with Java.

To check whether Java is installed, open a terminal and type:

```
java -version
```

---

## Setting it up

1. Put `EmployeePortalAuth.java` in a folder.
2. Open a terminal in that folder.
3. Build the program:

   ```
   javac EmployeePortalAuth.java
   ```

   This creates some `.class` files next to it. That's normal.

---

## Adding employees

Before anyone can log in, an administrator needs to add them. For example, to add an employee called `jsmith`:

```
java EmployeePortalAuth add-user jsmith
```

You'll be asked to type the new password twice. The password won't show on screen while you type.

Rules:

- **Usernames** must be 3 to 32 characters long. Use only lowercase letters, numbers, dots (`.`), underscores (`_`) or dashes (`-`). Capital letters are turned into lowercase automatically, so `JSmith` and `jsmith` are the same person.
- **Passwords** must be 12 to 128 characters long.

If you run `add-user` for someone who already exists, their password is replaced. Use this to reset a forgotten password.

## Removing employees

When someone leaves, remove them like this:

```
java EmployeePortalAuth remove-user jsmith
```

---

## Logging in

To log in, run:

```
java EmployeePortalAuth
```

Then type your username and password when asked.

- If they're right, you'll see: `Access granted. Welcome, jsmith.`
- If either one is wrong, you'll see: `Access denied: invalid username or password.`

You get **3 tries**. The program waits a little longer after each wrong try. After 3 wrong tries it stops and tells you to contact the IT help desk.

The program also sets an exit code, which is useful if another program or script runs it:

| Exit code | Meaning                                    |
|-----------|--------------------------------------------|
| 0         | Success (access granted, or a user was added or removed) |
| 1         | Access denied                              |
| 2         | Something was typed wrong (for example, a bad username or passwords that don't match) |
| 3         | The records file couldn't be read or written |

---

## Where employee records are kept

By default, records are saved in a file called `employees.db` in the folder where you run the program. It's created the first time you add an employee.

To keep the file somewhere else, set the `PORTAL_USER_DB` environment variable before running the program:

```
export PORTAL_USER_DB=/secure/location/employees.db
java EmployeePortalAuth
```

The file is plain text with one employee per line. It looks something like this:

```
jsmith:600000:G9qXy3jYPwCjWj9meESIdQ==:nS9FO6wLwrN3OAbU6bpgyhycCyd8znmQq/ZsymvO+QY=
```

Each line has the username, a number, and two scrambled values. **The real password is not in this file.**

---

## How passwords are kept safe

- **Passwords are never saved.** The program saves a "fingerprint" of each password instead (a hash). You can't turn it back into the original password.
- **Every password gets its own random extra value** (a "salt"). Two people with the same password end up with different fingerprints.
- **Making a fingerprint is slow on purpose.** The program runs the hashing step 600,000 times (the method is called PBKDF2-HMAC-SHA256). You won't notice this when logging in once, but it makes guessing millions of passwords very slow for an attacker.
- **The same error message for every failure.** The program never says whether the username or the password was wrong, so nobody can use it to find out which usernames exist. It also takes about the same time either way.
- **Guessing is slowed down.** There are only 3 tries per run, with a pause after each wrong one.
- **Passwords are hidden while typing,** and they're wiped from memory once they've been checked.
- **The records file is private.** On Linux and macOS, only the account that runs the program can read it.
- **Records are saved safely.** Changes go into a temporary file first and then replace the old file in one step, so the file won't be left half-written if something goes wrong.

---

## Things to know

- **Hidden passwords need a real terminal.** If you pipe input into the program, for example from a script, it can't hide what's typed. It will print a warning when this happens.
- **This is a starting point, not a whole login system.** Before using it for real, think about:
  - Keeping the records file on a secure server rather than on employees' own computers.
  - Locking an account after repeated failures across runs. Right now the 3-try limit starts over each time the program runs.
  - Recording login attempts in a log so they can be reviewed.
  - Connecting to your company's existing sign-in system (like Active Directory, LDAP or single sign-on), if you have one.
  - Adding a second step, like a code from a phone app.

---

## Quick example

```
$ javac EmployeePortalAuth.java

$ java EmployeePortalAuth add-user jsmith
New password for jsmith:
Confirm password:
Added employee jsmith.

$ java EmployeePortalAuth
=== Employee Portal Login ===
Username: jsmith
Password:
Access granted. Welcome, jsmith.
```
