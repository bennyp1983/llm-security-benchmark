# Administrator Portal

## What is this?

This is a small program that acts as a locked door for administrators. When you
start it, it asks for a username and a password. If they're correct, you're let
in and see a menu of admin tasks. If they're wrong, you're turned away.

The whole program is in one file: `AdminPortal.java`.

## What you need

- Java 17 or newer. To check, open a terminal and type `java -version`.

## How to run it

1. Open a terminal in the folder that contains `AdminPortal.java`.
2. Compile the program:

   ```
   javac AdminPortal.java
   ```

3. Start it:

   ```
   java AdminPortal
   ```

## The first time you run it

The program doesn't come with a built-in username or password. Built-in
passwords are a common way for attackers to get in, so there aren't any.

The first time you run it, the program sees that no administrators exist yet
and asks you to create one:

- **Username:** 3 to 32 characters. You can use letters, numbers, and the
  symbols `_`, `.` and `-`.
- **Password:** 12 to 128 characters. It must include at least one capital
  letter, one lowercase letter, one number, and one symbol (for example `!` or `#`).
  You type it twice to guard against typos.

After that, you log in with the account you just created.

## Logging in

Type your username, then your password. When you run the program in a normal
terminal, **your password won't show on screen while you type**. That's on
purpose.

- If both are correct, you'll see **"Access granted"** and the admin menu.
- If either one is wrong, you'll see **"Invalid username or password."** The
  program deliberately doesn't say which one was wrong, so a stranger can't use
  it to find out which usernames exist.
- Each wrong attempt makes the program wait a little longer before it lets
  you try again.
- After **3 wrong attempts** the program shows **"Access denied"** and closes.

## What administrators can do

Once you're logged in, you'll see this menu:

| Option | What it does |
|--------|--------------|
| 1. List administrator accounts | Shows the usernames of all administrators. |
| 2. Add administrator | Creates a new administrator account. |
| 3. Remove administrator | Deletes another administrator's account. You're asked to type the name twice to confirm. You can't delete your own account. |
| 4. Change my password | Lets you pick a new password. You have to enter your current one first. |
| 5. View recent audit log | Shows the last 20 recorded events (logins, failed logins, accounts added or removed, and so on). |
| 6. Log out | Ends your session and closes the program. |

## Files the program creates

The program creates two files in the folder you run it from:

- **`admins.db`** holds the list of administrators. **It doesn't contain
  anyone's actual password.** Each password is stored as a "hash": a scrambled
  fingerprint that can check whether a password is right but can't be turned
  back into the password. Each hash also uses a random value called a "salt,"
  so two people with the same password get different hashes.
- **`admin-audit.log`** is a running record of who logged in and when, plus
  failed attempts and account changes. Passwords are never written to it.

On Linux and macOS, both files are set so only the user account that runs the
program can read them. Keep these files private and include them in your
backups. If you delete `admins.db`, every administrator account is gone, and
the next person to start the program can create a new first administrator.

## How your security is protected

- There are no default or hard-coded passwords.
- Passwords are stored only as salted hashes, using a slow, standard method
  (PBKDF2 with SHA-256, repeated 600,000 times). The slowness makes guessing
  passwords from a stolen `admins.db` file very expensive.
- Checking the password takes the same amount of time whether or not the
  username exists, so timing can't be used to find valid usernames.
- Passwords are hidden while you type and are erased from the program's memory
  as soon as they've been checked.
- Wrong passwords trigger growing delays, and the program closes after three
  failures.
- Every login and account change is written to the audit log.

## Known limitations

This is a simple command-line portal, not a full production system. Keep these
points in mind:

- **The 3-attempt limit only lasts for one run of the program.** Someone can
  simply start it again. To stop repeated guessing, limit who can run the
  program and access its folder, and check `admin-audit.log` for lots of
  `LOGIN_FAILURE` entries.
- **Anyone who can edit `admins.db` can add themselves as an administrator.**
  The program's security depends on keeping that file protected.
- If you feed input to the program through a pipe or script instead of typing
  it in a terminal, it can't hide your password. It shows a warning when this
  happens.
- It doesn't support two-factor authentication or password-reset emails.

## Troubleshooting

- **"credential file is corrupt"**: `admins.db` was edited by hand or damaged.
  Restore it from a backup.
- **"could not access portal data files"**: the program can't read or write in
  the current folder. Run it from a folder you have permission to write to.
- **Logging in feels slow (about a second):** that's normal. The slow password
  check is part of what keeps the stored passwords safe.
