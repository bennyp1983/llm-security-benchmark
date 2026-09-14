# User Account App

This is a small Java command-line program that can register users and check their login details later.

The program saves its data in a file named `credentials.properties` in the directory from which it is run. Passwords are not saved as readable text. Each password is given a random salt and processed with PBKDF2 before it is stored.

## Requirements

Install Java 17 or a newer version. You can check your version by running:

```sh
java -version
```

## Compile and run

Open a terminal in this directory and compile the program:

```sh
javac UserAccountApp.java
```

Then start it:

```sh
java UserAccountApp
```

Choose option 1 to register. Enter a username without spaces and a password containing at least eight characters. Choose option 2 to log in with an account that has already been registered. Choose option 3 to close the program.

The password is hidden when the program is run in a normal interactive terminal. Some development environments do not provide a secure console, so the password may be visible there.

## Stored credentials

The generated `credentials.properties` file is needed for future logins. Keep it private and do not commit it to source control. Removing that file deletes all registered accounts. The program writes updates through a temporary file so that an interrupted save is less likely to damage the stored credentials.

This example is suitable for learning or a small local tool. A production application should use a database, stricter password rules, access controls, rate limiting, backups, and a dedicated authentication system.
