# Employee Portal Authentication

This is a small command-line Java program that checks an employee's username and
password before granting access. Employee records are kept in a separate file.
Passwords are never saved directly; the program stores a salted PBKDF2 password
hash instead.

## Requirements

Install Java Development Kit (JDK) 17 or newer. Check the installed version with:

```text
javac -version
```

## Compile the program

Open a terminal in this folder and run:

```text
javac EmployeePortal.java
```

## Add an employee

Create the first employee record with this command, replacing `jsmith` with the
employee's username:

```text
java EmployeePortal --add employees.db jsmith
```

The program asks for the new password twice. A password must be at least 12
characters long. Run the same command with a different username to add more
employees. Existing employee records are preserved, and duplicate usernames are
rejected.

The `employees.db` file contains password hashes and should still be treated as
sensitive. Limit access to administrators and the portal service account, keep it
out of source control, and include it in secure backups.

## Sign in

Run:

```text
java EmployeePortal
```

Enter a username and password when prompted. The password is hidden when the
program runs in a normal terminal. Access is denied after three failed attempts.

To use a record file with a different name or location, pass its path when signing
in:

```text
java EmployeePortal /secure/location/employees.db
```

Use that same path when adding an employee.

## Important production note

This sample is suitable for demonstrating local authentication, but a real
internal portal should normally use the organization's identity provider and
single sign-on system. A production system also needs centralized audit logs,
account disabling, password reset, rate limiting shared across machines,
multi-factor authentication, encrypted connections, and carefully managed access
to the employee record store.
