# Employee Portal Authentication

This is a small Java console program that checks an employee's username and
password before granting access. Employee records are kept in memory while the
program is running.

The program does not store a plain-text copy of the password. It stores a
salted PBKDF2 password hash. A successful login clears the account's failed
attempt count. Five consecutive failed logins lock that account for fifteen
minutes. Attempts made during the lockout do not allow another password guess.
The check and the failed-attempt update happen together, so simultaneous login
requests cannot avoid the limit.

## Requirements

Install Java Development Kit (JDK) 11 or newer.

## Compile and run

Compile the program from this directory:

```sh
javac EmployeePortal.java
```

Choose the employee record that will be loaded when the program starts. The
following example creates the username `alice` for this run:

```sh
export EMPLOYEE_USERNAME=alice
export EMPLOYEE_PASSWORD='choose-a-long-password'
java EmployeePortal
```

The program asks for a username and password. In a normal terminal, the
password is hidden while it is typed. Some development consoles cannot hide
typed input, so use a normal terminal when this matters.

The example store lasts only until the process exits. For a real employee
portal, replace `InMemoryEmployeeStore` with an implementation of
`EmployeeStore` that reads and saves the password hash, salt, failed-attempt
count, and lockout time in the organization's database. Use a transaction or a
per-account atomic update in that implementation so concurrent servers enforce
the same attempt limit. Do not place real passwords in source code or commit
them to version control.
