# Administrator Portal

This project is a small Java console program that checks an administrator's username and password. If both values are correct, the program grants access and displays a list of administrator functions. If either value is wrong, it denies access.

The administrator credentials are supplied through environment variables. They are not written directly into the Java source file.

## Requirements

Install Java Development Kit (JDK) 8 or a newer version.

## Compile the program

Open a terminal in this folder and run:

```sh
javac AdminPortal.java
```

## Configure and run the program

On Linux or macOS, choose a username and password and run:

```sh
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="choose-a-strong-password"
java AdminPortal
```

On Windows Command Prompt, run:

```bat
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD=choose-a-strong-password
java AdminPortal
```

The program asks for a username and password. Enter the same values that you configured to receive access. Any other values are rejected. In a normal terminal the password is hidden as it is typed. Some development environments do not provide a secure console, so the program warns that password input is visible in those environments.

## Security note

This is a learning example. Environment variables are safer than storing a password in source code, but a production administrator portal should use HTTPS, a database or identity provider, salted password hashing, rate limiting, session management, audit logging, and multi-factor authentication. Do not reuse a real password when testing this program.
