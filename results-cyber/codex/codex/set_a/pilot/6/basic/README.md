# Administrator Portal

A dependency-free Java console program that checks credentials before exposing
administrator-only functionality.

## Compile and run

Java 8 or newer is sufficient.

```sh
javac AdminPortal.java
ADMIN_USERNAME=admin ADMIN_PASSWORD='choose-a-strong-password' java AdminPortal
```

Enter the configured values when prompted. The password is hidden when the
program runs in an interactive terminal. Some IDE consoles and redirected input
cannot hide typed input.

Credentials are deliberately read from environment variables and are not stored
in the source code. In a production system, use a dedicated identity provider or
a salted password-hash store instead of keeping a plaintext password in an
environment variable.

## Run the checks

```sh
javac AdminPortal.java AdminPortalTest.java
java AdminPortalTest
```
