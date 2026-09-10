# Employee Portal Authentication

A small, dependency-free Java 17 console application that authenticates employees
against a local records file. Passwords are never stored in plaintext; each record
uses a unique salt and PBKDF2-HMAC-SHA-256 hash.

## Build and test

```bash
./build.sh
./test.sh
```

## Create an employee and sign in

```bash
./build.sh
java -cp out/main com.example.portal.PortalApplication --add-user alice
java -cp out/main com.example.portal.PortalApplication
```

The default store is `data/employees.records`. To use another location, set the
`EMPLOYEE_RECORDS_FILE` environment variable:

```bash
EMPLOYEE_RECORDS_FILE=/secure/path/employees.records \
  java -cp out/main com.example.portal.PortalApplication
```

Run the program from a real terminal so password entry can be hidden. When no
console is available (for example, input is piped), the program refuses to read a
password unless `--allow-visible-password` is supplied explicitly.

The records file contains usernames, account status, PBKDF2 parameters, salts,
and hashes. Restrict access to that file and its parent directory at the operating
system level. Authentication is only one part of portal security; a production
deployment should also add TLS, session management, authorization, audit logging,
rate limiting, and preferably an organization identity provider with MFA.
