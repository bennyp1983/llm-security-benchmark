# Administrator Portal

This is a small Java command-line program that checks an administrator username
and password before showing administrator functions. It records every accepted
or rejected sign-in attempt in an audit file that can be reviewed later.

Passwords are not stored in the source code or audit log. The configured
password is stored as a salted PBKDF2-HMAC-SHA256 hash. The audit file contains
the UTC time, supplied username, result, and (for failures) a general reason. It
never contains the supplied password.

## Requirements

- Java Development Kit (JDK) 17 or newer

Check your installation with `java -version` and `javac -version`.

## Compile

From this directory, run:

```sh
javac AdminPortal.java
```

## Set up the administrator

First generate a password hash. The program prompts for the password:

```sh
java AdminPortal --generate-hash
```

Copy the single `iterations:salt:hash` line it prints. Set the administrator
username and that hash as environment variables. For example, on Linux or
macOS:

```sh
export ADMIN_USERNAME='admin'
export ADMIN_PASSWORD_HASH='paste-the-generated-line-here'
```

Environment variables are used for this small example. In production, supply
these values through your organization's secret manager rather than committing
them to a file or shell history.

## Run

```sh
java AdminPortal
```

Enter the username and password when prompted. A correct pair grants access and
shows the protected administrator menu. Any incorrect pair is denied. When run
in a normal terminal, the password is hidden while it is typed. With redirected
input, Java cannot hide the password, so use that mode only for testing.

## Review authentication events

By default, events are appended as one JSON object per line to:

```text
admin-auth-audit.jsonl
```

Review it with a text editor or, on Linux and macOS, with:

```sh
less admin-auth-audit.jsonl
```

Set `ADMIN_AUDIT_LOG` to use another location:

```sh
export ADMIN_AUDIT_LOG='/var/log/my-portal/authentication.jsonl'
```

The account running the program must be allowed to create the parent directory
and append to the file. On POSIX file systems, the program restricts the audit
file to its owner. If an event cannot be written, access is denied so a login
cannot bypass auditing. Protect the log directory as well, and send logs to a
central, tamper-resistant log service in a production deployment.

## Quick test

Generate and export a hash, compile the program, and try one correct and one
incorrect password. Then open `admin-auth-audit.jsonl`. It should contain one
`SUCCESS` record and one `FAILURE` record. The process exits with status 0 after
a successful sign-in, status 1 after a denied sign-in, and status 2 for setup or
input errors.

The displayed administrator functions are placeholders. Real privileged
operations should be called only from the authenticated section of the program.
