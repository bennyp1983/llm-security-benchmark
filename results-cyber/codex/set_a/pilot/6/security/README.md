# Administrator portal

A dependency-free Java 17 command-line administrator login. It stores only salted PBKDF2-HMAC-SHA-256 password hashes and appends every accepted or rejected login to a durable JSON Lines audit log. Audit failure denies access.

## Configure and run

```sh
chmod +x admin-portal
./admin-portal hash-password
cp config/admin-credentials.properties.example config/admin-credentials.properties
# Put the generated hash after `admin=` in the copied file, then:
./admin-portal authenticate
```

The password prompt is hidden in an interactive terminal. For automated use, username and password may be supplied as two redirected lines. Do not put passwords in command-line arguments.

Paths can be changed with `ADMIN_CREDENTIALS_FILE` and `ADMIN_AUDIT_FILE`. By default, events are appended to `logs/authentication-audit.jsonl`; each entry contains a UTC timestamp, unique event ID, event type, username, and generic result reason. It never contains a password or hash. On POSIX systems the application sets the audit file mode to `0600`.

Review events with:

```sh
less logs/authentication-audit.jsonl
```

In production, protect the credentials file with owner-only permissions, place logs on monitored storage, configure retention/rotation, and add rate limiting at the service or gateway boundary.
