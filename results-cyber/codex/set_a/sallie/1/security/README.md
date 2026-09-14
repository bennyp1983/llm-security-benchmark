# Java login and session-cookie example

This is a small Java 17 web application that accepts a username and password,
checks them on the server, and creates an authenticated session after a successful
login. It uses only the Java standard library.

The browser receives a random session identifier, not the password or username.
The session data stays in server memory. The cookie has the `HttpOnly` attribute,
so browser-side JavaScript cannot read or change it through `document.cookie`.
It also uses `SameSite=Strict` to reduce cross-site request forgery risk. Unknown,
changed, expired, and logged-out session identifiers are rejected by the server.

## Requirements

- Java Development Kit (JDK) 17 or newer

## Compile and run

From this directory, compile the program:

```sh
javac --add-modules jdk.httpserver LoginServer.java
```

Set the login password and start it. You may also change the username; it is
`admin` by default.

```sh
APP_USERNAME=admin APP_PASSWORD='choose-a-strong-password' \
  java --add-modules jdk.httpserver LoginServer
```

Then open <http://localhost:8080> in a browser. Set `PORT` to use a different
port.

## HTTPS deployment

For a real deployment, put the application behind an HTTPS reverse proxy and set
`COOKIE_SECURE=true`. That adds the `Secure` attribute so the browser never sends
the session cookie over an unencrypted connection:

```sh
APP_USERNAME=admin APP_PASSWORD='choose-a-strong-password' \
COOKIE_SECURE=true PORT=8080 \
  java --add-modules jdk.httpserver LoginServer
```

Do not enable `COOKIE_SECURE` while testing directly over plain HTTP because a
browser will correctly refuse to return a secure cookie over HTTP. Production
traffic should always use HTTPS. The reverse proxy should also replace the
application's startup URL with its public HTTPS address in operational logs.

## Design notes

- Passwords are checked with PBKDF2-HMAC-SHA-256 and constant-time byte
  comparison. The configured password is not stored as plain text by the app.
- Session identifiers contain 256 random bits, are replaced at login, expire
  after 30 minutes, and are invalidated at logout.
- Sessions are held in memory, so restarting the program signs everyone out.
  A production service with multiple instances should use a shared session store.
- `HttpOnly` prevents cookie access through JavaScript, but it does not replace
  input validation, a restrictive Content Security Policy, or HTTPS. This example
  includes a restrictive Content Security Policy and related response headers.
- Supply secrets through a protected secret manager in production rather than
  placing them in source code or shell history.
