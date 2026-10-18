# Java session login example

This is a small Java 17 web application that shows how a username and password can create an authenticated browser session. It uses only classes included with the JDK.

The login form sends the username and password to the server. If they match the configured credentials, the server creates a random session identifier and stores the session in memory. The browser receives that identifier in a `SESSION_ID` cookie. The password is never placed in the cookie.

The cookie is `HttpOnly`, which prevents browser JavaScript from reading it, and `SameSite=Lax`, which provides basic protection against cross-site requests. Sessions expire after 30 minutes. Logging out removes the server-side session and expires the browser cookie.

## Run the application

You need Java 17 or newer and Maven.

Set your own credentials, compile the application, and start it:

```sh
export APP_USERNAME='alice'
export APP_PASSWORD='choose-a-long-password'
mvn package
java -cp target/classes com.example.SessionAuthServer
```

Open `http://localhost:8080/login` in a browser and sign in with the values you set. If you do not set credentials, the demonstration defaults are `demo` and `change-me`.

To use another port, set `PORT` before starting the program:

```sh
export PORT=9090
```

## Production use

This project is deliberately small and stores both the configured account and active sessions in memory. Restarting the process signs everyone out. A production system should store password hashes made with a password-specific algorithm such as Argon2id, bcrypt, or scrypt, and it should use a database or identity provider for users. Do not keep real passwords in source code.

Production login traffic must use HTTPS. When the application is served through HTTPS, enable the cookie's `Secure` flag:

```sh
export SESSION_COOKIE_SECURE=true
```

Keep that setting off only for local plain-HTTP testing, because browsers do not send a `Secure` cookie over plain HTTP. For a larger application, also add login rate limiting, session cleanup, password reset support, audit logging, and CSRF tokens for state-changing forms.

## Quick command-line check

With the server running and the example credentials configured, this command saves the returned cookie and follows the redirect to the protected page:

```sh
curl -i -L -c cookies.txt -b cookies.txt \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=alice&password=choose-a-long-password' \
  http://localhost:8080/login
```

Delete `cookies.txt` when you finish testing.
