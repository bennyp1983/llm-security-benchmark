# Secure Login Server

This is a small Java web application. It shows a sign-in page, checks a username and password, and keeps you signed in with a session cookie. The cookie is set up so that scripts running in the browser cannot read it or change it.

The whole program is one file, `SecureLoginServer.java`. It only uses what comes with Java, so there is nothing extra to download.

---

## What you need

- Java 17 or newer. You can check your version by running `java -version`.

---

## How to run it

1. Open a terminal in this folder.
2. Start the program:

   ```
   java SecureLoginServer.java
   ```

   Java compiles and runs the file in one step.

3. The terminal prints the web address, plus a username and a random password for a demo account. For example:

   ```
   Server started at http://localhost:8080/
   No APP_DEMO_PASSWORD set. Demo account -> username: alice  password: 9fK2...
   ```

4. Open `http://localhost:8080/` in your browser and sign in with that username and password.
5. To stop the server, press `Ctrl+C`.

If you want to pick the demo password yourself, set it before you start the program:

```
APP_DEMO_PASSWORD='choose-a-long-password' java SecureLoginServer.java
```

If you'd rather compile first and run afterward:

```
javac SecureLoginServer.java
java SecureLoginServer
```

---

## How it works

1. **You open the sign-in page** (`/login`) and enter your username and password.
2. **The server checks them.** Passwords are never stored as plain text. The server keeps a "salted hash" of each password (made with PBKDF2-SHA256, run 600,000 times). When you sign in, it hashes what you typed the same way and compares the two results.
3. **If they match, the server starts a session.** It makes a long random session ID, stores the session on the server, and sends the ID to your browser in a cookie.
4. **Your browser sends the cookie with every later request.** The server looks up the ID to see who you are. That is how the home page (`/home`) knows you are signed in.
5. **When you click "Sign out"** (`/logout`), the server deletes the session and tells the browser to delete the cookie.

If the username or password is wrong, you see "Invalid username or password." The message is the same in both cases, so nobody can use it to find out which usernames exist.

---

## How the session cookie is protected

The server sends a cookie like this:

```
Set-Cookie: __Host-SESSIONID=<random value>; Path=/; Secure; HttpOnly; SameSite=Strict
```

Here is what each part does:

| Setting | What it does |
|---|---|
| `HttpOnly` | **This is what keeps scripts away from the cookie.** JavaScript on the page cannot see it (`document.cookie` won't show it), and scripts can't overwrite or delete it. So even if someone slipped a harmful script onto the page, it couldn't steal your session. |
| `Secure` | The browser only sends the cookie over an encrypted HTTPS connection. (Browsers make an exception for `localhost` so you can test on your own computer.) |
| `SameSite=Strict` | The browser won't send the cookie when some other website makes a request to this one. This helps stop other sites from acting on your behalf. |
| `__Host-` name prefix | The browser only accepts the cookie if it is `Secure`, applies to the whole site (`Path=/`), and isn't shared with other subdomains. That stops a nearby subdomain from planting a fake cookie with the same name. |
| No expiry date | It's a true "session cookie," so the browser drops it when you close the browser. |

The cookie's value is just a random number, 256 bits long. It holds no username or other personal data. Changing it doesn't help an attacker: a changed value won't match any session on the server, so it's simply rejected.

---

## Other safety features

- **New session ID on every sign-in.** Any session ID the browser had before is thrown away. This blocks "session fixation," where an attacker tricks you into using a session ID they already know.
- **Sessions expire.** A session ends after 15 minutes of inactivity, or 8 hours after sign-in, whichever comes first.
- **Session IDs are not kept in plain form.** The server stores only a SHA-256 fingerprint of each ID.
- **Protection against password guessing.** After 5 wrong tries for the same username, that username is blocked for 5 minutes. After 20 wrong tries from the same computer (IP address), that address is blocked for 5 minutes. The limit per address is higher because many people can share one address, for example in an office.
- **Protection against forged requests.** Sign-in and sign-out requests coming from other websites are rejected. Signing out also needs a secret token that only the real page has.
- **Safe page output.** Anything shown on a page is escaped, so text can't be turned into HTML or script.
- **Strict browser security headers.** Pages forbid all scripts (Content-Security-Policy), can't be shown inside frames on other sites, and are never cached.
- **Size limits.** Very large requests and very long usernames or passwords are refused.
- **Timing and log safety.** Signing in with a username that doesn't exist takes about as long as one that does. Usernames are cleaned before being written to the log.
- **Safe default network setting.** Without HTTPS, the server only listens on your own computer (`127.0.0.1`). It refuses to run plain HTTP on a public network address.

---

## Settings

You change settings with environment variables. All of them are optional.

| Variable | Default | Meaning |
|---|---|---|
| `APP_PORT` | `8080` | Port the server listens on. |
| `APP_BIND_ADDRESS` | `127.0.0.1` | Network address the server listens on. Anything other than a local address needs HTTPS. |
| `APP_DEMO_USERNAME` | `alice` | Username of the demo account. |
| `APP_DEMO_PASSWORD` | random | Password of the demo account. If you don't set it, a random one is printed at startup. |
| `APP_KEYSTORE` | not set | Path to a PKCS12 keystore file. Setting this turns on HTTPS. |
| `APP_KEYSTORE_PASSWORD` | not set | Password for the keystore. Required when `APP_KEYSTORE` is set. |

---

## Turning on HTTPS

On a real network you must use HTTPS. Without it, browsers won't store the `Secure` cookie, and passwords would travel unencrypted.

For testing, you can make a self-signed certificate with Java's `keytool`:

```
keytool -genkeypair -alias local -keyalg EC -groupname secp256r1 -validity 30 \
  -dname "CN=localhost" -ext "SAN=dns:localhost" \
  -storetype PKCS12 -keystore local.p12 -storepass change-me -keypass change-me

APP_KEYSTORE=local.p12 APP_KEYSTORE_PASSWORD=change-me java SecureLoginServer.java
```

Then open `https://localhost:8080/`. Your browser will warn you because the certificate is self-signed. That's expected for testing. For real use, get a certificate from a trusted certificate authority.

When HTTPS is on, the server also tells browsers to always use HTTPS for this site (Strict-Transport-Security) and only allows TLS 1.2 and 1.3.

---

## Trying it from the command line

Replace the password below with the one printed when the server started.

```
# Sign in. The response shows the Set-Cookie header with HttpOnly, Secure, SameSite=Strict.
curl -i -c cookies.txt -d 'username=alice' -d 'password=YOUR-PASSWORD' http://localhost:8080/login

# Visit the home page using the saved cookie.
curl -i -b cookies.txt http://localhost:8080/home
```

---

## Before using this in production

This is a small, self-contained example meant to show the right way to handle a login session. For a real product, keep in mind:

- **Users live in memory.** There is only one demo account, and everything resets when the server restarts. A real system would load users from a database that stores the same kind of salted password hashes.
- **Sessions live in memory.** Restarting the server signs everyone out. If you run several copies of the server, they won't share sessions.
- **Built-in Java web server.** The server that comes with Java (`com.sun.net.httpserver`) is fine for small apps and learning. Busy public sites usually run behind a hardened server or a framework such as Spring Boot. There, you'd set the same cookie options (`HttpOnly`, `Secure`, `SameSite=Strict`).
- **Proxies.** If the app sits behind a reverse proxy, every request looks like it comes from the proxy's IP address. The per-IP guessing limit would then need to use the real client address that the proxy passes along.
- **Printed password.** The random demo password is printed to the terminal for convenience. Don't do that with real accounts.

---

## Files

| File | What it is |
|---|---|
| `SecureLoginServer.java` | The complete application source code. |
| `README.md` | This document. |
