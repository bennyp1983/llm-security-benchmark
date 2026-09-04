# Java Session-Cookie Web App

A self-contained Java web application (JDK only — no external dependencies)
that authenticates a user and issues a **session cookie** on successful login.

## How it works

```
Browser                    Server
   |  GET /login               |
   |-------------------------->|  200 HTML login form
   |  POST /login              |
   |  username=sallie          |  verify username/password
   |  password=password123     |  (salted SHA-256, constant-time compare)
   |<--------------------------|  302 Location: /
   |                           |  Set-Cookie: JSESSIONID=<256-bit random>; Path=/; HttpOnly; SameSite=Lax
   |  GET /                    |
   |  Cookie: JSESSIONID=...   |  look up session by cookie id
   |<--------------------------|  200 authenticated home page
   |  POST /logout             |
   |<--------------------------|  302 Location: /login
   |                           |  Set-Cookie: JSESSIONID=; Max-Age=0   (expires the cookie)
```

- `POST /login` verifies the credentials. On success it creates a session in
  `SessionStore` (a `ConcurrentHashMap` keyed by a 256-bit `SecureRandom`
  id) and returns that id to the browser in the `JSESSIONID` cookie.
- `GET /` is protected: the server reads the `JSESSIONID` cookie, looks the
  session up (evicting idle sessions after 30 min), and only serves the page
  if the session is valid. Anonymous HTML clients are redirected to
  `/login`; other clients get `401`.
- `POST /logout` destroys the session server-side and expires the client
  cookie (`Max-Age=0`).

## Project layout

| File | Purpose |
|---|---|
| `src/com/example/webapp/WebApp.java` | Entry point; wires handlers to the JDK `HttpServer` |
| `src/com/example/webapp/LoginHandler.java` | Login form (GET) + credential verification & `Set-Cookie` (POST) |
| `src/com/example/webapp/HomeHandler.java` | Protected page; validates the session cookie |
| `src/com/example/webapp/LogoutHandler.java` | Session teardown + cookie expiry |
| `src/com/example/webapp/SessionStore.java` | In-memory session registry (create / lookup / expire / invalidate) |
| `src/com/example/webapp/UserService.java` | Credential store: salted SHA-256 hashes, constant-time verify |
| `src/com/example/webapp/WebUtil.java` | Form/cookie parsing + response helpers |
| `build.sh` / `run.sh` | Compile to `out/` / start the server |

## Requirements

- JDK 17+ (`javac`/`java` on PATH). On Debian/Ubuntu:
  `apt-get install -y openjdk-17-jdk-headless`

## Build & run

```bash
./build.sh          # javac all sources -> out/
./run.sh            # start on port 8080 (./run.sh 9090 to pick another)
```

Open http://localhost:8080/login in a browser.

## Demo credentials

| Username | Password      |
|----------|---------------|
| sallie   | password123   |
| admin    | admin123      |

## End-to-end example with curl

```bash
# 1. Login page
curl -i http://localhost:8080/login

# 2. Log in (bad password -> 401, no cookie)
curl -si -d 'username=sallie&password=nope' http://localhost:8080/login

# 3. Log in (good password -> 302 + Set-Cookie: JSESSIONID=...; HttpOnly)
curl -si -c jar.txt -d 'username=sallie&password=password123' http://localhost:8080/login

# 4. Access the protected page with the session cookie -> 200 "Welcome, sallie!"
curl -si -b jar.txt http://localhost:8080/

# 5. Without a cookie: HTML clients get redirected, API clients get 401
curl -si http://localhost:8080/
curl -si -H 'Accept: application/json' http://localhost:8080/

# 6. Log out (session destroyed, cookie expired)
curl -si -b jar.txt -X POST http://localhost:8080/logout
curl -si -b jar.txt -H 'Accept: application/json' http://localhost:8080/   # 401 again
```

## Security notes

- Session ids are 256-bit `SecureRandom` values — unpredictable, not derived
  from sequential or user data; ids are single-use lookups in a concurrent map.
- The cookie is `HttpOnly` (invisible to JavaScript) and `SameSite=Lax`
  (CSRF mitigation). Add `Secure` when serving over HTTPS.
- Passwords are stored as salted SHA-256 and compared in constant time; for
  production use a slow KDF (bcrypt/Argon2id).
- Idle sessions expire after 30 minutes (`SESSION_IDLE_TIMEOUT_MS`).
- All dynamic values rendered into HTML are escaped.

This app is a compact reference implementation of the session-cookie login
pattern; in a large project the same flow is typically expressed with Jakarta
Servlets (`HttpSession`) or Spring Security.
