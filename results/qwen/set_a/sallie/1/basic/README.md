# Signing people in, and handing the browser a session cookie

A small Java web application that does one job properly: somebody types a username and a password,
the server checks them, and on success the browser gets a cookie that says "this visitor is signed
in" for as long as the session lasts.

It is a plain Servlet application (Jakarta Servlet 6.0, Java 17) that runs in any Servlet container —
Tomcat 10.1 or newer, Jetty 11 or newer, WildFly. No Spring, no build tool, no database.

---

## The short version

```sh
./build.sh              # compile and package build/session-cookie-auth-demo.war
./run-demo.sh           # start a throwaway Tomcat and walk through one whole sign-in with curl
./tests/unit-checks.sh  # 67 checks on the parts that need no server
./tests/end-to-end.sh   # 69 checks against the real server, driven by curl
```

Then open `http://localhost:8181/app/login` (the port is `8181` unless you pass `HTTP_PORT`) and sign
in as:

| Username | Password           | Roles        |
|----------|--------------------|--------------|
| `alice`  | `Alice!2345`       | admin, user  |
| `bob`    | `B0b-the-Builder`  | user         |

---

## Where the code is

Everything is under `src/main/java`. Nothing is generated; these are the files.

| File | What it is for |
|------|----------------|
| `com/example/auth/web/LoginServlet.java` | Shows the sign-in form, checks the credentials, issues the cookie. **The heart of the answer to this task.** |
| `com/example/auth/web/AccountServlet.java` | A page that only renders when the cookie names a live session |
| `com/example/auth/web/AuthFilter.java` | The gate in front of every page that needs an identity |
| `com/example/auth/web/LogoutServlet.java` | Ends the session and clears the cookie |
| `com/example/auth/web/StatusServlet.java` | Says how the application is configured, as JSON |
| `com/example/auth/web/Cookies.java` | Reading and writing the one cookie this app cares about |
| `com/example/auth/web/AuthContext.java` | Builds the collaborators at startup from `web.xml` settings |
| `com/example/auth/web/LoginThrottle.java` | Counts failed attempts and locks a caller out for a while |
| `com/example/auth/PasswordService.java` | Turns passwords into verifiable records and back |
| `com/example/auth/SessionStore.java` | Session records: which cookie belongs to whom, and until when |
| `com/example/auth/UserStore.java`, `InMemoryUserStore.java`, `AuthenticatedUser.java` | The accounts, behind an interface |

Supporting files:

- `src/main/webapp/WEB-INF/web.xml` — settings: password cost, session lifetimes, lockout, accounts
- `build.sh` — compiles and packages the war
- `run-demo.sh` — starts Tomcat and narrates one sign-in with `curl`
- `tests/java/UnitChecks.java`, `tests/unit-checks.sh` — checks that need no server, no port, no network
- `tests/end-to-end.sh` — the checks against the running server, below
- `tools/tomcat-env.sh` — Tomcat start/stop plumbing shared by the two scripts above

---

## What happens, step by step

1. **`GET /login`.** The server makes up a random 32-byte identifier, writes it as the `app_session`
   cookie, and remembers *nothing* about who is signed in — the record behind that cookie is
   anonymous and exists only to hold a single-use token that is embedded in the form.

2. **`POST /login` with the form.** The server checks the token, then looks up the account, re-runs
   the password stretching with that account's own salt and cost, and compares the two digests in a
   way whose duration does not depend on where the first differing byte is.

3. **On success:** the anonymous record and its identifier are thrown away, a **brand-new** random
   identifier is generated, the identity is stored against it, and it is sent to the browser as
   `Set-Cookie: app_session=...; Path=/app; HttpOnly; SameSite=Lax`. The browser is redirected to
   `/account`.

   The identifier that existed *before* the credentials were proven never survives the login. That
   single rule is what stops session fixation: an attacker who tricks a victim into starting with a
   known cookie value finds that value discarded the moment the victim signs in.

4. **`GET /account` later.** The browser sends the cookie automatically. `AuthFilter` looks the value
   up in `SessionStore`; a hit means the request continues, a miss means a redirect back to the
   sign-in page (or a `401` with a JSON body, when the caller is a script rather than a browser
   navigating a page). Nothing about identity is read from any other request header, parameter, or
   hidden form field — the cookie is the whole story.

5. **`POST /logout`.** The server deletes the record and re-issues the cookie with `Max-Age=0`, so
   the browser drops it. Even a copy of the old value is now worthless: the server has nothing to
   match it against.

---

## What the cookie looks like on the wire

```
Set-Cookie: app_session=tPqI_q5Q52lb7k58amqwHtMwiTV0FjZrPhi6uHJ3oG8; Path=/app; HttpOnly; SameSite=Lax
```

- **`HttpOnly`** — page script cannot read it, so a cross-site scripting bug on some other page of
  the site cannot simply copy the session out.
- **`SameSite=Lax`** — a form posted from somebody else's site does not carry it, which kills most
  cross-site request forgery before it starts.
- **`Secure`** — added automatically whenever the request arrived over HTTPS.
- **`Path=/app`** — sent only to this application, not to every application on the host.
- **No `Expires`/`Max-Age`** by default — a "session cookie" in the browser's own sense: closing the
  browser ends it.
- **`Max-Age`** only when "Keep me signed in" is ticked, and then with a lifetime the *server* decided,
  never longer than the absolute session timeout.

The value is 43 Base64url characters: 256 bits from `SecureRandom`. It is not derived from the
username or the time, and it is never printed inside a page — which the tests check, because
`HttpOnly` is worth little if the application helpfully writes the identifier into the HTML.

---

## Decisions worth explaining

**Sessions are kept server-side, in `SessionStore`, not in the container's `HttpSession`.** The
cookie carries an opaque identifier and nothing else; the identity lives in memory on the server,
keyed by it. It also means the parts worth testing — expiry, session-fixation protection, the lockout
— can be tested at all. A real deployment would put these records in Redis or a database so several
servers can share them.

**Passwords are stretched with PBKDF2-HMAC-SHA256, 240 000 iterations, 16-byte random salt per
account,** and stored as `pbkdf2-sha256$iterations$base64(salt)$base64(digest)`. Each record carries
its own salt and cost, so raising the number later does not break existing accounts: an old record
still verifies at its own cost. What the format makes possible — re-storing an account at the new cost
the next time its owner signs in — this demo does not do, because it has no account to write back to;
see "What this is not". The comparison uses `MessageDigest.isEqual`.

**Some passwords are refused rather than stored, because the JDK cannot tell them apart from other
passwords.** Measured on this JDK's `PBKDF2WithHmacSHA256`: it throws away NUL bytes at the end of the
character array, so `abc` and `abc`-followed-by-a-NUL stretch to the *same* digest; and it encodes an
unpaired surrogate half as a `?`, so `p` plus half of an emoji and `p?` stretch to the same digest too.
Someone allowed to store `abc<NUL>` would find that `abc` opens their account. So `PasswordService`
rejects the ambiguous shapes — empty, trailing NUL, unpaired surrogate half — on the way *in*
(`hash()` refuses to store them) and refuses them on the way out (`verify()` will not accept them),
while leaving alone the shapes that do survive the stretch, such as a NUL in the middle of a password.
A refused attempt is not a shortcut: it is charged a full stretching run whose result is thrown away,
so a rejected sign-in takes the same time whichever reason caused the rejection. Delete the one
condition in `verify()` and `abc<NUL>` verifies against `abc`'s record — the unit checks pin that down.

**A wrong password and an unknown username answer identically**, and the unknown-username path still
pays a full stretching cost. Without that, the endpoint answers "is this username taken?" for
free — either from the wording or from a stopwatch. `./tests/end-to-end.sh` times both paths and
fails if they diverge.

**Failures are counted.** Five rejections for one username within 15 minutes earns a 15-minute
lockout for that caller and username together, with a `429` and a `Retry-After` header — and the
lockout refuses even a *correct* password, because its job is to slow the guesser down, not to be
polite.

**Everything is denied by default.** `AuthFilter` covers `/*` and lets through only `/login`,
`/logout`, `/status` and `/favicon.ico`. A new endpoint is behind the gate the moment it exists,
rather than after somebody remembers to add it to a list.

**No `jsessionid` in URLs.** `web.xml` sets `tracking-mode` to `COOKIE` only. A session identifier in
a link leaks into browser history, proxy logs and `Referer` headers.

**Output is escaped, not assembled.** Usernames and messages pass through `Html.escape` before they
reach a page, and the JSON status body goes through `Json.quote`.

---

## How to run it

### Build

```sh
./build.sh
```

Needs a JDK 17 or newer and a Servlet 6.0 (`jakarta.*`) API jar. The jar is *found*, not hardcoded:
`SERVLET_API_JAR=/path/to/jar ./build.sh` wins if set, otherwise `build.sh` looks in the usual Tomcat
places. It refuses a jar that has no `jakarta/servlet/http/Cookie.class` in it — a Tomcat 9 jar sits
at the same path and compiles nothing useful, because it still carries the old `javax.*` namespace.

It compiles with `-Xlint:all -Werror`, so a warning fails the build. Sources are ASCII-only, so the
build needs no `-encoding` flag on any console. The compiled classes are left in `build/classes`,
which is what the unit checks run against.

### Check it

```sh
./tests/unit-checks.sh   # quick, no server
./tests/end-to-end.sh    # builds, deploys, drives a throwaway Tomcat
```

### Try it

```sh
./run-demo.sh
```

Deploys the war into a **throwaway** Tomcat under `build/tomcat` (your Tomcat installation is never
touched), then prints the whole exchange: the settings, the refusal without a cookie, the cookie the
sign-in page sets, the `302` on success, the protected page, the sign-out, and the same request
refused afterwards. Add `--keep-open` to leave the server running so you can poke at it.

```
TOMCAT_HOME=/opt/tomcat HTTP_PORT=9090 ./run-demo.sh
```

To use a particular Tomcat or port. If a port is taken, the script says so rather than borrowing it
silently — and it only counts a port as taken when something is *listening* on it, which matters
because a port held by yesterday's closed connections looks busy to a careless check for minutes.

Or deploy `build/session-cookie-auth-demo.war` into your own container's deployment directory.

### Accounts

Seeded from `web.xml`, `seed.user.<name>` parameters, format `password | role,role`. Stretched at
startup and held in memory; gone on restart. These are throwaway credentials for a demo, and the
shape of the thing is what matters: in a real deployment the accounts come from a database and
nothing password-shaped appears in a deployment descriptor.

---

## What the tests actually check

There are two suites, and they check different kinds of claim.

**`./tests/unit-checks.sh`** (67 checks) compiles `tests/java/UnitChecks.java` against the classes
`build.sh` produced and runs it in a plain JVM — no Tomcat, no port, no network. It covers the claims
that are awkward to observe from `curl`: which password shapes the JDK would silently merge together,
that a stored record round-trips through its text form and that a stray character appended to it is
rejected rather than quietly decoded, that a record never prints its own salt or digest, that sessions
expire on schedule and that a persistent session keeps its absolute deadline when it is touched, that a
form token cannot be spent twice, and the lockout arithmetic — including that a lockout leaves a
different username, or a different caller, alone.

**`./tests/end-to-end.sh`** (69 checks) builds the war, deploys it into a throwaway Tomcat, drives it
with `curl` and asserts on the bytes that came back — status line, `Set-Cookie` attributes, `Location`,
body, elapsed time. It reasons about nothing; if the container disagrees with what the code appears to
say, the test finds out. Both suites pass, and both are stable across repeated runs.

Highlights from the end-to-end run:

- `HttpOnly`, `SameSite=Lax` and `Path=/app` are really on the `Set-Cookie` line the container sent.
- The identifier that survives login differs from the one the sign-in page was given.
- An identifier of the right shape that this server never issued gets bounced.
- The same identifier, replayed by hand after sign-out, still gets bounced.
- Two browsers signed in as the same user are independent: signing one out leaves the other working.
- "Keep me signed in" produces a `Max-Age` inside the 8-hour ceiling.
- A wrong password and a nonexistent username return the same status, the same message, **and the
  same duration** — and a rejected attempt really does spend the stretching time, so the timing
  check cannot be satisfied by a stub.
- A form token posted twice is honoured once.
- `GET /logout` is refused with `405`: a link or an `<img>` tag cannot sign anybody out.
- After five rejections, the *correct* password is refused too, with `429` and `Retry-After`.
- Neither the session identifier nor any account detail appears in a page or in the public status
  output.

---

## What this is not

A framework, or something to deploy as-is. What it would need before facing the internet:

- **HTTPS, really** — a TLS terminator in front, `Secure` cookies, HSTS, HTTP refused.
- **A real account store** — a database, with an upsert-and-upgrade path, instead of `web.xml`.
- **Shared session storage** — Redis or similar, so requests can land on any server, plus a way to
  revoke every session for one user.
- **A modern password hash** — Argon2id or scrypt if a vetted library is available; the per-record
  cost field is already there so records can migrate as the algorithm changes.
- **Rate limiting at the edge**, account-recovery flows, an audit trail of sign-ins, and a Content
  Security Policy once there is real page script to govern.

The session cookie handling itself is the part worth reading; the rest is scaffolding to make it
runnable and testable as one thing.
