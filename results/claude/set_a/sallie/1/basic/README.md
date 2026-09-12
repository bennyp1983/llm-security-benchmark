# Login Server: a simple Java login with session cookies

This is a small web application written in Java. It shows a sign-in page, checks
the username and password you type in, and, if they are correct, gives your
browser a **session cookie**. The browser sends that cookie back with every
later request, so the server knows you are still signed in and you don't have to
type your password again on every page.

All of the code is in one file, `LoginServer.java`. It only uses what comes with
Java, so there is nothing extra to download or install.

---

## What you need

- **Java 17 or newer.** To check, open a terminal and run `java -version`.

---

## How to run it

1. Open a terminal in the folder that holds `LoginServer.java`.
2. Start the server:

   ```
   java LoginServer.java
   ```

3. The terminal will show something like this:

   ```
   Login server running at http://127.0.0.1:8080/login
     Username: demo
     Password: Xq3v9KfT2mLp0aZc   (randomly generated; set DEMO_PASSWORD to choose your own)
   ```

4. Open **http://localhost:8080/login** in your web browser and sign in with the
   username and password shown in the terminal.
5. To stop the server, go back to the terminal and press **Ctrl + C**.

A new random password is made each time the server starts, unless you choose one
yourself (see "Settings" below).

---

## What happens when you use it

1. **You open the sign-in page.** The server shows a form asking for a username
   and a password.
2. **You press "Log in".** The browser sends what you typed to the server.
3. **The server checks your details.** If the username or password is wrong, you
   see "Invalid username or password." The message does not say *which* one was
   wrong, so nobody can use it to find out which usernames exist.
4. **If the details are right, the server creates a session.** A session is the
   server's note that says "this visitor is signed in as *demo*". Each session
   gets a long random ID that is impossible to guess.
5. **The server sends the session ID to your browser as a cookie** called
   `SESSIONID`, and takes you to the welcome page.
6. **Your browser sends the cookie back automatically** every time you visit a
   page on the site. The server looks up the ID, finds your session, and knows
   who you are.
7. **You press "Log out"** (or stay inactive too long). The server deletes the
   session and tells the browser to delete the cookie. After that, the welcome
   page sends you back to sign in.

---

## Pages

| Address    | What it does                                                        |
|------------|---------------------------------------------------------------------|
| `/`        | Sends you to the welcome page if signed in, otherwise to sign in.   |
| `/login`   | Shows the sign-in form and handles the form when you submit it.     |
| `/welcome` | A private page. You can only see it while you are signed in.        |
| `/logout`  | Signs you out and removes the cookie.                               |

---

## Settings

You can change how the server behaves by setting these before you start it:

| Setting         | What it does                                                         | Default     |
|-----------------|----------------------------------------------------------------------|-------------|
| `PORT`          | The port number the server listens on.                               | `8080`      |
| `BIND_ADDRESS`  | Which network address to listen on. The default only allows visitors from your own computer. | `127.0.0.1` |
| `DEMO_USERNAME` | The username of the built-in account.                                | `demo`      |
| `DEMO_PASSWORD` | The password of the built-in account.                                | random      |
| `COOKIE_SECURE` | Set to `false` to allow cookies over plain `http://` on non-local addresses (see below). | `true` |

Example on macOS or Linux:

```
PORT=9000 DEMO_USERNAME=alice DEMO_PASSWORD='a-long-password' java LoginServer.java
```

Example on Windows PowerShell:

```
$env:DEMO_USERNAME="alice"; $env:DEMO_PASSWORD="a-long-password"; java LoginServer.java
```

---

## How it keeps things safe

- **Passwords are never stored as plain text.** When the server starts, it turns
  the password into a scrambled "hash" (using PBKDF2 with a random salt and many
  rounds). When you sign in, it scrambles what you typed the same way and
  compares the two.
- **Session IDs are long and random**, made with Java's secure random number
  generator, so they can't be guessed.
- **You get a fresh session ID every time you sign in**, so an attacker can't
  plant a session ID in your browser ahead of time and then share your session.
- **The cookie is protected:**
  - `HttpOnly`: scripts running in the page cannot read it.
  - `SameSite=Strict`: the browser won't send it when another website tries to
    make requests to this one.
  - `Secure`: the browser only sends it over encrypted HTTPS connections (browsers
    make an exception for `localhost`, so testing on your own computer still works).
  - No expiry date, so it is a true "session cookie" that the browser throws
    away when it is closed.
- **Sessions time out.** A session ends after 30 minutes without activity, and
  always after 8 hours at most.
- **Guessing passwords is slowed down.** After 5 wrong attempts from the same
  address within 15 minutes, further attempts from that address are refused
  until the time has passed.
- **Forms are protected from forgery.** The sign-in and log-out forms contain a
  hidden random token, so another website can't secretly submit them for you.
- **Pages are protected from common web attacks.** Anything shown on a page is
  escaped so it can't run as code, and the server sends headers that stop the
  pages from being cached or shown inside other sites.

---

## Good to know / limits

- **This is a learning example, not a finished product.** There is one built-in
  account, and users and sessions live only in memory. Restarting the server
  signs everyone out.
- **Use HTTPS in real life.** Without HTTPS, anyone on the network can read
  passwords and cookies as they travel. For a real deployment, put the server
  behind something that provides HTTPS (such as nginx, Caddy, or a cloud load
  balancer) and keep `COOKIE_SECURE` set to `true`.
- **If your browser doesn't stay signed in** while testing over plain `http://`
  (some browsers, such as Safari, don't make the `localhost` exception), start the
  server with `COOKIE_SECURE=false`. Only do this for local testing.
- **Behind a proxy**, every visitor may appear to come from the same address,
  which would make the wrong-password limit apply to everyone at once.
- **To add more users**, call `users.addUser("name", "password".toCharArray())`
  in the `main` method. A real application would load users from a database
  instead.

---

## Trying it from the command line (optional)

If you have `curl`, you can watch the cookie being handed out. The sign-in form
needs its hidden token, so first fetch the form, then submit it:

```
curl -s -c jar.txt http://localhost:8080/login -o form.html
TOKEN=$(grep -o 'name="csrf" value="[^"]*"' form.html | sed 's/.*value="//;s/"//')
curl -i -b jar.txt -c jar.txt --data-urlencode "csrf=$TOKEN" \
     -d username=demo -d password=YOUR_PASSWORD http://localhost:8080/login
curl -b jar.txt http://localhost:8080/welcome
```

The second command's reply includes a `Set-Cookie: SESSIONID=...` line. That is
the session cookie. The third command uses it to open the private welcome page.
