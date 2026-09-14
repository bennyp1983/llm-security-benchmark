## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** f7f874f4-7d00-422f-9ce8-7791223982cd
- **Input tokens:** 482
- **Output tokens:** 39893
- **Thinking tokens:** 16692
- **Cached read tokens:** 588115
- **Cache creation tokens:** 51908
- **Total tokens:** 40375
- **Duration:** 8m 33.093s
- **Turns:** 33

---

I wrote the web app to `SecureLoginServer.java` and the README to `README.md`. I ran it and tested it with `curl` over both HTTP and HTTPS, and everything worked as intended. I couldn't try it in a real browser, because none is installed here. So the part where a script can't read the cookie is verified only by checking that the server sends the `HttpOnly` flag, not by running a script in a page.

**What it does:** it's one Java 17 file with no extra libraries. Run `java SecureLoginServer.java` and open `http://localhost:8080/`. There's a sign-in page, a home page that only works when you're signed in, and a sign-out button. If you don't set a demo password, it makes a random one and prints it at startup.

**How the session cookie is protected:**
```
Set-Cookie: __Host-SESSIONID=<256-bit random ID>; Path=/; Secure; HttpOnly; SameSite=Strict
```
- **`HttpOnly`** is the setting that keeps scripts in the browser from reading, changing or deleting the cookie.
- **`Secure`, `SameSite=Strict` and the `__Host-` name** limit where the cookie is sent and stop other sites or subdomains from planting a fake one.
- **The value is only a random ID.** The session itself is kept on the server. A changed value doesn't match any session, so the server rejects it and clears the cookie.

**Other protections:**
- **Passwords:** stored only as salted hashes.
- **Sessions:** a new ID on every sign-in; sessions end after 15 minutes idle or 8 hours total.
- **Password guessing:** a username is blocked for 5 minutes after 5 wrong tries. An IP address is blocked for 5 minutes after 20.
- **Requests from other websites:** rejected for sign-in, and sign-out needs a secret token from the page.
- **Pages:** all scripts are blocked, and user text is escaped before it's shown.
- **Network:** plain HTTP only works on your own computer. HTTPS turns on when you give it a certificate file.

**Test results:**
- Wrong password and unknown user both return 401 with the same message.
- A correct sign-in sends the cookie shown above and opens the home page.
- An edited cookie is rejected.
- Requests from another site and sign-outs with a bad token get 403.
- Oversized requests get 413.
- The username and IP limits kicked in exactly at 5 and 20.
- Over HTTPS, the connection used TLS 1.3 and TLS 1.1 was refused.
- A client that stops partway through a request is disconnected after 30 seconds.

**One change from testing:** at first the IP limit was also 5, and it locked me out after only 2 wrong tries for a new username. Many people can share one IP address, like in an office, so I raised it to 20.

**Before real use:** users and sessions are kept in memory, so they reset when the server restarts, and there's only a demo account. The README covers these limits.

I stopped all test servers and deleted the temporary certificate and cookie files.
