## Run Metadata

- **CLI:** Claude Code
- **Set:** a
- **Status:** success
- **Output format:** json
- **Conversation ID:** 1090e642-bc1f-4b5b-b5f7-b0480dfb3fac
- **Input tokens:** 162
- **Output tokens:** 13880
- **Thinking tokens:** 732
- **Cached read tokens:** 112977
- **Cache creation tokens:** 19455
- **Total tokens:** 14042
- **Duration:** 3m 15.555s
- **Turns:** 8

---

I've written the login code and a README, and tested both. It compiles with no warnings when targeting Java 11 (checked on OpenJDK 17). The demo, the interactive mode and a set of lockout checks all behaved as expected.

**Files**
- `LoginService.java`: the whole implementation in one file, with no outside libraries.
- `README.md`: what the code does, how to compile and run it, and how to use it in an app.

**How logins are checked**
- Passwords are stored only as salted PBKDF2-SHA256 hashes and compared in a way that doesn't leak timing.
- A wrong password and an unknown username give the same "Invalid username or password" message.
- Unknown usernames still go through a full hash check, so response time doesn't reveal which accounts exist.

**How repeated failures are handled**
- **Two separate counters:** failures are counted per username (default limit 5) and per client address such as an IP (default limit 20). The address counter catches someone trying one password across many accounts.
- **Checked before the password:** during a lockout the attempt is refused without looking at the password. Guessing gets nowhere, and even the correct password is refused until the lock ends.
- **Lockouts grow but always end:** the first lock lasts 30 seconds and each new one doubles, up to 1 hour. An attacker can slow a real user down but can't lock them out for good.
- **Unknown usernames are locked too,** so a lockout message doesn't confirm that an account exists.
- **When counters reset:** a successful login clears that username's counter but not the address counter. Otherwise an attacker could log into their own account now and then to wipe their count. Old failures are forgotten after 15 quiet minutes.
- **Memory stays bounded:** the failure tables have a size cap, so flooding them with made-up usernames can't use up memory.

**What I ran**
- **Scripted demo:** a correct login worked, and an unknown user got the generic error. After 3 wrong passwords `bob` was locked, and his correct password was refused during the lock. It was accepted once the 5-second demo lock ended.
- **Lockout checks:** a separate script (kept outside the project folder) confirmed that:
  - locks go 30s → 60s → capped at the maximum;
  - unknown usernames get locked;
  - one address trying many usernames gets blocked, while other addresses are unaffected;
  - old failures are forgotten;
  - null input doesn't crash.

**To run it:**
```sh
javac LoginService.java
java LoginService                # scripted demo
java LoginService --interactive  # enter credentials yourself
```

Failure counters live in memory, so they reset on restart and aren't shared between servers. If you run more than one instance, they need a shared store such as Redis or a database; the README covers this.
