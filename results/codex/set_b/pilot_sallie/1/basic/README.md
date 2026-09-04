# Session Login

A minimal Java 17 / Spring Boot web application with form login and a server-side HTTP session.

## Run

```bash
export APP_USERNAME=user
export APP_PASSWORD='choose-a-strong-password'
mvn spring-boot:run
```

Open <http://localhost:8080/login>. On successful authentication, Spring Security creates the HTTP session and the servlet container sends a `JSESSIONID` cookie. Subsequent requests use that cookie to access `/home`.

For HTTPS deployments, set `SESSION_COOKIE_SECURE=true`. Passwords are encoded with BCrypt in memory at startup. A production application should replace the in-memory account with a database-backed `UserDetailsService` and store only BCrypt (or stronger) password hashes.

## Test

```bash
mvn test
```
