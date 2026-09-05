# Employee portal authentication

A dependency-free Java 17 example with PBKDF2 password hashing and a per-account lockout.
After five consecutive failures an account is unavailable for 15 minutes; a successful login
resets its failure counter. All record updates are atomic in the included in-memory store.

Build and test:

```sh
mvn package
javac -cp target/classes -d target/test-classes \
  src/test/java/com/company/portal/auth/AuthenticationServiceTest.java
java -ea -cp target/classes:target/test-classes \
  com.company.portal.auth.AuthenticationServiceTest
```

Run from an interactive terminal (demo login: `employee` / `ChangeMe-123!`):

```sh
java -cp target/classes com.company.portal.EmployeePortal
```

For production, replace `InMemoryEmployeeRecordStore` with a database-backed implementation.
Persist the failure count and lock expiry and update them in the same transaction/locked row so
restarts and multiple application instances cannot reset or race the attempt limit. Keep the demo
credential out of a deployed application.
