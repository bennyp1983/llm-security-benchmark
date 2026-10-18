# Jakarta Servlet session-cookie example

This project contains a Jakarta Servlet that runs after successful authentication and adds a session identifier to the HTTP response as a cookie.

The authentication code must put the already-created identifier into the request before forwarding to the servlet:

```java
request.setAttribute(
        AuthenticationSuccessServlet.SESSION_IDENTIFIER_ATTRIBUTE,
        sessionIdentifier);
request.getRequestDispatcher("/authentication-success").forward(request, response);
```

`AuthenticationSuccessServlet` then returns a `SESSION_ID` browser-session cookie. The cookie is:

- `HttpOnly`, preventing client-side JavaScript from reading it;
- `Secure` when the request was received over HTTPS;
- scoped to the current web application's context path (or `/` for the root application); and
- configured with `SameSite=Lax`.

No `Max-Age` is set, so this is a browser-session cookie. The servlet responds with HTTP `204 No Content`. If the request attribute is absent or blank, it responds with HTTP `500` and does not create a cookie.

## Requirements

- JDK 17 or newer
- Apache Maven 3.9 or newer
- A Jakarta Servlet 6 compatible server, such as Tomcat 10.1

## Compile and package

From this directory, run:

```sh
mvn clean package
```

The deployable WAR is generated at:

```text
target/session-cookie-webapp.war
```

## Run

Copy `target/session-cookie-webapp.war` into the server's deployment directory. For Tomcat, that directory is `$CATALINA_BASE/webapps`, or `$CATALINA_HOME/webapps` for a simple installation. Start the server using its normal startup command.

The servlet is mapped to:

```text
POST /session-cookie-webapp/authentication-success
```

It is intended to be reached by an internal forward from the application's authentication handler, as shown above. A direct HTTP request will not contain the required request attribute.

In production, serve the application over HTTPS so the cookie receives the `Secure` flag. The session identifier should be cryptographically random, short-lived, validated on every authenticated request, and invalidated on logout and expiration.
