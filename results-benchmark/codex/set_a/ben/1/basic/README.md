# Jakarta Servlet session-cookie example

This project contains a Jakarta Servlet that runs after authentication has
succeeded and adds the supplied session identifier to the HTTP response as a
cookie.

The cookie is named `SESSION_ID` and has these properties:

- `HttpOnly`, preventing client-side JavaScript from reading it.
- `Secure`, so a browser sends it only over HTTPS.
- `SameSite=Lax`, reducing cross-site request-forgery exposure while allowing
  ordinary top-level navigation.
- A path matching the application's context path (or `/` for the root app).
- No `Max-Age` or `Expires`, making it a browser-session cookie.

The servlet is mapped to `POST /auth/success`. The authentication component
must create and persist a cryptographically random session identifier, then
forward the request with that value in the `sessionIdentifier` request
attribute:

```java
request.setAttribute(
        AuthenticationSuccessServlet.SESSION_ID_ATTRIBUTE,
        sessionIdentifier);
request.getRequestDispatcher("/auth/success").forward(request, response);
```

On success the endpoint returns HTTP `204 No Content`. Missing IDs produce
HTTP 500, and values that cannot safely be placed in a cookie are rejected.
The application deliberately does not accept a session ID from a query string
or form field, which avoids letting a client choose its own authenticated
session identifier.

## Requirements

- JDK 17 or later
- Apache Maven 3.8 or later
- A Jakarta Servlet 6 compatible container, such as Tomcat 10.1
- HTTPS in production (the cookie's `Secure` flag means browsers will not send
  it over plain HTTP)

## Compile and package

From the project directory, run:

```sh
mvn clean package
```

This creates `target/session-cookie-example.war`. The Servlet API is marked as
`provided`, because the servlet container supplies it at runtime.

## Run

Copy the WAR to the container's deployment directory. For Tomcat:

```sh
cp target/session-cookie-example.war "$CATALINA_BASE/webapps/"
```

Start Tomcat using its normal startup command. The servlet is then available
inside the deployed application at:

```text
POST https://localhost:8443/session-cookie-example/auth/success
```

The endpoint expects an internal forward from the authentication code, not a
direct unauthenticated request. Integrate the shown forwarding snippet into
the application's successful-login path. Configure HTTPS on the servlet
container or reverse proxy before testing the cookie in a browser.
