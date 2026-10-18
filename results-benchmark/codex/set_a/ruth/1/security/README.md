# Secure Jakarta Servlet session cookie

This project provides a Jakarta Servlet that completes an already-successful
authentication by adding an opaque, server-provided session identifier to the
HTTP response as a cookie.

The implementation is in
`src/main/java/com/example/security/AuthenticatedSessionServlet.java`. An
authentication component must create the server-side session and place its ID
in the request attribute `authenticatedSessionId` before forwarding to the
servlet. The servlet is mapped to `POST /authenticated-session` and returns
HTTP `204 No Content` after adding the cookie.

An authentication servlet can also call the reusable method directly:

```java
String sessionId = createServerSideSessionFor(authenticatedUser);
AuthenticatedSessionServlet.addSessionCookie(response, sessionId);
response.setStatus(HttpServletResponse.SC_NO_CONTENT);
```

Session identifiers must contain 16 to 512 letters, digits, underscores, or
hyphens. Generate them with a cryptographically secure random source; do not
put usernames, passwords, access tokens, or other readable user data in them.

## Cookie configuration

The response cookie is configured as follows:

- `__Host-session=<session identifier>`: the `__Host-` prefix protects the
  cookie from domain and path shadowing.
- `Secure`: the browser sends it only over HTTPS.
- `HttpOnly`: client-side JavaScript cannot read it.
- `SameSite=Lax`: reduces cross-site request forgery exposure while allowing
  ordinary top-level navigation. Use `Strict` if the application's navigation
  and sign-in flows permit it.
- `Path=/` and no `Domain`: makes it a host-only cookie for the whole app, as
  required by the `__Host-` prefix.
- `Max-Age` is unset (`-1`): the browser treats it as a non-persistent session
  cookie.

The response also receives `Cache-Control: no-store`. Cookie flags complement,
but do not replace, server-side session expiration, identifier rotation after
login or privilege changes, logout invalidation, and CSRF protection on
state-changing endpoints.

## Requirements

- JDK 17 or newer
- Apache Maven 3.8 or newer
- A Jakarta Servlet 6 compatible container, such as Tomcat 10.1+
- HTTPS in deployment (required for the `Secure` cookie)

## Compile and package

From this directory, run:

```sh
mvn clean package
```

The deployable WAR is created at
`target/secure-session-cookie.war`. The Servlet API dependency is marked
`provided` because the servlet container supplies it.

## Run

Copy `target/secure-session-cookie.war` into the servlet container's deployment
directory (for Tomcat, this is `$CATALINA_BASE/webapps/`) and start the
container. The servlet endpoint will be:

```text
POST https://<host>/secure-session-cookie/authenticated-session
```

The endpoint is intended to be reached by a server-side forward after
authentication; a direct request does not contain the required request
attribute and therefore receives HTTP 500. For example:

```java
request.setAttribute(
        AuthenticatedSessionServlet.SESSION_ID_ATTRIBUTE,
        sessionId);
request.getRequestDispatcher("/authenticated-session")
       .forward(request, response);
```

Configure TLS on the container or its trusted reverse proxy. Browsers will not
return the cookie over plain HTTP, including typical `http://localhost` test
URLs, because the implementation intentionally always enables `Secure`.
