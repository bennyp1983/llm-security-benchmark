package com.example.auth.web;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal {@code HttpServletRequest}/{@code HttpServletResponse} stand-ins built on dynamic proxies,
 * which is enough to observe exactly what a servlet hands the container.
 */
final class ServletFakes {

    private ServletFakes() {
    }

    static final class ResponseLog {
        final List<Cookie> cookies = new ArrayList<>();
        final Map<String, String> headers = new LinkedHashMap<>();
        int status = HttpServletResponse.SC_OK;

        List<Cookie> cookiesNamed(String name) {
            return cookies.stream().filter(c -> name.equals(c.getName())).toList();
        }

        boolean sentActiveSessionCookie() {
            return cookies.stream().anyMatch(c -> c.getMaxAge() != 0);
        }
    }

    static final class RequestStub {
        final Map<String, Object> attributes = new LinkedHashMap<>();
        Cookie[] cookies;
        String requestedSessionId;
        boolean requestedSessionIdFromUrl;
        HttpSession preAuthSession;
        boolean createSessionRequested;
        boolean sessionInvalidated;

        RequestStub attribute(String name, Object value) {
            attributes.put(name, value);
            return this;
        }

        HttpServletRequest toRequest() {
            return (HttpServletRequest) proxy(HttpServletRequest.class, (proxy, method, args) -> {
                switch (method.getName()) {
                    case "getAttribute":
                        return attributes.get((String) args[0]);
                    case "getCookies":
                        return cookies;
                    case "getRequestedSessionId":
                        return requestedSessionId;
                    case "isRequestedSessionIdFromURL":
                        return requestedSessionIdFromUrl;
                    case "isRequestedSessionIdFromCookie":
                        return requestedSessionId != null && !requestedSessionIdFromUrl;
                    case "getSession":
                        if (args.length == 0 || (Boolean) args[0]) {
                            createSessionRequested = true;
                            return preAuthSession != null ? preAuthSession : newSession();
                        }
                        return preAuthSession;
                    default:
                        return defaultValue(method.getReturnType());
                }
            });
        }

        HttpSession newSession() {
            return (HttpSession) proxy(HttpSession.class, (proxy, method, args) -> {
                if ("invalidate".equals(method.getName())) {
                    sessionInvalidated = true;
                    preAuthSession = null;
                    return null;
                }
                return defaultValue(method.getReturnType());
            });
        }
    }

    static HttpServletResponse response(ResponseLog log) {
        return (HttpServletResponse) proxy(HttpServletResponse.class, (proxy, method, args) -> {
            switch (method.getName()) {
                case "addCookie":
                    log.cookies.add((Cookie) args[0]);
                    return null;
                case "setHeader":
                case "setIntHeader":
                case "setDateHeader":
                    log.headers.put((String) args[0], String.valueOf(args[1]));
                    return null;
                case "addHeader":
                    log.headers.merge((String) args[0], String.valueOf(args[1]), (a, b) -> a + ", " + b);
                    return null;
                case "containsHeader":
                    return log.headers.containsKey((String) args[0]);
                case "setStatus":
                    if (args.length == 1) {
                        log.status = (Integer) args[0];
                    }
                    return null;
                case "getStatus":
                    return log.status;
                case "isCommitted":
                    return Boolean.FALSE;
                default:
                    return defaultValue(method.getReturnType());
            }
        });
    }

    static HttpSession invalidatingSession(RequestStub stub) {
        HttpSession session = stub.newSession();
        stub.preAuthSession = session;
        return session;
    }

    private static Object proxy(Class<?> face, InvocationHandler handler) {
        return Proxy.newProxyInstance(face.getClassLoader(), new Class<?>[] {face}, (p, m, a) -> {
            if ("toString".equals(m.getName())) {
                return face.getSimpleName() + "$Fake";
            }
            if ("hashCode".equals(m.getName())) {
                return System.identityHashCode(p);
            }
            if ("equals".equals(m.getName())) {
                return p == a[0];
            }
            return handler.invoke(p, m, a);
        });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return Boolean.FALSE;
        }
        if (type == void.class) {
            return null;
        }
        return 0;
    }
}
