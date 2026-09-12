package com.example.auth;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal stand-ins for the servlet interfaces, so the cookie behaviour can be asserted without a
 * servlet container. Every unstubbed method returns the type's default instead of throwing, which
 * keeps the doubles from failing on calls the production code happens to add later.
 */
final class ServletDoubles {

    private ServletDoubles() {
    }

    static final class RecordedResponse {
        final List<Cookie> cookies = new ArrayList<>();
        final Map<String, String> headers = new LinkedHashMap<>();
        final StringWriter body = new StringWriter();
        final PrintWriter writer = new PrintWriter(body);
        Integer status;
        Integer errorStatus;
        String errorMessage;

        Cookie onlyCookie() {
            if (cookies.size() != 1) {
                throw new AssertionError("expected exactly one cookie, got " + cookies);
            }
            return cookies.get(0);
        }
    }

    static HttpServletResponse response(RecordedResponse sink) {
        return (HttpServletResponse) Proxy.newProxyInstance(
                ServletDoubles.class.getClassLoader(),
                new Class<?>[] { HttpServletResponse.class },
                new Handler("response") {
                    @Override
                    Object handle(Method method, Object[] args) {
                        switch (method.getName()) {
                            case "addCookie":
                                sink.cookies.add((Cookie) args[0]);
                                return null;
                            case "setHeader":
                            case "addHeader":
                                sink.headers.put((String) args[0], (String) args[1]);
                                return null;
                            case "setStatus":
                                if (args.length == 1) {
                                    sink.status = (Integer) args[0];
                                }
                                return null;
                            case "sendError":
                                sink.errorStatus = (Integer) args[0];
                                sink.errorMessage = args.length > 1 ? (String) args[1] : null;
                                return null;
                            case "getWriter":
                                return sink.writer;
                            default:
                                return null;
                        }
                    }
                });
    }

    static HttpServletRequest request(Map<String, Object> attributes, Map<String, String[]> parameters,
            Cookie[] cookies) {
        Map<String, Object> attrs = attributes == null ? new HashMap<>() : attributes;
        Map<String, String[]> params = parameters == null ? new HashMap<>() : parameters;
        return (HttpServletRequest) Proxy.newProxyInstance(
                ServletDoubles.class.getClassLoader(),
                new Class<?>[] { HttpServletRequest.class },
                new Handler("request") {
                    @Override
                    Object handle(Method method, Object[] args) {
                        switch (method.getName()) {
                            case "getAttribute":
                                return attrs.get((String) args[0]);
                            case "getParameter":
                                String[] values = params.get((String) args[0]);
                                return (values == null || values.length == 0) ? null : values[0];
                            case "getParameterMap":
                                return params;
                            case "getCookies":
                                return cookies;
                            default:
                                return null;
                        }
                    }
                });
    }

    static ServletConfig servletConfig(Map<String, String> initParams) {
        Map<String, String> params = initParams == null ? new HashMap<>() : initParams;
        return (ServletConfig) Proxy.newProxyInstance(
                ServletDoubles.class.getClassLoader(),
                new Class<?>[] { ServletConfig.class },
                new Handler("config") {
                    @Override
                    Object handle(Method method, Object[] args) {
                        switch (method.getName()) {
                            case "getInitParameter":
                                return params.get((String) args[0]);
                            case "getInitParameterNames":
                                return java.util.Collections.enumeration(params.keySet());
                            case "getServletName":
                                return "test";
                            default:
                                return null;
                        }
                    }
                });
    }

    private abstract static class Handler implements InvocationHandler {
        private final String label;

        Handler(String label) {
            this.label = label;
        }

        @Override
        public final Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                case "toString":
                    return label;
                default:
                    break;
            }
            Object result = handle(method, args);
            return result != null ? result : defaultValue(method.getReturnType());
        }

        abstract Object handle(Method method, Object[] args);
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive() || type == void.class) {
            return null;
        }
        if (type == boolean.class) {
            return Boolean.FALSE;
        }
        if (type == char.class) {
            return (char) 0;
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == float.class) {
            return 0f;
        }
        return 0d;
    }
}
