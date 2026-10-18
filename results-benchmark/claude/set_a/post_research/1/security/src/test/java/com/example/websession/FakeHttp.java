package com.example.websession;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Minimal servlet request/response doubles backed by dynamic proxies, so the tests do not
 * need a container. Only the methods this component calls are implemented.
 */
final class FakeHttp {

    private FakeHttp() {
    }

    static final class Request {
        final Map<String, Object> attributes = new HashMap<>();
        final Map<String, String> headers = new HashMap<>();
        String remoteAddr = "203.0.113.7";
        boolean secure = true;

        HttpServletRequest proxy() {
            InvocationHandler handler = (p, method, args) -> switch (method.getName()) {
                case "getAttribute" -> attributes.get((String) args[0]);
                case "setAttribute" -> {
                    attributes.put((String) args[0], args[1]);
                    yield null;
                }
                case "removeAttribute" -> {
                    attributes.remove((String) args[0]);
                    yield null;
                }
                case "getHeader" -> headers.get(((String) args[0]).toLowerCase(Locale.ROOT));
                case "getRemoteAddr" -> remoteAddr;
                case "isSecure" -> secure;
                case "toString" -> "FakeRequest";
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == args[0];
                default -> defaultFor(method);
            };
            return (HttpServletRequest) Proxy.newProxyInstance(
                    FakeHttp.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class}, handler);
        }

        Request header(String name, String value) {
            headers.put(name.toLowerCase(Locale.ROOT), value);
            return this;
        }
    }

    static final class Response {
        final Map<String, List<String>> headers = new HashMap<>();
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        int status = 200;
        boolean committed;

        HttpServletResponse proxy() {
            InvocationHandler handler = (p, method, args) -> switch (method.getName()) {
                case "setHeader" -> {
                    headers.put(key(args[0]), new ArrayList<>(List.of(String.valueOf(args[1]))));
                    yield null;
                }
                case "addHeader" -> {
                    headers.computeIfAbsent(key(args[0]), k -> new ArrayList<>()).add(String.valueOf(args[1]));
                    yield null;
                }
                case "containsHeader" -> headers.containsKey(key(args[0]));
                case "setStatus" -> {
                    status = (int) args[0];
                    yield null;
                }
                case "getStatus" -> status;
                case "isCommitted" -> committed;
                case "setContentType", "setContentLength", "setCharacterEncoding" -> null;
                case "getOutputStream" -> outputStream();
                case "toString" -> "FakeResponse";
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == args[0];
                default -> defaultFor(method);
            };
            return (HttpServletResponse) Proxy.newProxyInstance(
                    FakeHttp.class.getClassLoader(), new Class<?>[]{HttpServletResponse.class}, handler);
        }

        private ServletOutputStream outputStream() {
            return new ServletOutputStream() {
                @Override
                public void write(int b) {
                    body.write(b);
                    committed = true;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setWriteListener(WriteListener writeListener) {
                }
            };
        }

        List<String> setCookies() {
            return headers.getOrDefault("set-cookie", List.of());
        }

        String header(String name) {
            List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
            return values == null || values.isEmpty() ? null : values.get(0);
        }

        String bodyText() {
            return body.toString(StandardCharsets.UTF_8);
        }

        private static String key(Object name) {
            return String.valueOf(name).toLowerCase(Locale.ROOT);
        }
    }

    private static Object defaultFor(Method method) {
        Class<?> type = method.getReturnType();
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == void.class) {
            return null;
        }
        return 0;
    }
}
