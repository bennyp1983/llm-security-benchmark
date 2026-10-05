package com.example.security.session;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class SessionCookieEndpointTest {
    private static final String VALID = "0123456789abcdefghijklmnopqrstuvwxyz_AB-CDE";

    @Test
    void authorizesThroughStoreBeforeIssuingCookie() throws Exception {
        AtomicReference<StoreCall> call = new AtomicReference<>();
        SessionHandoffStore store = (id, wellFormed, source) -> {
            call.set(new StoreCall(id, wellFormed, source));
            return SessionHandoffStore.Decision.AUTHORIZE;
        };
        CapturedResponse captured = new CapturedResponse();

        endpoint(store).doPost(request(VALID, "192.0.2.10", true), captured.proxy());

        assertEquals(new StoreCall(VALID, true, "192.0.2.10"), call.get());
        assertEquals(204, captured.status);
        assertEquals(1, captured.cookies.size());
        assertEquals(VALID, captured.cookies.get(0).getValue());
        assertEquals("no-store, max-age=0", captured.headers.get("Cache-Control"));
        assertEquals(0, captured.body.size());
    }

    @Test
    void invalidInputUsesDummyWorkAndOneGenericFailure() throws Exception {
        AtomicReference<StoreCall> call = new AtomicReference<>();
        SessionHandoffStore store = (id, wellFormed, source) -> {
            call.set(new StoreCall(id, wellFormed, source));
            return SessionHandoffStore.Decision.AUTHORIZE; // must still fail closed
        };
        CapturedResponse captured = new CapturedResponse();

        endpoint(store).doPost(request("bad;value", "192.0.2.10", true), captured.proxy());

        assertEquals(new StoreCall(SessionCookiePolicy.DUMMY_SESSION_ID, false, "192.0.2.10"),
                call.get());
        assertEquals(401, captured.status);
        assertEquals("Authentication handoff failed.\n",
                captured.body.toString(StandardCharsets.UTF_8));
        assertEquals(0, captured.cookies.get(0).getMaxAge());
    }

    @Test
    void insecureTransportCannotConsumeRealHandoff() throws Exception {
        AtomicReference<StoreCall> call = new AtomicReference<>();
        CapturedResponse captured = new CapturedResponse();

        endpoint((id, wellFormed, source) -> {
            call.set(new StoreCall(id, wellFormed, source));
            return SessionHandoffStore.Decision.DENY;
        }).doPost(request(VALID, "192.0.2.10", false), captured.proxy());

        assertEquals(SessionCookiePolicy.DUMMY_SESSION_ID, call.get().id());
        assertFalse(call.get().wellFormed());
        assertEquals(401, captured.status);
    }

    private static SessionCookieEndpoint endpoint(SessionHandoffStore store) {
        return new SessionCookieEndpoint(store, System.getLogger("session-cookie-test"));
    }

    private static HttpServletRequest request(Object value, String remoteAddress, boolean secure) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                SessionCookieEndpointTest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getAttribute" -> SessionCookiePolicy.REQUEST_ATTRIBUTE.equals(args[0])
                            ? value : null;
                    case "getRemoteAddr" -> remoteAddress;
                    case "isSecure" -> secure;
                    default -> defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (type == void.class) return null;
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0F;
        if (type == double.class) return 0D;
        if (type == char.class) return '\0';
        throw new AssertionError("unknown primitive");
    }

    private record StoreCall(String id, boolean wellFormed, String source) {}

    private static final class CapturedResponse {
        int status;
        final List<Cookie> cookies = new ArrayList<>();
        final Map<String, String> headers = new HashMap<>();
        final ByteArrayOutputStream body = new ByteArrayOutputStream();

        HttpServletResponse proxy() {
            ServletOutputStream stream = new ServletOutputStream() {
                @Override public void write(int value) { body.write(value); }
                @Override public boolean isReady() { return true; }
                @Override public void setWriteListener(WriteListener listener) { /* synchronous */ }
            };
            return (HttpServletResponse) Proxy.newProxyInstance(
                    getClass().getClassLoader(), new Class<?>[]{HttpServletResponse.class},
                    (proxy, method, args) -> {
                        switch (method.getName()) {
                            case "isCommitted": return false;
                            case "reset":
                                status = 0;
                                cookies.clear();
                                headers.clear();
                                body.reset();
                                return null;
                            case "setHeader":
                                headers.put((String) args[0], (String) args[1]);
                                return null;
                            case "addCookie": cookies.add((Cookie) args[0]); return null;
                            case "setStatus": status = (int) args[0]; return null;
                            case "getOutputStream": return stream;
                            default: return defaultValue(method.getReturnType());
                        }
                    });
        }
    }
}
