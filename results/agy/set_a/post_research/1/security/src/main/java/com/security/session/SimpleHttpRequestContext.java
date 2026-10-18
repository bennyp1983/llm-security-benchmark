package com.security.session;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * In-memory implementation of HttpRequestContext, ideal for unit testing and framework adapters.
 */
public class SimpleHttpRequestContext implements HttpRequestContext {

    private final String remoteAddr;
    private final boolean secure;
    private final String method;
    private final Map<String, String> headers = new HashMap<>();

    public SimpleHttpRequestContext(String remoteAddr, boolean secure) {
        this(remoteAddr, secure, "POST");
    }

    public SimpleHttpRequestContext(String remoteAddr, boolean secure, String method) {
        this.remoteAddr = (remoteAddr != null) ? remoteAddr : "127.0.0.1";
        this.secure = secure;
        this.method = (method != null) ? method : "POST";
    }

    public void setHeader(String name, String value) {
        headers.put(name.toLowerCase(), value);
    }

    @Override
    public String getRemoteAddr() {
        return remoteAddr;
    }

    @Override
    public boolean isSecure() {
        return secure;
    }

    @Override
    public String getHeader(String name) {
        if (name == null) return null;
        return headers.get(name.toLowerCase());
    }

    @Override
    public String getMethod() {
        return method;
    }
}
