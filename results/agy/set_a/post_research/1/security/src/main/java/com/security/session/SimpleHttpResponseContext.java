package com.security.session;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * In-memory implementation of HttpResponseContext for testing and non-servlet environments.
 */
public class SimpleHttpResponseContext implements HttpResponseContext {

    private int status = 200;
    private final Map<String, List<String>> headers = new HashMap<>();
    private String body;

    @Override
    public void setHeader(String name, String value) {
        List<String> list = new ArrayList<>();
        list.add(value);
        headers.put(name.toLowerCase(), list);
    }

    @Override
    public void addHeader(String name, String value) {
        headers.computeIfAbsent(name.toLowerCase(), k -> new ArrayList<>()).add(value);
    }

    @Override
    public void setStatus(int statusCode) {
        this.status = statusCode;
    }

    @Override
    public void writeJsonBody(String body) {
        this.body = body;
    }

    public int getStatus() {
        return status;
    }

    public String getHeader(String name) {
        List<String> list = headers.get(name.toLowerCase());
        return (list != null && !list.isEmpty()) ? list.get(list.size() - 1) : null;
    }

    public List<String> getHeaders(String name) {
        List<String> list = headers.get(name.toLowerCase());
        return (list != null) ? Collections.unmodifiableList(list) : Collections.emptyList();
    }

    public Map<String, List<String>> getAllHeaders() {
        return Collections.unmodifiableMap(headers);
    }

    public String getBody() {
        return body;
    }
}
