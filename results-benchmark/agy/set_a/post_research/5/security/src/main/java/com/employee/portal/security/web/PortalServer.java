package com.employee.portal.security.web;

import com.employee.portal.security.service.AuthenticationService;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Embedded HTTP server for employee portal authentication.
 * Uses standard library com.sun.net.httpserver (Rule 8).
 */
public final class PortalServer {

    private final HttpServer server;
    private final ExecutorService executor;

    public PortalServer(int port, AuthenticationService authService, boolean requireSecureCookies) throws IOException {
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.executor = Executors.newFixedThreadPool(8);
        this.server.setExecutor(executor);

        PortalHttpHandler handler = new PortalHttpHandler(authService, requireSecureCookies);
        this.server.createContext("/api/", handler);
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
        executor.shutdownNow();
    }

    public int getPort() {
        return server.getAddress().getPort();
    }
}
