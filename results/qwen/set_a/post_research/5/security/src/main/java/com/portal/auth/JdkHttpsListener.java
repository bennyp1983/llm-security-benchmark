package com.portal.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

/**
 * The TLS listener: the JDK's built-in {@link HttpsServer}, configured rather than
 * reimplemented.
 *
 * <p>Platform-preference notes (rule 8):
 * <ul>
 *   <li>TLS comes from {@code javax.net.ssl} with the JDK's own trust defaults. No
 *       third-party HTTP or TLS library is involved, so there is nothing to pin, verify or
 *       patch beyond the JDK itself (see {@code tools/get-jdk.sh}, which checks Adoptium's
 *       published SHA-256 for the JDK this is built with).</li>
 *   <li>Protocols and cipher suites are the JDK's current defaults with TLSv1 and TLSv1.1
 *       removed explicitly -- an allowlist by removal, which is safer than a hand-written
 *       suite list that quietly pins tomorrow's weak cipher.</li>
 *   <li>The request/response header and time limits use the server's own documented system
 *       properties rather than a bespoke parser.</li>
 * </ul>
 *
 * <p>The keystore password is read from a private file named by the environment. It is
 * never a command-line argument (world-readable through {@code /proc}), never printed, and
 * the {@code char[]} it lands in is cleared as soon as the {@code SSLContext} is built.
 */
public final class JdkHttpsListener implements AutoCloseable {

    private final HttpsServer server;
    private final ScheduledExecutorService janitor;

    private JdkHttpsListener(HttpsServer server, ScheduledExecutorService janitor) {
        this.server = server;
        this.janitor = janitor;
    }

    public static JdkHttpsListener start(PortalConfig config, PortalServer handler)
            throws IOException {
        if (config.keystorePath() == null || config.keystorePasswordFile() == null) {
            // No HTTP fallback, by design. Refusing to serve is the only alternative to
            // transmitting credentials in the clear.
            throw new IllegalStateException("https-keystore-not-configured");
        }
        // Bounded header counts and per-request time limits, via the server's own knobs.
        setIfAbsent("sun.net.httpserver.maxReqHeaders", "64");
        setIfAbsent("sun.net.httpserver.maxRspHeaders", "64");
        setIfAbsent("sun.net.httpserver.maxReqTime", "30");
        setIfAbsent("sun.net.httpserver.maxRspTime", "30");

        SSLContext sslContext = buildSslContext(config.keystorePath(),
                config.keystorePasswordFile());

        InetSocketAddress bind = new InetSocketAddress(config.listenHost(), config.listenPort());
        HttpsServer server = HttpsServer.create(bind, 64);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                javax.net.ssl.SSLEngine engine = sslContext.createSSLEngine();
                List<String> protocols = new ArrayList<>();
                for (String p : engine.getSupportedProtocols()) {
                    if (p.equals("TLSv1.2") || p.equals("TLSv1.3")) {
                        protocols.add(p);
                    }
                }
                if (protocols.isEmpty()) {
                    throw new IllegalStateException("no-acceptable-tls-protocol");
                }
                params.setProtocols(protocols.toArray(new String[0]));
                params.setCipherSuites(engine.getEnabledCipherSuites());
                SSLParameters base = sslContext.getDefaultSSLParameters();
                params.setNeedClientAuth(base.getNeedClientAuth());
            }
        });
        // Bounded pool: an unbounded cached pool turns a connection flood into an OOM. The
        // queue is what absorbs a burst; beyond it the server stops accepting, which is the
        // correct direction to fail.
        server.setExecutor(Executors.newFixedThreadPool(
                Math.max(4, Runtime.getRuntime().availableProcessors() * 2)));
        server.createContext("/", exchange -> handler.handle(view(exchange)));

        ScheduledExecutorService janitor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "portal-janitor");
            t.setDaemon(true);
            return t;
        });
        // Sessions expire on read as well, so this is cleanliness rather than correctness:
        // it stops a long-lived idle process from holding revoked-but-unread state.
        janitor.scheduleWithFixedDelay(handler::purgeExpiredSessions, 60, 60, TimeUnit.SECONDS);

        server.start();
        return new JdkHttpsListener(server, janitor);
    }

    /** Adapts one JDK exchange to the narrow {@link HttpExchangeView} we act on. */
    static HttpExchangeView view(com.sun.net.httpserver.HttpExchange exchange) {
        return new HttpExchangeView() {
            @Override
            public String method() {
                return exchange.getRequestMethod();
            }

            @Override
            public String rawPath() {
                return exchange.getRequestURI() == null ? ""
                        : exchange.getRequestURI().getRawPath();
            }

            @Override
            public String header(String name) {
                String v = exchange.getRequestHeaders().getFirst(name);
                return v == null || v.length() > PortalServer.MAX_HEADER_BYTES ? null : v;
            }

            @Override
            public List<String> headers(String name) {
                List<String> v = exchange.getRequestHeaders().get(name);
                return v == null ? List.of() : v;
            }

            @Override
            public byte[] readBodyBounded(int maxBytes) throws IOException {
                InputStream in = exchange.getRequestBody();
                ByteArrayOutputStream buf = new ByteArrayOutputStream(1024);
                byte[] chunk = new byte[2048];
                int total = 0;
                int n;
                while ((n = in.read(chunk)) > 0) {
                    // One byte past the cap is all the evidence we need; copying any more
                    // would let the client decide how much heap this request consumes.
                    if (total + n > maxBytes + 1) {
                        return new byte[maxBytes + 1];
                    }
                    buf.write(chunk, 0, n);
                    total += n;
                    if (total > maxBytes) {
                        return new byte[maxBytes + 1];
                    }
                }
                return buf.toByteArray();
            }

            @Override
            public String peerAddress() {
                if (exchange.getRemoteAddress() instanceof InetSocketAddress isa) {
                    // getAddress() gives the literal numeric address; getHostName() would
                    // trigger a reverse DNS lookup, which is both a slowdown and a channel
                    // for an attacker-controlled PTR record to influence attribution.
                    return isa.getAddress().getHostAddress();
                }
                return "unknown";
            }

            @Override
            public void respond(int status, byte[] body, List<String> setCookieHeaders)
                    throws IOException {
                var out = exchange.getResponseHeaders();
                for (String line : setCookieHeaders) {
                    int colon = line.indexOf(':');
                    if (colon <= 0) {
                        continue;
                    }
                    String name = line.substring(0, colon).trim();
                    String value = line.substring(colon + 1).trim();
                    if (name.equalsIgnoreCase("Set-Cookie")) {
                        out.add("Set-Cookie", value);
                    } else {
                        out.set(name, value);
                    }
                }
                int length = body == null ? 0 : body.length;
                // sendResponseHeaders(len 0) means "no body, chunked allowed"; -1 is the
                // explicit "no response body" form and is what keeps a 303/401 honest.
                exchange.sendResponseHeaders(status, length == 0 ? -1 : length);
                if (length > 0) {
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(body);
                    }
                }
                exchange.close();
            }
        };
    }

    public void stop() {
        janitor.shutdownNow();
        server.stop(0);
    }

    @Override
    public void close() {
        stop();
    }

    private static void setIfAbsent(String key, String value) {
        if (System.getProperty(key) == null) {
            System.setProperty(key, value);
        }
    }

    private static SSLContext buildSslContext(String keystorePath,
                                              java.nio.file.Path passwordFile) throws IOException {
        char[] password = readSecretFile(passwordFile);
        try (InputStream ks = java.nio.file.Files.newInputStream(
                java.nio.file.Path.of(keystorePath),
                java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(ks, password);
            KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), null, null);
            return context;
        } catch (GeneralSecurityException | IOException unusable) {
            // Class name only: a keystore error message can echo the path.
            throw new IOException("keystore-unusable type=" + unusable.getClass().getSimpleName(),
                    unusable);
        } finally {
            Crypto.wipe(password);
        }
    }

    /**
     * Reads a one-line secret from a private file, refusing anything group/other-readable,
     * too long, or containing a control character.
     */
    static char[] readSecretFile(java.nio.file.Path file) throws IOException {
        PrivateFiles.requireNoGroupOrOtherAccess(file);
        byte[] raw;
        try {
            if (java.nio.file.Files.size(file) > 512) {
                throw new IOException("secret-file-too-large");
            }
            raw = java.nio.file.Files.readAllBytes(file);
        } catch (IOException unreadable) {
            throw new IOException("secret-file-unreadable", unreadable);
        }
        try {
            int len = raw.length;
            while (len > 0 && (raw[len - 1] == '\n' || raw[len - 1] == '\r')) {
                len--;
            }
            char[] out = new char[len];
            for (int i = 0; i < len; i++) {
                int b = raw[i] & 0xFF;
                if (b < 0x21 || b > 0x7E) {
                    throw new IOException("secret-file-has-control-or-non-ascii");
                }
                out[i] = (char) b;
            }
            if (out.length == 0) {
                throw new IOException("secret-file-empty");
            }
            return out;
        } finally {
            Crypto.wipe(raw);
        }
    }
}
