package com.portal.auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Single entry point. {@code portal portal} runs the HTTPS listener, everything else is
 * the command line in {@link PortalCli}.
 *
 * <p>Startup is refuse-only: a missing data directory, an insecure config/keystore file
 * mode, a roster record below the KDF floor, or a keystore we cannot open all end the
 * process with a machine token and exit code 2. No branch here falls back to a weaker
 * configuration in order to keep running.
 */
public final class Main {

    private static final String PORTAL_SUBCOMMAND = "portal";

    public static void main(String[] argv) {
        List<String> args = new ArrayList<>(List.of(argv));
        boolean servePortal = !args.isEmpty() && args.get(0).equals(PORTAL_SUBCOMMAND);

        PortalConfig config;
        try {
            config = PortalConfig.fromEnvironment();
        } catch (RuntimeException refusal) {
            System.err.println("startup-refused reason=" + safeToken(refusal.getMessage()));
            System.exit(2);
            return;
        }

        if (!servePortal) {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(System.in, StandardCharsets.UTF_8));
            int code = new PortalCli(config, System.out, reader, System.console()).run(args);
            System.exit(code);
            return;
        }

        args.remove(0);
        if (!args.isEmpty()) {
            System.err.println("startup-refused reason=unexpected-argument");
            System.exit(2);
            return;
        }
        try {
            PortalRuntime runtime = PortalRuntime.open(config);
            PortalServer handler = new PortalServer(runtime, config);
            JdkHttpsListener listener = JdkHttpsListener.start(config, handler);
            // Host and port are operational facts, not secrets; nothing else is printed.
            System.out.println("portal listening on " + config.listenHost() + ":"
                    + config.listenPort() + " (https)");
            Runtime.getRuntime().addShutdownHook(new Thread(listener::stop, "portal-stop"));
        } catch (IllegalStateException refusal) {
            System.err.println("startup-refused reason=" + safeToken(refusal.getMessage()));
            System.exit(2);
        } catch (IOException failure) {
            System.err.println("startup-refused reason=" + safeToken(failure.getMessage()));
            System.exit(2);
        }
    }

    /**
     * One redaction rule for the whole program, delegated so the CLI and the listener
     * cannot drift apart -- see {@link PortalCli#safeToken}.
     */
    private static String safeToken(String message) {
        return PortalCli.safeToken(message);
    }
}
