package com.example.auth;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * Sends diagnostics to stderr via java.util.logging. Diagnostics are for the operator:
 * the user-facing stdout messages never carry a reason, an address, or a token.
 */
final class LoggingSetup {

    private LoggingSetup() {
    }

    static void apply() {
        if (System.getProperty("java.util.logging.config.file") != null) {
            return; // operator-supplied configuration wins
        }
        Logger root = LogManager.getLogManager().getLogger("");
        for (Handler handler : root.getHandlers()) {
            root.removeHandler(handler);
        }
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.INFO);
        root.addHandler(handler);
        root.setLevel(Level.INFO);
    }
}
