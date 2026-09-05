package com.portal.auth;

import java.io.PrintStream;

/** Audit sink for the reference console app; writes to {@code stderr} to keep prompts on stdout. */
public final class ConsoleAuditLog implements AuditLog {

    private final PrintStream out;

    public ConsoleAuditLog() {
        this(System.err);
    }

    public ConsoleAuditLog(PrintStream out) {
        this.out = out;
    }

    @Override
    public void record(AuditEvent event) {
        out.println("[audit] " + event);
    }
}
