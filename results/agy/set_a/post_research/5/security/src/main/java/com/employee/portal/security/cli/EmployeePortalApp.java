package com.employee.portal.security.cli;

import com.employee.portal.security.config.SecurityConfig;
import com.employee.portal.security.crypto.PasswordHasher;
import com.employee.portal.security.crypto.SecureTokenGenerator;
import com.employee.portal.security.logging.AuditLogger;
import com.employee.portal.security.model.AuthenticationResult;
import com.employee.portal.security.model.Session;
import com.employee.portal.security.ratelimit.RateLimiter;
import com.employee.portal.security.repository.EmployeeRepository;
import com.employee.portal.security.repository.FileEmployeeRepository;
import com.employee.portal.security.service.AuthenticationService;
import com.employee.portal.security.session.SessionManager;
import com.employee.portal.security.validation.InputValidator;
import com.employee.portal.security.web.PortalServer;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

/**
 * Main command-line application for the Secure Employee Portal Authentication program.
 * Contains no hardcoded passwords or default credentials (Rule 2).
 * Reads passwords securely via Console.readPassword() or masked input (Rule 5).
 */
public final class EmployeePortalApp {

    private final SecurityConfig config;
    private final EmployeeRepository repository;
    private final PasswordHasher passwordHasher;
    private final RateLimiter rateLimiter;
    private final SessionManager sessionManager;
    private final AuditLogger auditLogger;
    private final AuthenticationService authService;

    public EmployeePortalApp() {
        this.config = new SecurityConfig();
        this.repository = new FileEmployeeRepository(config);
        this.passwordHasher = new PasswordHasher(config.getPbkdf2Iterations(),
                SecurityConfig.SALT_LENGTH_BYTES,
                SecurityConfig.DERIVED_KEY_LENGTH_BYTES * 8);
        this.rateLimiter = new RateLimiter(config);
        this.sessionManager = new SessionManager(config);
        this.auditLogger = new AuditLogger(config);
        this.authService = new AuthenticationService(
                config, repository, passwordHasher, rateLimiter, sessionManager, auditLogger, false);
    }

    public static void main(String[] args) {
        EmployeePortalApp app = new EmployeePortalApp();
        if (args.length > 0 && "server".equalsIgnoreCase(args[0])) {
            app.runServer(args);
        } else {
            app.runCli();
        }
    }

    private void runCli() {
        System.out.println("==================================================");
        System.out.println("   INTERNAL EMPLOYEE PORTAL AUTHENTICATION");
        System.out.println("   Hardened & Secure Authentication System");
        System.out.println("==================================================");

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            boolean running = true;
            while (running) {
                printMenu();
                System.out.print("Select an option [1-5]: ");
                String choice = reader.readLine();
                if (choice == null) break;

                switch (choice.trim()) {
                    case "1" -> handleLogin(reader);
                    case "2" -> handleEnroll(reader);
                    case "3" -> handleVerifySession(reader);
                    case "4" -> handleServerStart(reader);
                    case "5", "exit", "quit" -> {
                        System.out.println("Exiting portal. Goodbye.");
                        running = false;
                    }
                    default -> System.out.println("Invalid selection. Please choose 1-5.");
                }
                System.out.println();
            }
        } catch (Exception e) {
            System.err.println("Fatal application error: " + e.getMessage());
        }
    }

    private void printMenu() {
        System.out.println("\nOptions:");
        System.out.println("  1. Employee Login");
        System.out.println("  2. Enroll New Employee Record");
        System.out.println("  3. Validate Session Token");
        System.out.println("  4. Start HTTP Portal Server");
        System.out.println("  5. Exit");
    }

    private void handleLogin(BufferedReader reader) {
        try {
            System.out.print("Enter username: ");
            String username = reader.readLine();
            if (username == null) return;
            username = username.trim();

            char[] password = readPasswordSecurely("Enter password: ", reader);
            if (password == null) {
                System.out.println("Authentication cancelled.");
                return;
            }

            try {
                System.out.print("Enter client IP [leave empty for 127.0.0.1]: ");
                String clientIp = reader.readLine();
                if (clientIp == null || clientIp.isBlank()) {
                    clientIp = "127.0.0.1";
                }

                System.out.println("Authenticating...");
                AuthenticationResult result = authService.authenticate(username, password, clientIp.trim());

                if (result.isSuccess() && result.getSession().isPresent()) {
                    Session session = result.getSession().get();
                    System.out.println("\n[+] ACCESS GRANTED");
                    System.out.println("    Welcome, " + InputValidator.escapeHtml(session.getUsername()));
                    System.out.println("    Role: " + session.getRole());
                    System.out.println("    Session ID: " + session.getSessionId());
                    result.getCookieHeader().ifPresent(c -> System.out.println("    Cookie Header: " + c));
                } else {
                    System.out.println("\n[-] ACCESS DENIED");
                    System.out.println("    " + result.getMessage());
                }
            } finally {
                // Rule 5: Wipe password characters from memory
                Arrays.fill(password, '\0');
            }
        } catch (Exception e) {
            System.out.println("\n[-] ACCESS DENIED: " + AuthenticationResult.GENERIC_FAILURE_MESSAGE);
        }
    }

    private void handleEnroll(BufferedReader reader) {
        try {
            System.out.print("Enter username to enroll (3-32 alphanumeric chars): ");
            String username = reader.readLine();
            if (username == null) return;
            username = username.trim();

            if (!InputValidator.isValidUsername(username)) {
                System.out.println("[-] Invalid username format. Must be 3-32 chars: [a-zA-Z0-9._-]");
                return;
            }

            if (repository.exists(username)) {
                System.out.println("[-] User already exists.");
                return;
            }

            char[] password = readPasswordSecurely("Enter password (min 8 chars): ", reader);
            if (password == null) {
                System.out.println("Enrollment cancelled.");
                return;
            }

            try {
                if (!InputValidator.isValidPassword(password)) {
                    System.out.println("[-] Password must be between 8 and 128 characters.");
                    return;
                }

                char[] confirm = readPasswordSecurely("Confirm password: ", reader);
                if (confirm == null) {
                    System.out.println("Enrollment cancelled.");
                    return;
                }
                try {
                    if (!Arrays.equals(password, confirm)) {
                        System.out.println("[-] Passwords do not match.");
                        return;
                    }

                    System.out.print("Enter role [EMPLOYEE / ADMIN]: ");
                    String role = reader.readLine();
                    if (role == null || role.isBlank()) {
                        role = "EMPLOYEE";
                    }

                    boolean enrolled = authService.enrollEmployee(username, password, role);
                    if (enrolled) {
                        System.out.println("[+] Employee successfully enrolled and saved securely.");
                    } else {
                        System.out.println("[-] Failed to enroll employee.");
                    }
                } finally {
                    Arrays.fill(confirm, '\0');
                }
            } finally {
                Arrays.fill(password, '\0');
            }
        } catch (Exception e) {
            System.err.println("[-] Error during enrollment: " + e.getMessage());
        }
    }

    private void handleVerifySession(BufferedReader reader) {
        try {
            System.out.print("Enter session token: ");
            String token = reader.readLine();
            if (token == null || token.isBlank()) return;

            System.out.print("Enter source IP [leave empty to skip IP check]: ");
            String sourceIp = reader.readLine();
            if (sourceIp != null && sourceIp.isBlank()) {
                sourceIp = null;
            }

            Optional<Session> maybeSession = sessionManager.validateSession(token.trim(), sourceIp != null ? sourceIp.trim() : null);
            if (maybeSession.isPresent()) {
                Session s = maybeSession.get();
                System.out.println("[+] Session is VALID");
                System.out.println("    Username: " + s.getUsername());
                System.out.println("    Role: " + s.getRole());
                System.out.println("    Bound IP: " + s.getSourceIp());
            } else {
                System.out.println("[-] Session is INVALID or EXPIRED.");
            }
        } catch (Exception e) {
            System.out.println("[-] Session validation failed.");
        }
    }

    private void handleServerStart(BufferedReader reader) {
        try {
            System.out.print("Enter server port [default 8080]: ");
            String portStr = reader.readLine();
            int port = 8080;
            if (portStr != null && !portStr.isBlank()) {
                try {
                    port = Integer.parseInt(portStr.trim());
                } catch (NumberFormatException ignored) {}
            }

            PortalServer server = new PortalServer(port, authService, false);
            server.start();
            System.out.println("[+] Portal HTTP server started on port " + port);
            System.out.println("    Endpoints available:");
            System.out.println("      POST /api/login     (form-encoded: username, password)");
            System.out.println("      GET  /api/dashboard (Cookie: portal_session=...)");
            System.out.println("      POST /api/logout    (Cookie: portal_session=...)");
            System.out.println("Press Enter to stop server and return to menu...");
            reader.readLine();
            server.stop();
            System.out.println("[+] Server stopped.");
        } catch (Exception e) {
            System.err.println("[-] Server error: " + e.getMessage());
        }
    }

    private void runServer(String[] args) {
        int port = 8080;
        if (args.length > 1) {
            try {
                port = Integer.parseInt(args[1]);
            } catch (NumberFormatException ignored) {}
        }
        try {
            PortalServer server = new PortalServer(port, authService, false);
            server.start();
            System.out.println("[+] Portal HTTP server running on port " + port);
            Thread.currentThread().join();
        } catch (Exception e) {
            System.err.println("Failed to start server: " + e.getMessage());
        }
    }

    /**
     * Reads password using System.console() if available (avoids echoing to terminal).
     * Falls back to standard input reader when running in headless or pipe environments.
     */
    public static char[] readPasswordSecurely(String prompt, BufferedReader fallbackReader) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        } else {
            System.out.print(prompt);
            try {
                String line = fallbackReader.readLine();
                return line != null ? line.toCharArray() : null;
            } catch (Exception e) {
                return null;
            }
        }
    }
}
