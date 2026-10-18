package portal;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Command line administrator portal.
 *
 * <p>Start it with no accounts and it asks you to create the first supervisor.
 * Every command after that needs a live session, and each session expires after
 * {@link LoginService#DEFAULT_SESSION_TTL_MILLIS} milliseconds.
 */
public class AdminPortal {

    public static final int EXIT_OK = 0;
    public static final int EXIT_USAGE = 1;
    public static final int EXIT_UNAVAILABLE = 2;

    static final String PROMPT_USER = "username: ";
    static final String PROMPT_PASS = "password: ";
    static final String PROMPT_NEW = "new password: ";
    static final String PROMPT_REPEAT = "repeat password: ";
    static final String PROMPT_CMD = "portal> ";

    private final CredentialStore store;
    private final AuditLog audit;
    private final LoginService login;
    private final Reader reader;
    final PrintStream out;
    private LoginService.Session session;

    public AdminPortal(CredentialStore store, AuditLog audit, LoginService login, Reader reader,
                       PrintStream out) {
        this.store = store;
        this.audit = audit;
        this.login = login;
        this.reader = reader;
        this.out = out;
    }

    public static void main(String[] args) {
        Path home = home();
        int code;
        try {
            Files.createDirectories(home);
            CredentialStore store = new CredentialStore(home.resolve("credentials.tsv"));
            AuditLog audit = new AuditLog(home.resolve("audit.log"));
            LoginService login = new LoginService(store, audit);
            Console console = System.console();
            AdminPortal portal = console == null
                    ? new AdminPortal(store, audit, login,
                            new BufferedReader(new InputStreamReader(System.in)), System.out)
                    : new ConsolePortal(store, audit, login, console, System.out);
            code = portal.run(args);
        } catch (IOException | RuntimeException fatal) {
            System.err.println("the portal stopped: " + fatal.getMessage());
            code = EXIT_UNAVAILABLE;
        }
        System.exit(code);
    }

    /** Reads straight from a terminal, with passwords hidden by the console. */
    static class ConsolePortal extends AdminPortal {
        private final Console console;

        ConsolePortal(CredentialStore store, AuditLog audit, LoginService login, Console console,
                      PrintStream out) {
            super(store, audit, login, null, out);
            this.console = console;
        }

        @Override
        protected String ask(String prompt) {
            out.print(prompt);
            out.flush();
            return console.readLine();
        }

        @Override
        protected char[] askSecret(String prompt) {
            out.print(prompt);
            out.flush();
            char[] value = console.readPassword();
            return value == null ? new char[0] : value;
        }
    }

    public static Path home() {
        String fromProperty = System.getProperty("portal.home");
        if (fromProperty != null && !fromProperty.isBlank()) {
            return Paths.get(fromProperty.trim());
        }
        String fromEnv = System.getenv("ADMIN_PORTAL_HOME");
        if (fromEnv != null && !fromEnv.isBlank()) {
            return Paths.get(fromEnv.trim());
        }
        return Paths.get(System.getProperty("user.home", "."), ".admin-portal");
    }

    /**
     * Interactive loop.
     *
     * @return process exit code
     */
    public int run(String[] args) throws IOException {
        if (store.isEmpty()) {
            out.println("no administrator account exists yet.");
            out.println("create the first supervisor to unlock the portal.");
            if (!bootstrapSupervisor()) {
                out.println("no administrator account could be created, the portal stays locked.");
                return EXIT_UNAVAILABLE;
            }
        }
        if (args.length > 0 && "self-test".equals(args[0])) {
            selfTest();
            return EXIT_OK;
        }
        while (true) {
            String line = ask(session == null ? PROMPT_USER : PROMPT_CMD);
            if (line == null) {
                out.println("the portal is closing.");
                return EXIT_OK;
            }
            if (session == null) {
                authenticateLine(line);
                continue;
            }
            String command = line.strip().toLowerCase(Locale.ROOT);
            if (command.isEmpty()) {
                continue;
            }
            if (command.equals("quit") || command.equals("exit")) {
                closeSession("ending the session.");
                out.println("the portal is closing.");
                return EXIT_OK;
            }
            if (command.equals("logout")) {
                closeSession("signed out.");
                continue;
            }
            execute(command);
        }
    }

    private void authenticateLine(String username) throws IOException {
        char[] password = askSecret(PROMPT_PASS);
        LoginService.AuthResult result = login.verify(username, password);
        out.println(result.message());
        if (!result.granted()) {
            out.println("access denied.");
            return;
        }
        if (!record("SESSION_OPEN", result.username(), "role=" + result.role())) {
            out.println("access refused: the session could not be recorded.");
            return;
        }
        session = login.issueSession(result.username(), result.role());
        out.println("signed in as " + result.username() + " (" + result.role() + ").");
        out.println("type a command, or 'help' to see them.");
    }

    private void execute(String command) throws IOException {
        String[] parts = command.split("\\s+", 2);
        String verb = parts[0];
        String argument = parts.length > 1 ? parts[1].strip() : "";
        switch (verb) {
            case "help" -> out.print(helpText());
            case "whoami" -> whoami();
            case "status" -> status();
            case "admins" -> listAdmins();
            case "create" -> create(argument);
            case "reset" -> reset(argument);
            case "remove" -> remove(argument);
            case "unlock" -> unlock(argument);
            case "audit" -> showAudit(argument);
            default -> out.println("unknown command: " + AuditLog.clean(verb) + " (try 'help')");
        }
    }

    private void whoami() throws IOException {
        if (!requireSession("whoami")) {
            return;
        }
        out.println("you are " + session.username() + " with role " + session.role()
                + ", this session ends at " + Instant.ofEpochMilli(session.expiresAtMillis()) + ".");
    }

    private void status() throws IOException {
        if (!requireSession("status")) {
            return;
        }
        out.println("administrators on file : " + store.size());
        out.println("rows it could not read : " + store.malformedRows());
        out.println("credential file        : " + store.path());
        out.println("audit log              : " + audit.path());
        out.println("failed attempts        : " + login.maxFailures() + " before an account locks");
    }

    private void listAdmins() throws IOException {
        if (!mayManage("admins")) {
            return;
        }
        List<String> names = new ArrayList<>(store.usernames());
        if (names.isEmpty()) {
            out.println("no accounts.");
            return;
        }
        for (String name : names) {
            out.println("  " + name + "  " + store.roleOf(name)
                    + (login.isLockedOut(name) ? "  (locked)" : ""));
        }
    }

    private void create(String argument) throws IOException {
        if (!mayManage("create")) {
            return;
        }
        String raw = argument.isEmpty() ? ask(PROMPT_USER) : argument;
        String name = validName(raw);
        if (name == null) {
            return;
        }
        if (store.contains(name)) {
            out.println("an administrator called " + name + " already exists.");
            return;
        }
        char[] password = readAcceptedPassword(name);
        if (password == null) {
            out.println("the account was not created.");
            return;
        }
        try {
            if (!record("ADMIN_CREATE", session.username(), "created=" + name + " role=operator")) {
                return;
            }
            store.put(name, password, Roles.OPERATOR);
            out.println("created " + name + " with role " + Roles.OPERATOR + ".");
        } catch (GeneralSecurityException | IOException failure) {
            out.println("the account could not be saved: " + safeMessage(failure));
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void reset(String argument) throws IOException {
        if (!mayManage("reset")) {
            return;
        }
        String raw = argument.isEmpty() ? ask(PROMPT_USER) : argument;
        String name = validName(raw);
        if (name == null) {
            return;
        }
        if (!store.contains(name)) {
            out.println("there is no administrator called " + AuditLog.clean(name) + ".");
            return;
        }
        char[] password = readAcceptedPassword(name);
        if (password == null) {
            out.println("the password was not changed.");
            return;
        }
        try {
            if (!record("ADMIN_RESET", session.username(), "reset=" + name)) {
                return;
            }
            store.put(name, password, store.roleOf(name));
            login.clearLock(name);
            out.println("the password for " + name + " was replaced and its lock cleared.");
        } catch (GeneralSecurityException | IOException failure) {
            out.println("the new password could not be saved: " + safeMessage(failure));
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void remove(String argument) throws IOException {
        if (!mayManage("remove")) {
            return;
        }
        String raw = argument.isEmpty() ? ask(PROMPT_USER) : argument;
        String name = validName(raw);
        if (name == null) {
            return;
        }
        if (store.size() == 1 && store.contains(name)) {
            refuse("remove", "removing the last administrator would lock everyone out.");
            return;
        }
        if (!record("ADMIN_REMOVE", session.username(), "removed=" + name)) {
            return;
        }
        try {
            if (!store.remove(name)) {
                out.println("there is no administrator called " + AuditLog.clean(name) + ".");
                return;
            }
        } catch (IOException failure) {
            out.println("the account could not be removed: " + safeMessage(failure));
            return;
        }
        login.clearLock(name);
        out.println("removed " + name + ".");
    }

    private void unlock(String argument) throws IOException {
        if (!mayManage("unlock")) {
            return;
        }
        String raw = argument.isEmpty() ? ask(PROMPT_USER) : argument;
        String name = validName(raw);
        if (name == null) {
            return;
        }
        if (!record("ADMIN_UNLOCK", session.username(), "unlocked=" + name)) {
            return;
        }
        login.clearLock(name);
        out.println("the lock on " + name + " was cleared.");
    }

    private void showAudit(String argument) throws IOException {
        if (!requireSession("audit")) {
            return;
        }
        int count = 20;
        if (!argument.isEmpty()) {
            try {
                count = Integer.parseInt(argument);
            } catch (NumberFormatException notNumber) {
                out.println("give a number of records, for example: audit 50");
                return;
            }
        }
        List<String> lines = audit.tail(count);
        if (lines.isEmpty()) {
            out.println("the audit log has no records yet.");
            return;
        }
        out.println("the last " + lines.size() + " record(s) from " + audit.path() + ":");
        for (String line : lines) {
            out.println("  " + line);
        }
    }

    /**
     * Reads a new password. It is checked before the operator is asked to repeat
     * it, so a rejected entry consumes exactly the lines it asks for. Returns
     * {@code null} when the operator gave up or every attempt was rejected.
     */
    private char[] readAcceptedPassword(String username) {
        for (int attempt = 0; attempt < 3; attempt++) {
            char[] first = askSecret(PROMPT_NEW);
            String problem = PasswordPolicy.check(first, username);
            if (problem != null) {
                Arrays.fill(first, '\0');
                out.println("rejected: " + problem);
                continue;
            }
            char[] again = askSecret(PROMPT_REPEAT);
            boolean same = Arrays.equals(first, again);
            Arrays.fill(again, '\0');
            if (!same) {
                Arrays.fill(first, '\0');
                out.println("rejected: the two entries do not match.");
                continue;
            }
            return first;
        }
        return null;
    }

    private boolean bootstrapSupervisor() {
        for (int attempt = 0; attempt < 3; attempt++) {
            String rawName = ask(PROMPT_USER);
            if (rawName == null) {
                return false;
            }
            String name = validName(rawName);
            if (name == null) {
                continue;
            }
            char[] password = readAcceptedPassword(name);
            if (password == null) {
                continue;
            }
            try {
                if (!record("ADMIN_BOOTSTRAP", name, "role=" + Roles.SUPERVISOR)) {
                    return false;
                }
                store.put(name, password, Roles.SUPERVISOR);
                out.println("created " + name + " with role " + Roles.SUPERVISOR + ".");
                return true;
            } catch (GeneralSecurityException | IOException failure) {
                out.println("the account could not be saved: " + safeMessage(failure));
                return false;
            } finally {
                Arrays.fill(password, '\0');
            }
        }
        return false;
    }

    /** @return the normalised username, or {@code null} after printing the reason */
    private String validName(String raw) {
        if (raw == null) {
            return null;
        }
        try {
            return Names.normalize(raw);
        } catch (IllegalArgumentException badName) {
            out.println("that is not a valid username: " + badName.getMessage());
            return null;
        }
    }

    private boolean requireSession(String what) throws IOException {
        if (login.authorized(session)) {
            return true;
        }
        if (session != null) {
            closeSession("your session has expired, sign in again.");
        }
        record("COMMAND_REFUSED", "-", "command without a session: " + what);
        out.println(what + " needs a signed-in administrator.");
        return false;
    }

    /** Session check plus the supervisor role check. */
    private boolean mayManage(String what) throws IOException {
        if (!requireSession(what)) {
            return false;
        }
        if (Roles.mayManageAccounts(session.role())) {
            return true;
        }
        refuse(what, "only a supervisor may do that.");
        return false;
    }

    private void closeSession(String notice) throws IOException {
        if (session != null) {
            record("SESSION_CLOSE", session.username(), "bye");
        }
        session = null;
        out.println(notice);
    }

    private void refuse(String what, String reason) throws IOException {
        record("COMMAND_DENIED", session == null ? "-" : session.username(), what + ": " + reason);
        out.println("refused: " + reason);
    }

    /** @return false when the record could not be written */
    private boolean record(String event, String subject, String detail) {
        try {
            audit.record(event, subject, detail);
            return true;
        } catch (IOException cannotRecord) {
            out.println("refused: the action could not be recorded ("
                    + safeMessage(cannotRecord) + ").");
            return false;
        }
    }

    protected String ask(String prompt) {
        out.print(prompt);
        out.flush();
        try {
            return readLine();
        } catch (IOException readFailed) {
            return null;
        }
    }

    /**
     * With piped input the characters already came from the caller, so they are
     * simply consumed. On a terminal {@link ConsolePortal} hides them.
     */
    protected char[] askSecret(String prompt) {
        out.print(prompt);
        out.flush();
        try {
            String line = readLine();
            return line == null ? new char[0] : line.toCharArray();
        } catch (IOException readFailed) {
            return new char[0];
        }
    }

    private String readLine() throws IOException {
        if (reader == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(64);
        int c;
        while ((c = reader.read()) != -1) {
            if (c == '\n') {
                return sb.toString();
            }
            if (c != '\r') {
                sb.append((char) c);
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static String safeMessage(Exception failure) {
        String message = failure.getMessage();
        return message == null || message.isBlank()
                ? failure.getClass().getSimpleName() : AuditLog.clean(message);
    }

    private String helpText() {
        return """
                commands (a live session is required for every one of them):
                  whoami           show who you are signed in as
                  status           portal state: accounts, files, lockout limit
                  admins           list administrators and roles   (supervisor)
                  create [name]    add an operator                 (supervisor)
                  reset [name]     set a new password              (supervisor)
                  remove [name]    delete an account               (supervisor)
                  unlock [name]    clear a failed-attempt lock     (supervisor)
                  audit [n]        show the last n audit records, 20 by default
                  logout           drop the session, stay connected
                  quit             close the portal
                """;
    }

    /**
     * Short scripted demonstration run by {@code self-test}: it exercises the
     * refusal branches and prints how long each took, so the equal-cost branches
     * can be compared by eye.
     */
    private void selfTest() throws IOException {
        out.println("--- self test ---");
        String name = store.usernames().stream().sorted().findFirst().orElseThrow();
        out.println("account on file: " + name + " (its password is not known here)");
        LoginService.AuthResult wrong = login.verify(name, "Definitely-Wrong-1!".toCharArray());
        out.println("wrong password   -> " + wrong.status() + " in " + ms(wrong.elapsedNanos()));
        LoginService.AuthResult ghost = login.verify("nobody-here", "Definitely-Wrong-1!".toCharArray());
        out.println("unknown username -> " + ghost.status() + " in " + ms(ghost.elapsedNanos()));
        LoginService.AuthResult blank = login.verify(name, new char[0]);
        out.println("blank password   -> " + blank.status() + " in " + ms(blank.elapsedNanos()));
        out.println("audit records now: " + audit.tail(500).size());
        out.println("--- end self test ---");
    }

    private static String ms(long nanos) {
        return String.format(Locale.ROOT, "%.1f ms", nanos / 1_000_000.0);
    }
}
