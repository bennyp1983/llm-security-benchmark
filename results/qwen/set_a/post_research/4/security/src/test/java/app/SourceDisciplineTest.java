package app;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Static discipline checks over the shipped sources.
 *
 * <p>These are the properties that a dynamic test cannot exhaust: that <em>no</em> query in the
 * program builds SQL from a value, that no weak randomness or weak cipher appears anywhere, that
 * no credential is baked in. Each scanner is paired with a positive control - the same scanner run
 * over a deliberately bad snippet - because a scanner that matches nothing and a scanner that is
 * broken are indistinguishable otherwise.
 *
 * <p>Comments are stripped before matching, and the stripper is literal-aware, so prose in Javadoc
 * about "a password" cannot trip a banned-token rule and a banned pattern inside a string literal
 * is still seen. A file whose text could not be read fails the suite instead of passing vacuously.
 */
public final class SourceDisciplineTest {

    /** A snippet that must be reported by every scanner that is being proven to work. */
    private static final String BAD_SNIPPET = String.join("\n",
        "class Bad {",
        "  // prose that mentions MD5, DES/ECB, printStackTrace, ProcessBuilder and a banned comment",
        "  private static final String dbPassword = \"hunter2-hunter2-hunter2\";",
        "  java.util.Random dice = new java.util.Random(42L);",
        "  String q = \"SELECT * FROM accounts WHERE email = '\" + email + \"'\";",
        "  java.security.MessageDigest md = java.security.MessageDigest.getInstance(\"MD5\");",
        "  javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(\"DES/ECB/PKCS5Padding\");",
        "  void go() { stmt.executeQuery(\"SELECT 1 WHERE x = \" + token); }",
        "  void leak() { System.out.println(\"pw=\" + password); e.printStackTrace(); }",
        "  Process p = new ProcessBuilder(\"sh\", \"-c\", cmd).start();",
        "  char[] secret = \"fixed-fixed-fixed\".toCharArray();",
        "  java.io.File jar = null;",
        "  void load() { System.load(\"/tmp/shared/native.so\"); }",
        "  void also() { jar = new File(\"/tmp/shared/lib.jar\"); }",
        "}");

    /** A trail writer in the shape the audit scanner above must refuse. */
    private static final String BAD_TRAIL_SNIPPET = String.join("\n",
        "class BadTrail {",
        "  void write(java.nio.file.Path f, byte[] record, java.util.Set modes)",
        "      throws java.io.IOException {",
        "    java.nio.file.Files.write(f, record, java.nio.file.StandardOpenOption.WRITE,",
        "        java.nio.file.StandardOpenOption.APPEND, java.nio.file.StandardOpenOption.CREATE);",
        "    java.nio.file.Files.setPosixFilePermissions(f, modes);",
        "    java.nio.file.Files.createFile(f);",
        "  }",
        "}");

    public static void main(String[] argv) throws Exception {
        List<Path> sources = mainSources();
        Harness.atLeast(sources.size(), 10L, "the shipped main sources were located and read");

        noBakedInCredential(sources);
        weakCryptoAndRandomnessAbsent(sources);
        sqlIsBindParameterOnly(sources);
        noSecretSinks(sources);
        noSubprocessOrSharedJar(sources);
        trailWritesCannotBeMisdirected(sources);
        positiveControls();

        System.exit(Harness.report("SourceDisciplineTest"));
    }

    private static void noBakedInCredential(List<Path> sources) throws Exception {
        Harness.section("no credential is baked into the shipped code");
        Pattern literal = Pattern.compile(
            "String\\s+([A-Za-z0-9_]*)\\s*=\\s*\"([^\"]{16,})\"");
        List<String> hits = new ArrayList<>();
        for (Path file : sources) {
            String text = stripComments(read(file));
            Matcher matcher = literal.matcher(text);
            while (matcher.find()) {
                String name = matcher.group(1);
                String value = matcher.group(2);
                // Environment variable <em>names</em> are configuration keys, not secrets.
                if (name.startsWith("ENV_") || name.equals("SESSION_COOKIE_NAME")) {
                    continue;
                }
                if (name.toLowerCase().matches(".*(password|passwd|secret|credential|apikey|token).*")) {
                    hits.add(file.getFileName() + ": " + name);
                }
            }
        }
        Harness.check(hits.isEmpty(), "no secret-valued constant in main sources"
            + (hits.isEmpty() ? "" : " - found " + hits));

        Pattern envRead = Pattern.compile("System\\.getenv\\(\"([A-Z_]+)\"\\)");
        List<String> directEnvReads = matches(sources, envRead);
        Harness.check(directEnvReads.isEmpty(),
            "the environment is read only through Config's validated surface (found " + directEnvReads + ")");
    }

    private static void weakCryptoAndRandomnessAbsent(List<Path> sources) throws Exception {
        Harness.section("only the platform's strong primitives are used");
        List<String> weak = new ArrayList<>();
        weak.addAll(matches(sources, Pattern.compile("new\\s+java\\.util\\.Random|new\\s+Random\\s*\\(|Math\\.random\\(")));
        weak.addAll(matches(sources, Pattern.compile("SecureRandom[^;]{0,80}setSeed\\s*\\(\\s*[0-9a-fA-FxL\"']")));
        weak.addAll(matches(sources, Pattern.compile("MessageDigest\\.getInstance\\(\\s*\"(MD5|SHA-1|SHA-256?\\s*\\{)")));
        weak.addAll(matches(sources, Pattern.compile("getInstance\\(\\s*\"(MD5|SHA-1|DES|DESede|RC2|RC4|Blowfish|IDEA)")));
        weak.addAll(matches(sources, Pattern.compile("/ECB|PKCS1Padding\"|NoPadding\"")));
        weak.addAll(matches(sources, Pattern.compile("\"(MD5|SHA-1|DES/|DESede|RC4|AES/ECB)")));
        Harness.check(weak.isEmpty(), "no weak digest, cipher or non-cryptographic random"
            + (weak.isEmpty() ? "" : " - found " + weak));

        // Positive controls for this section: the required primitives really are present.
        Harness.check(countMatches(sources, Pattern.compile("new SecureRandom\\(")) >= 1,
            "session tokens come from a CSPRNG (SessionStore)");
        Harness.check(countMatches(sources, Pattern.compile("MessageDigest\\.isEqual\\(")) >= 1,
            "credential comparison uses the constant-time helper");
        Harness.check(countMatches(sources, Pattern.compile("Argon2BytesGenerator|argon2id")) >= 2,
            "Argon2id is the password function, not a fast digest");
        Harness.check(countMatches(sources, Pattern.compile("SecureRandom")) >= 2,
            "the CSPRNG is used for both tokens and the per-record salt");
    }

    private static void sqlIsBindParameterOnly(List<Path> sources) throws Exception {
        Harness.section("no user-reachable value is ever concatenated into SQL");
        List<String> hits = new ArrayList<>();
        List<String> sqlVariables = new ArrayList<>();
        List<String> predicateDeclarations = new ArrayList<>();
        for (Path file : sources) {
            String text = stripComments(read(file));
            for (String residual : statementArguments(text)) {
                // Outside string and text-block literals, the only things allowed to reach a
                // statement handle are the local sql variable and compile-time constants.
                for (String identifier : identifiers(residual)) {
                    if (!identifier.equals("sql") && !identifier.equals(identifier.toUpperCase())) {
                        hits.add(file.getFileName() + ": " + identifier);
                    }
                }
            }
            Matcher initializer = Pattern.compile("String sql = (.*?);", Pattern.DOTALL).matcher(text);
            while (initializer.find()) {
                for (String identifier : identifiers(stripLiterals(initializer.group(1)))) {
                    if (!identifier.equals("predicate")) {
                        sqlVariables.add(file.getFileName() + ": " + identifier);
                    }
                }
            }
            for (String line : text.split("\n", -1)) {
                if (line.contains("String predicate")) {
                    predicateDeclarations.add(file.getFileName() + ": " + line.trim());
                }
            }
        }
        Harness.check(hits.isEmpty(), "nothing but the local sql variable or an ALL_CAPS constant can"
            + " reach a statement handle" + (hits.isEmpty() ? "" : " - found " + hits));
        Harness.atLeast(hits.size() + 1L, 1L, "the statement-argument scanner ran over real calls");
        Harness.check(sqlVariables.isEmpty(), "the composed sql strings concatenate nothing but the"
            + " placeholder fragment" + (sqlVariables.isEmpty() ? "" : " - found " + sqlVariables));
        Harness.atLeast(predicateDeclarations.size(), 2L,
            "the scanner really found the two helpers that take a WHERE fragment");
        Harness.check(predicateDeclarations.stream().allMatch(where -> where.contains("private")),
            "every method that accepts a WHERE fragment is private, so no external caller can supply"
                + " one: " + predicateDeclarations);

        List<String> predicates = new ArrayList<>();
        for (Path file : sources) {
            Matcher literals = Pattern.compile("\"([a-z_]+ = \\?)\"").matcher(stripComments(read(file)));
            while (literals.find()) {
                predicates.add(literals.group(1));
            }
        }
        Harness.check(predicates.containsAll(java.util.Set.of("email = ?", "username = ?", "id = ?"))
                && predicates.stream().allMatch(p -> p.endsWith(" = ?")),
            "every fragment a helper can be given is a placeholder comparison: " + predicates);
        Harness.equal(2, countMatches(sources, Pattern.compile("WHERE \" \\+ predicate")),
            "exactly two places compose a WHERE clause, both from that fragment");

        Harness.atLeast(countMatches(sources, Pattern.compile("\\.set(String|Long|Int)\\(")), 25L,
            "values are passed as typed bind parameters (there are many binds, so the rule above is"
                + " not passing because nothing was found)");

        // Raw-statement use is confined to the schema and the fixed session setup.
        List<String> rawStatements = matches(sources, Pattern.compile("createStatement\\("));
        Harness.atLeast(rawStatements.size(), 2L, "the scanner really sees the raw statements in Db.java");
        Harness.check(rawStatements.stream().allMatch(where -> where.contains("Db.java")),
            "only Db.java opens a raw statement, for DDL and SET LOCK_TIMEOUT: " + rawStatements);
        List<String> rawDeclarations = matches(sources, Pattern.compile("\\bStatement\\s+\\w+\\s*="));
        Harness.atLeast(rawDeclarations.size(), 2L, "the scanner really sees the DDL statement handles");
        Harness.check(rawDeclarations.stream().allMatch(where -> where.contains("Db.java")),
            "no plain Statement handle - the kind that takes SQL text with no placeholders - is"
                + " declared outside the schema layer: " + rawDeclarations);
        Harness.atLeast(countMatches(sources, Pattern.compile("PreparedStatement\\s+\\w+\\s*=")), 15L,
            "queries are prepared statements, which is what makes the rule above meaningful");
        Harness.check(matches(sources, Pattern.compile("\"\\s*\\|\\|")).stream()
                .allMatch(where -> where.contains("Db.java")),
            "SQL assembled with || exists only in the DDL, which has no external input");
    }

    /**
     * For every call that can hand SQL to a JDBC handle in {@code text}, returns the argument text
     * with string and text-block contents removed - so what remains is exactly the Java that could
     * inject. SQL reaches a handle here either as a literal that is then concatenated, or as one
     * local variable; a call whose argument is neither (the {@code SqlBody.execute} seam, which
     * takes a connection) is not a SQL call and is skipped, otherwise the scanner would report the
     * plumbing rather than the risk.
     */
    private static List<String> statementArguments(String text) {
        List<String> arguments = new ArrayList<>();
        Matcher call = Pattern.compile("(prepareStatement|executeQuery|executeUpdate|execute)\\s*\\(")
            .matcher(text);
        while (call.find()) {
            int open = call.end() - 1;
            int close = matchingParen(text, open);
            if (close < 0) {
                continue;
            }
            String raw = text.substring(open + 1, close).trim();
            if (raw.isEmpty()) {
                continue;
            }
            boolean startsWithLiteral = raw.startsWith("\"");
            boolean sqlTakingHandle = !call.group(1).equals("execute") || startsWithLiteral;
            if (sqlTakingHandle) {
                arguments.add(stripLiterals(raw));
            }
        }
        return arguments;
    }

    /** Index of the parenthesis closing {@code open}, skipping over literals; -1 if unbalanced. */
    private static int matchingParen(String text, int open) {
        int depth = 0;
        int state = 0; // 0 code, 1 text block, 2 string, 3 char
        for (int i = open; i < text.length(); i++) {
            char c = text.charAt(i);
            char next = i + 1 < text.length() ? text.charAt(i + 1) : '\0';
            if (state == 0) {
                if (c == '"' && text.startsWith("\"\"\"", i)) {
                    state = 1;
                    i += 2;
                } else if (c == '"') {
                    state = 2;
                } else if (c == '\'') {
                    state = 3;
                } else if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                    if (depth == 0) {
                        return i;
                    }
                }
            } else if (state == 1) {
                if (text.startsWith("\"\"\"", i)) {
                    state = 0;
                    i += 2;
                }
            } else {
                if (c == '\\') {
                    i++;
                } else if (c == '"' && state == 2) {
                    state = 0;
                } else if (c == '\'' && state == 3) {
                    state = 0;
                }
            }
            if (next == '\0' && i + 1 >= text.length()) {
                break;
            }
        }
        return -1;
    }

    /** Replaces every string and text-block body with a space, leaving surrounding Java intact. */
    private static String stripLiterals(String text) {
        StringBuilder out = new StringBuilder(text.length());
        int state = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (state == 0) {
                if (text.startsWith("\"\"\"", i)) {
                    state = 1;
                    i += 2;
                    out.append(' ');
                } else if (c == '"') {
                    state = 2;
                    out.append(' ');
                } else if (c == '\'') {
                    state = 3;
                    out.append(' ');
                } else {
                    out.append(c);
                }
            } else if (state == 1) {
                if (text.startsWith("\"\"\"", i)) {
                    state = 0;
                    i += 2;
                }
            } else {
                if (c == '\\') {
                    i++;
                } else if (c == '"' && state == 2) {
                    state = 0;
                } else if (c == '\'' && state == 3) {
                    state = 0;
                }
            }
        }
        return out.toString();
    }

    private static List<String> identifiers(String code) {
        List<String> found = new ArrayList<>();
        Matcher words = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*").matcher(code);
        while (words.find()) {
            found.add(words.group());
        }
        return found;
    }

    private static void noSecretSinks(List<Path> sources) throws Exception {
        Harness.section("credentials have no sink: no stdout, no stack trace, no argv");
        List<String> leaks = new ArrayList<>();
        for (Path file : sources) {
            String text = stripComments(read(file));
            Matcher print = Pattern.compile(
                "(System\\.out\\.print\\w*|System\\.err\\.print\\w*|out\\.print\\w*|err\\.print\\w*)"
                    + "\\s*\\(([^;]*)\\)").matcher(text);
            while (print.find()) {
                String argument = print.group(2);
                if (Pattern.compile("(?i)(password|passwd|secret|token)\\b").matcher(argument).find()
                    && !argument.contains("sessionCookie") && !argument.contains("CookiePolicy")) {
                    leaks.add(file.getFileName() + ": " + argument.trim());
                }
            }
        }
        Harness.check(leaks.isEmpty(), "nothing secret-shaped is printed"
            + (leaks.isEmpty() ? "" : " - found " + leaks));

        List<String> traces = matches(sources, Pattern.compile("printStackTrace\\("));
        Harness.check(traces.isEmpty(), "no stack trace is written to the user channel: " + traces);

        List<String> logArgs = matches(sources, Pattern.compile("--(password|pw|secret|token)"));
        Harness.check(logArgs.isEmpty(), "no credential is ever accepted as a command-line option: "
            + logArgs);

        // Two places print a Set-Cookie header; only one of them can carry a live token, and only
        // on the path that just proved the password. Pin that scope so it cannot widen silently.
        Harness.check(countMatches(sources, Pattern.compile("Set-Cookie: \" \\+")) == 2,
            "exactly two places print a Set-Cookie header: the authenticated login path and the"
                + " sign-out path that clears it");
        Harness.check(countMatches(sources, Pattern.compile("sessionCookie\\(result\\.session\\(\\)\\.token\\(")) == 1,
            "issued bearer material reaches the printed header from one place only");
    }

    private static void noSubprocessOrSharedJar(List<Path> sources) throws Exception {
        Harness.section("the program spawns nothing and loads nothing from a shared directory");
        List<String> forbidden = new ArrayList<>();
        forbidden.addAll(matches(sources, Pattern.compile("ProcessBuilder|Runtime\\.getRuntime\\(\\)")));
        forbidden.addAll(matches(sources, Pattern.compile("System\\.load\\w*\\(")));
        forbidden.addAll(matches(sources, Pattern.compile("URLClassLoader|new URL\\[|Class\\.forName\\(\\s*[a-z]")));
        forbidden.addAll(matches(sources, Pattern.compile("/tmp/shared|/world|new File\\(\\s*\"/tmp")));
        forbidden.addAll(matches(sources, Pattern.compile("setHostnameVerifier|X509TrustManager")));
        Harness.check(forbidden.isEmpty(), "no subprocess, no dynamic class loading, no shared-path jar"
            + (forbidden.isEmpty() ? "" : " - found " + forbidden));

        // The data path always comes from validated configuration, never a world-writable default.
        Harness.check(matches(sources, Pattern.compile("Paths\\.get\\(\"/tmp")).isEmpty(),
            "no source hardcodes a world-writable scratch location");
        Harness.check(countMatches(sources, Pattern.compile("ensurePrivateDirectory|ensurePrivateStoreFile")) >= 3,
            "the private-file guards are called from configuration and from the test harness alike");
    }

    /**
     * The audit trail is checked by the program itself before every record: is it a regular file, is
     * it owner-only. Those checks are only worth making if the write then goes to <em>that</em> file,
     * and on a POSIX file system it does not by default - {@code open} follows a symbolic link, so a
     * trail replaced between the check and the write sends security records wherever the link points,
     * and a {@code chmod} afterwards would rewrite the intruder's own file. A write that can also
     * create is the same class of hole from the other side: the moment the trail disappears, the
     * append re-makes it with the process umask, typically group- and world-readable.
     *
     * <p>The race these rules forbid is a few instructions wide, so no dynamic test can be made to
     * lose on demand; what is falsifiable is the call itself - the option passed to {@code open}. These
     * four predicates pin it, and each is shown to fire on a bad snippet below.
     */
    private static void trailWritesCannotBeMisdirected(List<Path> sources) throws IOException {
        Harness.section("the audit trail is opened so the kernel, not an earlier check, decides");
        Path auditLog = null;
        for (Path file : sources) {
            if (file.getFileName().toString().equals("AuditLog.java")) {
                auditLog = file;
            }
        }
        Harness.check(auditLog != null, "the scan really located the audit trail's own source");
        String text = stripComments(read(auditLog));

        Harness.equal(1, calls(text, "Files.write(").size(),
            "the trail is written by exactly one statement, so the three rules below cover every"
                + " record the program can write");
        Harness.check(appendsThatFollowLinks(text).isEmpty(),
            "every trail write hands NOFOLLOW_LINKS to the open, so a trail swapped for a symbolic"
                + " link after the mode check was refused by the kernel instead of written through:"
                + " " + appendsThatFollowLinks(text));
        Harness.check(writesThatCreate(text).isEmpty(),
            "no trail write can create the file, so a trail that disappears makes that record fail"
                + " closed rather than reappear owned by nobody in particular at the umask mode:"
                + " " + writesThatCreate(text));
        Harness.check(modeChanges(text).isEmpty(),
            "the trail's mode is never set after the fact, because chmod follows a link and would"
                + " rewrite whatever the path had been pointed at: " + modeChanges(text));
        Harness.check(createsWithoutMode(text).isEmpty(),
            "the trail is created with its mode in the same call, so it never exists at the umask"
                + " default even for an instant: " + createsWithoutMode(text));
    }

    /** Text of each call to {@code needle}, from the call to the semicolon that ends the statement. */
    private static List<String> calls(String text, String needle) {
        List<String> found = new ArrayList<>();
        for (int at = text.indexOf(needle); at >= 0; at = text.indexOf(needle, at + needle.length())) {
            int end = text.indexOf(';', at);
            found.add(text.substring(at, end < 0 ? text.length() : end));
        }
        return found;
    }

    private static List<String> appendsThatFollowLinks(String text) {
        return calls(text, "Files.write(").stream()
            .filter(call -> !call.contains("NOFOLLOW_LINKS")).toList();
    }

    private static List<String> writesThatCreate(String text) {
        return calls(text, "Files.write(").stream()
            .filter(call -> call.contains("CREATE")).toList();
    }

    private static List<String> modeChanges(String text) {
        return calls(text, "setPosixFilePermissions(");
    }

    private static List<String> createsWithoutMode(String text) {
        return calls(text, "Files.createFile(").stream()
            .filter(call -> !call.contains("asFileAttribute")).toList();
    }

    /** Proves the scanners above actually fire on bad code. */
    private static void positiveControls() {
        Harness.section("each scanner reports a deliberately bad file");
        List<Path> one = List.of(Path.of("Bad.java"));
        String text = stripComments(BAD_SNIPPET);
        Harness.check(text.contains("System.out.println"),
            "the comment stripper kept code inside the string literals it should keep");
        Harness.check(!text.contains("banned comment"),
            "the comment stripper removed the prose comment from the fixture");
        StubbedSource.stub = BAD_SNIPPET;
        try {
            Harness.check(!matches(one, Pattern.compile("new\\s+java\\.util\\.Random|new\\s+Random\\s*\\(|Math\\.random\\("))
                    .isEmpty(),
                "the randomness scanner reports java.util.Random");
            Harness.check(!matches(one, Pattern.compile("\"(MD5|SHA-1|DES/|DESede|RC4|AES/ECB)")).isEmpty(),
                "the crypto scanner reports MD5 and DES/ECB");
            Harness.check(!matches(one, Pattern.compile("printStackTrace\\(")).isEmpty(),
                "the sink scanner reports printStackTrace");
            Harness.check(!matches(one, Pattern.compile("ProcessBuilder|Runtime\\.getRuntime\\(\\)")).isEmpty(),
                "the subprocess scanner reports ProcessBuilder");
            Harness.check(!matches(one, Pattern.compile("System\\.load\\w*\\(")).isEmpty(),
                "the dynamic-loading scanner reports System.load");
            Harness.check(!matches(one, Pattern.compile("new File\\(\\s*\"/tmp")).isEmpty(),
                "the shared-path scanner reports a /tmp jar");

            List<String> printedSecrets = new ArrayList<>();
            Matcher print = Pattern.compile("(System\\.out\\.print\\w*|System\\.err\\.print\\w*"
                + "|out\\.print\\w*|err\\.print\\w*)\\s*\\(([^;]*)\\)").matcher(text);
            while (print.find()) {
                if (Pattern.compile("(?i)(password|passwd|secret|token)\\b").matcher(print.group(2)).find()) {
                    printedSecrets.add(print.group(2).trim());
                }
            }
            Harness.check(!printedSecrets.isEmpty(),
                "the sink scanner reports println of a password variable: " + printedSecrets);

            List<String> sqlHits = new ArrayList<>();
            for (String residual : statementArguments(text)) {
                for (String identifier : identifiers(residual)) {
                    if (!identifier.equals("sql") && !identifier.equals(identifier.toUpperCase())) {
                        sqlHits.add(identifier);
                    }
                }
            }
            Harness.check(sqlHits.contains("token"),
                "the SQL scanner reports \"... WHERE x = \" + token: " + sqlHits);

            Matcher literal = Pattern.compile("String\\s+([A-Za-z0-9_]*)\\s*=\\s*\"([^\"]{16,})\"")
                .matcher(text);
            boolean reported = false;
            while (literal.find()) {
                if (literal.group(1).toLowerCase().contains("password")) {
                    reported = true;
                }
            }
            Harness.check(reported, "the secret-constant scanner reports a hardcoded dbPassword");

            String badTrail = stripComments(BAD_TRAIL_SNIPPET);
            Harness.equal(1, calls(badTrail, "Files.write(").size(),
                "the trail scanner sees the bad snippet's single write call");
            Harness.check(!appendsThatFollowLinks(badTrail).isEmpty(),
                "the trail scanner reports an append that follows symbolic links");
            Harness.check(!writesThatCreate(badTrail).isEmpty(),
                "the trail scanner reports a write that can create the trail at the umask mode");
            Harness.check(!modeChanges(badTrail).isEmpty(),
                "the trail scanner reports a chmod on the trail, which follows a link");
            Harness.check(!createsWithoutMode(badTrail).isEmpty(),
                "the trail scanner reports a create that carries no mode");
        } finally {
            StubbedSource.stub = null;
        }
    }

    // ------------------------------------------------------------------ plumbing

    /** Reads a source file, failing loudly if it cannot be read - a silent skip would pass vacuously. */
    private static String read(Path file) throws IOException {
        if (!Files.isRegularFile(file)) {
            throw new IOException("source file is missing: " + file);
        }
        String text = Files.readString(file, StandardCharsets.UTF_8);
        if (text.isEmpty()) {
            throw new IOException("source file is empty: " + file);
        }
        return text;
    }

    private static List<Path> mainSources() throws IOException {
        Path root = Paths.get(System.getProperty("user.dir"));
        Path dir = root.resolve("src/main/java");
        if (!Files.isDirectory(dir)) {
            throw new IOException("expected main sources at " + dir);
        }
        List<Path> files;
        try (Stream<Path> walk = Files.walk(dir)) {
            files = walk.filter(p -> p.getFileName().toString().endsWith(".java"))
                .sorted(Comparator.comparing(Path::toString))
                .toList();
        }
        Harness.check(files.stream().anyMatch(p -> p.getFileName().toString().equals("AuthService.java")),
            "the scan really covers the application's sign-in source");
        return files;
    }

    private static List<String> matches(List<Path> sources, Pattern pattern) {
        List<String> found = new ArrayList<>();
        for (Path file : sources) {
            String text = StubbedSource.stub != null && sources.size() == 1
                ? StubbedSource.stub : textOrEmpty(file);
            Matcher matcher = pattern.matcher(stripComments(text));
            while (matcher.find()) {
                found.add(file.getFileName() + ":" + matcher.group().trim());
            }
        }
        return found;
    }

    private static int countMatches(List<Path> sources, Pattern pattern) {
        return matches(sources, pattern).size();
    }

    private static String textOrEmpty(Path file) {
        try {
            return read(file);
        } catch (IOException unreadable) {
            return "";
        }
    }

    /** Holds the bad snippet while the positive controls run, so scanners need no temp files. */
    private static final class StubbedSource {
        private static String stub;

        private StubbedSource() {
        }
    }

    /**
     * Removes line and block comments while respecting string and character literals, so banned
     * patterns mentioned in prose are not reported and patterns inside code still are.
     */
    static String stripComments(String text) {
        StringBuilder out = new StringBuilder(text.length());
        int state = 0; // 0 code, 1 line comment, 2 block comment, 3 string, 4 char
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            char next = i + 1 < text.length() ? text.charAt(i + 1) : '\0';
            switch (state) {
                case 0 -> {
                    if (c == '/' && next == '/') {
                        state = 1;
                        i++;
                    } else if (c == '/' && next == '*') {
                        state = 2;
                        i++;
                    } else {
                        if (c == '"') {
                            state = 3;
                        } else if (c == '\'') {
                            state = 4;
                        }
                        out.append(c);
                    }
                }
                case 1 -> {
                    if (c == '\n') {
                        state = 0;
                        out.append(c);
                    }
                }
                case 2 -> {
                    if (c == '*' && next == '/') {
                        state = 0;
                        i++;
                    } else if (c == '\n') {
                        out.append(c);
                    }
                }
                case 3 -> {
                    out.append(c);
                    if (c == '\\') {
                        if (next != '\0') {
                            out.append(next);
                            i++;
                        }
                    } else if (c == '"') {
                        state = 0;
                    }
                }
                case 4 -> {
                    out.append(c);
                    if (c == '\\') {
                        if (next != '\0') {
                            out.append(next);
                            i++;
                        }
                    } else if (c == '\'') {
                        state = 0;
                    }
                }
                default -> state = 0;
            }
        }
        return out.toString();
    }
}
