#!/usr/bin/env python3 -u
"""Mutation battery for the session-handoff security guards.

Each mutant is a single semantic edit to a copy of src/main (the real sources are never modified).
A mutant is killed only when the frozen in-process harness fails an assertion. Everything else is
accounted for honestly as its own status, never folded into "killed":

  killed(assert)   the harness printed at least one FAILED line and exited non-zero
  killed(build)    the mutant does not compile -- reported separately, not counted as an assertion kill
  survived         the harness passed with the guard weakened
  equivalent       survived, and the suite proves this edit cannot change any outcome (see EQUIVALENT)
  anchor-fail      the expected source text was not found exactly once (the battery's own bug)
  compile-fail     compiled but the harness could not be started
  timeout          the harness hung past its deadline

Usage: tools/mutants.py --list | --dry | --run [id ...] [--timeout SECONDS]
"""

import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVLET_API = os.environ.get("SERVLET_API_JAR", "tools/jakarta.servlet-api-6.0.0.jar")
JAVA_HOME_DIR = os.environ.get("JAVA_HOME", "/usr/lib/jvm/java-17-openjdk-amd64")
JAVAC = os.path.join(JAVA_HOME_DIR, "bin", "javac")
JAVA = os.path.join(JAVA_HOME_DIR, "bin", "java")
WORK = "build/mut"
LOGS = "build/logs/mutants"
CLASSES = "build/mut-classes"
TEST_CLASSES = "build/mut-test-classes"
# One frozen copy of src/main, taken before the first mutant is built. Without it, an edit that
# lands while a 30-mutant battery is running gives each mutant a different baseline -- and an anchor
# that matched when the run started can silently stop matching halfway through.
PRISTINE = "build/mut-pristine"

# Live harness JVMs are capped so the suite's own timing measurements stay believable; replaced in
# main() once --jobs and --max-jvms are known.
MAX_JVMS = threading.Semaphore(2)

# (id, file, exact text to replace, replacement, what the guard is supposed to do)
# Every anchor was taken from the current source and is verified exactly-once by --dry.
MUTANTS = [
    # ---- SessionId: the only thing between an attacker's string and a session cookie
    ("SID-min-length", "src/main/java/com/acme/portal/session/SessionId.java",
     "public static final int MIN_LENGTH = 32;",
     "public static final int MIN_LENGTH = 6;",
     "refuses a short identifier; a 6-character value would be guessable"),
    ("SID-max-length", "src/main/java/com/acme/portal/session/SessionId.java",
     "if (length > MAX_LENGTH) {",
     "if (length > MAX_LENGTH * 100) {",
     "bounds the size of a stored value (rule 5)"),
    ("SID-charset", "src/main/java/com/acme/portal/session/SessionId.java",
     "        return (c >= 'A' && c <= 'Z')\n"
     "                || (c >= 'a' && c <= 'z')\n"
     "                || (c >= '0' && c <= '9')\n"
     "                || c == '-'\n"
     "                || c == '_';",
     "        return true;",
     "allowlists the cookie-token charset, so no delimiter or control byte can be smuggled in"),
    ("SID-selftest-diversity", "src/main/java/com/acme/portal/session/SessionId.java",
     "if (distinctCharacters(candidate) < SELF_TEST_MIN_DISTINCT_CHARS) {",
     "if (distinctCharacters(candidate) < 0) {",
     "refuses to hand out an identifier this class minted when its own output looks degenerate"),
    ("SID-selftest-shape", "src/main/java/com/acme/portal/session/SessionId.java",
     "        Rejection shape = inspect(candidate);\n"
     "        if (shape != Rejection.NONE) {\n"
     "            return shape;\n"
     "        }",
     "        Rejection shape = inspect(candidate);\n"
     "        if (false) {\n"
     "            return shape;\n"
     "        }",
     "makes the generator self-test include the shape checks, so it cannot mint what it would refuse"),
    ("SID-request-path-diversity", "src/main/java/com/acme/portal/session/SessionId.java",
     "        for (int i = 0; i < length; i++) {\n"
     "            if (!isAllowedCharacter(raw.charAt(i))) {\n"
     "                return Rejection.ILLEGAL_CHARACTER;\n"
     "            }\n"
     "        }\n"
     "        return Rejection.NONE;",
     "        for (int i = 0; i < length; i++) {\n"
     "            if (!isAllowedCharacter(raw.charAt(i))) {\n"
     "                return Rejection.ILLEGAL_CHARACTER;\n"
     "            }\n"
     "        }\n"
     "        if (distinctCharacters(raw) < SELF_TEST_MIN_DISTINCT_CHARS) {\n"
     "            return Rejection.LOW_CHAR_DIVERSITY;\n"
     "        }\n"
     "        return Rejection.NONE;",
     "keeps an invented entropy heuristic out of the request path -- applied to hex identifiers it "
     "refused about one sign-in in 59 that the authoritative store had already vouched for"),
    # ---- Masking: the value must never reach a log, a message or a page
    ("MASK-fingerprint", "src/main/java/com/acme/portal/session/SessionId.java",
     "return CacheSupport.digestHexPrefix(new String[]{FINGERPRINT_PREFIX, value}, FINGERPRINT_HEX);",
     "return value;",
     "exposes only a truncated digest, never the credential itself"),
    # ---- SessionCookieWriter: the emission path
    ("WRITER-httpOnly", "src/main/java/com/acme/portal/session/SessionCookieWriter.java",
     "cookie.setHttpOnly(policy.httpOnly());",
     "cookie.setHttpOnly(false);",
     "marks the cookie HttpOnly so script cannot read the session"),
    ("WRITER-secure", "src/main/java/com/acme/portal/session/SessionCookieWriter.java",
     "cookie.setSecure(policy.secure());",
     "cookie.setSecure(false);",
     "marks the cookie Secure so it never travels over plain HTTP"),
    ("WRITER-samesite", "src/main/java/com/acme/portal/session/SessionCookieWriter.java",
     'cookie.setAttribute(SAME_SITE_ATTRIBUTE, policy.sameSite());',
     'cookie.setAttribute(SAME_SITE_ATTRIBUTE, "None");',
     "pins SameSite=Strict so a cross-site request cannot carry the cookie"),
    ("WRITER-no-store", "src/main/java/com/acme/portal/session/SessionCookieWriter.java",
     'response.setHeader("Cache-Control", NO_STORE);',
     'response.setHeader("Cache-Control", "public, max-age=86400");',
     "makes any response that can carry session material uncacheable"),
    ("WRITER-second-check", "src/main/java/com/acme/portal/session/SessionCookieWriter.java",
     "if (rejection != SessionId.Rejection.NONE) {",
     "if (false && rejection != SessionId.Rejection.NONE) {",
     "re-validates the value at the trust boundary immediately before emission"),
    ("WRITER-domain", "src/main/java/com/acme/portal/session/SessionCookieWriter.java",
     "cookie.setPath(policy.path());",
     "cookie.setPath(policy.path());\n        cookie.setDomain(\"example.com\");",
     "stays host-only by never setting Domain (the __Host- prefix requires it)"),
    # ---- SessionCookiePolicy: invariants a bad deployment could otherwise weaken
    ("POLICY-secure-hardcoded", "src/main/java/com/acme/portal/session/SessionCookiePolicy.java",
     "    public boolean secure() {\n        return true;",
     "    public boolean secure() {\n        return false;",
     "hardcodes Secure=true with no way to turn it off"),
    ("POLICY-httpOnly-hardcoded", "src/main/java/com/acme/portal/session/SessionCookiePolicy.java",
     "    public boolean httpOnly() {\n        return true;",
     "    public boolean httpOnly() {\n        return false;",
     "hardcodes HttpOnly=true with no way to turn it off"),
    ("POLICY-host-prefix", "src/main/java/com/acme/portal/session/SessionCookiePolicy.java",
     'if (name.startsWith("__Host-") && !"/".equals(path)) {',
     "if (false) {",
     "refuses a __Host- name paired with anything but Path=/"),
    ("POLICY-samesite-none", "src/main/java/com/acme/portal/session/SessionCookiePolicy.java",
     'throw new IllegalArgumentException("SameSite=None is refused; use Strict or Lax");',
     'return "None";',
     "refuses SameSite=None rather than shipping a cross-site session cookie"),
    # ---- SessionHandoffService: the decision itself
    ("SVC-null-verifier", "src/main/java/com/acme/portal/session/SessionHandoffService.java",
     "this.verifier = verifier == null ? DENY_ALL : verifier;",
     "this.verifier = verifier == null ? new SessionStateVerifier() {\n"
     "            @Override\n"
     "            public boolean isSessionValid(String sessionId) {\n"
     "                return true;\n"
     "            }\n"
     "        } : verifier;",
     "fails closed when no session-state authority is wired in. NOTE: deleting DENY_ALL outright is "
     "an equivalent mutant -- a null field would NPE inside handle() and the existing catch turns "
     "that into 'no'. This edit weakens the meaning instead of just the structure."),
    ("SVC-verifier-throw", "src/main/java/com/acme/portal/session/SessionHandoffService.java",
     "            valid = false;\n        }",
     "            valid = true;\n        }",
     "treats a verifier that cannot answer as 'no'"),
    ("SVC-order-budget-first", "src/main/java/com/acme/portal/session/SessionHandoffService.java",
     "        try {\n            sessionId = SessionId.fromTrustedComponent(request.assertedSessionId);",
     "        try {\n            limiter.tryAcquire(source);\n"
     "            sessionId = SessionId.fromTrustedComponent(request.assertedSessionId);",
     "refuses garbage before consulting the limiter, so junk cannot spend a victim's allowance"),
    ("SVC-hygiene-order", "src/main/java/com/acme/portal/session/SessionStateVerifierProvider.java",
     "            candidate = only.type();",
     "            candidate = only.get().getClass();",
     "names the candidate class without instantiating it, so a verifier planted in a world-writable"
     " location is refused before its static initialiser or constructor has run"),
    # ---- AttemptLimiter: throttle without enabling lockout
    ("LIM-global-order", "src/main/java/com/acme/portal/session/AttemptLimiter.java",
     "            rollIfStale(global, now);\n"
     "            if (global.count >= globalCeiling) {\n"
     "                // Deliberately before incrementing: a saturated shared lane must not spend this\n"
     "                // source's own allowance, or a flood would lock out the clients it never touched.\n"
     "                return Decision.LIMITED_GLOBALLY;\n"
     "            }\n"
     "            window.count++;\n"
     "            global.count++;",
     "            window.count++;\n"
     "            global.count++;\n"
     "            rollIfStale(global, now);\n"
     "            if (global.count >= globalCeiling) {\n"
     "                return Decision.LIMITED_GLOBALLY;\n"
     "            }",
     "checks the shared lane before charging a source its own allowance"),
    ("LIM-tracking-bound", "src/main/java/com/acme/portal/session/AttemptLimiter.java",
     "if (windows.size() >= maxTrackedSources && !reclaimRolled(now)) {",
     "if (false && windows.size() >= maxTrackedSources && !reclaimRolled(now)) {",
     "bounds tracking state so a source flood cannot grow memory"),
    ("LIM-reclaim-bound", "src/main/java/com/acme/portal/session/AttemptLimiter.java",
     "private static final int RECLAIM_CANDIDATES = 64;",
     "private static final int RECLAIM_CANDIDATES = 200000;",
     "keeps the work done inside the shared monitor independent of how many sources are tracked; a "
     "scan sized by the crowd is what let one client's stall become everyone else's 429"),
    ("LIM-unknown-ceiling", "src/main/java/com/acme/portal/session/AttemptLimiter.java",
     "int ceiling = source.isUnknown() ? unknownSourceCeiling : perSourceCeiling;",
     "int ceiling = perSourceCeiling;",
     "gives an unidentifiable source a smaller bucket than an identified one"),
    # ---- ClientAddress: fair buckets, no DNS, no parser tricks
    ("ADDR-shorthand", "src/main/java/com/acme/portal/session/ClientAddress.java",
     "} else if (!isDottedQuad(remoteAddr)) {",
     "} else if (false) {",
     "refuses InetAddress shorthand forms, so 517996801 cannot become a real address"),
    ("ADDR-allowlist", "src/main/java/com/acme/portal/session/ClientAddress.java",
     "if (!allowed) {",
     "if (false && !allowed) {",
     "restricts address text to hex digits, dot and colon before any parser sees it"),
    ("ADDR-colon-grammar", "src/main/java/com/acme/portal/session/ClientAddress.java",
     "if (remoteAddr.length() > MAX_IPV6_LENGTH || !isIpv6Literal(remoteAddr)) {",
     "if (remoteAddr.length() > MAX_IPV6_LENGTH + 100) {",
     "proves a colon string is a complete IPv6 literal before the JDK parser sees it, so a request "
     "cannot buy an OS resolver round trip with its address text"),
    ("ADDR-compat-fold", "src/main/java/com/acme/portal/session/ClientAddress.java",
     "if (isIpv4Mapped(bytes)) {",
     "if (isIpv4Mapped(bytes)\n                    || (bytes.length == 16 && bytes[10] == 0"
     " && bytes[11] == 0)) {",
     "folds only ::ffff:a.b.c.d; the obsoleted IPv4-compatible fold is what made ::1 claim the "
     "bucket key 0.0.0.1/32"),
    # ---- Settings: no permissive default, no silent normalisation
    ("SET-range", "src/main/java/com/acme/portal/session/SessionHandoffSettings.java",
     "if (value < minimum || value > maximum) {",
     "if (false) {",
     "keeps every numeric setting inside a range where it cannot disable throttling"),
    ("SET-relations", "src/main/java/com/acme/portal/session/SessionHandoffSettings.java",
     "if (maxPerWindow > globalMax) {",
     "if (false) {",
     "refuses a configuration where one source can saturate the global lane"),
    # ---- Servlet: fail closed, uniform refusals, no state-changing methods
    ("SRV-methods-allowed", "src/main/java/com/acme/portal/session/SessionHandoffServlet.java",
     '        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);\n'
     '        response.setHeader("Allow", "GET, HEAD");',
     '        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);\n'
     '        response.setHeader("Allow", "GET, HEAD, POST, PUT, DELETE, PATCH");',
     "advertises only the methods it actually serves"),
    ("SRV-equalizer", "src/main/java/com/acme/portal/session/SessionHandoffServlet.java",
     "WorkEqualizer.apply();",
     "// WorkEqualizer.apply();",
     "does the same fixed work on every outcome so timing cannot rank them"),
    ("SRV-not-serving", "src/main/java/com/acme/portal/session/SessionHandoffServlet.java",
     "            if (!serving) {\n                respondUnavailable(response, writeBody);\n"
     "                return;\n            }",
     "            if (false) {\n                respondUnavailable(response, writeBody);\n"
     "                return;\n            }",
     "answers 503 for everything while it is not serving"),
    ("SRV-serve-partial", "src/main/java/com/acme/portal/session/SessionHandoffServlet.java",
     "boolean complete = service != null && cookieWriter != null && assertionSource != null;",
     "boolean complete = true;",
     "refuses to serve at all unless every collaborator is present"),
    ("SRV-head-cookie", "src/main/java/com/acme/portal/session/SessionHandoffServlet.java",
     "        if (!writeBody) {",
     "        if (false && !writeBody) {",
     "issues no cookie in answer to HEAD, which cannot use one"),
    ("SRV-head-length", "src/main/java/com/acme/portal/session/SessionHandoffServlet.java",
     "response.setContentLength(body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);",
     "response.setContentLength(0);",
     "describes a HEAD with the byte length the equivalent GET would have written, on every outcome"),
    ("SRV-cache-headers", "src/main/java/com/acme/portal/session/SessionHandoffServlet.java",
     "        response.setHeader(\"Cache-Control\", \"no-store, max-age=0\");\n"
     "        response.setHeader(\"Pragma\", \"no-cache\");",
     "        response.setHeader(\"Cache-Control\", \"public, max-age=60\");\n"
     "        response.setHeader(\"Pragma\", \"cache\");",
     "makes every response uncacheable from one place, so a shared cache cannot hold a document that "
     "describes a session decision"),
    ("SRV-shape-drift", "src/main/java/com/acme/portal/session/SessionHandoffServlet.java",
     "        response.setStatus(SC_TOO_MANY_REQUESTS);\n        applyStandardHeaders(response);",
     "        response.setStatus(SC_TOO_MANY_REQUESTS);\n        applyStandardHeaders(response);\n"
     "        response.setHeader(\"Cache-Control\", \"public, max-age=60\");",
     "keeps one response shape for every outcome: a refusal that answers with different cache "
     "directives than a grant tells you which gate answered without looking at the body"),
    # ---- ResponseBody: output encoding on everything that is echoed
    ("BODY-escape", "src/main/java/com/acme/portal/session/ResponseBody.java",
     '                    replacement = "&lt;";',
     "                    replacement = String.valueOf(c);",
     "HTML-encodes the configured cookie name before putting it in a document"),
    ("BODY-output-bound", "src/main/java/com/acme/portal/session/ResponseBody.java",
     "if (out.length() + WIDEST_ENTITY > MAX_ESCAPED_LENGTH) {",
     "if (false) {",
     "bounds the escaped OUTPUT rather than the input read: escaping only grows, so a quote-heavy "
     "value would otherwise leave six times the page budget on the wire"),
    # ---- DeploymentHygiene: refuse to load code from a writable place
    ("HYG-writable", "src/main/java/com/acme/portal/session/DeploymentHygiene.java",
     "return permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);",
     "return false;",
     "refuses to serve when its code is loadable from a world-writable location"),
    ("HYG-missing-entry", "src/main/java/com/acme/portal/session/DeploymentHygiene.java",
     "                return \"a code location named by the deployment is not present to be inspected: \"\n"
     "                        + logSafe(location);",
     "                continue;",
     "reports a classpath entry it could not inspect instead of treating 'never looked' as safe"),
    ("HYG-logsafe", "src/main/java/com/acme/portal/session/DeploymentHygiene.java",
     "            if (c >= 0x20 && c != 0x7F) {",
     "            if (true) {",
     "keeps control characters out of a refusal reason, so a file name cannot forge a second log line"),
]


# A mutant whose edit cannot change any behaviour is an *equivalent* mutant, not a gap in the suite.
# Folding one into "survived" would be as dishonest as folding a build failure into "killed", so each
# one is listed here with the argument and the test that backs it, and reported as its own status.
EQUIVALENT = {
    "ADDR-allowlist":
        "the character allowlist refuses a superset of what the two address grammars refuse, so "
        "deleting the loop cannot change a parse outcome. Harness.clientAddress sweeps 20 564 strings "
        "the allowlist refuses -- every non-allowlisted character on its own and at every position of "
        "eleven address seeds, plus every short string that mixes them with grammar characters -- and "
        "asserts none of them reaches a bucket. Running this mutant, that section reports failures=0: "
        "with the loop gone every one of the 20 564 strings is still refused by the grammars, which is "
        "the equivalence. If a grammar is ever loosened the sweep fails and this entry has to go.",
}


def sh(cmd, cwd=ROOT, timeout=600, env=None):
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return subprocess.run(cmd, cwd=cwd, shell=isinstance(cmd, str), timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=merged)


def main_root():
    """The frozen src/main the whole battery is built from (see PRISTINE)."""
    frozen = os.path.join(ROOT, PRISTINE, "main")
    return frozen if os.path.isdir(frozen) else os.path.join(ROOT, "src/main")


def sources():
    out = []
    for base, _, names in os.walk(os.path.join(main_root(), "java")):
        for name in names:
            if name.endswith(".java"):
                out.append(os.path.join(base, name))
    return out


def prepare_pristine():
    """Compile main and the frozen test suite once; the battery only ever swaps main.

    Its own output directories: build.sh also writes build/classes, and sharing them would let a
    concurrent run compile against (or wipe) another run's half-written classes.
    """
    for path in (os.path.join(ROOT, CLASSES), os.path.join(ROOT, TEST_CLASSES),
                 os.path.join(ROOT, PRISTINE)):
        shutil.rmtree(path, ignore_errors=True)
    os.makedirs(os.path.join(ROOT, CLASSES), exist_ok=True)
    os.makedirs(os.path.join(ROOT, TEST_CLASSES), exist_ok=True)
    os.makedirs(os.path.join(ROOT, PRISTINE), exist_ok=True)
    shutil.copytree(os.path.join(ROOT, "src/main"), os.path.join(ROOT, PRISTINE, "main"))
    api = os.path.join(ROOT, SERVLET_API)
    compile_ = sh([JAVAC, "-nowarn", "-encoding", "US-ASCII", "-cp", api,
                   "-d", CLASSES] + sources(), timeout=600)
    if compile_.returncode != 0:
        sys.exit("pristine main sources do not compile:\n" + compile_.stdout.decode("utf-8", "replace"))
    tests = []
    for base, _, names in os.walk(os.path.join(ROOT, "src/test/java")):
        for name in names:
            if name.endswith(".java"):
                tests.append(os.path.join(base, name))
    compile_ = sh([JAVAC, "-nowarn", "-encoding", "US-ASCII",
                   "-cp", "%s:%s" % (api, os.path.join(ROOT, CLASSES)),
                   "-d", TEST_CLASSES] + tests, timeout=600)
    if compile_.returncode != 0:
        sys.exit("test sources do not compile:\n" + compile_.stdout.decode("utf-8", "replace"))
    return api


def anchor(mutant):
    path = os.path.join(main_root(), os.path.relpath(os.path.join(ROOT, mutant[1]),
                                                      os.path.join(ROOT, "src/main")))
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    return text.count(mutant[2])


def apply_mutant(mutant, dest_root):
    """Copy the frozen src/main to dest_root/src and rewrite one file. (status, detail)."""
    src = main_root()
    target = os.path.join(dest_root, "src")
    if os.path.isdir(dest_root):
        shutil.rmtree(dest_root)
    shutil.copytree(src, target)
    rel = os.path.relpath(os.path.join(ROOT, mutant[1]), os.path.join(ROOT, "src/main"))
    path = os.path.join(target, rel)
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    if text.count(mutant[2]) != 1:
        return "anchor-fail", "expected text occurs %d time(s)" % text.count(mutant[2])
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text.replace(mutant[2], mutant[3], 1))
    return "applied", ""


def run_one(mutant, api, timeout):
    ident = mutant[0]
    # One scratch tree per mutant, and an empty one: sharing a directory between concurrent mutants
    # lets one run read another's classes and fabricate (or mask) a result.
    root = os.path.join(ROOT, WORK, "%s-%d" % (ident, os.getpid()))
    try:
        return _run_one(mutant, ident, root, api, timeout)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _run_one(mutant, ident, root, api, timeout):
    status, detail = apply_mutant(mutant, root)
    if status != "applied":
        return ident, "anchor-fail", detail, []
    classes = os.path.join(root, "classes")
    srcs = []
    for base, _, names in os.walk(os.path.join(root, "src/java")):
        for name in names:
            if name.endswith(".java"):
                srcs.append(os.path.join(base, name))
    built = sh([JAVAC, "-nowarn", "-encoding", "US-ASCII", "-cp", api, "-d", classes] + srcs,
               timeout=timeout)
    if built.returncode != 0:
        return ident, "killed(build)", "does not compile", []
    cp = "%s:%s:%s" % (api, classes, os.path.join(ROOT, TEST_CLASSES))
    # Compile in parallel, but run at most MAX_JVMS harnesses at once. Worker threads alone are not a
    # concurrency guard: a worker that dies instantly also occupies no slot, so the semaphore is what
    # actually bounds live JVMs and keeps the suite's timing assertions honest.
    with MAX_JVMS:
        try:
            run = sh([JAVA, "-cp", cp, "com.acme.portal.session.Harness"], timeout=timeout)
        except subprocess.TimeoutExpired:
            return ident, "timeout", "harness exceeded %d s" % timeout, []
    text = run.stdout.decode("utf-8", "replace")
    failed = [line.strip() for line in text.splitlines() if line.startswith("FAILED")]
    if run.returncode == 0 and not failed:
        return ident, "survived", text.splitlines()[-1] if text else "no output", []
    if failed:
        return ident, "killed(assert)", "FAILED x%d" % len(failed), failed
    # A non-zero exit with no FAILED line is the harness crashing, not an assertion killing the
    # mutant. Reporting it as a kill would credit the suite with something it never checked.
    return ident, "harness-error", "exit %d with no FAILED line" % run.returncode, []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--dry", action="store_true")
    parser.add_argument("--run", nargs="*", default=None)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--max-jvms", type=int, default=2)
    args = parser.parse_args()

    wanted = set(args.run) if args.run else None
    selected = [m for m in MUTANTS if wanted is None or m[0] in wanted]

    if args.list:
        for m in selected:
            print("%-24s %-58s %s" % (m[0], os.path.basename(m[1]), m[4]))
        print("total %d" % len(selected))
        return 0

    unknown = wanted - {m[0] for m in MUTANTS} if wanted else set()
    if unknown:
        print("ERROR unknown mutant ids: %s" % ", ".join(sorted(unknown)), file=sys.stderr)
        return 2

    os.makedirs(os.path.join(ROOT, LOGS), exist_ok=True)
    api = prepare_pristine()

    if args.dry:
        bad = 0
        for m in selected:
            hits = anchor(m)
            print("%-24s anchor=%d %s" % (m[0], hits, "OK" if hits == 1 else "NOT UNIQUE"))
            bad += 0 if hits == 1 else 1
        print("dry run: %d mutant(s), %d anchor problem(s)" % (len(selected), bad))
        return 1 if bad else 0

    if os.path.isdir(os.path.join(ROOT, WORK)):
        shutil.rmtree(os.path.join(ROOT, WORK))
    global MAX_JVMS
    MAX_JVMS = threading.Semaphore(max(1, min(args.max_jvms, args.jobs)))
    started = time.time()
    results = {}
    # Wall clock per mutant, kept so the per-mutant timeout below can be justified by a number in
    # the log instead of by the author's memory of one slow afternoon. With --jobs > 1 these overlap,
    # so they are "how long this mutant took to come back", not CPU time.
    timings = {}

    def timed(mutant):
        began = time.time()
        outcome = run_one(mutant, api, args.timeout)
        timings[mutant[0]] = time.time() - began
        return outcome

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {pool.submit(timed, m): m for m in selected}
        for future in concurrent.futures.as_completed(futures):
            mutant = futures[future]
            try:
                ident, status, detail, failed = future.result()
            except Exception as boom:  # a runner bug must not masquerade as a result
                ident, status, detail, failed = mutant[0], "runner-error", "runner error: %r" % boom, []
            results[ident] = (status, detail, failed)
            with open(os.path.join(ROOT, LOGS, "%s.log" % ident), "w", encoding="utf-8") as handle:
                handle.write("%s %s\n" % (status, detail))
                for line in failed:
                    handle.write(line + "\n")
            print("%-24s %-15s %5.1fs %s" % (ident, status, timings.get(ident, 0.0), detail),
                  flush=True)

    tally = {}
    for ident in sorted(results):
        status, detail, failed = results[ident]
        if status == "survived" and ident in EQUIVALENT:
            results[ident] = ("equivalent", detail, failed)
            # Rewrite the per-mutant log too, so the archived evidence says what the run concluded
            # rather than leaving a bare "survived" for the next reader to re-litigate.
            with open(os.path.join(ROOT, LOGS, "%s.log" % ident), "w", encoding="utf-8") as handle:
                handle.write("equivalent %s\n%s\n" % (detail, EQUIVALENT[ident]))
    for status, _, _ in results.values():
        tally[status] = tally.get(status, 0) + 1
    slowest = max(timings.items(), key=lambda kv: kv[1]) if timings else ("none", 0.0)
    print("\nSUMMARY mutants=%d seconds=%d slowest=%s(%.0fs) %s"
          % (len(selected), time.time() - started, slowest[0], slowest[1],
             " ".join("%s=%d" % kv for kv in sorted(tally.items()))))
    # A build failure is not a test killing the mutant -- it only shows the edit was not a legal
    # program. It is reported separately and never folded into the assertion kill count.
    trouble = ("survived", "anchor-fail", "harness-error", "runner-error", "timeout")
    for ident, (status, detail, failed) in sorted(results.items()):
        if status in trouble:
            print("NEEDS-ATTENTION %s (%s) %s" % (ident, status, detail))
            for line in failed[:4]:
                print("    %s" % line[:160])
        elif status == "equivalent":
            print("EQUIVALENT %s (documented, not a gap) %s" % (ident, EQUIVALENT[ident]))
        elif status == "killed(assert)" and ident in EQUIVALENT:
            print("NOTE %s was listed equivalent but the suite killed it: the two guards have "
                  "diverged, the deleted code is load-bearing again, and this entry must go" % ident)
    kills = tally.get("killed(assert)", 0)
    builds = tally.get("killed(build)", 0)
    accounted = sum(tally.values())
    bad = sum(tally.get(name, 0) for name in trouble)
    print("ACCOUNTED mutants=%d assertion-kills=%d build-failures=%d equivalent=%d needs-attention=%d"
          % (accounted, kills, builds, tally.get("equivalent", 0), bad))
    # The battery is only meaningful when every mutant is accounted for and none survived unexplained.
    return 0 if accounted == len(selected) and bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
