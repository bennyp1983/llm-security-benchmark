package com.example.identity;

/**
 * The per-source rate-limit key: the label the deployment asserts about <em>where a request came
 * from</em>.
 *
 * <h2>This value is attacker-influenced, and that is the whole problem with it</h2>
 * Rule 1 says treat it as hostile; Rule 3 says limit attempts per source. Those collide - a label
 * the caller chooses is a label the caller can rotate, and rotating it defeats a per-source limit.
 * Four controls keep that from being the end of the story:
 * <ol>
 *   <li><b>Strict grammar, no resolver.</b> Only a canonical IPv4/IPv6 <em>literal</em> or the
 *     literal {@code local}. Deliberately not {@link java.net.InetAddress#getByName}: it performs a
 *     DNS lookup for anything it cannot parse, which would let a name server decide a rate-limit
 *     bucket, and its IPv4 parser has historically accepted octal and leading-zero forms, letting
 *     {@code 0177.0.0.1} be a distinct key for one host. Addresses are parsed here, byte by byte,
 *     and re-rendered canonically, so {@code 0:0:0:0:0:0:0:1}, {@code ::1} and {@code ::0001} all
 *     map to one bucket. Scope ids ({@code %eth0}) name an interface on the <em>server</em> and say
 *     nothing about the client, so they are refused rather than folded in.</li>
 *   <li><b>A rejected source aborts the request.</b> An unusable label is
 *     {@link Reason#INVALID_REQUEST} and the attempt is never counted <em>and never proceeds</em> -
 *     no lookup, no derivation. Evasion would require a garbage label to be <em>accepted</em>;
 *     instead it gets nothing, and the request costs the caller a refusal rather than our CPU.</li>
 *   <li><b>Independent limits that do not depend on it.</b> The per-account counter is keyed by the
 *     account and so is global across sources; registration additionally has a global budget.
 *     Source-spraying buys neither unlimited attempts against one account nor unlimited
 *     registrations.</li>
 *   <li><b>Not rotatable in the delivered shape.</b> The CLI passes the constant {@code local}, so
 *     everyone at the keyboard shares one bucket.</li>
 * </ol>
 *
 * <p><b>Remaining risk, for the reviewer:</b> the label is asserted by whatever fronts this code. A
 * front end that trusts {@code X-Forwarded-For} lets an attacker pick their own bucket, and the
 * per-source limit becomes decorative - the per-account and global limits then carry the whole
 * load. Binding the source to the actual transport peer is the deployment's job and is called out
 * in README "Limitations".
 */
public record SourceId(String canonical) {

    static final String LOCAL = "local";
    private static final int MAX_INPUT_CHARS = 45; // 45 == longest IPv6 literal, 15 for IPv4

    public SourceId {
        if (canonical == null || canonical.isEmpty() || canonical.length() > MAX_INPUT_CHARS) {
            throw new IllegalArgumentException("source label is unusable");
        }
        if (!LOCAL.equals(canonical) && !isCanonicalIp(canonical)) {
            throw new IllegalArgumentException("source label must be a canonical IP literal or local");
        }
    }

    /** The label every CLI request uses. */
    static SourceId local() {
        return new SourceId(LOCAL);
    }

    /**
     * Validates and canonicalises. Returns {@code null} for anything unacceptable.
     */
    static SourceId parse(String submitted) {
        String s = Identity.stripSurroundingSpacesOnly(submitted);
        if (s == null || s.isEmpty() || s.length() > MAX_INPUT_CHARS) {
            return null;
        }
        if (Identity.containsControlOrDel(s)) {
            return null;
        }
        if (LOCAL.equals(s)) {
            return new SourceId(LOCAL);
        }
        byte[] raw = s.indexOf(':') >= 0 ? parseIpv6(s) : parseIpv4(s);
        if (raw == null) {
            return null;
        }
        try {
            return new SourceId(render(raw));
        } catch (IllegalArgumentException rejected) {
            return null;
        }
    }

    // ------------------------------------------------------------------ IPv4

    /** Dotted quad, 0-255 per octet, no leading zeros, no short forms, no sign, no whitespace. */
    static byte[] parseIpv4(String s) {
        if (s.isEmpty() || s.length() > 15) {
            return null;
        }
        String[] parts = s.split("\\.", -1); // literal dot, not the regex "any char"
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3) {
                return null;
            }
            for (int j = 0; j < p.length(); j++) {
                if (p.charAt(j) < '0' || p.charAt(j) > '9') {
                    return null;
                }
            }
            if (p.length() > 1 && p.charAt(0) == '0') {
                return null; // "0177" would be a second spelling of 127
            }
            int v = Integer.parseInt(p);
            if (v > 255) {
                return null;
            }
            out[i] = (byte) v;
        }
        return out;
    }

    // ------------------------------------------------------------------ IPv6

    /**
     * Full-form and compressed IPv6, with an optional embedded IPv4 tail. No scope id, no brackets,
     * no percent, and {@code ::} appears at most once. Anything ambiguous is refused; refusing is
     * safe here because a refused source never reaches authentication.
     */
    static byte[] parseIpv6(String s) {
        if (s.isEmpty() || s.length() > 45 || s.indexOf('%') >= 0 || s.indexOf('[') >= 0
                || s.indexOf(']') >= 0 || s.indexOf(' ') >= 0) {
            return null;
        }
        int doubleColon = s.indexOf("::");
        if (doubleColon >= 0 && s.indexOf("::", doubleColon + 1) >= 0) {
            return null; // two compressions is not an address
        }
        String head;
        String tail;
        boolean compressed;
        if (doubleColon >= 0) {
            head = s.substring(0, doubleColon);
            tail = s.substring(doubleColon + 2);
            compressed = true;
        } else {
            head = s;
            tail = "";
            compressed = false;
        }
        int[] groups = new int[8];
        int count = 0;
        int[] headGroups = groupsOf(head, false);
        if (headGroups == null) {
            return null;
        }
        for (int g : headGroups) {
            if (count >= 8) {
                return null;
            }
            groups[count++] = g;
        }
        int[] tailGroups = groupsOf(tail, true);
        if (tailGroups == null) {
            return null;
        }
        if (!compressed) {
            if (tailGroups.length != 0 || headGroups.length + 0 != 8 - tailGroups.length) {
                return null;
            }
        }
        if (count + tailGroups.length > 8) {
            return null;
        }
        // Right-align the tail; the gap is the compressed run.
        int tailStart = 8 - tailGroups.length;
        if (!compressed && tailGroups.length != 0) {
            return null;
        }
        if (compressed && count > tailStart) {
            return null; // head and tail would overlap
        }
        if (!compressed && count != 8) {
            return null;
        }
        for (int g : tailGroups) {
            groups[tailStart++] = g;
        }
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[i * 2] = (byte) (groups[i] >>> 8);
            out[i * 2 + 1] = (byte) (groups[i] & 0xFF);
        }
        return out;
    }

    /**
     * Colon-separated 16-bit hex groups, each 1-4 digits, optionally ending in a dotted quad.
     * Empty input yields a zero-length group list (the {@code ::} edge cases).
     */
    private static int[] groupsOf(String part, boolean trailingSide) {
        if (part.isEmpty()) {
            return new int[0];
        }
        // An empty component adjacent to the compression marker belongs to the marker, not to us:
        // "fe80::1" -> tail "1"; "::ffff:1.2.3.4" -> tail "ffff:1.2.3.4". A leading or trailing
        // lone colon here ("1:::2" minus "::" leaves ":2") is malformed.
        if (part.startsWith(":") || part.endsWith(":")) {
            return null;
        }
        String[] tokens = part.split(":", -1);
        int[] scratch = new int[tokens.length + 2];
        int n = 0;
        for (int i = 0; i < tokens.length; i++) {
            String t = tokens[i];
            if (t.isEmpty()) {
                return null;
            }
            int dot = t.indexOf('.');
            if (dot >= 0) {
                // Embedded IPv4 is legal only as the final 32 bits.
                if (i != tokens.length - 1) {
                    return null;
                }
                byte[] v4 = parseIpv4(t);
                if (v4 == null) {
                    return null;
                }
                if (n + 2 > 8) {
                    return null;
                }
                scratch[n++] = ((v4[0] & 0xFF) << 8) | (v4[1] & 0xFF);
                scratch[n++] = ((v4[2] & 0xFF) << 8) | (v4[3] & 0xFF);
                continue;
            }
            if (t.length() > 4) {
                return null;
            }
            int v = 0;
            for (int j = 0; j < t.length(); j++) {
                int d = Character.digit(t.charAt(j), 16);
                if (d < 0) {
                    return null;
                }
                v = (v << 4) | d;
            }
            scratch[n++] = v;
        }
        return java.util.Arrays.copyOf(scratch, n);
    }

    // ------------------------------------------------------------------ rendering

    /** Canonical text: dotted quad, or RFC 5952 lower-case with the longest zero run compressed. */
    private static String render(byte[] raw) {
        if (raw.length == 4) {
            StringBuilder sb = new StringBuilder(15);
            for (int i = 0; i < 4; i++) {
                if (i > 0) {
                    sb.append('.');
                }
                sb.append(raw[i] & 0xFF);
            }
            return sb.toString();
        }
        int[] g = new int[8];
        for (int i = 0; i < 8; i++) {
            g[i] = ((raw[i * 2] & 0xFF) << 8) | (raw[i * 2 + 1] & 0xFF);
        }
        int bestStart = -1;
        int bestLen = 0;
        int runStart = -1;
        for (int i = 0; i <= 8; i++) {
            boolean zero = i < 8 && g[i] == 0;
            if (zero) {
                if (runStart < 0) {
                    runStart = i;
                }
            } else if (runStart >= 0) {
                int len = i - runStart;
                if (len > bestLen) { // strictly longest wins, ties go to the first
                    bestLen = len;
                    bestStart = runStart;
                }
                runStart = -1;
            }
        }
        if (bestLen < 2) {
            bestStart = -1; // RFC 5952: do not compress a single group
        }
        StringBuilder sb = new StringBuilder(45);
        int i = 0;
        while (i < 8) {
            if (bestStart >= 0 && i == bestStart) {
                sb.append("::");
                i += bestLen;
                if (i >= 8) {
                    break;
                }
            } else if (sb.length() > 0 && !sb.toString().endsWith(":")) {
                sb.append(':');
            }
            sb.append(Integer.toHexString(g[i]));
            i++;
        }
        return sb.toString();
    }

    /** Round-trips through the parser, so a rendering bug cannot silently widen the key space. */
    private static boolean isCanonicalIp(String s) {
        if (LOCAL.equals(s)) {
            return true;
        }
        byte[] raw = s.indexOf(':') >= 0 ? parseIpv6(s) : parseIpv4(s);
        return raw != null && render(raw).equals(s);
    }

    /** Never the raw value; the address family is all a log line gets. */
    @Override
    public String toString() {
        return LOCAL.equals(canonical) ? "SourceId[local]" : "SourceId[" + (canonical.indexOf(':') >= 0 ? "ipv6" : "ipv4") + "]";
    }
}
