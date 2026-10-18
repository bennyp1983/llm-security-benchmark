package com.portal.auth;

import java.util.ArrayList;
import java.util.List;

/**
 * Turns a network peer into the label used for per-source throttling.
 *
 * <p>The peer address is the only client-supplied value that participates in a security
 * decision other than the credentials, so it is parsed by hand rather than through
 * {@link java.net.InetAddress}: {@code InetAddress.getByName} performs a DNS lookup for
 * anything that is not a literal address, which would (a) let an attacker make the
 * server issue DNS queries with attacker-chosen names, and (b) accept a hostname whose
 * resolved address has nothing to do with the connection. Literal-only parsing also
 * rejects IPv6 scope ids ({@code %eth0}), which would otherwise leak an interface name
 * into a derived value.
 *
 * <p>{@code X-Forwarded-For} is honoured only when the socket peer is inside the
 * configured trusted-proxy set, and then by walking the list right-to-left and stopping
 * at the first address that is not a trusted proxy. A client that injects a forged
 * {@code X-Forwarded-For} cannot move itself behind a trusted address, because the walk
 * only ever discards entries it recognises as its own proxies.
 */
public final class SourceRef {

    public static final String LOCAL_LABEL = "local";
    private static final int MAX_HOPS = 8;

    private SourceRef() {
    }

    /** 16-hex reference used as the ledger key and in audit lines. */
    public static String ref(String rawAddressOrLabel) {
        return Crypto.sha256Hex(normalizeToCanonical(rawAddressOrLabel)).substring(0, 16);
    }

    /**
     * Reduce whatever a front end hands the throttle layer to a ledger key. Never
     * throws for hostile input: an unparseable address collapses to the "unknown"
     * bucket, which is still throttled, so a caller cannot escape per-source limiting by
     * sending a malformed address.
     */
    public static String normalizeForLedger(String rawAddressOrLabel) {
        return ref(rawAddressOrLabel);
    }

    private static String normalizeToCanonical(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "unknown";
        }
        if (raw.length() > 128) {
            // Oversized: not a valid address, so it joins the "unknown" bucket, which is
            // still rate-limited. Refusing outright would hand an attacker a way to skip
            // per-source limiting by overflowing the label.
            return "unknown";
        }
        if (LOCAL_LABEL.equals(raw)) {
            return LOCAL_LABEL;
        }
        if (isLiteralIpv4(raw) || isLiteralIpv6(raw)) {
            return canonical(raw);
        }
        // An already-derived reference (from a worker process) is namespaced so it can
        // never collide with the canonical form of a real address. It is only ever a lookup
        // key, never rendered back to a client. Note that this means normalising is NOT
        // idempotent -- ref(ref(x)) is a different bucket from ref(x) -- so each request
        // must reduce its label exactly once. PortalServer resolves the peer and hands the
        // *label* to the Authenticator, which performs that one reduction.
        if (raw.length() == 16 && isLowerHex(raw)) {
            return "ref:" + raw;
        }
        return "unknown";
    }

    /** Strict dotted-quad: four octets, 0-255, no leading zeros, no extra text. */
    public static boolean isLiteralIpv4(String s) {
        if (s == null || s.length() < 7 || s.length() > 15) {
            return false;
        }
        int octets = 0;
        int value = 0;
        int digits = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '.') {
                if (digits == 0) {
                    return false;
                }
                if (digits > 1 && s.charAt(i - digits) == '0') {
                    return false;
                }
                if (value > 255) {
                    return false;
                }
                octets++;
                value = 0;
                digits = 0;
                continue;
            }
            if (c < '0' || c > '9') {
                return false;
            }
            value = value * 10 + (c - '0');
            digits++;
            if (value > 255) {
                return false;
            }
        }
        if (digits == 0 || value > 255) {
            return false;
        }
        if (digits > 1 && s.charAt(s.length() - digits) == '0') {
            return false;
        }
        return octets == 3;
    }

    /**
     * Strict RFC 4291 textual IPv6, with {@code ::} compression and an embedded IPv4
     * suffix. Rejects zone/scope identifiers ({@code %eth0}) and anything that is not
     * hexadecimal. There is exactly one parser -- {@link #expandIpv6} -- because a
     * second validator that disagrees with the expander is how an address ends up
     * accepted by one code path and bucketed differently by another.
     */
    public static boolean isLiteralIpv6(String s) {
        return expandIpv6(s) != null;
    }

    /**
     * Normalise for comparison so that two spellings of one address share a throttle
     * bucket: IPv4 as-is, IPv6 expanded to eight lower-case 4-digit groups. Returns the
     * input unchanged if it cannot be expanded -- an address that failed the strict
     * literal parse never reaches a security decision anyway.
     */
    public static String canonical(String literal) {
        if (literal == null) {
            return "";
        }
        if (isLiteralIpv4(literal)) {
            return literal;
        }
        String[] expanded = expandIpv6(literal);
        if (expanded == null) {
            return literal.toLowerCase(java.util.Locale.ROOT);
        }
        StringBuilder sb = new StringBuilder(39);
        for (int i = 0; i < expanded.length; i++) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(expanded[i]);
        }
        return sb.toString();
    }

    /**
     * Eight zero-padded lower-case groups, or null when the text is not a valid literal.
     *
     * <p>This is the only IPv6 parser in the program and it must not ask
     * {@link #isLiteralIpv6} whether its input is valid first: that predicate is defined
     * as {@code expandIpv6(...) != null}, so the two would call each other until the stack
     * ran out. Every shape check lives here, in the one function that produces the answer.
     */
    static String[] expandIpv6(String text) {
        if (text == null || text.isEmpty() || text.length() > 45) {
            // 45 is the longest legal textual form,
            // "0000:0000:0000:0000:0000:0000:255.255.255.255", so nothing valid is refused
            // and oversized junk is rejected without being parsed.
            return null;
        }
        String s = text.toLowerCase(java.util.Locale.ROOT);
        String v4Tail = "";
        int lastColon = s.lastIndexOf(':');
        String candidateTail = s.substring(lastColon + 1);
        if (candidateTail.indexOf('.') >= 0) {
            if (!isLiteralIpv4(candidateTail)) {
                return null;
            }
            v4Tail = candidateTail;
            s = s.substring(0, lastColon + 1) + v4ToTailGroups(candidateTail);
        }
        String left;
        String right;
        int dc = s.indexOf("::");
        if (dc >= 0) {
            left = s.substring(0, dc);
            right = s.substring(dc + 2);
        } else {
            left = s;
            right = null;
        }
        List<String> low = groupsOf(left, true);
        if (low == null) {
            return null;
        }
        List<String> high = new ArrayList<>();
        if (right != null) {
            high = groupsOf(right, false);
            if (high == null) {
                return null;
            }
            if (low.size() + high.size() > 7) {
                return null;
            }
        } else if (low.size() != 8) {
            return null;
        } else {
            high = List.of();
        }
        List<String> out = new ArrayList<>(low);
        while (out.size() < 8 - high.size()) {
            out.add("0000");
        }
        out.addAll(high);
        if (out.size() != 8) {
            return null;
        }
        String[] arr = new String[8];
        for (int i = 0; i < 8; i++) {
            String g = out.get(i);
            if (g.length() > 4) {
                return null;
            }
            arr[i] = "0000".substring(g.length()) + g;
        }
        return arr;
    }

    private static String v4ToTailGroups(String v4) {
        long value = ipv4ToLong(v4);
        int hi = (int) ((value >> 16) & 0xFFFF);
        int lo = (int) (value & 0xFFFF);
        return String.format("%04x:%04x", hi, lo);
    }

    private static List<String> groupsOf(String half, boolean allowEmptyBecauseCompressed) {
        List<String> out = new ArrayList<>();
        if (half.isEmpty()) {
            return out;
        }
        for (String g : half.split(":", -1)) {
            if (g.isEmpty() || g.length() > 4) {
                return null;
            }
            for (int i = 0; i < g.length(); i++) {
                if (!isHexDigit(g.charAt(i))) {
                    return null;
                }
            }
            out.add(g);
        }
        return out;
    }

    private static String stripLeadingZeros(String group) {
        int i = 0;
        while (i < group.length() - 1 && group.charAt(i) == '0') {
            i++;
        }
        return group.substring(i);
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isLowerHex(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    /** A parsed IPv4 CIDR. IPv6 is deliberately not supported as a trusted-proxy range. */
    public static final class Cidr {
        public final long network;
        public final int prefix;

        Cidr(long network, int prefix) {
            this.network = network;
            this.prefix = prefix;
        }
    }

    /** Strict {@code a.b.c.d/pp} parse. Anything else is a configuration refusal. */
    public static Cidr parseCidr(String spec) {
        if (spec == null) {
            throw new IllegalArgumentException("cidr-null");
        }
        int slash = spec.indexOf('/');
        if (slash < 0 || spec.indexOf('/', slash + 1) >= 0) {
            throw new IllegalArgumentException("cidr-shape");
        }
        String addr = spec.substring(0, slash);
        String mask = spec.substring(slash + 1);
        if (!isLiteralIpv4(addr) || mask.isEmpty() || mask.length() > 2) {
            throw new IllegalArgumentException("cidr-shape");
        }
        int prefix;
        try {
            prefix = Integer.parseInt(mask);
        } catch (NumberFormatException bad) {
            throw new IllegalArgumentException("cidr-prefix");
        }
        if (prefix < 0 || prefix > 32) {
            throw new IllegalArgumentException("cidr-prefix-range");
        }
        // The range check alone is not enough: parseInt accepts a leading sign, so "/+8"
        // parses as 8 and passes while "/08" is refused below. A trusted-proxy range decides
        // which socket peers may name a client in the throttle ledger, so exactly one
        // spelling must mean 8 -- otherwise the text a reviewer approved ("/+8") and the rule
        // the parser applied ("/8") are different objects that happen to agree today.
        for (int i = 0; i < mask.length(); i++) {
            if (mask.charAt(i) < '0' || mask.charAt(i) > '9') {
                throw new IllegalArgumentException("cidr-prefix-form");
            }
        }
        if (mask.length() > 1 && mask.charAt(0) == '0') {
            throw new IllegalArgumentException("cidr-prefix-form");
        }
        return new Cidr(ipv4ToLong(addr), prefix);
    }

    public static List<Cidr> parseCidrList(String csv) {
        List<Cidr> out = new ArrayList<>();
        if (csv == null || csv.isBlank()) {
            return out;
        }
        if (csv.length() > 512) {
            throw new IllegalArgumentException("cidr-list-too-long");
        }
        for (String part : csv.split(",")) {
            if (part.isEmpty()) {
                throw new IllegalArgumentException("cidr-empty-entry");
            }
            out.add(parseCidr(part));
        }
        if (out.size() > 16) {
            throw new IllegalArgumentException("cidr-list-too-many");
        }
        return out;
    }

    /**
     * The address to attribute a request to.
     *
     * @param socketPeer literal address of the TCP peer (never a hostname)
     * @param forwardedValue raw {@code X-Forwarded-For} header, may be null
     * @param trusted proxies we are willing to believe; empty means the header is ignored
     */
    public static String resolvePeer(String socketPeer, String forwardedValue, List<Cidr> trusted) {
        String peer = isLiteralIpv4(socketPeer) || isLiteralIpv6(socketPeer) ? socketPeer : null;
        if (peer == null) {
            return "unknown";
        }
        if (trusted.isEmpty() || forwardedValue == null || forwardedValue.isEmpty()) {
            return peer;
        }
        if (!isTrusted(peer, trusted)) {
            return peer;
        }
        if (forwardedValue.length() > 256) {
            return peer;
        }
        String[] hops = forwardedValue.split(",");
        if (hops.length == 0 || hops.length > MAX_HOPS) {
            return peer;
        }
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = trimOws(hops[i]);
            if (hop.length() > 45) {
                return peer;
            }
            // After the optional whitespace the standard puts around a list item, the hop
            // must be a strict IP literal. Anything else -- a hostname, an address padded
            // with CR/LF/NUL, a value with trailing junk -- is a reason to keep the socket
            // peer rather than to repair the value.
            if (!isLiteralIpv4(hop) && !isLiteralIpv6(hop)) {
                return peer;
            }
            if (!isTrusted(hop, trusted)) {
                return hop;
            }
        }
        return peer;
    }

    /**
     * Strip HTTP optional whitespace (SP / HTAB only, RFC 9110 OWS) around a list item.
     *
     * <p>{@code X-Forwarded-For} is defined as a comma-separated list, and every
     * implementation on this planet separates the items with {@code ", "}, so a walker that
     * refuses a leading space never fires against a real proxy at all -- the trusted-proxy
     * feature would silently do nothing and every behind-a-proxy user would share the
     * proxy's single throttle bucket, which is the opposite of what it exists for.
     *
     * <p>This is deliberately narrower than {@code String.trim()}, which removes every
     * character {@code <= U+0020} including NUL, CR and LF: an attacker could then steer
     * their own bucket by padding an address with invisible characters, or smuggle a line
     * break into a value that is later written to a log. A hop padded with anything other
     * than SP/HTAB stays malformed and the socket peer is kept.
     */
    private static String trimOws(String hop) {
        int from = 0;
        int to = hop.length();
        while (from < to && (hop.charAt(from) == ' ' || hop.charAt(from) == '\t')) {
            from++;
        }
        while (to > from && (hop.charAt(to - 1) == ' ' || hop.charAt(to - 1) == '\t')) {
            to--;
        }
        return hop.substring(from, to);
    }

    public static boolean isTrusted(String literalIpv4, List<Cidr> trusted) {
        if (!isLiteralIpv4(literalIpv4)) {
            return false;
        }
        long value = ipv4ToLong(literalIpv4);
        for (Cidr c : trusted) {
            long mask = c.prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - c.prefix)) & 0xFFFFFFFFL;
            if ((value & mask) == (c.network & mask)) {
                return true;
            }
        }
        return false;
    }

    private static long ipv4ToLong(String addr) {
        long out = 0;
        int value = 0;
        boolean any = false;
        for (int i = 0; i < addr.length(); i++) {
            char c = addr.charAt(i);
            if (c == '.') {
                out = (out << 8) | value;
                value = 0;
                any = false;
                continue;
            }
            value = value * 10 + (c - '0');
            any = true;
        }
        if (!any) {
            throw new IllegalArgumentException("ipv4-trailing");
        }
        return (out << 8) | value;
    }
}
