package com.acme.portal.session;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;

/**
 * Normalised client source address, used only as a rate-limit bucket key.
 *
 * <p>{@code request.getRemoteAddr()} is supplied by the container. It is unspoofable for a direct
 * TCP connection but fully attacker-chosen behind a proxy, so the container is treated as part of
 * the attack surface: the value is validated before use and never trusted to *identify* anyone.
 * Getting it wrong costs a slower retry for one bucket, never access, which is why it is safe to
 * key a limit on it at all (rules 1 and 3).
 *
 * <p>Canonicalisation matters for fairness. Without it {@code 0:0:0:0:0:0:0:1},
 * {@code 0::1} and {@code ::1} are three different buckets, and an attacker on one IPv6 address
 * could spend the allowance of another by varying textual form. Canonical text is also what keeps
 * the bucket map from growing without bound on cosmetic variants.
 *
 * <p>{@code X-Forwarded-For} and every other {@code * -For} header are deliberately never read:
 * see the README for the deployment condition under which that must be revisited.
 */
public final class ClientAddress {

    /**
     * Address used when the container supplies nothing usable. One shared bucket is the
     * least-privilege choice: a missing source must not become an unlimited lane, and it must not
     * create an unbounded number of lanes either.
     */
    public static final ClientAddress UNKNOWN = new ClientAddress("unknown", 0, true);

    private static final int MAX_RAW_LENGTH = 64;
    private static final int MAX_IPV6_LENGTH = 45;

    /**
     * True for {@code d.d.d.d} with four groups of one to three digits, each 0-255. Refuses the
     * shorthand forms {@code InetAddress} tolerates, so one host cannot open several buckets for one
     * address by varying how it is written.
     */
    private static boolean isDottedQuad(String text) {
        int groups = 0;
        int digits = 0;
        int value = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '.') {
                if (digits == 0 || digits > 3 || value > 255) {
                    return false;
                }
                groups++;
                digits = 0;
                value = 0;
            } else if (c >= '0' && c <= '9') {
                // A leading zero is tolerated in text but the numeric bound below is what matters.
                digits++;
                value = value * 10 + (c - '0');
            } else {
                return false;
            }
        }
        if (digits == 0 || digits > 3 || value > 255) {
            return false;
        }
        groups++;
        return groups == 4;
    }

    /**
     * Full grammar of an IPv6 <i>literal</i>: groups of one to four hex digits, at most one
     * {@code ::}, at most eight 16-bit groups in total, an optional trailing dotted quad, and nothing
     * else. {@code -1} means malformed.
     *
     * <p>This exists because "contains a colon" is not a shape check. The character allowlist permits
     * hex digits and colons, so text like {@code a:b}, {@code 1234:5678} or {@code deadbeef:cafe}
     * looks like an address to anything that only counts dots and colons, and
     * {@code InetAddress.getByName} then hands it to the operating-system resolver as a hostname.
     * Measured here: those forms cost 14-41 us each in a lookup attempt, against 3 us for a real
     * literal, and they cost it on every request before any throttle has been consulted -- an
     * attacker-chosen amount of resolver work per packet. Rejecting them here also means no name
     * beyond this method's grammar can ever reach a resolver from a request.
     *
     * <p>Interface scope ids ({@code fe80::1%9}) never reach here: {@code %} is outside the character
     * allowlist, so they are refused as unparseable and land in the shared unknown bucket.
     *
     * @param run        one side of the {@code ::}, or the whole address when there is none
     * @param atEnd      whether this run ends the address, which is where a dotted quad may appear
     * @return the number of 16-bit groups the run accounts for, or {@code -1}
     */
    private static int ipv6Groups(String run, boolean atEnd) {
        if (run.isEmpty()) {
            return 0;
        }
        String[] parts = run.split(":", -1);
        int total = 0;
        for (int i = 0; i < parts.length; i++) {
            String group = parts[i];
            if (group.indexOf('.') >= 0) {
                // The mixed form is legal only as the last two groups of the whole address.
                if (!atEnd || i != parts.length - 1 || !isDottedQuad(group)) {
                    return -1;
                }
                total += 2;
                continue;
            }
            if (group.isEmpty() || group.length() > 4) {
                return -1;
            }
            for (int c = 0; c < group.length(); c++) {
                char digit = group.charAt(c);
                boolean hex = (digit >= '0' && digit <= '9')
                        || (digit >= 'a' && digit <= 'f')
                        || (digit >= 'A' && digit <= 'F');
                if (!hex) {
                    return -1;
                }
            }
            total++;
        }
        return total;
    }

    /**
     * Whether {@code text} is a complete IPv6 literal, per {@link #ipv6Groups}.
     *
     * <p>Stricter than the JDK where the two disagree: a container emits the expanded
     * eight-group form, so accepting {@code ::} compression is convenience rather than necessity, and
     * anything the JDK would tolerate beyond this grammar (scope ids, embedded text) is refused here
     * and degrades to the shared bucket instead.
     */
    private static boolean isIpv6Literal(String text) {
        int compress = text.indexOf("::");
        if (compress < 0) {
            if (text.indexOf(':') < 0) {
                return false;
            }
            return ipv6Groups(text, true) == 8;
        }
        if (text.indexOf("::", compress + 1) >= 0) {
            return false;
        }
        int head = ipv6Groups(text.substring(0, compress), false);
        int tail = ipv6Groups(text.substring(compress + 2), true);
        // '::' has to stand for at least one all-zero group, so at most six may be written out.
        if (head < 0 || tail < 0 || head + tail > 6) {
            return false;
        }
        if (text.indexOf('.') >= 0) {
            // Inside a compressed address exactly one mixed spelling is accepted: the one a
            // dual-stack container emits for an IPv4 peer. "::127.0.0.1" and its like (the IPv4
            // *compatible* form, obsoleted by RFC 4291) are refused outright rather than
            // canonicalised on a guess -- they mean different things to different stacks, and
            // folding them is how "::1" used to arrive as the bucket key "0.0.0.1/32".
            return isIpv4MappedText(text);
        }
        return true;
    }

    /** The one compressed mixed form that is admitted: {@code ::ffff:d.d.d.d}, either hex case. */
    private static boolean isIpv4MappedText(String text) {
        String prefix = "::ffff:";
        return text.regionMatches(true, 0, prefix, 0, prefix.length())
                && isDottedQuad(text.substring(prefix.length()));
    }

    private final String canonical;
    private final int prefixBits;
    private final boolean unknown;

    private ClientAddress(String canonical, int prefixBits, boolean unknown) {
        this.canonical = canonical;
        this.prefixBits = prefixBits;
        this.unknown = unknown;
    }

    /**
     * Parses and canonicalises a textual address.
     *
     * <p>The shape is checked before the JDK parser is consulted, because
     * {@code InetAddress.getByName} also accepts {@code 517996801}, {@code 0x7f.1}, {@code 10.1} and
     * similar shorthand forms. A container never emits those, and admitting them would mean one host
     * could hold several buckets for the same address purely by textual form -- the exact unfairness
     * this class exists to prevent.
     *
     * @return the canonical form, or {@link #UNKNOWN} for absent, oversized, non-textual or
     *         unparseable input. No exception is thrown: a malformed address must degrade to a
     *         shared limited bucket, never to an unlimited one, and never to a stack trace.
     */
    public static ClientAddress parse(String remoteAddr) {
        if (remoteAddr == null || remoteAddr.isEmpty() || remoteAddr.length() > MAX_RAW_LENGTH) {
            return UNKNOWN;
        }
        // Reject structural surprises before the parser sees them, so no bracket, scope-id,
        // percent-encoding or control character can reach InetAddress parsing. This loop is redundant
        // with the two grammars below -- they admit the same five classes of character and nothing else
        // -- and it is kept as the cheap gate that says so in one line. The harness sweeps every
        // character this refuses against both grammars, so if either grammar is ever loosened the
        // redundancy ends in a failing test rather than in a resolver round trip per request.
        for (int i = 0; i < remoteAddr.length(); i++) {
            char c = remoteAddr.charAt(i);
            boolean allowed = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
                    || c == '.' || c == ':';
            if (!allowed) {
                return UNKNOWN;
            }
        }
        boolean ipv6 = remoteAddr.indexOf(':') >= 0;
        if (ipv6) {
            if (remoteAddr.length() > MAX_IPV6_LENGTH || !isIpv6Literal(remoteAddr)) {
                return UNKNOWN;
            }
        } else if (!isDottedQuad(remoteAddr)) {
            return UNKNOWN;
        }
        InetAddress address;
        try {
            // Only two shapes can arrive here -- a four-group dotted quad and a complete IPv6
            // literal -- and both are literals, so getByName takes its parse-without-a-lookup path
            // and the resolver is never consulted. That guarantee is what the two shape checks exist
            // to provide: a DNS round trip per request would turn the limiter into an amplifier
            // driven by an attacker-supplied address, and reverse lookups are never requested either.
            address = InetAddress.getByName(remoteAddr);
        } catch (IllegalArgumentException malformed) {
            return UNKNOWN;
        } catch (UnknownHostException notAnAddress) {
            return UNKNOWN;
        }
        byte[] bytes = address.getAddress();
        if (address instanceof java.net.Inet4Address) {
            return new ClientAddress(address.getHostAddress(), 32, false);
        }
        if (address instanceof java.net.Inet6Address) {
            // A dual-stack container reports an IPv4 peer as ::ffff:a.b.c.d. That is the same host as
            // a.b.c.d and must not get a second lane, so the mapped form folds onto the IPv4 bucket.
            // The deprecated IPv4-*compatible* form (::a.b.c.d, obsoleted by RFC 4291) is deliberately
            // not folded any more: folding it is what used to turn "::1" into the bucket key
            // "0.0.0.1/32" -- an IPv6 loopback peer asserting an IPv4 identity, merged with an address
            // that never appears on a wire. Nothing a container actually emits needs that fold, so an
            // unroutable legacy spelling now falls into the plain /64 lane like any other v6 peer.
            if (isIpv4Mapped(bytes)) {
                return new ClientAddress(
                        (bytes[12] & 0xFF) + "." + (bytes[13] & 0xFF) + "."
                                + (bytes[14] & 0xFF) + "." + (bytes[15] & 0xFF),
                        32, false);
            }
            // /64 is the allocation unit an attacker commonly controls wholesale (and the unit a
            // /64-routing site hands out), so limiting per address would be a joke while limiting
            // per /64 stays fair to a normal dual-stack client. One consequence is worth writing down
            // instead of leaving to chance: every address whose top 64 bits are zero -- "::1" first --
            // shares the single lane "0:0:0:0/64". Those addresses are not reachable over a public
            // link, so that lane holds local processes and port-forwarded sockets, and merging them
            // is the conservative direction: it can delay a local caller, it cannot hand anyone a
            // wider lane than their own address would have had.
            return new ClientAddress(canonicalIpv6Prefix(bytes), 64, false);
        }
        return UNKNOWN;
    }

    /** True for {@code ::ffff:a.b.c.d}, the form a dual-stack socket reports an IPv4 peer as. */
    private static boolean isIpv4Mapped(byte[] bytes) {
        if (bytes.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF;
    }

    /** Lower-case canonical text of the top 64 bits, e.g. {@code 2001:db8:0:1}. */
    private static String canonicalIpv6Prefix(byte[] bytes) {
        StringBuilder text = new StringBuilder(19);
        for (int group = 0; group < 4; group++) {
            if (group > 0) {
                text.append(':');
            }
            int value = ((bytes[group * 2] & 0xFF) << 8) | (bytes[group * 2 + 1] & 0xFF);
            text.append(Integer.toHexString(value));
        }
        return text.toString().toLowerCase(Locale.ROOT);
    }

    /** Bucket key: canonical text plus the prefix length, so v4 and v6 lanes never collide. */
    public String key() {
        return canonical + '/' + prefixBits;
    }

    /**
     * Whether this bucket shares the allowance with every other unknown-source request. Callers
     * apply a stricter ceiling to it: a request whose source cannot be established is exactly the
     * shape an attacker would forge.
     */
    public boolean isUnknown() {
        return unknown;
    }

    /** Canonical text only. It is the caller's own address, so it is not a secret. */
    @Override
    public String toString() {
        return canonical;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ClientAddress)) {
            return false;
        }
        return key().equals(((ClientAddress) other).key());
    }

    @Override
    public int hashCode() {
        return key().hashCode();
    }
}
