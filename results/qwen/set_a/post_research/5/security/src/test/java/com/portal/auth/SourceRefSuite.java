package com.portal.auth;

import java.util.List;

/**
 * Attribution. Per-source throttling is only as good as the label it throttles on: if two
 * spellings of one machine get two labels, the budget resets per spelling; if a label can
 * be chosen by the client, the limit is opt-out; if parsing a label can crash, a crafted
 * address takes the login endpoint down.
 *
 * <p>The parser is literal-only on purpose. {@code InetAddress.getByName} would resolve a
 * hostname, so an attacker could (a) make the server issue DNS queries with names they
 * choose and (b) get bucketed by an address that has nothing to do with the connection.
 */
public final class SourceRefSuite {

    public static void main(String[] args) {
        ipv4();
        ipv6();
        canonicalisation();
        hostileLabelsNeverThrow();
        cidr();
        forwardedFor();
        System.exit(TestKit.report("source-ref"));
    }

    // -------------------------------------------------------------------------- IPv4

    private static void ipv4() {
        String[] good = {"0.0.0.0", "10.0.0.1", "192.168.1.1", "255.255.255.255", "1.2.3.4"};
        for (String s : good) {
            TestKit.ok("accepted " + s, SourceRef.isLiteralIpv4(s));
        }
        // Each fixture is invalid in exactly one way, so a pass cannot be credited to the
        // wrong rule.
        String[] bad = {"", "1", "1.2", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.256.1.1",
                "1.1.1.256", "01.2.3.4", "1.02.3.4", "1.2.3.04", "1.2.3.", ".1.2.3",
                "1..2.3", "1.2.3.4 ", " 1.2.3.4", "1.2.3.4\n", "1.2.3.-1", "1.2.3.4:80",
                "0x7f.0.0.1", "1.2.3.0x4", "12345678901234", "1.2.3.4\t\t", "fe80::1",
                "1.2.3.4/24", "1.2.3.4#"};
        for (String s : bad) {
            TestKit.ok("refused [" + TestKit.show(s) + "]", !SourceRef.isLiteralIpv4(s));
        }
        TestKit.ok("null refused", !SourceRef.isLiteralIpv4(null));
        TestKit.ok("an octet boundary of 255 is still accepted",
                SourceRef.isLiteralIpv4("10.255.0.255"));
    }

    // -------------------------------------------------------------------------- IPv6

    private static void ipv6() {
        String[] good = {"::", "::1", "2001:db8::1", "fe80::1", "2001:0db8:0000:0000:"
                + "0000:0000:0000:0001", "ABCD:EF01:2345:6789:ABCD:EF01:2345:6789",
                "::ffff:192.168.0.1", "2001:db8::192.168.0.1", "1:2:3:4:5:6:7:8",
                "1::8", "1:2:3:4:5:6::8", "::2:3:4:5:6:7:8", "1:2:3:4:5:6:7::"};
        for (String s : good) {
            TestKit.ok("accepted " + s, SourceRef.isLiteralIpv6(s));
            TestKit.ok("expands " + s, SourceRef.expandIpv6(s) != null);
        }
        String[] bad = {"", ":", ":::", "1::2::3", "1:2:3:4:5:6:7:8:9", "12345::",
                "fe80::1%eth0", "fe80::1%25eth0", "g::1", "1:2:3:4:5:6:7:g",
                "1.2.3.4", "2001:db8::192.168.0.256", "2001:db8::1.2.3", "::ffff:0x7f000001",
                "1:", ":1", "2001:db8:::1", "1:2:3:4:5:6:7:8:", "::1::"};
        for (String s : bad) {
            TestKit.ok("refused [" + TestKit.show(s) + "]", !SourceRef.isLiteralIpv6(s));
        }
        TestKit.ok("null refused", !SourceRef.isLiteralIpv6(null));
        TestKit.ok("oversized rejected without parsing",
                !SourceRef.isLiteralIpv6("f".repeat(60) + "::"));
        // A scope id is not just invalid, it must not be silently accepted as a valid
        // address with the suffix ignored -- that would leak an interface name into the
        // derived bucket and let one host pick its own bucket.
        TestKit.ok("scope id does not fold onto the bare address",
                !SourceRef.ref("fe80::1%eth0").equals(SourceRef.ref("fe80::1")));
    }

    private static void canonicalisation() {
        TestKit.eq("short form and long form share a bucket",
                SourceRef.canonical("2001:db8::1"),
                SourceRef.canonical("2001:0DB8:0000:0000:0000:0000:0000:0001"));
        TestKit.eq("case does not change the bucket", SourceRef.canonical("ABCD::1"),
                SourceRef.canonical("abcd::1"));
        TestKit.eq("the derived reference agrees", SourceRef.ref("2001:db8::1"),
                SourceRef.ref("2001:0DB8:0000:0000:0000:0000:0000:0001"));
        TestKit.eq("embedded v4 matches its own hex expansion",
                SourceRef.canonical("::ffff:192.168.0.1"), SourceRef.canonical("::ffff:c0a8:1"));
        TestKit.ok("and is not confused with the different address that drops the ffff",
                !SourceRef.canonical("::ffff:192.168.0.1")
                        .equals(SourceRef.canonical("::c0a8:1")));
        TestKit.eq("ipv4 canonicalises to itself", "10.0.0.1", SourceRef.canonical("10.0.0.1"));
        TestKit.ok("distinct addresses get distinct buckets",
                !SourceRef.ref("10.0.0.1").equals(SourceRef.ref("10.0.0.2")));
        TestKit.eq("the bucket label is 16 lower hex", true,
                SourceRef.ref("2001:db8::1").matches("[0-9a-f]{16}"));
        TestKit.eq("null canonicalises to empty, never throws", "",
                SourceRef.canonical(null));
        TestKit.eq("the local pipe has its own bucket", true,
                !SourceRef.ref(SourceRef.LOCAL_LABEL).equals(SourceRef.ref("unknown")));
    }

    /**
     * The regression this whole file exists for: {@code isLiteralIpv6} was defined as
     * {@code expandIpv6(...) != null} while {@code expandIpv6} began by calling
     * {@code isLiteralIpv6}. Any input that was not a plain IPv4 literal recursed until the
     * stack blew up, which is a remote denial of service against the login endpoint -- and
     * it survived until something other than a dotted-quad was ever tried.
     */
    private static void hostileLabelsNeverThrow() {
        String[] labels = {"", "garbage", "localhost", "LOCALHOST", "not-an-ip", "999.1.1.1",
                "1.2.3.4 ", "%20", "x".repeat(300), "fe80::1%eth0", "::", "::1", "2001:db8::1",
                "::::", "1::2::3::4::5", "\u00e9\u00e9\u00e9", "\u0000\u0001", "10.0.0.1:80",
                "HTTP/1.1\r\nX: y", "0:0:0:0:0:0:0:0", "-1.-1.-1.-1", "https://10.0.0.1",
                "ref:0123456789abcdef", "0123456789abcdef", "ffff:ffff:ffff:ffff:ffff:ffff"
                        + ":ffff:ffff", "a".repeat(128), "b".repeat(129), "1.2.3.4/32",
                "[::1]", "%25%31", "\\", "'", "\" OR 1=1 --"};
        String unknown = SourceRef.normalizeForLedger("definitely not an address");
        for (String s : labels) {
            try {
                String got = SourceRef.normalizeForLedger(s);
                TestKit.ok("labelled [" + TestKit.show(s) + "] as " + got,
                        got != null && got.length() == 16 && got.matches("[0-9a-f]{16}"));
            } catch (Throwable t) {
                TestKit.ok("normalizeForLedger[" + TestKit.show(s) + "] threw "
                        + t.getClass().getSimpleName(), false);
            }
        }
        TestKit.ok("null is bucketed, not fatal",
                SourceRef.normalizeForLedger(null) != null);
        TestKit.eq("oversized joins the unknown bucket rather than being refused", unknown,
                SourceRef.normalizeForLedger("c".repeat(4000)));
        TestKit.eq("junk joins the unknown bucket", unknown,
                SourceRef.normalizeForLedger("still not an address"));
        TestKit.ok("the unknown bucket is not a real address's bucket",
                !unknown.equals(SourceRef.normalizeForLedger("10.0.0.1")));
        TestKit.ok("a real IPv6 literal is not in the unknown bucket",
                !unknown.equals(SourceRef.normalizeForLedger("2001:db8::1")));
    }

    // ---------------------------------------------------------------------------- CIDR

    private static void cidr() {
        TestKit.ok("/0 accepted", SourceRef.parseCidr("0.0.0.0/0").prefix == 0);
        TestKit.ok("/32 accepted", SourceRef.parseCidr("10.0.0.1/32").prefix == 32);
        // The parsed network must really be masked: if the host bits survived, a /24
        // configured as 10.0.9.0/24 would trust only 10.0.9.0 itself, and one configured
        // from a proxy's own address would silently trust the whole /8 instead.
        List<SourceRef.Cidr> onlyNine = SourceRef.parseCidrList("10.0.9.0/24");
        TestKit.ok("a /24 trusts the whole /24", SourceRef.isTrusted("10.0.9.200", onlyNine));
        TestKit.ok("a /24 does not trust the neighbouring /24",
                !SourceRef.isTrusted("10.0.10.1", onlyNine));
        TestKit.ok("a /24 does not trust the address it was written as, plus one host bit",
                !SourceRef.isTrusted("10.0.10.0", onlyNine));
        TestKit.ok("/32 trusts exactly one address",
                SourceRef.isTrusted("10.0.0.1", SourceRef.parseCidrList("10.0.0.1/32"))
                        && !SourceRef.isTrusted("10.0.0.2",
                        SourceRef.parseCidrList("10.0.0.1/32")));
        String[] badSpecs = {null, "", "10.0.0.0", "10.0.0.0/", "/24", "10.0.0.0/33",
                "10.0.0.0/-1", "10.0.0.0/024", "10.0.0.0/+8", "10.0.0.0/+0", "10.0.0.0/8/8",
                "010.0.0.0/8", "10.0.0.256/8",
                "10.0.0.0/abc", "10.0.0.0/ 8", "10.0.0.0/8 ", "::1/128", "10.0.0.0//8"};
        for (String s : badSpecs) {
            TestKit.ok("config refused [" + TestKit.show(s) + "]", throwsIllegal(
                    () -> SourceRef.parseCidr(s)));
        }
        List<SourceRef.Cidr> trusted = SourceRef.parseCidrList("10.0.0.0/8,192.168.0.0/16");
        TestKit.eq("two ranges", 2, trusted.size());
        TestKit.ok("inside the range", SourceRef.isTrusted("10.1.2.3", trusted));
        TestKit.ok("outside the range", !SourceRef.isTrusted("11.1.2.3", trusted));
        TestKit.ok("boundary in", SourceRef.isTrusted("10.255.255.255", trusted));
        TestKit.ok("other range", SourceRef.isTrusted("192.168.7.7", trusted));
        TestKit.ok("an IPv6 peer is never trusted by an IPv4 range",
                !SourceRef.isTrusted("2001:db8::1", trusted));
        TestKit.ok("junk is never trusted", !SourceRef.isTrusted("garbage", trusted));
        TestKit.ok("empty list trusts nobody",
                !SourceRef.isTrusted("10.0.0.1", SourceRef.parseCidrList("")));
        TestKit.eq("empty config parses to empty", 0, SourceRef.parseCidrList(null).size());
        TestKit.ok("empty entry refused",
                throwsIllegal(() -> SourceRef.parseCidrList("10.0.0.0/8,,10.0.0.0/8")));
        TestKit.ok("too many ranges refused", throwsIllegal(
                () -> SourceRef.parseCidrList(String.join(",", java.util.Collections.nCopies(
                        17, "10.0.0.0/8")))));
        TestKit.ok("oversized list refused",
                throwsIllegal(() -> SourceRef.parseCidrList("z".repeat(600))));
        TestKit.ok("/0 trusts everything",
                SourceRef.isTrusted("8.8.8.8", SourceRef.parseCidrList("0.0.0.0/0")));
    }

    // ------------------------------------------------------------------ X-Forwarded-For

    private static final String[] pendingRepair = {
            "\r203.0.113.9", "203.0.113.9\r\n", "203.0.113.9\u0000", "\u0000203.0.113.9",
            "\n203.0.113.9", "\u00a0203.0.113.9", "\u2007203.0.113.9", "203.0.113.9\u000b",
            "\u000c203.0.113.9", "\r\n 203.0.113.9", " 203.0.113.9 \r\n",
            " 203.0.113.9, 10.0.0.6\r\n", "203.0.113.\u00099",
    };

    private static void forwardedFor() {
        List<SourceRef.Cidr> trusted = SourceRef.parseCidrList("10.0.0.0/8");

        TestKit.eq("no header means the socket peer", "203.0.113.9",
                SourceRef.resolvePeer("203.0.113.9", null, trusted));
        TestKit.eq("empty header means the socket peer", "203.0.113.9",
                SourceRef.resolvePeer("203.0.113.9", "", trusted));

        // A client that is not a trusted proxy cannot move itself behind one. This is the
        // whole point of walking right-to-left and of checking the socket peer first.
        TestKit.eq("forged XFF from an untrusted peer is ignored", "203.0.113.9",
                SourceRef.resolvePeer("203.0.113.9", "10.0.0.1", trusted));
        TestKit.eq("forged chain from an untrusted peer is ignored", "203.0.113.9",
                SourceRef.resolvePeer("203.0.113.9", "8.8.8.8, 10.0.0.1", trusted));

        TestKit.eq("through a trusted proxy the real client is used", "203.0.113.9",
                SourceRef.resolvePeer("10.0.0.5", "203.0.113.9", trusted));
        TestKit.eq("right-to-left: untrusted entry stops the walk", "203.0.113.9",
                SourceRef.resolvePeer("10.0.0.5", "198.51.100.7, 203.0.113.9", trusted));
        // Right-to-left: the answer is the rightmost address that is not one of our
        // proxies, i.e. the closest hop we cannot explain. A client that prepends its own
        // entries to a chain our proxy already extended cannot get past that point, which
        // is the property that matters -- see the forged-header cases above.
        TestKit.eq("our own proxies are stepped over from the right", "203.0.113.9",
                SourceRef.resolvePeer("10.0.0.5", "203.0.113.9, 10.0.0.6, 10.0.0.7", trusted));
        TestKit.eq("a client-prefixed fake entry is never chosen", "198.51.100.7",
                SourceRef.resolvePeer("10.0.0.5", "8.8.8.8, 198.51.100.7, 10.0.0.6", trusted));
        TestKit.eq("all-trusted chain falls back to the socket peer", "10.0.0.5",
                SourceRef.resolvePeer("10.0.0.5", "10.0.0.6, 10.0.0.7", trusted));

        // Malformed entries must never be used. HTTP optional whitespace (SP/HTAB) is
        // stripped because the standard itself puts it between list items -- every real
        // proxy sends "client, proxy1" -- but no other whitespace is repaired.
        TestKit.eq("standard ', ' separated list is honoured", "203.0.113.9",
                SourceRef.resolvePeer("10.0.0.5", "203.0.113.9, 10.0.0.6", trusted));
        TestKit.eq("a padded single hop is honoured", "203.0.113.9",
                SourceRef.resolvePeer("10.0.0.5", " 203.0.113.9 ", trusted));
        TestKit.eq("tab padding is honoured", "203.0.113.9",
                SourceRef.resolvePeer("10.0.0.5", "\t203.0.113.9\t", trusted));
        // Padding that String.trim() would happily eat must not be able to steer the
        // bucket: an address wrapped in invisible characters must stay malformed.
        String[] invisiblePadding = pendingRepair;
        for (String p : invisiblePadding) {
            TestKit.eq("padding [" + TestKit.show(p) + "] cannot steer the bucket", "10.0.0.5",
                    SourceRef.resolvePeer("10.0.0.5", p, trusted));
        }
        TestKit.eq("a junk hop keeps the socket peer", "10.0.0.5",
                SourceRef.resolvePeer("10.0.0.5", "evil.example", trusted));
        TestKit.eq("an oversized header keeps the socket peer", "10.0.0.5",
                SourceRef.resolvePeer("10.0.0.5", "203.0.113.9" + ",10.0.0.9".repeat(40),
                        trusted));
        TestKit.eq("too many hops keeps the socket peer", "10.0.0.5",
                SourceRef.resolvePeer("10.0.0.5",
                        "203.0.113.9" + ",10.0.0.9".repeat(8), trusted));
        TestKit.eq("an over-long single hop keeps the socket peer", "10.0.0.5",
                SourceRef.resolvePeer("10.0.0.5", "f".repeat(60), trusted));
        TestKit.eq("with no proxies configured the header is inert", "203.0.113.9",
                SourceRef.resolvePeer("203.0.113.9", "8.8.8.8", List.of()));
        TestKit.eq("an unparseable socket peer is the unknown bucket", "unknown",
                SourceRef.resolvePeer("hostname-not-an-ip", "8.8.8.8", trusted));
        TestKit.eq("an IPv6 client behind a proxy is honoured", "2001:db8::7",
                SourceRef.resolvePeer("10.0.0.5", "2001:db8::7", trusted));
        TestKit.ok("different clients behind one proxy get different buckets",
                !SourceRef.ref(SourceRef.resolvePeer("10.0.0.5", "203.0.113.9", trusted))
                        .equals(SourceRef.ref(
                                SourceRef.resolvePeer("10.0.0.5", "198.51.100.9", trusted))));
    }

    // ---------------------------------------------------------------------------- utils

    private static boolean throwsIllegal(Runnable r) {
        try {
            r.run();
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }
}
