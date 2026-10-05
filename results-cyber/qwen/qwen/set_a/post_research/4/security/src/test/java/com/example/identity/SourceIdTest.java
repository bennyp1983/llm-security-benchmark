package com.example.identity;

import static com.example.identity.Harness.check;
import static com.example.identity.Harness.checkEquals;
import static com.example.identity.Harness.section;

/**
 * The asserted network origin, which is the key of a rate-limit bucket.
 *
 * <p>Deliberately not {@link java.net.InetAddress#getByName}: that resolves hostnames, so
 * {@code "attacker.example"} would become a bucket - and one hostname could resolve to many
 * addresses or many hostnames to one, letting whoever controls DNS choose which bucket a request
 * lands in. It also accepts octal ({@code 0177.0.0.1}) and short ({@code 127.1}) IPv4 forms, each a
 * second spelling of the same host and so a second identity for the same limiter.
 *
 * <p>Everything here is about one property: one network source maps to exactly one bucket, and no
 * caller can choose a label that maps onto somebody else's.
 */
public final class SourceIdTest {

    private SourceIdTest() {
    }

    public static void run() {
        section("SourceId: the local label and canonical forms");
        checkEquals("local parses", "local", SourceId.parse(SourceId.LOCAL).canonical());
        checkEquals("surrounding spaces are stripped", "local", SourceId.parse("  local  ").canonical());
        checkEquals("a canonical IPv4 round-trips", "192.0.2.1", SourceId.parse("192.0.2.1").canonical());
        checkEquals("::1 canonicalises to itself", "::1", SourceId.parse("::1").canonical());
        checkEquals("an IPv4-mapped tail renders as hex groups",
                "::ffff:c000:201", SourceId.parse("::ffff:192.0.2.1").canonical());

        section("SourceId: surrounding spaces are stripped, everything else survives to be refused");
        checkEquals("spaces around an IPv4 are stripped", "127.0.0.1", SourceId.parse(" 127.0.0.1 ").canonical());
        checkEquals("spaces around an IPv6 are stripped", "::1", SourceId.parse(" ::1 ").canonical());

        section("SourceId: every alternative IPv4 spelling is refused, not folded");
        // Each of these denotes a real address by some legacy rule. Accepting any of them would give
        // one host an unlimited supply of distinct bucket identities, which is the limiter's own
        // bypass - so they are refused outright rather than canonicalised.
        for (String bad : new String[]{
                "0177.0.0.1",          // octal first octet
                "010.0.0.1",           // octal
                "000.0.0.1",           // octal zero
                "127.1",               // two-part short form
                "127.0.1",             // three-part short form
                "127",                 // single number
                "2130706433",          // 127.0.0.1 as one integer
                "0x7f.0.0.1",          // hex octet
                "127.0.0.1.",          // trailing dot
                ".127.0.0.1",          // leading dot
                "127.0.0.01",          // leading zero in the last octet
                "256.0.0.1",           // out of range
                "127.0.0.-1",          // negative
                "127.0.0.+1",          // signed
                "127.0.0",             // too few octets
                "127.0.0.1.7",         // too many octets
                "127.0.0.1/24",        // CIDR is not an address
                "127.0.0.1:80",        // a port is not part of the origin
                "127.0.0.1%eth0",      // scope id is not part of the origin
                "127.0.0.1;INIT=1",    // JDBC property separator must never reach a key
                "127.0.0.1 =x",        // assignment
                "localhost",           // would be resolved
                "LOCAL",               // the local label is case-sensitive
                "Local",
                "127.0.0.1\u0009",     // tab (trim() would delete it and it would still parse)
                "127.0.0.1\u0000",     // NUL
                "127.0.0.1\u007f",     // DEL
                "2001:db8::\u0000",
                "[::1]",               // brackets belong to URLs, not to a bucket key
                "", " ", "   ", "..", "%"}) {
            check("refused: '" + flat(bad) + "'", SourceId.parse(bad) == null);
        }
        check("null is refused", SourceId.parse(null) == null);
        check("an oversized label is refused without being scanned",
                SourceId.parse("1" + Harness.repeat("2", 400)) == null);

        section("SourceId: malformed IPv6 is refused, not folded");
        for (String bad : new String[]{
                "::1%1",                     // scope id
                "fe80::1%eth0",
                "fe80::1%9",
                "[::1]",
                "1::2::3",                   // two compressions
                "12345::1",                  // over-long group
                ":::",
                "::::",
                "1:2:3:4:5:6:7:8:9",         // too many groups
                "gggg::1",                   // not hex
                "::1\u0009",
                "2001:db8::192.0.2.256",     // bad embedded IPv4
                "2001:db8::192.0.2",         // truncated embedded IPv4
                "::192.0.2.1.5"}) {          // embedded IPv4 must be a whole quad
            check("refused: '" + flat(bad) + "'", SourceId.parse(bad) == null);
        }

        section("SourceId: distinct hosts get distinct buckets, one host gets one bucket");
        check("different addresses have different canonical forms",
                !SourceId.parse("192.0.2.1").canonical().equals(SourceId.parse("192.0.2.2").canonical()));
        checkEquals("the full form of ::1 canonicalises to the compressed form",
                SourceId.parse("::1").canonical(), SourceId.parse("0:0:0:0:0:0:0:1").canonical());
        checkEquals("upper-case hex canonicalises to lower case",
                SourceId.parse("2001:DB8::1").canonical(), SourceId.parse("2001:db8::1").canonical());
        checkEquals("leading zeros in a group canonicalise away",
                SourceId.parse("2001:0db8::1").canonical(), SourceId.parse("2001:db8::1").canonical());
        check("the two spellings really are the SAME bucket key (a limiter must not be evadable by"
                + " spelling)", "::1".equals(SourceId.parse("0:0:0:0:0:0:0:1").canonical()));
        checkEquals("the all-zero address canonicalises to ::", "::", SourceId.parse("0:0:0:0:0:0:0:0").canonical());
        checkEquals("a single zero group is not compressed (RFC 5952)",
                "2001:db8:0:1::1", SourceId.parse("2001:DB8:0:1:0:0:0:1").canonical());
        checkEquals("the longest zero run wins, and a leading single group stays literal",
                "0:1:2:3:4:5:6:7", SourceId.parse("::1:2:3:4:5:6:7").canonical());
        checkEquals("a trailing run is compressed", "1::", SourceId.parse("1:0:0:0:0:0:0:0").canonical());
        checkEquals("the first of two equal-length runs wins (RFC 5952 section 4.2.2)",
                "1::5:6:0:0", SourceId.parse("1:0:0:0:5:6:0:0").canonical());
        check("every canonical form round-trips through the parser",
                "192.0.2.1".equals(SourceId.parse(SourceId.parse("192.0.2.1").canonical()).canonical())
                        && "::1".equals(SourceId.parse(SourceId.parse("::1").canonical()).canonical())
                        && "2001:db8:0:1::1".equals(
                        SourceId.parse(SourceId.parse("2001:DB8:0:1:0:0:0:1").canonical()).canonical()));

        section("SourceId: the canonical form is the only accepted construction");
        for (String notCanonical : new String[]{"0177.0.0.1", "127.1", "127.0.0.01", "LOCAL", "[::1]",
                "0:0:0:0:0:0:0:1", "2001:DB8::1", "2001:0db8::1"}) {
            boolean rejectedAtTheBoundary = false;
            try {
                new SourceId(notCanonical);
            } catch (IllegalArgumentException expected) {
                rejectedAtTheBoundary = true;
            }
            check("the record itself refuses the non-canonical '" + flat(notCanonical) + "'",
                    rejectedAtTheBoundary);
        }
        check("an empty canonical is refused by the record", throwsIae(""));
        check("an over-long canonical is refused by the record", throwsIae("1" + Harness.repeat("2", 60)));
        check("null canonical is refused by the record", throwsIae(null));

        section("SourceId: nothing a log sees can be the value");
        SourceId v4 = SourceId.parse("198.51.100.23");
        SourceId v6 = SourceId.parse("2001:db8:1234::5");
        check("an IPv4 renders as the family only",
                "SourceId[ipv4]".equals(v4.toString()));
        check("an IPv6 renders as the family only",
                "SourceId[ipv6]".equals(v6.toString()));
        check("local renders as local", "SourceId[local]".equals(SourceId.local().toString()));
        check("the rendered IPv4 does not contain the address", !v4.toString().contains("198.51.100.23"));
        check("the rendered IPv4 does not contain any octet of it",
                !v4.toString().contains("198") && !v4.toString().contains("23"));
        check("the rendered IPv6 does not contain the address", !v6.toString().contains("2001:db8"));

        section("SourceId: registration budget is keyed by source, not by identity");
        // Structural guard. When this was keyed on email+"|"+username, one source could register an
        // unlimited number of accounts by varying them - i.e. the per-source limit Rule 3 asks for
        // did not exist. Behaviour alone cannot falsify that cheaply (it needs two sources), so the
        // call site is asserted directly. Comment-stripped so prose cannot satisfy it.
        String store = Harness.stripJavaComments(Harness.sourceOf("SqlIdentityStore"));
        int at = store.indexOf("Outcome register(");
        check("the register method is found in the store source", at >= 0);
        String registerBody = at >= 0 ? braceBlock(store, at) : "";
        check("the register body is non-empty", registerBody.length() > 200);
        check("the per-source registration bucket uses the source's canonical label",
                registerBody.contains("source.canonical()"));
        // The registration bucket must live in its own namespace. It used to be built with the
        // sign-in source kind, so a clearBucket(SOURCE, ip) after a successful sign-in wiped that
        // source's registration budget, and failed sign-ins from a source exhausted its ability to
        // register. Asserting the kind here is what keeps the two budgets separate.
        check("the per-source registration bucket is built from the source's canonical label under the"
                + " registration kind (never the sign-in kind, never from the email or username)",
                registerBody.contains("bucketId(BUCKET_KIND_REGISTER_SOURCE, source.canonical())")
                        && !registerBody.contains("bucketId(BUCKET_KIND_SOURCE, source.canonical())"));
        check("the account cap is counted inside register (not before the lock)",
                registerBody.contains("countAll(\"account\")"));
        check("register takes the serialisation row lock with FOR UPDATE",
                registerBody.toUpperCase(java.util.Locale.ROOT).contains("FOR UPDATE"));
        check("register refuses to proceed when the serialisation row is missing",
                registerBody.contains("STORAGE_UNAVAILABLE"));
    }

    // ------------------------------------------------------------------ helpers

    private static String flat(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            sb.append(c < 0x20 || c > 0x7e ? '?' : c);
        }
        return sb.length() == 0 ? "<empty>" : sb.toString();
    }

    private static boolean throwsIae(String value) {
        try {
            new SourceId(value);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    /** The brace-delimited block starting at or after {@code from}. */
    private static String braceBlock(String text, int from) {
        int open = text.indexOf('{', from);
        if (open < 0) {
            return "";
        }
        int depth = 0;
        for (int i = open; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return text.substring(from, i + 1);
                }
            }
        }
        return "";
    }
}
