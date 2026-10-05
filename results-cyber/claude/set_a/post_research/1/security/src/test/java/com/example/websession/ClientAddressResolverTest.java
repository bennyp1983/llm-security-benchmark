package com.example.websession;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class ClientAddressResolverTest {

    @Test
    void ignoresForwardedForWhenNoProxyIsTrusted() {
        FakeHttp.Request request = new FakeHttp.Request().header("X-Forwarded-For", "1.2.3.4");
        request.remoteAddr = "203.0.113.7";
        assertEquals("203.0.113.7", new ClientAddressResolver(0).resolve(request.proxy()));
    }

    @Test
    void readsOnlyTheHopTheTrustedProxyWrote() {
        FakeHttp.Request request = new FakeHttp.Request()
                .header("X-Forwarded-For", "9.9.9.9, 198.51.100.20");
        request.remoteAddr = "10.0.0.1";
        // One trusted proxy: it wrote the last entry; "9.9.9.9" came from the client.
        assertEquals("198.51.100.20", new ClientAddressResolver(1).resolve(request.proxy()));
    }

    @Test
    void fallsBackToTheObservedAddressForJunkValues() {
        FakeHttp.Request junk = new FakeHttp.Request().header("X-Forwarded-For", "not-an-address");
        junk.remoteAddr = "203.0.113.7";
        assertEquals("203.0.113.7", new ClientAddressResolver(1).resolve(junk.proxy()));

        FakeHttp.Request oversized = new FakeHttp.Request().header("X-Forwarded-For", "1.1.1.1, ".repeat(400));
        oversized.remoteAddr = "203.0.113.8";
        assertEquals("203.0.113.8", new ClientAddressResolver(1).resolve(oversized.proxy()));

        FakeHttp.Request shortChain = new FakeHttp.Request().header("X-Forwarded-For", "1.1.1.1");
        shortChain.remoteAddr = "203.0.113.9";
        assertEquals("203.0.113.9", new ClientAddressResolver(3).resolve(shortChain.proxy()));
    }

    @Test
    void stripsPortsAndAcceptsIpv6() {
        FakeHttp.Request v6 = new FakeHttp.Request().header("X-Forwarded-For", "[2001:db8::1]:443");
        v6.remoteAddr = "10.0.0.1";
        assertEquals("2001:db8::1", new ClientAddressResolver(1).resolve(v6.proxy()));

        FakeHttp.Request v4 = new FakeHttp.Request().header("X-Forwarded-For", "198.51.100.3:52000");
        v4.remoteAddr = "10.0.0.1";
        assertEquals("198.51.100.3", new ClientAddressResolver(1).resolve(v4.proxy()));
    }
}
