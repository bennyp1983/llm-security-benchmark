package example.security.auth;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuthenticationServiceTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-01T12:00:00Z"), ZoneOffset.UTC);

    @Test void successUsesServerStateSecureCookieAndClearsPassword() throws Exception {
        Fixture f = fixture(10, 10);
        char[] supplied = "correct horse battery staple".toCharArray();

        AuthenticationService.Result result = f.service.authenticate("ALICE", supplied,
                InetAddress.getByName("192.0.2.10"));

        assertTrue(result.authenticated());
        assertEquals("Authenticated.", result.message());
        assertTrue(result.setCookieHeader().startsWith("__Host-session="));
        assertTrue(result.setCookieHeader().contains("; Path=/;"));
        assertTrue(result.setCookieHeader().contains("; Secure; HttpOnly; SameSite=Strict"));
        assertFalse(result.toString().contains("__Host-session"));
        assertArrayEquals(new char[supplied.length], supplied);
        assertEquals(AuthenticationEvent.Outcome.SUCCESS, f.events.get(0).outcome());
    }

    @Test void allFailuresAreGenericAndSensitiveValuesNeverReachEvents() throws Exception {
        Fixture f = fixture(10, 10);
        char[] wrong = "not-the-password".toCharArray();
        char[] unknown = "not-the-password".toCharArray();

        var a = f.service.authenticate("alice", wrong, InetAddress.getByName("192.0.2.11"));
        var b = f.service.authenticate("nobody", unknown, InetAddress.getByName("192.0.2.11"));
        var c = f.service.authenticate("bad\nname", new char[0], null);

        assertEquals(AuthenticationService.GENERIC_FAILURE, a.message());
        assertEquals(a, b);
        assertEquals(a, c);
        assertTrue(f.events.stream().allMatch(e -> e.outcome() == AuthenticationEvent.Outcome.FAILURE));
        String events = f.events.toString();
        assertFalse(events.contains("alice"));
        assertFalse(events.contains("not-the-password"));
        assertArrayEquals(new char[wrong.length], wrong);
        assertArrayEquals(new char[unknown.length], unknown);
    }

    @Test void accountThrottleDoesNotLetAnAttackerLockOutCorrectCredentials() throws Exception {
        Fixture f = fixture(1, 1);
        InetAddress source = InetAddress.getByName("192.0.2.12");
        f.service.authenticate("alice", "wrong".toCharArray(), source);
        f.service.authenticate("alice", "still-wrong".toCharArray(), source);
        char[] correct = "correct horse battery staple".toCharArray();

        var result = f.service.authenticate("alice", correct, source);

        assertTrue(result.authenticated());
        assertEquals(AuthenticationEvent.Reason.THROTTLED, f.events.get(1).reason());
    }

    private static Fixture fixture(int sourceLimit, int accountLimit) {
        SecureRandom random = new SecureRandom();
        char[] initial = "correct horse battery staple".toCharArray();
        PasswordRecord record;
        try { record = PasswordVerifier.hashForStorage(initial, random); }
        finally { Arrays.fill(initial, '\0'); }
        var principal = new CredentialStore.AuthenticatedPrincipal("account_01");
        var store = new InMemoryCredentialStore(Map.of("alice",
                new InMemoryCredentialStore.Entry(principal, record)));
        List<AuthenticationEvent> events = new ArrayList<>();
        byte[] key = new byte[32];
        random.nextBytes(key);
        var service = new AuthenticationService(store,
                new InMemoryLoginRateLimiter(Duration.ofMinutes(5), sourceLimit, accountLimit),
                new InMemorySessionStore(100, CLOCK), events::add, random, CLOCK,
                Duration.ofHours(1), key);
        Arrays.fill(key, (byte) 0);
        return new Fixture(service, events);
    }

    private record Fixture(AuthenticationService service, List<AuthenticationEvent> events) {}
}
