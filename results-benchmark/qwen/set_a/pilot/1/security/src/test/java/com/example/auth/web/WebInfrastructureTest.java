package com.example.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.auth.session.InMemorySessionRegistry;
import com.example.auth.session.SessionCookieConfig;
import com.example.auth.session.SessionCookieConfig.SameSite;
import com.example.auth.session.SessionRegistry;
import jakarta.servlet.ServletContext;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class WebInfrastructureTest {

    private static final class FakeContext {
        final Map<String, Object> attributes = new LinkedHashMap<>();
        final Map<String, String> initParams = new LinkedHashMap<>();

        ServletContext proxy() {
            return (ServletContext) Proxy.newProxyInstance(
                    ServletContext.class.getClassLoader(),
                    new Class<?>[] {ServletContext.class},
                    (p, method, args) -> {
                        switch (method.getName()) {
                            case "getAttribute":
                                return attributes.get((String) args[0]);
                            case "setAttribute":
                                attributes.put((String) args[0], args[1]);
                                return null;
                            case "getInitParameter":
                                return initParams.get((String) args[0]);
                            default:
                                if (method.getReturnType() == boolean.class) {
                                    return Boolean.FALSE;
                                }
                                return method.getReturnType().isPrimitive() ? 0 : null;
                        }
                    });
        }
    }

    @Test
    void defaultsToAHardenedHostOnlyCookie() {
        SessionCookieConfig config = WebInfrastructure.sessionCookieConfig(new FakeContext().proxy());

        assertEquals("SESSION", config.effectiveName());
        assertEquals("/", config.path());
        assertNull(config.domain());
        assertEquals(-1, config.maxAgeSeconds());
        assertTrue(config.secure());
        assertTrue(config.httpOnly());
        assertEquals(SameSite.LAX, config.sameSite());
        assertEquals(Duration.ofMinutes(30), WebInfrastructure.sessionTtl(new FakeContext().proxy()));
    }

    @Test
    void contextParamsTightenTheCookie() {
        FakeContext context = new FakeContext();
        context.initParams.put(WebInfrastructure.COOKIE_NAME_PARAM, "APPSESSION");
        context.initParams.put(WebInfrastructure.COOKIE_HOST_PREFIX_PARAM, "true");
        context.initParams.put(WebInfrastructure.COOKIE_SAME_SITE_PARAM, "strict");
        context.initParams.put(WebInfrastructure.COOKIE_MAX_AGE_PARAM, "1800");
        context.initParams.put(WebInfrastructure.SESSION_TTL_PARAM, "1800");

        SessionCookieConfig config = WebInfrastructure.sessionCookieConfig(context.proxy());

        assertEquals("__Host-APPSESSION", config.effectiveName());
        assertEquals(SameSite.STRICT, config.sameSite());
        assertEquals(1800, config.maxAgeSeconds());
        assertEquals(Duration.ofSeconds(1800), WebInfrastructure.sessionTtl(context.proxy()));
    }

    @Test
    void anApplicationBoundRegistryOrConfigWins() {
        FakeContext context = new FakeContext();
        SessionRegistry bound = new InMemorySessionRegistry();
        context.attributes.put(WebInfrastructure.SESSION_REGISTRY_ATTRIBUTE, bound);
        context.attributes.put(WebInfrastructure.COOKIE_CONFIG_ATTRIBUTE,
                SessionCookieConfig.DEFAULTS.withSameSite(SameSite.STRICT));

        assertSame(bound, WebInfrastructure.sessionRegistry(context.proxy()));
        assertEquals(SameSite.STRICT,
                WebInfrastructure.sessionCookieConfig(context.proxy()).sameSite());
    }

    @Test
    void theDefaultRegistryIsSharedByEverythingInWebApplication() {
        FakeContext context = new FakeContext();

        assertSame(WebInfrastructure.sessionRegistry(context.proxy()),
                WebInfrastructure.sessionRegistry(context.proxy()));
    }

    @Test
    void rejectsNonsenseConfigurationInsteadOfGuessing() {
        FakeContext badNumber = new FakeContext();
        badNumber.initParams.put(WebInfrastructure.SESSION_TTL_PARAM, "thirty-minutes");
        assertThrows(IllegalStateException.class,
                () -> WebInfrastructure.sessionTtl(badNumber.proxy()));

        FakeContext badSameSite = new FakeContext();
        badSameSite.initParams.put(WebInfrastructure.COOKIE_SAME_SITE_PARAM, "no-restrictions");
        assertThrows(IllegalStateException.class,
                () -> WebInfrastructure.sessionCookieConfig(badSameSite.proxy()));
    }
}
