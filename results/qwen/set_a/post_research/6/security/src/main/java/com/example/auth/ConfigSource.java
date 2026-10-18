package com.example.auth;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Read-only view of operator-supplied configuration.
 *
 * <p>Every value obtained through this interface is treated as attacker-controlled: the process
 * environment can be influenced by anything that can write deployment files, and system properties
 * can be influenced by anything that can write the launch command line. Values are therefore never
 * used without the explicit validation performed in {@link AuthConfig}, and an unrecognised
 * {@code AUTH_}-prefixed key is a start-up error rather than something to ignore.
 */
public interface ConfigSource {

    /** Namespace whose unknown keys are rejected instead of ignored. */
    String NAMESPACE = "AUTH_";

    /** Returns the raw value for {@code key}, or {@code null} when absent. */
    String get(String key);

    /** Returns every key this source can see, including keys outside {@value #NAMESPACE}. */
    Set<String> keys();

    /** Configuration taken from the process environment. */
    static ConfigSource ofEnvironment() {
        final Map<String, String> snapshot = new LinkedHashMap<>(System.getenv());
        return new SnapshotConfigSource(snapshot);
    }

    /** Configuration taken from an explicit map; used by tests and by embedded deployments. */
    static ConfigSource ofMap(Map<String, String> values) {
        return new SnapshotConfigSource(new LinkedHashMap<>(values));
    }
}

/**
 * Immutable {@link ConfigSource}. The key set is snapshotted at construction so that
 * {@link AuthConfig} can detect unknown keys in the same namespace.
 */
final class SnapshotConfigSource implements ConfigSource {

    private final Map<String, String> values;
    private final Set<String> keys;

    SnapshotConfigSource(Map<String, String> values) {
        this.values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
        this.keys = Collections.unmodifiableSet(new LinkedHashSet<>(values.keySet()));
    }

    @Override
    public String get(String key) {
        return values.get(key);
    }

    @Override
    public Set<String> keys() {
        return keys;
    }

    @Override
    public String toString() {
        // Never render values: they may contain paths or other operator-private material.
        long inNamespace = keys.stream().filter(k -> k.startsWith(NAMESPACE)).count();
        return "SnapshotConfigSource[" + keys.size() + " keys, " + inNamespace + " in " + NAMESPACE + "]";
    }
}
