package com.employee.portal.security.ratelimit;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;

/**
 * Thread-safe bounded LRU (Least Recently Used) cache to prevent memory exhaustion DoS (Rule 5).
 * Uses a ReentrantLock to ensure atomic check-and-act operations (Rule 7).
 */
public final class BoundedLruCache<K, V> {

    private final int maxCapacity;
    private final LinkedHashMap<K, V> map;
    private final ReentrantLock lock;

    public BoundedLruCache(int maxCapacity) {
        if (maxCapacity <= 0) {
            throw new IllegalArgumentException("maxCapacity must be > 0");
        }
        this.maxCapacity = maxCapacity;
        this.lock = new ReentrantLock();
        this.map = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > BoundedLruCache.this.maxCapacity;
            }
        };
    }

    public V get(K key) {
        Objects.requireNonNull(key, "key cannot be null");
        lock.lock();
        try {
            return map.get(key);
        } finally {
            lock.unlock();
        }
    }

    public void put(K key, V value) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(value, "value cannot be null");
        lock.lock();
        try {
            map.put(key, value);
        } finally {
            lock.unlock();
        }
    }

    public V remove(K key) {
        Objects.requireNonNull(key, "key cannot be null");
        lock.lock();
        try {
            return map.remove(key);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Atomically computes a new value for the key. Guarantees atomic check-and-act (Rule 7).
     */
    public V compute(K key, BiFunction<? super K, ? super V, ? extends V> remappingFunction) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(remappingFunction, "remappingFunction cannot be null");
        lock.lock();
        try {
            return map.compute(key, remappingFunction);
        } finally {
            lock.unlock();
        }
    }

    public int size() {
        lock.lock();
        try {
            return map.size();
        } finally {
            lock.unlock();
        }
    }

    public void clear() {
        lock.lock();
        try {
            map.clear();
        } finally {
            lock.unlock();
        }
    }

    public void forEach(BiConsumer<? super K, ? super V> action) {
        Objects.requireNonNull(action);
        lock.lock();
        try {
            map.forEach(action);
        } finally {
            lock.unlock();
        }
    }
}
