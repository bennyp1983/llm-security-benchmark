package com.example.users;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * JDBC test double assembled from the {@code java.sql} interfaces with dynamic proxies, so the
 * repository can be exercised without a database driver on the classpath.
 *
 * <p>It records what the repository actually did - the SQL text it asked for, the parameters it
 * bound, the columns it read, which resources it closed - which is exactly what the security
 * properties here are about.
 */
final class FakeJdbc {

    /** Observations a test asserts on, for a single lookup. */
    static final class Recorded {
        String sql;
        int prepareCalls;
        int otherConnectionCalls;
        int maxRows = -1;
        final Map<Integer, Object> parameters = new LinkedHashMap<>();
        final Set<Integer> columnsRead = new TreeSet<>();
        int nextCalls;
        boolean executed;
        boolean statementClosed;
        boolean resultSetClosed;
    }

    private FakeJdbc() {
    }

    /**
     * @param rows      scripted result rows, in the column order of the SELECT list
     * @param onPrepare exception to throw from {@code prepareStatement}, or {@code null}
     */
    static Connection connection(Recorded rec, List<Object[]> rows, SQLException onPrepare) {
        return (Connection) Proxy.newProxyInstance(
                FakeJdbc.class.getClassLoader(),
                new Class<?>[] {Connection.class},
                (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return objectMethod(proxy, method, args);
                    }
                    if ("prepareStatement".equals(method.getName()) && args != null && args.length >= 1) {
                        rec.prepareCalls++;
                        rec.sql = (String) args[0];
                        if (onPrepare != null) {
                            throw onPrepare;
                        }
                        return statement(rec, rows);
                    }
                    // close / commit / rollback / setAutoCommit: anything the repository might
                    // try against a connection it does not own.
                    rec.otherConnectionCalls++;
                    return defaultValue(method.getReturnType());
                });
    }

    private static PreparedStatement statement(Recorded rec, List<Object[]> rows) {
        return (PreparedStatement) Proxy.newProxyInstance(
                FakeJdbc.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if (method.getDeclaringClass() == Object.class) {
                        return objectMethod(proxy, method, args);
                    }
                    if ("executeQuery".equals(name)) {
                        rec.executed = true;
                        return resultSet(rec, rows);
                    }
                    if ("setMaxRows".equals(name)) {
                        rec.maxRows = (Integer) args[0];
                        return null;
                    }
                    if ("close".equals(name)) {
                        rec.statementClosed = true;
                        return null;
                    }
                    if (name.startsWith("set") && args != null && args.length >= 2 && args[0] instanceof Integer) {
                        rec.parameters.put((Integer) args[0], args[1]);
                        return null;
                    }
                    return defaultValue(method.getReturnType());
                });
    }

    private static ResultSet resultSet(Recorded rec, List<Object[]> rows) {
        int[] cursor = {-1};
        boolean[] lastWasNull = {false};

        return (ResultSet) Proxy.newProxyInstance(
                FakeJdbc.class.getClassLoader(),
                new Class<?>[] {ResultSet.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if (method.getDeclaringClass() == Object.class) {
                        return objectMethod(proxy, method, args);
                    }
                    switch (name) {
                        case "next":
                            rec.nextCalls++;
                            cursor[0]++;
                            return cursor[0] < rows.size();
                        case "close":
                            rec.resultSetClosed = true;
                            return null;
                        case "wasNull":
                            return lastWasNull[0];
                        case "getString":
                        case "getLong":
                        case "getInt":
                        case "getTimestamp":
                        case "getObject": {
                            Object value = valueAt(rec, rows, cursor[0], args[0], name);
                            lastWasNull[0] = value == null;
                            if (value == null) {
                                return defaultValue(method.getReturnType());
                            }
                            switch (name) {
                                case "getString":
                                    return value.toString();
                                case "getLong":
                                    return ((Number) value).longValue();
                                case "getInt":
                                    return ((Number) value).intValue();
                                case "getTimestamp":
                                    return (Timestamp) value;
                                default:
                                    return value;
                            }
                        }
                        default:
                            return defaultValue(method.getReturnType());
                    }
                });
    }

    private static Object valueAt(Recorded rec, List<Object[]> rows, int cursor, Object column, String accessor) {
        if (!(column instanceof Integer)) {
            throw new UnsupportedOperationException(
                    accessor + " by label is not supported by this double; the repository reads by index");
        }
        int index = (Integer) column;
        rec.columnsRead.add(index);
        Object[] row = rows.get(cursor);
        if (index < 1 || index > row.length) {
            throw new IllegalStateException("column " + index + " is outside the scripted row of "
                    + row.length + " columns");
        }
        return row[index - 1];
    }

    private static Object objectMethod(Object proxy, java.lang.reflect.Method method, Object[] args) {
        switch (method.getName()) {
            case "toString":
                return "FakeJdbc";
            case "hashCode":
                return System.identityHashCode(proxy);
            case "equals":
                return proxy == args[0];
            default:
                return defaultValue(method.getReturnType());
        }
    }

    /** Zero/false for primitive return types, so an unstubbed call cannot blow up on unboxing. */
    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive() || type == void.class) {
            return null;
        }
        if (type == boolean.class) {
            return Boolean.FALSE;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == double.class) {
            return 0d;
        }
        if (type == float.class) {
            return 0f;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        return Character.valueOf((char) 0);
    }
}
