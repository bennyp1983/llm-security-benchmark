import java.nio.file.*;
import java.security.SecureRandom;
import java.sql.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Probe {
    static byte[] kdf(char[] pw, byte[] salt, int iters) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(pw, salt, iters, 256);
        try {
            return f.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    public static void main(String[] a) throws Exception {
        Path base = Files.createTempDirectory("probe");
        System.out.println("TEMP=" + base);

        // 1. file access mode options
        String[] opts = {"ACCESS_MODE_DATA=rw-------", "ACCESS_MODE_DATA=rw", "ACCESS_MODE_DATA=rws"};
        int i = 0;
        for (String o : opts) {
            String url = "jdbc:h2:" + base.resolve("db" + (i++)) + ";" + o + ";DB_CLOSE_ON_EXIT=FALSE";
            try (Connection c = DriverManager.getConnection(url, "sa", "x")) {
                c.createStatement().execute("CREATE TABLE t(k INT)");
            }
            try (Connection c = DriverManager.getConnection(url, "sa", "x")) {
                c.createStatement().execute("INSERT INTO t VALUES (1)");
            }
            final String pre = "db" + (i - 1) + ".mv.db";
            final String label = o;
            for (Path p : Files.newDirectoryStream(base)) {
                if (p.getFileName().toString().equals(pre)) {
                    System.out.println("  " + label + " -> " + Files.getPosixFilePermissions(p));
                }
            }
        }

        // 2. does a semicolon in the path get treated as a URL option?
        try {
            String url = "jdbc:h2:" + base.resolve("evil;INIT=RUNSCRIPT FROM 'src/test/resources/x.sql'");
            System.out.print("SEMI-URL: ");
            try (Connection c = DriverManager.getConnection(url, "sa", "x")) {
                DatabaseMetaData md = c.getMetaData();
                System.out.println("opened db=" + md.getURL());
            }
        } catch (Exception e) {
            System.out.println("SEMI-URL rejected: " + e.getClass().getSimpleName());
        }

        // 3. FOR UPDATE + atomic update semantics
        String url = "jdbc:h2:" + base.resolve("lockdb") + ";ACCESS_MODE_DATA=rw-------";
        try (Connection c = DriverManager.getConnection(url, "sa", "x")) {
            c.setAutoCommit(false);
            Statement s = c.createStatement();
            s.execute("CREATE TABLE throttle(k VARCHAR(64) PRIMARY KEY, n INT, v BIGINT)");
            c.commit();
            // MERGE upsert
            try (PreparedStatement m = c.prepareStatement("MERGE INTO throttle(k,n,v) KEY(k) VALUES (?,?,?)")) {
                m.setString(1, "k1"); m.setInt(2, 0); m.setLong(3, 0L); m.executeUpdate();
            }
            c.commit();
            try (PreparedStatement p = c.prepareStatement("SELECT n FROM throttle WHERE k=? FOR UPDATE")) {
                p.setString(1, "k1");
                try (ResultSet rs = p.executeQuery()) {
                    System.out.println("FOR UPDATE ok, rows=" + (rs.next() ? rs.getInt(1) : -1));
                }
            }
            c.commit();
            // does one statement's UPDATE return the new value? H2 supports RETURNING via execute? test updateCount
            try (PreparedStatement u = c.prepareStatement("UPDATE throttle SET n=n+1 WHERE k=? AND v<?")) {
                u.setString(1, "k1"); u.setLong(2, 9L);
                System.out.println("conditional update count=" + u.executeUpdate());
            }
            c.commit();
            // isolation levels available
            DatabaseMetaData md = c.getMetaData();
            System.out.println("SERIALIZABLE supported=" + md.supportsTransactionIsolationLevel(Connection.TRANSACTION_SERIALIZABLE)
                + " RC=" + md.supportsTransactionIsolationLevel(Connection.TRANSACTION_READ_COMMITTED));
            System.out.println("txn=" + md.getDefaultTransactionIsolation());
        }

        // 4. concurrency: 8 threads x 50 increments on one row, FOR UPDATE txn
        long t0 = System.nanoTime();
        final String u2 = url;
        int T = 8, N = 50;
        Thread[] th = new Thread[T];
        for (int t = 0; t < T; t++) {
            th[t] = new Thread(() -> {
                try (Connection c = DriverManager.getConnection(u2, "sa", "x")) {
                    c.setAutoCommit(false);
                    for (int j = 0; j < N; j++) {
                        try (PreparedStatement p = c.prepareStatement("SELECT n FROM throttle WHERE k=? FOR UPDATE")) {
                            p.setString(1, "k1");
                            int cur;
                            try (ResultSet rs = p.executeQuery()) { rs.next(); cur = rs.getInt(1); }
                            try (PreparedStatement up = c.prepareStatement("UPDATE throttle SET n=? WHERE k=?")) {
                                up.setInt(1, cur + 1); up.setString(2, "k1"); up.executeUpdate();
                            }
                            c.commit();
                        }
                    }
                } catch (Exception e) { System.out.println("THREAD ERR " + e); }
            });
            th[t].start();
        }
        for (Thread th1 : th) th1.join();
        try (Connection c = DriverManager.getConnection(url, "sa", "x");
             Statement s = c.createStatement();
             ResultSet rs = s.executeQuery("SELECT n FROM throttle WHERE k='k1'")) {
            rs.next();
            System.out.println("ATOMIC expected=" + (T * N + 1) + " actual=" + rs.getInt(1)
                + " in " + (System.nanoTime() - t0) / 1_000_000 + " ms");
        }

        // 4b. cross-connection FOR UPDATE contention: block or throw?
        String ulock = "jdbc:h2:" + base.resolve("lockdb") + ";LOCK_TIMEOUT=250";
        try (Connection c1 = DriverManager.getConnection(ulock, "sa", "x");
             Connection c2 = DriverManager.getConnection(ulock, "sa", "x")) {
            c1.setAutoCommit(false);
            try (PreparedStatement p = c1.prepareStatement("SELECT n FROM throttle WHERE k=? FOR UPDATE")) {
                p.setString(1, "k1");
                try (ResultSet rs = p.executeQuery()) { rs.next(); }
                long w0 = System.nanoTime();
                try (PreparedStatement p2 = c2.prepareStatement("SELECT n FROM throttle WHERE k=? FOR UPDATE")) {
                    p2.setString(1, "k1");
                    try (ResultSet rs = p2.executeQuery()) { rs.next(); }
                    System.out.println("CONTENTION: second txn read after " + (System.nanoTime() - w0) / 1_000_000 + " ms");
                } catch (SQLException e) {
                    System.out.println("CONTENTION: threw " + e.getClass().getSimpleName() + " sqlState=" + e.getSQLState()
                        + " after " + (System.nanoTime() - w0) / 1_000_000 + " ms");
                }
            }
            c1.rollback();
        }
        // which files does H2 create, and with what perms
        for (Path p : Files.newDirectoryStream(base)) {
            String n = p.getFileName().toString();
            if (n.startsWith("lockdb")) {
                System.out.println("FILE " + n + " " + Files.getPosixFilePermissions(p) + " size=" + Files.size(p));
            }
        }

        // 5. KDF timing
        char[] pw = "Calibrate-Me-Please-7".toCharArray();
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        for (int it : new int[]{50000, 100000, 210000, 310000, 600000}) {
            long s1 = System.nanoTime();
            kdf(pw, salt, it);
            long s2 = System.nanoTime();
            kdf(pw, salt, it);
            long s3 = System.nanoTime();
            System.out.println("PBKDF2 iters=" + it + " first=" + (s2 - s1) / 1_000_000
                + " ms warm=" + (s3 - s2) / 1_000_000 + " ms");
        }
        System.out.println("PROBE DONE");
    }
}
