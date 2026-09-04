import java.io.*;
import java.net.*;
import java.util.*;

public class AuthTest {
    public static void main(String[] args) throws Exception {
        // Start server in background thread
        Thread serverThread = new Thread(() -> {
            try {
                AuthApplication.main(new String[0]);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        Thread.sleep(1000);

        System.out.println("--- Test 1: Access Dashboard without Cookie (Expect 302 Redirect to /login) ---");
        HttpURLConnection conn1 = (HttpURLConnection) new URL("http://localhost:8080/dashboard").openConnection();
        conn1.setInstanceFollowRedirects(false);
        int code1 = conn1.getResponseCode();
        String loc1 = conn1.getHeaderField("Location");
        System.out.println("Response code: " + code1 + ", Location: " + loc1);
        assert code1 == 302 && "/login".equals(loc1) : "Failed test 1";

        System.out.println("\n--- Test 2: Login with Invalid Credentials ---");
        HttpURLConnection conn2 = (HttpURLConnection) new URL("http://localhost:8080/login").openConnection();
        conn2.setRequestMethod("POST");
        conn2.setDoOutput(true);
        conn2.setInstanceFollowRedirects(false);
        try (OutputStream os = conn2.getOutputStream()) {
            os.write("username=admin&password=WrongPassword".getBytes());
        }
        int code2 = conn2.getResponseCode();
        String body2 = new String(conn2.getInputStream().readAllBytes());
        System.out.println("Response code: " + code2 + ", Contains error: " + body2.contains("Invalid username or password"));
        assert code2 == 200 && body2.contains("Invalid username or password") : "Failed test 2";

        System.out.println("\n--- Test 3: Login with Valid Credentials & Get Session Cookie ---");
        HttpURLConnection conn3 = (HttpURLConnection) new URL("http://localhost:8080/login").openConnection();
        conn3.setRequestMethod("POST");
        conn3.setDoOutput(true);
        conn3.setInstanceFollowRedirects(false);
        try (OutputStream os = conn3.getOutputStream()) {
            os.write("username=admin&password=Password123!".getBytes());
        }
        int code3 = conn3.getResponseCode();
        String setCookieHeader = conn3.getHeaderField("Set-Cookie");
        String loc3 = conn3.getHeaderField("Location");
        System.out.println("Response code: " + code3 + ", Set-Cookie: " + setCookieHeader + ", Location: " + loc3);
        assert code3 == 302 && "/dashboard".equals(loc3) : "Failed test 3 redirect";
        assert setCookieHeader != null && setCookieHeader.contains("JSESSIONID=") : "Failed test 3 cookie";

        String sessionCookie = setCookieHeader.split(";")[0];

        System.out.println("\n--- Test 4: Access Dashboard with Valid Cookie ---");
        HttpURLConnection conn4 = (HttpURLConnection) new URL("http://localhost:8080/dashboard").openConnection();
        conn4.setRequestProperty("Cookie", sessionCookie);
        int code4 = conn4.getResponseCode();
        String body4 = new String(conn4.getInputStream().readAllBytes());
        System.out.println("Response code: " + code4 + ", Contains user greeting: " + body4.contains("Welcome, admin!"));
        assert code4 == 200 && body4.contains("Welcome, admin!") : "Failed test 4";

        System.out.println("\n--- Test 5: Logout & Invalidate Session ---");
        HttpURLConnection conn5 = (HttpURLConnection) new URL("http://localhost:8080/logout").openConnection();
        conn5.setRequestProperty("Cookie", sessionCookie);
        conn5.setInstanceFollowRedirects(false);
        int code5 = conn5.getResponseCode();
        String expiredCookie = conn5.getHeaderField("Set-Cookie");
        System.out.println("Response code: " + code5 + ", Expired cookie: " + expiredCookie);
        assert code5 == 302 && expiredCookie.contains("Max-Age=0") : "Failed test 5";

        System.out.println("\n--- Test 6: Access Dashboard after Logout (Expect Redirect) ---");
        HttpURLConnection conn6 = (HttpURLConnection) new URL("http://localhost:8080/dashboard").openConnection();
        conn6.setRequestProperty("Cookie", sessionCookie);
        conn6.setInstanceFollowRedirects(false);
        int code6 = conn6.getResponseCode();
        System.out.println("Response code: " + code6 + ", Location: " + conn6.getHeaderField("Location"));
        assert code6 == 302 && "/login".equals(conn6.getHeaderField("Location")) : "Failed test 6";

        System.out.println("\nALL TESTS PASSED SUCCESSFULLY!");
    }
}
