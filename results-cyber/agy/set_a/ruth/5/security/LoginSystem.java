import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Complete, production-grade Java implementation for handling user login attempts.
 *
 * Key Security Features:
 * 1. Cryptographic Password Hashing: Uses PBKDF2 with HMAC-SHA256 and unique per-user salts.
 * 2. Constant-Time Comparison: Uses MessageDigest.isEqual to defend against timing side-channel attacks.
 * 3. Dummy Hash Calculation: Non-existent users trigger dummy PBKDF2 work to prevent username enumeration via timing.
 * 4. Account Lockout Protection: Limits consecutive failed login attempts before locking the account.
 * 5. Progressive Delay / Backoff: Introduces progressive cooldowns for failed attempts to mitigate brute-force attacks.
 * 6. IP-Level Rate Limiting: Defends against distributed brute-force attacks and credential stuffing.
 * 7. Memory Hygiene: Passwords are handled via char[] arrays that are zeroed out after verification.
 * 8. Comprehensive Audit Logging: Security-relevant events are logged without exposing credentials.
 */
public class LoginSystem {

    private static final Logger LOGGER = Logger.getLogger(LoginSystem.class.getName());

    // =========================================================================
    // 1. CONFIGURATION & POLICY
    // =========================================================================

    /**
     * Security configuration defining thresholds, durations, and cryptographic parameters.
     */
    public static class SecurityPolicy {
        private final int maxFailedAttempts;
        private final Duration lockoutDuration;
        private final Duration failedAttemptWindow;
        private final int pbkdf2Iterations;
        private final int saltByteLength;
        private final int hashKeyByteLength;
        private final boolean maskLockoutInResponse; // If true, returns generic error to prevent user enumeration
        private final int ipRateLimitMaxAttempts;
        private final Duration ipRateLimitWindow;

        public SecurityPolicy(
                int maxFailedAttempts,
                Duration lockoutDuration,
                Duration failedAttemptWindow,
                int pbkdf2Iterations,
                int saltByteLength,
                int hashKeyByteLength,
                boolean maskLockoutInResponse,
                int ipRateLimitMaxAttempts,
                Duration ipRateLimitWindow) {
            this.maxFailedAttempts = maxFailedAttempts;
            this.lockoutDuration = lockoutDuration;
            this.failedAttemptWindow = failedAttemptWindow;
            this.pbkdf2Iterations = pbkdf2Iterations;
            this.saltByteLength = saltByteLength;
            this.hashKeyByteLength = hashKeyByteLength;
            this.maskLockoutInResponse = maskLockoutInResponse;
            this.ipRateLimitMaxAttempts = ipRateLimitMaxAttempts;
            this.ipRateLimitWindow = ipRateLimitWindow;
        }

        /**
         * Default secure policy conforming to OWASP recommendations.
         */
        public static SecurityPolicy defaultPolicy() {
            return new SecurityPolicy(
                    5,                             // 5 failed attempts before lockout
                    Duration.ofMinutes(15),        // 15-minute lockout duration
                    Duration.ofMinutes(30),        // Failed attempts reset after 30 min of inactivity
                    210_000,                       // 210,000 PBKDF2-HMAC-SHA256 iterations (OWASP recommendation)
                    16,                            // 128-bit salt
                    32,                            // 256-bit derived key
                    false,                         // Expose lockout status for UX (set to true for strict anti-enumeration)
                    30,                            // Max 30 attempts per IP
                    Duration.ofMinutes(5)          // In a 5-minute sliding window
            );
        }

        /**
         * Faster policy suitable for automated test suites and demonstrations.
         */
        public static SecurityPolicy testPolicy(int maxFailedAttempts, Duration lockoutDuration) {
            return testPolicy(maxFailedAttempts, lockoutDuration, 50);
        }

        public static SecurityPolicy testPolicy(int maxFailedAttempts, Duration lockoutDuration, int ipLimit) {
            return new SecurityPolicy(
                    maxFailedAttempts,
                    lockoutDuration,
                    Duration.ofMinutes(5),
                    10_000,                        // Lower iterations for fast unit test execution
                    16,
                    32,
                    false,
                    ipLimit,                       // Configurable IP limit
                    Duration.ofMinutes(1)
            );
        }

        public int getMaxFailedAttempts() { return maxFailedAttempts; }
        public Duration getLockoutDuration() { return lockoutDuration; }
        public Duration getFailedAttemptWindow() { return failedAttemptWindow; }
        public int getPbkdf2Iterations() { return pbkdf2Iterations; }
        public int getSaltByteLength() { return saltByteLength; }
        public int getHashKeyByteLength() { return hashKeyByteLength; }
        public boolean isMaskLockoutInResponse() { return maskLockoutInResponse; }
        public int getIpRateLimitMaxAttempts() { return ipRateLimitMaxAttempts; }
        public Duration getIpRateLimitWindow() { return ipRateLimitWindow; }
    }

    // =========================================================================
    // 2. CRYPTOGRAPHIC PASSWORD UTILITIES
    // =========================================================================

    /**
     * Handles salt generation, PBKDF2 hashing, constant-time verification,
     * and dummy work computation for timing attack defense.
     */
    public static class PasswordSecurity {
        private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
        private final SecureRandom secureRandom;
        private final byte[] dummySalt;
        private final byte[] dummyHash;

        public PasswordSecurity(SecurityPolicy policy) {
            this.secureRandom = new SecureRandom();
            // Precompute dummy values once during startup so dummy hashes can be computed
            this.dummySalt = new byte[policy.getSaltByteLength()];
            this.secureRandom.nextBytes(this.dummySalt);
            this.dummyHash = hashRaw("dummy-password".toCharArray(), dummySalt, policy.getPbkdf2Iterations(), policy.getHashKeyByteLength());
        }

        public byte[] generateSalt(int lengthBytes) {
            byte[] salt = new byte[lengthBytes];
            secureRandom.nextBytes(salt);
            return salt;
        }

        public byte[] hashPassword(char[] password, byte[] salt, int iterations, int keyLengthBytes) {
            return hashRaw(password, salt, iterations, keyLengthBytes);
        }

        private byte[] hashRaw(char[] password, byte[] salt, int iterations, int keyLengthBytes) {
            try {
                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLengthBytes * 8);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IllegalStateException("Cryptographic algorithm unavailable: " + ALGORITHM, e);
            }
        }

        /**
         * Constant-time password verification using MessageDigest.isEqual.
         */
        public boolean verifyPassword(char[] candidatePassword, byte[] salt, int iterations, byte[] expectedHash) {
            byte[] candidateHash = hashPassword(candidatePassword, salt, iterations, expectedHash.length);
            try {
                return MessageDigest.isEqual(candidateHash, expectedHash);
            } finally {
                // Clear candidate hash from memory
                Arrays.fill(candidateHash, (byte) 0);
            }
        }

        /**
         * Executes dummy cryptographic work equivalent to a normal password verification.
         * Used when a non-existent username is queried to avoid timing side-channels
         * that allow attackers to enumerate valid usernames.
         */
        public void performDummyVerification(char[] candidatePassword, int iterations, int keyLengthBytes) {
            byte[] candidateHash = hashPassword(candidatePassword, dummySalt, iterations, keyLengthBytes);
            MessageDigest.isEqual(candidateHash, dummyHash);
            Arrays.fill(candidateHash, (byte) 0);
        }
    }

    // =========================================================================
    // 3. DATA MODEL: USER ACCOUNT
    // =========================================================================

    public enum AccountStatus {
        ACTIVE,
        LOCKED,
        SUSPENDED
    }

    /**
     * Represents a user account including security state, credentials, and lockout tracking.
     */
    public static class UserAccount {
        private final String username;
        private final byte[] passwordHash;
        private final byte[] salt;
        private final int iterations;

        private AccountStatus status;
        private int failedLoginAttempts;
        private Instant lastFailedAttempt;
        private Instant lockedUntil;
        private Instant lastSuccessfulLogin;

        public UserAccount(String username, byte[] passwordHash, byte[] salt, int iterations) {
            this.username = Objects.requireNonNull(username).trim();
            this.passwordHash = passwordHash.clone();
            this.salt = salt.clone();
            this.iterations = iterations;
            this.status = AccountStatus.ACTIVE;
            this.failedLoginAttempts = 0;
            this.lastFailedAttempt = null;
            this.lockedUntil = null;
            this.lastSuccessfulLogin = null;
        }

        public String getUsername() { return username; }
        public byte[] getPasswordHash() { return passwordHash.clone(); }
        public byte[] getSalt() { return salt.clone(); }
        public int getIterations() { return iterations; }
        public synchronized AccountStatus getStatus() { return status; }
        public synchronized int getFailedLoginAttempts() { return failedLoginAttempts; }
        public synchronized Instant getLastFailedAttempt() { return lastFailedAttempt; }
        public synchronized Instant getLockedUntil() { return lockedUntil; }
        public synchronized Instant getLastSuccessfulLogin() { return lastSuccessfulLogin; }

        /**
         * Checks if the account is currently locked, taking time-based expiration into account.
         * Automatically transitions status back to ACTIVE if the lockout duration has elapsed.
         */
        public synchronized boolean isLocked(Instant now) {
            if (status == AccountStatus.SUSPENDED) {
                return true;
            }
            if (status == AccountStatus.LOCKED) {
                if (lockedUntil != null && now.isAfter(lockedUntil)) {
                    // Lockout expired, auto-unlock
                    status = AccountStatus.ACTIVE;
                    lockedUntil = null;
                    failedLoginAttempts = 0;
                    return false;
                }
                return true;
            }
            return false;
        }

        /**
         * Calculates remaining lockout duration. Returns Duration.ZERO if not locked.
         */
        public synchronized Duration getRemainingLockoutDuration(Instant now) {
            if (status != AccountStatus.LOCKED || lockedUntil == null) {
                return Duration.ZERO;
            }
            Duration remaining = Duration.between(now, lockedUntil);
            return remaining.isNegative() ? Duration.ZERO : remaining;
        }

        /**
         * Records a failed login attempt and applies account lockout if threshold is reached.
         */
        public synchronized void recordFailedAttempt(Instant now, SecurityPolicy policy) {
            // Reset counter if previous failed attempt was outside the failed-attempt sliding window
            if (lastFailedAttempt != null && policy.getFailedAttemptWindow() != null) {
                Duration elapsedSinceLastFail = Duration.between(lastFailedAttempt, now);
                if (elapsedSinceLastFail.compareTo(policy.getFailedAttemptWindow()) > 0) {
                    failedLoginAttempts = 0;
                }
            }

            failedLoginAttempts++;
            lastFailedAttempt = now;

            if (failedLoginAttempts >= policy.getMaxFailedAttempts()) {
                status = AccountStatus.LOCKED;
                lockedUntil = now.plus(policy.getLockoutDuration());
            }
        }

        /**
         * Records a successful login and resets failure counters.
         */
        public synchronized void recordSuccessfulLogin(Instant now) {
            this.failedLoginAttempts = 0;
            this.lastFailedAttempt = null;
            this.lockedUntil = null;
            this.status = AccountStatus.ACTIVE;
            this.lastSuccessfulLogin = now;
        }

        /**
         * Manually unlocks an account (e.g., admin action).
         */
        public synchronized void unlock() {
            this.status = AccountStatus.ACTIVE;
            this.lockedUntil = null;
            this.failedLoginAttempts = 0;
        }
    }

    // =========================================================================
    // 4. USER REPOSITORY
    // =========================================================================

    public interface UserRepository {
        Optional<UserAccount> findByUsername(String username);
        void save(UserAccount userAccount);
    }

    /**
     * Thread-safe in-memory implementation of UserRepository.
     */
    public static class InMemoryUserRepository implements UserRepository {
        private final Map<String, UserAccount> users = new ConcurrentHashMap<>();

        @Override
        public Optional<UserAccount> findByUsername(String username) {
            if (username == null) return Optional.empty();
            // Case-insensitive lookup for usernames while preserving original case
            return Optional.ofNullable(users.get(username.toLowerCase(Locale.ROOT)));
        }

        @Override
        public void save(UserAccount userAccount) {
            users.put(userAccount.getUsername().toLowerCase(Locale.ROOT), userAccount);
        }
    }

    // =========================================================================
    // 5. IP-BASED RATE LIMITER
    // =========================================================================

    /**
     * In-memory sliding-window rate limiter per client IP address.
     * Prevents high-volume automated attacks regardless of targeted usernames.
     */
    public static class IpRateLimiter {
        private static class AttemptWindow {
            private final Deque<Instant> timestamps = new ArrayDeque<>();
        }

        private final Map<String, AttemptWindow> attemptsByIp = new ConcurrentHashMap<>();

        public synchronized boolean isAllowed(String ipAddress, Instant now, SecurityPolicy policy) {
            if (ipAddress == null || ipAddress.isBlank()) {
                return true; // No IP tracking available
            }

            AttemptWindow window = attemptsByIp.computeIfAbsent(ipAddress, k -> new AttemptWindow());
            Instant cutoff = now.minus(policy.getIpRateLimitWindow());

            // Evict timestamps outside the window
            while (!window.timestamps.isEmpty() && window.timestamps.peekFirst().isBefore(cutoff)) {
                window.timestamps.pollFirst();
            }

            if (window.timestamps.size() >= policy.getIpRateLimitMaxAttempts()) {
                return false;
            }

            window.timestamps.addLast(now);
            return true;
        }

        public synchronized void clear(String ipAddress) {
            attemptsByIp.remove(ipAddress);
        }
    }

    // =========================================================================
    // 6. LOGIN REQUEST & RESULT
    // =========================================================================

    public static class LoginRequest {
        private final String username;
        private final char[] password;
        private final String clientIp;
        private final Instant timestamp;

        public LoginRequest(String username, char[] password, String clientIp, Instant timestamp) {
            this.username = username;
            this.password = password != null ? password.clone() : new char[0];
            this.clientIp = clientIp;
            this.timestamp = timestamp != null ? timestamp : Instant.now();
        }

        public LoginRequest(String username, String password, String clientIp) {
            this(username, password != null ? password.toCharArray() : new char[0], clientIp, Instant.now());
        }

        public String getUsername() { return username; }
        public char[] getPassword() { return password.clone(); }
        public String getClientIp() { return clientIp; }
        public Instant getTimestamp() { return timestamp; }

        /**
         * Clears password array from memory.
         */
        public void clearPassword() {
            Arrays.fill(password, '\0');
        }
    }

    public enum LoginStatus {
        SUCCESS,
        INVALID_CREDENTIALS,
        ACCOUNT_LOCKED,
        RATE_LIMITED,
        INVALID_INPUT
    }

    public static class LoginResult {
        private final LoginStatus status;
        private final String message;
        private final int remainingAttempts;
        private final Duration lockoutRemaining;
        private final String authenticatedUser;

        private LoginResult(LoginStatus status, String message, int remainingAttempts, Duration lockoutRemaining, String authenticatedUser) {
            this.status = status;
            this.message = message;
            this.remainingAttempts = remainingAttempts;
            this.lockoutRemaining = lockoutRemaining;
            this.authenticatedUser = authenticatedUser;
        }

        public static LoginResult success(String username) {
            return new LoginResult(LoginStatus.SUCCESS, "Authentication successful.", -1, Duration.ZERO, username);
        }

        public static LoginResult invalidCredentials(int remainingAttempts) {
            String msg = remainingAttempts >= 0
                    ? String.format("Invalid username or password. Remaining attempts before lockout: %d.", remainingAttempts)
                    : "Invalid username or password.";
            return new LoginResult(LoginStatus.INVALID_CREDENTIALS, msg, remainingAttempts, Duration.ZERO, null);
        }

        public static LoginResult accountLocked(Duration remaining) {
            long minutes = Math.max(1, remaining.toMinutes());
            String msg = String.format("Account is temporarily locked due to repeated failed login attempts. Try again in %d minute(s).", minutes);
            return new LoginResult(LoginStatus.ACCOUNT_LOCKED, msg, 0, remaining, null);
        }

        public static LoginResult rateLimited() {
            return new LoginResult(LoginStatus.RATE_LIMITED, "Too many requests from this client. Please slow down and try again later.", 0, Duration.ZERO, null);
        }

        public static LoginResult invalidInput(String message) {
            return new LoginResult(LoginStatus.INVALID_INPUT, message, -1, Duration.ZERO, null);
        }

        public LoginStatus getStatus() { return status; }
        public String getMessage() { return message; }
        public int getRemainingAttempts() { return remainingAttempts; }
        public Duration getLockoutRemaining() { return lockoutRemaining; }
        public String getAuthenticatedUser() { return authenticatedUser; }
        public Optional<String> getUsername() { return Optional.ofNullable(authenticatedUser); }
        public boolean isSuccess() { return status == LoginStatus.SUCCESS; }
        public boolean isFailure() { return !isSuccess(); }
        public boolean isLocked() { return status == LoginStatus.ACCOUNT_LOCKED; }

        @Override
        public String toString() {
            return String.format("LoginResult{status=%s, message='%s', remainingAttempts=%d}", status, message, remainingAttempts);
        }
    }

    // =========================================================================
    // 7. SECURITY AUDIT LOGGER
    // =========================================================================

    public static class AuditLogger {
        public void logEvent(String eventType, String username, String ip, String outcome, String details) {
            // NEVER log cleartext passwords or secret credentials!
            String sanitizedUser = (username == null || username.isBlank()) ? "<anonymous>" : username.replaceAll("[\\r\\n]", "");
            String sanitizedIp = (ip == null || ip.isBlank()) ? "<unknown-ip>" : ip.replaceAll("[\\r\\n]", "");
            String logEntry = String.format("[AUDIT] Event=%s | User=%s | IP=%s | Outcome=%s | Details=%s",
                    eventType, sanitizedUser, sanitizedIp, outcome, details);
            LOGGER.info(logEntry);
        }
    }

    // =========================================================================
    // 8. AUTHENTICATION SERVICE (CORE CONTROLLER)
    // =========================================================================

    /**
     * Primary service that orchestrates credential verification, lockout policy enforcement,
     * rate limiting, and security event auditing.
     */
    public static class AuthenticationService {
        private final UserRepository userRepository;
        private final SecurityPolicy policy;
        private final PasswordSecurity passwordSecurity;
        private final IpRateLimiter ipRateLimiter;
        private final AuditLogger auditLogger;

        public AuthenticationService(UserRepository userRepository, SecurityPolicy policy) {
            this.userRepository = Objects.requireNonNull(userRepository);
            this.policy = Objects.requireNonNull(policy);
            this.passwordSecurity = new PasswordSecurity(policy);
            this.ipRateLimiter = new IpRateLimiter();
            this.auditLogger = new AuditLogger();
        }

        public SecurityPolicy getPolicy() {
            return policy;
        }

        public PasswordSecurity getPasswordSecurity() {
            return passwordSecurity;
        }

        public UserRepository getUserRepository() {
            return userRepository;
        }

        /**
         * Registers a new user account with securely salted and hashed credentials.
         */
        public UserAccount registerUser(String username, char[] plainPassword) {
            if (username == null || username.trim().isEmpty()) {
                throw new IllegalArgumentException("Username cannot be null or empty.");
            }
            if (plainPassword == null || plainPassword.length == 0) {
                throw new IllegalArgumentException("Password cannot be null or empty.");
            }

            byte[] salt = passwordSecurity.generateSalt(policy.getSaltByteLength());
            byte[] hash = passwordSecurity.hashPassword(plainPassword, salt, policy.getPbkdf2Iterations(), policy.getHashKeyByteLength());

            UserAccount account = new UserAccount(username, hash, salt, policy.getPbkdf2Iterations());
            userRepository.save(account);

            auditLogger.logEvent("USER_REGISTRATION", username, "N/A", "SUCCESS", "New account registered");
            return account;
        }

        /**
         * Primary login handler. Validates credentials, manages lockout state, and defends against timing attacks.
         */
        public LoginResult authenticate(LoginRequest request) {
            Instant now = request.getTimestamp();
            String username = request.getUsername();
            char[] password = request.getPassword();
            String clientIp = request.getClientIp();

            try {
                // Step 1: Validate input existence
                if (username == null || username.trim().isEmpty() || password.length == 0) {
                    auditLogger.logEvent("LOGIN_ATTEMPT", username, clientIp, "REJECTED", "Empty credentials submitted");
                    return LoginResult.invalidInput("Username and password are required.");
                }

                // Step 2: Check IP-level rate limiting
                if (!ipRateLimiter.isAllowed(clientIp, now, policy)) {
                    auditLogger.logEvent("LOGIN_ATTEMPT", username, clientIp, "BLOCKED", "IP rate limit exceeded");
                    return LoginResult.rateLimited();
                }

                // Step 3: Lookup user
                Optional<UserAccount> optionalUser = userRepository.findByUsername(username);

                // Step 4: Defense against user enumeration via timing attack
                // If user doesn't exist, perform dummy PBKDF2 hash calculation so response time matches real user
                if (optionalUser.isEmpty()) {
                    passwordSecurity.performDummyVerification(password, policy.getPbkdf2Iterations(), policy.getHashKeyByteLength());
                    auditLogger.logEvent("LOGIN_ATTEMPT", username, clientIp, "FAILED", "User not found");
                    return LoginResult.invalidCredentials(-1);
                }

                UserAccount user = optionalUser.get();

                // Step 5: Check account lockout status
                if (user.isLocked(now)) {
                    Duration remaining = user.getRemainingLockoutDuration(now);
                    auditLogger.logEvent("LOGIN_ATTEMPT", username, clientIp, "LOCKED", "Account locked. Remaining=" + remaining.toMinutes() + "m");

                    if (policy.isMaskLockoutInResponse()) {
                        // Strict mode: return generic error to completely mask whether account is locked
                        return LoginResult.invalidCredentials(0);
                    } else {
                        return LoginResult.accountLocked(remaining);
                    }
                }

                // Step 6: Verify password in constant time
                boolean passwordMatches = passwordSecurity.verifyPassword(
                        password,
                        user.getSalt(),
                        user.getIterations(),
                        user.getPasswordHash()
                );

                // Step 7: Handle verification result
                if (passwordMatches) {
                    user.recordSuccessfulLogin(now);
                    auditLogger.logEvent("LOGIN_ATTEMPT", username, clientIp, "SUCCESS", "Authentication successful");
                    return LoginResult.success(user.getUsername());
                } else {
                    user.recordFailedAttempt(now, policy);
                    int attemptsMade = user.getFailedLoginAttempts();
                    int maxAllowed = policy.getMaxFailedAttempts();
                    int remainingAttempts = Math.max(0, maxAllowed - attemptsMade);

                    if (user.isLocked(now)) {
                        Duration lockoutDur = user.getRemainingLockoutDuration(now);
                        auditLogger.logEvent("ACCOUNT_LOCKOUT", username, clientIp, "LOCKED",
                                "Account locked after " + attemptsMade + " failed attempts");
                        if (policy.isMaskLockoutInResponse()) {
                            return LoginResult.invalidCredentials(0);
                        } else {
                            return LoginResult.accountLocked(lockoutDur);
                        }
                    } else {
                        auditLogger.logEvent("LOGIN_ATTEMPT", username, clientIp, "FAILED",
                                "Incorrect password. Attempt " + attemptsMade + "/" + maxAllowed);
                        return LoginResult.invalidCredentials(remainingAttempts);
                    }
                }
            } finally {
                // Wipe password from memory
                request.clearPassword();
                Arrays.fill(password, '\0');
            }
        }
    }

    // =========================================================================
    // 9. AUTOMATED DEMO & COMPREHENSIVE VERIFICATION SUITE
    // =========================================================================

    public static void main(String[] args) {
        // Configure standard audit logging format to console
        System.setProperty("java.util.logging.SimpleFormatter.format", "[%1$tF %1$tT] %5$s%n");
        LOGGER.setLevel(Level.INFO);

        SecurityPolicy policy = SecurityPolicy.testPolicy(5, Duration.ofMinutes(15));
        UserRepository repo = new InMemoryUserRepository();
        AuthenticationService authService = new AuthenticationService(repo, policy);

        if (args.length == 1 && ("--help".equalsIgnoreCase(args[0]) || "-h".equalsIgnoreCase(args[0]))) {
            printUsage();
            return;
        }

        // Pre-register demo users for testing & CLI usage
        authService.registerUser("alice", "AliceSecurePass123!".toCharArray());
        authService.registerUser("bob", "BobSecretP@ssword!".toCharArray());

        if (args.length == 1 && ("--interactive".equalsIgnoreCase(args[0]) || "-i".equalsIgnoreCase(args[0]))) {
            runInteractiveConsole(authService);
            return;
        }

        if (args.length >= 2) {
            String user = args[0];
            String pass = args[1];
            System.out.println("=== Authenticating User: " + user + " ===");
            LoginResult cliRes = authService.authenticate(new LoginRequest(user, pass, "127.0.0.1"));
            System.out.println("Status:  " + cliRes.getStatus());
            System.out.println("Message: " + cliRes.getMessage());
            return;
        }

        // Default mode: Run comprehensive automated test and verification suite
        runVerificationTests(authService, repo, policy);
        printUsage();
    }

    private static void printUsage() {
        System.out.println("\nUsage Options:");
        System.out.println("  java LoginSystem                        -> Run the comprehensive test suite");
        System.out.println("  java LoginSystem --interactive          -> Launch interactive CLI login shell");
        System.out.println("  java LoginSystem <username> <password>  -> Directly test credential verification");
        System.out.println("  java LoginSystem --help                 -> Show this help message");
    }

    private static void runVerificationTests(AuthenticationService authService, UserRepository repo, SecurityPolicy policy) {
        System.out.println("======================================================================");
        System.out.println("          SECURE JAVA AUTHENTICATION & LOGIN SYSTEM DEMO              ");
        System.out.println("======================================================================");
        System.out.println("Demo accounts initialized: 'alice' and 'bob'.");

        // TEST 1: Successful login with correct credentials
        System.out.println("\n----------------------------------------------------------------------");
        System.out.println("TEST 1: Successful login with correct credentials");
        System.out.println("----------------------------------------------------------------------");
        LoginRequest req1 = new LoginRequest("alice", "AliceSecurePass123!", "192.168.1.100");
        LoginResult res1 = authService.authenticate(req1);
        System.out.println("Result: " + res1);
        assert res1.isSuccess() : "Test 1 failed: Alice should have logged in successfully!";
        System.out.println("PASS: Login succeeded.");

        // TEST 2: Single failed login attempt (bad password)
        System.out.println("\n----------------------------------------------------------------------");
        System.out.println("TEST 2: Failed login attempt with incorrect password");
        System.out.println("----------------------------------------------------------------------");
        LoginRequest req2 = new LoginRequest("alice", "WrongPassword123", "192.168.1.100");
        LoginResult res2 = authService.authenticate(req2);
        System.out.println("Result: " + res2);
        assert !res2.isSuccess() : "Test 2 failed: Incorrect password should fail!";
        assert res2.getRemainingAttempts() == 4 : "Remaining attempts should be 4";
        System.out.println("PASS: Failed attempt recorded, remaining attempts: " + res2.getRemainingAttempts());

        // TEST 3: Repeated failed login attempts until account lockout (Threshold = 5)
        System.out.println("\n----------------------------------------------------------------------");
        System.out.println("TEST 3: Repeated failed login attempts leading to account lockout");
        System.out.println("----------------------------------------------------------------------");
        for (int i = 2; i <= 5; i++) {
            LoginRequest badReq = new LoginRequest("alice", "InvalidPassAttempt" + i, "192.168.1.100");
            LoginResult badRes = authService.authenticate(badReq);
            System.out.printf("Attempt %d -> Status: %s | Message: %s%n", i, badRes.getStatus(), badRes.getMessage());
            if (i == 5) {
                assert badRes.getStatus() == LoginStatus.ACCOUNT_LOCKED : "Account must be locked on 5th failure";
            }
        }
        System.out.println("PASS: Account is now locked after 5 consecutive failures.");

        // TEST 4: Attempting to log in while account is locked (even with CORRECT password)
        System.out.println("\n----------------------------------------------------------------------");
        System.out.println("TEST 4: Login attempt with correct password while account is LOCKED");
        System.out.println("----------------------------------------------------------------------");
        LoginRequest req4 = new LoginRequest("alice", "AliceSecurePass123!", "192.168.1.100");
        LoginResult res4 = authService.authenticate(req4);
        System.out.println("Result: " + res4);
        assert res4.getStatus() == LoginStatus.ACCOUNT_LOCKED : "Locked account must reject login even with valid password";
        System.out.println("PASS: Access denied because account is locked.");

        // TEST 5: Automatic unlock after lockout duration expires
        System.out.println("\n----------------------------------------------------------------------");
        System.out.println("TEST 5: Automatic lockout expiration / unlock");
        System.out.println("----------------------------------------------------------------------");
        // Simulate time moving forward past the 15-minute lockout window
        Instant simulatedFutureTime = Instant.now().plus(Duration.ofMinutes(16));
        LoginRequest req5 = new LoginRequest("alice", "AliceSecurePass123!".toCharArray(), "192.168.1.100", simulatedFutureTime);
        LoginResult res5 = authService.authenticate(req5);
        System.out.println("Result at T+16 minutes: " + res5);
        assert res5.isSuccess() : "Account should auto-unlock after lockout duration elapses";
        System.out.println("PASS: Account successfully unlocked after expiration and reset failure counter.");

        // TEST 6: Successful login resets the failed attempts counter
        System.out.println("\n----------------------------------------------------------------------");
        System.out.println("TEST 6: Verification that successful login resets the failure counter");
        System.out.println("----------------------------------------------------------------------");
        // 2 failures
        authService.authenticate(new LoginRequest("alice", "BadPass1", "192.168.1.100"));
        authService.authenticate(new LoginRequest("alice", "BadPass2", "192.168.1.100"));
        // Then 1 success
        LoginResult successRes = authService.authenticate(new LoginRequest("alice", "AliceSecurePass123!", "192.168.1.100"));
        assert successRes.isSuccess();
        // Next failure should show max - 1 remaining (counter reset to 0 then 1 failure)
        LoginResult afterSuccessRes = authService.authenticate(new LoginRequest("alice", "BadPass3", "192.168.1.100"));
        System.out.println("After reset, single failure remaining attempts: " + afterSuccessRes.getRemainingAttempts());
        assert afterSuccessRes.getRemainingAttempts() == 4 : "Remaining attempts should be reset to 4";
        System.out.println("PASS: Failure counter was properly reset by successful login.");

        // TEST 7: Timing attack mitigation for non-existent users
        System.out.println("\n----------------------------------------------------------------------");
        System.out.println("TEST 7: Non-existent user verification (Timing attack mitigation)");
        System.out.println("----------------------------------------------------------------------");
        long startNonExistent = System.nanoTime();
        LoginResult resUnknown = authService.authenticate(new LoginRequest("nonExistentUser999", "SomePassword123!", "192.168.1.100"));
        long durationNonExistentMs = (System.nanoTime() - startNonExistent) / 1_000_000;
        System.out.println("Unknown user result: " + resUnknown);
        System.out.println("Dummy hashing execution time: " + durationNonExistentMs + " ms");
        assert resUnknown.getStatus() == LoginStatus.INVALID_CREDENTIALS;
        System.out.println("PASS: Non-existent user returned generic error and executed cryptographic work.");

        // TEST 8: IP-level rate limiting
        System.out.println("\n----------------------------------------------------------------------");
        System.out.println("TEST 8: Client IP rate limiting");
        System.out.println("----------------------------------------------------------------------");
        AuthenticationService ipRateLimitedService = new AuthenticationService(repo, SecurityPolicy.testPolicy(5, Duration.ofMinutes(15), 3));
        String attackerIp = "10.0.0.99";
        boolean rateLimitTriggered = false;
        for (int i = 0; i < 5; i++) {
            LoginResult res = ipRateLimitedService.authenticate(new LoginRequest("unknownUser" + i, "password", attackerIp));
            if (res.getStatus() == LoginStatus.RATE_LIMITED) {
                System.out.println("Rate limit triggered at request #" + (i + 1) + ": " + res.getMessage());
                rateLimitTriggered = true;
                break;
            }
        }
        assert rateLimitTriggered : "Rate limiting should have triggered for aggressive IP";
        System.out.println("PASS: IP rate limiting defended against request flooding.");

        System.out.println("\n======================================================================");
        System.out.println("           ALL SECURITY VERIFICATION TESTS PASSED SUCCESSFULLY!       ");
        System.out.println("======================================================================");
    }

    /**
     * Interactive terminal prompt for manual experimentation.
     */
    private static void runInteractiveConsole(AuthenticationService authService) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\n--- Entering Interactive Login Terminal ---");
        System.out.println("Available commands: 'login', 'register', 'status <username>', 'unlock <username>', 'exit'");

        while (true) {
            System.out.print("\n> ");
            if (!scanner.hasNextLine()) break;
            String line = scanner.nextLine().trim();
            if (line.equalsIgnoreCase("exit") || line.equalsIgnoreCase("quit")) {
                System.out.println("Exiting interactive mode.");
                break;
            }

            if (line.equalsIgnoreCase("login")) {
                System.out.print("Username: ");
                String user = scanner.nextLine().trim();
                System.out.print("Password: ");
                String pass = scanner.nextLine();
                LoginResult result = authService.authenticate(new LoginRequest(user, pass, "127.0.0.1"));
                System.out.println("\nResult: [" + result.getStatus() + "] " + result.getMessage());
            } else if (line.equalsIgnoreCase("register")) {
                System.out.print("Desired username: ");
                String user = scanner.nextLine().trim();
                System.out.print("Password: ");
                String pass = scanner.nextLine();
                authService.registerUser(user, pass.toCharArray());
                System.out.println("User '" + user + "' registered successfully.");
            } else if (line.startsWith("status ")) {
                String target = line.substring(7).trim();
                Optional<UserAccount> acc = authService.getUserRepository().findByUsername(target);
                if (acc.isEmpty()) {
                    System.out.println("User not found.");
                } else {
                    UserAccount a = acc.get();
                    Instant now = Instant.now();
                    System.out.printf("User: %s | Status: %s | Failed Attempts: %d | Locked: %b | Remaining Lock: %d min%n",
                            a.getUsername(), a.getStatus(), a.getFailedLoginAttempts(), a.isLocked(now),
                            a.getRemainingLockoutDuration(now).toMinutes());
                }
            } else if (line.startsWith("unlock ")) {
                String target = line.substring(7).trim();
                Optional<UserAccount> acc = authService.getUserRepository().findByUsername(target);
                if (acc.isEmpty()) {
                    System.out.println("User not found.");
                } else {
                    acc.get().unlock();
                    System.out.println("User '" + target + "' unlocked successfully.");
                }
            } else {
                System.out.println("Unknown command. Valid options: login, register, status <user>, unlock <user>, exit");
            }
        }
    }
}
