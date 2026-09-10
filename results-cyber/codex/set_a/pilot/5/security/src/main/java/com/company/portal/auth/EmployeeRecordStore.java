package com.company.portal.auth;

import java.time.Duration;
import java.time.Instant;

public interface EmployeeRecordStore {
    /** Implementations must perform the read/check/update as one atomic operation. */
    AuthenticationResult authenticate(
            String username,
            char[] password,
            PasswordHasher hasher,
            int maximumAttempts,
            Duration lockDuration,
            Instant now);
}
