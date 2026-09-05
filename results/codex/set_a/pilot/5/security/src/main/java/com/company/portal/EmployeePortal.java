package com.company.portal;

import com.company.portal.auth.AuthenticationResult;
import com.company.portal.auth.AuthenticationService;
import com.company.portal.auth.EmployeeRecord;
import com.company.portal.auth.InMemoryEmployeeRecordStore;
import com.company.portal.auth.PasswordHasher;

import java.io.Console;
import java.time.Duration;
import java.util.Arrays;

public final class EmployeePortal {
    private EmployeePortal() {}

    public static void main(String[] args) {
        Console console = System.console();
        if (console == null) {
            System.err.println("Run this application from an interactive terminal so passwords are hidden.");
            return;
        }

        PasswordHasher hasher = new PasswordHasher();
        InMemoryEmployeeRecordStore records = new InMemoryEmployeeRecordStore();
        // Demonstration only. Replace this seed record with a persistent employee repository.
        char[] initialPassword = "ChangeMe-123!".toCharArray();
        try {
            PasswordHasher.PasswordData data = hasher.hash(initialPassword);
            records.add(new EmployeeRecord("employee", data.salt(), data.hash()));
        } finally {
            Arrays.fill(initialPassword, '\0');
        }

        AuthenticationService authentication =
                new AuthenticationService(records, 5, Duration.ofMinutes(15));

        String username = console.readLine("Username: ");
        char[] password = console.readPassword("Password: ");
        if (password == null) return;
        try {
            AuthenticationResult result = authentication.authenticate(username, password);
            // Deliberately do not reveal whether the username, password, or lock state was responsible.
            System.out.println(result == AuthenticationResult.AUTHENTICATED
                    ? "Access granted."
                    : "Access denied. Invalid credentials or account temporarily unavailable.");
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
