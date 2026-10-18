package com.example.adminportal;

import java.util.ArrayList;
import java.util.List;

/** Minimum strength requirements applied when an administrator password is set. */
final class PasswordPolicy {

    private static final int MIN_LENGTH = 12;
    private static final int MAX_LENGTH = 256;

    private PasswordPolicy() {
    }

    /** Returns the reasons {@code password} is unacceptable; empty means it passes. */
    static List<String> violations(char[] password) {
        List<String> problems = new ArrayList<>();
        if (password == null || password.length < MIN_LENGTH) {
            problems.add("must be at least " + MIN_LENGTH + " characters long");
            return problems;
        }
        if (password.length > MAX_LENGTH) {
            // Bounded so an oversized input cannot turn the KDF into a denial-of-service lever.
            problems.add("must be at most " + MAX_LENGTH + " characters long");
        }
        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean symbol = false;
        for (char c : password) {
            if (Character.isUpperCase(c)) {
                upper = true;
            } else if (Character.isLowerCase(c)) {
                lower = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            } else {
                symbol = true;
            }
        }
        if (!upper) {
            problems.add("must contain an uppercase letter");
        }
        if (!lower) {
            problems.add("must contain a lowercase letter");
        }
        if (!digit) {
            problems.add("must contain a digit");
        }
        if (!symbol) {
            problems.add("must contain a symbol");
        }
        return problems;
    }
}
