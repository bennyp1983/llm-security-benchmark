package com.example.portal;

import java.io.IOException;
import java.util.Optional;

public interface CredentialStore {
    Optional<EmployeeRecord> findByUsername(String username) throws IOException;
    void save(EmployeeRecord employee) throws IOException;
}
