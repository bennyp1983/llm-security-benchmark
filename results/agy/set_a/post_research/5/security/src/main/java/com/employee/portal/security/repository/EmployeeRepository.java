package com.employee.portal.security.repository;

import com.employee.portal.security.model.EmployeeRecord;

import java.util.Optional;

/**
 * Contract for employee record persistence.
 */
public interface EmployeeRepository {

    Optional<EmployeeRecord> findByUsername(String username);

    boolean save(EmployeeRecord record);

    boolean exists(String username);

    int count();

    void reload();
}
