package com.example.ssoapp.model;

// Define the roles for the application
public enum Role {
    // Role for the global system administrator
    SUPERADMIN,
    // Role for a tenant's own administrator
    TENANT_ADMIN,
    // Standard application user
    USER;

    // Spring Security expects roles to be prefixed with "ROLE_"
    public String withPrefix() {
        return "ROLE_" + this.name();
    }
}