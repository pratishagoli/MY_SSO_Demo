package com.example.ssoapp.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * DTO for the SuperAdmin to create a new tenant and its Tenant Admin user.
 */
public class CreateTenantRequest {

    @NotBlank
    private String name;

    @NotBlank
    @Email
    private String email; // The Tenant Admin's email

    @NotBlank
    private String password; // The Tenant Admin's password

    @NotBlank
    private String subdomain; // The tenant's identifier (e.g., 'acme')

    // Getters and Setters (omitted for brevity, but needed in real code)
    // You should use Lombok or write them manually. I'll write them here for completeness.

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSubdomain() {
        return subdomain;
    }

    public void setSubdomain(String subdomain) {
        this.subdomain = subdomain;
    }
}