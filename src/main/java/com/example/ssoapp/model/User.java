package com.example.ssoapp.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import org.hibernate.annotations.Filter;       // NEW
import org.hibernate.annotations.FilterDef;    // NEW
import org.hibernate.annotations.ParamDef;     // NEW

@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = "email")
})
// 🚀 NEW: Define the filter named "tenantFilter"
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = String.class))
// 🚀 NEW: Apply the filter to this entity, except when tenant_id is NULL (Superadmin)
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // --- MULTITENANCY FIELD ---
    @Column(name = "tenant_id", nullable = true)
    private String tenantId;

    @Size(max = 50)
    @Column(nullable = true)
    private String username;

    @Size(max = 120)
    @Column(nullable = true)
    private String password;

    @Size(max = 80)
    @Email
    @Column(nullable = false, unique = true)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuthProvider provider;

    @Column(nullable = true)
    private String providerId;


    // 🚀 CRITICAL FIX: Change type from String to Role Enum
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private Role role = Role.USER;

    public User() {}

    // --- Getters and Setters (Updated for Role Enum) ---
    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    // CRITICAL FIX: Setter parameter changed to Role
    public void setRole(Role role) {
        this.role = role;
    }

    // CRITICAL FIX: Getter return type changed to Role
    public Role getRole() {
        return role;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public AuthProvider getProvider() {
        return provider;
    }

    public void setProvider(AuthProvider provider) {
        this.provider = provider;
    }

    public String getProviderId() {
        return providerId;
    }

    public void setProviderId(String providerId) {
        this.providerId = providerId;
    }
}