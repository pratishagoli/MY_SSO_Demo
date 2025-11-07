package com.example.ssoapp.service;

import com.example.ssoapp.dto.CreateTenantRequest;
import com.example.ssoapp.model.Role;
import com.example.ssoapp.model.User;
import com.example.ssoapp.model.AuthProvider;
import com.example.ssoapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors; // NEW IMPORT for toList() compatibility

@Service
public class TenantService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Creates a new tenant admin user. The tenant ID is derived from the subdomain.
     */
    @Transactional
    public User createTenant(CreateTenantRequest request) {

        // Use the lowercased subdomain as the tenantId (Hard Constraint: simplest way)
        String tenantId = request.getSubdomain().toLowerCase();

        // 1. Check for duplicate tenant admin email (globally, for simplicity)
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already exists globally.");
        }

        // 2. Create the Tenant Admin user
        User tenantAdmin = new User();
        tenantAdmin.setUsername(request.getName() + " Admin");
        tenantAdmin.setEmail(request.getEmail());
        tenantAdmin.setPassword(passwordEncoder.encode(request.getPassword()));
        tenantAdmin.setProvider(AuthProvider.LOCAL);

        // ⚠️ CORRECTION 1: Set role directly using the Enum, not String.valueOf()
        tenantAdmin.setRole(Role.TENANT_ADMIN);

        tenantAdmin.setTenantId(tenantId); // Crucial: Set the tenant ID

        return userRepository.save(tenantAdmin);
    }

    /**
     * Finds all users for a given tenant ID. Used by SuperAdmin.
     */
    public List<User> findAllUsersByTenantId(String tenantId) {
        return userRepository.findAllByTenantId(tenantId);
    }

    /**
     * Mock method to get a list of all tenants (represented by their Tenant Admin).
     * In a real app, you would have a dedicated 'Tenant' table.
     * Hard Constraint: simplest way, so we'll just pull all TENANT_ADMINs.
     */
    public List<User> findAllTenantsMinimal() {
        // Querying for all users with the TENANT_ADMIN role

        // ⚠️ CORRECTION 2: Use .equals() for Enum comparison (Role.TENANT_ADMIN)
        // with the User's Role field (which is the Enum type).
        // Note: Java streams' toList() method is available since Java 16,
        // using Collectors.toList() for broader compatibility.
        return userRepository.findAll().stream()
                .filter(u -> Role.TENANT_ADMIN.equals(u.getRole()))
                .collect(Collectors.toList());
    }
}