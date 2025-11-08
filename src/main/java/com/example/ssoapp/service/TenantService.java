package com.example.ssoapp.service;

import com.example.ssoapp.dto.TenantMinimalDTO;
import com.example.ssoapp.model.Role;
import com.example.ssoapp.model.Tenant;
import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.TenantRepository;
import com.example.ssoapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class TenantService {

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SsoConfigService ssoConfigService;

    // ============================================================
    // ✅ 1️⃣  CREATE TENANT (For SuperAdmin)
    // ============================================================
    @Transactional
    public Tenant createTenant(String orgName, String adminEmail, String adminPassword, String subdomain) {

        if (tenantRepository.existsBySubdomain(subdomain)) {
            throw new RuntimeException("Subdomain already taken: " + subdomain);
        }

        if (userRepository.existsByEmailIgnoreCase(adminEmail)) {
            throw new RuntimeException("User with email " + adminEmail + " already exists");
        }

        // Create tenant
        Tenant tenant = new Tenant();
        tenant.setName(orgName);
        tenant.setAdminEmail(adminEmail);
        tenant.setSubdomain(subdomain);
        Tenant savedTenant = tenantRepository.save(tenant);

        // ✅ CRITICAL: Initialize SSO configs AFTER tenant is saved
        //logger.info("Initializing SSO configs for new tenant: {}", savedTenant.getId());
        ssoConfigService.initializeDefaultConfigsForTenant(savedTenant.getId());

        // Create admin user for this tenant
        User adminUser = new User();
        adminUser.setUsername(orgName + "_admin");
        adminUser.setEmail(adminEmail);
        adminUser.setPassword(passwordEncoder.encode(adminPassword));
        adminUser.setTenantId(savedTenant.getId());
        adminUser.setRole(Role.TENANT_ADMIN);
        adminUser.setProvider(com.example.ssoapp.model.AuthProvider.LOCAL);

        userRepository.save(adminUser);

        return savedTenant;
    }

    // ============================================================
    // ✅ 2️⃣  FIND ALL TENANTS (Minimal DTO)
    // ============================================================
    public List<TenantMinimalDTO> findAllTenantMinimal() {
        return tenantRepository.findAllTenantMinimal();
    }

    // ============================================================
    // ✅ 3️⃣  OTHER UTILITIES (Existing)
    // ============================================================
    public List<Tenant> getAllTenants() {
        return tenantRepository.findAll();
    }

    public Optional<Tenant> getTenantBySubdomain(String subdomain) {
        return tenantRepository.findBySubdomain(subdomain);
    }

    public Optional<Tenant> getTenantById(Long id) {
        return tenantRepository.findById(id);
    }

    public boolean existsBySubdomain(String subdomain) {
        return tenantRepository.existsBySubdomain(subdomain);
    }
}

