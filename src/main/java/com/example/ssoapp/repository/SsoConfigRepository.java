package com.example.ssoapp.repository;

import com.example.ssoapp.model.SsoConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SsoConfigRepository extends JpaRepository<SsoConfig, Long> {

    // 🚀 Find by SSO type for a specific tenant
    Optional<SsoConfig> findByTenantIdAndSsoType(Long tenantId, String ssoType);

    // 🚀 Find all SSO configs for a specific tenant
    List<SsoConfig> findByTenantId(Long tenantId);

    // 🚀 Find global/SuperAdmin configs (tenant_id is NULL)
    Optional<SsoConfig> findByTenantIdIsNullAndSsoType(String ssoType);

    // Legacy method (keep for backward compatibility during migration)
    Optional<SsoConfig> findBySsoType(String ssoType);
}