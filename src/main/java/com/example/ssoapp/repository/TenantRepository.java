package com.example.ssoapp.repository;

import com.example.ssoapp.model.Tenant;
import com.example.ssoapp.dto.TenantMinimalDTO;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TenantRepository extends JpaRepository<Tenant, Long> {

    Optional<Tenant> findBySubdomain(String subdomain);

    // ✅ FIXED: Changed to match the 'adminEmail' field in your Tenant entity
    Optional<Tenant> findByAdminEmail(String email);

    boolean existsBySubdomain(String subdomain);

    // ✅ FIXED: Changed to match the 'name' field in your Tenant entity
    Optional<Tenant> findByNameIgnoreCase(String name);

    // ✅ NEW: Minimal DTO query (lightweight fetch for superadmin dashboard)
    @Query("SELECT new com.example.ssoapp.dto.TenantMinimalDTO(t.id, t.name, t.subdomain) FROM Tenant t")
    List<TenantMinimalDTO> findAllTenantMinimal();
}