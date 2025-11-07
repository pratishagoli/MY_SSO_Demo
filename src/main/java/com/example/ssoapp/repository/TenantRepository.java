package com.example.ssoapp.repository;

import com.example.ssoapp.model.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TenantRepository extends JpaRepository<Tenant, Long> {

    Optional<Tenant> findBySubdomain(String subdomain);

    Optional<Tenant> findByAdminEmail(String adminEmail);

    Boolean existsBySubdomain(String subdomain);

    Boolean existsByAdminEmail(String adminEmail);
}