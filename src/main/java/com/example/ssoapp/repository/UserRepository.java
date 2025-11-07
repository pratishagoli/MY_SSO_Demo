package com.example.ssoapp.repository;

import com.example.ssoapp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import com.example.ssoapp.model.Role;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import java.util.List;
import java.util.Optional;

@EnableJpaRepositories
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // --- NEW: Find the SUPERADMIN by email (tenantId is null) ---
    @Query("SELECT u FROM User u WHERE u.email = ?1 AND u.role = 'SUPERADMIN' AND u.tenantId IS NULL")
    Optional<User> findSuperAdminByEmail(String email);

    // --- MODIFIED: Find User by username OR email (Tenant-Aware) ---
    @Query("SELECT u FROM User u WHERE (u.username = ?1 OR u.email = ?2) AND u.tenantId = ?3")
    Optional<User> findByUsernameOrEmailAndTenantId(String username, String email, String tenantId);

    // Not strictly needed for the scope, but for completion:
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);

    // --- NEW: Find all users for a specific tenant (Used by SuperAdmin) ---
    List<User> findAllByTenantId(String tenantId);
    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    Optional<User> findByUsernameOrEmail(String username, String email);
}
